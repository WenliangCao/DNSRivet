//! UDP + TCP DNS listener loops feeding the cache and upstream manager.

mod cache;
mod wire;

use crate::config::Config;
use crate::upstream::Manager;
use cache::Cache;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// Bound on concurrently in-flight queries (memory backstop).
const MAX_INFLIGHT: usize = 512;
const MAX_TCP_CONNECTIONS: usize = 256;
const MAX_TCP_QUERY_SIZE: usize = 4096;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve(config: Config) -> Result<(), String> {
    let system_fallback = match crate::osdns::fallback_servers(&config.listeners) {
        Ok(servers) => {
            if servers.is_empty() {
                log::warn!("no usable system DNS fallback server was found");
            } else {
                log::info!("system DNS fallback ready: {servers:?}");
            }
            servers
        }
        Err(err) => {
            log::warn!("system DNS fallback unavailable: {err}");
            Vec::new()
        }
    };
    let manager = Arc::new(Manager::new(
        config.upstreams,
        &config.listeners,
        system_fallback,
    )?);
    let cache = Arc::new(Cache::new(
        config.service.cache_enable,
        config.service.cache_size,
    ));
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
    let tcp_connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));

    for addr in &config.listeners {
        let udp = UdpSocket::bind(addr)
            .await
            .map_err(|e| format!("bind udp {addr}: {e}"))?;
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind tcp {addr}: {e}"))?;
        log::info!("listening on {addr} (udp+tcp)");
        tokio::spawn(udp_loop(
            Arc::new(udp),
            manager.clone(),
            cache.clone(),
            inflight.clone(),
        ));
        tokio::spawn(tcp_loop(
            tcp,
            manager.clone(),
            cache.clone(),
            inflight.clone(),
            tcp_connections.clone(),
        ));
    }

    wait_for_shutdown().await;
    log::info!("shutting down");
    Ok(())
}

async fn udp_loop(
    sock: Arc<UdpSocket>,
    manager: Arc<Manager>,
    cache: Arc<Cache>,
    inflight: Arc<Semaphore>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(err) => {
                log::warn!("udp recv error: {err}");
                continue;
            }
        };
        if n < 12 {
            continue;
        }
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            log::warn!("dropping query: {MAX_INFLIGHT} already in flight");
            continue;
        };
        let query = buf[..n].to_vec();
        let sock = sock.clone();
        let manager = manager.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            let meta = wire::parse_query_meta(&query);
            let mut response = resolve(&manager, &cache, &query, false, meta.as_ref()).await;
            wire::truncate_to(
                &mut response,
                meta.as_ref()
                    .map_or_else(|| wire::udp_payload_size(&query), |meta| meta.udp_size),
            );
            let _ = sock.send_to(&response, peer).await;
            drop(permit);
        });
    }
}

async fn tcp_loop(
    listener: TcpListener,
    manager: Arc<Manager>,
    cache: Arc<Cache>,
    inflight: Arc<Semaphore>,
    connections: Arc<Semaphore>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(connection) = connections.clone().try_acquire_owned() else {
                    log::warn!("dropping TCP connection: {MAX_TCP_CONNECTIONS} already open");
                    continue;
                };
                let manager = manager.clone();
                let cache = cache.clone();
                let inflight = inflight.clone();
                tokio::spawn(async move {
                    let _connection = connection;
                    let _ = tcp_conn(stream, manager, cache, inflight).await;
                });
            }
            Err(err) => log::warn!("tcp accept error: {err}"),
        }
    }
}

/// RFC 7766: length-prefixed messages, several per connection.
async fn tcp_conn(
    mut stream: TcpStream,
    manager: Arc<Manager>,
    cache: Arc<Cache>,
    inflight: Arc<Semaphore>,
) -> std::io::Result<()> {
    loop {
        let mut lenbuf = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut lenbuf)).await {
            Err(_) | Ok(Err(_)) => return Ok(()), // idle timeout, EOF or reset
            Ok(Ok(_)) => {}
        }
        let n = u16::from_be_bytes(lenbuf) as usize;
        if !(12..=MAX_TCP_QUERY_SIZE).contains(&n) {
            return Ok(());
        }
        let mut query = vec![0u8; n];
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut query)).await {
            Err(_) | Ok(Err(_)) => return Ok(()),
            Ok(Ok(_)) => {}
        }
        let _permit = inflight
            .acquire()
            .await
            .expect("inflight semaphore is never closed");
        let meta = wire::parse_query_meta(&query);
        let response = resolve(&manager, &cache, &query, true, meta.as_ref()).await;
        let len = u16::try_from(response.len()).unwrap_or(u16::MAX);
        let write = async {
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(&response[..len as usize]).await
        };
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, write).await {
            Err(_) | Ok(Err(_)) => return Ok(()),
            Ok(Ok(())) => {}
        }
    }
}

async fn resolve(
    manager: &Manager,
    cache: &Cache,
    query: &[u8],
    client_tcp: bool,
    meta: Option<&wire::QueryMeta>,
) -> Vec<u8> {
    if let Some(meta) = meta
        && let Some(response) = cache.get(meta, [query[0], query[1]])
    {
        log::debug!("cache hit");
        return response;
    }

    let response = match manager.forward(query, client_tcp).await {
        Some(response) => response,
        None => servfail(query),
    };
    if let Some(meta) = meta {
        cache.insert(meta, &response);
    }
    response
}

/// Header-echo SERVFAIL: QR=1, RA=1, RCODE=2, question section preserved.
fn servfail(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    if response.len() >= 12 {
        response[2] = (response[2] & 0x79) | 0x80; // QR=1, keep opcode/RD, clear AA+TC
        response[3] = 0x82; // RA=1, RCODE=SERVFAIL
    }
    response
}

async fn wait_for_shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
