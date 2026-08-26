//! UDP + TCP DNS listener loops feeding the cache and upstream manager.

mod cache;

use crate::config::Config;
use crate::upstream::Manager;
use crate::wire;
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

const WATCHDOG_INTERVAL: Duration = Duration::from_secs(120);
const WATCHDOG_SLOW_INTERVAL: Duration = Duration::from_secs(1800);
/// A reassert followed by renewed drift within this many ticks counts as one
/// flap strike; this many strikes switch to the slow cadence.
const FLAP_WINDOW_TICKS: u32 = 3;
const FLAP_STRIKES: u32 = 3;

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

    // The takeover watchdog only makes sense with a loopback:53 listener
    // (service mode). Its gate — backup, marker, root — is re-evaluated on
    // every tick, never once at startup: `start` boots this daemon before it
    // writes the backup, so a one-shot check would disable the watchdog
    // forever.
    match crate::service::takeover_address(&config.listeners) {
        Ok(takeover_ip) => {
            tokio::spawn(watchdog_loop(takeover_ip, manager.clone()));
        }
        Err(_) => log::debug!("takeover watchdog not started: no loopback port-53 listener"),
    }

    wait_for_shutdown().await;
    log::info!("shutting down");
    Ok(())
}

/// Periodically verify the DNS takeover and repair it when an external event
/// (a macOS update rewriting network preferences, another tool) removed it.
/// The first tick fires immediately, so a daemon restarted while DNS is
/// already drifted recovers in seconds rather than a full interval.
async fn watchdog_loop(server: std::net::IpAddr, manager: Arc<Manager>) {
    if unsafe { libc::geteuid() } != 0 {
        log::info!("takeover watchdog inactive: not running as root");
        return;
    }
    let mut interval = tokio::time::interval(WATCHDOG_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ticks_since_reassert: Option<u32> = None;
    let mut flap_strikes = 0u32;
    let mut slow_mode = false;
    loop {
        interval.tick().await;
        // networksetup/scutil are blocking subprocess calls; keep them off
        // the single-threaded reactor.
        let outcome = match tokio::task::spawn_blocking(move || crate::osdns::watchdog_tick(server))
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                log::warn!("takeover watchdog task failed: {err}");
                continue;
            }
        };
        match outcome {
            Ok(crate::osdns::TickOutcome::NotActive) => {
                log::debug!("takeover watchdog idle: takeover not active");
            }
            Ok(crate::osdns::TickOutcome::Clean) => {
                if slow_mode {
                    slow_mode = false;
                    flap_strikes = 0;
                    ticks_since_reassert = None;
                    interval = tokio::time::interval(WATCHDOG_INTERVAL);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    interval.reset();
                    log::info!("DNS settings stable again; watchdog back to normal cadence");
                } else if let Some(ticks) = &mut ticks_since_reassert {
                    *ticks += 1;
                    if *ticks >= FLAP_WINDOW_TICKS {
                        ticks_since_reassert = None;
                        flap_strikes = 0;
                    }
                }
            }
            Ok(crate::osdns::TickOutcome::Reasserted {
                corrected,
                captured,
            }) => {
                log::warn!(
                    "system DNS no longer pointed at {server} on {corrected:?}; takeover reasserted"
                );
                if captured.is_empty() {
                    log::warn!(
                        "could not capture the current network DNS; keeping the previous fallback list"
                    );
                } else {
                    log::info!("runtime system DNS fallback refreshed: {captured:?}");
                    manager.set_system_fallback(captured);
                }
                flap_strikes = if ticks_since_reassert.is_some() {
                    flap_strikes + 1
                } else {
                    1
                };
                ticks_since_reassert = Some(0);
                if flap_strikes >= FLAP_STRIKES && !slow_mode {
                    slow_mode = true;
                    interval = tokio::time::interval(WATCHDOG_SLOW_INTERVAL);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    interval.reset();
                    log::warn!(
                        "DNS settings keep being rewritten externally; another DNS manager may be active — checking every {}s from now on",
                        WATCHDOG_SLOW_INTERVAL.as_secs()
                    );
                }
            }
            Err(err) => log::warn!("takeover watchdog: {err}"),
        }
    }
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
    // RFC 9619: a QUERY with more than one question is malformed. Answer it
    // locally with FORMERR; it must never reach the cache or any upstream.
    if wire::is_multi_question_query(query) {
        return formerr(query);
    }

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

/// Header-only FORMERR for multi-question queries. The question section is
/// dropped and every count zeroed: RFC 9619 constrains all OPCODE=0 messages,
/// so echoing QDCOUNT > 1 would make the error response itself malformed.
fn formerr(query: &[u8]) -> Vec<u8> {
    let mut response = vec![0u8; 12];
    response[..2].copy_from_slice(&query[..2]);
    response[2] = (query[2] & 0x79) | 0x80; // QR=1, keep opcode/RD, clear AA+TC
    response[3] = 0x81; // RA=1, RCODE=FORMERR
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IpStack, Proto, Upstream};

    fn multi_question_query() -> Vec<u8> {
        let mut query = vec![0xab, 0xcd, 0x01, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        query.extend_from_slice(&[1, b'b', 0, 0, 1, 0, 1]);
        query
    }

    #[test]
    fn formerr_is_a_header_only_response() {
        let query = multi_question_query();
        let response = formerr(&query);
        assert_eq!(response.len(), 12);
        assert_eq!(&response[..2], &query[..2]);
        assert_ne!(response[2] & 0x80, 0); // QR
        assert_eq!(response[2] & 0x01, query[2] & 0x01); // RD echoed
        assert_eq!(response[3] & 0x0f, 1); // FORMERR
        assert_eq!(&response[4..12], &[0u8; 8]); // all four counts zero
    }

    #[tokio::test]
    async fn multi_question_queries_never_reach_an_upstream() {
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream_sock.local_addr().unwrap();
        let manager = Manager::new(
            vec![Upstream {
                name: "counting".into(),
                proto: Proto::Legacy,
                host: addr.ip().to_string(),
                port: addr.port(),
                path: String::new(),
                bootstrap_ip: Some(addr.ip()),
                timeout_ms: 50,
                ip_stack: IpStack::Both,
            }],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();
        let cache = Cache::new(false, 1);
        let query = multi_question_query();
        let meta = wire::parse_query_meta(&query);
        assert!(meta.is_none(), "multi-question queries must bypass the cache");

        for client_tcp in [false, true] {
            let response = resolve(&manager, &cache, &query, client_tcp, meta.as_ref()).await;
            assert_eq!(response.len(), 12);
            assert_eq!(&response[..2], &query[..2]);
            assert_ne!(response[2] & 0x80, 0);
            assert_eq!(response[3] & 0x0f, 1);
            assert_eq!(&response[4..12], &[0u8; 8]);
        }

        let mut buf = [0u8; 512];
        assert!(
            upstream_sock.try_recv_from(&mut buf).is_err(),
            "upstream received a packet for a FORMERR-gated query"
        );
    }
}
