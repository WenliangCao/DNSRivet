//! UDP + TCP DNS listener loops feeding the cache and upstream manager.

mod cache;

use crate::config::Config;
use crate::upstream::Manager;
use crate::wire;
use cache::Cache;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// Bound on concurrently in-flight queries (memory backstop).
const MAX_INFLIGHT: usize = 512;
const MAX_TCP_CONNECTIONS: usize = 64;
const MAX_QUERY_SIZE: usize = 4096;
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

    tokio::spawn(fallback_refresh_loop(config.listeners, manager));
    wait_for_shutdown().await;
    log::info!("shutting down");
    Ok(())
}

/// Route checks do not send packets; spawn ipconfig only after a source change.
async fn fallback_refresh_loop(listeners: Vec<std::net::SocketAddr>, manager: Arc<Manager>) {
    let mut previous = None;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let source = crate::upstream::encrypted::route_source("1.1.1.1:53".parse().unwrap())
            .or_else(|| {
                crate::upstream::encrypted::route_source(
                    "[2606:4700:4700::1111]:53".parse().unwrap(),
                )
            });
        if source == previous {
            continue;
        }
        previous = source;
        let Some(source) = source else {
            continue;
        };
        let listeners = listeners.clone();
        match tokio::task::spawn_blocking(move || crate::osdns::dhcp_fallback(source, &listeners))
            .await
        {
            Ok(Ok(servers)) => {
                log::info!("route changed; runtime system DNS fallback refreshed: {servers:?}");
                manager.set_system_fallback(servers);
            }
            Ok(Err(err)) => log::debug!("runtime DHCP DNS fallback not refreshed: {err}"),
            Err(err) => log::warn!("runtime DHCP DNS refresh task failed: {err}"),
        }
    }
}

/// Periodically verify the DNS takeover and repair it when an external event
/// (a macOS update rewriting network preferences, another tool) removed it.
/// The first tick fires immediately, so a daemon restarted while DNS is
/// already drifted recovers in seconds rather than a full interval.
async fn watchdog_loop(server: std::net::IpAddr, manager: Arc<Manager>) {
    if !nix::unistd::geteuid().is_root() {
        log::info!("takeover watchdog inactive: not running as root");
        return;
    }
    let mut interval = tokio::time::interval(WATCHDOG_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ticks_since_reassert: Option<u32> = None;
    let mut flap_strikes = 0u32;
    let mut slow_mode = false;
    let mut last_stamp = None;
    loop {
        interval.tick().await;
        let stamp = crate::osdns::watchdog_stamp();
        if stamp.is_some() && stamp == last_stamp {
            continue;
        }
        // networksetup/scutil are blocking subprocess calls; keep them off
        // the single-threaded reactor.
        let outcome =
            match tokio::task::spawn_blocking(move || crate::osdns::watchdog_tick(server)).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    log::warn!("takeover watchdog task failed: {err}");
                    continue;
                }
            };
        if outcome.is_ok() {
            last_stamp = stamp;
        }
        match outcome {
            Ok(crate::osdns::TickOutcome::NotActive) => {
                log::debug!("takeover watchdog idle: takeover not active");
            }
            Ok(crate::osdns::TickOutcome::Clean {
                captured,
                capture_error,
            }) => {
                if let Some(captured) = captured {
                    log::info!("runtime system DNS fallback refreshed: {captured:?}");
                    manager.set_system_fallback(captured);
                } else if let Some(reason) = capture_error {
                    log::debug!("runtime system DNS fallback not refreshed: {reason}");
                }
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
                capture_error,
            }) => {
                log::warn!(
                    "system DNS no longer pointed at {server} on {corrected:?}; takeover reasserted"
                );
                if captured.is_empty() {
                    log::warn!(
                        "could not capture the current network DNS; keeping the previous fallback list: {}",
                        capture_error
                            .as_deref()
                            .unwrap_or("no usable DNS server was reported")
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
    // The extra byte detects datagrams clipped by recv_from. Oversized input
    // must not be forwarded as if it were a complete, valid 4 KiB query.
    let mut buf = vec![0u8; MAX_QUERY_SIZE + 1];
    let mut last_warning = None;
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(err) => {
                if warning_due(&mut last_warning) {
                    log::warn!("udp recv error: {err}");
                }
                continue;
            }
        };
        if !(12..=MAX_QUERY_SIZE).contains(&n) || buf[2] & 0x80 != 0 {
            continue;
        }
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            if warning_due(&mut last_warning) {
                log::warn!("dropping query: {MAX_INFLIGHT} already in flight");
            }
            continue;
        };
        let query = buf[..n].to_vec();
        let sock = sock.clone();
        let manager = manager.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            let meta = cache.query_meta(&query);
            let mut response = Vec::new();
            if !local_response(&cache, &query, meta.as_ref(), &mut response) {
                response = forward(&manager, &cache, &query, false, meta.as_ref()).await;
            }
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
    let mut last_warning = None;
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(connection) = connections.clone().try_acquire_owned() else {
                    if warning_due(&mut last_warning) {
                        log::warn!("dropping TCP connection: {MAX_TCP_CONNECTIONS} already open");
                    }
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
            Err(err) => {
                if warning_due(&mut last_warning) {
                    log::warn!("tcp accept error: {err}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn warning_due(last: &mut Option<Instant>) -> bool {
    let now = Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < Duration::from_secs(1)) {
        return false;
    }
    *last = Some(now);
    true
}

/// RFC 7766: length-prefixed messages, several per connection.
async fn tcp_conn(
    stream: TcpStream,
    manager: Arc<Manager>,
    cache: Arc<Cache>,
    inflight: Arc<Semaphore>,
) -> std::io::Result<()> {
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let mut pending = tokio::task::JoinSet::new();
    loop {
        while let Some(result) = pending.try_join_next() {
            result.map_err(std::io::Error::other)??;
        }
        let mut lenbuf = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut lenbuf)).await {
            Err(_) | Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
        }
        let n = u16::from_be_bytes(lenbuf) as usize;
        if !(12..=MAX_QUERY_SIZE).contains(&n) {
            return Ok(());
        }
        let mut query = vec![0; n];
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut query)).await {
            Err(_) | Ok(Err(_)) => return Ok(()),
            Ok(Ok(_)) => {}
        }
        if query[2] & 0x80 != 0 {
            continue;
        }
        let permit = inflight
            .clone()
            .acquire_owned()
            .await
            .expect("inflight semaphore is never closed");
        let (manager, cache, writer) = (manager.clone(), cache.clone(), writer.clone());
        pending.spawn(async move {
            let _permit = permit;
            let meta = cache.query_meta(&query);
            let mut response = Vec::new();
            if !local_response(&cache, &query, meta.as_ref(), &mut response) {
                response = forward(&manager, &cache, &query, true, meta.as_ref()).await;
            }
            let frame = tcp_frame(&query, response);
            // Answers may finish out of order; serialize only the complete frame writes.
            tokio::time::timeout(TCP_IDLE_TIMEOUT, async {
                writer.lock().await.write_all(&frame).await
            })
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
        });
    }
    // A client can finish sending while still waiting for outstanding answers.
    while let Some(result) = pending.join_next().await {
        result.map_err(std::io::Error::other)??;
    }
    Ok(())
}

fn tcp_frame(query: &[u8], mut response: Vec<u8>) -> Vec<u8> {
    if response.len() > u16::MAX as usize {
        response = servfail(query);
    }
    let mut framed = Vec::with_capacity(response.len() + 2);
    framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
    framed.extend_from_slice(&response);
    framed
}

/// Share the same local-answer gate between UDP and TCP clients.
fn local_response(
    cache: &Cache,
    query: &[u8],
    meta: Option<&wire::QueryMeta>,
    response: &mut Vec<u8>,
) -> bool {
    // RFC 9619: malformed multi-question queries must never reach upstreams.
    if wire::is_multi_question_query(query) {
        *response = formerr(query);
        return true;
    }
    if let Some(meta) = meta
        && cache.get_into(meta, [query[0], query[1]], response)
    {
        let end = 12 + meta.key.qname.len();
        response[12..end].copy_from_slice(&query[12..end]);
        log::debug!("cache hit");
        return true;
    }
    false
}

async fn forward(
    manager: &Manager,
    cache: &Cache,
    query: &[u8],
    client_tcp: bool,
    meta: Option<&wire::QueryMeta>,
) -> Vec<u8> {
    let Some(answer) = manager.forward_answer(query, client_tcp).await else {
        return servfail(query);
    };
    if answer.cacheable
        && let Some(meta) = meta
    {
        cache.insert(meta, &answer.bytes);
    }
    answer.bytes
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
    async fn cached_udp_answers_preserve_ids_truncation_and_inflight_budget() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let manager = Arc::new(
            Manager::new(
                vec![Upstream {
                    name: "must remain unused".into(),
                    proto: Proto::Legacy,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    path: String::new(),
                    bootstrap_ip: Some(addr.ip()),
                    timeout_ms: 50,
                    ip_stack: IpStack::Both,
                }],
                &[],
                Vec::new(),
            )
            .unwrap(),
        );
        let cache = Arc::new(Cache::new(true, 2));
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        let meta = wire::parse_query_meta(&query).unwrap();
        let mut answer = query.clone();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[7] = 40;
        for _ in 0..40 {
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        }
        cache.insert(&meta, &answer);
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let listen_addr = listener.local_addr().unwrap();
        let inflight = Arc::new(Semaphore::new(1));
        let serving = tokio::spawn(udp_loop(listener, manager, cache, inflight.clone()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(listen_addr).await.unwrap();
        let mut response = [0; 1024];
        for id in [3u16, 9, 42] {
            query[..2].copy_from_slice(&id.to_be_bytes());
            client.send(&query).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response[..2], &query[..2]);
            assert!(n <= 512);
            assert_ne!(response[2] & 2, 0);
            wire::validate_response(&query, &response[..n]).unwrap();
        }
        query[2] |= 0x80;
        client.send(&query).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), client.recv(&mut response))
                .await
                .is_err()
        );
        query[2] &= 0x7f;
        assert!(upstream.try_recv_from(&mut [0; 512]).is_err());
        let held = inflight.acquire().await.unwrap();
        client.send(&query).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), client.recv(&mut response))
                .await
                .is_err()
        );
        drop(held);
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
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
        assert!(
            meta.is_none(),
            "multi-question queries must bypass the cache"
        );

        for client_tcp in [false, true] {
            let mut response = Vec::new();
            if !local_response(&cache, &query, meta.as_ref(), &mut response) {
                response = forward(&manager, &cache, &query, client_tcp, meta.as_ref()).await;
            }
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
    #[tokio::test]
    async fn fallback_answers_bypass_cache_and_cache_hits_echo_question_case() {
        let query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        let mut answer = query.clone();
        answer[2] |= 0x80;
        answer[7] = 1;
        answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let manager = Manager::new(vec![], &[], vec![socket.local_addr().unwrap()]).unwrap();
        let sent = answer.clone();
        let responder = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (_, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut sent = sent;
            sent[..2].copy_from_slice(&buf[..2]);
            socket.send_to(&sent, peer).await.unwrap();
        });
        let cache = Cache::new(true, 2);
        let meta = cache.query_meta(&query).unwrap();
        assert_eq!(
            forward(&manager, &cache, &query, false, Some(&meta)).await,
            answer
        );
        assert!(!local_response(
            &cache,
            &query,
            Some(&meta),
            &mut Vec::new()
        ));
        responder.await.unwrap();
        cache.insert(&meta, &answer);
        let mut upper = query.clone();
        upper[13] = b'A';
        let mut response = Vec::new();
        assert!(local_response(&cache, &upper, Some(&meta), &mut response));
        assert_eq!(response[13], b'A');
        assert!(local_response(&cache, &query, Some(&meta), &mut response));
        assert_eq!(response[13], b'a');
    }
    #[tokio::test]
    async fn tcp_pipelining_returns_fast_answers_without_waiting_for_slow_queries() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = upstream.local_addr().unwrap();
            let manager = Arc::new(
                Manager::new(
                    vec![Upstream {
                        name: "pipelined".into(),
                        proto: Proto::Legacy,
                        host: address.ip().to_string(),
                        port: address.port(),
                        path: String::new(),
                        bootstrap_ip: Some(address.ip()),
                        timeout_ms: 5000,
                        ip_stack: IpStack::Both,
                    }],
                    &[],
                    vec![],
                )
                .unwrap(),
            );
            let responder = tokio::spawn(async move {
                let mut responses = Vec::new();
                for _ in 0..2 {
                    let mut packet = vec![0; 512];
                    let (n, peer) = upstream.recv_from(&mut packet).await.unwrap();
                    packet.truncate(n);
                    packet[2] |= 0x80;
                    responses.push((packet, peer));
                }
                responses.sort_by_key(|(packet, _)| std::cmp::Reverse(packet[13]));
                for (packet, peer) in responses {
                    upstream.send_to(&packet, peer).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let serving = tokio::spawn(tcp_conn(
                stream,
                manager,
                Arc::new(Cache::new(false, 1)),
                Arc::new(Semaphore::new(2)),
            ));
            let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
            let mut frames = tcp_frame(&query, query.clone());
            query[1] = 2;
            query[13] = b'b';
            frames.extend_from_slice(&tcp_frame(&query, query.clone()));
            client.write_all(&frames).await.unwrap();
            client.shutdown().await.unwrap();
            for id in [2, 1] {
                let len = client.read_u16().await.unwrap();
                let mut answer = vec![0; len as usize];
                client.read_exact(&mut answer).await.unwrap();
                assert_eq!(answer[1], id);
                assert_ne!(answer[2] & 0x80, 0);
            }
            serving.await.unwrap().unwrap();
            responder.await.unwrap();
        })
        .await
        .expect("the peer must receive both pipelined queries before answering");
    }

    #[test]
    fn oversized_tcp_answers_become_well_formed_servfail_frames() {
        let query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        let frame = tcp_frame(&query, vec![0; 65_536]);
        assert_eq!(
            u16::from_be_bytes([frame[0], frame[1]]) as usize,
            frame.len() - 2
        );
        assert_eq!(frame[5] & 15, 2);
        wire::validate_response(&query, &frame[2..]).unwrap();
    }
}
