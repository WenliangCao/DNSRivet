//! UDP + TCP DNS listener loops feeding the cache and upstream manager.

mod cache;

use crate::config::{Config, SplitRule, SplitTarget};
use crate::upstream::Manager;
use crate::wire;
use cache::Cache;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// Bound on concurrently in-flight queries (memory backstop).
const MAX_INFLIGHT: usize = 512;
const MAX_TCP_CONNECTIONS: usize = 64;
const MAX_TCP_INFLIGHT_PER_CONN: usize = 32;
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
    let split_rules: Arc<[SplitRule]> = config.split_dns.into();
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
            split_rules.clone(),
            inflight.clone(),
        ));
        tokio::spawn(tcp_loop(
            tcp,
            manager.clone(),
            cache.clone(),
            split_rules.clone(),
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

fn current_route_source() -> Option<IpAddr> {
    crate::upstream::encrypted::route_source(SocketAddr::from(([1, 1, 1, 1], 53))).or_else(|| {
        crate::upstream::encrypted::route_source(SocketAddr::from((
            [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111],
            53,
        )))
    })
}

/// Route checks do not send packets; spawn ipconfig only after a source change.
async fn fallback_refresh_loop(listeners: Vec<SocketAddr>, manager: Arc<Manager>) {
    let mut previous = current_route_source();
    let mut retries = 0u8;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let source = current_route_source();
        if let Some(current) = source
            && source != previous
        {
            let listeners = listeners.clone();
            match tokio::task::spawn_blocking(move || {
                crate::osdns::dhcp_fallback(current, &listeners)
            })
            .await
            {
                Ok(Ok(servers)) => {
                    log::info!("route changed; runtime system DNS fallback refreshed: {servers:?}");
                    manager.set_system_fallback(servers);
                }
                Ok(Err(err)) if retries < 3 => {
                    log::debug!("runtime DHCP DNS fallback not refreshed: {err}");
                    retries += 1;
                    continue;
                }
                Ok(Err(err)) => log::debug!("runtime DHCP DNS fallback not refreshed: {err}"),
                Err(err) => log::warn!("runtime DHCP DNS refresh task failed: {err}"),
            }
        }
        previous = source;
        retries = 0;
    }
}

/// Periodically verify the DNS takeover and repair it when an external event
/// (a macOS update rewriting network preferences, another tool) removed it.
/// The first tick fires immediately, so a daemon restarted while DNS is
/// already drifted recovers in seconds rather than a full interval.
async fn watchdog_loop(server: IpAddr, manager: Arc<Manager>) {
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
            if record_stable_tick(&mut ticks_since_reassert, &mut flap_strikes, &mut slow_mode) {
                set_watchdog_interval(&mut interval, WATCHDOG_INTERVAL);
                log::info!("DNS settings stable again; watchdog back to normal cadence");
            }
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
            last_stamp = crate::osdns::watchdog_stamp();
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
                if record_stable_tick(&mut ticks_since_reassert, &mut flap_strikes, &mut slow_mode)
                {
                    set_watchdog_interval(&mut interval, WATCHDOG_INTERVAL);
                    log::info!("DNS settings stable again; watchdog back to normal cadence");
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
                    set_watchdog_interval(&mut interval, WATCHDOG_SLOW_INTERVAL);
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

fn set_watchdog_interval(interval: &mut tokio::time::Interval, period: Duration) {
    *interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.reset();
}

fn record_stable_tick(
    ticks_since_reassert: &mut Option<u32>,
    flap_strikes: &mut u32,
    slow_mode: &mut bool,
) -> bool {
    if let Some(ticks) = ticks_since_reassert {
        *ticks += 1;
        if *ticks >= FLAP_WINDOW_TICKS {
            *ticks_since_reassert = None;
            *flap_strikes = 0;
            if *slow_mode {
                *slow_mode = false;
                return true;
            }
        }
    }
    false
}

async fn udp_loop(
    sock: Arc<UdpSocket>,
    manager: Arc<Manager>,
    cache: Arc<Cache>,
    rules: Arc<[SplitRule]>,
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
                tokio::time::sleep(Duration::from_millis(50)).await;
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
        let rules = rules.clone();
        tokio::spawn(async move {
            let response = resolve_query(&manager, &cache, &rules, &query, false).await;
            let _ = sock.send_to(&response, peer).await;
            drop(permit);
        });
    }
}

async fn tcp_loop(
    listener: TcpListener,
    manager: Arc<Manager>,
    cache: Arc<Cache>,
    rules: Arc<[SplitRule]>,
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
                let rules = rules.clone();
                let inflight = inflight.clone();
                tokio::spawn(async move {
                    let _connection = connection;
                    let _ = tcp_conn(stream, manager, cache, rules, inflight).await;
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
    split_rules: Arc<[SplitRule]>,
    inflight: Arc<Semaphore>,
) -> std::io::Result<()> {
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(Some(writer)));
    let writer_failed = Arc::new(AtomicBool::new(false));
    let conn_inflight = Arc::new(Semaphore::new(MAX_TCP_INFLIGHT_PER_CONN));
    let mut pending = tokio::task::JoinSet::new();
    loop {
        while let Some(result) = pending.try_join_next() {
            result.map_err(std::io::Error::other)??;
        }
        if writer_failed.load(Ordering::Acquire) {
            break;
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
        let Ok(permits) = tokio::time::timeout(TCP_IDLE_TIMEOUT, async {
            (
                conn_inflight.clone().acquire_owned().await.unwrap(),
                inflight.clone().acquire_owned().await.unwrap(),
            )
        })
        .await
        else {
            break;
        };
        if writer_failed.load(Ordering::Acquire) {
            break;
        }
        let manager = manager.clone();
        let cache = cache.clone();
        let rules = split_rules.clone();
        let writer = writer.clone();
        let writer_failed = writer_failed.clone();
        pending.spawn(async move {
            let _permits = permits;
            let response = resolve_query(&manager, &cache, &rules, &query, true).await;
            let frame = tcp_frame(&query, response);
            // Answers may finish out of order; serialize only the complete frame writes.
            let mut guard = writer.lock().await;
            let Some(mut stream_writer) = guard.take() else {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            };
            let result = tokio::time::timeout(TCP_IDLE_TIMEOUT, stream_writer.write_all(&frame))
                .await
                .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
            if result.is_ok() {
                *guard = Some(stream_writer);
            } else {
                writer_failed.store(true, Ordering::Release);
            }
            result
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
        response = wire::servfail_response(query);
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

async fn resolve_query(
    manager: &Manager,
    cache: &Cache,
    rules: &[SplitRule],
    query: &[u8],
    client_tcp: bool,
) -> Vec<u8> {
    let target = wire::match_domain_suffix(query, rules).map(|index| rules[index].target);
    let bypass_cache = matches!(target, Some(SplitTarget::System | SplitTarget::Direct(_)));
    let meta = (!bypass_cache).then(|| cache.query_meta(query)).flatten();
    let mut response = Vec::new();
    if !local_response(cache, query, meta.as_ref(), &mut response) {
        let answer = match target {
            Some(target) => manager.forward_split(query, client_tcp, target).await,
            None => manager.forward_answer(query, client_tcp).await,
        };
        if let Some(answer) = answer {
            if answer.cacheable
                && let Some(meta) = meta.as_ref()
            {
                cache.insert(meta, &answer.bytes);
            }
            response = answer.bytes;
        } else {
            response = wire::servfail_response(query);
        }
    }
    if !client_tcp {
        let max_payload = meta
            .as_ref()
            .map_or_else(|| wire::udp_payload_size(query), |meta| meta.udp_size);
        wire::truncate_to(&mut response, max_payload);
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

    async fn forward(
        manager: &Manager,
        cache: &Cache,
        query: &[u8],
        client_tcp: bool,
        meta: Option<&wire::QueryMeta>,
    ) -> Vec<u8> {
        let Some(answer) = manager.forward_answer(query, client_tcp).await else {
            return wire::servfail_response(query);
        };
        if answer.cacheable
            && let Some(meta) = meta
        {
            cache.insert(meta, &answer.bytes);
        }
        answer.bytes
    }

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
        let serving = tokio::spawn(udp_loop(
            listener,
            manager,
            cache,
            Arc::from([]),
            inflight.clone(),
        ));
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
                Arc::from([]),
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

    #[tokio::test(start_paused = true)]
    async fn tcp_slow_query_exceeding_idle_timeout_still_writes_response() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let manager = Arc::new(
            Manager::new(
                vec![Upstream {
                    name: "slow".into(),
                    proto: Proto::Legacy,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    path: String::new(),
                    bootstrap_ip: Some(addr.ip()),
                    timeout_ms: 20_000,
                    ip_stack: IpStack::Both,
                }],
                &[],
                Vec::new(),
            )
            .unwrap(),
        );
        let (tx_seen, mut rx_seen) = tokio::sync::mpsc::channel(1);
        let responder = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
            buf.truncate(n);
            buf[2] |= 0x80;
            tx_seen.send((buf, peer, upstream)).await.unwrap();
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
            Arc::from([]),
            Arc::new(Semaphore::new(4)),
        ));

        let query = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        client
            .write_all(&tcp_frame(&query, query.clone()))
            .await
            .unwrap();
        let (mut resp, peer, upstream) = rx_seen.recv().await.unwrap();
        responder.await.unwrap();

        // Advance past TCP_IDLE_TIMEOUT while the client keeps the TCP stream open and idle.
        tokio::time::advance(TCP_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        resp[3] = 0x80;
        upstream.send_to(&resp, peer).await.unwrap();

        let len = client.read_u16().await.unwrap() as usize;
        let mut answer = vec![0u8; len];
        client.read_exact(&mut answer).await.unwrap();
        wire::validate_response(&query, &answer).unwrap();
        assert_eq!(&answer[..2], &[0, 7]);
        serving.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_write_timeout_prevents_subsequent_frames() {
        // Unresponsive upstream with 11s timeout: marker query finishes after 10s write timeout.
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let manager = Arc::new(
            Manager::new(
                vec![Upstream {
                    name: "blackhole".into(),
                    proto: Proto::Legacy,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    path: String::new(),
                    bootstrap_ip: Some(addr.ip()),
                    timeout_ms: 11_000,
                    ip_stack: IpStack::Both,
                }],
                &[],
                Vec::new(),
            )
            .unwrap(),
        );

        let cache = Arc::new(Cache::new(true, 4));
        let cached_query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        let meta = wire::parse_query_meta(&cached_query).unwrap();
        let mut big_answer = cached_query.clone();
        big_answer[2] = 0x81;
        big_answer[3] = 0x80;
        // 250 A records = 4,019 bytes (fits Cache::insert's 4,096-byte cap).
        let rrs: u16 = 250;
        big_answer[6..8].copy_from_slice(&rrs.to_be_bytes());
        for _ in 0..rrs {
            big_answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        }
        cache.insert(&meta, &big_answer);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        nix::sys::socket::setsockopt(&listener, nix::sys::socket::sockopt::SndBuf, &1024).unwrap();
        nix::sys::socket::setsockopt(&listener, nix::sys::socket::sockopt::RcvBuf, &1024).unwrap();
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        nix::sys::socket::setsockopt(&sock, nix::sys::socket::sockopt::RcvBuf, &1024).unwrap();
        let mut client = sock.connect(listener.local_addr().unwrap()).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let serving = tokio::spawn(tcp_conn(
            stream,
            manager,
            cache,
            Arc::from([]),
            Arc::new(Semaphore::new(64)),
        ));

        // Send 1 uncached marker query (11s timeout) + 300 cached ~4 KiB responses (~1.2 MiB).
        let mut batch = Vec::new();
        let marker_query = vec![
            0x99, 0x99, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'b', 0, 0, 1, 0, 1,
        ];
        batch.extend_from_slice(&tcp_frame(&marker_query, marker_query.clone()));
        for id in 1..=300u16 {
            let mut q = cached_query.clone();
            q[..2].copy_from_slice(&id.to_be_bytes());
            batch.extend_from_slice(&tcp_frame(&q, q.clone()));
        }
        client.write_all(&batch).await.unwrap();

        // Wait until tcp_conn has read marker_query and let cached writers fill the socket buffer.
        let mut probe = [0u8; 64];
        upstream.recv_from(&mut probe).await.unwrap();
        for _ in 0..1024 {
            tokio::task::yield_now().await;
        }

        // Keep the read loop alive past t=10s by sending an ignored QR=1 packet at t=5s.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        let mut keepalive = cached_query.clone();
        keepalive[2] |= 0x80;
        client
            .write_all(&tcp_frame(&keepalive, keepalive.clone()))
            .await
            .unwrap();

        // Advance to t=10.5s so the blocked cached frame hits TCP_IDLE_TIMEOUT (10s) first,
        // then advance to t=11.5s so marker_query's 11s timeout fires and tries to write.
        tokio::time::advance(Duration::from_millis(5_500)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let _ = client.shutdown().await;

        let mut received = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = client.read(&mut buf).await {
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        let frame_len = 2 + big_answer.len();
        assert!(
            received.len() < 300 * frame_len,
            "expected write timeout to stop remaining frames, got {} bytes",
            received.len()
        );
        let complete = received.len() / frame_len;
        for i in 0..complete {
            let frame = &received[i * frame_len..(i + 1) * frame_len];
            let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
            assert_eq!(len, big_answer.len());
            let id = u16::from_be_bytes([frame[2], frame[3]]);
            assert!((1..=300).contains(&id), "unexpected frame id {id:#x}");
            assert_eq!(&frame[4..], &big_answer[2..]);
        }
        let tail = &received[complete * frame_len..];
        if tail.len() >= 2 {
            assert_eq!(
                u16::from_be_bytes([tail[0], tail[1]]) as usize,
                big_answer.len(),
                "trailing partial frame must be the interrupted big frame, not marker"
            );
        }
        if tail.len() >= 4 {
            let id = u16::from_be_bytes([tail[2], tail[3]]);
            assert!((1..=300).contains(&id), "unexpected tail frame id {id:#x}");
            assert_eq!(&tail[4..], &big_answer[2..2 + tail.len() - 4]);
        }
        assert!(serving.await.is_ok(), "tcp_conn task must not panic");
    }

    #[tokio::test]
    async fn tcp_per_conn_cap_prevents_exhausting_global_inflight() {
        let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = upstream.local_addr().unwrap();
        let (tx_seen, mut rx_seen) = tokio::sync::mpsc::channel(64);
        let upstream_rx = upstream.clone();
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = upstream_rx.recv_from(&mut buf).await {
                if tx_seen.send((buf[..n].to_vec(), peer)).await.is_err() {
                    break;
                }
            }
        });

        let manager = Arc::new(
            Manager::new(
                vec![Upstream {
                    name: "cap".into(),
                    proto: Proto::Legacy,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    path: String::new(),
                    bootstrap_ip: Some(addr.ip()),
                    timeout_ms: 2_000,
                    ip_stack: IpStack::Both,
                }],
                &[],
                Vec::new(),
            )
            .unwrap(),
        );
        let global_inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let serving = tokio::spawn(tcp_conn(
            stream,
            manager,
            Arc::new(Cache::new(false, 1)),
            Arc::from([]),
            global_inflight.clone(),
        ));

        let mut batch = Vec::new();
        for id in 0..(MAX_TCP_INFLIGHT_PER_CONN + 2) as u16 {
            let mut q = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
            q[..2].copy_from_slice(&id.to_be_bytes());
            batch.extend_from_slice(&tcp_frame(&q, q.clone()));
        }
        client.write_all(&batch).await.unwrap();
        client.shutdown().await.unwrap();

        let mut held = Vec::new();
        for _ in 0..MAX_TCP_INFLIGHT_PER_CONN {
            held.push(
                tokio::time::timeout(Duration::from_secs(1), rx_seen.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx_seen.recv())
                .await
                .is_err()
        );
        assert_eq!(
            global_inflight.available_permits(),
            MAX_INFLIGHT - MAX_TCP_INFLIGHT_PER_CONN
        );

        let (mut first_q, first_peer) = held.remove(0);
        first_q[2] |= 0x80;
        upstream.send_to(&first_q, first_peer).await.unwrap();
        held.push(
            tokio::time::timeout(Duration::from_secs(1), rx_seen.recv())
                .await
                .unwrap()
                .unwrap(),
        );
        for (mut q, peer) in held {
            q[2] |= 0x80;
            upstream.send_to(&q, peer).await.unwrap();
        }
        if let Ok(Some((mut q, peer))) =
            tokio::time::timeout(Duration::from_secs(1), rx_seen.recv()).await
        {
            q[2] |= 0x80;
            upstream.send_to(&q, peer).await.unwrap();
        }
        for _ in 0..(MAX_TCP_INFLIGHT_PER_CONN + 2) {
            let len = client.read_u16().await.unwrap() as usize;
            let mut answer = vec![0u8; len];
            client.read_exact(&mut answer).await.unwrap();
            assert_ne!(answer[2] & 0x80, 0);
        }
        serving.await.unwrap().unwrap();
        responder.abort();
    }

    #[tokio::test]
    async fn servfail_strips_edns_cookie_and_trailing_records() {
        let mut query = vec![
            0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1,
        ];
        let question_end = query.len();
        // OPT RR with 8-byte RFC 7873 COOKIE option (code 10, len 8).
        query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 12]);
        query.extend_from_slice(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);

        let manager = Manager::new(vec![], &[], Vec::new()).unwrap();
        let cache = Cache::new(false, 1);
        let resp = forward(&manager, &cache, &query, false, None).await;
        assert_eq!(resp.len(), question_end);
        assert_eq!(&resp[..2], &[0x42, 0x42]);
        assert_eq!(resp[2], 0x81);
        assert_eq!(resp[3], 0x82);
        assert_eq!(&resp[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        wire::validate_response(&query, &resp).unwrap();
    }

    #[test]
    fn record_stable_tick_exits_slow_mode_after_flap_window() {
        let mut ticks_since = Some(0);
        let mut strikes = FLAP_STRIKES;
        let mut slow_mode = true;

        assert!(!record_stable_tick(
            &mut ticks_since,
            &mut strikes,
            &mut slow_mode
        ));
        assert!(slow_mode);
        assert!(!record_stable_tick(
            &mut ticks_since,
            &mut strikes,
            &mut slow_mode
        ));
        assert!(slow_mode);
        assert!(record_stable_tick(
            &mut ticks_since,
            &mut strikes,
            &mut slow_mode
        ));
        assert!(!slow_mode);
        assert_eq!(strikes, 0);
        assert!(ticks_since.is_none());
    }

    fn named_a_query(id: u16, labels: &[&[u8]]) -> Vec<u8> {
        let mut q = Vec::from(id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in labels {
            q.push(label.len() as u8);
            q.extend_from_slice(label);
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    async fn counting_responder(
        sock: Arc<UdpSocket>,
        rcode: u8,
        ttl: u32,
        count: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            count.fetch_add(1, Ordering::Relaxed);
            let mut resp = buf[..n].to_vec();
            resp[2] = 0x81;
            resp[3] = 0x80 | rcode;
            if rcode == 0 {
                resp[6..8].copy_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                resp.extend_from_slice(&ttl.to_be_bytes());
                resp.extend_from_slice(&[0, 4, 10, 0, 0, 1]);
            } else {
                resp[8..10].copy_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1]);
                resp.extend_from_slice(&ttl.to_be_bytes());
                resp.extend_from_slice(&24u16.to_be_bytes());
                resp.extend_from_slice(&[0xc0, 0x0c, 0xc0, 0x0c]);
                resp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4]);
                resp.extend_from_slice(&ttl.to_be_bytes());
            }
            let _ = sock.send_to(&resp, peer).await;
        }
    }

    #[tokio::test]
    async fn split_dns_end_to_end_system_upstream_and_direct_with_cache_policy() {
        use std::sync::atomic::AtomicUsize;

        let default_up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let split_up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sys_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let direct_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let split_hits = Arc::new(AtomicUsize::new(0));
        let sys_hits = Arc::new(AtomicUsize::new(0));
        let direct_hits = Arc::new(AtomicUsize::new(0));

        let t1 = tokio::spawn(counting_responder(
            split_up.clone(),
            0,
            60,
            split_hits.clone(),
        ));
        let t2 = tokio::spawn(counting_responder(
            sys_sock.clone(),
            3,
            120,
            sys_hits.clone(),
        ));
        let t3 = tokio::spawn(counting_responder(
            direct_sock.clone(),
            0,
            45,
            direct_hits.clone(),
        ));

        let up0 = Upstream {
            name: "default".into(),
            proto: Proto::Legacy,
            host: default_up.local_addr().unwrap().ip().to_string(),
            port: default_up.local_addr().unwrap().port(),
            path: String::new(),
            bootstrap_ip: Some(default_up.local_addr().unwrap().ip()),
            timeout_ms: 500,
            ip_stack: IpStack::Both,
        };
        let up1 = Upstream {
            name: "corp".into(),
            proto: Proto::Legacy,
            host: split_up.local_addr().unwrap().ip().to_string(),
            port: split_up.local_addr().unwrap().port(),
            path: String::new(),
            bootstrap_ip: Some(split_up.local_addr().unwrap().ip()),
            timeout_ms: 500,
            ip_stack: IpStack::Both,
        };
        let manager = Arc::new(
            Manager::new(vec![up0, up1], &[], vec![sys_sock.local_addr().unwrap()]).unwrap(),
        );
        let cache = Arc::new(Cache::new(true, 16));
        let rules: Arc<[SplitRule]> = Arc::from([
            SplitRule {
                suffix: "corp.example".into(),
                target: SplitTarget::Upstream(1),
            },
            SplitRule {
                suffix: "home.arpa".into(),
                target: SplitTarget::System,
            },
            SplitRule {
                suffix: "lan".into(),
                target: SplitTarget::Direct(direct_sock.local_addr().unwrap()),
            },
        ]);

        // 1) Upstream split rule uses shared cache.
        let q_up = named_a_query(1, &[b"app", b"corp", b"example"]);
        let r1 = resolve_query(&manager, &cache, &rules, &q_up, false).await;
        let r2 = resolve_query(&manager, &cache, &rules, &q_up, false).await;
        assert_eq!(r1[3] & 0x0f, 0);
        assert_eq!(r2, r1);
        assert_eq!(split_hits.load(Ordering::Relaxed), 1);

        // 2) System split rule bypasses cache, preserves 120s negative TTL (no 5s rewrite),
        //    still rejects multi-question with FORMERR, and returns SERVFAIL when fallback is empty.
        let q_sys = named_a_query(2, &[b"nas", b"home", b"arpa"]);
        let s1 = resolve_query(&manager, &cache, &rules, &q_sys, false).await;
        let s2 = resolve_query(&manager, &cache, &rules, &q_sys, false).await;
        assert_eq!(s1[3] & 0x0f, 3);
        assert_eq!(s2, s1);
        assert_eq!(sys_hits.load(Ordering::Relaxed), 2);
        // SOA RR TTL at offset q_sys.len() + 6 must remain 120 (not rewritten to 5).
        let ttl_off = q_sys.len() + 6;
        assert_eq!(
            u32::from_be_bytes(s1[ttl_off..ttl_off + 4].try_into().unwrap()),
            120
        );

        let mut multi_sys = q_sys.clone();
        multi_sys[4..6].copy_from_slice(&2u16.to_be_bytes());
        multi_sys.extend_from_slice(&[1, b'x', 0, 0, 1, 0, 1]);
        let formerr_resp = resolve_query(&manager, &cache, &rules, &multi_sys, false).await;
        assert_eq!(formerr_resp.len(), 12);
        assert_eq!(formerr_resp[3] & 0x0f, 1);
        assert_eq!(sys_hits.load(Ordering::Relaxed), 2);

        manager.set_system_fallback(Vec::new());
        let sf = resolve_query(&manager, &cache, &rules, &q_sys, false).await;
        assert_eq!(sf[3] & 0x0f, 2);

        // 3) Direct split rule works over TCP and bypasses shared cache,
        //    and preserves client EDNS UDP payload size on UDP.
        let q_dir = named_a_query(3, &[b"printer", b"lan"]);
        let d1 = resolve_query(&manager, &cache, &rules, &q_dir, true).await;
        let d2 = resolve_query(&manager, &cache, &rules, &q_dir, true).await;
        assert_eq!(d1[3] & 0x0f, 0);
        assert_eq!(d2, d1);
        assert_eq!(direct_hits.load(Ordering::Relaxed), 2);

        let big_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let big_addr = big_sock.local_addr().unwrap();
        let big_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = big_sock.recv_from(&mut buf).await.unwrap();
                let mut resp = buf[..n].to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[6..8].copy_from_slice(&40u16.to_be_bytes());
                resp[10..12].fill(0);
                resp.truncate(q_dir.len());
                for _ in 0..40 {
                    resp.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1,
                    ]);
                }
                big_sock.send_to(&resp, peer).await.unwrap();
            }
        });
        let big_rules = [SplitRule {
            suffix: "big.lan".into(),
            target: SplitTarget::Direct(big_addr),
        }];
        let q_small_udp = named_a_query(4, &[b"srv", b"big", b"lan"]);
        let trunc = resolve_query(&manager, &cache, &big_rules, &q_small_udp, false).await;
        assert!(trunc.len() <= 512 && trunc[2] & 0x02 != 0);

        let mut q_edns = named_a_query(5, &[b"srv", b"big", b"lan"]);
        q_edns[11] = 1;
        q_edns.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        let full = resolve_query(&manager, &cache, &big_rules, &q_edns, false).await;
        assert!(full.len() > 512 && full[2] & 0x02 == 0);
        big_task.await.unwrap();
        assert!(default_up.try_recv_from(&mut [0u8; 512]).is_err());

        for t in [t1, t2, t3] {
            t.abort();
        }
    }
}
