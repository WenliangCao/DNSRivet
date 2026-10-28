pub mod bootstrap;
pub mod encrypted;
pub mod legacy;

use crate::config::{IpStack, Proto, Upstream};
use bootstrap::Bootstrap;
use hickory_net::proto::op::{Message, MessageType, OpCode};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Includes hedged attempts still running after their client has been answered.
const MAX_ATTEMPTS: usize = 512;

/// How long an upstream may stay silent before the next one is queried in
/// parallel. Well above a warm DoH/DoH3 round trip, so healthy upstreams
/// rarely trigger it, yet far below the default 5s timeout that would
/// otherwise stall every query while a transport is silently dropped (e.g.
/// UDP/443 loss breaking DoH3 while DoH still works).
const HEDGE_DELAY: Duration = Duration::from_millis(300);

/// Ordered-failover view over the configured upstreams.
pub struct Manager {
    entries: Vec<Arc<Entry>>,
    attempts: Arc<Semaphore>,
    /// Runtime-refreshable: the watchdog swaps in the current network's DNS
    /// when it recovers a lost takeover. Never persisted to the backup.
    system_fallback: std::sync::RwLock<Vec<SocketAddr>>,
    fallback_active: AtomicBool,
    fallback_failed: AtomicBool,
}

struct Entry {
    name: String,
    timeout_ms: u64,
    backend: Backend,
}

/// Borrow on the single-upstream path; own only when tasks can outlive forward.
/// Encrypted attempts share one lazy parse, including failed parses.
struct Request<'a> {
    bytes: Cow<'a, [u8]>,
    parsed: OnceLock<Result<Message, String>>,
}

impl<'a> Request<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
            parsed: OnceLock::new(),
        }
    }

    fn into_owned(self) -> Request<'static> {
        Request {
            bytes: Cow::Owned(self.bytes.into_owned()),
            parsed: self.parsed,
        }
    }

    fn message(&self) -> Result<&Message, String> {
        self.parsed
            .get_or_init(|| {
                let message = Message::from_vec(&self.bytes)
                    .map_err(|e| format!("unparseable query: {e}"))?;
                if !safe_encrypted_query(&message) {
                    return Err("unsupported query shape for encrypted forwarding".into());
                }
                Ok(message)
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

enum Backend {
    Legacy {
        host: String,
        port: u16,
        ip: Option<IpAddr>,
        stack: IpStack,
        bootstrap: Arc<Bootstrap>,
        deny: Arc<Vec<SocketAddr>>,
    },
    Encrypted(encrypted::Channel),
}

impl Manager {
    pub fn new(
        all: Vec<Upstream>,
        listeners: &[SocketAddr],
        system_fallback: Vec<SocketAddr>,
    ) -> Result<Self, String> {
        let boot = Arc::new(Bootstrap::new());
        let deny = Arc::new(listeners.to_vec());
        let needs_tls = all.iter().any(|up| up.proto != Proto::Legacy);
        let tls = needs_tls.then(|| Arc::new(encrypted::base_tls_config()));

        let mut entries = Vec::new();
        for up in all {
            // Static-address self-loop is a config error, not a runtime skip.
            if let Some(ip) = up.bootstrap_ip
                && is_self_address(SocketAddr::new(ip, up.port), listeners)
            {
                return Err(format!(
                    "upstream {}: endpoint {}:{} points at our own listener",
                    up.name, ip, up.port
                ));
            }
            let name = up.name.clone();
            let timeout_ms = up.timeout_ms;
            let backend = match up.proto {
                Proto::Legacy => Backend::Legacy {
                    host: up.host,
                    port: up.port,
                    ip: up.bootstrap_ip,
                    stack: up.ip_stack,
                    bootstrap: boot.clone(),
                    deny: deny.clone(),
                },
                _ => Backend::Encrypted(encrypted::Channel::new(
                    up,
                    tls.clone()
                        .expect("tls config built when encrypted upstreams exist"),
                    boot.clone(),
                    deny.clone(),
                )),
            };
            entries.push(Arc::new(Entry {
                name,
                timeout_ms,
                backend,
            }));
        }
        Ok(Self {
            entries,
            attempts: Arc::new(Semaphore::new(MAX_ATTEMPTS)),
            system_fallback: std::sync::RwLock::new(system_fallback),
            fallback_active: AtomicBool::new(false),
            fallback_failed: AtomicBool::new(false),
        })
    }

    /// Replace the runtime fallback list. Callers must pass a non-empty,
    /// freshly captured list; an empty capture keeps the previous one.
    pub fn set_system_fallback(&self, servers: Vec<SocketAddr>) {
        *self.system_fallback.write().unwrap() = servers;
    }

    /// Try each upstream in config order; None when all of them failed.
    /// An upstream silent for [`HEDGE_DELAY`] is raced against the next one
    /// rather than waited out. `client_tcp` enables the TC-triggered TCP
    /// retry on legacy upstreams.
    pub async fn forward(&self, query: &[u8], client_tcp: bool) -> Option<Vec<u8>> {
        let request = Request::new(query);
        let response = if let [entry] = self.entries.as_slice() {
            // No task, owned query copy, or JoinSet for the common single-upstream case.
            let _permit = self.attempts.try_acquire().ok()?;
            self.configured_answer(&entry.name, query, entry.run(&request, client_tcp).await)
        } else {
            self.forward_hedged(Arc::new(request.into_owned()), client_tcp)
                .await
        };
        match response {
            Some(response) => Some(response),
            None => self.forward_to_system(query, client_tcp).await,
        }
    }

    async fn forward_hedged(
        &self,
        shared: Arc<Request<'static>>,
        client_tcp: bool,
    ) -> Option<Vec<u8>> {
        let query = shared.bytes.as_ref();
        let mut attempts = JoinSet::new();
        let mut legacy_attempts = Vec::new();
        let mut next = 0;
        // When to start the next upstream while earlier ones are pending.
        let mut hedge_at = None;

        loop {
            let due = hedge_at.is_some_and(|at| Instant::now() >= at);
            if attempts.is_empty() || due {
                hedge_at = None;
                let Some(entry) = self.entries.get(next) else {
                    if attempts.is_empty() {
                        break;
                    }
                    continue;
                };
                let Ok(permit) = self.attempts.clone().try_acquire_owned() else {
                    if attempts.is_empty() {
                        break;
                    }
                    // Disable this hedge, not this upstream: retry it in order
                    // when a pending attempt completes and returns its permit.
                    continue;
                };
                let index = next;
                next += 1;
                log::debug!(
                    "trying upstream {} (timeout {}ms)",
                    entry.name,
                    entry.timeout_ms
                );
                // A `timeout = 0` upstream is waited on forever by contract:
                // it is never raced, and never started as a race either,
                // since a detached attempt without a deadline would leak.
                let racer = self.entries.get(next);
                if entry.timeout_ms > 0 && racer.is_some_and(|racer| racer.timeout_ms > 0) {
                    hedge_at = Some(Instant::now() + HEDGE_DELAY);
                }
                let is_legacy = matches!(entry.backend, Backend::Legacy { .. });
                let (entry, query) = (entry.clone(), shared.clone());
                let mut attempt = Box::pin(async move {
                    let _permit = permit;
                    (index, entry.run(&query, client_tcp).await)
                });
                if attempts.is_empty() {
                    // Poll in the caller until we actually need a race. The
                    // owned, pinned future can then move unchanged into a task;
                    // no query is restarted and its original deadline is kept.
                    let completed = tokio::select! {
                        biased;
                        finished = &mut attempt => Some(finished),
                        () = wait_for_hedge(hedge_at) => None,
                    };
                    if let Some((_, result)) = completed {
                        if let Some(response) = self.configured_answer(
                            &self.entries[index].name,
                            shared.bytes.as_ref(),
                            result,
                        ) {
                            return Some(response);
                        }
                        continue;
                    }
                }
                let abort = attempts.spawn(attempt);
                if is_legacy {
                    legacy_attempts.push(abort);
                }
                continue;
            }

            let (index, result) = tokio::select! {
                Some(joined) = attempts.join_next() => match joined {
                    Ok(finished) => finished,
                    Err(err) => {
                        log::debug!("upstream attempt aborted: {err}");
                        continue;
                    }
                },
                () = wait_for_hedge(hedge_at) => {
                    let slow = &self.entries[next - 1].name;
                    log::debug!("upstream {slow} slow; racing the next upstream");
                    continue;
                }
            };
            let Some(response) = self.configured_answer(&self.entries[index].name, query, result)
            else {
                continue;
            };
            // Legacy attempts have no connection health to maintain. Encrypted
            // losers keep their budget until their own deadline so stalled
            // channels still invalidate and back off without unbounded work.
            for attempt in legacy_attempts {
                attempt.abort();
            }
            attempts.detach_all();
            return Some(response);
        }
        None
    }

    fn configured_answer(
        &self,
        name: &str,
        query: &[u8],
        result: Result<Vec<u8>, String>,
    ) -> Option<Vec<u8>> {
        let mut response = match result {
            Ok(response) => response,
            Err(err) => {
                log::debug!("upstream {name}: {err}");
                return None;
            }
        };
        // Every backend validates before returning from Entry::attempt. Do not
        // parse the same question again here; this layer only selects answers.
        if response[3] & 0x0f == 2 {
            log::debug!("upstream {name}: SERVFAIL; waiting for another upstream");
            return None;
        }
        let fallback_was_active = self.fallback_active.swap(false, Ordering::Relaxed);
        let fallback_had_failed = self.fallback_failed.swap(false, Ordering::Relaxed);
        if fallback_was_active {
            log::info!("configured DNS upstreams recovered; system fallback inactive");
        } else if fallback_had_failed {
            log::info!("configured DNS upstreams recovered after a SERVFAIL episode");
        }
        // Transports may rewrite the DNS ID (DoQ pins it to 0).
        response[..2].copy_from_slice(&query[..2]);
        Some(response)
    }

    async fn forward_to_system(&self, query: &[u8], client_tcp: bool) -> Option<Vec<u8>> {
        let _permit = self.attempts.try_acquire().ok()?;
        // Snapshot and drop the guard before any await: the read guard is not
        // Send, and holding it would also block the watchdog's refresh.
        let system_fallback: Vec<SocketAddr> = self.system_fallback.read().unwrap().clone();
        if system_fallback.is_empty() {
            if !self.fallback_failed.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "all configured upstreams failed and no system DNS fallback is available; returning SERVFAIL"
                );
            }
            return None;
        }
        if !self.fallback_active.swap(true, Ordering::Relaxed) {
            log::warn!("all configured upstreams failed; using pre-takeover system DNS directly");
        }
        for server in &system_fallback {
            let attempt = legacy::query(*server, query, client_tcp);
            match tokio::time::timeout(Duration::from_secs(2), attempt).await {
                Ok(Ok(response)) => {
                    // legacy::query already checks the ID and question, including TCP retries.
                    if response[3] & 0x0f == 2 {
                        log::debug!("system DNS fallback {server}: SERVFAIL");
                        continue;
                    }
                    if self.fallback_failed.swap(false, Ordering::Relaxed) {
                        log::info!("system DNS fallback recovered");
                    }
                    return Some(response);
                }
                Ok(Err(err)) => log::debug!("system DNS fallback {server}: {err}"),
                Err(_) => log::debug!("system DNS fallback {server}: timeout after 2000ms"),
            }
        }
        if !self.fallback_failed.swap(true, Ordering::Relaxed) {
            log::warn!("system DNS fallback also failed; returning SERVFAIL");
        }
        None
    }
}

async fn wait_for_hedge(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

impl Entry {
    /// Legacy transports have no internal deadline, so the outer timeout is
    /// exact for them; encrypted channels time out internally, and the outer
    /// bound only catches a stuck channel, with a small scheduling margin.
    fn outer_timeout(&self) -> Option<Duration> {
        if self.timeout_ms == 0 {
            return None;
        }
        let base = Duration::from_millis(self.timeout_ms);
        Some(match self.backend {
            Backend::Legacy { .. } => base,
            Backend::Encrypted(_) => base + Duration::from_millis(250),
        })
    }

    async fn run(&self, request: &Request<'_>, client_tcp: bool) -> Result<Vec<u8>, String> {
        // Encrypted channels enforce this deadline themselves so their
        // invalidation stays generation-precise; the outer timeout below is a
        // pure scheduling backstop with no channel side effects.
        let deadline =
            (self.timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(self.timeout_ms));
        let attempt = self.attempt(request, client_tcp, deadline);
        match self.outer_timeout() {
            Some(limit) => tokio::time::timeout(limit, attempt)
                .await
                .unwrap_or_else(|_| Err(format!("timeout after {}ms", self.timeout_ms))),
            None => attempt.await,
        }
    }

    async fn attempt(
        &self,
        request: &Request<'_>,
        client_tcp: bool,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>, String> {
        let query = request.bytes.as_ref();
        match &self.backend {
            Backend::Legacy {
                host,
                port,
                ip,
                stack,
                bootstrap,
                deny,
            } => {
                if let Some(ip) = ip {
                    return legacy::query(SocketAddr::new(*ip, *port), query, client_tcp).await;
                }
                let ips = bootstrap.resolve(host, *stack).await?;
                let mut last_err = None;
                for ip in ips {
                    let addr = SocketAddr::new(ip, *port);
                    if is_self_address(addr, deny) {
                        last_err = Some(format!("{addr} points back at our own listener"));
                        continue;
                    }
                    match legacy::query(addr, query, client_tcp).await {
                        Ok(response) => return Ok(response),
                        Err(err) => last_err = Some(err),
                    }
                }
                Err(last_err.unwrap_or_else(|| "no addresses".into()))
            }
            Backend::Encrypted(channel) => {
                let response = channel.query(request.message()?, deadline).await?;
                crate::wire::validate_response(query, &response)
                    .map_err(|err| format!("rejected response: {err}"))?;
                Ok(response)
            }
        }
    }
}

/// One self-dial rule for literal, bootstrap-resolved, and encrypted targets.
fn is_self_address(addr: SocketAddr, listeners: &[SocketAddr]) -> bool {
    let ip = addr.ip().to_canonical();
    listeners.iter().any(|listener| {
        listener.port() == addr.port()
            && (listener.ip().to_canonical() == ip || ip.is_loopback() || ip.is_unspecified())
    })
}

/// Encrypted transports re-encode requests. Keep the supported stub-query
/// shape bounded: one question, no resource records or signatures, and an
/// optional EDNS record, even with the patched encoder.
fn safe_encrypted_query(message: &Message) -> bool {
    message.metadata.message_type == MessageType::Query
        && message.metadata.op_code == OpCode::Query
        && message.queries.len() == 1
        && message.answers.is_empty()
        && message.authorities.is_empty()
        && message.additionals.is_empty()
        && message.signature.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::op::Query;
    use hickory_net::proto::rr::{Name, RData, Record, RecordType, rdata::A};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use tokio::net::UdpSocket;

    #[test]
    fn requests_borrow_until_shared_and_parse_encrypted_queries_only_once() {
        let query = labeled_query(1);
        let request = Request::new(&query);
        assert!(matches!(request.bytes, Cow::Borrowed(_)));
        assert!(
            request.parsed.get().is_none(),
            "legacy forwarding must not parse"
        );
        let shared = Arc::new(request.into_owned());
        let next_attempt = shared.clone();
        assert!(std::ptr::eq(
            shared.message().unwrap(),
            next_attempt.message().unwrap()
        ));
        assert_eq!(shared.bytes.as_ref(), query);

        let invalid = Request::new(&[0; 12]);
        assert!(invalid.message().is_err());
        assert!(invalid.parsed.get().unwrap().is_err());
    }

    #[test]
    fn self_dial_checks_normalize_mapped_addresses_and_keep_remote_targets() {
        let listeners = [
            "127.0.0.1:53".parse().unwrap(),
            "192.0.2.1:5354".parse().unwrap(),
        ];
        for addr in [
            "127.0.0.2:53",
            "[::1]:53",
            "[::ffff:127.0.0.1]:53",
            "0.0.0.0:53",
            "192.0.2.1:5354",
        ] {
            assert!(is_self_address(addr.parse().unwrap(), &listeners), "{addr}");
        }
        for addr in ["127.0.0.1:853", "192.0.2.2:53", "[2001:db8::53]:53"] {
            assert!(
                !is_self_address(addr.parse().unwrap(), &listeners),
                "{addr}"
            );
        }
    }

    #[test]
    fn encrypted_encoder_accepts_only_single_question_queries() {
        use hickory_net::proto::op::Edns;
        use hickory_net::proto::rr::{
            DNSClass,
            rdata::{TSIG, tsig::TsigAlgorithm},
        };

        let name = Name::from_str("example.com.").unwrap();
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(name.clone(), RecordType::A));
        for edns in [None, Some(Edns::new())] {
            query.edns = edns;
            assert!(Request::new(&query.to_vec().unwrap()).message().is_ok());
        }

        // Exercise the encoder and parser boundary, not only the in-memory guard:
        // the new Message API separates authorities, EDNS, and TSIG fields.
        let record = Record::from_rdata(name.clone(), 60, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let mut invalid = Vec::new();
        let mut message = query.clone();
        message.answers.push(record.clone());
        invalid.push(message);
        let mut message = query.clone();
        message.authorities.push(record.clone());
        invalid.push(message);
        let mut message = query.clone();
        message.additionals.push(record);
        invalid.push(message);
        let mut message = query.clone();
        message.queries.clear();
        invalid.push(message);
        let mut message = query.clone();
        message.queries.push(message.queries[0].clone());
        invalid.push(message);
        let mut message = query.clone();
        message.metadata.message_type = MessageType::Response;
        invalid.push(message);
        let mut message = query.clone();
        message.metadata.op_code = OpCode::Update;
        invalid.push(message);
        let mut message = query;
        let mut signature = Record::from_rdata(
            name,
            0,
            TSIG::new(
                TsigAlgorithm::HmacSha256,
                0,
                300,
                Vec::new(),
                0,
                None,
                Vec::new(),
            ),
        );
        signature.dns_class = DNSClass::ANY;
        message.signature = Some(Box::new(signature));
        invalid.push(message);

        for message in invalid {
            let bytes = message.to_vec().unwrap();
            let parsed =
                Message::from_vec(&bytes).expect("fixture must be a decodable DNS message");
            assert!(!safe_encrypted_query(&parsed), "{parsed:?}");
            assert!(Request::new(&bytes).message().is_err());
        }
    }

    #[tokio::test]
    async fn exhausted_upstreams_use_direct_system_fallback() {
        let fallback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (n, peer) = fallback.recv_from(&mut query).await.unwrap();
            query[2] |= 0x80;
            query[3] |= 0x80;
            fallback.send_to(&query[..n], peer).await.unwrap();
        });

        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        let upstream = Upstream {
            name: "dead primary".into(),
            proto: Proto::Legacy,
            host: dead_addr.ip().to_string(),
            port: dead_addr.port(),
            path: String::new(),
            bootstrap_ip: Some(dead_addr.ip()),
            timeout_ms: 20,
            ip_stack: IpStack::Both,
        };
        let manager = Manager::new(
            vec![upstream],
            &["127.0.0.1:5354".parse().unwrap()],
            vec![fallback_addr],
        )
        .unwrap();
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        let response = manager.forward(&query, false).await.unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_ne!(response[2] & 0x80, 0);
        assert!(manager.fallback_active.load(Ordering::Relaxed));
        assert!(!manager.fallback_failed.load(Ordering::Relaxed));
        responder.await.unwrap();
        drop(dead);
    }

    fn test_upstream(name: &str, addr: SocketAddr, timeout_ms: u64) -> Upstream {
        Upstream {
            name: name.into(),
            proto: Proto::Legacy,
            host: addr.ip().to_string(),
            port: addr.port(),
            path: String::new(),
            bootstrap_ip: Some(addr.ip()),
            timeout_ms,
            ip_stack: IpStack::Both,
        }
    }

    const TEST_QUERY: [u8; 17] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x01,
    ];

    /// Documented hazard, locked in as a regression test: with an explicit
    /// `timeout = 0`, a black-holed first upstream hangs the query forever and
    /// the healthy second upstream is never consulted.
    #[tokio::test]
    async fn zero_timeout_never_fails_over_past_a_blackhole() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let healthy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let manager = Manager::new(
            vec![
                test_upstream("blackhole", blackhole.local_addr().unwrap(), 0),
                test_upstream("healthy", healthy.local_addr().unwrap(), 0),
            ],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        let pending = tokio::time::timeout(
            Duration::from_millis(300),
            manager.forward(&TEST_QUERY, false),
        )
        .await;
        assert!(pending.is_err(), "timeout=0 must hang, not fail over");

        let mut buf = [0u8; 512];
        assert!(blackhole.try_recv_from(&mut buf).is_ok());
        assert!(
            healthy.try_recv_from(&mut buf).is_err(),
            "healthy upstream must receive zero packets"
        );
    }

    fn labeled_query(id: u16) -> Vec<u8> {
        let mut query = Vec::from(id.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        query.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        query
    }

    /// Spawn a UDP responder that echoes with QR set; `mutate_name` turns it
    /// into a liar answering a different question.
    async fn udp_responder(mutate_name: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut message = [0u8; 512];
            let (n, peer) = sock.recv_from(&mut message).await.unwrap();
            message[2] |= 0x80;
            if mutate_name {
                message[13] = b'z';
            }
            sock.send_to(&message[..n], peer).await.unwrap();
        });
        (addr, task)
    }

    #[tokio::test]
    async fn responses_answering_a_different_question_are_rejected() {
        let (liar_addr, liar) = udp_responder(true).await;
        let (healthy_addr, healthy) = udp_responder(false).await;
        let manager = Manager::new(
            vec![
                test_upstream("liar", liar_addr, 200),
                test_upstream("healthy", healthy_addr, 200),
            ],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        let query = labeled_query(0x4242);
        let response = manager.forward(&query, false).await.unwrap();
        assert_eq!(response[13], b'a', "answer must echo the real question");
        liar.await.unwrap();
        healthy.await.unwrap();
    }

    #[tokio::test]
    async fn fallback_responses_are_validated_too() {
        let (liar_addr, liar) = udp_responder(true).await;
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let manager = Manager::new(
            vec![test_upstream("dead", dead.local_addr().unwrap(), 20)],
            &["127.0.0.1:5354".parse().unwrap()],
            vec![liar_addr],
        )
        .unwrap();

        let query = labeled_query(0x4243);
        assert!(manager.forward(&query, false).await.is_none());
        assert!(manager.fallback_failed.load(Ordering::Relaxed));
        liar.await.unwrap();
        drop(dead);
    }

    /// Control group: any positive timeout restores ordered failover.
    #[tokio::test]
    async fn bounded_timeout_fails_over_to_the_healthy_upstream() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let healthy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let healthy_addr = healthy.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (n, peer) = healthy.recv_from(&mut query).await.unwrap();
            query[2] |= 0x80;
            healthy.send_to(&query[..n], peer).await.unwrap();
        });

        let manager = Manager::new(
            vec![
                test_upstream("blackhole", blackhole.local_addr().unwrap(), 200),
                test_upstream("healthy", healthy_addr, 200),
            ],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        let response = manager.forward(&TEST_QUERY, false).await.unwrap();
        assert_eq!(&response[..2], &TEST_QUERY[..2]);
        assert_ne!(response[2] & 0x80, 0);
        responder.await.unwrap();

        let mut buf = [0u8; 512];
        assert!(blackhole.try_recv_from(&mut buf).is_ok());
    }

    #[tokio::test]
    async fn silent_upstream_is_raced_well_before_its_timeout() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (healthy_addr, healthy) = udp_responder(false).await;
        let manager = Manager::new(
            vec![
                test_upstream("blackhole", blackhole.local_addr().unwrap(), 5000),
                test_upstream("healthy", healthy_addr, 5000),
            ],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        let started = Instant::now();
        let response = manager.forward(&TEST_QUERY, false).await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(&response[..2], &TEST_QUERY[..2]);
        assert!(elapsed >= HEDGE_DELAY, "raced too early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "waited out: {elapsed:?}");
        healthy.await.unwrap();

        let mut buf = [0u8; 512];
        assert!(blackhole.try_recv_from(&mut buf).is_ok());
    }

    #[tokio::test]
    async fn servfail_racer_does_not_discard_a_successful_primary() {
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let backup = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backup_addr = backup.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut primary_query = [0u8; 512];
            let (n, peer) = primary.recv_from(&mut primary_query).await.unwrap();
            let mut backup_query = [0u8; 512];
            let (m, backup_peer) = backup.recv_from(&mut backup_query).await.unwrap();
            backup_query[2] |= 0x80;
            backup_query[3] = 0x82;
            backup
                .send_to(&backup_query[..m], backup_peer)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            primary_query[2] |= 0x80;
            primary.send_to(&primary_query[..n], peer).await.unwrap();
        });
        let manager = Manager::new(
            vec![
                test_upstream("slow success", primary_addr, 1000),
                test_upstream("fast SERVFAIL", backup_addr, 1000),
            ],
            &[],
            Vec::new(),
        )
        .unwrap();
        let response = manager.forward(&TEST_QUERY, false).await.unwrap();
        assert_eq!(response[3] & 0x0f, 0);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn negative_answers_are_not_treated_as_server_failure() {
        for rcode in [0, 3, 5] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = server.local_addr().unwrap();
            let responder = tokio::spawn(async move {
                let mut query = [0u8; 512];
                let (n, peer) = server.recv_from(&mut query).await.unwrap();
                query[2] |= 0x80;
                query[3] = 0x80 | rcode;
                server.send_to(&query[..n], peer).await.unwrap();
            });
            let manager =
                Manager::new(vec![test_upstream("answer", addr, 1000)], &[], Vec::new()).unwrap();
            let response = manager.forward(&TEST_QUERY, false).await.unwrap();
            assert_eq!(response[3] & 0x0f, rcode);
            responder.await.unwrap();
        }
    }

    #[tokio::test]
    async fn losing_legacy_attempts_release_their_budget_before_the_timeout() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (healthy_addr, healthy) = udp_responder(false).await;
        let manager = Manager::new(
            vec![
                test_upstream("blackhole", blackhole.local_addr().unwrap(), 5000),
                test_upstream("healthy", healthy_addr, 5000),
            ],
            &[],
            Vec::new(),
        )
        .unwrap();
        manager.forward(&TEST_QUERY, false).await.unwrap();
        healthy.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(manager.attempts.available_permits(), MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn promoting_a_slow_attempt_to_a_task_never_resends_it() {
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (backup_addr, backup) = udp_responder(false).await;
        let manager = Manager::new(
            vec![
                test_upstream("slow", primary.local_addr().unwrap(), 5000),
                test_upstream("backup", backup_addr, 5000),
            ],
            &[],
            Vec::new(),
        )
        .unwrap();
        manager.forward(&TEST_QUERY, false).await.unwrap();
        backup.await.unwrap();
        tokio::task::yield_now().await;
        let mut packet = [0; 512];
        assert!(primary.try_recv_from(&mut packet).is_ok());
        assert!(
            primary.try_recv_from(&mut packet).is_err(),
            "moving the future must not restart the request"
        );
        assert_eq!(manager.attempts.available_permits(), MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn cancelling_an_inline_multi_upstream_attempt_releases_its_budget() {
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backup = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let manager = Manager::new(
            vec![
                test_upstream("slow", primary.local_addr().unwrap(), 5000),
                test_upstream("backup", backup.local_addr().unwrap(), 5000),
            ],
            &[],
            Vec::new(),
        )
        .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                manager.forward(&TEST_QUERY, false)
            )
            .await
            .is_err()
        );
        assert_eq!(manager.attempts.available_permits(), MAX_ATTEMPTS);
        assert!(backup.try_recv_from(&mut [0; 512]).is_err());
    }

    #[tokio::test]
    async fn budget_blocked_hedge_still_tries_the_backup_after_primary_timeout() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (healthy_addr, healthy) = udp_responder(false).await;
        let manager = Manager::new(
            vec![
                test_upstream("blackhole", blackhole.local_addr().unwrap(), 400),
                test_upstream("healthy", healthy_addr, 1000),
            ],
            &[],
            Vec::new(),
        )
        .unwrap();
        let _reserved = manager
            .attempts
            .acquire_many((MAX_ATTEMPTS - 1) as u32)
            .await
            .unwrap();
        let response =
            tokio::time::timeout(Duration::from_secs(2), manager.forward(&TEST_QUERY, false))
                .await
                .unwrap()
                .expect("the backup must not be skipped when the hedge has no budget");
        assert_eq!(response[3] & 0x0f, 0);
        healthy.await.unwrap();
        assert_eq!(manager.attempts.available_permits(), 1);
    }

    #[tokio::test]
    async fn exhausted_attempt_budget_never_opens_an_upstream_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let manager = Manager::new(
            vec![test_upstream("blocked", server.local_addr().unwrap(), 1000)],
            &[],
            vec![server.local_addr().unwrap()],
        )
        .unwrap();
        let _reserved = manager
            .attempts
            .acquire_many(MAX_ATTEMPTS as u32)
            .await
            .unwrap();
        assert!(manager.forward(&TEST_QUERY, false).await.is_none());
        assert!(server.try_recv_from(&mut [0; 512]).is_err());
    }

    #[tokio::test]
    async fn zero_timeout_upstream_is_never_started_as_a_race() {
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let slow_answer = tokio::spawn(async move {
            let mut message = [0u8; 512];
            let (n, peer) = primary.recv_from(&mut message).await.unwrap();
            tokio::time::sleep(HEDGE_DELAY + Duration::from_millis(100)).await;
            message[2] |= 0x80;
            primary.send_to(&message[..n], peer).await.unwrap();
        });
        let unbounded = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let manager = Manager::new(
            vec![
                test_upstream("slow primary", primary_addr, 5000),
                test_upstream("unbounded", unbounded.local_addr().unwrap(), 0),
            ],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        manager.forward(&TEST_QUERY, false).await.unwrap();
        slow_answer.await.unwrap();
        let mut buf = [0u8; 512];
        assert!(
            unbounded.try_recv_from(&mut buf).is_err(),
            "a deadline-free attempt must not be raced and then detached"
        );
    }

    #[tokio::test]
    async fn answering_upstream_is_not_raced() {
        let (primary_addr, primary) = udp_responder(false).await;
        let standby = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let manager = Manager::new(
            vec![
                test_upstream("primary", primary_addr, 5000),
                test_upstream("standby", standby.local_addr().unwrap(), 5000),
            ],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        manager.forward(&TEST_QUERY, false).await.unwrap();
        primary.await.unwrap();
        tokio::time::sleep(HEDGE_DELAY + Duration::from_millis(100)).await;
        let mut buf = [0u8; 512];
        assert!(
            standby.try_recv_from(&mut buf).is_err(),
            "standby must not see queries the primary answered"
        );
    }

    #[tokio::test]
    async fn exhausted_upstreams_record_missing_system_fallback_once() {
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        let upstream = Upstream {
            name: "dead primary".into(),
            proto: Proto::Legacy,
            host: dead_addr.ip().to_string(),
            port: dead_addr.port(),
            path: String::new(),
            bootstrap_ip: Some(dead_addr.ip()),
            timeout_ms: 20,
            ip_stack: IpStack::Both,
        };
        let manager = Manager::new(
            vec![upstream],
            &["127.0.0.1:5354".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        assert!(manager.forward(&query, false).await.is_none());
        assert!(manager.fallback_failed.load(Ordering::Relaxed));
        assert!(!manager.fallback_active.load(Ordering::Relaxed));
        assert!(manager.forward(&query, false).await.is_none());
        assert!(manager.fallback_failed.load(Ordering::Relaxed));
        drop(dead);
    }
}
