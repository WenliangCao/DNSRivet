//! Hostname resolution that never touches the system resolver — once we own
//! the OS DNS, getaddrinfo would loop straight back into our own listener.
//! Queries go directly to hardcoded public bootstrap servers: UDP first, TCP
//! when UDP is lost or truncated. A failed refresh falls back to the last
//! known addresses for up to [`MAX_STALE`] and pauses lookups for that host
//! for [`RETRY_AFTER_FAILURE`].

use crate::config::IpStack;
use crate::upstream::legacy;
use hickory_net::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_net::proto::rr::{Name, RData, RecordType};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SERVERS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
];
/// Anycast public resolvers answer in tens of milliseconds; past 1s the
/// datagram is almost certainly lost, so retrying over TCP beats waiting.
const UDP_TIMEOUT: Duration = Duration::from_secs(1);
/// Covers the TCP handshake plus one exchange. Together with [`UDP_TIMEOUT`]
/// this bounds one server to 3s and a full failed lookup to 12s.
const TCP_TIMEOUT: Duration = Duration::from_secs(2);
const MIN_TTL_SECS: u64 = 60;
const PARTIAL_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 86_400;
/// How long expired addresses remain a fallback when every bootstrap server
/// fails. Upstream providers rarely renumber within a day; beyond that a
/// hard error is more honest than dialing addresses that may be reassigned.
const MAX_STALE: Duration = Duration::from_secs(86_400);

/// Pause between lookups after a failed refresh, as in RFC 8767's failure
/// recheck timer. While bootstrap servers are unreachable, only one caller
/// per host pays the lookup timeouts in each window; the rest get cached
/// addresses (or the cached error) at once. Longer delays recovery.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30);

type Key = (String, IpStack);

struct Entry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

impl Entry {
    fn is_fresh(&self, now: Instant) -> bool {
        now < self.expires
    }

    fn is_servable(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.expires) <= MAX_STALE
    }
}

struct Failure {
    err: String,
    retry_at: Instant,
}

#[derive(Default)]
struct Slot {
    /// Last successful answer, kept past expiry as a fallback.
    entry: Option<Entry>,
    /// Last failed refresh; no new lookup before its `retry_at`.
    failure: Option<Failure>,
    /// Held for the whole lookup so one refresh runs per key at a time.
    refresh: Arc<tokio::sync::Mutex<()>>,
}

enum Plan {
    Answer(Result<Vec<IpAddr>, String>),
    Refresh {
        refresh: Arc<tokio::sync::Mutex<()>>,
        stale: Option<Vec<IpAddr>>,
    },
}

impl Slot {
    fn plan(&mut self, now: Instant) -> Plan {
        if let Some(entry) = &self.entry {
            if entry.is_fresh(now) {
                return Plan::Answer(Ok(entry.ips.clone()));
            }
            if !entry.is_servable(now) {
                self.entry = None;
            }
        }
        let stale = self.entry.as_ref().map(|entry| entry.ips.clone());
        if let Some(failure) = &self.failure
            && now < failure.retry_at
        {
            return Plan::Answer(stale.ok_or_else(|| failure.err.clone()));
        }
        Plan::Refresh {
            refresh: self.refresh.clone(),
            stale,
        }
    }

    fn record(
        &mut self,
        result: Result<(Vec<IpAddr>, u64), String>,
        now: Instant,
    ) -> Result<Vec<IpAddr>, String> {
        match result {
            Ok((ips, ttl)) => {
                self.failure = None;
                self.entry = Some(Entry {
                    ips: ips.clone(),
                    expires: now + Duration::from_secs(ttl),
                });
                Ok(ips)
            }
            Err(err) => {
                self.failure = Some(Failure {
                    err: err.clone(),
                    retry_at: now
                        + if self
                            .entry
                            .as_ref()
                            .is_some_and(|entry| entry.is_servable(now))
                        {
                            RETRY_AFTER_FAILURE
                        } else {
                            Duration::from_secs(2)
                        },
                });
                match &self.entry {
                    Some(entry) if entry.is_servable(now) => {
                        log::warn!(
                            "{err}; using cached addresses {:?} for {}s",
                            entry.ips,
                            RETRY_AFTER_FAILURE.as_secs()
                        );
                        Ok(entry.ips.clone())
                    }
                    _ => {
                        self.entry = None;
                        Err(err)
                    }
                }
            }
        }
    }
}

pub struct Bootstrap {
    servers: Vec<SocketAddr>,
    slots: Mutex<HashMap<Key, Slot>>,
}

impl Bootstrap {
    pub fn new() -> Self {
        Self::with_servers(SERVERS.map(|ip| SocketAddr::new(ip, 53)).to_vec())
    }

    fn with_servers(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            slots: Mutex::new(HashMap::new()),
        }
    }

    pub async fn resolve(
        self: &Arc<Self>,
        host: &str,
        stack: IpStack,
    ) -> Result<Vec<IpAddr>, String> {
        let key = (host.to_ascii_lowercase(), stack);
        let (refresh, stale) = match self.plan(&key) {
            Plan::Answer(result) => return result,
            Plan::Refresh { refresh, stale } => (refresh, stale),
        };
        let refreshing = match refresh.clone().try_lock_owned() {
            Ok(guard) => guard,
            // Another caller is refreshing: use stale addresses rather than
            // wait out its timeouts, or wait and share its outcome.
            Err(_) => {
                if let Some(ips) = stale {
                    return Ok(ips);
                }
                let guard = refresh.lock_owned().await;
                if let Plan::Answer(result) = self.plan(&key) {
                    return result;
                }
                guard
            }
        };
        // A full failed lookup outlasts typical upstream timeouts. Run it as
        // its own task so a cancelled caller still records the outcome, which
        // is what lets later callers use stale addresses and the retry pause.
        let this = self.clone();
        let host = host.to_owned();
        tokio::spawn(async move {
            let _refreshing = refreshing;
            let result = this.lookup(&host, stack).await;
            let mut slots = this.slots.lock().unwrap();
            slots.entry(key).or_default().record(result, Instant::now())
        })
        .await
        .unwrap_or_else(|err| Err(format!("bootstrap refresh aborted: {err}")))
    }

    /// Force re-resolution after connect failures (host may have moved).
    /// The old addresses stay cached as a fallback if re-resolution fails.
    pub fn invalidate(&self, host: &str) {
        let host = host.to_ascii_lowercase();
        let now = Instant::now();
        for ((name, _), slot) in self.slots.lock().unwrap().iter_mut() {
            if *name == host
                && let Some(entry) = &mut slot.entry
            {
                entry.expires = entry.expires.min(now);
            }
        }
    }

    /// A new network should not inherit the old network's failure pause.
    pub fn reset(&self, host: &str) {
        self.invalidate(host);
        for ((name, _), slot) in self.slots.lock().unwrap().iter_mut() {
            if name.eq_ignore_ascii_case(host) {
                slot.failure = None;
            }
        }
    }

    fn plan(&self, key: &Key) -> Plan {
        let mut slots = self.slots.lock().unwrap();
        slots.entry(key.clone()).or_default().plan(Instant::now())
    }

    /// Queries bootstrap servers in order; under `IpStack::Both`, queries
    /// subsequent servers for a missing family if one family errored.
    async fn lookup(&self, host: &str, stack: IpStack) -> Result<(Vec<IpAddr>, u64), String> {
        let name = Name::from_str(host).map_err(|e| format!("invalid hostname {host:?}: {e}"))?;
        let mut need_a = stack != IpStack::V6;
        let mut need_aaaa = stack != IpStack::V4;
        let mut a_errored = false;
        let mut aaaa_errored = false;
        let mut ips = Vec::new();
        let mut min_ttl = MAX_TTL_SECS;
        let mut last_err = String::from("no bootstrap servers");

        for server in ordered_servers(&self.servers, stack) {
            // A and AAAA go out together so a lost datagram costs one timeout.
            let (a, aaaa) = tokio::join!(
                query_if(need_a, server, &name, RecordType::A),
                query_if(need_aaaa, server, &name, RecordType::AAAA),
            );
            for (result, need, errored) in [
                (a, &mut need_a, &mut a_errored),
                (aaaa, &mut need_aaaa, &mut aaaa_errored),
            ] {
                match result {
                    Some(Ok((mut got, ttl))) => {
                        *need = false;
                        *errored = false;
                        min_ttl = min_ttl.min(u64::from(ttl));
                        ips.append(&mut got);
                    }
                    Some(Err(err)) => {
                        *errored = true;
                        last_err = err;
                    }
                    None => {}
                }
            }
            if !need_a && !need_aaaa && !ips.is_empty() {
                break;
            }
            if ips.is_empty() && !need_a && !need_aaaa {
                need_a = stack != IpStack::V6;
                need_aaaa = stack != IpStack::V4;
            }
        }
        if !ips.is_empty() {
            ips.sort_by_key(|ip| ip.is_ipv6()); // prefer v4 dial order
            ips.dedup();
            let max_ttl = if a_errored || aaaa_errored {
                PARTIAL_TTL_SECS
            } else {
                MAX_TTL_SECS
            };
            let ttl = min_ttl.clamp(MIN_TTL_SECS, max_ttl);
            log::debug!("bootstrap: {host} -> {ips:?} (ttl {ttl}s)");
            return Ok((ips, ttl));
        }
        Err(format!("bootstrap failed for {host}: {last_err}"))
    }
}

fn ordered_servers(servers: &[SocketAddr], stack: IpStack) -> Vec<SocketAddr> {
    let mut servers = servers.to_vec();
    servers.sort_by_key(|server| match stack {
        IpStack::V4 => server.is_ipv6(),
        IpStack::V6 => server.is_ipv4(),
        IpStack::Both => false,
    });
    servers
}

async fn query(
    server: SocketAddr,
    name: &Name,
    rtype: RecordType,
) -> Result<(Vec<IpAddr>, u32), String> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name.clone(), rtype));
    let bytes = msg.to_vec().map_err(|e| e.to_string())?;

    let response = exchange(server, &bytes).await?;
    let parsed = Message::from_vec(&response).map_err(|e| e.to_string())?;
    let rcode = parsed.metadata.response_code;
    if rcode != ResponseCode::NoError {
        return Err(format!("bootstrap server {server}: {rcode}"));
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for record in &parsed.answers {
        match &record.data {
            RData::A(a) => {
                ips.push(IpAddr::V4(a.0));
                ttl = ttl.min(record.ttl);
            }
            RData::AAAA(aaaa) => {
                ips.push(IpAddr::V6(aaaa.0));
                ttl = ttl.min(record.ttl);
            }
            _ => {} // CNAME chain links etc.
        }
    }
    Ok((ips, ttl))
}

async fn query_if(
    wanted: bool,
    server: SocketAddr,
    name: &Name,
    rtype: RecordType,
) -> Option<Result<(Vec<IpAddr>, u32), String>> {
    if wanted {
        Some(query(server, name, rtype).await)
    } else {
        None
    }
}

/// UDP first; TCP when the datagram times out, errors, or comes back truncated.
async fn exchange(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let udp_err = match tokio::time::timeout(
        UDP_TIMEOUT,
        legacy::query_udp_with_retry(server, query, false),
    )
    .await
    {
        Ok(Ok(response)) if !legacy::is_truncated(&response) => return Ok(response),
        Ok(Ok(_)) => "truncated".to_string(),
        Ok(Err(err)) => err,
        Err(_) => "timed out".to_string(),
    };
    match tokio::time::timeout(TCP_TIMEOUT, legacy::query_tcp(server, query)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(err)) => Err(format!(
            "bootstrap server {server}: udp {udp_err}, tcp {err}"
        )),
        Err(_) => Err(format!(
            "bootstrap server {server}: udp {udp_err}, tcp timed out"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::rr::Record;
    use hickory_net::proto::rr::rdata::{A, AAAA};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    impl Bootstrap {
        pub(in crate::upstream) fn with_test_servers(servers: Vec<SocketAddr>) -> Self {
            Self::with_servers(servers)
        }

        pub(in crate::upstream) fn seed_test_ips(
            &self,
            host: &str,
            stack: IpStack,
            ips: &[IpAddr],
        ) {
            let mut slots = self.slots.lock().unwrap();
            slots
                .entry((host.to_ascii_lowercase(), stack))
                .or_default()
                .entry = Some(Entry {
                ips: ips.to_vec(),
                expires: Instant::now() + Duration::from_secs(300),
            });
        }

        pub(in crate::upstream) fn seed_test_failure(&self, host: &str, stack: IpStack) {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.entry((host.to_ascii_lowercase(), stack)).or_default();
            slot.failure = Some(Failure {
                err: "seeded failure".into(),
                retry_at: Instant::now() + RETRY_AFTER_FAILURE,
            });
        }

        pub(in crate::upstream) fn has_active_failure(&self, host: &str, stack: IpStack) -> bool {
            self.slots
                .lock()
                .unwrap()
                .get(&(host.to_ascii_lowercase(), stack))
                .is_some_and(|slot| slot.failure.is_some())
        }
    }

    const V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    fn answer(request: &[u8]) -> Vec<u8> {
        let mut msg = Message::from_vec(request).unwrap();
        let question = msg.queries[0].clone();
        let rdata = match question.query_type() {
            RecordType::A => RData::A(A(V4)),
            _ => RData::AAAA(AAAA(V6)),
        };
        msg.metadata.message_type = MessageType::Response;
        msg.add_answer(Record::from_rdata(question.name().clone(), 300, rdata));
        msg.to_vec().unwrap()
    }

    /// Swallows every UDP datagram and answers A/AAAA over TCP, like a path
    /// that drops UDP port 53. The UDP socket lives as long as the runtime.
    async fn udp_blackhole_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while udp.recv_from(&mut buf).await.is_ok() {}
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await.unwrap();
                    let mut request = vec![0u8; u16::from_be_bytes(len) as usize];
                    stream.read_exact(&mut request).await.unwrap();
                    let response = answer(&request);
                    let len = u16::try_from(response.len()).unwrap();
                    stream.write_all(&len.to_be_bytes()).await.unwrap();
                    stream.write_all(&response).await.unwrap();
                });
            }
        });
        addr
    }

    /// Counts UDP queries and never answers; TCP on the same port is refused.
    /// Each lookup therefore costs one full UDP timeout.
    async fn counting_blackhole_server() -> (SocketAddr, Arc<AtomicUsize>) {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = queries.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while udp.recv_from(&mut buf).await.is_ok() {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
        (addr, queries)
    }

    fn insert_cached(boot: &Bootstrap, ips: &[IpAddr], expires: Instant) {
        boot.slots
            .lock()
            .unwrap()
            .entry(("dns.example".into(), IpStack::V4))
            .or_default()
            .entry = Some(Entry {
            ips: ips.to_vec(),
            expires,
        });
    }

    /// A loopback port with nothing listening: UDP and TCP are both refused.
    async fn dead_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    #[test]
    fn ipv6_stack_prefers_ipv6_bootstrap_servers() {
        let servers = Bootstrap::new().servers;
        let servers = ordered_servers(&servers, IpStack::V6);
        assert!(servers[..2].iter().all(SocketAddr::is_ipv6));
        assert!(servers[2..].iter().all(SocketAddr::is_ipv4));
    }

    #[test]
    fn bootstrap_server_addresses_include_both_ip_stacks() {
        assert!(SERVERS.iter().any(IpAddr::is_ipv4));
        assert!(SERVERS.iter().any(IpAddr::is_ipv6));
    }

    #[tokio::test]
    async fn lost_udp_falls_back_to_tcp_with_a_and_aaaa_in_parallel() {
        let boot = Arc::new(Bootstrap::with_servers(vec![udp_blackhole_server().await]));
        let started = Instant::now();
        let ips = boot.resolve("dns.example", IpStack::Both).await.unwrap();
        assert_eq!(ips, [IpAddr::V4(V4), IpAddr::V6(V6)]);
        // Sequential A then AAAA would spend two full UDP timeouts.
        assert!(
            started.elapsed() < UDP_TIMEOUT * 2,
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn invalidated_entry_survives_as_fallback_when_refresh_fails() {
        let boot = Arc::new(Bootstrap::with_servers(vec![dead_server().await]));
        let cached = [IpAddr::V4(V4)];
        insert_cached(&boot, &cached, Instant::now() + Duration::from_secs(300));

        boot.invalidate("DNS.example");
        let key = ("dns.example".to_string(), IpStack::V4);
        let expired = {
            let slots = boot.slots.lock().unwrap();
            !slots[&key].entry.as_ref().unwrap().is_fresh(Instant::now())
        };
        assert!(expired, "invalidate must expire the entry, not delete it");
        let ips = boot.resolve("dns.example", IpStack::V4).await.unwrap();
        assert_eq!(ips, cached);
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_failed_lookup_and_then_pause() {
        let (server, queries) = counting_blackhole_server().await;
        let boot = Arc::new(Bootstrap::with_servers(vec![server]));

        let (first, second) = tokio::join!(
            boot.resolve("dns.example", IpStack::V4),
            boot.resolve("dns.example", IpStack::V4),
        );
        assert!(first.is_err() && second.is_err());
        assert_eq!(queries.load(Ordering::Relaxed), 1);

        let started = Instant::now();
        let err = boot.resolve("dns.example", IpStack::V4).await.unwrap_err();
        assert!(err.contains("bootstrap failed for dns.example"), "{err}");
        assert!(
            started.elapsed() < UDP_TIMEOUT / 2,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(queries.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stale_callers_do_not_wait_for_an_inflight_refresh() {
        let (server, queries) = counting_blackhole_server().await;
        let boot = Arc::new(Bootstrap::with_servers(vec![server]));
        let cached = [IpAddr::V4(V4)];
        insert_cached(&boot, &cached, Instant::now());

        let (refreshing, waiting) = tokio::join!(boot.resolve("dns.example", IpStack::V4), async {
            // Let the first caller start its refresh.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let started = Instant::now();
            let ips = boot.resolve("dns.example", IpStack::V4).await;
            (ips, started.elapsed())
        });
        assert_eq!(refreshing.unwrap(), cached);
        assert_eq!(waiting.0.unwrap(), cached);
        assert!(waiting.1 < UDP_TIMEOUT / 2, "{:?}", waiting.1);
        assert_eq!(queries.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelled_caller_still_records_the_failed_refresh() {
        let (server, queries) = counting_blackhole_server().await;
        let boot = Arc::new(Bootstrap::with_servers(vec![server]));
        let cached = [IpAddr::V4(V4)];
        insert_cached(&boot, &cached, Instant::now());

        // Upstream timeouts can be far shorter than a failed lookup.
        let cancelled = tokio::time::timeout(
            Duration::from_millis(100),
            boot.resolve("dns.example", IpStack::V4),
        )
        .await;
        assert!(cancelled.is_err());
        tokio::time::sleep(UDP_TIMEOUT + Duration::from_millis(300)).await;

        let started = Instant::now();
        let ips = boot.resolve("dns.example", IpStack::V4).await.unwrap();
        assert_eq!(ips, cached);
        assert!(
            started.elapsed() < UDP_TIMEOUT / 2,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(queries.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refresh_failure_without_cache_is_an_error() {
        let boot = Arc::new(Bootstrap::with_servers(vec![dead_server().await]));
        let err = boot.resolve("dns.example", IpStack::V4).await.unwrap_err();
        assert!(err.contains("bootstrap failed for dns.example"), "{err}");
    }

    #[tokio::test]
    async fn legacy_resolution_rejects_self_addresses_before_sending() {
        use crate::config::{Proto, Upstream};
        use crate::upstream::{Backend, Manager};

        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap();
        let self_ip: IpAddr = "192.0.2.53".parse().unwrap();
        let up = Upstream {
            name: "resolved legacy".into(),
            proto: Proto::Legacy,
            host: "dns.example".into(),
            port: addr.port(),
            path: String::new(),
            bootstrap_ip: None,
            timeout_ms: 1000,
            ip_stack: IpStack::V4,
        };
        let manager =
            Manager::new(vec![up], &[SocketAddr::new(self_ip, addr.port())], vec![]).unwrap();
        let Backend::Legacy { bootstrap, .. } = &manager.entries[0].backend else {
            unreachable!()
        };
        // Every loopback on this port is denied, including IPv4-mapped IPv6.
        let ips = [self_ip, addr.ip(), "::ffff:127.0.0.1".parse().unwrap()];
        insert_cached(bootstrap, &ips, Instant::now() + Duration::from_secs(60));
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("review.invalid.").unwrap(),
            RecordType::A,
        ));
        assert!(
            manager
                .forward(&query.to_vec().unwrap(), false)
                .await
                .is_none()
        );
        assert!(
            target.try_recv_from(&mut [0; 512]).is_err(),
            "must not send to a resolved self address"
        );
    }

    #[test]
    fn stale_entry_is_servable_for_one_day_after_expiry() {
        let expires = Instant::now();
        let entry = Entry {
            ips: vec![IpAddr::V4(V4)],
            expires,
        };
        assert!(!entry.is_fresh(expires));
        assert!(entry.is_servable(expires + MAX_STALE));
        assert!(!entry.is_servable(expires + MAX_STALE + Duration::from_secs(1)));
    }
    #[test]
    fn cold_bootstrap_failure_retries_quickly_and_network_reset_clears_it() {
        let now = Instant::now();
        let mut slot = Slot::default();
        assert!(slot.record(Err("offline".into()), now).is_err());
        assert!(matches!(
            slot.plan(now + Duration::from_secs(2)),
            Plan::Refresh { .. }
        ));
        let boot = Bootstrap::new();
        boot.slots
            .lock()
            .unwrap()
            .insert(("dns.example".into(), IpStack::V4), slot);
        boot.reset("dns.example");
        assert!(matches!(
            boot.plan(&("dns.example".into(), IpStack::V4)),
            Plan::Refresh { .. }
        ));
    }

    async fn mock_udp_dns(
        mut handler: impl FnMut(RecordType, &[u8]) -> Vec<u8> + Send + 'static,
    ) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let msg = Message::from_vec(&buf[..n]).unwrap();
                let resp = handler(msg.queries[0].query_type(), &buf[..n]);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    fn rcode_answer(request: &[u8], rcode: ResponseCode) -> Vec<u8> {
        let mut msg = Message::from_vec(request).unwrap();
        msg.metadata.message_type = MessageType::Response;
        msg.metadata.response_code = rcode;
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn non_noerror_rcode_returns_error_and_fails_over() {
        let servfail_srv = mock_udp_dns(|_, req| rcode_answer(req, ResponseCode::ServFail)).await;
        let refused_srv = mock_udp_dns(|_, req| rcode_answer(req, ResponseCode::Refused)).await;
        let healthy_srv = mock_udp_dns(|_, req| answer(req)).await;

        let failing = Arc::new(Bootstrap::with_servers(vec![servfail_srv, refused_srv]));
        let err = failing
            .resolve("dns.example", IpStack::V4)
            .await
            .unwrap_err();
        assert!(err.contains("ServFail") || err.contains("Refused"), "{err}");

        let failover = Arc::new(Bootstrap::with_servers(vec![servfail_srv, healthy_srv]));
        assert_eq!(
            failover.resolve("dns.example", IpStack::V4).await.unwrap(),
            [IpAddr::V4(V4)]
        );
    }

    #[tokio::test]
    async fn dual_stack_partial_failure_recovers_missing_family_from_next_server() {
        let srv0 = mock_udp_dns(|rtype, req| match rtype {
            RecordType::A => answer(req),
            _ => rcode_answer(req, ResponseCode::ServFail),
        })
        .await;
        let srv1_a_queries = Arc::new(AtomicUsize::new(0));
        let srv1_a = srv1_a_queries.clone();
        let srv1 = mock_udp_dns(move |rtype, req| match rtype {
            RecordType::A => {
                srv1_a.fetch_add(1, Ordering::Relaxed);
                answer(req)
            }
            _ => answer(req),
        })
        .await;

        let boot = Arc::new(Bootstrap::with_servers(vec![srv0, srv1]));
        let ips = boot.resolve("dns.example", IpStack::Both).await.unwrap();
        assert_eq!(ips, [IpAddr::V4(V4), IpAddr::V6(V6)]);
        assert_eq!(
            srv1_a_queries.load(Ordering::Relaxed),
            0,
            "srv1 must only be queried for the missing AAAA family"
        );
        let slots = boot.slots.lock().unwrap();
        let ttl = slots[&("dns.example".into(), IpStack::Both)]
            .entry
            .as_ref()
            .unwrap()
            .expires
            .saturating_duration_since(Instant::now());
        assert!(ttl > Duration::from_secs(PARTIAL_TTL_SECS));
    }

    #[tokio::test]
    async fn dual_stack_persistent_partial_failure_caps_ttl_at_60s() {
        let srv0 = mock_udp_dns(|rtype, req| match rtype {
            RecordType::A => answer(req),
            _ => rcode_answer(req, ResponseCode::ServFail),
        })
        .await;
        let boot = Arc::new(Bootstrap::with_servers(vec![srv0]));
        let ips = boot.resolve("dns.example", IpStack::Both).await.unwrap();
        assert_eq!(ips, [IpAddr::V4(V4)]);
        let slots = boot.slots.lock().unwrap();
        let ttl = slots[&("dns.example".into(), IpStack::Both)]
            .entry
            .as_ref()
            .unwrap()
            .expires
            .saturating_duration_since(Instant::now());
        assert!(ttl <= Duration::from_secs(PARTIAL_TTL_SECS));
    }
}
