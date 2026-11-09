//! DoH / DoH3 / DoT / DoQ upstream channels.
//!
//! Each upstream keeps one lazily-connected `DnsExchange` (a multiplexed
//! persistent connection) in a generation-tracked slot; queries clone the
//! cheap handle. Failure handling follows a fixed event table:
//!
//! - send failure on a REUSED connection: invalidate that generation, no
//!   backoff, redial once while budget remains (QUIC's default 30s idle
//!   timeout kills idle connections constantly; the first query after an
//!   idle gap should stay on this upstream instead of failing over);
//! - the redial's connect failure: backoff via the connect path only;
//! - send failure after a redial, or on a freshly dialed connection:
//!   invalidate + backoff;
//! - deadline expiry without another answer since send: invalidate + backoff (a wedged-but-accepting
//!   upstream must not tax every query with its full timeout);
//! - errors from a superseded generation: no state change; retry once on
//!   the successor while budget remains if the failed lease was reused;
//! - host slept since the last query: drop the connection before sending,
//!   no backoff, and re-resolve the bootstrap address (the peer has likely
//!   forgotten it, and a black-holed send would burn the whole deadline and
//!   push the query to the plaintext system fallback);
//! - route source for the peer changed (network switch, VPN up/down): drop
//!   the connection before sending, no backoff;
//! - deadline expiry after sleep or a route change under that lease: no
//!   backoff, one retry on a fresh connection with a short extra budget.

use crate::config::{IpStack, Proto, Upstream};
use crate::upstream::bootstrap::Bootstrap;
use hickory_net::NetError;
use hickory_net::h2::HttpsClientStream;
use hickory_net::h3::H3ClientStream;
use hickory_net::proto::op::{DnsRequest, DnsRequestOptions, Message};
use hickory_net::quic::QuicClientStream;
use hickory_net::runtime::{TokioRuntimeProvider, TokioTime};
use hickory_net::tls::tls_client_connect;
use hickory_net::xfer::{
    BufDnsStreamHandle, DnsClientStream, DnsExchange, DnsHandle, DnsMultiplexer, DnsRequestSender,
    FirstAnswer,
};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF_SHIFT: u32 = 5; // 2^5 = 32s cap
/// A redial is only worth it while at least this much budget remains.
const MIN_REDIAL_BUDGET: Duration = Duration::from_millis(250);
/// Sleep longer than this renews connections before the next query.
const RENEW_AFTER_SLEEP: Duration = Duration::from_secs(5);
/// Route lookups cost a few syscalls; at most one per channel per interval.
const ROUTE_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Extra time a query gets when the network moved under its connection.
const STALE_RETRY_BUDGET: Duration = Duration::from_secs(2);

/// rustls config shared by every encrypted upstream: ring provider,
/// webpki (Mozilla) trust anchors, session resumption on by default.
/// ALPN stays empty — hickory fills in h2 / doq / h3 per transport.
pub fn base_tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Paired clock readings. `Instant` stops while macOS sleeps (it reads
/// CLOCK_UPTIME_RAW) and the wall clock does not, so their drift between two
/// stamps is the time the host spent asleep. A forward wall-clock step reads
/// as sleep too; that only costs one early redial.
#[derive(Clone, Copy)]
struct Stamp {
    mono: Instant,
    wall: SystemTime,
}

impl Stamp {
    fn now() -> Self {
        Self {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    fn slept_since(self, earlier: Stamp) -> Duration {
        let wall = self.wall.duration_since(earlier.wall).unwrap_or_default();
        wall.saturating_sub(self.mono.saturating_duration_since(earlier.mono))
    }
}

/// The kernel's source address for `peer`. `connect` on a UDP socket only
/// consults the routing table; nothing is sent. None means no route now.
pub(crate) fn route_source(peer: SocketAddr) -> Option<IpAddr> {
    let unspecified = if peer.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let socket = std::net::UdpSocket::bind((unspecified, 0)).ok()?;
    socket.connect(peer).ok()?;
    socket.local_addr().ok().map(|local| local.ip())
}

/// Where a connection was dialed to, and from which route-selected source.
#[derive(Clone, Copy)]
struct RoutePath {
    peer: SocketAddr,
    source: Option<IpAddr>,
    checked: Instant,
}

/// Generation-tracked connection slot. Generic over the handle type so the
/// invalidation rules are unit-testable without real connections.
struct Slot<E> {
    exchange: Option<E>,
    generation: u64,
    connect_failures: u32,
    cooldown_until: Option<Instant>,
    /// When the slot was last leased or stored, for sleep detection.
    last_used: Option<Stamp>,
    path: Option<RoutePath>,
    last_answer: Option<Instant>,
}

impl<E> Default for Slot<E> {
    fn default() -> Self {
        Self {
            exchange: None,
            generation: 0,
            connect_failures: 0,
            cooldown_until: None,
            last_used: None,
            path: None,
            last_answer: None,
        }
    }
}

impl<E: Clone> Slot<E> {
    fn lease(&self) -> Option<(E, u64)> {
        self.exchange.clone().map(|e| (e, self.generation))
    }

    fn store(&mut self, exchange: E) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.exchange = Some(exchange);
        self.connect_failures = 0;
        self.cooldown_until = None;
        self.last_used = Some(Stamp::now());
        self.path = None;
        self.last_answer = None;
        self.generation
    }

    fn record_path(&mut self, peer: SocketAddr, source: Option<IpAddr>) {
        self.path = Some(RoutePath {
            peer,
            source,
            checked: Instant::now(),
        });
    }

    /// Drop the connection if the host slept since the slot was last used,
    /// returning how long it slept. No backoff: the connection did not fail.
    fn drop_if_slept(&mut self, now: Stamp) -> Option<Duration> {
        let slept = now.slept_since(self.last_used.replace(now)?);
        if slept <= RENEW_AFTER_SLEEP || (self.exchange.is_none() && self.cooldown_until.is_none())
        {
            return None;
        }
        self.exchange = None;
        self.path = None;
        self.connect_failures = 0;
        self.cooldown_until = None;
        Some(slept)
    }

    /// The peer to look up when this connection's route check is due.
    fn route_check_due(&mut self, now: Instant) -> Option<SocketAddr> {
        let path = self.path.as_mut()?;
        if now.saturating_duration_since(path.checked) < ROUTE_CHECK_INTERVAL {
            return None;
        }
        path.checked = now;
        Some(path.peer)
    }

    /// Drop the connection if its route source changed, returning the old
    /// and new source. No route says nothing: the same source may return.
    fn drop_if_moved(&mut self, current: Option<IpAddr>) -> Option<(Option<IpAddr>, IpAddr)> {
        let (from, to) = (self.path?.source, current?);
        if from == Some(to) {
            return None;
        }
        self.exchange = None;
        self.path = None;
        self.connect_failures = 0;
        self.cooldown_until = None;
        Some((from, to))
    }

    /// Clear the slot only if `generation` is still the current one; a
    /// failure from a superseded lease must never tear down its successor.
    fn invalidate(&mut self, generation: u64) -> bool {
        if self.generation == generation && self.exchange.is_some() {
            self.exchange = None;
            if let Some(path) = self.path {
                self.record_path(path.peer, route_source(path.peer));
            }
            true
        } else {
            false
        }
    }

    fn backoff(&mut self) -> Duration {
        self.connect_failures = self.connect_failures.saturating_add(1);
        let backoff = Duration::from_secs(1 << self.connect_failures.min(MAX_BACKOFF_SHIFT));
        self.cooldown_until = Some(Instant::now() + backoff);
        backoff
    }
}

struct Lease {
    exchange: DnsExchange<TokioRuntimeProvider>,
    generation: u64,
    reused: bool,
    path: Option<RoutePath>,
    taken: Stamp,
}

impl Lease {
    /// Whether the host slept or the route moved since this lease was taken,
    /// so a deadline expiry says nothing about the upstream itself.
    fn went_stale(&self) -> bool {
        Stamp::now().slept_since(self.taken) > RENEW_AFTER_SLEEP
            || self.path.is_some_and(|path| {
                route_source(path.peer).is_some_and(|to| Some(to) != path.source)
            })
    }
}

enum SendFailure {
    Deadline,
    Transport(String),
    Request(String),
}

pub struct Channel {
    up: Upstream,
    tls: Arc<rustls::ClientConfig>,
    bootstrap: Arc<Bootstrap>,
    /// Our own listener addresses — refuse to dial ourselves.
    deny: Arc<Vec<SocketAddr>>,
    state: Mutex<Slot<DnsExchange<TokioRuntimeProvider>>>,
}

impl Channel {
    pub fn new(
        up: Upstream,
        tls: Arc<rustls::ClientConfig>,
        bootstrap: Arc<Bootstrap>,
        deny: Arc<Vec<SocketAddr>>,
    ) -> Self {
        Self {
            up,
            tls,
            bootstrap,
            deny,
            state: Mutex::new(Slot::default()),
        }
    }

    /// Send one query within `deadline` (None = no deadline, from
    /// `timeout = 0`). The channel owns its timeout so invalidation stays
    /// generation-precise; the manager's outer timeout is a scheduling
    /// backstop with no side effects here.
    pub async fn query(
        &self,
        message: &Message,
        mut deadline: Option<Instant>,
    ) -> Result<Vec<u8>, String> {
        let retry_budget = deadline.map(|at| {
            at.saturating_duration_since(Instant::now())
                .min(STALE_RETRY_BUDGET)
        });
        let mut lease = self.acquire(deadline).await?;
        let mut retried = false;
        loop {
            match send(&lease.exchange, message.clone(), deadline).await {
                Ok(buffer) => {
                    if let Ok(mut state) = self.state.try_lock()
                        && state.generation == lease.generation
                    {
                        state.last_answer = Some(Instant::now());
                    }
                    return Ok(buffer);
                }
                Err(SendFailure::Request(err)) => return Err(err),
                Err(SendFailure::Deadline) => {
                    let stale = !retried && lease.went_stale();
                    if let Ok(mut state) = self.state.try_lock() {
                        let responsive = state.last_answer.is_some_and(|at| at >= lease.taken.mono);
                        if !stale && responsive && state.generation == lease.generation {
                            return Err(
                                "no answer within the deadline; connection still responsive".into(),
                            );
                        }
                        if state.invalidate(lease.generation) && !stale {
                            state.backoff();
                        }
                    }
                    if !stale {
                        return Err("no answer within the deadline".into());
                    }
                    log::info!(
                        "upstream {}: network changed during a query; retrying on a fresh connection",
                        self.up.name
                    );
                    retried = true;
                    deadline = retry_budget.map(|budget| Instant::now() + budget);
                    lease = self.acquire(deadline).await.map_err(|err| {
                        format!("no answer within the deadline; redial failed: {err}")
                    })?;
                }
                Err(SendFailure::Transport(err)) => {
                    let redial = lease.reused && !retried && budget_allows_redial(deadline);
                    if let Ok(mut state) = self.state.try_lock()
                        && state.invalidate(lease.generation)
                        && !redial
                    {
                        state.backoff();
                    }
                    if !redial {
                        return Err(err);
                    }
                    // A concurrent query may already have invalidated or
                    // replaced this generation. Share its successor without
                    // changing that connection's state or backoff.
                    log::debug!(
                        "upstream {}: stale connection ({err}); retrying once",
                        self.up.name
                    );
                    retried = true;
                    lease = self
                        .acquire(deadline)
                        .await
                        .map_err(|redial_err| format!("{err}; redial failed: {redial_err}"))?;
                }
            }
        }
    }

    async fn acquire(&self, deadline: Option<Instant>) -> Result<Lease, String> {
        // Holding the async lock across connect serializes dial attempts,
        // so a burst of queries cannot stampede-connect.
        let mut state = within(deadline, self.state.lock()).await?;
        let now = Stamp::now();
        if let Some(slept) = state.drop_if_slept(now) {
            log::info!(
                "upstream {}: host slept {:.0}s; renewing connection",
                self.up.name,
                slept.as_secs_f32()
            );
            if self.up.bootstrap_ip.is_none() {
                self.bootstrap.reset(&self.up.host).await;
            }
        }
        if let Some(peer) = state.route_check_due(now.mono)
            && let Some((from, to)) = state.drop_if_moved(route_source(peer))
        {
            log::info!(
                "upstream {}: route source changed from {from:?} to {to}; renewing connection",
                self.up.name
            );
            self.bootstrap.reset(&self.up.host).await;
        }
        if let Some((exchange, generation)) = state.lease() {
            return Ok(Lease {
                exchange,
                generation,
                reused: true,
                path: state.path,
                taken: now,
            });
        }
        if let Some(until) = state.cooldown_until {
            let now = Instant::now();
            if now < until {
                return Err(format!(
                    "in cooldown for {:.1}s",
                    (until - now).as_secs_f32()
                ));
            }
        }

        // Keep a route observation even when bootstrap or dialing fails.
        let probe = self
            .up
            .bootstrap_ip
            .unwrap_or_else(|| match self.up.ip_stack {
                IpStack::V6 => "2606:4700:4700::1111".parse().unwrap(),
                _ => "1.1.1.1".parse().unwrap(),
            });
        let peer = SocketAddr::new(probe, self.up.port);
        state.record_path(peer, route_source(peer));
        let ips = match self.up.bootstrap_ip {
            Some(ip) => vec![ip],
            None => {
                if state.connect_failures > 0 {
                    self.bootstrap.invalidate(&self.up.host).await;
                }
                match within(
                    deadline,
                    self.bootstrap.resolve(&self.up.host, self.up.ip_stack),
                )
                .await
                .and_then(|result| result)
                {
                    Ok(ips) => ips,
                    Err(err) => {
                        state.backoff();
                        return Err(format!("{err}; backing off after bootstrap failure"));
                    }
                }
            }
        };

        let mut last_err = String::from("no candidate addresses");
        let count = ips.len();
        for (index, ip) in ips.into_iter().enumerate() {
            let addr = SocketAddr::new(ip, self.up.port);
            if super::is_self_address(addr, &self.deny) {
                last_err = format!("{addr} points back at our own listener");
                continue;
            }
            log::debug!(
                "upstream {}: dialing {} {addr}",
                self.up.name,
                self.up.proto.as_str()
            );
            // Connection setup carries large TLS/QUIC futures. Allocate only
            // when dialing, so every forwarded query has a smaller future.
            let candidate_deadline = dial_deadline(deadline, count - index);
            state.record_path(addr, route_source(addr));
            match Box::pin(connect(&self.up, &self.tls, addr, Some(candidate_deadline))).await {
                Ok(exchange) => {
                    log::debug!(
                        "upstream {}: connected {} to {addr}",
                        self.up.name,
                        self.up.proto.as_str()
                    );
                    let generation = state.store(exchange.clone());
                    state.record_path(addr, route_source(addr));
                    return Ok(Lease {
                        exchange,
                        generation,
                        reused: false,
                        path: state.path,
                        taken: now,
                    });
                }
                Err(err) => {
                    log::debug!("upstream {}: dial {addr}: {err}", self.up.name);
                    last_err = err;
                }
            }
        }

        let backoff = state.backoff();
        Err(format!(
            "connect failed ({last_err}); backing off {backoff:?}"
        ))
    }
}

async fn within<T>(
    deadline: Option<Instant>,
    future: impl Future<Output = T>,
) -> Result<T, String> {
    match deadline {
        Some(at) => tokio::time::timeout_at(at.into(), future)
            .await
            .map_err(|_| "no answer within the deadline".into()),
        None => Ok(future.await),
    }
}

fn dial_deadline(deadline: Option<Instant>, remaining: usize) -> Instant {
    let now = Instant::now();
    let budget = deadline.map_or(CONNECT_TIMEOUT, |at| at.saturating_duration_since(now));
    now + budget / u32::try_from(remaining).unwrap_or(u32::MAX)
}

fn budget_allows_redial(deadline: Option<Instant>) -> bool {
    deadline.is_none_or(|d| d.saturating_duration_since(Instant::now()) > MIN_REDIAL_BUDGET)
}

async fn send(
    exchange: &DnsExchange<TokioRuntimeProvider>,
    message: Message,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, SendFailure> {
    let request = DnsRequest::new(message, DnsRequestOptions::default());
    let answer = exchange.send(request).first_answer();
    let result = match deadline {
        Some(at) => match tokio::time::timeout_at(at.into(), answer).await {
            Ok(result) => result,
            Err(_) => return Err(SendFailure::Deadline),
        },
        None => answer.await,
    };
    result
        .map(|response| response.into_buffer())
        .map_err(|err| match err {
            NetError::Timeout => SendFailure::Deadline,
            NetError::Busy | NetError::RequestTooLarge | NetError::Proto(_) => {
                SendFailure::Request(err.to_string())
            }
            // Hickory 0.26 represents HTTP status errors as text.
            NetError::Msg(ref message)
                if message.starts_with("http unsuccessful code:")
                    || message == "mpsc::SendError send failed because channel is full" =>
            {
                SendFailure::Request(err.to_string())
            }
            _ => SendFailure::Transport(err.to_string()),
        })
}

async fn connect(
    up: &Upstream,
    tls: &Arc<rustls::ClientConfig>,
    addr: SocketAddr,
    deadline: Option<Instant>,
) -> Result<DnsExchange<TokioRuntimeProvider>, String> {
    let provider = TokioRuntimeProvider::new();
    match up.proto {
        Proto::Dot => {
            let server_name = rustls::pki_types::ServerName::try_from(up.host.clone())
                .map_err(|err| err.to_string())?;
            let (conn, handle) = tls_client_connect(addr, server_name, tls.clone(), provider);
            connect_dot(conn, handle, deadline).await
        }
        Proto::Doh => {
            let builder = HttpsClientStream::builder(tls.clone(), provider);
            finish(
                builder.build(addr, up.host.as_str().into(), up.path.as_str().into()),
                deadline,
            )
            .await
        }
        Proto::Doq => {
            let builder = QuicClientStream::builder().crypto_config((**tls).clone());
            finish(builder.build(addr, up.host.as_str().into()), deadline).await
        }
        Proto::Doh3 => {
            let builder = H3ClientStream::builder().crypto_config((**tls).clone());
            finish(
                builder.build(addr, up.host.as_str().into(), up.path.as_str().into()),
                deadline,
            )
            .await
        }
        Proto::Legacy => unreachable!("legacy upstreams don't use encrypted channels"),
    }
}

/// Only Channel's deadline may expire a DoT query. Hickory's default
/// multiplexer imposes a hidden 5s limit, including for `timeout = 0`.
async fn connect_dot<F, S>(
    conn: F,
    handle: BufDnsStreamHandle,
    deadline: Option<Instant>,
) -> Result<DnsExchange<TokioRuntimeProvider>, String>
where
    F: Future<Output = Result<S, NetError>> + Send + 'static,
    S: DnsClientStream<Time = TokioTime>,
{
    finish(
        async move {
            // Hickory requires a duration; Tokio saturates MAX to its far-future
            // timer. Cancellation and positive deadlines remain owned by Channel.
            Ok(DnsMultiplexer::new(conn.await?, handle)
                .with_max_active_requests(super::MAX_ATTEMPTS)
                .with_timeout(Duration::MAX))
        },
        deadline,
    )
    .await
}

async fn finish<F, S>(
    connect: F,
    deadline: Option<Instant>,
) -> Result<DnsExchange<TokioRuntimeProvider>, String>
where
    F: Future<Output = Result<S, NetError>> + Send + 'static,
    S: DnsRequestSender,
{
    let limit = match deadline {
        Some(at) => CONNECT_TIMEOUT.min(at.saturating_duration_since(Instant::now())),
        None => CONNECT_TIMEOUT,
    };
    let stream = tokio::time::timeout(limit, connect)
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let (exchange, background) = DnsExchange::from_stream(stream);
    tokio::spawn(background);
    Ok(exchange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpStack;
    use crate::upstream::{Backend, Manager};
    use futures_core::Stream;
    use hickory_net::proto::op::{DnsResponse, Edns, MessageType, OpCode, Query};
    use hickory_net::proto::rr::rdata::opt::EdnsOption;
    use hickory_net::proto::rr::{Name, RecordType};
    use hickory_net::xfer::DnsResponseStream;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::sync::{mpsc, oneshot};

    #[tokio::test(start_paused = true)]
    async fn dot_waits_past_five_seconds_but_obeys_the_channel_deadline() {
        use hickory_net::runtime::iocompat::AsyncIoTokioAsStd;
        use hickory_net::tcp::{TcpClientStream, TcpStream};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Exercise DoT's real framing and multiplexer over in-memory I/O. TLS
        // only supplies this byte stream; no certificate fixtures are needed.
        for timeout_ms in [0, 8000, 1000] {
            let (manager, unused_background) = test_manager(TestTransport::default()).await;
            let (client, mut server) = tokio::io::duplex(4096);
            let (stream, handle) =
                TcpStream::from_stream(AsyncIoTokioAsStd(client), "127.0.0.1:853".parse().unwrap());
            let conn = std::future::ready(Ok(TcpClientStream::from_stream(stream)));
            let exchange = connect_dot(conn, handle, None).await.unwrap();
            let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                unreachable!()
            };
            channel.state.lock().await.store(exchange);
            unused_background.await.unwrap();
            let (ready, received) = oneshot::channel();
            let responder = tokio::spawn(async move {
                let len = server.read_u16().await.unwrap();
                let mut query = vec![0; usize::from(len)];
                server.read_exact(&mut query).await.unwrap();
                ready.send(()).unwrap();
                tokio::time::sleep(Duration::from_secs(6)).await;
                query[2] |= 0x80;
                let _ = server.write_u16(len).await;
                let _ = server.write_all(&query).await;
            });
            let manager = Arc::new(manager);
            let deadline = (timeout_ms > 0).then(|| {
                (tokio::time::Instant::now() + Duration::from_millis(timeout_ms)).into_std()
            });
            let pending = start_query(&manager, deadline);
            received.await.unwrap();
            tokio::time::advance(Duration::from_secs(6)).await;
            let result = pending.await.unwrap();
            if timeout_ms == 1000 {
                assert!(result.unwrap_err().contains("deadline"));
            } else {
                assert!(result.is_ok(), "timeout={timeout_ms}: {result:?}");
            }
            responder.await.unwrap();
        }
    }

    #[tokio::test]
    async fn dot_reuses_a_backpressured_connection_without_reencoding_answers() {
        use hickory_net::runtime::iocompat::AsyncIoTokioAsStd;
        use hickory_net::tcp::{TcpClientStream, TcpStream};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Deliberately leave the answer owner uncompressed and mixed-case.
        // Re-encoding through Message would change these bytes.
        fn answer(query: &[u8]) -> Vec<u8> {
            const QUESTION_END: usize = 29; // example.com. A IN
            let mut response = query[..QUESTION_END].to_vec();
            response[2] |= 0x80;
            response[3] |= 0x80;
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(
                b"\x07ExAmPlE\x03CoM\0\0\x01\0\x01\0\0\0\x2a\0\x04\xc0\0\x02\x01",
            );
            response.extend_from_slice(&query[QUESTION_END..]);
            response
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            let (manager, unused_background) = test_manager(TestTransport::default()).await;
            // Smaller than one padded query: writes must wait for the reader.
            let (client, mut server) = tokio::io::duplex(64);
            let (stream, handle) =
                TcpStream::from_stream(AsyncIoTokioAsStd(client), "127.0.0.1:853".parse().unwrap());
            let exchange = connect_dot(
                std::future::ready(Ok(TcpClientStream::from_stream(stream))),
                handle,
                None,
            )
            .await
            .unwrap();
            let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                unreachable!();
            };
            let generation = channel.state.lock().await.store(exchange);
            unused_background.await.unwrap();
            let manager = Arc::new(manager);
            let mut query = encrypted_test_query(128);
            query.queries[0].set_name(Name::from_ascii("ExAmPlE.CoM.").unwrap());
            query.metadata.checking_disabled = true;
            query.metadata.authentic_data = true;
            let wire_query = query.to_vec().unwrap();
            let expected = answer(&wire_query);
            assert_ne!(
                Message::from_vec(&expected).unwrap().to_vec().unwrap(),
                expected
            );

            let (allow_reads, mut begin) = mpsc::channel(1);
            let sent = wire_query.clone();
            let responder = tokio::spawn(async move {
                for _ in 0..3 {
                    begin.recv().await.unwrap();
                    let mut responses = Vec::new();
                    for _ in 0..32 {
                        let n = server.read_u16().await.unwrap();
                        let mut query = vec![0; usize::from(n)];
                        server.read_exact(&mut query).await.unwrap();
                        // DoT may rewrite the ID, but not flags, question, or EDNS.
                        assert_eq!(&query[2..], &sent[2..]);
                        responses.push(answer(&query));
                    }
                    // Responses arrive out of order on the same connection.
                    for response in responses.into_iter().rev() {
                        server.write_u16(response.len() as u16).await.unwrap();
                        server.write_all(&response).await.unwrap();
                    }
                }
            });
            for round in 0..3 {
                let mut pending = tokio::task::JoinSet::new();
                for id in (round * 32)..((round + 1) * 32) {
                    let manager = manager.clone();
                    let mut query = wire_query.clone();
                    query[..2].copy_from_slice(&(id as u16).to_be_bytes());
                    pending.spawn(async move {
                        let expected = answer(&query);
                        assert_eq!(manager.forward(&query, false).await.unwrap(), expected);
                    });
                }
                // No answers can arrive yet. Fill the existing bounded pipeline
                // before allowing the peer to consume its first query.
                while manager.attempts.available_permits() > super::super::MAX_ATTEMPTS - 32 {
                    tokio::task::yield_now().await;
                }
                allow_reads.send(()).await.unwrap();
                while let Some(result) = pending.join_next().await {
                    result.unwrap();
                }
                assert_eq!(
                    manager.attempts.available_permits(),
                    super::super::MAX_ATTEMPTS
                );
                let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                    unreachable!();
                };
                let state = channel.state.lock().await;
                assert_eq!(state.generation, generation);
                assert_eq!(state.connect_failures, 0);
                assert!(state.cooldown_until.is_none());
            }
            responder.await.unwrap();
        })
        .await
        .expect("bounded DoT requests must survive write backpressure");
    }

    #[test]
    fn forwarding_future_keeps_connection_setup_out_of_line() {
        let upstream = Upstream {
            name: "future sizing".into(),
            proto: Proto::Doh,
            host: "resolver.test".into(),
            port: 443,
            path: "/dns-query".into(),
            bootstrap_ip: Some("192.0.2.53".parse().unwrap()),
            timeout_ms: 5000,
            ip_stack: IpStack::V4,
        };
        let manager = Manager::new(vec![upstream], &[], Vec::new()).unwrap();
        let message = encrypted_test_query(0);
        let query = message.to_vec().unwrap();
        let request = crate::upstream::Request::new(&query);
        // The task body must be measured too: moving work into a spawned task
        // must not make this guard pass while the actual attempt grows.
        for (name, size) in [
            (
                "forward",
                std::mem::size_of_val(&manager.forward(&query, false)),
            ),
            (
                "attempt",
                std::mem::size_of_val(&manager.entries[0].run(&request, false)),
            ),
        ] {
            assert!(size < 3072, "{name} future grew to {size} bytes");
        }
    }

    #[derive(Default)]
    struct TestTransport {
        closed: bool,
        failures: Option<mpsc::UnboundedSender<oneshot::Sender<()>>>,
        /// Accept requests and never answer, like a path dropping UDP/443.
        silent: bool,
        silent_first: bool,
        request_error: Option<NetError>,
        wrong_question: bool,
    }

    impl Stream for TestTransport {
        type Item = Result<(), NetError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.closed {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }
    }

    impl DnsRequestSender for TestTransport {
        fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
            if self.silent || std::mem::take(&mut self.silent_first) {
                return Box::pin(std::future::pending()).into();
            }
            if let Some(error) = self.request_error.take() {
                return error.into();
            }
            if let Some(failures) = &self.failures {
                let (release, pending) = oneshot::channel();
                failures.send(release).unwrap();
                return Box::pin(async move {
                    let _ = pending.await;
                    Err(NetError::from("stale connection"))
                })
                .into();
            }
            let (mut message, _) = request.into_parts();
            if self.wrong_question {
                message.queries[0].set_name(Name::from_ascii("wrong.invalid.").unwrap());
            }
            // Model DoQ's zero ID so the manager must restore the client's ID.
            message.metadata.message_type = MessageType::Response;
            message.metadata.id = 0;
            Box::pin(async move { DnsResponse::from_message(message).map_err(NetError::from) })
                .into()
        }

        fn shutdown(&mut self) {
            self.closed = true;
        }

        fn is_shutdown(&self) -> bool {
            self.closed
        }
    }

    async fn test_manager(transport: TestTransport) -> (Manager, tokio::task::JoinHandle<()>) {
        let upstream = Upstream {
            name: "in-memory encrypted transport".into(),
            proto: Proto::Doh,
            host: "resolver.test".into(),
            port: 443,
            path: "/dns-query".into(),
            bootstrap_ip: Some("192.0.2.53".parse().unwrap()),
            timeout_ms: 0,
            ip_stack: IpStack::V4,
        };
        let manager = Manager::new(vec![upstream], &[], Vec::new()).unwrap();
        let Backend::Encrypted(channel) = &manager.entries[0].backend else {
            panic!("the test upstream must use an encrypted channel");
        };
        let (exchange, background) = DnsExchange::from_stream(transport);
        channel.state.lock().await.store(exchange);
        (manager, tokio::spawn(background))
    }

    fn encrypted_test_query(padding: usize) -> Message {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        if padding > 0 {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            edns.options_mut()
                .insert(EdnsOption::Unknown(12, vec![0; padding]));
            message.set_edns(edns);
        }
        message
    }

    fn start_query(
        manager: &Arc<Manager>,
        deadline: Option<Instant>,
    ) -> tokio::task::JoinHandle<Result<Vec<u8>, String>> {
        let manager = manager.clone();
        tokio::spawn(async move {
            let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                unreachable!();
            };
            channel.query(&encrypted_test_query(0), deadline).await
        })
    }

    #[tokio::test]
    async fn raced_out_encrypted_upstream_still_backs_off_at_its_deadline() {
        let standby = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let standby_addr = standby.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut message = [0u8; 512];
            let (n, peer) = standby.recv_from(&mut message).await.unwrap();
            message[2] |= 0x80;
            standby.send_to(&message[..n], peer).await.unwrap();
        });
        let primary = Upstream {
            name: "silent DoH3".into(),
            proto: Proto::Doh3,
            host: "resolver.test".into(),
            port: 443,
            path: "/dns-query".into(),
            bootstrap_ip: Some("192.0.2.53".parse().unwrap()),
            timeout_ms: 600,
            ip_stack: IpStack::V4,
        };
        let standby = Upstream {
            name: "standby".into(),
            proto: Proto::Legacy,
            host: standby_addr.ip().to_string(),
            port: standby_addr.port(),
            path: String::new(),
            bootstrap_ip: Some(standby_addr.ip()),
            timeout_ms: 600,
            ip_stack: IpStack::V4,
        };
        let manager = Manager::new(vec![primary, standby], &[], Vec::new()).unwrap();
        let Backend::Encrypted(channel) = &manager.entries[0].backend else {
            unreachable!();
        };
        let transport = TestTransport {
            silent: true,
            ..TestTransport::default()
        };
        let (exchange, background) = DnsExchange::from_stream(transport);
        let background = tokio::spawn(background);
        channel.state.lock().await.store(exchange);

        let query = encrypted_test_query(0).to_vec().unwrap();
        let started = tokio::time::Instant::now();
        let response = manager.forward(&query, false).await.unwrap();
        crate::wire::validate_response(&query, &response).unwrap();
        responder.await.unwrap();
        assert!(channel.state.lock().await.exchange.is_some());
        assert_eq!(
            manager.attempts.available_permits(),
            super::super::MAX_ATTEMPTS - 1
        );

        // The original deadline is 600ms. Restarting the future at the 300ms
        // hedge would extend it to 900ms; check in between to catch that regression.
        tokio::time::sleep_until(started + Duration::from_millis(750)).await;
        let state = channel.state.lock().await;
        assert!(
            state.exchange.is_none(),
            "silent connection must be dropped"
        );
        assert!(
            state.cooldown_until.is_some(),
            "silent upstream must back off"
        );
        drop(state);
        assert_eq!(
            manager.attempts.available_permits(),
            super::super::MAX_ATTEMPTS
        );
        background.abort();
    }

    /// Measures local parsing/dispatch/transport work, not network or TLS latency.
    /// Run with `mbx test --release benchmark_encrypted_dispatch -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "manual warm encrypted dispatch benchmark"]
    async fn benchmark_encrypted_dispatch() {
        use std::hint::black_box;

        for upstreams in [1, 2] {
            for padding in [0, 1024] {
                let (mut manager, background) = test_manager(TestTransport::default()).await;
                Arc::get_mut(&mut manager.entries[0]).unwrap().timeout_ms = 5000;
                if upstreams == 2 {
                    manager.entries.push(manager.entries[0].clone());
                }
                // Production queries run in spawned tasks, not in block_on's
                // root future. The latter adds an artificial reactor poll per reply.
                tokio::spawn(async move {
                    let query = encrypted_test_query(padding).to_vec().unwrap();
                    for _ in 0..1000 {
                        black_box(manager.forward(&query, false).await.unwrap());
                    }
                    let mut samples = [0.0; 7];
                    for sample in &mut samples {
                        let started = Instant::now();
                        for _ in 0..20_000 {
                            black_box(manager.forward(black_box(&query), false).await.unwrap());
                        }
                        *sample = started.elapsed().as_nanos() as f64 / 20_000.0;
                    }
                    samples.sort_by(f64::total_cmp);
                    println!(
                        "upstreams={upstreams} padding={padding} median={:.1} ns/query min={:.1} max={:.1}",
                        samples[3], samples[0], samples[6]
                    );
                }).await.unwrap();
                background.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn encrypted_mismatched_questions_are_rejected_on_both_dispatch_paths() {
        for upstreams in [1, 2] {
            let (mut manager, background) = test_manager(TestTransport {
                wrong_question: true,
                ..TestTransport::default()
            })
            .await;
            if upstreams == 2 {
                manager.entries.push(manager.entries[0].clone());
            }
            let query = encrypted_test_query(0).to_vec().unwrap();
            assert!(manager.forward(&query, false).await.is_none());
            drop(manager);
            background.await.unwrap();
        }
    }

    #[tokio::test]
    async fn encrypted_forward_preserves_question_id_and_edns() {
        let (manager, background) = test_manager(TestTransport::default()).await;
        for padding in [0, 1024] {
            let query = encrypted_test_query(padding);
            let wire_query = query.to_vec().unwrap();
            let response = manager.forward(&wire_query, false).await.unwrap();
            crate::wire::validate_response(&wire_query, &response).unwrap();
            let response = Message::from_vec(&response).unwrap();
            assert_eq!(response.metadata.id, query.metadata.id);
            assert_eq!(response.queries, query.queries);
            assert_eq!(response.edns, query.edns);
        }
        drop(manager);
        background.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_connection_attempt_releases_lock_and_socket() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        tokio::time::timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let manager = Arc::new(
                Manager::new(
                    vec![Upstream {
                        name: "pending TLS handshake".into(),
                        proto: Proto::Dot,
                        host: "resolver.test".into(),
                        port: addr.port(),
                        path: String::new(),
                        bootstrap_ip: Some(addr.ip()),
                        timeout_ms: 0,
                        ip_stack: IpStack::V4,
                    }],
                    &[],
                    Vec::new(),
                )
                .unwrap(),
            );
            let query = start_query(&manager, None);
            // Leave the TLS handshake pending after TCP connects.
            let (mut socket, _) = listener.accept().await.unwrap();
            query.abort();
            assert!(query.await.unwrap_err().is_cancelled());

            let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                unreachable!();
            };
            let state = channel.state.lock().await;
            assert!(state.exchange.is_none());
            assert_eq!(state.generation, 0);
            assert_eq!(state.connect_failures, 0);
            assert!(state.cooldown_until.is_none());
            drop(state);

            // Dropping the boxed dial future must close its TCP connection.
            socket.read_to_end(&mut Vec::new()).await.unwrap();
        })
        .await
        .expect("cancelled dialing must release its resources");
    }

    #[tokio::test]
    async fn concurrent_stale_failures_share_successor_without_fallback() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (failure_tx, mut failures) = mpsc::unbounded_channel();
            let (manager, old_background) = test_manager(TestTransport {
                failures: Some(failure_tx),
                ..TestTransport::default()
            })
            .await;
            let manager = Arc::new(manager);
            let mut queries = Vec::new();
            for record_type in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
                let manager = manager.clone();
                let mut query = encrypted_test_query(0);
                query.queries[0].set_query_type(record_type);
                let wire_query = query.to_vec().unwrap();
                queries.push(tokio::spawn(async move {
                    let response = manager.forward(&wire_query, false).await.unwrap();
                    crate::wire::validate_response(&wire_query, &response).unwrap();
                }));
            }

            // Every query holds the old lease before any send can fail.
            let mut pending = Vec::new();
            for _ in 0..3 {
                pending.push(failures.recv().await.unwrap());
            }
            let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                unreachable!();
            };
            let (successor, background) = DnsExchange::from_stream(TestTransport::default());
            let background = tokio::spawn(background);
            // Model a concurrent query having already reconnected. No real
            // network or production connector hook is needed for this race.
            let generation = channel.state.lock().await.store(successor);
            for release in pending {
                release.send(()).unwrap();
            }
            for query in queries {
                query.await.unwrap();
            }

            let state = channel.state.lock().await;
            assert_eq!(state.generation, generation);
            assert!(state.exchange.is_some());
            assert_eq!(state.connect_failures, 0);
            assert!(state.cooldown_until.is_none());
            assert!(
                !manager
                    .fallback_failed
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
            drop(state);
            drop(manager);
            old_background.await.unwrap();
            background.await.unwrap();
        })
        .await
        .expect("concurrent queries must finish");
    }

    #[tokio::test]
    async fn failed_successor_backs_off_once_and_late_stale_failure_respects_cooldown() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (failure_tx, mut failures) = mpsc::unbounded_channel();
            let (manager, old_background) = test_manager(TestTransport {
                failures: Some(failure_tx),
                ..TestTransport::default()
            })
            .await;
            let manager = Arc::new(manager);
            let first = start_query(&manager, None);
            let first_failure = failures.recv().await.unwrap();
            let late = start_query(&manager, None);
            let late_failure = failures.recv().await.unwrap();

            let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                unreachable!();
            };
            let (retry_tx, mut retries) = mpsc::unbounded_channel();
            let (successor, background) = DnsExchange::from_stream(TestTransport {
                failures: Some(retry_tx),
                ..TestTransport::default()
            });
            let background = tokio::spawn(background);
            let generation = channel.state.lock().await.store(successor);
            first_failure.send(()).unwrap();
            retries.recv().await.unwrap().send(()).unwrap();
            assert_eq!(first.await.unwrap().unwrap_err(), "stale connection");

            let state = channel.state.lock().await;
            assert_eq!(state.generation, generation);
            assert!(state.exchange.is_none());
            assert_eq!(state.connect_failures, 1);
            let cooldown = state.cooldown_until;
            assert!(cooldown.is_some());
            drop(state);

            // A late failure from the original connection must neither dial
            // through the successor's cooldown nor increase its backoff.
            late_failure.send(()).unwrap();
            assert!(late.await.unwrap().unwrap_err().contains("in cooldown"));
            let state = channel.state.lock().await;
            assert_eq!(state.generation, generation);
            assert!(state.exchange.is_none());
            assert_eq!(state.connect_failures, 1);
            assert_eq!(state.cooldown_until, cooldown);
            drop(state);
            drop(manager);
            old_background.await.unwrap();
            background.await.unwrap();
        })
        .await
        .expect("failed retries must finish");
    }

    #[tokio::test]
    async fn stale_failure_without_retry_budget_preserves_successor() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (failure_tx, mut failures) = mpsc::unbounded_channel();
            let (manager, old_background) = test_manager(TestTransport {
                failures: Some(failure_tx),
                ..TestTransport::default()
            })
            .await;
            let manager = Arc::new(manager);
            let query = start_query(&manager, Some(Instant::now() + MIN_REDIAL_BUDGET));
            let failure = failures.recv().await.unwrap();
            let Backend::Encrypted(channel) = &manager.entries[0].backend else {
                unreachable!();
            };
            let (successor, background) = DnsExchange::from_stream(TestTransport::default());
            let background = tokio::spawn(background);
            let generation = channel.state.lock().await.store(successor);
            failure.send(()).unwrap();
            assert_eq!(query.await.unwrap().unwrap_err(), "stale connection");

            let state = channel.state.lock().await;
            assert_eq!(state.generation, generation);
            assert!(state.exchange.is_some());
            assert_eq!(state.connect_failures, 0);
            assert!(state.cooldown_until.is_none());
            drop(state);
            drop(manager);
            old_background.await.unwrap();
            background.await.unwrap();
        })
        .await
        .expect("queries without retry budget must finish");
    }

    #[test]
    fn store_bumps_generation_and_clears_backoff_state() {
        let mut slot = Slot::<u8> {
            connect_failures: 3,
            cooldown_until: Some(Instant::now()),
            ..Slot::default()
        };
        let generation = slot.store(1);
        assert_eq!(generation, 1);
        assert_eq!(slot.connect_failures, 0);
        assert!(slot.cooldown_until.is_none());
        assert_eq!(slot.lease(), Some((1, 1)));
    }

    /// The core race: a failure from a superseded lease must not tear down
    /// the connection a concurrent query just established.
    #[test]
    fn invalidate_ignores_stale_generations() {
        let mut slot: Slot<u8> = Slot::default();
        let old = slot.store(1);
        let new = slot.store(2);
        assert!(!slot.invalidate(old), "stale generation must be a no-op");
        assert_eq!(slot.lease(), Some((2, new)));
        assert!(slot.invalidate(new));
        assert!(slot.lease().is_none());
        assert!(!slot.invalidate(new), "second invalidation is a no-op");
    }

    #[test]
    fn sleep_drops_the_connection_without_backoff() {
        let mut slot: Slot<u8> = Slot::default();
        let generation = slot.store(1);
        let last = slot.last_used.unwrap();
        let awake = Stamp {
            mono: last.mono + Duration::from_secs(60),
            wall: last.wall + Duration::from_secs(61),
        };
        assert_eq!(slot.drop_if_slept(awake), None, "1s drift is not sleep");
        assert_eq!(slot.lease(), Some((1, generation)));

        let woke = Stamp {
            mono: awake.mono + Duration::from_secs(1),
            wall: awake.wall + Duration::from_secs(3600),
        };
        assert_eq!(slot.drop_if_slept(woke), Some(Duration::from_secs(3599)));
        assert!(slot.lease().is_none());
        assert_eq!(slot.connect_failures, 0);
        assert!(slot.cooldown_until.is_none());
        assert_eq!(slot.drop_if_slept(woke), None, "nothing left to drop");
    }

    #[test]
    fn route_lookup_finds_the_local_source_without_sending() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        assert_eq!(route_source(peer), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn route_changes_drop_the_connection_without_backoff() {
        let (peer, old, new) = (
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 443)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        );
        let mut slot: Slot<u8> = Slot::default();
        let generation = slot.store(1);
        slot.record_path(peer, Some(old));

        assert_eq!(slot.drop_if_moved(Some(old)), None);
        assert_eq!(slot.drop_if_moved(None), None, "no route is not a move");
        assert_eq!(slot.lease(), Some((1, generation)));

        assert_eq!(slot.drop_if_moved(Some(new)), Some((Some(old), new)));
        assert!(slot.lease().is_none());
        assert_eq!(slot.connect_failures, 0);
        assert!(slot.cooldown_until.is_none());
        assert_eq!(slot.drop_if_moved(Some(old)), None, "nothing left to drop");
    }

    #[test]
    fn route_checks_are_rate_limited_per_connection() {
        let peer = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 443));
        let mut slot: Slot<u8> = Slot::default();
        slot.store(1);
        assert_eq!(slot.route_check_due(Instant::now()), None, "no path yet");

        slot.record_path(peer, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        let start = slot.path.unwrap().checked;
        assert_eq!(slot.route_check_due(start), None);
        let later = start + ROUTE_CHECK_INTERVAL;
        assert_eq!(slot.route_check_due(later), Some(peer));
        assert_eq!(slot.route_check_due(later), None);
    }

    /// A deadline on a connection whose route moved is not the upstream's
    /// fault: no backoff, and the query gets one more try on the successor.
    #[tokio::test]
    async fn deadline_after_a_route_change_retries_without_backoff() {
        let (manager, old_background) = test_manager(TestTransport {
            silent: true,
            ..TestTransport::default()
        })
        .await;
        let Backend::Encrypted(channel) = &manager.entries[0].backend else {
            unreachable!();
        };
        // The route to loopback is loopback, so any other source reads as moved.
        channel.state.lock().await.record_path(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        );

        let message = encrypted_test_query(0);
        let deadline = Instant::now() + Duration::from_millis(100);
        let query = channel.query(&message, Some(deadline));
        tokio::pin!(query);
        tokio::select! {
            result = &mut query => panic!("silent connection answered: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }

        // Model a concurrent query having already reconnected.
        let (successor, background) = DnsExchange::from_stream(TestTransport::default());
        let background = tokio::spawn(background);
        let generation = channel.state.lock().await.store(successor);
        query.await.expect("the retry must reach the successor");

        let state = channel.state.lock().await;
        assert_eq!(state.generation, generation);
        assert!(state.exchange.is_some());
        assert_eq!(state.connect_failures, 0);
        assert!(state.cooldown_until.is_none());
        drop(state);
        old_background.abort();
        background.abort();
    }

    #[test]
    fn wall_clock_stepping_back_is_not_sleep() {
        let mut slot: Slot<u8> = Slot::default();
        slot.store(1);
        let last = slot.last_used.unwrap();
        let stepped = Stamp {
            mono: last.mono + Duration::from_secs(10),
            wall: last.wall - Duration::from_secs(3600),
        };
        assert_eq!(slot.drop_if_slept(stepped), None);
        assert!(slot.lease().is_some());
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        let mut slot: Slot<u8> = Slot::default();
        assert_eq!(slot.backoff(), Duration::from_secs(2));
        assert_eq!(slot.backoff(), Duration::from_secs(4));
        for _ in 0..10 {
            slot.backoff();
        }
        assert_eq!(slot.backoff(), Duration::from_secs(32));
    }

    #[test]
    fn redial_budget_respects_the_deadline() {
        assert!(budget_allows_redial(None));
        assert!(budget_allows_redial(Some(
            Instant::now() + Duration::from_secs(1)
        )));
        assert!(!budget_allows_redial(Some(
            Instant::now() + Duration::from_millis(50)
        )));
    }
    #[tokio::test]
    async fn a_slow_query_and_request_errors_preserve_a_responsive_connection() {
        let (manager, background) = test_manager(TestTransport {
            silent_first: true,
            ..TestTransport::default()
        })
        .await;
        let manager = Arc::new(manager);
        let slow = start_query(&manager, Some(Instant::now() + Duration::from_millis(100)));
        tokio::time::sleep(Duration::from_millis(20)).await;
        start_query(&manager, None).await.unwrap().unwrap();
        assert!(
            slow.await
                .unwrap()
                .unwrap_err()
                .contains("still responsive")
        );
        start_query(&manager, None).await.unwrap().unwrap();
        background.abort();
        for error in [
            NetError::Busy,
            NetError::Msg("mpsc::SendError send failed because channel is full".into()),
            NetError::Msg("http unsuccessful code: 425, message: retry".into()),
        ] {
            let (manager, background) = test_manager(TestTransport {
                request_error: Some(error),
                ..TestTransport::default()
            })
            .await;
            let manager = Arc::new(manager);
            assert!(start_query(&manager, None).await.unwrap().is_err());
            start_query(&manager, None).await.unwrap().unwrap();
            background.abort();
        }
    }

    #[tokio::test]
    async fn waiting_for_a_dial_obeys_the_query_deadline() {
        let (manager, background) = test_manager(TestTransport::default()).await;
        let Backend::Encrypted(channel) = &manager.entries[0].backend else {
            unreachable!()
        };
        let held = channel.state.lock().await;
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            channel.query(
                &encrypted_test_query(0),
                Some(Instant::now() + Duration::from_millis(20)),
            ),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().contains("deadline"));
        drop(held);
        background.abort();
    }

    #[test]
    fn network_recovery_clears_cooldown_without_an_existing_connection() {
        let mut state: Slot<u8> = Slot::default();
        state.record_path("192.0.2.53:853".parse().unwrap(), None);
        for _ in 0..5 {
            state.backoff();
        }
        assert!(
            state
                .drop_if_moved(Some("192.0.2.2".parse().unwrap()))
                .is_some()
        );
        assert!(state.cooldown_until.is_none());
        assert_eq!(state.connect_failures, 0);
    }

    #[tokio::test]
    async fn candidate_dial_leaves_time_for_the_next_address() {
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(
            finish::<_, TestTransport>(
                std::future::pending(),
                Some(dial_deadline(Some(deadline), 2))
            )
            .await
            .is_err()
        );
        let exchange = finish(
            std::future::ready(Ok(TestTransport::default())),
            Some(dial_deadline(Some(deadline), 1)),
        )
        .await
        .unwrap();
        assert!(
            send(&exchange, encrypted_test_query(0), Some(deadline))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn dot_accepts_more_than_32_inflight_requests() {
        use hickory_net::runtime::iocompat::AsyncIoTokioAsStd;
        use hickory_net::tcp::{TcpClientStream, TcpStream};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, mut server) = tokio::io::duplex(4096);
            let (stream, handle) =
                TcpStream::from_stream(AsyncIoTokioAsStd(client), "127.0.0.1:853".parse().unwrap());
            let exchange = connect_dot(
                std::future::ready(Ok(TcpClientStream::from_stream(stream))),
                handle,
                None,
            )
            .await
            .unwrap();
            let mut pending = tokio::task::JoinSet::new();
            let mut responses = Vec::new();
            for _ in 0..64 {
                let exchange = exchange.clone();
                pending.spawn(async move {
                    send(&exchange, encrypted_test_query(0), None).await.is_ok()
                });
                let len = server.read_u16().await.unwrap();
                let mut query = vec![0; len as usize];
                server.read_exact(&mut query).await.unwrap();
                query[2] |= 0x80;
                responses.push(query);
            }
            for response in responses {
                server.write_u16(response.len() as u16).await.unwrap();
                server.write_all(&response).await.unwrap();
            }
            while let Some(result) = pending.join_next().await {
                assert!(result.unwrap());
            }
        })
        .await
        .expect("all 64 requests must reach the peer before it answers");
    }
}
