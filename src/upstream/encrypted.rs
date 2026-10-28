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
//! - deadline expiry: invalidate + backoff, no retry (a wedged-but-accepting
//!   upstream must not tax every query with its full timeout);
//! - errors from a superseded generation: no state change; retry once on
//!   the successor while budget remains if the failed lease was reused.

use crate::config::{Proto, Upstream};
use crate::upstream::bootstrap::Bootstrap;
use hickory_proto::ProtoError;
use hickory_proto::h2::HttpsClientStreamBuilder;
use hickory_proto::h3::H3ClientStream;
use hickory_proto::op::Message;
use hickory_proto::quic::QuicClientStream;
use hickory_proto::runtime::{TokioRuntimeProvider, TokioTime};
use hickory_proto::rustls::tls_client_connect;
use hickory_proto::xfer::{
    DnsExchange, DnsExchangeConnect, DnsHandle, DnsMultiplexer, DnsRequest, DnsRequestOptions,
    DnsRequestSender, FirstAnswer,
};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF_SHIFT: u32 = 5; // 2^5 = 32s cap
/// A redial is only worth it while at least this much budget remains.
const MIN_REDIAL_BUDGET: Duration = Duration::from_millis(250);

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

/// Generation-tracked connection slot. Generic over the handle type so the
/// invalidation rules are unit-testable without real connections.
struct Slot<E> {
    exchange: Option<E>,
    generation: u64,
    connect_failures: u32,
    cooldown_until: Option<Instant>,
}

impl<E> Default for Slot<E> {
    fn default() -> Self {
        Self {
            exchange: None,
            generation: 0,
            connect_failures: 0,
            cooldown_until: None,
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
        self.generation
    }

    /// Clear the slot only if `generation` is still the current one; a
    /// failure from a superseded lease must never tear down its successor.
    fn invalidate(&mut self, generation: u64) -> bool {
        if self.generation == generation && self.exchange.is_some() {
            self.exchange = None;
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
    exchange: DnsExchange,
    generation: u64,
    reused: bool,
}

enum SendFailure {
    Deadline,
    Transport(String),
}

pub struct Channel {
    up: Upstream,
    tls: Arc<rustls::ClientConfig>,
    bootstrap: Arc<Bootstrap>,
    /// Our own listener addresses — refuse to dial ourselves.
    deny: Arc<Vec<SocketAddr>>,
    state: Mutex<Slot<DnsExchange>>,
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
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>, String> {
        let mut lease = self.acquire(deadline).await?;
        let mut retried = false;
        loop {
            match send(&lease.exchange, message.clone(), deadline).await {
                Ok(buffer) => return Ok(buffer),
                Err(SendFailure::Deadline) => {
                    let mut state = self.state.lock().await;
                    if state.invalidate(lease.generation) {
                        state.backoff();
                    }
                    return Err("no answer within the deadline".into());
                }
                Err(SendFailure::Transport(err)) => {
                    let mut state = self.state.lock().await;
                    let invalidated = state.invalidate(lease.generation);
                    let redial = lease.reused && !retried && budget_allows_redial(deadline);
                    if !redial {
                        if invalidated {
                            state.backoff();
                        }
                        return Err(err);
                    }
                    // A concurrent query may already have invalidated or
                    // replaced this generation. Share its successor without
                    // changing that connection's state or backoff.
                    drop(state);
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
        let mut state = self.state.lock().await;
        if let Some((exchange, generation)) = state.lease() {
            return Ok(Lease {
                exchange,
                generation,
                reused: true,
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

        let ips = match self.up.bootstrap_ip {
            Some(ip) => vec![ip],
            None => {
                if state.connect_failures > 0 {
                    self.bootstrap.invalidate(&self.up.host).await;
                }
                match self
                    .bootstrap
                    .resolve(&self.up.host, self.up.ip_stack)
                    .await
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
        for ip in ips {
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
            match Box::pin(connect(&self.up, &self.tls, addr, deadline)).await {
                Ok(exchange) => {
                    log::info!(
                        "upstream {}: connected {} to {addr}",
                        self.up.name,
                        self.up.proto.as_str()
                    );
                    let generation = state.store(exchange.clone());
                    return Ok(Lease {
                        exchange,
                        generation,
                        reused: false,
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

fn budget_allows_redial(deadline: Option<Instant>) -> bool {
    deadline.is_none_or(|d| d.saturating_duration_since(Instant::now()) > MIN_REDIAL_BUDGET)
}

async fn send(
    exchange: &DnsExchange,
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
        .map_err(|err| SendFailure::Transport(err.to_string()))
}

async fn connect(
    up: &Upstream,
    tls: &Arc<rustls::ClientConfig>,
    addr: SocketAddr,
    deadline: Option<Instant>,
) -> Result<DnsExchange, String> {
    let provider = TokioRuntimeProvider::new();
    match up.proto {
        Proto::Dot => {
            let (conn, handle) = tls_client_connect(addr, up.host.clone(), tls.clone(), provider);
            finish(
                DnsExchange::connect(DnsMultiplexer::new(conn, handle, None)),
                deadline,
            )
            .await
        }
        Proto::Doh => {
            let builder = HttpsClientStreamBuilder::with_client_config(tls.clone(), provider);
            finish(
                DnsExchange::connect(builder.build(addr, up.host.clone(), up.path.clone())),
                deadline,
            )
            .await
        }
        Proto::Doq => {
            let mut builder = QuicClientStream::builder();
            builder.crypto_config((**tls).clone());
            finish(
                DnsExchange::connect(builder.build(addr, up.host.clone())),
                deadline,
            )
            .await
        }
        Proto::Doh3 => {
            let mut builder = H3ClientStream::builder();
            builder.crypto_config((**tls).clone());
            finish(
                DnsExchange::connect(builder.build(addr, up.host.clone(), up.path.clone())),
                deadline,
            )
            .await
        }
        Proto::Legacy => unreachable!("legacy upstreams don't use encrypted channels"),
    }
}

async fn finish<F, S>(
    connect: DnsExchangeConnect<F, S, TokioTime>,
    deadline: Option<Instant>,
) -> Result<DnsExchange, String>
where
    F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
    S: DnsRequestSender + Send + Unpin + 'static,
{
    let limit = match deadline {
        Some(at) => CONNECT_TIMEOUT.min(at.saturating_duration_since(Instant::now())),
        None => CONNECT_TIMEOUT,
    };
    let (exchange, background) = tokio::time::timeout(limit, connect)
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| e.to_string())?;
    tokio::spawn(background);
    Ok(exchange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpStack;
    use crate::upstream::{Backend, Manager};
    use futures_core::Stream;
    use hickory_proto::op::{Edns, MessageType, Query};
    use hickory_proto::rr::rdata::opt::EdnsOption;
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::xfer::{DnsResponse, DnsResponseStream};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::sync::{mpsc, oneshot};

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
        let size = std::mem::size_of_val(&manager.forward(&query, false));
        // Leave room for compiler/layout differences while detecting inline
        // connection futures being carried by every concurrent request.
        assert!(size < 3072, "forwarding future grew to {size} bytes");
    }

    #[derive(Default)]
    struct TestTransport {
        closed: bool,
        failures: Option<mpsc::UnboundedSender<oneshot::Sender<()>>>,
        /// Accept requests and never answer, like a path dropping UDP/443.
        silent: bool,
    }

    impl Stream for TestTransport {
        type Item = Result<(), ProtoError>;

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
            if self.silent {
                return Box::pin(std::future::pending()).into();
            }
            if let Some(failures) = &self.failures {
                let (release, pending) = oneshot::channel();
                failures.send(release).unwrap();
                return Box::pin(async move {
                    let _ = pending.await;
                    Err(ProtoError::from("stale connection"))
                })
                .into();
            }
            let (mut message, _) = request.into_parts();
            // Model DoQ's zero ID so the manager must restore the client's ID.
            message.set_message_type(MessageType::Response).set_id(0);
            Box::pin(async move { DnsResponse::from_message(message) }).into()
        }

        fn shutdown(&mut self) {
            self.closed = true;
        }

        fn is_shutdown(&self) -> bool {
            self.closed
        }
    }

    async fn test_manager(
        transport: TestTransport,
    ) -> (Manager, tokio::task::JoinHandle<Result<(), ProtoError>>) {
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
        let (exchange, background) = DnsExchange::from_stream::<_, TokioTime>(transport);
        channel.state.lock().await.store(exchange);
        (manager, tokio::spawn(background))
    }

    fn encrypted_test_query(padding: usize) -> Message {
        let mut message = Message::new();
        message
            .set_id(0x1234)
            .set_recursion_desired(true)
            .add_query(Query::query(
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
        let (exchange, background) = DnsExchange::from_stream::<_, TokioTime>(transport);
        let background = tokio::spawn(background);
        channel.state.lock().await.store(exchange);

        let query = encrypted_test_query(0).to_vec().unwrap();
        let response = manager.forward(&query, false).await.unwrap();
        crate::wire::validate_response(&query, &response).unwrap();
        responder.await.unwrap();
        assert!(channel.state.lock().await.exchange.is_some());
        assert_eq!(
            manager.attempts.available_permits(),
            super::super::MAX_ATTEMPTS - 1
        );

        // The raced-out attempt keeps its budget and hits its own deadline.
        tokio::time::sleep(Duration::from_millis(800)).await;
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

    #[tokio::test]
    async fn encrypted_forward_preserves_question_id_and_edns() {
        let (manager, background) = test_manager(TestTransport::default()).await;
        for padding in [0, 1024] {
            let query = encrypted_test_query(padding);
            let wire_query = query.to_vec().unwrap();
            let response = manager.forward(&wire_query, false).await.unwrap();
            crate::wire::validate_response(&wire_query, &response).unwrap();
            let response = Message::from_vec(&response).unwrap();
            assert_eq!(response.id(), query.id());
            assert_eq!(response.queries(), query.queries());
            assert_eq!(response.extensions(), query.extensions());
        }
        drop(manager);
        background.await.unwrap().unwrap();
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
                query.queries_mut()[0].set_query_type(record_type);
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
            let (successor, background) =
                DnsExchange::from_stream::<_, TokioTime>(TestTransport::default());
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
            old_background.await.unwrap().unwrap();
            background.await.unwrap().unwrap();
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
            let (successor, background) = DnsExchange::from_stream::<_, TokioTime>(TestTransport {
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
            old_background.await.unwrap().unwrap();
            background.await.unwrap().unwrap();
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
            let (successor, background) =
                DnsExchange::from_stream::<_, TokioTime>(TestTransport::default());
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
            old_background.await.unwrap().unwrap();
            background.await.unwrap().unwrap();
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
}
