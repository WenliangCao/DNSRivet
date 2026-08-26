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
//! - errors from a superseded generation: no state change at all.

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
        message: Message,
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
                    if !state.invalidate(lease.generation) {
                        // A concurrent query already replaced this
                        // generation; leave the successor alone.
                        return Err(err);
                    }
                    let redial = lease.reused && !retried && budget_allows_redial(deadline);
                    if !redial {
                        state.backoff();
                        return Err(err);
                    }
                    drop(state);
                    log::debug!(
                        "upstream {}: stale connection ({err}); redialing once",
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
            if self.deny.contains(&addr)
                || (ip.is_loopback() && self.deny.iter().any(|l| l.port() == self.up.port))
            {
                last_err = format!("{addr} points back at our own listener");
                continue;
            }
            log::debug!(
                "upstream {}: dialing {} {addr}",
                self.up.name,
                self.up.proto.as_str()
            );
            match connect(&self.up, &self.tls, addr, deadline).await {
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
