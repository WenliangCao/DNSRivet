//! DoH / DoH3 / DoT / DoQ upstream channels.
//!
//! Each upstream keeps one lazily-connected `DnsExchange` (a multiplexed
//! persistent connection); queries clone the cheap handle. Failed sends drop
//! the exchange so the next query reconnects; repeated connect failures back
//! off exponentially.

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

#[derive(Default)]
struct State {
    exchange: Option<DnsExchange>,
    connect_failures: u32,
    cooldown_until: Option<Instant>,
}

pub struct Channel {
    up: Upstream,
    tls: Arc<rustls::ClientConfig>,
    bootstrap: Arc<Bootstrap>,
    /// Our own listener addresses — refuse to dial ourselves.
    deny: Arc<Vec<SocketAddr>>,
    state: Mutex<State>,
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
            state: Mutex::new(State::default()),
        }
    }

    pub async fn query(&self, message: Message) -> Result<Vec<u8>, String> {
        let exchange = self.acquire().await?;
        let request = DnsRequest::new(message, DnsRequestOptions::default());
        match exchange.send(request).first_answer().await {
            Ok(response) => Ok(response.into_buffer()),
            Err(err) => {
                // Connection is broken; next query dials fresh.
                self.state.lock().await.exchange = None;
                Err(err.to_string())
            }
        }
    }

    /// Discard a possibly wedged multiplexed connection after the manager's
    /// per-upstream request timeout fires.
    pub async fn reset(&self) {
        let mut state = self.state.lock().await;
        state.exchange = None;
        set_backoff(&mut state);
    }

    async fn acquire(&self) -> Result<DnsExchange, String> {
        // Holding the async lock across connect serializes dial attempts,
        // so a burst of queries cannot stampede-connect.
        let mut state = self.state.lock().await;
        if let Some(exchange) = &state.exchange {
            return Ok(exchange.clone());
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
                        set_backoff(&mut state);
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
            match connect(&self.up, &self.tls, addr).await {
                Ok(exchange) => {
                    log::info!(
                        "upstream {}: connected {} to {addr}",
                        self.up.name,
                        self.up.proto.as_str()
                    );
                    state.exchange = Some(exchange.clone());
                    state.connect_failures = 0;
                    state.cooldown_until = None;
                    return Ok(exchange);
                }
                Err(err) => {
                    log::debug!("upstream {}: dial {addr}: {err}", self.up.name);
                    last_err = err;
                }
            }
        }

        let backoff = set_backoff(&mut state);
        Err(format!(
            "connect failed ({last_err}); backing off {backoff:?}"
        ))
    }
}

fn set_backoff(state: &mut State) -> Duration {
    state.connect_failures = state.connect_failures.saturating_add(1);
    let backoff = Duration::from_secs(1 << state.connect_failures.min(MAX_BACKOFF_SHIFT));
    state.cooldown_until = Some(Instant::now() + backoff);
    backoff
}

async fn connect(
    up: &Upstream,
    tls: &Arc<rustls::ClientConfig>,
    addr: SocketAddr,
) -> Result<DnsExchange, String> {
    let provider = TokioRuntimeProvider::new();
    match up.proto {
        Proto::Dot => {
            let (conn, handle) = tls_client_connect(addr, up.host.clone(), tls.clone(), provider);
            finish(DnsExchange::connect(DnsMultiplexer::new(
                conn, handle, None,
            )))
            .await
        }
        Proto::Doh => {
            let builder = HttpsClientStreamBuilder::with_client_config(tls.clone(), provider);
            finish(DnsExchange::connect(builder.build(
                addr,
                up.host.clone(),
                up.path.clone(),
            )))
            .await
        }
        Proto::Doq => {
            let mut builder = QuicClientStream::builder();
            builder.crypto_config((**tls).clone());
            finish(DnsExchange::connect(builder.build(addr, up.host.clone()))).await
        }
        Proto::Doh3 => {
            let mut builder = H3ClientStream::builder();
            builder.crypto_config((**tls).clone());
            finish(DnsExchange::connect(builder.build(
                addr,
                up.host.clone(),
                up.path.clone(),
            )))
            .await
        }
        Proto::Legacy => unreachable!("legacy upstreams don't use encrypted channels"),
    }
}

async fn finish<F, S>(connect: DnsExchangeConnect<F, S, TokioTime>) -> Result<DnsExchange, String>
where
    F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
    S: DnsRequestSender + Send + Unpin + 'static,
{
    let (exchange, background) = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| e.to_string())?;
    tokio::spawn(background);
    Ok(exchange)
}
