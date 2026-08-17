pub mod bootstrap;
pub mod encrypted;
pub mod legacy;

use crate::config::{IpStack, Proto, Upstream};
use bootstrap::Bootstrap;
use hickory_proto::op::{Message, MessageType, OpCode};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Ordered-failover view over the configured upstreams.
pub struct Manager {
    entries: Vec<Entry>,
    system_fallback: Vec<SocketAddr>,
    fallback_active: AtomicBool,
    fallback_failed: AtomicBool,
}

struct Entry {
    name: String,
    timeout_ms: u64,
    backend: Backend,
}

enum Backend {
    Legacy {
        host: String,
        port: u16,
        ip: Option<IpAddr>,
        stack: IpStack,
        bootstrap: Arc<Bootstrap>,
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
            if let Some(ip) = up.bootstrap_ip {
                let dialing_self = listeners.contains(&SocketAddr::new(ip, up.port))
                    || (ip.is_loopback() && listeners.iter().any(|l| l.port() == up.port));
                if dialing_self {
                    return Err(format!(
                        "upstream {}: endpoint {}:{} points at our own listener",
                        up.name, ip, up.port
                    ));
                }
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
                },
                _ => Backend::Encrypted(encrypted::Channel::new(
                    up,
                    tls.clone()
                        .expect("tls config built when encrypted upstreams exist"),
                    boot.clone(),
                    deny.clone(),
                )),
            };
            entries.push(Entry {
                name,
                timeout_ms,
                backend,
            });
        }
        Ok(Self {
            entries,
            system_fallback,
            fallback_active: AtomicBool::new(false),
            fallback_failed: AtomicBool::new(false),
        })
    }

    /// Try each upstream in config order; None when all of them failed.
    /// `client_tcp` enables the TC-triggered TCP retry on legacy upstreams.
    pub async fn forward(&self, query: &[u8], client_tcp: bool) -> Option<Vec<u8>> {
        // Encrypted transports need the parsed message (they re-serialize with
        // their own IDs); parse once, lazily, and reuse across attempts.
        let mut parsed: Option<Message> = None;

        for entry in &self.entries {
            log::debug!(
                "trying upstream {} (timeout {}ms)",
                entry.name,
                entry.timeout_ms
            );
            let attempt = entry.attempt(query, client_tcp, &mut parsed);
            let result = if entry.timeout_ms > 0 {
                match tokio::time::timeout(Duration::from_millis(entry.timeout_ms), attempt).await {
                    Ok(result) => result,
                    Err(_) => {
                        entry.reset_after_timeout().await;
                        Err(format!("timeout after {}ms", entry.timeout_ms))
                    }
                }
            } else {
                attempt.await
            };
            match result {
                Ok(mut response) => {
                    let fallback_was_active = self.fallback_active.swap(false, Ordering::Relaxed);
                    let fallback_had_failed = self.fallback_failed.swap(false, Ordering::Relaxed);
                    if fallback_was_active {
                        log::info!("configured DNS upstreams recovered; system fallback inactive");
                    } else if fallback_had_failed {
                        log::info!("configured DNS upstreams recovered after a SERVFAIL episode");
                    }
                    if response.len() >= 2 {
                        // Transports may rewrite the DNS ID (DoQ pins it to 0);
                        // hand the client back its own.
                        response[..2].copy_from_slice(&query[..2]);
                    }
                    return Some(response);
                }
                Err(err) => log::debug!("upstream {}: {err}", entry.name),
            }
        }
        self.forward_to_system(query, client_tcp).await
    }

    async fn forward_to_system(&self, query: &[u8], client_tcp: bool) -> Option<Vec<u8>> {
        if self.system_fallback.is_empty() {
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
        for server in &self.system_fallback {
            let attempt = legacy::query(*server, query, client_tcp);
            match tokio::time::timeout(Duration::from_secs(2), attempt).await {
                Ok(Ok(response)) => {
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

impl Entry {
    async fn reset_after_timeout(&self) {
        if let Backend::Encrypted(channel) = &self.backend {
            channel.reset().await;
        }
    }

    async fn attempt(
        &self,
        query: &[u8],
        client_tcp: bool,
        parsed: &mut Option<Message>,
    ) -> Result<Vec<u8>, String> {
        match &self.backend {
            Backend::Legacy {
                host,
                port,
                ip,
                stack,
                bootstrap,
            } => {
                let ips = match ip {
                    Some(ip) => vec![*ip],
                    None => bootstrap.resolve(host, *stack).await?,
                };
                let mut last_err = String::from("no addresses");
                for ip in ips {
                    match legacy::query(SocketAddr::new(ip, *port), query, client_tcp).await {
                        Ok(response) => return Ok(response),
                        Err(err) => last_err = err,
                    }
                }
                Err(last_err)
            }
            Backend::Encrypted(channel) => {
                if parsed.is_none() {
                    let message =
                        Message::from_vec(query).map_err(|e| format!("unparseable query: {e}"))?;
                    if !safe_encrypted_query(&message) {
                        return Err("unsupported query shape for encrypted forwarding".into());
                    }
                    *parsed = Some(message);
                }
                channel.query(parsed.clone().unwrap()).await
            }
        }
    }
}

/// hickory-proto 0.25's transport API re-encodes requests. Bound that encoder
/// to the only shape a recursive stub should send: one question, no resource
/// records or signatures, and an optional EDNS record. Besides rejecting
/// nonsensical client messages, this makes the record-amplification precondition
/// from RUSTSEC-2026-0119 unreachable.
fn safe_encrypted_query(message: &Message) -> bool {
    message.message_type() == MessageType::Query
        && message.op_code() == OpCode::Query
        && message.queries().len() == 1
        && message.answers().is_empty()
        && message.name_servers().is_empty()
        && message.additionals().is_empty()
        && message.signature().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use tokio::net::UdpSocket;

    #[test]
    fn encrypted_encoder_accepts_only_single_question_queries() {
        let name = Name::from_str("example.com.").unwrap();
        let mut query = Message::new();
        query
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .add_query(Query::query(name.clone(), RecordType::A));
        assert!(safe_encrypted_query(&query));

        query.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        assert!(!safe_encrypted_query(&query));
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
