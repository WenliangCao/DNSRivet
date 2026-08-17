pub mod bootstrap;
pub mod encrypted;
pub mod legacy;

use crate::config::{IpStack, Proto, Upstream};
use bootstrap::Bootstrap;
use hickory_proto::op::{Message, MessageType, OpCode};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Ordered-failover view over the configured upstreams.
pub struct Manager {
    entries: Vec<Entry>,
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
    pub fn new(all: Vec<Upstream>, listeners: &[SocketAddr]) -> Result<Self, String> {
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
        Ok(Self { entries })
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
}
