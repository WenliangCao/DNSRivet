//! Hostname resolution that never touches the system resolver — once we own
//! the OS DNS, getaddrinfo would loop straight back into our own listener.
//! Queries go as plain UDP directly to hardcoded public bootstrap servers.

use crate::config::IpStack;
use crate::upstream::legacy;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const SERVERS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 86_400;

struct Entry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

pub struct Bootstrap {
    cache: Mutex<HashMap<(String, IpStack), Entry>>,
}

impl Bootstrap {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub async fn resolve(&self, host: &str, stack: IpStack) -> Result<Vec<IpAddr>, String> {
        let key = (host.to_ascii_lowercase(), stack);
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(&key)
                && Instant::now() < entry.expires
            {
                return Ok(entry.ips.clone());
            }
        }

        let name = Name::from_str(host).map_err(|e| format!("invalid hostname {host:?}: {e}"))?;
        let rtypes: &[RecordType] = match stack {
            IpStack::V4 => &[RecordType::A],
            IpStack::V6 => &[RecordType::AAAA],
            IpStack::Both => &[RecordType::A, RecordType::AAAA],
        };

        let mut ips = Vec::new();
        let mut min_ttl = MAX_TTL_SECS;
        let mut last_err = String::from("no bootstrap servers");
        for server in SERVERS {
            for &rtype in rtypes {
                match query(server, &name, rtype).await {
                    Ok((mut got, ttl)) => {
                        min_ttl = min_ttl.min(u64::from(ttl));
                        ips.append(&mut got);
                    }
                    Err(err) => last_err = err,
                }
            }
            if !ips.is_empty() {
                break; // first bootstrap server that answers wins
            }
        }
        if ips.is_empty() {
            return Err(format!("bootstrap failed for {host}: {last_err}"));
        }
        ips.sort_by_key(|ip| ip.is_ipv6()); // prefer v4 dial order
        ips.dedup();

        let ttl = min_ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        log::debug!("bootstrap: {host} -> {ips:?} (ttl {ttl}s)");
        self.cache.lock().await.insert(
            key,
            Entry {
                ips: ips.clone(),
                expires: Instant::now() + Duration::from_secs(ttl),
            },
        );
        Ok(ips)
    }

    /// Force re-resolution after connect failures (host may have moved).
    pub async fn invalidate(&self, host: &str) {
        let host = host.to_ascii_lowercase();
        self.cache.lock().await.retain(|(h, _), _| *h != host);
    }
}

async fn query(
    server: IpAddr,
    name: &Name,
    rtype: RecordType,
) -> Result<(Vec<IpAddr>, u32), String> {
    let mut msg = Message::new();
    msg.set_id(next_id())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name.clone(), rtype));
    let bytes = msg.to_vec().map_err(|e| e.to_string())?;

    let response = tokio::time::timeout(
        QUERY_TIMEOUT,
        legacy::query(SocketAddr::new(server, 53), &bytes, false),
    )
    .await
    .map_err(|_| format!("bootstrap server {server} timed out"))??;

    let parsed = Message::from_vec(&response).map_err(|e| e.to_string())?;
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for record in parsed.answers() {
        match record.data() {
            RData::A(a) => {
                ips.push(IpAddr::V4(a.0));
                ttl = ttl.min(record.ttl());
            }
            RData::AAAA(aaaa) => {
                ips.push(IpAddr::V6(aaaa.0));
                ttl = ttl.min(record.ttl());
            }
            _ => {} // CNAME chain links etc.
        }
    }
    Ok((ips, ttl))
}

fn next_id() -> u16 {
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16;
    nanos ^ COUNTER.fetch_add(0x9e37, Ordering::Relaxed)
}
