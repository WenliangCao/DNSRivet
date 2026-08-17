use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

// ---------- raw TOML layer ----------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawConfig {
    service: RawService,
    listener: BTreeMap<String, RawListener>,
    upstream: BTreeMap<String, RawUpstream>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RawService {
    log_level: String,
    log_path: String,
    cache_enable: bool,
    cache_size: usize,
}

impl Default for RawService {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            log_path: String::new(),
            cache_enable: true,
            cache_size: 4096,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RawListener {
    ip: String,
    port: u16,
}

impl Default for RawListener {
    fn default() -> Self {
        Self {
            ip: "127.0.0.1".into(),
            port: 53,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawUpstream {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    endpoint: String,
    bootstrap_ip: String,
    timeout: u64,
    ip_stack: String,
}

// ---------- validated layer ----------

#[derive(Debug)]
pub struct Loaded {
    pub config: Config,
    /// Deferred to the caller so they can be emitted once the logger is up.
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct Config {
    pub service: Service,
    pub listeners: Vec<SocketAddr>,
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug)]
pub struct Service {
    pub log_level: log::LevelFilter,
    pub log_path: Option<String>,
    pub cache_enable: bool,
    pub cache_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Doh,
    Doh3,
    Dot,
    Doq,
    Legacy,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Doh => "doh",
            Proto::Doh3 => "doh3",
            Proto::Dot => "dot",
            Proto::Doq => "doq",
            Proto::Legacy => "legacy",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Proto::Doh | Proto::Doh3 => 443,
            Proto::Dot | Proto::Doq => 853,
            Proto::Legacy => 53,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpStack {
    Both,
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub proto: Proto,
    /// Hostname or IP literal: TLS server name and connect target.
    pub host: String,
    pub port: u16,
    /// URL path + query for doh/doh3; empty otherwise.
    pub path: String,
    /// Pre-resolved address; filled from `bootstrap_ip` or an IP-literal host.
    pub bootstrap_ip: Option<IpAddr>,
    /// 0 = no timeout.
    pub timeout_ms: u64,
    pub ip_stack: IpStack,
}

pub fn load(path: &Path) -> Result<Loaded, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let table: toml::Table = text.parse().map_err(|e| format!("TOML parse error: {e}"))?;

    let mut warnings = Vec::new();
    scan_unknown(&table, &mut warnings);

    let raw: RawConfig = table
        .try_into()
        .map_err(|e| format!("invalid config: {e}"))?;

    let service = parse_service(raw.service, &mut warnings)?;

    let mut listeners = Vec::new();
    for (key, listener) in sorted_numeric(raw.listener) {
        let ip: IpAddr = listener
            .ip
            .parse()
            .map_err(|_| format!("[listener.{key}] invalid ip: {:?}", listener.ip))?;
        listeners.push(SocketAddr::new(ip, listener.port));
    }
    if listeners.is_empty() {
        listeners.push("127.0.0.1:53".parse().unwrap());
    }

    let mut upstreams = Vec::new();
    for (key, upstream) in sorted_numeric(raw.upstream) {
        upstreams.push(parse_upstream(&key, upstream, &mut warnings)?);
    }
    if upstreams.is_empty() {
        return Err("at least one [upstream.N] section is required".into());
    }

    Ok(Loaded {
        config: Config {
            service,
            listeners,
            upstreams,
        },
        warnings,
    })
}

/// Unknown or intentionally unsupported config sections/fields: warn instead
/// of silently swallowing them so migrating users know what changed.
fn scan_unknown(root: &toml::Table, warnings: &mut Vec<String>) {
    for key in root.keys() {
        if !matches!(key.as_str(), "service" | "listener" | "upstream") {
            warnings.push(format!("section [{key}] is not supported and was ignored"));
        }
    }

    if let Some(service) = root.get("service").and_then(|v| v.as_table()) {
        for field in service.keys() {
            if !matches!(
                field.as_str(),
                "log_level" | "log_path" | "cache_enable" | "cache_size"
            ) {
                warnings.push(format!(
                    "[service] field {field:?} is not supported and was ignored"
                ));
            }
        }
    }

    for (section, allowed) in [
        ("listener", &["ip", "port"][..]),
        (
            "upstream",
            &[
                "name",
                "type",
                "endpoint",
                "bootstrap_ip",
                "timeout",
                "ip_stack",
            ][..],
        ),
    ] {
        let Some(entries) = root.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        for (key, entry) in entries {
            let Some(table) = entry.as_table() else {
                continue;
            };
            for field in table.keys() {
                if !allowed.contains(&field.as_str()) {
                    warnings.push(format!(
                        "[{section}.{key}] field {field:?} is not supported and was ignored"
                    ));
                }
            }
        }
    }
}

/// "0", "1", "10" should order numerically, not lexically.
fn sorted_numeric<T>(map: BTreeMap<String, T>) -> Vec<(String, T)> {
    let mut entries: Vec<_> = map.into_iter().collect();
    entries.sort_by_key(|(k, _)| (k.parse::<u64>().unwrap_or(u64::MAX), k.clone()));
    entries
}

fn parse_service(raw: RawService, warnings: &mut Vec<String>) -> Result<Service, String> {
    let log_level = match raw.log_level.to_ascii_lowercase().as_str() {
        "" | "info" => log::LevelFilter::Info,
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "warn" | "warning" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        "fatal" => {
            warnings.push("[service] log_level \"fatal\" treated as \"error\"".into());
            log::LevelFilter::Error
        }
        other => return Err(format!("[service] invalid log_level: {other:?}")),
    };
    let cache_enable = raw.cache_enable && raw.cache_size > 0;
    if raw.cache_enable && raw.cache_size == 0 {
        warnings.push("[service] cache_size must be positive; cache disabled".into());
    }
    Ok(Service {
        log_level,
        log_path: if raw.log_path.is_empty() {
            None
        } else {
            Some(raw.log_path)
        },
        cache_enable,
        cache_size: raw.cache_size.max(1),
    })
}

fn parse_upstream(
    key: &str,
    raw: RawUpstream,
    warnings: &mut Vec<String>,
) -> Result<Upstream, String> {
    let ctx = format!("[upstream.{key}]");
    if raw.endpoint.is_empty() {
        return Err(format!("{ctx} endpoint is required"));
    }

    // Protocol: explicit `type` wins; otherwise inferred from the endpoint scheme.
    let explicit = match raw.kind.to_ascii_lowercase().as_str() {
        "" => None,
        "doh" => Some(Proto::Doh),
        "doh3" => Some(Proto::Doh3),
        "dot" => Some(Proto::Dot),
        "doq" => Some(Proto::Doq),
        "legacy" => Some(Proto::Legacy),
        other => {
            return Err(format!(
                "{ctx} invalid type {other:?} (expected doh, doh3, dot, doq or legacy)"
            ));
        }
    };

    let (scheme, rest) = split_scheme(&raw.endpoint);
    let inferred = match scheme {
        Some("https") => Some(Proto::Doh),
        Some("h3") => Some(Proto::Doh3),
        Some("quic") => Some(Proto::Doq),
        Some("tls") | Some("dot") => Some(Proto::Dot),
        Some(other) => return Err(format!("{ctx} unsupported endpoint scheme {other:?}://")),
        None => None,
    };

    let proto = match (explicit, inferred) {
        (Some(t), None) => t,
        (None, Some(i)) => i,
        (Some(t), Some(i)) => {
            // https:// carries both doh and doh3; other mismatches are config errors.
            let compatible = i == t || (i == Proto::Doh && t == Proto::Doh3);
            if !compatible {
                return Err(format!(
                    "{ctx} endpoint scheme {}:// conflicts with type {:?}",
                    scheme.unwrap(),
                    raw.kind
                ));
            }
            t
        }
        (None, None) => {
            if rest.parse::<IpAddr>().is_ok()
                || split_host_port(rest, 53)
                    .map(|(h, _)| h.parse::<IpAddr>().is_ok())
                    .unwrap_or(false)
            {
                Proto::Legacy
            } else {
                return Err(format!(
                    "{ctx} type is required for endpoint {:?}",
                    raw.endpoint
                ));
            }
        }
    };

    // Split host[:port] and, for DoH/DoH3, the URL path.
    let (hostport, path) = if matches!(proto, Proto::Doh | Proto::Doh3) {
        let (hostport, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        let path = if path.is_empty() || path == "/" {
            if scheme.is_none() {
                warnings.push(format!(
                    "{ctx} bare {} endpoint; assuming https://{}/dns-query",
                    proto.as_str(),
                    hostport
                ));
            }
            "/dns-query".to_string()
        } else {
            path.to_string()
        };
        (hostport, path)
    } else {
        if rest.contains('/') {
            return Err(format!(
                "{ctx} {} endpoint must be host[:port], not a URL",
                proto.as_str()
            ));
        }
        (rest, String::new())
    };

    let (host, port) = split_host_port(hostport, proto.default_port())
        .ok_or_else(|| format!("{ctx} invalid endpoint host: {hostport:?}"))?;

    let mut bootstrap_ip = if raw.bootstrap_ip.is_empty() {
        None
    } else {
        Some(
            raw.bootstrap_ip
                .parse::<IpAddr>()
                .map_err(|_| format!("{ctx} invalid bootstrap_ip: {:?}", raw.bootstrap_ip))?,
        )
    };
    // IP-literal hosts are already resolved.
    if bootstrap_ip.is_none() {
        bootstrap_ip = host.parse::<IpAddr>().ok();
    }

    let ip_stack = match raw.ip_stack.to_ascii_lowercase().as_str() {
        "" | "both" => IpStack::Both,
        "v4" => IpStack::V4,
        "v6" => IpStack::V6,
        "split" => {
            warnings.push(format!(
                "{ctx} ip_stack \"split\" treated as \"both\" in this build"
            ));
            IpStack::Both
        }
        other => return Err(format!("{ctx} invalid ip_stack: {other:?}")),
    };

    Ok(Upstream {
        name: if raw.name.is_empty() {
            format!("upstream.{key}")
        } else {
            raw.name
        },
        proto,
        host,
        port,
        path,
        bootstrap_ip,
        timeout_ms: raw.timeout,
        ip_stack,
    })
}

fn split_scheme(endpoint: &str) -> (Option<&str>, &str) {
    match endpoint.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, endpoint),
    }
}

/// `host`, `host:port`, `[v6]`, `[v6]:port`, bare `v6` (no port).
fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        return match tail.strip_prefix(':') {
            Some(port) => Some((host.to_string(), port.parse().ok()?)),
            None if tail.is_empty() => Some((host.to_string(), default_port)),
            None => None,
        };
    }
    if s.matches(':').count() > 1 {
        // Bare IPv6 literal without brackets.
        return Some((s.to_string(), default_port));
    }
    match s.split_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((s.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_hostname_and_ipv6_endpoints() {
        assert_eq!(
            split_host_port("dns.example:853", 53),
            Some(("dns.example".into(), 853))
        );
        assert_eq!(
            split_host_port("[::1]:5354", 53),
            Some(("::1".into(), 5354))
        );
        assert_eq!(
            split_host_port("2606:4700::1111", 53),
            Some(("2606:4700::1111".into(), 53))
        );
    }

    #[test]
    fn infers_protocol_and_default_doh_path() {
        let raw = RawUpstream {
            endpoint: "https://dns.example".into(),
            ..RawUpstream::default()
        };
        let upstream = parse_upstream("0", raw, &mut Vec::new()).unwrap();
        assert_eq!(upstream.proto, Proto::Doh);
        assert_eq!(upstream.host, "dns.example");
        assert_eq!(upstream.port, 443);
        assert_eq!(upstream.path, "/dns-query");
    }

    #[test]
    fn zero_cache_size_disables_cache_with_warning() {
        let raw = RawService {
            cache_enable: true,
            cache_size: 0,
            ..RawService::default()
        };
        let mut warnings = Vec::new();
        let service = parse_service(raw, &mut warnings).unwrap();
        assert!(!service.cache_enable);
        assert_eq!(service.cache_size, 1);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("cache_size"))
        );
    }
}
