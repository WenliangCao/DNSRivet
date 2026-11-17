use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

// ---------- raw TOML layer ----------

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct RawConfig {
    service: RawService,
    listener: BTreeMap<String, RawListener>,
    upstream: BTreeMap<String, RawUpstream>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    split_dns: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct RawUpstream {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    endpoint: String,
    bootstrap_ip: String,
    /// None (omitted) = DEFAULT_TIMEOUT_MS; explicit 0 = no timeout at all.
    timeout: Option<u64>,
    ip_stack: String,
}

/// Applied when an upstream omits `timeout`. An omitted field must never mean
/// "wait forever": a black-holed first upstream would then hang every query
/// and exhaust the in-flight budget. Only an explicit `timeout = 0` opts into
/// that behavior.
const DEFAULT_TIMEOUT_MS: u64 = 5000;

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
    pub split_dns: Vec<SplitRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTarget {
    System,
    Upstream(usize),
    Direct(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitRule {
    pub suffix: String,
    pub target: SplitTarget,
}

impl AsRef<str> for SplitRule {
    fn as_ref(&self) -> &str {
        &self.suffix
    }
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
    /// Milliseconds before this upstream is abandoned for the next one.
    /// 0 = no timeout (explicit opt-in only; omitted fields become 5000).
    pub timeout_ms: u64,
    pub ip_stack: IpStack,
}

pub fn load(path: &Path) -> Result<Loaded, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    load_text(&text)
}

pub fn load_text(text: &str) -> Result<Loaded, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("TOML parse error: {e}"))?;

    let mut warnings = Vec::new();
    scan_unknown(&table, &mut warnings);

    let raw: RawConfig = table
        .try_into()
        .map_err(|e| format!("invalid config: {e}"))?;

    let service = parse_service(raw.service, &mut warnings)?;

    let mut listeners = Vec::new();
    for (key, listener) in sorted_numeric(raw.listener) {
        if listener.port == 0 {
            return Err(format!("[listener.{key}] port must not be 0"));
        }
        let ip: IpAddr = listener
            .ip
            .parse()
            .map_err(|_| format!("[listener.{key}] invalid ip: {:?}", listener.ip))?;
        if !ip.to_canonical().is_loopback() {
            warnings.push(format!("[listener.{key}] {ip} exposes DNS to other hosts; bind a specific trusted interface address and restrict access"));
        }
        listeners.push(SocketAddr::new(ip, listener.port));
    }
    if listeners.is_empty() {
        listeners.push("127.0.0.1:53".parse().unwrap());
    }

    let mut upstreams = Vec::new();
    let mut keys = Vec::new();
    for (key, upstream) in sorted_numeric(raw.upstream) {
        upstreams.push(parse_upstream(&key, upstream, &mut warnings)?);
        keys.push(key);
    }
    if upstreams.is_empty() {
        return Err("at least one [upstream.N] section is required".into());
    }
    let mut split_dns = Vec::with_capacity(raw.split_dns.len());
    for (raw_suffix, raw_target) in raw.split_dns {
        let suffix = raw_suffix.trim_matches('.').to_ascii_lowercase();
        if !valid_dns_name(&suffix) {
            return Err(format!("[split_dns] invalid suffix {raw_suffix:?}"));
        }
        let target = if raw_target.eq_ignore_ascii_case("system") {
            SplitTarget::System
        } else if let Some(index) = upstreams
            .iter()
            .position(|upstream| upstream.name == raw_target)
            .or_else(|| {
                keys.iter()
                    .position(|key| raw_target.strip_prefix("upstream.") == Some(key.as_str()))
            })
        {
            SplitTarget::Upstream(index)
        } else if let Some(addr) = split_host_port(&raw_target, 53)
            .and_then(|(host, port)| Some(SocketAddr::new(host.parse().ok()?, port)))
            .filter(|addr| addr.port() != 0 && !crate::upstream::is_self_address(*addr, &listeners))
        {
            SplitTarget::Direct(addr)
        } else {
            return Err(format!("[split_dns] invalid target {raw_target:?}"));
        };
        split_dns.push(SplitRule { suffix, target });
    }
    split_dns.sort_by(|left, right| {
        (right.suffix.len(), &left.suffix).cmp(&(left.suffix.len(), &right.suffix))
    });
    if split_dns
        .windows(2)
        .any(|pair| pair[0].suffix == pair[1].suffix)
    {
        return Err("[split_dns] duplicate suffix".into());
    }

    Ok(Loaded {
        config: Config {
            service,
            listeners,
            upstreams,
            split_dns,
        },
        warnings,
    })
}

/// Render the quick CLI surface to canonical TOML, then validate that TOML
/// through the same parser used for hand-written configuration files.
pub fn quick_toml(
    listeners: &[String],
    upstreams: &[String],
    split_dns: &[String],
    timeout_ms: Option<u64>,
    cache_size: Option<usize>,
    no_cache: bool,
) -> Result<String, String> {
    if upstreams.is_empty() {
        return Err("quick configuration requires at least one upstream".into());
    }

    let mut raw = RawConfig::default();
    raw.service.cache_enable = !no_cache;
    raw.service.cache_size = cache_size.unwrap_or(4096);

    let listeners: Vec<String> = if listeners.is_empty() {
        vec!["127.0.0.1:53".into()]
    } else {
        listeners.to_vec()
    };
    for (index, value) in listeners.iter().enumerate() {
        let addr: SocketAddr = value
            .parse()
            .map_err(|_| format!("invalid --listen address {value:?}; expected IP:PORT"))?;
        raw.listener.insert(
            index.to_string(),
            RawListener {
                ip: addr.ip().to_string(),
                port: addr.port(),
            },
        );
    }

    for (index, spec) in upstreams.iter().enumerate() {
        let (kind, endpoint) = match (spec.find('='), spec.find("://")) {
            (Some(eq_pos), scheme_pos)
                if scheme_pos.is_none_or(|pos| eq_pos < pos)
                    && eq_pos > 0
                    && eq_pos + 1 < spec.len() =>
            {
                (&spec[..eq_pos], &spec[eq_pos + 1..])
            }
            (Some(eq_pos), Some(scheme_pos)) if scheme_pos < eq_pos => ("", spec.as_str()),
            (None, _) if !spec.is_empty() => ("", spec.as_str()),
            _ => {
                return Err(format!(
                    "invalid --upstream {spec:?}; expected TYPE=ENDPOINT"
                ));
            }
        };
        raw.upstream.insert(
            index.to_string(),
            RawUpstream {
                name: format!("upstream.{index}"),
                kind: kind.into(),
                endpoint: endpoint.into(),
                bootstrap_ip: String::new(),
                timeout: Some(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
                ip_stack: "both".into(),
            },
        );
    }

    for rule in split_dns {
        let (suffix, target) = rule
            .split_once('=')
            .ok_or_else(|| format!("invalid --split-dns {rule:?}"))?;
        if raw.split_dns.insert(suffix.into(), target.into()).is_some() {
            return Err(format!("duplicate --split-dns suffix {suffix:?}"));
        }
    }

    let text =
        toml::to_string_pretty(&raw).map_err(|e| format!("serialize quick configuration: {e}"))?;
    load_text(&text)?;
    Ok(text)
}

/// Unknown or intentionally unsupported config sections/fields: warn instead
/// of silently swallowing them so migrating users know what changed.
fn scan_unknown(root: &toml::Table, warnings: &mut Vec<String>) {
    for key in root.keys() {
        if !["service", "listener", "upstream", "split_dns"].contains(&key.as_str()) {
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
    if raw.cache_size > 16_384 {
        return Err("[service] cache_size must not exceed 16384 entries".into());
    }
    let log_level = match raw.log_level.to_ascii_lowercase().as_str() {
        "" | "info" => log::LevelFilter::Info,
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "warn" | "warning" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
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

    let (mut host, port) = split_host_port(hostport, proto.default_port())
        .ok_or_else(|| format!("{ctx} invalid endpoint host: {hostport:?}"))?;
    if port == 0 {
        return Err(format!("{ctx} port must not be 0"));
    }

    let ip_literal = host.parse::<IpAddr>().ok();
    if ip_literal.is_none() {
        if host.ends_with('.') {
            host.pop();
        }
        if !valid_dns_name(&host)
            || host
                .rsplit('.')
                .next()
                .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(format!("{ctx} invalid endpoint hostname: {host:?}"));
        }
    }
    if matches!(proto, Proto::Doh | Proto::Doh3) && matches!(ip_literal, Some(IpAddr::V6(_))) {
        return Err(format!(
            "{ctx} IPv6 literal {host:?} is not supported in {} URLs; use a hostname with bootstrap_ip = {host:?}",
            proto.as_str()
        ));
    }

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
        bootstrap_ip = ip_literal;
    }

    let ip_stack = match raw.ip_stack.to_ascii_lowercase().as_str() {
        "" | "both" => IpStack::Both,
        "v4" => IpStack::V4,
        "v6" => IpStack::V6,
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
        timeout_ms: raw.timeout.unwrap_or(DEFAULT_TIMEOUT_MS),
        ip_stack,
    })
}

fn valid_dns_name(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
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

    #[test]
    fn quick_config_round_trips_through_toml_parser() {
        let text = quick_toml(
            &["127.0.0.1:5354".into()],
            &[
                "doh3=https://resolver.example/profile".into(),
                "dot=resolver-backup.example".into(),
            ],
            &[],
            Some(750),
            Some(128),
            false,
        )
        .unwrap();
        let loaded = load_text(&text).unwrap();
        assert_eq!(loaded.config.listeners[0].port(), 5354);
        assert_eq!(loaded.config.upstreams.len(), 2);
        assert_eq!(loaded.config.upstreams[0].proto, Proto::Doh3);
        assert_eq!(loaded.config.upstreams[0].timeout_ms, 750);
        assert_eq!(loaded.config.service.cache_size, 128);
    }

    #[test]
    fn quick_config_rejects_ambiguous_hostname_without_type() {
        let err =
            quick_toml(&[], &["resolver.example".into()], &[], None, None, false).unwrap_err();
        assert!(err.contains("type is required"));
    }

    #[test]
    fn omitted_timeout_defaults_to_5000() {
        let loaded = load_text(
            "[upstream.0]\ntype = \"doh\"\nendpoint = \"https://resolver.example/dns-query\"\n",
        )
        .unwrap();
        assert_eq!(loaded.config.upstreams[0].timeout_ms, 5000);
    }

    #[test]
    fn explicit_zero_timeout_stays_disabled() {
        let loaded = load_text(
            "[upstream.0]\ntype = \"doh\"\nendpoint = \"https://resolver.example/dns-query\"\ntimeout = 0\n",
        )
        .unwrap();
        assert_eq!(loaded.config.upstreams[0].timeout_ms, 0);
    }

    #[test]
    fn explicit_timeout_is_preserved() {
        let loaded = load_text(
            "[upstream.0]\ntype = \"doh\"\nendpoint = \"https://resolver.example/dns-query\"\ntimeout = 800\n",
        )
        .unwrap();
        assert_eq!(loaded.config.upstreams[0].timeout_ms, 800);
    }
    #[test]
    fn validates_cache_capacity_hostnames_and_exposed_listeners() {
        for host in [
            "bad host name!",
            "-bad.example",
            "bad..example",
            "bad_.example",
        ] {
            assert!(quick_toml(&[], &[format!("dot={host}")], &[], None, None, false).is_err());
        }
        assert!(
            quick_toml(
                &[],
                &["dot=dns.example".into()],
                &[],
                None,
                Some(99_999_999),
                false
            )
            .is_err()
        );
        let text = quick_toml(
            &["0.0.0.0:5354".into()],
            &["dot=dns.example".into()],
            &[],
            None,
            None,
            false,
        )
        .unwrap();
        assert!(
            load_text(&text)
                .unwrap()
                .warnings
                .iter()
                .any(|warning| warning.contains("exposes DNS"))
        );
    }

    #[test]
    fn rejects_zero_ports_numeric_tlds_ipv6_doh_and_preserves_query_equals() {
        assert!(
            quick_toml(
                &["127.0.0.1:0".into()],
                &["dot=dns.example".into()],
                &[],
                None,
                None,
                false
            )
            .is_err()
        );
        assert!(quick_toml(&[], &["dot=dns.example:0".into()], &[], None, None, false).is_err());

        let trailing =
            quick_toml(&[], &["dot=dns.example.".into()], &[], None, None, false).unwrap();
        let loaded = load_text(&trailing).unwrap();
        assert_eq!(loaded.config.upstreams[0].host, "dns.example");

        assert!(quick_toml(&[], &["dot=127.0.0.1.999".into()], &[], None, None, false).is_err());
        assert!(quick_toml(&[], &["dot=foo.123".into()], &[], None, None, false).is_err());

        for spec in ["https://[::1]/dns-query", "doh3=[2606:4700:4700::1111]"] {
            let err = quick_toml(&[], &[spec.into()], &[], None, None, false).unwrap_err();
            assert!(err.contains("bootstrap_ip"), "{spec}: {err}");
        }

        let query_eq = quick_toml(
            &[],
            &["https://dns.example/dns-query?a=1".into()],
            &[],
            None,
            None,
            false,
        )
        .unwrap();
        let loaded = load_text(&query_eq).unwrap();
        assert_eq!(loaded.config.upstreams[0].proto, Proto::Doh);
        assert_eq!(loaded.config.upstreams[0].path, "/dns-query?a=1");
    }

    #[test]
    fn parses_normalizes_and_sorts_split_dns_rules() {
        let loaded = load_text(
            "[listener.0]\nip = \"127.0.0.1\"\nport = 53\n\
             [upstream.0]\nname = \"cloudflare\"\nendpoint = \"https://1.1.1.1/dns-query\"\n\
             [upstream.10]\nname = \"quad9\"\nendpoint = \"https://9.9.9.9/dns-query\"\n\
             [split_dns]\n\
             \"local\" = \"SYSTEM\"\n\
             \".Corp.Internal.\" = \"10.0.0.1\"\n\
             \"sub.corp.internal\" = \"cloudflare\"\n\
             \"b.home.arpa\" = \"upstream.10\"\n\
             \"c.home.arpa\" = \"[2001:db8::53]\"\n\
             \"a.home.arpa\" = \"[fd00::53]:5353\"\n",
        )
        .unwrap();
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
        assert_eq!(
            loaded.config.split_dns,
            vec![
                SplitRule {
                    suffix: "sub.corp.internal".into(),
                    target: SplitTarget::Upstream(0),
                },
                SplitRule {
                    suffix: "corp.internal".into(),
                    target: SplitTarget::Direct("10.0.0.1:53".parse().unwrap()),
                },
                SplitRule {
                    suffix: "a.home.arpa".into(),
                    target: SplitTarget::Direct("[fd00::53]:5353".parse().unwrap()),
                },
                SplitRule {
                    suffix: "b.home.arpa".into(),
                    target: SplitTarget::Upstream(1),
                },
                SplitRule {
                    suffix: "c.home.arpa".into(),
                    target: SplitTarget::Direct("[2001:db8::53]:53".parse().unwrap()),
                },
                SplitRule {
                    suffix: "local".into(),
                    target: SplitTarget::System,
                },
            ]
        );
    }

    #[test]
    fn rejects_invalid_duplicate_and_self_loop_split_dns_rules() {
        let base = "[listener.0]\nip = \"127.0.0.1\"\nport = 53\n\
                    [upstream.0]\nendpoint = \"https://1.1.1.1/dns-query\"\n";

        for bad_suffix in ["", ".", "..", "a..b", "-bad.local", "bad_.local", "*.local"] {
            let err = load_text(&format!("{base}[split_dns]\n{bad_suffix:?} = \"system\"\n"))
                .unwrap_err();
            assert!(err.contains("[split_dns]"), "{bad_suffix:?}: {err}");
        }

        let dup = load_text(&format!(
            "{base}[split_dns]\n\"corp.local\" = \"system\"\n\".CORP.LOCAL.\" = \"10.0.0.1\"\n"
        ))
        .unwrap_err();
        assert!(dup.contains("duplicate"), "{dup}");

        for bad_target in [
            "unknown-upstream",
            "10.0.0.1:0",
            "[fd00::53]:0",
            "127.0.0.1",
            "127.0.0.1:53",
            "[::ffff:127.0.0.1]:53",
            "0.0.0.0:53",
            "[::1]:53",
        ] {
            let err = load_text(&format!(
                "{base}[split_dns]\n\"corp.local\" = {bad_target:?}\n"
            ))
            .unwrap_err();
            assert!(err.contains("[split_dns]"), "{bad_target:?}: {err}");
        }

        let non_loop = load_text(&format!(
            "{base}[split_dns]\n\"corp.local\" = \"127.0.0.1:5353\"\n"
        ))
        .unwrap();
        assert_eq!(
            non_loop.config.split_dns[0].target,
            SplitTarget::Direct("127.0.0.1:5353".parse().unwrap())
        );
    }

    #[test]
    fn quick_toml_validates_split_dns() {
        let text = quick_toml(
            &["127.0.0.1:5354".into()],
            &["doh=https://1.1.1.1/dns-query".into()],
            &[
                "corp.local=10.0.0.1".into(),
                "home.arpa=system".into(),
                "ts.net=upstream.0".into(),
            ],
            None,
            None,
            false,
        )
        .unwrap();
        let loaded = load_text(&text).unwrap();
        assert_eq!(loaded.config.split_dns.len(), 3);
        assert!(
            quick_toml(
                &[],
                &["doh=https://1.1.1.1/dns-query".into()],
                &["missing_equals".into()],
                None,
                None,
                false,
            )
            .is_err()
        );
        assert!(
            quick_toml(
                &[],
                &["doh=https://1.1.1.1/dns-query".into()],
                &["corp.local=system".into(), "corp.local=10.0.0.1".into()],
                None,
                None,
                false,
            )
            .is_err()
        );
    }
}
