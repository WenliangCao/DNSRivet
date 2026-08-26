//! Transactional macOS DNS configuration through `networksetup`.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, Output};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const SCUTIL: &str = "/usr/sbin/scutil";
pub const BACKUP_PATH: &str = "/Library/Application Support/DNSRivet/dns-backup.toml";
/// Created only after a takeover applied to every service; its absence next
/// to a backup means the takeover state is not trustworthy.
pub const MARKER_PATH: &str = "/Library/Application Support/DNSRivet/takeover-active";
const LOCK_PATH: &str = "/Library/Application Support/DNSRivet/.lock";

/// Cross-process critical section (flock) shared by the CLI lifecycle
/// commands and the daemon watchdog. Dropping it releases the lock.
struct FsLock {
    _file: std::fs::File,
}

fn lock() -> Result<FsLock, String> {
    let parent = Path::new(LOCK_PATH)
        .parent()
        .expect("lock path has a parent");
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create support directory {}: {e}", parent.display()))?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(LOCK_PATH)
        .map_err(|e| format!("open lock file {LOCK_PATH}: {e}"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!(
            "lock {LOCK_PATH}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(FsLock { _file: file })
}

pub fn marker_exists() -> bool {
    Path::new(MARKER_PATH).is_file()
}

fn create_marker() -> Result<(), String> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(MARKER_PATH)
        .map(|_| ())
        .map_err(|e| format!("create takeover marker {MARKER_PATH}: {e}"))
}

fn remove_marker() -> Result<(), String> {
    match std::fs::remove_file(MARKER_PATH) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("remove takeover marker {MARKER_PATH}: {err}")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TakeoverState {
    NotTakenOver,
    Active,
    /// Backup without marker: a takeover attempt did not complete.
    Indeterminate,
    /// Marker without backup: restore data is gone.
    Corrupted,
}

fn classify(backup: bool, marker: bool) -> TakeoverState {
    match (backup, marker) {
        (false, false) => TakeoverState::NotTakenOver,
        (true, true) => TakeoverState::Active,
        (true, false) => TakeoverState::Indeterminate,
        (false, true) => TakeoverState::Corrupted,
    }
}

pub fn takeover_state() -> TakeoverState {
    classify(backup_exists(), marker_exists())
}

#[derive(Debug, Deserialize, Serialize)]
struct Backup {
    version: u8,
    services: Vec<ServiceDns>,
    #[serde(default)]
    fallback_servers: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ServiceDns {
    name: String,
    servers: Vec<String>,
}

pub fn backup_exists() -> bool {
    Path::new(BACKUP_PATH).is_file()
}

/// Save every enabled network service's explicit DNS settings, then point all
/// of them at the local proxy. On partial failure, already-modified services
/// are rolled back before returning. The takeover-active marker is created
/// last, only once every service was switched.
pub fn take_over(server: IpAddr) -> Result<(), String> {
    let _lock = lock()?;
    if backup_exists() {
        return Err(format!(
            "DNS backup already exists at {BACKUP_PATH}; run `dnsrivet stop` before starting again"
        ));
    }

    let mut fallback_servers = match effective_dns_servers() {
        Ok(servers) => servers,
        Err(err) => {
            eprintln!("warning: could not snapshot effective system DNS: {err}");
            Vec::new()
        }
    };
    let mut services = Vec::new();
    for name in list_services()? {
        let servers = get_dns_servers(&name)?;
        fallback_servers.extend(
            servers
                .iter()
                .filter_map(|value| value.parse::<IpAddr>().ok()),
        );
        // Snapshotting a service that already lists the takeover address
        // would write our own loopback into the restore backup: after a later
        // `stop`, the system would point at a proxy that no longer runs.
        // Whether the entry is a stale leftover or another local DNS tool,
        // proceeding is wrong.
        if servers
            .iter()
            .any(|existing| existing == &server.to_string())
        {
            return Err(format!(
                "network service {name:?} already lists {server} as a DNS server; \
                 refusing to take over. Clear it first (sudo networksetup \
                 -setdnsservers {name:?} Empty) or remove the other local DNS tool"
            ));
        }
        services.push(ServiceDns { name, servers });
    }
    if services.is_empty() {
        return Err("networksetup returned no enabled network services".into());
    }

    let backup = Backup {
        version: 2,
        services,
        fallback_servers: filter_fallback_servers(fallback_servers, &[server])
            .into_iter()
            .map(|ip| ip.to_string())
            .collect(),
    };
    if backup.fallback_servers.is_empty() {
        eprintln!(
            "warning: no usable pre-takeover system DNS server was found; upstream exhaustion will return SERVFAIL"
        );
    }
    write_backup(&backup)?;

    let mut changed = Vec::new();
    for service in &backup.services {
        if let Err(err) = set_dns_servers(&service.name, &[server.to_string()]) {
            let rollback_ok = rollback(&backup, &changed);
            if rollback_ok {
                let _ = std::fs::remove_file(BACKUP_PATH);
            }
            return Err(format!(
                "{err}; DNS takeover rollback {}",
                if rollback_ok {
                    "completed"
                } else {
                    "was incomplete"
                }
            ));
        }
        changed.push(service.name.clone());
    }
    create_marker()?;
    flush_caches();
    Ok(())
}

/// stop/uninstall entry point: handles all four takeover states under the
/// cross-process lock and refuses to proceed when stopping would strand the
/// machine on a dead loopback resolver.
pub fn release() -> Result<bool, String> {
    let _lock = lock()?;
    if !backup_exists() {
        if marker_exists() {
            if system_points_at_loopback()? {
                return Err(
                    "a takeover marker exists without a DNS backup, and the system still \
                     resolves through a loopback address; stopping now would cut off DNS. \
                     Restore DNS manually first (for each service: sudo networksetup \
                     -setdnsservers <service> Empty), then retry"
                        .into(),
                );
            }
            remove_marker()?;
        }
        return Ok(false);
    }
    // Marker first: a crash between these steps leaves backup-without-marker,
    // which `stop` can still restore from.
    remove_marker()?;
    restore()
}

fn system_points_at_loopback() -> Result<bool, String> {
    if !current_loopback_dns()?.is_empty() {
        return Ok(true);
    }
    for name in list_services()? {
        let loopback = get_dns_servers(&name)?
            .iter()
            .any(|value| value.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()));
        if loopback {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Restore the exact per-service DNS snapshot. A missing backup means this
/// process has no evidence that it owns the current DNS settings, so it safely
/// leaves them untouched.
fn restore() -> Result<bool, String> {
    if !backup_exists() {
        return Ok(false);
    }
    let backup = read_backup()?;
    if !matches!(backup.version, 1 | 2) {
        return Err(format!("unsupported DNS backup version {}", backup.version));
    }

    let current_services = list_all_services()?;
    let mut errors = Vec::new();
    for service in &backup.services {
        if !current_services.contains(&service.name) {
            eprintln!(
                "warning: network service {:?} no longer exists; skipping its DNS restore",
                service.name
            );
            continue;
        }
        if let Err(err) = set_dns_servers(&service.name, &service.servers) {
            errors.push(err);
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "could not restore every network service: {} (backup retained at {BACKUP_PATH})",
            errors.join("; ")
        ));
    }
    std::fs::remove_file(BACKUP_PATH)
        .map_err(|e| format!("remove restored DNS backup {BACKUP_PATH}: {e}"))?;
    flush_caches();
    Ok(true)
}

/// Direct DNS servers that were effective before system takeover. The proxy
/// queries these addresses itself, never through the now-looping OS resolver.
pub fn fallback_servers(listeners: &[SocketAddr]) -> Result<Vec<SocketAddr>, String> {
    let denied: Vec<IpAddr> = listeners.iter().map(SocketAddr::ip).collect();
    let candidates = if backup_exists() {
        let backup = read_backup()?;
        if !matches!(backup.version, 1 | 2) {
            return Err(format!("unsupported DNS backup version {}", backup.version));
        }
        let mut candidates: Vec<IpAddr> = backup
            .fallback_servers
            .iter()
            .filter_map(|value| value.parse().ok())
            .collect();
        if candidates.is_empty() {
            candidates.extend(
                backup
                    .services
                    .iter()
                    .flat_map(|service| &service.servers)
                    .filter_map(|value| value.parse::<IpAddr>().ok()),
            );
        }
        candidates
    } else {
        effective_dns_servers()?
    };
    Ok(filter_fallback_servers(candidates, &denied)
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 53))
        .collect())
}

pub enum TickOutcome {
    /// Gate not satisfied (no backup, no marker): nothing to guard.
    NotActive,
    /// Every backed-up service still points exactly at the takeover address.
    Clean,
    /// Drift was detected and corrected.
    Reasserted {
        corrected: Vec<String>,
        /// Global DNS captured while takeover was lost — the only moment the
        /// current network's real resolvers are visible. Runtime-only; the
        /// restore backup is never rewritten.
        captured: Vec<SocketAddr>,
    },
}

/// One watchdog cycle, run by the daemon under the cross-process lock:
/// verify that every backed-up service still lists exactly the takeover
/// address (a second resolver would leak queries around the proxy), and on
/// drift capture the currently effective DNS before reasserting.
pub fn watchdog_tick(server: IpAddr) -> Result<TickOutcome, String> {
    let _lock = lock()?;
    if !(backup_exists() && marker_exists()) {
        return Ok(TickOutcome::NotActive);
    }
    let expected = server.to_string();
    let current = service_dns_snapshot()?;
    let drifted: Vec<String> = services_needing_reassert(&current, &expected)
        .into_iter()
        .map(str::to_string)
        .collect();
    if drifted.is_empty() {
        return Ok(TickOutcome::Clean);
    }

    // Capture before reassert: right now scutil still shows the network's
    // own resolvers; afterwards it will only show the loopback again.
    let captured: Vec<SocketAddr> = effective_dns_servers()
        .map(|ips| {
            filter_fallback_servers(ips, &[server])
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 53))
                .collect()
        })
        .unwrap_or_default();

    let mut errors = Vec::new();
    for name in &drifted {
        if let Err(err) = set_dns_servers(name, std::slice::from_ref(&expected)) {
            errors.push(err);
        }
    }
    flush_caches();
    if !errors.is_empty() {
        return Err(format!("reassert incomplete: {}", errors.join("; ")));
    }
    Ok(TickOutcome::Reasserted {
        corrected: drifted,
        captured,
    })
}

/// Read-only variant for `restart`'s verification wait.
pub fn takeover_intact(server: IpAddr) -> Result<bool, String> {
    let expected = server.to_string();
    let current = service_dns_snapshot()?;
    Ok(services_needing_reassert(&current, &expected).is_empty())
}

/// Current DNS list of every backed-up service that still exists.
fn service_dns_snapshot() -> Result<Vec<(String, Vec<String>)>, String> {
    let backup = read_backup()?;
    let all_services = list_all_services()?;
    let mut snapshot = Vec::new();
    for service in &backup.services {
        if !all_services.contains(&service.name) {
            continue; // vanished service: nothing to reassert
        }
        snapshot.push((service.name.clone(), get_dns_servers(&service.name)?));
    }
    Ok(snapshot)
}

/// Exact-list check: anything other than exactly `[server]` is drift, even a
/// list that still contains the server alongside a second resolver.
fn services_needing_reassert<'a>(
    current: &'a [(String, Vec<String>)],
    server: &str,
) -> Vec<&'a str> {
    current
        .iter()
        .filter(|(_, servers)| !(servers.len() == 1 && servers[0] == server))
        .map(|(name, _)| name.as_str())
        .collect()
}

/// Loopback DNS endpoints currently advertised by macOS. This lets unprivileged
/// health checks probe the active service without reading its private config.
pub fn current_loopback_dns() -> Result<Vec<SocketAddr>, String> {
    let mut seen = HashSet::new();
    Ok(effective_dns_servers()?
        .into_iter()
        .filter(|ip| ip.is_loopback() && seen.insert(*ip))
        .map(|ip| SocketAddr::new(ip, 53))
        .collect())
}

fn read_backup() -> Result<Backup, String> {
    let text = std::fs::read_to_string(BACKUP_PATH)
        .map_err(|e| format!("read DNS backup {BACKUP_PATH}: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("parse DNS backup {BACKUP_PATH}: {e}"))
}

fn effective_dns_servers() -> Result<Vec<IpAddr>, String> {
    let output = run(SCUTIL, &["--dns"])?;
    let text = stdout(&output, "read effective system DNS")?;
    Ok(parse_scutil_global_dns(&text))
}

/// Global default resolvers only. Accepted resolver blocks must sit in the
/// section titled exactly `DNS configuration` — every `DNS configuration
/// (...)` variant (scoped or service-specific) is excluded — and must carry
/// no `domain` restriction: a split-DNS VPN resolver in the main section
/// serves only its own domain and must never become a global fallback.
fn parse_scutil_global_dns(text: &str) -> Vec<IpAddr> {
    fn commit(pending: &mut Vec<IpAddr>, domain_scoped: &mut bool, out: &mut Vec<IpAddr>) {
        if !*domain_scoped {
            out.append(pending);
        }
        pending.clear();
        *domain_scoped = false;
    }

    let mut servers = Vec::new();
    let mut pending = Vec::new();
    let mut domain_scoped = false;
    let mut in_global = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line == "DNS configuration" {
            commit(&mut pending, &mut domain_scoped, &mut servers);
            in_global = true;
        } else if line.starts_with("DNS configuration (") {
            commit(&mut pending, &mut domain_scoped, &mut servers);
            in_global = false;
        } else if !in_global {
            continue;
        } else if line.starts_with("resolver #") {
            commit(&mut pending, &mut domain_scoped, &mut servers);
        } else if line.starts_with("domain") {
            // `domain : x` restricts the block; `search domain[N]` does not.
            domain_scoped = true;
        } else if line.starts_with("nameserver[")
            && let Some((_, value)) = line.split_once(':')
        {
            let value = value.trim();
            if !value.contains('%')
                && let Ok(ip) = value.parse()
            {
                pending.push(ip);
            }
        }
    }
    commit(&mut pending, &mut domain_scoped, &mut servers);
    servers
}

fn filter_fallback_servers(mut servers: Vec<IpAddr>, denied: &[IpAddr]) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    servers.retain(|ip| {
        !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !denied.contains(ip)
            && seen.insert(*ip)
    });
    servers
}

fn list_services() -> Result<Vec<String>, String> {
    let output = run(NETWORKSETUP, &["-listallnetworkservices"])?;
    let text = stdout(&output, "list network services")?;
    Ok(parse_services(&text))
}

fn list_all_services() -> Result<Vec<String>, String> {
    let output = run(NETWORKSETUP, &["-listallnetworkservices"])?;
    let text = stdout(&output, "list network services")?;
    Ok(parse_all_services(&text))
}

fn get_dns_servers(service: &str) -> Result<Vec<String>, String> {
    let output = run(NETWORKSETUP, &["-getdnsservers", service])?;
    let text = stdout(&output, &format!("read DNS servers for {service:?}"))?;
    parse_dns_servers(&text)
        .ok_or_else(|| format!("unrecognized DNS server output for {service:?}: {text:?}"))
}

fn set_dns_servers(service: &str, servers: &[String]) -> Result<(), String> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    let output = run(NETWORKSETUP, &args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "set DNS servers for {service:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn rollback(backup: &Backup, changed: &[String]) -> bool {
    let mut ok = true;
    for name in changed.iter().rev() {
        let Some(service) = backup.services.iter().find(|service| &service.name == name) else {
            continue;
        };
        if let Err(err) = set_dns_servers(&service.name, &service.servers) {
            eprintln!("warning: rollback failed: {err}");
            ok = false;
        }
    }
    flush_caches();
    ok
}

fn write_backup(backup: &Backup) -> Result<(), String> {
    let path = Path::new(BACKUP_PATH);
    let parent = path.parent().expect("backup path has a parent");
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create support directory {}: {e}", parent.display()))?;
    let temporary = parent.join(".dns-backup.toml.tmp");
    let text = toml::to_string(backup).map_err(|e| format!("serialize DNS backup: {e}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| format!("write DNS backup {}: {e}", temporary.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write DNS backup {}: {e}", temporary.display()))?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("secure DNS backup {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("install DNS backup {BACKUP_PATH}: {e}"))
}

fn run(program: &str, args: &[&str]) -> Result<Output, String> {
    Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("run {program}: {e}"))
}

fn stdout(output: &Output, action: &str) -> Result<String, String> {
    if !output.status.success() {
        return Err(format!(
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout.clone()).map_err(|e| format!("{action}: non-UTF-8 output: {e}"))
}

fn parse_services(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_string)
        .collect()
}

fn parse_all_services(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.strip_prefix('*').unwrap_or(line).trim().to_string())
        .collect()
}

fn parse_dns_servers(text: &str) -> Option<Vec<String>> {
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() == 1 && lines[0].starts_with("There aren't any DNS Servers set on") {
        return Some(Vec::new());
    }
    lines
        .iter()
        .map(|line| line.parse::<IpAddr>().ok().map(|ip| ip.to_string()))
        .collect()
}

fn flush_caches() {
    for (program, args) in [
        ("/usr/bin/dscacheutil", &["-flushcache"][..]),
        ("/usr/bin/killall", &["-HUP", "mDNSResponder"][..]),
    ] {
        match run(program, args) {
            Ok(output) if output.status.success() => {}
            Ok(output) => eprintln!(
                "warning: {program} failed while flushing DNS caches: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(err) => eprintln!("warning: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enabled_network_services() {
        let text = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\niPhone USB\n";
        assert_eq!(parse_services(text), ["Wi-Fi", "iPhone USB"]);
        assert_eq!(
            parse_all_services(text),
            ["Wi-Fi", "Thunderbolt Bridge", "iPhone USB"]
        );
    }

    #[test]
    fn parses_dns_server_lists_and_empty_marker() {
        assert_eq!(
            parse_dns_servers("1.1.1.1\n2606:4700:4700::1111\n").unwrap(),
            ["1.1.1.1", "2606:4700:4700::1111"]
        );
        assert!(
            parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n")
                .unwrap()
                .is_empty()
        );
        assert!(parse_dns_servers("unexpected output\n").is_none());
    }

    #[test]
    fn dns_backup_round_trips_through_toml() {
        let backup = Backup {
            version: 2,
            services: vec![ServiceDns {
                name: "USB & Wi-Fi".into(),
                servers: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()],
            }],
            fallback_servers: vec!["192.0.2.53".into()],
        };
        let text = toml::to_string(&backup).unwrap();
        let decoded: Backup = toml::from_str(&text).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.services[0].name, "USB & Wi-Fi");
        assert_eq!(decoded.services[0].servers.len(), 2);
        assert_eq!(decoded.fallback_servers, ["192.0.2.53"]);
    }

    #[test]
    fn parses_and_filters_effective_dns_servers() {
        let text = r#"
DNS configuration

resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : 127.0.0.1
resolver #2
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  nameserver[2] : 2001:db8::53
"#;
        assert_eq!(
            filter_fallback_servers(
                parse_scutil_global_dns(text),
                &["127.0.0.1".parse().unwrap()]
            ),
            [
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn global_parser_excludes_domain_and_scoped_resolvers() {
        let text = r#"
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fdfd:3b1d:1c26::1

resolver #2
  domain   : corp.example
  nameserver[0] : 10.0.0.53

resolver #3
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 10.9.9.9
  if_index : 12 (en0)
"#;
        assert_eq!(
            parse_scutil_global_dns(text),
            [
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "fdfd:3b1d:1c26::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn drift_requires_exactly_the_takeover_address() {
        let current = vec![
            ("Wi-Fi".to_string(), vec!["127.0.0.1".to_string()]),
            (
                "USB LAN".to_string(),
                vec!["127.0.0.1".to_string(), "8.8.8.8".to_string()],
            ),
            ("Bridge".to_string(), Vec::new()),
        ];
        assert_eq!(
            services_needing_reassert(&current, "127.0.0.1"),
            ["USB LAN", "Bridge"]
        );
    }

    #[test]
    fn takeover_state_matrix() {
        assert_eq!(classify(false, false), TakeoverState::NotTakenOver);
        assert_eq!(classify(true, true), TakeoverState::Active);
        assert_eq!(classify(true, false), TakeoverState::Indeterminate);
        assert_eq!(classify(false, true), TakeoverState::Corrupted);
    }
}
