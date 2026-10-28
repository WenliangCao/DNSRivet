//! Transactional macOS DNS configuration through `networksetup`.

use super::lock::FsLock;
use crate::atomic_file;
use nix::net::if_::if_nametoindex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Output};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const SCUTIL: &str = "/usr/sbin/scutil";
pub const BACKUP_PATH: &str = "/Library/Application Support/DNSRivet/dns-backup.toml";
/// Created only after a takeover applied to every service; its absence next
/// to a backup means the takeover state is not trustworthy.
pub const MARKER_PATH: &str = "/Library/Application Support/DNSRivet/takeover-active";
const LOCK_PATH: &str = "/Library/Application Support/DNSRivet/.lock";

/// DNS-only critical section shared with the daemon watchdog. Never hold
/// this while waiting for the daemon's reassertion during CLI restart.
fn lock() -> Result<FsLock, String> {
    FsLock::acquire(Path::new(LOCK_PATH))
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
    /// All addresses used since takeover. None means legacy history is unknown;
    /// watchdog ticks must not promote a partial observation to complete history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    takeover_servers: Option<Vec<IpAddr>>,
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
                .filter_map(|value| parse_dns_socket(value).ok()),
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
        takeover_servers: Some(vec![server]),
        fallback_servers: filter_fallback_servers(fallback_servers, &[server])
            .into_iter()
            .map(serialize_dns_socket)
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
    // Disabled services can later be re-enabled; do not strand them either.
    for name in list_all_services()? {
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
    restore_at(
        Path::new(BACKUP_PATH),
        list_all_services,
        get_dns_servers,
        set_dns_servers,
    )?;
    flush_caches();
    Ok(true)
}

/// Restore known names, then verify all services before discarding recovery data.
/// The injected networksetup operations keep tests away from production OS state.
fn restore_at(
    backup_path: &Path,
    mut list: impl FnMut() -> Result<Vec<String>, String>,
    mut get: impl FnMut(&str) -> Result<Vec<String>, String>,
    mut set: impl FnMut(&str, &[String]) -> Result<(), String>,
) -> Result<(), String> {
    let backup = read_backup_at(backup_path)?;
    if !matches!(backup.version, 1 | 2) {
        return Err(format!("unsupported DNS backup version {}", backup.version));
    }

    let current_services = list()?;
    let mut errors = Vec::new();
    for service in &backup.services {
        if !current_services.contains(&service.name) {
            eprintln!(
                "warning: network service {:?} was removed or renamed; its original DNS settings remain in the backup until restoration is verified",
                service.name
            );
            continue;
        }
        if let Err(err) = set(&service.name, &service.servers) {
            errors.push(err);
        }
    }

    // Re-list after writes: a renamed or newly added service must not escape
    // verification just because its old name was absent from the backup.
    match list() {
        Ok(names) => {
            for name in names {
                match get(&name) {
                    Ok(servers) if dns_may_depend_on_takeover(&backup, &name, &servers) => {
                        errors.push(format!(
                            "network service {name:?} still lists DNS that may use DNSRivet: {}",
                            servers.join(", ")
                        ));
                    }
                    Ok(_) => {}
                    Err(err) => errors.push(err),
                }
            }
        }
        Err(err) => errors.push(err),
    }
    if !errors.is_empty() {
        return Err(format!(
            "refusing to stop DNSRivet: {} (backup retained at {}); restore the affected services' known correct DNS settings manually, or rename services back to their backed-up names, then retry `dnsrivet stop`. Original DNS for renamed services will not be guessed",
            errors.join("; "),
            backup_path.display()
        ));
    }
    std::fs::remove_file(backup_path)
        .map_err(|e| format!("remove restored DNS backup {}: {e}", backup_path.display()))
}

fn dns_may_depend_on_takeover(backup: &Backup, name: &str, servers: &[String]) -> bool {
    if let Some(takeovers) = &backup.takeover_servers {
        return servers.iter().any(|value| {
            parse_dns_socket(value).is_ok_and(|address| takeovers.contains(&address.ip()))
        });
    }
    // Legacy backups do not identify the resolver. Only an exact original
    // list on the same service proves that loopback DNS belonged to another tool.
    let original = backup.services.iter().find(|service| service.name == name);
    let restored_original = original.is_some_and(|service| service.servers == servers);
    !restored_original
        && servers
            .iter()
            .any(|value| parse_dns_socket(value).is_ok_and(|address| address.ip().is_loopback()))
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
        let mut candidates: Vec<SocketAddr> = backup
            .fallback_servers
            .iter()
            .filter_map(|value| parse_dns_socket(value).ok())
            .collect();
        if candidates.is_empty() {
            candidates.extend(
                backup
                    .services
                    .iter()
                    .flat_map(|service| &service.servers)
                    .filter_map(|value| parse_dns_socket(value).ok()),
            );
        }
        candidates
    } else {
        effective_dns_servers()?
    };
    Ok(filter_fallback_servers(candidates, &denied))
}

pub enum TickOutcome {
    /// Gate not satisfied (no backup, no marker): nothing to guard.
    NotActive,
    /// Every backed-up service still points exactly at the takeover address.
    Clean {
        captured: Option<Vec<SocketAddr>>,
        capture_error: Option<String>,
    },
    /// Drift was detected and corrected.
    Reasserted {
        corrected: Vec<String>,
        /// Global DNS captured while takeover was lost — the only moment the
        /// current network's real resolvers are visible. Runtime-only; the
        /// restore backup is never rewritten.
        captured: Vec<SocketAddr>,
        capture_error: Option<String>,
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
    let mut backup = read_backup()?;
    let known_services: HashSet<&str> = backup
        .services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    let new_services: Vec<(String, Vec<String>)> = list_services()?
        .into_iter()
        .filter(|name| !known_services.contains(name.as_str()))
        .map(|name| get_dns_servers(&name).map(|servers| (name, servers)))
        .collect::<Result<_, _>>()?;
    prepare_watchdog_backup(&mut backup, new_services, server, write_backup)?;
    let current = service_dns_snapshot()?;
    let drifted: Vec<String> = services_needing_reassert(&current, &expected)
        .into_iter()
        .map(str::to_string)
        .collect();
    let capture = capture_runtime_fallback(server);
    if drifted.is_empty() {
        return Ok(TickOutcome::Clean {
            captured: capture.as_ref().ok().cloned(),
            capture_error: capture.err(),
        });
    }

    // Capture before reassert: right now scutil still shows the network's
    // own resolvers; afterwards it will only show the loopback again.
    let (captured, capture_error) = match capture {
        Ok(servers) => (servers, None),
        Err(error) => (Vec::new(), Some(error)),
    };

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
        capture_error,
    })
}

/// Read-only variant for `restart`'s verification wait.
pub fn takeover_intact(server: IpAddr) -> Result<bool, String> {
    let expected = server.to_string();
    let backup = read_backup()?;
    takeover_intact_with(
        &backup,
        &expected,
        &list_services()?,
        list_all_services,
        get_dns_servers,
    )
}

fn takeover_intact_with(
    backup: &Backup,
    expected: &str,
    enabled: &[String],
    list: impl FnOnce() -> Result<Vec<String>, String>,
    mut get: impl FnMut(&str) -> Result<Vec<String>, String>,
) -> Result<bool, String> {
    let mut checked = false;
    for name in list()? {
        let servers = get(&name)?;
        let known = backup.services.iter().any(|service| service.name == name);
        // Unknown names may have been renamed while retaining an old takeover
        // address. Never declare a new listener verified while DNS still uses it.
        if known || enabled.contains(&name) || dns_may_depend_on_takeover(backup, &name, &servers) {
            checked = true;
            if servers.len() != 1 || servers[0] != expected {
                return Ok(false);
            }
        }
    }
    Ok(checked)
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

/// Persist restore data and address history before the watchdog changes DNS.
fn prepare_watchdog_backup(
    backup: &mut Backup,
    snapshots: Vec<(String, Vec<String>)>,
    server: IpAddr,
    persist: impl FnOnce(&Backup) -> Result<(), String>,
) -> Result<(), String> {
    let mut changed = add_new_service_snapshots(backup, snapshots, &server.to_string())?;
    if let Some(takeovers) = &mut backup.takeover_servers
        && !takeovers.contains(&server)
    {
        takeovers.push(server);
        changed = true;
    }
    if changed {
        persist(backup)?;
    }
    Ok(())
}

fn add_new_service_snapshots(
    backup: &mut Backup,
    snapshots: Vec<(String, Vec<String>)>,
    expected: &str,
) -> Result<bool, String> {
    let mut added = false;
    for (name, servers) in snapshots {
        if backup.services.iter().any(|service| service.name == name) {
            continue;
        }
        if servers.iter().any(|server| server == expected)
            || dns_may_depend_on_takeover(backup, &name, &servers)
        {
            return Err(format!(
                "network service {name:?} already lists a DNSRivet takeover address as a DNS server; \
                 refusing to capture an unknown restore state"
            ));
        }
        backup.services.push(ServiceDns { name, servers });
        added = true;
    }
    Ok(added)
}

fn capture_runtime_fallback(server: IpAddr) -> Result<Vec<SocketAddr>, String> {
    let current = effective_dns_servers()
        .map_err(|err| format!("could not read current system DNS: {err}"))?;
    usable_runtime_fallback(current, server)
}

fn usable_runtime_fallback(
    current: Vec<SocketAddr>,
    server: IpAddr,
) -> Result<Vec<SocketAddr>, String> {
    let usable = filter_fallback_servers(current, &[server]);
    if usable.is_empty() {
        Err("macOS exposed no non-loopback global DNS server while the takeover was active".into())
    } else {
        Ok(usable)
    }
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
        .filter(|address| address.ip().is_loopback() && seen.insert(*address))
        .collect())
}

fn read_backup() -> Result<Backup, String> {
    read_backup_at(Path::new(BACKUP_PATH))
}

fn read_backup_at(path: &Path) -> Result<Backup, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read DNS backup {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("parse DNS backup {}: {e}", path.display()))
}

fn effective_dns_servers() -> Result<Vec<SocketAddr>, String> {
    let output = run(SCUTIL, &["--dns"])?;
    let text = stdout(&output, "read effective system DNS")?;
    parse_scutil_global_dns(&text)
}

/// Global default resolvers only. Accepted resolver blocks must sit in the
/// section titled exactly `DNS configuration` — every `DNS configuration
/// (...)` variant (scoped or service-specific) is excluded — and must carry
/// no `domain` restriction: a split-DNS VPN resolver in the main section
/// serves only its own domain and must never become a global fallback.
fn parse_scutil_global_dns(text: &str) -> Result<Vec<SocketAddr>, String> {
    fn commit(pending: &mut Vec<SocketAddr>, domain_scoped: &mut bool, out: &mut Vec<SocketAddr>) {
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
            pending.push(parse_dns_socket(value.trim())?);
        }
    }
    commit(&mut pending, &mut domain_scoped, &mut servers);
    Ok(servers)
}

fn parse_dns_socket(value: &str) -> Result<SocketAddr, String> {
    let value = value.trim();
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    let (address, scope) = value
        .rsplit_once('%')
        .ok_or_else(|| format!("invalid DNS server address {value:?}"))?;
    let ip = address
        .parse::<Ipv6Addr>()
        .map_err(|err| format!("invalid IPv6 DNS server address {value:?}: {err}"))?;
    let scope_id = scope.parse::<u32>().or_else(|_| {
        if_nametoindex(scope).map_err(|err| format!("unknown IPv6 DNS interface {scope:?}: {err}"))
    })?;
    Ok(SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, scope_id)))
}

fn serialize_dns_socket(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => address.ip().to_string(),
        SocketAddr::V6(address) if address.scope_id() != 0 => {
            format!("{}%{}", address.ip(), address.scope_id())
        }
        SocketAddr::V6(address) => address.ip().to_string(),
    }
}

fn filter_fallback_servers(mut servers: Vec<SocketAddr>, denied: &[IpAddr]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    servers.retain(|address| {
        let ip = address.ip();
        !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !denied.contains(&ip)
            && seen.insert(*address)
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
    write_backup_at(Path::new(BACKUP_PATH), backup)
}

fn write_backup_at(path: &Path, backup: &Backup) -> Result<(), String> {
    let parent = path.parent().expect("backup path has a parent");
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create support directory {}: {e}", parent.display()))?;
    let text = toml::to_string(backup).map_err(|e| format!("serialize DNS backup: {e}"))?;
    atomic_file::write(path, 0o600, |file, _| file.write_all(text.as_bytes()))
        .map_err(|e| format!("install DNS backup {}: {e}", path.display()))
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
        .map(|line| parse_dns_socket(line).ok().map(|_| (*line).to_string()))
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
            takeover_servers: Some(vec!["127.0.0.1".parse().unwrap()]),
        };
        let text = toml::to_string(&backup).unwrap();
        let decoded: Backup = toml::from_str(&text).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.services[0].name, "USB & Wi-Fi");
        assert_eq!(decoded.services[0].servers.len(), 2);
        assert_eq!(decoded.fallback_servers, ["192.0.2.53"]);
        assert_eq!(
            decoded.takeover_servers,
            Some(vec!["127.0.0.1".parse().unwrap()])
        );
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
  nameserver[1] : fe80::1%7
  nameserver[2] : 2001:db8::53
"#;
        assert_eq!(
            filter_fallback_servers(
                parse_scutil_global_dns(text).unwrap(),
                &["127.0.0.1".parse().unwrap()]
            ),
            [
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[fe80::1%7]:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse::<SocketAddr>().unwrap()
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
            parse_scutil_global_dns(text).unwrap(),
            [
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[fdfd:3b1d:1c26::1]:53".parse::<SocketAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn parses_and_serializes_scoped_ipv6_dns_servers() {
        let address = parse_dns_socket("fe80::1%7").unwrap();
        assert_eq!(address, "[fe80::1%7]:53".parse().unwrap());
        assert_eq!(serialize_dns_socket(address), "fe80::1%7");
        assert_eq!(
            serialize_dns_socket(parse_dns_socket("2001:db8::53").unwrap()),
            "2001:db8::53"
        );
    }

    #[test]
    fn runtime_fallback_rejects_only_loopback_servers() {
        let error = usable_runtime_fallback(
            vec!["127.0.0.1:53".parse().unwrap()],
            "127.0.0.1".parse().unwrap(),
        )
        .unwrap_err();
        assert!(error.contains("no non-loopback"));
        assert_eq!(
            usable_runtime_fallback(
                vec!["192.0.2.53:53".parse().unwrap()],
                "127.0.0.1".parse().unwrap(),
            )
            .unwrap(),
            ["192.0.2.53:53".parse::<SocketAddr>().unwrap()]
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
    fn new_service_snapshots_are_added_once_before_reassertion() {
        let mut backup = Backup {
            version: 2,
            services: vec![ServiceDns {
                name: "Wi-Fi".into(),
                servers: vec!["192.0.2.53".into()],
            }],
            fallback_servers: Vec::new(),
            takeover_servers: None,
        };
        assert!(
            add_new_service_snapshots(
                &mut backup,
                vec![
                    ("Wi-Fi".into(), vec!["192.0.2.53".into()]),
                    ("iPhone USB".into(), Vec::new()),
                ],
                "127.0.0.1"
            )
            .unwrap()
        );
        assert_eq!(backup.services.len(), 2);
        assert_eq!(backup.services[1].name, "iPhone USB");
        assert!(backup.services[1].servers.is_empty());
        assert!(
            !add_new_service_snapshots(
                &mut backup,
                vec![("iPhone USB".into(), Vec::new())],
                "127.0.0.1"
            )
            .unwrap()
        );
        assert_eq!(backup.services.len(), 2);
    }

    #[test]
    fn new_service_already_pointing_at_proxy_is_rejected() {
        let mut backup = Backup {
            version: 2,
            services: Vec::new(),
            fallback_servers: Vec::new(),
            takeover_servers: None,
        };
        let error = add_new_service_snapshots(
            &mut backup,
            vec![("iPhone USB".into(), vec!["127.0.0.1".into()])],
            "127.0.0.1",
        )
        .unwrap_err();
        assert!(error.contains("iPhone USB"));
        assert!(backup.services.is_empty());
    }

    struct RestoreFixture {
        root: std::path::PathBuf,
        path: std::path::PathBuf,
        dns: std::cell::RefCell<std::collections::BTreeMap<String, Vec<String>>>,
    }

    impl RestoreFixture {
        fn new(backup: &Backup, current: &[(&str, &[&str])]) -> Self {
            let root = std::env::temp_dir().join(format!(
                "dnsrivet-restore-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            let path = root.join("dns-backup.toml");
            std::fs::write(&path, toml::to_string(backup).unwrap()).unwrap();
            let dns = std::cell::RefCell::new(
                current
                    .iter()
                    .map(|(name, servers)| {
                        (
                            (*name).to_string(),
                            servers.iter().map(|server| (*server).to_string()).collect(),
                        )
                    })
                    .collect(),
            );
            Self { root, path, dns }
        }

        fn restore(&self, fail_read: Option<&str>, fail_write: Option<&str>) -> Result<(), String> {
            restore_at(
                &self.path,
                || Ok(self.dns.borrow().keys().cloned().collect()),
                |name| {
                    if Some(name) == fail_read {
                        Err(format!("read failed for {name}"))
                    } else {
                        Ok(self.dns.borrow()[name].clone())
                    }
                },
                |name, servers| {
                    if Some(name) == fail_write {
                        Err(format!("write failed for {name}"))
                    } else {
                        self.dns.borrow_mut().insert(name.into(), servers.to_vec());
                        Ok(())
                    }
                },
            )
        }
    }

    impl Drop for RestoreFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn restore_backup() -> Backup {
        Backup {
            version: 2,
            services: vec![
                ServiceDns {
                    name: "Wi-Fi".into(),
                    servers: vec!["192.0.2.53".into()],
                },
                ServiceDns {
                    name: "USB LAN".into(),
                    servers: Vec::new(),
                },
            ],
            fallback_servers: Vec::new(),
            takeover_servers: Some(vec!["127.0.0.1".parse().unwrap()]),
        }
    }

    #[test]
    fn renamed_service_blocks_restore_and_retains_original_backup() {
        let fixture = RestoreFixture::new(
            &restore_backup(),
            &[
                ("Renamed Wi-Fi", &["127.0.0.1"]),
                ("USB LAN", &["127.0.0.1"]),
            ],
        );
        let original = std::fs::read(&fixture.path).unwrap();
        let error = fixture.restore(None, None).unwrap_err();
        assert!(error.contains("Renamed Wi-Fi"));
        assert!(error.contains("rename services back"));
        assert_eq!(std::fs::read(&fixture.path).unwrap(), original);
        assert_eq!(fixture.dns.borrow()["Renamed Wi-Fi"], ["127.0.0.1"]);
        assert!(fixture.dns.borrow()["USB LAN"].is_empty());

        // Restoring the old name is actionable recovery, not a guessed DNS list.
        let servers = fixture.dns.borrow_mut().remove("Renamed Wi-Fi").unwrap();
        fixture.dns.borrow_mut().insert("Wi-Fi".into(), servers);
        fixture.restore(None, None).unwrap();
        assert!(!fixture.path.exists());
        assert_eq!(fixture.dns.borrow()["Wi-Fi"], ["192.0.2.53"]);
    }

    #[test]
    fn changed_takeover_address_is_persisted_and_blocks_renamed_service_restore() {
        let fixture = RestoreFixture::new(&restore_backup(), &[("Wi-Fi", &["127.0.0.1"])]);
        let mut backup = read_backup_at(&fixture.path).unwrap();
        let next_server = "127.0.0.4".parse().unwrap();
        prepare_watchdog_backup(&mut backup, Vec::new(), next_server, |updated| {
            // DNS is still at A while the backup is made durable for B.
            assert_eq!(fixture.dns.borrow()["Wi-Fi"], ["127.0.0.1"]);
            write_backup_at(&fixture.path, updated)
        })
        .unwrap();
        let persisted = read_backup_at(&fixture.path).unwrap();
        assert_eq!(
            persisted.takeover_servers,
            Some(vec!["127.0.0.1".parse().unwrap(), next_server])
        );
        prepare_watchdog_backup(&mut backup, Vec::new(), next_server, |_| {
            panic!("an unchanged address must not rewrite the backup")
        })
        .unwrap();

        // Simulate reassertion at B, followed by a rename before the next tick.
        fixture.dns.borrow_mut().remove("Wi-Fi");
        fixture
            .dns
            .borrow_mut()
            .insert("Renamed Wi-Fi".into(), vec![next_server.to_string()]);
        let original = std::fs::read(&fixture.path).unwrap();
        let error = fixture.restore(None, None).unwrap_err();
        assert!(error.contains("Renamed Wi-Fi"));
        assert!(error.contains("127.0.0.4"));
        assert_eq!(std::fs::read(&fixture.path).unwrap(), original);
        assert_eq!(fixture.dns.borrow()["Renamed Wi-Fi"], ["127.0.0.4"]);

        // A must also remain guarded: disabled/failed services can retain it.
        fixture
            .dns
            .borrow_mut()
            .insert("Renamed Wi-Fi".into(), vec!["127.0.0.1".into()]);
        assert!(
            fixture
                .restore(None, None)
                .unwrap_err()
                .contains("127.0.0.1")
        );
        assert_eq!(std::fs::read(&fixture.path).unwrap(), original);
    }

    #[test]
    fn takeover_verification_observes_renamed_services_and_never_passes_vacuously() {
        let backup = restore_backup();
        let names = || Ok(vec!["Renamed Wi-Fi".into()]);
        assert!(
            !takeover_intact_with(&backup, "127.0.0.4", &[], names, |_| Ok(vec![
                "127.0.0.1".into()
            ]))
            .unwrap()
        );
        assert!(
            takeover_intact_with(&backup, "127.0.0.1", &[], names, |_| Ok(vec![
                "127.0.0.1".into()
            ]))
            .unwrap()
        );
        assert!(
            !takeover_intact_with(
                &backup,
                "127.0.0.1",
                &[],
                || Ok(Vec::new()),
                |_| unreachable!()
            )
            .unwrap()
        );
        assert!(
            takeover_intact_with(&backup, "127.0.0.1", &[], names, |_| Err(
                "cannot read DNS".into()
            ))
            .is_err()
        );
    }

    #[test]
    fn takeover_verification_includes_new_enabled_services_but_not_unrelated_disabled_ones() {
        let backup = restore_backup();
        let names = || Ok(vec!["Wi-Fi".into(), "New adapter".into()]);
        let dns = |name: &str| {
            Ok(vec![
                if name == "Wi-Fi" {
                    "127.0.0.1"
                } else {
                    "192.0.2.53"
                }
                .into(),
            ])
        };
        assert!(
            !takeover_intact_with(&backup, "127.0.0.1", &["New adapter".into()], names, dns)
                .unwrap()
        );
        assert!(takeover_intact_with(&backup, "127.0.0.1", &[], names, dns).unwrap());
    }

    #[test]
    fn watchdog_cannot_reassert_after_address_history_persistence_fails() {
        let fixture = RestoreFixture::new(&restore_backup(), &[("Wi-Fi", &["127.0.0.1"])]);
        let original = std::fs::read(&fixture.path).unwrap();
        let mut backup = read_backup_at(&fixture.path).unwrap();
        let result = prepare_watchdog_backup(
            &mut backup,
            Vec::new(),
            "127.0.0.4".parse().unwrap(),
            |_| Err("backup write failed".into()),
        )
        .map(|()| {
            fixture
                .dns
                .borrow_mut()
                .insert("Wi-Fi".into(), vec!["127.0.0.4".into()]);
        });
        assert_eq!(result.unwrap_err(), "backup write failed");
        assert_eq!(fixture.dns.borrow()["Wi-Fi"], ["127.0.0.1"]);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), original);
    }

    #[test]
    fn watchdog_keeps_legacy_history_unknown_and_rejects_old_untracked_loopback() {
        for version in [1, 2] {
            let mut backup = restore_backup();
            backup.version = version;
            backup.takeover_servers = None;
            let fixture = RestoreFixture::new(&backup, &[("Renamed Wi-Fi", &["127.0.0.1"])]);
            prepare_watchdog_backup(
                &mut backup,
                vec![("New service".into(), vec!["198.51.100.53".into()])],
                "127.0.0.4".parse().unwrap(),
                |updated| write_backup_at(&fixture.path, updated),
            )
            .unwrap();
            assert!(
                read_backup_at(&fixture.path)
                    .unwrap()
                    .takeover_servers
                    .is_none()
            );
            assert!(
                fixture
                    .restore(None, None)
                    .unwrap_err()
                    .contains("Renamed Wi-Fi")
            );
            assert!(fixture.path.exists());
            assert!(
                prepare_watchdog_backup(
                    &mut backup,
                    vec![("Renamed Wi-Fi".into(), vec!["127.0.0.1".into()])],
                    "127.0.0.4".parse().unwrap(),
                    |_| panic!("must not capture an unknown previous takeover address"),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn watchdog_rejects_new_name_still_using_a_previous_takeover_address() {
        let mut backup = restore_backup();
        let error = prepare_watchdog_backup(
            &mut backup,
            vec![("Renamed Wi-Fi".into(), vec!["127.0.0.1".into()])],
            "127.0.0.4".parse().unwrap(),
            |_| panic!("must not capture the old takeover as original DNS"),
        )
        .unwrap_err();
        assert!(error.contains("Renamed Wi-Fi"));
        assert!(error.contains("unknown restore state"));
        assert_eq!(backup.services.len(), 2);
    }

    #[test]
    fn removed_service_is_safe_when_remaining_dns_is_restored() {
        let fixture = RestoreFixture::new(&restore_backup(), &[("USB LAN", &["127.0.0.1"])]);
        fixture.restore(None, None).unwrap();
        assert!(!fixture.path.exists());
        assert!(fixture.dns.borrow()["USB LAN"].is_empty());
    }

    #[test]
    fn renamed_service_with_changed_dns_is_left_untouched() {
        let fixture = RestoreFixture::new(
            &restore_backup(),
            &[
                ("Renamed Wi-Fi", &["198.51.100.53"]),
                ("USB LAN", &["127.0.0.1"]),
            ],
        );
        fixture.restore(None, None).unwrap();
        assert!(!fixture.path.exists());
        assert_eq!(fixture.dns.borrow()["Renamed Wi-Fi"], ["198.51.100.53"]);
    }

    #[test]
    fn untracked_service_with_extra_resolver_still_blocks_stop() {
        let fixture = RestoreFixture::new(
            &restore_backup(),
            &[
                ("Wi-Fi", &["127.0.0.1"]),
                ("New service", &["198.51.100.53", "127.0.0.1"]),
            ],
        );
        let error = fixture.restore(None, None).unwrap_err();
        assert!(error.contains("New service"));
        assert!(fixture.path.exists());
    }

    #[test]
    fn partial_write_and_verification_errors_retain_backup_for_retry() {
        let fixture = RestoreFixture::new(
            &restore_backup(),
            &[("Wi-Fi", &["127.0.0.1"]), ("USB LAN", &["127.0.0.1"])],
        );
        let original = std::fs::read(&fixture.path).unwrap();
        let error = fixture.restore(Some("USB LAN"), Some("Wi-Fi")).unwrap_err();
        assert!(error.contains("write failed for Wi-Fi"));
        assert!(error.contains("read failed for USB LAN"));
        assert!(error.contains("Wi-Fi\" still lists DNS"));
        assert_eq!(std::fs::read(&fixture.path).unwrap(), original);
        assert!(fixture.dns.borrow()["USB LAN"].is_empty());
        fixture.restore(None, None).unwrap();
        assert!(!fixture.path.exists());
    }

    #[test]
    fn normal_restore_preserves_other_loopback_dns() {
        let mut backup = restore_backup();
        backup.services[0].servers = vec!["127.0.0.2".into(), "::1".into()];
        let fixture = RestoreFixture::new(
            &backup,
            &[
                ("Wi-Fi", &["127.0.0.1"]),
                ("USB LAN", &["127.0.0.1"]),
                ("Other tool", &["127.0.0.3"]),
            ],
        );
        fixture.restore(None, None).unwrap();
        assert!(!fixture.path.exists());
        assert_eq!(fixture.dns.borrow()["Wi-Fi"], ["127.0.0.2", "::1"]);
        assert_eq!(fixture.dns.borrow()["Other tool"], ["127.0.0.3"]);
        assert!(fixture.dns.borrow()["USB LAN"].is_empty());
    }

    #[test]
    fn legacy_backups_preserve_proven_original_loopback_but_reject_unknown_loopback() {
        for version in [1, 2] {
            let text = format!(
                "version = {version}\n[[services]]\nname = 'Wi-Fi'\nservers = ['127.0.0.2']\n"
            );
            let backup: Backup = toml::from_str(&text).unwrap();
            assert!(backup.takeover_servers.is_none());
            let fixture = RestoreFixture::new(
                &backup,
                &[("Wi-Fi", &["127.0.0.1"]), ("Unknown", &["127.0.0.1"])],
            );
            assert!(fixture.restore(None, None).unwrap_err().contains("Unknown"));
            assert_eq!(fixture.dns.borrow()["Wi-Fi"], ["127.0.0.2"]);
            assert!(fixture.path.exists());
            fixture
                .dns
                .borrow_mut()
                .insert("Unknown".into(), vec!["198.51.100.53".into()]);
            fixture.restore(None, None).unwrap();
            assert!(!fixture.path.exists());
        }
    }

    #[test]
    fn services_appearing_during_restore_are_verified() {
        let fixture = RestoreFixture::new(&restore_backup(), &[("Wi-Fi", &["127.0.0.1"])]);
        let mut lists = 0;
        let error = restore_at(
            &fixture.path,
            || {
                lists += 1;
                Ok(if lists == 1 {
                    vec!["Wi-Fi".into()]
                } else {
                    vec!["Wi-Fi".into(), "New service".into()]
                })
            },
            |name| {
                Ok(if name == "Wi-Fi" {
                    vec!["192.0.2.53".into()]
                } else {
                    vec!["127.0.0.1".into()]
                })
            },
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("New service"));
        assert!(fixture.path.exists());
    }

    #[test]
    fn verification_list_error_retains_backup() {
        let fixture = RestoreFixture::new(&restore_backup(), &[]);
        let mut lists = 0;
        let error = restore_at(
            &fixture.path,
            || {
                lists += 1;
                if lists == 1 {
                    Ok(Vec::new())
                } else {
                    Err("list failed".into())
                }
            },
            |_| panic!("no service DNS should be read"),
            |_, _| panic!("no service DNS should be written"),
        )
        .unwrap_err();
        assert!(error.contains("list failed"));
        assert!(fixture.path.exists());
    }

    #[test]
    fn takeover_state_matrix() {
        assert_eq!(classify(false, false), TakeoverState::NotTakenOver);
        assert_eq!(classify(true, true), TakeoverState::Active);
        assert_eq!(classify(true, false), TakeoverState::Indeterminate);
        assert_eq!(classify(false, true), TakeoverState::Corrupted);
    }
}
