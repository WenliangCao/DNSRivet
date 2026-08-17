//! Transactional macOS DNS configuration through `networksetup`.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
pub const BACKUP_PATH: &str = "/Library/Application Support/DNSRivet/dns-backup.toml";

#[derive(Debug, Deserialize, Serialize)]
struct Backup {
    version: u8,
    services: Vec<ServiceDns>,
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
/// are rolled back before returning.
pub fn take_over(server: IpAddr) -> Result<(), String> {
    if backup_exists() {
        return Err(format!(
            "DNS backup already exists at {BACKUP_PATH}; run `dnsrivet stop` before starting again"
        ));
    }

    let mut services = Vec::new();
    for name in list_services()? {
        let servers = get_dns_servers(&name)?;
        if servers
            .iter()
            .any(|existing| existing == &server.to_string())
        {
            eprintln!(
                "warning: network service {name:?} already uses {server}; another local DNS tool may own it"
            );
        }
        services.push(ServiceDns { name, servers });
    }
    if services.is_empty() {
        return Err("networksetup returned no enabled network services".into());
    }

    let backup = Backup {
        version: 1,
        services,
    };
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
    flush_caches();
    Ok(())
}

/// Restore the exact per-service DNS snapshot. A missing backup means this
/// process has no evidence that it owns the current DNS settings, so it safely
/// leaves them untouched.
pub fn restore() -> Result<bool, String> {
    if !backup_exists() {
        return Ok(false);
    }
    let text = std::fs::read_to_string(BACKUP_PATH)
        .map_err(|e| format!("read DNS backup {BACKUP_PATH}: {e}"))?;
    let backup: Backup =
        toml::from_str(&text).map_err(|e| format!("parse DNS backup {BACKUP_PATH}: {e}"))?;
    if backup.version != 1 {
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
            version: 1,
            services: vec![ServiceDns {
                name: "USB & Wi-Fi".into(),
                servers: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()],
            }],
        };
        let text = toml::to_string(&backup).unwrap();
        let decoded: Backup = toml::from_str(&text).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.services[0].name, "USB & Wi-Fi");
        assert_eq!(decoded.services[0].servers.len(), 2);
    }
}
