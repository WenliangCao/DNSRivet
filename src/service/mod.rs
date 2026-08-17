mod launchd;

use crate::{config, osdns};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::unix::fs::symlink;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SUPPORT_DIR: &str = "/Library/Application Support/DNSRivet";
pub const CONFIG_PATH: &str = "/Library/Application Support/DNSRivet/config.toml";
pub const BINARY_PATH: &str = "/Library/Application Support/DNSRivet/dnsrivet";
pub const COMMAND_PATH: &str = "/usr/local/bin/dnsrivet";

pub fn start(
    config_path: Option<PathBuf>,
    generated_config: Option<String>,
) -> Result<String, String> {
    require_root()?;
    if launchd::is_loaded() {
        return Err("service is already loaded; use `dnsrivet restart`".into());
    }
    if osdns::backup_exists() {
        return Err(
            "a previous DNS backup is still present; run `dnsrivet stop` before starting".into(),
        );
    }

    let installed_config = install_config(config_path, generated_config)?;
    let loaded = config::load(&installed_config)
        .map_err(|e| format!("{}: {e}", installed_config.display()))?;
    let dns_ip = takeover_address(&loaded.config.listeners)?;

    // Hold all sockets until the plist is ready. This detects existing DNS
    // software and conflicts among our configured listeners before network
    // state is changed.
    let listeners = preflight_listeners(&loaded.config.listeners)?;
    let current_binary = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("resolve current executable: {e}"))?;
    let binary = install_binary(&current_binary)?;
    install_command(&binary)?;
    launchd::write_plist(&binary, &installed_config)?;
    drop(listeners);

    launchd::set_enabled(true)?;
    if let Err(err) = launchd::bootstrap() {
        let _ = launchd::remove_plist();
        return Err(err);
    }

    let probe_addr = SocketAddr::new(dns_ip, 53);
    if let Err(err) = wait_for_dns(probe_addr, Duration::from_secs(15)) {
        let _ = launchd::bootout();
        let _ = launchd::remove_plist();
        return Err(format!("service started but failed its DNS probe: {err}"));
    }

    if let Err(err) = osdns::take_over(dns_ip) {
        if osdns::backup_exists() {
            return Err(format!(
                "DNS takeover failed and rollback was incomplete: {err}; the service was left running so any network service still using {dns_ip} can resolve—run `dnsrivet stop` to retry restoration"
            ));
        }
        let _ = launchd::bootout();
        let _ = launchd::remove_plist();
        return Err(format!(
            "service was stopped because DNS takeover failed: {err}"
        ));
    }

    Ok(format!(
        "service started; system DNS now uses {dns_ip} (backup: {})",
        osdns::BACKUP_PATH
    ))
}

pub fn stop() -> Result<String, String> {
    require_root()?;
    let restored = osdns::restore()?;
    let managed = launchd::is_installed() || launchd::is_loaded();
    if managed {
        launchd::set_enabled(false)?;
    }
    let stopped = launchd::bootout()?;
    Ok(match (restored, stopped) {
        (true, true) => "service stopped and system DNS restored".into(),
        (true, false) => "service was not loaded; system DNS was restored".into(),
        (false, true) => {
            "service stopped; no DNSRivet DNS backup existed, so DNS was unchanged".into()
        }
        (false, false) => "service is not loaded; DNS was unchanged".into(),
    })
}

pub fn restart(
    config_path: Option<PathBuf>,
    generated_config: Option<String>,
) -> Result<String, String> {
    require_root()?;
    if !launchd::is_loaded() {
        return Err("service is not loaded; use `dnsrivet start`".into());
    }
    if config_path.is_some() || generated_config.is_some() {
        let replacement = config_bytes(config_path, generated_config)?
            .expect("replacement requested when a config source is present");
        return restart_with_config(&replacement);
    }
    launchd::restart()?;
    let addr = installed_probe_address()?;
    wait_for_dns(addr, Duration::from_secs(15))?;
    Ok("service restarted and DNS probe passed".into())
}

pub fn status() -> Result<String, String> {
    if !launchd::is_loaded() {
        return Ok(if launchd::is_installed() {
            "service: installed but stopped".into()
        } else {
            "service: not installed".into()
        });
    }
    let addresses = match installed_probe_address() {
        Ok(addr) => vec![addr],
        Err(config_err) => {
            let addresses = osdns::current_loopback_dns()?;
            if addresses.is_empty() {
                return Err(config_err);
            }
            addresses
        }
    };
    let mut failures = Vec::new();
    for addr in addresses {
        match wait_for_dns(addr, Duration::from_secs(2)) {
            Ok(()) => return Ok(format!("service: loaded; DNS probe at {addr}: healthy")),
            Err(err) => failures.push(format!("{addr}: {err}")),
        }
    }
    Ok(format!(
        "service: loaded; DNS probe failed ({})",
        failures.join("; ")
    ))
}

pub fn uninstall() -> Result<String, String> {
    require_root()?;
    let restored = osdns::restore()?;
    let managed = launchd::is_installed() || launchd::is_loaded();
    if managed {
        launchd::set_enabled(false)?;
    }
    let stopped = launchd::bootout()?;
    launchd::remove_plist()?;
    remove_command()?;
    remove_installed_binary()?;
    // Clear the persistent launchd disabled override now that no job remains.
    if managed {
        launchd::set_enabled(true)?;
    }
    Ok(format!(
        "service uninstalled{}{}; config preserved at {CONFIG_PATH}",
        if stopped { " and stopped" } else { "" },
        if restored {
            "; system DNS restored"
        } else {
            "; DNS unchanged"
        }
    ))
}

fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err("this command changes a system LaunchDaemon or DNS settings; rerun it with sudo".into())
    }
}

fn install_config(explicit: Option<PathBuf>, generated: Option<String>) -> Result<PathBuf, String> {
    let destination = Path::new(CONFIG_PATH);
    if let Some(bytes) = config_bytes(explicit, generated)? {
        write_config(destination, &bytes)?;
    } else if !destination.is_file() {
        let local = Path::new("dnsrivet.toml");
        if local.is_file() {
            let bytes = std::fs::read(local)
                .map_err(|e| format!("read config {}: {e}", local.display()))?;
            config::load_text(
                std::str::from_utf8(&bytes).map_err(|e| format!("config is not UTF-8: {e}"))?,
            )?;
            write_config(destination, &bytes)?;
        } else {
            return Err(
                "no config found; pass --config PATH or at least one --upstream TYPE=ENDPOINT"
                    .into(),
            );
        }
    }
    Ok(destination.to_path_buf())
}

fn config_bytes(
    explicit: Option<PathBuf>,
    generated: Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    match (explicit, generated) {
        (Some(_), Some(_)) => Err("config path and generated config cannot be combined".into()),
        (Some(path), None) => {
            if !path.is_file() {
                return Err(format!("config file not found: {}", path.display()));
            }
            let bytes =
                std::fs::read(&path).map_err(|e| format!("read config {}: {e}", path.display()))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|e| format!("{} is not UTF-8: {e}", path.display()))?;
            config::load_text(text).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(Some(bytes))
        }
        (None, Some(text)) => {
            config::load_text(&text)?;
            Ok(Some(text.into_bytes()))
        }
        (None, None) => Ok(None),
    }
}

fn restart_with_config(replacement: &[u8]) -> Result<String, String> {
    let destination = Path::new(CONFIG_PATH);
    let previous = std::fs::read(destination)
        .map_err(|e| format!("read installed config {}: {e}", destination.display()))?;
    write_config(destination, replacement)?;

    let result = launchd::restart().and_then(|()| {
        let addr = installed_probe_address()?;
        wait_for_dns(addr, Duration::from_secs(15))
    });
    match result {
        Ok(()) => Ok("configuration installed; service restarted and DNS probe passed".into()),
        Err(err) => {
            write_config(destination, &previous)?;
            let rollback = launchd::restart().and_then(|()| {
                let addr = installed_probe_address()?;
                wait_for_dns(addr, Duration::from_secs(15))
            });
            match rollback {
                Ok(()) => Err(format!(
                    "new configuration failed: {err}; previous configuration restored and restarted"
                )),
                Err(rollback_err) => Err(format!(
                    "new configuration failed: {err}; previous configuration was restored but its restart failed: {rollback_err}"
                )),
            }
        }
    }
}

fn write_config(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(SUPPORT_DIR)
        .map_err(|e| format!("create support directory {SUPPORT_DIR}: {e}"))?;
    let temporary = Path::new(SUPPORT_DIR).join(".config.toml.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| format!("write config {}: {e}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write config {}: {e}", temporary.display()))?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("set config permissions {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("install config {}: {e}", path.display()))
}

fn install_binary(source: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(SUPPORT_DIR)
        .map_err(|e| format!("create support directory {SUPPORT_DIR}: {e}"))?;
    let bytes =
        std::fs::read(source).map_err(|e| format!("read executable {}: {e}", source.display()))?;
    let temporary = Path::new(SUPPORT_DIR).join(".dnsrivet.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o755)
        .open(&temporary)
        .map_err(|e| format!("write executable {}: {e}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write executable {}: {e}", temporary.display()))?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("set executable permissions {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, BINARY_PATH)
        .map_err(|e| format!("install executable {BINARY_PATH}: {e}"))?;
    Ok(PathBuf::from(BINARY_PATH))
}

fn install_command(binary: &Path) -> Result<(), String> {
    install_command_at(Path::new(COMMAND_PATH), binary)
}

fn install_command_at(command: &Path, binary: &Path) -> Result<(), String> {
    let parent = command
        .parent()
        .ok_or_else(|| format!("command path {} has no parent", command.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create command directory {}: {e}", parent.display()))?;

    match std::fs::symlink_metadata(command) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = std::fs::read_link(command)
                .map_err(|e| format!("read command link {}: {e}", command.display()))?;
            if target != binary {
                return Err(format!(
                    "refusing to replace command link {} -> {}",
                    command.display(),
                    target.display()
                ));
            }
        }
        Ok(_) => {
            return Err(format!(
                "refusing to replace existing command path {}",
                command.display()
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("inspect command path {}: {err}", command.display())),
    }

    let temporary = parent.join(format!(".dnsrivet-link-{}.tmp", std::process::id()));
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("remove stale command link: {err}")),
    }
    symlink(binary, &temporary)
        .map_err(|e| format!("create command link {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, command)
        .map_err(|e| format!("install command link {}: {e}", command.display()))
}

fn remove_command() -> Result<(), String> {
    remove_command_at(Path::new(COMMAND_PATH), Path::new(BINARY_PATH))
}

fn remove_command_at(command: &Path, binary: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(command) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = std::fs::read_link(command)
                .map_err(|e| format!("read command link {}: {e}", command.display()))?;
            if target == binary {
                std::fs::remove_file(command)
                    .map_err(|e| format!("remove command link {}: {e}", command.display()))?;
            } else {
                eprintln!(
                    "warning: command link {} now points to {}; leaving it untouched",
                    command.display(),
                    target.display()
                );
            }
            Ok(())
        }
        Ok(_) => {
            eprintln!(
                "warning: command path {} is no longer a DNSRivet link; leaving it untouched",
                command.display()
            );
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("inspect command path {}: {err}", command.display())),
    }
}

fn remove_installed_binary() -> Result<(), String> {
    match std::fs::remove_file(BINARY_PATH) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("remove installed executable {BINARY_PATH}: {err}")),
    }
}

fn takeover_address(listeners: &[SocketAddr]) -> Result<IpAddr, String> {
    listeners
        .iter()
        .find(|addr| addr.port() == 53 && addr.ip().is_loopback() && addr.is_ipv4())
        .or_else(|| {
            listeners
                .iter()
                .find(|addr| addr.port() == 53 && addr.ip().is_loopback())
        })
        .map(SocketAddr::ip)
        .ok_or_else(|| {
            "service mode requires a loopback listener on port 53 (normally 127.0.0.1:53)".into()
        })
}

struct BoundListeners {
    _udp: Vec<UdpSocket>,
    _tcp: Vec<TcpListener>,
}

fn preflight_listeners(addresses: &[SocketAddr]) -> Result<BoundListeners, String> {
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    for addr in addresses {
        udp.push(
            UdpSocket::bind(addr)
                .map_err(|e| format!("cannot start: UDP listener {addr} is unavailable: {e}"))?,
        );
        tcp.push(
            TcpListener::bind(addr)
                .map_err(|e| format!("cannot start: TCP listener {addr} is unavailable: {e}"))?,
        );
    }
    Ok(BoundListeners {
        _udp: udp,
        _tcp: tcp,
    })
}

fn installed_probe_address() -> Result<SocketAddr, String> {
    let loaded = config::load(Path::new(CONFIG_PATH)).map_err(|e| format!("{CONFIG_PATH}: {e}"))?;
    Ok(SocketAddr::new(
        takeover_address(&loaded.config.listeners)?,
        53,
    ))
}

fn wait_for_dns(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_error = "no response".to_string();
    while Instant::now() < deadline {
        match dns_probe(addr, Duration::from_secs(1)) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = err,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(last_error)
}

fn dns_probe(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    socket.connect(addr).map_err(|e| e.to_string())?;

    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16;
    let mut query = Vec::from(id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    query.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
    socket.send(&query).map_err(|e| e.to_string())?;
    let mut response = [0u8; 4096];
    let n = socket.recv(&mut response).map_err(|e| e.to_string())?;
    if n < 12
        || response[..2] != id.to_be_bytes()
        || response[2] & 0x80 == 0
        || response[3] & 0x0f != 0
        || u16::from_be_bytes([response[6], response[7]]) == 0
    {
        return Err("invalid DNS probe response".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_ipv4_loopback_listener_on_port_53() {
        let listeners = ["[::1]:53".parse().unwrap(), "127.0.0.1:53".parse().unwrap()];
        assert_eq!(
            takeover_address(&listeners).unwrap().to_string(),
            "127.0.0.1"
        );
    }

    #[test]
    fn rejects_nonstandard_service_listener() {
        assert!(takeover_address(&["127.0.0.1:5354".parse().unwrap()]).is_err());
    }

    #[test]
    fn preflight_reports_an_occupied_tcp_listener() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap();
        let err = match preflight_listeners(&[addr]) {
            Ok(_) => panic!("preflight unexpectedly accepted an occupied TCP port"),
            Err(err) => err,
        };
        assert!(err.contains("TCP listener"));
    }

    #[test]
    fn command_link_install_and_remove_are_ownership_safe() {
        let root = std::env::temp_dir().join(format!(
            "dnsrivet-command-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let binary = root.join("installed/dnsrivet");
        let command = root.join("bin/dnsrivet");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"binary").unwrap();

        install_command_at(&command, &binary).unwrap();
        assert_eq!(std::fs::read_link(&command).unwrap(), binary);
        remove_command_at(&command, &binary).unwrap();
        assert!(!command.exists());

        std::fs::write(&command, b"unrelated").unwrap();
        assert!(install_command_at(&command, &binary).is_err());
        remove_command_at(&command, &binary).unwrap();
        assert_eq!(std::fs::read(&command).unwrap(), b"unrelated");
        std::fs::remove_dir_all(root).unwrap();
    }
}
