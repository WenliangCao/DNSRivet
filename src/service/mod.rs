mod launchd;

use crate::{config, osdns};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SUPPORT_DIR: &str = "/Library/Application Support/DNSRivet";
pub const CONFIG_PATH: &str = "/Library/Application Support/DNSRivet/config.toml";
pub const BINARY_PATH: &str = "/Library/Application Support/DNSRivet/dnsrivet";

pub fn start(config_path: Option<PathBuf>) -> Result<String, String> {
    require_root()?;
    if launchd::is_loaded() {
        return Err("service is already loaded; use `dnsrivet restart`".into());
    }
    if osdns::backup_exists() {
        return Err(
            "a previous DNS backup is still present; run `dnsrivet stop` before starting".into(),
        );
    }

    let installed_config = install_config(config_path)?;
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

pub fn restart() -> Result<String, String> {
    require_root()?;
    if !launchd::is_loaded() {
        return Err("service is not loaded; use `dnsrivet start`".into());
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
    let addr = installed_probe_address()?;
    match wait_for_dns(addr, Duration::from_secs(2)) {
        Ok(()) => Ok(format!("service: loaded; DNS probe at {addr}: healthy")),
        Err(err) => Ok(format!(
            "service: loaded; DNS probe at {addr}: failed ({err})"
        )),
    }
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

fn install_config(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    let destination = Path::new(CONFIG_PATH);
    let source = match explicit {
        Some(path) => {
            if !path.is_file() {
                return Err(format!("config file not found: {}", path.display()));
            }
            config::load(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            Some(path)
        }
        None if destination.is_file() => None,
        None if Path::new("dnsrivet.toml").is_file() => Some(PathBuf::from("dnsrivet.toml")),
        None => {
            write_config(destination, include_bytes!("../../example.config.toml"))?;
            return Ok(destination.to_path_buf());
        }
    };

    if let Some(source) = source {
        let bytes =
            std::fs::read(&source).map_err(|e| format!("read config {}: {e}", source.display()))?;
        write_config(destination, &bytes)?;
    }
    Ok(destination.to_path_buf())
}

fn write_config(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(SUPPORT_DIR)
        .map_err(|e| format!("create support directory {SUPPORT_DIR}: {e}"))?;
    let temporary = Path::new(SUPPORT_DIR).join(".config.toml.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(&temporary)
        .map_err(|e| format!("write config {}: {e}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write config {}: {e}", temporary.display()))?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o644))
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
}
