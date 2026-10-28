mod launchd;

use crate::osdns::lock::FsLock;
use crate::{atomic_file, config, osdns};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SUPPORT_DIR: &str = "/Library/Application Support/DNSRivet";
pub const CONFIG_PATH: &str = "/Library/Application Support/DNSRivet/config.toml";
pub const BINARY_PATH: &str = "/Library/Application Support/DNSRivet/dnsrivet";
pub const COMMAND_PATH: &str = "/usr/local/bin/dnsrivet";
// Independent of the DNS/watchdog lock: restart waits for daemon reassertion
// while holding this guard. Never remove the file, including during uninstall.
const LIFECYCLE_LOCK_PATH: &str = "/Library/Application Support/DNSRivet/.lifecycle.lock";

pub fn start(
    config_path: Option<PathBuf>,
    generated_config: Option<String>,
) -> Result<String, String> {
    require_root()?;
    let _lifecycle = FsLock::acquire(Path::new(LIFECYCLE_LOCK_PATH))?;
    if launchd::is_loaded()? {
        return Err("service is already loaded; use `dnsrivet restart`".into());
    }
    match osdns::takeover_state() {
        osdns::TakeoverState::NotTakenOver => {}
        osdns::TakeoverState::Corrupted => {
            return Err(
                "a takeover-active marker exists without a DNS backup (state corrupted); \
                 run `dnsrivet stop` to clean up before starting"
                    .into(),
            );
        }
        osdns::TakeoverState::Active | osdns::TakeoverState::Indeterminate => {
            return Err(
                "a previous DNS backup is still present; run `dnsrivet stop` before starting"
                    .into(),
            );
        }
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
    install_command(&binary, &current_binary)?;
    launchd::write_plist(&binary, &installed_config)?;
    drop(listeners);

    launchd::set_enabled(true)?;
    if let Err(err) = launchd::bootstrap() {
        let _ = launchd::remove_plist();
        return Err(err);
    }

    let probe_addr = SocketAddr::new(dns_ip, 53);
    if let Err(err) = wait_for_dns(probe_addr, Duration::from_secs(15)) {
        return Err(cleanup_failed_start(
            &format!("service started but failed its DNS probe: {err}"),
            launchd::bootout,
            launchd::remove_plist,
        ));
    }

    if let Err(err) = osdns::take_over(dns_ip) {
        if osdns::backup_exists() {
            return Err(format!(
                "DNS takeover failed and rollback was incomplete: {err}; the service was left running so any network service still using {dns_ip} can resolve—run `dnsrivet stop` to retry restoration"
            ));
        }
        return Err(cleanup_failed_start(
            &format!("DNS takeover failed: {err}"),
            launchd::bootout,
            launchd::remove_plist,
        ));
    }

    Ok(format!(
        "service started; system DNS now uses {dns_ip} (backup: {})",
        osdns::BACKUP_PATH
    ))
}

fn cleanup_failed_start(
    failure: &str,
    stop: impl FnOnce() -> Result<bool, String>,
    remove_plist: impl FnOnce() -> Result<(), String>,
) -> String {
    let stopped = match stop() {
        Ok(stopped) => stopped,
        Err(err) => {
            return format!(
                "{failure}; could not stop service: {err}; service may still be running, \
                 so the launchd plist was retained; run `dnsrivet stop` to retry"
            );
        }
    };
    let status = if stopped {
        "service was stopped"
    } else {
        "service was not loaded"
    };
    match remove_plist() {
        Ok(()) => format!("{failure}; {status}"),
        Err(err) => format!("{failure}; {status}; could not remove launchd plist: {err}"),
    }
}

pub fn stop() -> Result<String, String> {
    require_root()?;
    let _lifecycle = FsLock::acquire(Path::new(LIFECYCLE_LOCK_PATH))?;
    let restored = osdns::release()?;
    let managed = launchd::is_installed() || launchd::is_loaded()?;
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
    let _lifecycle = FsLock::acquire(Path::new(LIFECYCLE_LOCK_PATH))?;
    if !launchd::is_loaded()? {
        return Err("service is not loaded; use `dnsrivet start`".into());
    }
    refresh_installed_binary()?;
    if config_path.is_some() || generated_config.is_some() {
        let replacement = config_bytes(config_path, generated_config)?
            .expect("replacement requested when a config source is present");
        return restart_with_config(&replacement);
    }
    launchd::restart()?;
    let addr = installed_probe_address()?;
    wait_for_dns(addr, Duration::from_secs(15))?;
    // The restarted daemon reconciles the takeover itself on its immediate
    // first watchdog tick; this CLI only observes the result and never
    // touches DNS settings.
    Ok(match osdns::takeover_state() {
        osdns::TakeoverState::Active => {
            if wait_for_reassertion(addr.ip(), Duration::from_secs(15)) {
                "service restarted; DNS probe passed and takeover verified".into()
            } else {
                "service restarted and DNS probe passed, but takeover verification did not \
                 complete in time; check `dnsrivet status`"
                    .into()
            }
        }
        osdns::TakeoverState::NotTakenOver => "service restarted and DNS probe passed".into(),
        osdns::TakeoverState::Indeterminate | osdns::TakeoverState::Corrupted => {
            "service restarted and DNS probe passed, but the takeover state is inconsistent; \
             run `dnsrivet stop` then `dnsrivet start` to re-establish it"
                .into()
        }
    })
}

/// Poll until every backed-up service points exactly at the takeover address
/// again (the daemon's first watchdog tick performs the actual reassert).
fn wait_for_reassertion(server: IpAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(true) = osdns::takeover_intact(server) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// One status line for the takeover. "Armed" (backup + marker) is not proof
/// that queries flow through the proxy — inside the watchdog's check window
/// the system DNS can already be drifted — so when the installed config and
/// backup are readable (root), verify the actual per-service DNS lists too.
fn takeover_status_line() -> String {
    match osdns::takeover_state() {
        osdns::TakeoverState::NotTakenOver => "takeover: not active".into(),
        osdns::TakeoverState::Indeterminate => {
            "takeover: indeterminate (backup without marker); run `sudo dnsrivet stop`".into()
        }
        osdns::TakeoverState::Corrupted => {
            "takeover: state corrupted (marker without backup); run `sudo dnsrivet stop`".into()
        }
        osdns::TakeoverState::Active => match installed_probe_address() {
            Ok(addr) => match osdns::takeover_intact(addr.ip()) {
                Ok(true) => "takeover: active".into(),
                Ok(false) => "takeover: armed but drifted (system DNS is not pointing at the \
                              proxy); the watchdog reasserts it within its check interval"
                    .into(),
                Err(err) => format!("takeover: armed (verification failed: {err})"),
            },
            // Unprivileged runs cannot read the installed config or backup.
            Err(_) => "takeover: armed (rerun with sudo to verify the system DNS)".into(),
        },
    }
}

pub fn status() -> Result<String, String> {
    let takeover = takeover_status_line();
    if !launchd::is_loaded()? {
        return Ok(format!(
            "{}\n{takeover}",
            if launchd::is_installed() {
                "service: installed but stopped"
            } else {
                "service: not installed"
            }
        ));
    }
    let addresses = match installed_probe_address() {
        Ok(addr) => vec![addr],
        Err(config_err) => {
            let addresses = osdns::current_loopback_dns()?;
            if addresses.is_empty() {
                // No readable config and no loopback resolver to probe —
                // exactly the drifted-takeover situation where diagnostics
                // matter most; report what is known instead of erroring out.
                return Ok(format!(
                    "service: loaded; DNS probe unavailable ({config_err})\n{takeover}"
                ));
            }
            addresses
        }
    };
    let mut failures = Vec::new();
    for addr in addresses {
        match wait_for_dns(addr, Duration::from_secs(2)) {
            Ok(()) => {
                return Ok(format!(
                    "service: loaded; DNS probe at {addr}: healthy\n{takeover}"
                ));
            }
            Err(err) => failures.push(format!("{addr}: {err}")),
        }
    }
    Ok(format!(
        "service: loaded; DNS probe failed ({})\n{takeover}",
        failures.join("; ")
    ))
}

pub fn uninstall() -> Result<String, String> {
    require_root()?;
    let _lifecycle = FsLock::acquire(Path::new(LIFECYCLE_LOCK_PATH))?;
    let restored = osdns::release()?;
    let managed = launchd::is_installed() || launchd::is_loaded()?;
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
    if nix::unistd::geteuid().is_root() {
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
    let verify_takeover = match osdns::takeover_state() {
        osdns::TakeoverState::Active => true,
        osdns::TakeoverState::NotTakenOver => false,
        _ => return Err("takeover state is inconsistent; restore it with `dnsrivet stop` before replacing the configuration".into()),
    };
    restart_config_transaction(
        &previous,
        replacement,
        |bytes| write_config(destination, bytes),
        || {
            launchd::restart()?;
            wait_for_dns(installed_probe_address()?, Duration::from_secs(15))
        },
        || {
            if verify_takeover
                && !wait_for_reassertion(installed_probe_address()?.ip(), Duration::from_secs(15))
            {
                return Err("DNS probe passed but system DNS takeover was not verified".into());
            }
            Ok(())
        },
    )
}

fn restart_config_transaction(
    previous: &[u8],
    replacement: &[u8],
    mut install: impl FnMut(&[u8]) -> Result<(), String>,
    mut reload: impl FnMut() -> Result<(), String>,
    mut verify: impl FnMut() -> Result<(), String>,
) -> Result<String, String> {
    install(replacement)?;
    let result = reload().and_then(|()| verify());
    match result {
        Ok(()) => Ok("configuration installed; service restarted and DNS checks passed".into()),
        Err(err) => {
            install(previous)?;
            let rollback = reload().and_then(|()| verify());
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
    atomic_file::write(path, 0o600, |file, _| file.write_all(bytes))
        .map_err(|e| format!("install config {}: {e}", path.display()))
}

fn install_binary(source: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(SUPPORT_DIR)
        .map_err(|e| format!("create support directory {SUPPORT_DIR}: {e}"))?;
    install_binary_at(source, Path::new(BINARY_PATH))?;
    Ok(PathBuf::from(BINARY_PATH))
}

fn install_binary_at(source: &Path, destination: &Path) -> Result<(), String> {
    let mut source_file = std::fs::File::open(source)
        .map_err(|e| format!("read executable {}: {e}", source.display()))?;
    atomic_file::write(destination, 0o755, |file, _| {
        std::io::copy(&mut source_file, file).map(|_| ())
    })
    .map_err(|e| format!("install executable {}: {e}", destination.display()))
}

/// Refresh the daemon copy when `restart` is invoked from a package manager's
/// binary. Calls through DNSRivet's own stable link resolve to `BINARY_PATH`
/// and therefore remain a no-op.
fn refresh_installed_binary() -> Result<(), String> {
    let current = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("resolve current executable: {e}"))?;
    let installed =
        std::fs::canonicalize(BINARY_PATH).unwrap_or_else(|_| PathBuf::from(BINARY_PATH));
    if current != installed {
        install_binary(&current)?;
    }
    Ok(())
}

fn install_command(binary: &Path, invoking_binary: &Path) -> Result<(), String> {
    install_command_at(Path::new(COMMAND_PATH), binary, invoking_binary)
}

fn install_command_at(command: &Path, binary: &Path, invoking_binary: &Path) -> Result<(), String> {
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
                // Homebrew owns its prefix link. If that link resolves to the
                // executable which invoked `start`, leave it under Homebrew's
                // ownership instead of replacing it with DNSRivet's link.
                if paths_resolve_to_same_file(command, invoking_binary) {
                    return Ok(());
                }
                return Err(format!(
                    "refusing to replace command link {} -> {}",
                    command.display(),
                    target.display()
                ));
            }
        }
        Ok(_) => {
            if paths_resolve_to_same_file(command, invoking_binary) {
                return Ok(());
            }
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

fn paths_resolve_to_same_file(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
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

/// Also used by the daemon's takeover watchdog to derive the guarded address.
pub(crate) fn takeover_address(listeners: &[SocketAddr]) -> Result<IpAddr, String> {
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

    struct LockFixture {
        root: PathBuf,
    }

    impl LockFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "dnsrivet-lifecycle-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            Self { root }
        }

        fn spawn(&self, action: &str) -> std::process::Child {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "service::tests::lifecycle_lock_child",
                    "--nocapture",
                ])
                .env("DNSRIVET_TEST_LOCK_DIR", &self.root)
                .env("DNSRIVET_TEST_LOCK_ACTION", action)
                .spawn()
                .unwrap()
        }
    }

    impl Drop for LockFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn append_lock_event(root: &Path, event: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("events"))
            .unwrap();
        writeln!(file, "{event}").unwrap();
    }

    fn wait_for_lock_child(child: &mut std::process::Child, signal: Option<&Path>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "lock child failed: {status}");
                assert!(
                    signal.is_none(),
                    "lock child exited before contention barrier"
                );
                return;
            }
            if signal.is_some_and(Path::is_file) {
                return;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("lock child did not reach its expected checkpoint");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Driven by the tests below in a separate process, with temporary paths only.
    #[test]
    fn lifecycle_lock_child() {
        let Some(root) = std::env::var_os("DNSRIVET_TEST_LOCK_DIR") else {
            return;
        };
        let root = PathBuf::from(root);
        let action = std::env::var("DNSRIVET_TEST_LOCK_ACTION").unwrap();
        let path = root.join(if action == "watchdog" {
            ".lock"
        } else {
            ".lifecycle.lock"
        });
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        if action == "watchdog" {
            // A watchdog must be able to run while restart holds the lifecycle lock.
            file.try_lock().unwrap();
            drop(file);
            let _dns = FsLock::acquire(&path).unwrap();
            append_lock_event(&root, "watchdog:reasserted");
            return;
        }
        assert!(matches!(
            file.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(file);
        std::fs::write(root.join("contended"), b"ready").unwrap();
        let _lifecycle = FsLock::acquire(&path).unwrap();
        // Initial state checks must observe the previous operation's final state,
        // including rollback, not its intermediate DNS/configuration transition.
        assert_eq!(std::fs::read(root.join("state")).unwrap(), b"settled");
        append_lock_event(&root, &format!("{action}:check"));
        append_lock_event(&root, &format!("{action}:restore"));
        append_lock_event(&root, &format!("{action}:bootout"));
        append_lock_event(&root, &format!("{action}:complete"));
    }

    fn simulate_lifecycle(
        fixture: &LockFixture,
        operation: &str,
        rollback: bool,
        contender: &str,
        child: &mut Option<std::process::Child>,
    ) -> Result<(), String> {
        let _lifecycle = FsLock::acquire(&fixture.root.join(".lifecycle.lock"))?;
        append_lock_event(&fixture.root, &format!("{operation}:check"));
        std::fs::write(fixture.root.join("state"), b"transitioning").unwrap();
        append_lock_event(&fixture.root, &format!("{operation}:launch"));
        *child = Some(fixture.spawn(contender));
        wait_for_lock_child(
            child.as_mut().unwrap(),
            Some(&fixture.root.join("contended")),
        );
        {
            let _dns = FsLock::acquire(&fixture.root.join(".lock"))?;
            append_lock_event(&fixture.root, &format!("{operation}:dns"));
        }
        // Waiting for daemon reassertion must not keep the DNS lock held.
        let mut watchdog = fixture.spawn("watchdog");
        wait_for_lock_child(&mut watchdog, None);
        assert_eq!(
            std::fs::read(fixture.root.join("state")).unwrap(),
            b"transitioning"
        );
        if rollback {
            append_lock_event(&fixture.root, &format!("{operation}:rollback"));
            std::fs::write(fixture.root.join("state"), b"settled").unwrap();
            return Err("simulated failure after rollback".into());
        }
        append_lock_event(&fixture.root, &format!("{operation}:complete"));
        std::fs::write(fixture.root.join("state"), b"settled").unwrap();
        Ok(())
    }

    #[test]
    fn lifecycle_file_lock_serializes_operations_through_completion_and_rollback() {
        for (operation, rollback, contender) in [
            ("start", false, "stop"),
            ("restart", false, "uninstall"),
            ("start", true, "stop"),
            ("restart", true, "uninstall"),
        ] {
            let fixture = LockFixture::new();
            let mut child = None;
            let result = simulate_lifecycle(&fixture, operation, rollback, contender, &mut child);
            assert_eq!(result.is_err(), rollback);
            wait_for_lock_child(child.as_mut().unwrap(), None);
            assert_eq!(
                std::fs::read_to_string(fixture.root.join("events")).unwrap(),
                format!(
                    "{operation}:check\n{operation}:launch\n{operation}:dns\nwatchdog:reasserted\n{operation}:{}\n{contender}:check\n{contender}:restore\n{contender}:bootout\n{contender}:complete\n",
                    if rollback { "rollback" } else { "complete" }
                )
            );
            // Reusing the same persistent file must work after both success and error.
            let _next = FsLock::acquire(&fixture.root.join(".lifecycle.lock")).unwrap();
        }
    }

    #[test]
    fn config_restart_rolls_back_when_probe_succeeds_but_takeover_fails() {
        use std::cell::RefCell;
        // Model A -> B: the new listener works, but renamed-service/history
        // guards prevent the watchdog from moving system DNS away from A.
        let installed = RefCell::new(b"A".to_vec());
        let running = RefCell::new(b"A".to_vec());
        let mut loads = 0;
        let error = restart_config_transaction(
            b"A",
            b"B",
            |bytes| {
                *installed.borrow_mut() = bytes.to_vec();
                Ok(())
            },
            || {
                *running.borrow_mut() = installed.borrow().clone();
                loads += 1;
                Ok(())
            },
            || {
                if *running.borrow() == b"B" {
                    Err("system DNS still points at A".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.contains("system DNS still points at A"));
        assert!(error.contains("previous configuration restored and restarted"));
        assert_eq!(*installed.borrow(), b"A");
        assert_eq!(*running.borrow(), b"A");
        assert_eq!(loads, 2);
    }

    #[test]
    fn verified_config_restart_keeps_replacement_and_reports_rollback_failures() {
        use std::cell::RefCell;
        for verify_ok in [true, false] {
            let installed = RefCell::new(Vec::new());
            let mut loads = 0;
            let result = restart_config_transaction(
                b"A",
                b"B",
                |bytes| {
                    *installed.borrow_mut() = bytes.to_vec();
                    Ok(())
                },
                || {
                    loads += 1;
                    if loads == 2 {
                        Err("old listener failed".into())
                    } else {
                        Ok(())
                    }
                },
                || {
                    if verify_ok {
                        Ok(())
                    } else {
                        Err("takeover failed".into())
                    }
                },
            );
            if verify_ok {
                assert!(result.is_ok());
                assert_eq!(*installed.borrow(), b"B");
                assert_eq!(loads, 1);
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .contains("restart failed: old listener failed")
                );
                assert_eq!(*installed.borrow(), b"A");
            }
        }
    }

    #[test]
    fn binary_install_streams_large_files_and_can_replace_its_source() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "dnsrivet-binary-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("installed");
        let mut original = std::fs::File::create(&source).unwrap();
        for byte in 0..128u8 {
            original.write_all(&[byte; 65536]).unwrap();
        }
        drop(original);

        install_binary_at(&source, &destination).unwrap();
        install_binary_at(&destination, &destination).unwrap();
        let mut installed = std::fs::File::open(&destination).unwrap();
        let mut bytes = [0; 65536];
        for byte in 0..128u8 {
            installed.read_exact(&mut bytes).unwrap();
            assert!(bytes.iter().all(|value| *value == byte));
        }
        assert_eq!(installed.read(&mut bytes).unwrap(), 0);
        assert_eq!(
            installed.metadata().unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_start_keeps_plist_when_stopping_fails() {
        let error = cleanup_failed_start(
            "DNS takeover failed: original error",
            || Err("launchctl bootout failed".into()),
            || panic!("must retain the plist while the service may still be running"),
        );
        assert!(error.contains("DNS takeover failed: original error"));
        assert!(error.contains("launchctl bootout failed"));
        assert!(error.contains("service may still be running"));
        assert!(error.contains("plist was retained"));
        assert!(!error.contains("service was stopped"));
    }

    #[test]
    fn failed_start_removes_plist_after_confirming_service_is_stopped() {
        use std::cell::Cell;

        for stopped in [true, false] {
            let stop_finished = Cell::new(false);
            let mut removed = false;
            let error = cleanup_failed_start(
                "DNS probe failed",
                || {
                    stop_finished.set(true);
                    Ok(stopped)
                },
                || {
                    assert!(
                        stop_finished.get(),
                        "stop must finish before removing the plist"
                    );
                    removed = true;
                    Ok(())
                },
            );
            assert!(removed);
            assert!(error.contains("DNS probe failed"));
            assert!(error.contains(if stopped {
                "service was stopped"
            } else {
                "service was not loaded"
            }));
        }
    }

    #[test]
    fn failed_start_reports_plist_removal_failure() {
        let error = cleanup_failed_start(
            "DNS probe failed",
            || Ok(true),
            || Err("permission denied".into()),
        );
        assert!(error.contains("DNS probe failed"));
        assert!(error.contains("service was stopped"));
        assert!(error.contains("could not remove launchd plist: permission denied"));
    }

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

        install_command_at(&command, &binary, &binary).unwrap();
        assert_eq!(std::fs::read_link(&command).unwrap(), binary);
        remove_command_at(&command, &binary).unwrap();
        assert!(!command.exists());

        std::fs::write(&command, b"unrelated").unwrap();
        assert!(install_command_at(&command, &binary, &binary).is_err());
        remove_command_at(&command, &binary).unwrap();
        assert_eq!(std::fs::read(&command).unwrap(), b"unrelated");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn leaves_package_manager_command_link_owned_by_package_manager() {
        let root = std::env::temp_dir().join(format!(
            "dnsrivet-package-manager-command-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let package_binary = root.join("cellar/dnsrivet");
        let installed_binary = root.join("support/dnsrivet");
        let command = root.join("bin/dnsrivet");
        std::fs::create_dir_all(package_binary.parent().unwrap()).unwrap();
        std::fs::create_dir_all(installed_binary.parent().unwrap()).unwrap();
        std::fs::create_dir_all(command.parent().unwrap()).unwrap();
        std::fs::write(&package_binary, b"package binary").unwrap();
        std::fs::write(&installed_binary, b"installed binary").unwrap();
        std::os::unix::fs::symlink(&package_binary, &command).unwrap();

        install_command_at(&command, &installed_binary, &package_binary).unwrap();
        assert_eq!(std::fs::read_link(&command).unwrap(), package_binary);
        remove_command_at(&command, &installed_binary).unwrap();
        assert!(command.is_symlink());

        std::fs::remove_dir_all(root).unwrap();
    }
}
