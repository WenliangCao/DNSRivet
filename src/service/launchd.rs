use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

pub const LABEL: &str = "io.github.wenliangcao.dnsrivet";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/io.github.wenliangcao.dnsrivet.plist";
const LAUNCHCTL: &str = "/bin/launchctl";

pub fn write_plist(binary: &Path, config: &Path) -> Result<(), String> {
    if !binary.is_absolute() || !config.is_absolute() {
        return Err("launchd binary and config paths must be absolute".into());
    }
    let plist = render_plist(binary, config);
    let temporary = Path::new("/Library/LaunchDaemons/.io.github.wenliangcao.dnsrivet.plist.tmp");
    std::fs::write(temporary, plist)
        .map_err(|e| format!("write temporary launchd plist {}: {e}", temporary.display()))?;
    let output = Command::new("/usr/bin/plutil")
        .args(["-lint", "--", temporary.to_str().unwrap()])
        .output()
        .map_err(|e| format!("run plutil: {e}"))?;
    if !output.status.success() {
        let _ = std::fs::remove_file(temporary);
        return Err(format!(
            "invalid generated launchd plist: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("set launchd plist permissions {}: {e}", temporary.display()))?;
    std::fs::rename(temporary, PLIST_PATH)
        .map_err(|e| format!("install launchd plist {PLIST_PATH}: {e}"))
}

pub fn remove_plist() -> Result<(), String> {
    match std::fs::remove_file(PLIST_PATH) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("remove launchd plist {PLIST_PATH}: {err}")),
    }
}

pub fn bootstrap() -> Result<(), String> {
    checked(
        Command::new(LAUNCHCTL)
            .args(["bootstrap", "system", PLIST_PATH])
            .output(),
        "bootstrap launchd service",
    )
}

pub fn set_enabled(enabled: bool) -> Result<(), String> {
    checked(
        Command::new(LAUNCHCTL)
            .args([
                if enabled { "enable" } else { "disable" },
                &format!("system/{LABEL}"),
            ])
            .output(),
        if enabled {
            "enable launchd service"
        } else {
            "disable launchd service"
        },
    )
}

pub fn is_installed() -> bool {
    Path::new(PLIST_PATH).is_file()
}

pub fn bootout() -> Result<bool, String> {
    if !is_loaded() {
        return Ok(false);
    }
    checked(
        Command::new(LAUNCHCTL)
            .args(["bootout", &format!("system/{LABEL}")])
            .output(),
        "stop launchd service",
    )?;
    Ok(true)
}

pub fn restart() -> Result<(), String> {
    checked(
        Command::new(LAUNCHCTL)
            .args(["kickstart", "-k", &format!("system/{LABEL}")])
            .output(),
        "restart launchd service",
    )
}

pub fn is_loaded() -> bool {
    Command::new(LAUNCHCTL)
        .args(["print", &format!("system/{LABEL}")])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn checked(output: std::io::Result<Output>, action: &str) -> Result<(), String> {
    let output = output.map_err(|e| format!("{action}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = if output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout)
    } else {
        String::from_utf8_lossy(&output.stderr)
    };
    Err(format!("{action}: {}", detail.trim()))
}

fn render_plist(binary: &Path, config: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>run</string>
        <string>--config</string>
        <string>{}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Library/Application Support/DNSRivet</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/dnsrivet.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/dnsrivet.log</string>
</dict>
</plist>
"#,
        xml_escape(&binary.display().to_string()),
        xml_escape(&config.display().to_string())
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_escapes_paths_and_contains_required_service_keys() {
        let plist = render_plist(Path::new("/tmp/a&b"), Path::new("/tmp/<config>"));
        assert!(plist.contains("/tmp/a&amp;b"));
        assert!(plist.contains("/tmp/&lt;config&gt;"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains(LABEL));
    }

    #[test]
    fn generated_plist_passes_plutil() {
        let plist = render_plist(Path::new("/tmp/dnsrivet"), Path::new("/tmp/config.toml"));
        let path =
            std::env::temp_dir().join(format!("dnsrivet-plist-{}.plist", std::process::id()));
        std::fs::write(&path, plist).unwrap();
        let output = Command::new("/usr/bin/plutil")
            .args(["-lint", "--", path.to_str().unwrap()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(path);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
