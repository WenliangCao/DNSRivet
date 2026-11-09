use std::path::Path;
use std::process::Command;

#[test]
fn package_scripts_reject_other_volumes_before_touching_the_running_system() {
    // Both scripts must exit at their volume guard; no root privileges or
    // installed paths are involved, and postinstall must never reach launchctl.
    for script in ["preinstall", "postinstall"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("packaging/macos/scripts")
            .join(script);
        for volume in ["/Volumes/Other Mac", "/Volumes/Other Mac/", "/tmp"] {
            let output = Command::new("/bin/sh")
                .arg(&path)
                .args(["DNSRivet.pkg", "/", volume])
                .output()
                .unwrap();
            assert!(!output.status.success(), "{script} accepted {volume}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("current startup volume"),
                "{script}: {output:?}"
            );
            assert!(output.stdout.is_empty());
        }
    }
}

#[test]
fn installed_package_reports_a_failed_restart_without_failing_installation() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("dnsrivet-postinstall-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let binary = root.join("dnsrivet");
    let launchctl = root.join("launchctl");
    for (path, code) in [(&binary, 1), (&launchctl, 0)] {
        std::fs::write(path, format!("#!/bin/sh\nexit {code}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/macos/scripts/postinstall"),
    )
    .unwrap();
    let isolated = source
        .replace(
            "/Library/Application Support/DNSRivet/dnsrivet",
            binary.to_str().unwrap(),
        )
        .replace("/usr/local/bin", root.join("bin").to_str().unwrap())
        .replace("/bin/launchctl", launchctl.to_str().unwrap());
    let script = root.join("postinstall");
    std::fs::write(&script, isolated).unwrap();
    let output = Command::new("/bin/sh")
        .arg(script)
        .args(["DNSRivet.pkg", "/", "/"])
        .output()
        .unwrap();
    std::fs::remove_dir_all(root).unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("was installed"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("sudo dnsrivet stop"));
}
