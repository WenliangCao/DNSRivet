use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dnsrivet-pkg-test-{label}-{}-{nonce}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
    let root = TempRoot::new("postinstall-restart");
    let binary = root.0.join("dnsrivet");
    let launchctl = root.0.join("launchctl");
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
        .replace("/usr/local/bin", root.0.join("bin").to_str().unwrap())
        .replace("/bin/launchctl", launchctl.to_str().unwrap());
    let script = root.0.join("postinstall");
    std::fs::write(&script, isolated).unwrap();
    let output = Command::new("/bin/sh")
        .arg(script)
        .args(["DNSRivet.pkg", "/", "/"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("was installed"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("sudo dnsrivet stop"));
    assert_eq!(
        std::fs::read_link(root.0.join("bin/dnsrivet")).unwrap(),
        binary
    );
}

#[test]
fn postinstall_leaves_existing_regular_file_and_dangling_symlink_untouched() {
    for existing_kind in ["regular", "dangling_symlink"] {
        let root = TempRoot::new("postinstall-existing");
        let bin_dir = root.0.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let command_path = bin_dir.join("dnsrivet");
        let managed = root.0.join("managed/dnsrivet");
        let launchctl = root.0.join("launchctl");
        std::fs::write(&launchctl, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&launchctl, std::fs::Permissions::from_mode(0o755)).unwrap();

        if existing_kind == "regular" {
            std::fs::write(&command_path, b"custom").unwrap();
        } else {
            symlink(root.0.join("missing-target"), &command_path).unwrap();
        }

        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/macos/scripts/postinstall"),
        )
        .unwrap();
        let isolated = source
            .replace(
                "/Library/Application Support/DNSRivet/dnsrivet",
                managed.to_str().unwrap(),
            )
            .replace("/usr/local/bin", bin_dir.to_str().unwrap())
            .replace("/bin/launchctl", launchctl.to_str().unwrap());
        let script = root.0.join("postinstall");
        std::fs::write(&script, isolated).unwrap();

        let output = Command::new("/bin/sh")
            .arg(&script)
            .args(["DNSRivet.pkg", "/", "/"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{existing_kind} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        if existing_kind == "regular" {
            assert_eq!(std::fs::read(&command_path).unwrap(), b"custom");
        } else {
            assert_eq!(
                std::fs::read_link(&command_path).unwrap(),
                root.0.join("missing-target")
            );
        }
    }
}

#[test]
fn preinstall_detects_arm_and_intel_homebrew_and_allows_managed_upgrade() {
    let preinstall_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/macos/scripts/preinstall"),
    )
    .unwrap();

    let run_isolated = |setup: &dyn Fn(&Path, &Path, &Path)| {
        let root = TempRoot::new("preinstall");
        let command_path = root.0.join("usr/local/bin/dnsrivet");
        let managed = root.0.join("support/dnsrivet");
        let arm_brew = root.0.join("opt/homebrew/bin/dnsrivet");
        std::fs::create_dir_all(command_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(arm_brew.parent().unwrap()).unwrap();
        setup(&command_path, &managed, &arm_brew);

        let isolated = preinstall_src
            .replace("/usr/local/bin/dnsrivet", command_path.to_str().unwrap())
            .replace(
                "/Library/Application Support/DNSRivet/dnsrivet",
                managed.to_str().unwrap(),
            )
            .replace("/opt/homebrew/bin/dnsrivet", arm_brew.to_str().unwrap());
        let script = root.0.join("preinstall");
        std::fs::write(&script, isolated).unwrap();
        Command::new("/bin/sh")
            .arg(&script)
            .args(["DNSRivet.pkg", "/", "/"])
            .output()
            .unwrap()
    };

    let intel_rel = run_isolated(&|cmd, _, _| {
        symlink("../Cellar/dnsrivet/0.4.2/bin/dnsrivet", cmd).unwrap();
    });
    assert!(!intel_rel.status.success());
    assert!(String::from_utf8_lossy(&intel_rel.stderr).contains("Homebrew"));

    let intel_abs = run_isolated(&|cmd, _, _| {
        symlink("/usr/local/Cellar/dnsrivet/0.4.2/bin/dnsrivet", cmd).unwrap();
    });
    assert!(!intel_abs.status.success());
    assert!(String::from_utf8_lossy(&intel_abs.stderr).contains("Homebrew"));

    let arm = run_isolated(&|_, _, arm_brew| {
        std::fs::write(arm_brew, b"brew").unwrap();
    });
    assert!(!arm.status.success());
    assert!(String::from_utf8_lossy(&arm.stderr).contains("Homebrew"));

    let upgrade = run_isolated(&|cmd, managed, _| {
        symlink(managed, cmd).unwrap();
    });
    assert!(upgrade.status.success());

    let unrelated = run_isolated(&|cmd, _, _| {
        std::fs::write(cmd, b"other").unwrap();
    });
    assert!(!unrelated.status.success());
    assert!(String::from_utf8_lossy(&unrelated.stderr).contains("Refusing to replace"));
}

#[test]
fn shell_scripts_pass_posix_syntax_check() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        "packaging/macos/scripts/preinstall",
        "packaging/macos/scripts/postinstall",
        "scripts/build-release.sh",
        "scripts/notarize-release.sh",
    ] {
        let output = Command::new("/bin/sh")
            .arg("-n")
            .arg(manifest_dir.join(rel))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{rel} syntax error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
