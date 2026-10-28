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
