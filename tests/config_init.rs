use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dnsrivet-config-init-test-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn init(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_dnsrivet"))
            .args([
                "config",
                "init",
                "--upstream",
                "doh=https://1.1.1.1/dns-query",
            ])
            .args(extra)
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn default_relative_output_is_private_valid_and_requires_force_to_replace() {
    let directory = TestDirectory::new();
    let output = directory.init(&[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "configuration written to dnsrivet.toml\n"
    );
    let path = directory.0.join("dnsrivet.toml");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let check = Command::new(env!("CARGO_BIN_EXE_dnsrivet"))
        .args(["config", "check"])
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(check.status.success(), "{check:?}");

    std::fs::write(&path, b"existing configuration").unwrap();
    let refused = directory.init(&[]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("use --force"));
    assert_eq!(std::fs::read(&path).unwrap(), b"existing configuration");

    let forced = directory.init(&["--force"]);
    assert!(forced.status.success(), "{forced:?}");
    assert_ne!(std::fs::read(&path).unwrap(), b"existing configuration");
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn dangling_output_symlink_is_preserved_without_force() {
    let directory = TestDirectory::new();
    let path = directory.0.join("dnsrivet.toml");
    let target = directory.0.join("missing-config");
    symlink(&target, &path).unwrap();
    let refused = directory.init(&[]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("use --force"));
    assert_eq!(std::fs::read_link(&path).unwrap(), target);
    assert!(!target.exists());

    let forced = directory.init(&["--force"]);
    assert!(forced.status.success(), "{forced:?}");
    assert!(!path.is_symlink());
    assert!(!target.exists());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn config_init_supports_split_dns_and_check_rejects_self_loop() {
    let directory = TestDirectory::new();
    let init = directory.init(&[
        "--split-dns",
        "corp.local=10.0.0.53",
        "--split-dns",
        "home.arpa=system",
        "--split-dns",
        "internal.example=upstream.0",
    ]);
    assert!(init.status.success(), "{init:?}");

    let written = std::fs::read_to_string(directory.0.join("dnsrivet.toml")).unwrap();
    assert!(written.contains("[split_dns]"), "{written}");
    assert!(written.contains("corp.local"), "{written}");

    let check = Command::new(env!("CARGO_BIN_EXE_dnsrivet"))
        .args(["config", "check"])
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(check.status.success(), "{check:?}");

    let bad_path = directory.0.join("bad.toml");
    std::fs::write(
        &bad_path,
        "[listener.0]\nip = \"127.0.0.1\"\nport = 53\n\
         [upstream.0]\nendpoint = \"1.1.1.1\"\n\
         [split_dns]\n\"corp.local\" = \"127.0.0.1:53\"\n",
    )
    .unwrap();
    let bad = Command::new(env!("CARGO_BIN_EXE_dnsrivet"))
        .args(["config", "check", "--config"])
        .arg(&bad_path)
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
