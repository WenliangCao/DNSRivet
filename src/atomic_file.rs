//! Atomic file replacement in directories controlled by the caller.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Write and validate privately, then publish the complete file in one step.
/// The parent directory must be trusted: this does not defend against a caller
/// that can rename directories or replace entries while the write is in flight.
pub fn write(
    destination: &Path,
    mode: u32,
    contents: impl FnOnce(&mut File, &Path) -> io::Result<()>,
) -> io::Result<()> {
    let mut temporary = TemporaryFile::new(destination)?;
    contents(&mut temporary.file, &temporary.path)?;
    temporary
        .file
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary.file.sync_all()?;
    std::fs::rename(&temporary.path, destination)
}

struct TemporaryFile {
    file: File,
    path: PathBuf,
}

impl TemporaryFile {
    fn new(destination: &Path) -> io::Result<Self> {
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for attempt in 0..16 {
            let path = parent.join(format!(
                ".dnsrivet-{}-{nonce}-{attempt}.tmp",
                std::process::id()
            ));
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok(Self { file, path }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary file",
        ))
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "dnsrivet-atomic-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn assert_no_temporary_files(&self) {
            for entry in std::fs::read_dir(&self.0).unwrap() {
                assert!(
                    !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp")
                );
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn writes_privately_then_installs_with_requested_permissions() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("binary");
        std::fs::write(&destination, b"old").unwrap();
        write(&destination, 0o755, |file, path| {
            assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::read(&destination)?, b"old");
            assert_ne!(path, destination);
            file.write_all(b"new")
        })
        .unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        directory.assert_no_temporary_files();
    }

    #[test]
    fn failed_write_preserves_original_and_removes_temporary_file() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("config");
        std::fs::write(&destination, b"original").unwrap();
        let error = write(&destination, 0o600, |file, _| {
            file.write_all(b"incomplete")?;
            Err(io::Error::other("injected write failure"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "injected write failure");
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        directory.assert_no_temporary_files();
    }

    #[test]
    fn failed_commit_preserves_destination_and_removes_temporary_file() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("config");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("existing"), b"original").unwrap();
        assert!(
            write(&destination, 0o600, |file, _| {
                file.write_all(b"replacement")
            })
            .is_err()
        );
        assert_eq!(
            std::fs::read(destination.join("existing")).unwrap(),
            b"original"
        );
        directory.assert_no_temporary_files();
    }

    #[test]
    fn replacement_does_not_follow_destination_symlinks() {
        let directory = TestDirectory::new();
        let target = directory.0.join("target");
        let destination = directory.0.join("config");
        std::fs::write(&target, b"unrelated").unwrap();
        symlink(&target, &destination).unwrap();
        write(&destination, 0o600, |file, _| {
            file.write_all(b"replacement")
        })
        .unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"replacement");
        assert_eq!(std::fs::read(target).unwrap(), b"unrelated");
        directory.assert_no_temporary_files();
    }

    #[test]
    fn concurrent_writers_publish_complete_independent_files() {
        let directory = TestDirectory::new();
        let destination = directory.0.join("config");
        let barrier = Arc::new(Barrier::new(8));
        std::thread::scope(|scope| {
            for value in 0u8..8 {
                let destination = &destination;
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    write(destination, 0o600, |file, _| {
                        file.write_all(&[value; 8192])?;
                        barrier.wait();
                        file.write_all(&[value; 8192])
                    })
                    .unwrap();
                });
            }
        });
        let bytes = std::fs::read(destination).unwrap();
        assert_eq!(bytes.len(), 16384);
        assert!(bytes[0] < 8);
        assert!(bytes.iter().all(|byte| *byte == bytes[0]));
        directory.assert_no_temporary_files();
    }
}
