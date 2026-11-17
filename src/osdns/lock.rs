//! Small cross-process file lock shared by DNS transitions and CLI lifecycle operations.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

// Independent of `.lock`: restart holds this while awaiting daemon reassertion. Never remove.
pub(crate) const LIFECYCLE_LOCK_PATH: &str =
    "/Library/Application Support/DNSRivet/.lifecycle.lock";

/// Dropping the guard closes the file and releases the lock. The lock file
/// must stay in place so concurrent processes always lock the same inode.
pub(crate) struct FsLock {
    _file: File,
}

impl FsLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, String> {
        let file = open_lock_file(path)?;
        file.lock()
            .map_err(|e| format!("lock {}: {e}", path.display()))?;
        Ok(Self { _file: file })
    }

    pub(crate) fn try_acquire(path: &Path) -> Result<Option<Self>, String> {
        let file = open_lock_file(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(err) => Err(format!("try lock {}: {err}", path.display())),
        }
    }
}

fn open_lock_file(path: &Path) -> Result<File, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("lock path {} has no parent", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|err| format!("create lock directory {}: {err}", parent.display()))?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("open lock file {}: {err}", path.display()))
}
