//! Small cross-process file lock shared by DNS transitions and CLI lifecycle operations.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Dropping the guard closes the file and releases the lock. The lock file
/// must stay in place so concurrent processes always lock the same inode.
pub(crate) struct FsLock {
    _file: File,
}

impl FsLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or_else(|| format!("lock path {} has no parent", path.display()))?;
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create lock directory {}: {e}", parent.display()))?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("open lock file {}: {e}", path.display()))?;
        file.lock()
            .map_err(|e| format!("lock {}: {e}", path.display()))?;
        Ok(Self { _file: file })
    }
}
