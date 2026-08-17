#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{
    BACKUP_PATH, backup_exists, current_loopback_dns, fallback_servers, restore, take_over,
};

#[cfg(not(target_os = "macos"))]
compile_error!("DNSRivet currently supports macOS only");
