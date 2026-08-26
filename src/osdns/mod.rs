#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{
    BACKUP_PATH, TakeoverState, TickOutcome, backup_exists, current_loopback_dns,
    fallback_servers, release, take_over, takeover_intact, takeover_state, watchdog_tick,
};

#[cfg(not(target_os = "macos"))]
compile_error!("DNSRivet currently supports macOS only");
