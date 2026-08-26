use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

mod cli;
mod config;
mod logger;
mod osdns;
mod proxy;
mod service;
mod upstream;
mod wire;

fn main() -> ExitCode {
    let cmd = match cli::parse() {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!("{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };

    match cmd {
        cli::Command::Help => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        cli::Command::Version => {
            println!("DNSRivet {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        cli::Command::Run {
            config,
            verbose,
            quick,
        } => run(config, verbose, quick),
        cli::Command::Start { config, quick } => service_result(
            quick_toml(&quick).and_then(|generated| service::start(config, generated)),
        ),
        cli::Command::Stop => service_result(service::stop()),
        cli::Command::Restart { config, quick } => service_result(
            quick_toml(&quick).and_then(|generated| service::restart(config, generated)),
        ),
        cli::Command::Status => service_result(service::status()),
        cli::Command::Uninstall => service_result(service::uninstall()),
        cli::Command::ConfigInit {
            output,
            force,
            quick,
        } => service_result(config_init(output, force, &quick)),
        cli::Command::ConfigCheck { config } => service_result(config_check(config)),
    }
}

fn service_result(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(config: Option<PathBuf>, verbose: bool, quick: cli::QuickArgs) -> ExitCode {
    let (loaded, source) = match quick_toml(&quick) {
        Ok(Some(text)) => match config::load_text(&text) {
            Ok(loaded) => (loaded, "command-line quick configuration".into()),
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        },
        Ok(None) => {
            let path = match resolve_config_path(config) {
                Ok(path) => path,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            match config::load(&path) {
                Ok(loaded) => (loaded, path.display().to_string()),
                Err(err) => {
                    eprintln!("error: {}: {err}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        loaded.config.service.log_level
    };
    if let Err(err) = logger::init(level, loaded.config.service.log_path.as_deref()) {
        eprintln!("error: {err}");
        return ExitCode::FAILURE;
    }

    log::info!(
        "DNSRivet {} starting, config: {}",
        env!("CARGO_PKG_VERSION"),
        source
    );
    for warning in &loaded.warnings {
        log::warn!("{warning}");
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            log::error!("failed to build tokio runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(proxy::serve(loaded.config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn quick_toml(quick: &cli::QuickArgs) -> Result<Option<String>, String> {
    if quick.is_empty() {
        return Ok(None);
    }
    config::quick_toml(
        &quick.listeners,
        &quick.upstreams,
        quick.timeout_ms,
        quick.cache_size,
        quick.no_cache,
    )
    .map(Some)
}

fn config_init(path: PathBuf, force: bool, quick: &cli::QuickArgs) -> Result<String, String> {
    let text = quick_toml(quick)?.expect("config init requires quick options");
    write_local_config(&path, text.as_bytes(), force)?;
    Ok(format!("configuration written to {}", path.display()))
}

fn config_check(explicit: Option<PathBuf>) -> Result<String, String> {
    let path = resolve_config_path(explicit)?;
    let loaded = config::load(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut message = format!(
        "configuration valid: {} ({} listener(s), {} upstream(s))",
        path.display(),
        loaded.config.listeners.len(),
        loaded.config.upstreams.len()
    );
    for warning in loaded.warnings {
        message.push_str("\nwarning: ");
        message.push_str(&warning);
    }
    Ok(message)
}

fn write_local_config(path: &std::path::Path, bytes: &[u8], force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "refusing to replace {}; use --force to overwrite it",
            path.display()
        ));
    }
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    if !parent.is_dir() {
        return Err(format!(
            "config destination directory does not exist: {}",
            parent.display()
        ));
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".dnsrivet-config-{}-{nonce}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| format!("write temporary config {}: {e}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write temporary config {}: {e}", temporary.display()))?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("secure temporary config {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("install config {}: {e}", path.display()))
}

/// --config wins; otherwise try ./dnsrivet.toml (dev convenience), then the
/// system location used by the launchd service.
fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!("config file not found: {}", path.display()));
    }
    let candidates = [
        PathBuf::from("dnsrivet.toml"),
        PathBuf::from("/Library/Application Support/DNSRivet/config.toml"),
    ];
    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    Err(format!(
        "no config file found (tried {}); pass one with --config",
        candidates.map(|p| p.display().to_string()).join(", ")
    ))
}
