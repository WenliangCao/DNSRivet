use std::path::PathBuf;
use std::process::ExitCode;

mod cli;
mod config;
mod logger;
mod osdns;
mod proxy;
mod service;
mod upstream;

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
        cli::Command::Run { config, verbose } => run(config, verbose),
        cli::Command::Start { config } => service_result(service::start(config)),
        cli::Command::Stop => service_result(service::stop()),
        cli::Command::Restart => service_result(service::restart()),
        cli::Command::Status => service_result(service::status()),
        cli::Command::Uninstall => service_result(service::uninstall()),
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

fn run(config: Option<PathBuf>, verbose: bool) -> ExitCode {
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let loaded = match config::load(&path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("error: {}: {err}", path.display());
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
        path.display()
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
