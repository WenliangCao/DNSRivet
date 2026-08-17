use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "\
DNSRivet — lightweight encrypted DNS forwarding daemon for macOS (DoH/DoH3/DoT/DoQ)

USAGE:
    dnsrivet <command> [options]

COMMANDS:
    run          Run the proxy in the foreground
    start        Install + start the launchd service, take over system DNS
    stop         Stop the service and restore system DNS
    restart      Restart the service, optionally installing a new config
    status       Show service and DNS health
    uninstall    Remove the service and restore system DNS
    config init  Write a TOML config from command-line options
    config check Validate a TOML config without starting the proxy
    version      Print version

OPTIONS:
    -c, --config <PATH>       Config file (default: ./dnsrivet.toml, then
                              /Library/Application Support/DNSRivet/config.toml)
    -v, --verbose             Debug logging for foreground mode
    -h, --help                Show this help

QUICK CONFIG OPTIONS (run, start, restart, config init):
        --listen <IP:PORT>    Listener; repeat for multiple listeners
        --upstream <SPEC>     Upstream as TYPE=ENDPOINT; repeat for failover
                              TYPE: doh, doh3, dot, doq, legacy
        --timeout <MS>        Timeout for each quick-config upstream (default: 5000)
        --cache-size <COUNT>  Enable a cache with this capacity (default: 4096)
        --no-cache            Disable the cache

CONFIG INIT OPTIONS:
    -o, --output <PATH>       Destination (default: ./dnsrivet.toml)
        --force               Replace an existing destination";

#[derive(Debug, Default)]
pub struct QuickArgs {
    pub listeners: Vec<String>,
    pub upstreams: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub cache_size: Option<usize>,
    pub no_cache: bool,
}

impl QuickArgs {
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
            && self.upstreams.is_empty()
            && self.timeout_ms.is_none()
            && self.cache_size.is_none()
            && !self.no_cache
    }
}

pub enum Command {
    Run {
        config: Option<PathBuf>,
        verbose: bool,
        quick: QuickArgs,
    },
    Start {
        config: Option<PathBuf>,
        quick: QuickArgs,
    },
    Stop,
    Restart {
        config: Option<PathBuf>,
        quick: QuickArgs,
    },
    Status,
    Uninstall,
    ConfigInit {
        output: PathBuf,
        force: bool,
        quick: QuickArgs,
    },
    ConfigCheck {
        config: Option<PathBuf>,
    },
    Version,
    Help,
}

pub fn parse() -> Result<Command, lexopt::Error> {
    parse_args(std::env::args_os().skip(1))
}

fn parse_args<I>(args: I) -> Result<Command, lexopt::Error>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_args(args);
    let mut positionals = Vec::new();
    let mut config: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut verbose = false;
    let mut force = false;
    let mut quick = QuickArgs::default();

    while let Some(arg) = parser.next()? {
        match arg {
            Value(value) => positionals.push(value.string()?),
            Short('c') | Long("config") => config = Some(PathBuf::from(parser.value()?)),
            Short('o') | Long("output") => output = Some(PathBuf::from(parser.value()?)),
            Short('v') | Long("verbose") => verbose = true,
            Short('h') | Long("help") => return Ok(Command::Help),
            Long("listen") => quick.listeners.push(parser.value()?.string()?),
            Long("upstream") => quick.upstreams.push(parser.value()?.string()?),
            Long("timeout") => {
                quick.timeout_ms = Some(parse_number(parser.value()?.string()?, "timeout")?)
            }
            Long("cache-size") => {
                quick.cache_size = Some(parse_number(parser.value()?.string()?, "cache-size")?)
            }
            Long("no-cache") => quick.no_cache = true,
            Long("force") => force = true,
            _ => return Err(arg.unexpected()),
        }
    }

    let command = positionals.first().map(String::as_str);
    let action = positionals.get(1).map(String::as_str);
    if positionals.len() > 2 {
        return Err(custom("too many command arguments"));
    }

    match (command, action) {
        (None, None) => no_options(config, output, verbose, force, &quick, Command::Help),
        (Some("run"), None) => {
            reject_output_and_force(output, force, "run")?;
            reject_mixed_config(&config, &quick)?;
            require_upstream_if_quick(&quick)?;
            Ok(Command::Run {
                config,
                verbose,
                quick,
            })
        }
        (Some("start"), None) => {
            reject_output_and_force(output, force, "start")?;
            reject_verbose(verbose, "start")?;
            reject_mixed_config(&config, &quick)?;
            require_upstream_if_quick(&quick)?;
            Ok(Command::Start { config, quick })
        }
        (Some("restart"), None) => {
            reject_output_and_force(output, force, "restart")?;
            reject_verbose(verbose, "restart")?;
            reject_mixed_config(&config, &quick)?;
            require_upstream_if_quick(&quick)?;
            Ok(Command::Restart { config, quick })
        }
        (Some("config"), Some("init")) => {
            if config.is_some() || verbose {
                return Err(custom("config init does not accept --config or --verbose"));
            }
            require_upstream_if_quick(&quick)?;
            if quick.is_empty() {
                return Err(custom("config init requires at least one --upstream"));
            }
            Ok(Command::ConfigInit {
                output: output.unwrap_or_else(|| PathBuf::from("dnsrivet.toml")),
                force,
                quick,
            })
        }
        (Some("config"), Some("check")) => {
            reject_output_and_force(output, force, "config check")?;
            reject_verbose(verbose, "config check")?;
            if !quick.is_empty() {
                return Err(custom("config check does not accept quick-config options"));
            }
            Ok(Command::ConfigCheck { config })
        }
        (Some("stop"), None) => no_options(config, output, verbose, force, &quick, Command::Stop),
        (Some("status"), None) => {
            no_options(config, output, verbose, force, &quick, Command::Status)
        }
        (Some("uninstall"), None) => {
            no_options(config, output, verbose, force, &quick, Command::Uninstall)
        }
        (Some("version"), None) => {
            no_options(config, output, verbose, force, &quick, Command::Version)
        }
        (Some("config"), None) => Err(custom("config requires either init or check")),
        (Some(other), None) => Err(custom(&format!("unknown command: {other}"))),
        (Some(command), Some(action)) => {
            Err(custom(&format!("unknown command: {command} {action}")))
        }
        (None, Some(_)) => unreachable!(),
    }
}

fn parse_number<T>(value: String, option: &str) -> Result<T, lexopt::Error>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| custom(&format!("--{option} requires a non-negative integer")))
}

fn require_upstream_if_quick(quick: &QuickArgs) -> Result<(), lexopt::Error> {
    if !quick.is_empty() && quick.upstreams.is_empty() {
        return Err(custom(
            "quick configuration requires at least one --upstream TYPE=ENDPOINT",
        ));
    }
    if quick.no_cache && quick.cache_size.is_some() {
        return Err(custom("--no-cache conflicts with --cache-size"));
    }
    Ok(())
}

fn reject_mixed_config(config: &Option<PathBuf>, quick: &QuickArgs) -> Result<(), lexopt::Error> {
    if config.is_some() && !quick.is_empty() {
        return Err(custom(
            "--config cannot be combined with quick-config options",
        ));
    }
    Ok(())
}

fn reject_output_and_force(
    output: Option<PathBuf>,
    force: bool,
    command: &str,
) -> Result<(), lexopt::Error> {
    if output.is_some() || force {
        return Err(custom(&format!(
            "{command} does not accept --output or --force"
        )));
    }
    Ok(())
}

fn reject_verbose(verbose: bool, command: &str) -> Result<(), lexopt::Error> {
    if verbose {
        return Err(custom(&format!("{command} does not accept --verbose")));
    }
    Ok(())
}

fn no_options(
    config: Option<PathBuf>,
    output: Option<PathBuf>,
    verbose: bool,
    force: bool,
    quick: &QuickArgs,
    command: Command,
) -> Result<Command, lexopt::Error> {
    if config.is_some() || output.is_some() || verbose || force || !quick.is_empty() {
        return Err(custom("this command does not accept options"));
    }
    Ok(command)
}

fn custom(message: &str) -> lexopt::Error {
    lexopt::Error::Custom(message.to_string().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_args_detect_any_override() {
        assert!(QuickArgs::default().is_empty());
        assert!(
            !QuickArgs {
                timeout_ms: Some(5000),
                ..QuickArgs::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn parses_one_line_service_configuration() {
        let command = parse_args([
            "start",
            "--upstream",
            "doh3=https://resolver.example/profile",
            "--timeout=700",
            "--cache-size=256",
        ])
        .unwrap();
        let Command::Start { config, quick } = command else {
            panic!("expected start command");
        };
        assert!(config.is_none());
        assert_eq!(quick.upstreams.len(), 1);
        assert_eq!(quick.timeout_ms, Some(700));
        assert_eq!(quick.cache_size, Some(256));
    }

    #[test]
    fn config_file_and_quick_options_are_mutually_exclusive() {
        let err = parse_args([
            "restart",
            "--config",
            "dnsrivet.toml",
            "--upstream",
            "doh=https://resolver.example/dns-query",
        ])
        .err()
        .unwrap();
        assert!(err.to_string().contains("cannot be combined"));
    }

    #[test]
    fn parses_config_init_destination() {
        let command = parse_args([
            "config",
            "init",
            "--upstream",
            "doq=resolver.example",
            "--output",
            "custom.toml",
        ])
        .unwrap();
        let Command::ConfigInit { output, .. } = command else {
            panic!("expected config init command");
        };
        assert_eq!(output, PathBuf::from("custom.toml"));
    }
}
