use std::path::PathBuf;

pub const USAGE: &str = "\
DNSRivet — lightweight encrypted DNS forwarding daemon for macOS (DoH/DoH3/DoT/DoQ)

USAGE:
    dnsrivet <command> [options]

COMMANDS:
    run          Run the proxy in the foreground
    start        Install + start the launchd service, take over system DNS
    stop         Stop the service and restore system DNS
    restart      Restart the launchd service
    status       Show service and DNS health
    uninstall    Remove the service and restore system DNS
    version      Print version

OPTIONS:
    -c, --config <PATH>   Config file (default: ./dnsrivet.toml, then
                          /Library/Application Support/DNSRivet/config.toml)
    -v, --verbose         Debug logging (overrides service.log_level)
    -h, --help            Show this help";

pub enum Command {
    Run {
        config: Option<PathBuf>,
        verbose: bool,
    },
    Start {
        config: Option<PathBuf>,
    },
    Stop,
    Restart,
    Status,
    Uninstall,
    Version,
    Help,
}

pub fn parse() -> Result<Command, lexopt::Error> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_env();
    let mut sub: Option<String> = None;
    let mut config: Option<PathBuf> = None;
    let mut verbose = false;

    while let Some(arg) = parser.next()? {
        match arg {
            Value(value) if sub.is_none() => sub = Some(value.string()?),
            Short('c') | Long("config") => config = Some(PathBuf::from(parser.value()?)),
            Short('v') | Long("verbose") => verbose = true,
            Short('h') | Long("help") => return Ok(Command::Help),
            _ => return Err(arg.unexpected()),
        }
    }

    match sub.as_deref() {
        Some("run") => Ok(Command::Run { config, verbose }),
        Some("start") if !verbose => Ok(Command::Start { config }),
        Some("stop") if config.is_none() && !verbose => Ok(Command::Stop),
        Some("restart") if config.is_none() && !verbose => Ok(Command::Restart),
        Some("status") if config.is_none() && !verbose => Ok(Command::Status),
        Some("uninstall") if config.is_none() && !verbose => Ok(Command::Uninstall),
        Some("version") if config.is_none() && !verbose => Ok(Command::Version),
        Some(command)
            if matches!(
                command,
                "start" | "stop" | "restart" | "status" | "uninstall" | "version"
            ) =>
        {
            Err(lexopt::Error::Custom(
                format!("unsupported option for {command}").into(),
            ))
        }
        None => Ok(Command::Help),
        Some(other) => Err(lexopt::Error::Custom(
            format!("unknown command: {other}").into(),
        )),
    }
}
