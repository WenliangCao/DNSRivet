//! Minimal zero-dependency logger: UTC timestamps to stderr or a file.
//! (tracing/env_logger are deliberately avoided for binary size.)

use log::{LevelFilter, Log, Metadata, Record};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

enum Sink {
    Stderr,
    File(File),
}

struct Logger {
    level: LevelFilter,
    sink: Mutex<Sink>,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:5} {}: {}\n",
            timestamp(),
            record.level(),
            record.target(),
            record.args()
        );
        let mut sink = self.sink.lock().unwrap();
        let _ = match &mut *sink {
            Sink::Stderr => std::io::stderr().write_all(line.as_bytes()),
            Sink::File(f) => f.write_all(line.as_bytes()),
        };
    }

    fn flush(&self) {
        if let Sink::File(f) = &mut *self.sink.lock().unwrap() {
            let _ = f.flush();
        }
    }
}

pub fn init(level: LevelFilter, path: Option<&str>) -> Result<(), String> {
    let sink = match path {
        None => Sink::Stderr,
        Some(p) => Sink::File(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map_err(|e| format!("cannot open log file {p}: {e}"))?,
        ),
    };
    log::set_boxed_logger(Box::new(Logger {
        level,
        sink: Mutex::new(sink),
    }))
    .map_err(|e| e.to_string())?;
    log::set_max_level(level);
    Ok(())
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let (days, tod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
        now.subsec_millis()
    )
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
