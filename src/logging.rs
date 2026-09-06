//! Minimal logging with size-based rotation.
//!
//! The daemon writes its log through a custom [`log::Log`] implementation that
//! owns the log file and rotates it when it grows past a configured size,
//! keeping a bounded number of backups. In the foreground the logger falls
//! back to stderr (the terminal), matching the previous env_logger behaviour.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The global logger that delegates to the installed backend (file or stderr).
static LOGGER: Logger = Logger {
    inner: Mutex::new(None),
};

struct Logger {
    inner: Mutex<Option<Box<dyn log::Log + Send + Sync>>>,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // A poisoned mutex (a thread panicked while holding it) must not
        // take the logging down with it: the inner state is still valid,
        // so the guard is recovered with `into_inner`.
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_none_or(|l| l.enabled(metadata))
    }
    fn log(&self, record: &log::Record) {
        if let Some(l) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            l.log(record);
        } else {
            // No backend installed yet (before config load): write to stderr.
            eprintln!("{}", format_record(record));
        }
    }
    fn flush(&self) {
        if let Some(l) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            l.flush();
        }
    }
}

/// Installs the delegating logger as the process-wide logger (idempotent).
/// The maximum level honours the `RUST_LOG` environment variable (default
/// `info`), matching the previous env_logger behaviour.
pub fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = log::set_logger(&LOGGER);
        let level = std::env::var("RUST_LOG")
            .ok()
            .and_then(|v| v.parse::<log::LevelFilter>().ok())
            .unwrap_or(log::LevelFilter::Info);
        log::set_max_level(level);
    });
}

/// Installs a rotating file backend (used in daemon mode).
pub fn install_file_logger(path: PathBuf, max_size: u64, max_files: u32) -> std::io::Result<()> {
    let logger = FileLogger::open(path, max_size, max_files)?;
    let mut inner = LOGGER.inner.lock().unwrap_or_else(|e| e.into_inner());
    *inner = Some(Box::new(logger));
    Ok(())
}

/// Rotating file backend.
struct FileLogger {
    path: PathBuf,
    max_size: u64,
    max_files: u32,
    inner: Mutex<FileState>,
}

struct FileState {
    file: std::fs::File,
    size: u64,
}

impl FileLogger {
    fn open(path: PathBuf, max_size: u64, max_files: u32) -> std::io::Result<FileLogger> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(FileLogger {
            path,
            max_size,
            max_files: max_files.max(1),
            inner: Mutex::new(FileState { file, size }),
        })
    }

    fn rotate(&self, state: &mut FileState) {
        if self.max_size == 0 || state.size < self.max_size {
            return;
        }
        // Shift the backups up: `.N-1` -> `.N`, `.1` -> `.2`, etc.
        for i in (1..self.max_files).rev() {
            let from = backup_path(&self.path, i);
            let to = backup_path(&self.path, i + 1);
            if from.exists()
                && let Err(e) = std::fs::rename(&from, &to)
            {
                eprintln!("cannot rotate log backup {}: {e}", from.display());
            }
        }
        // The current file becomes `.1` and a fresh one is opened. A failed
        // rename is logged (the old log content between the rotation size
        // and the failure would otherwise be silently lost).
        let first = backup_path(&self.path, 1);
        if let Err(e) = std::fs::rename(&self.path, &first) {
            eprintln!(
                "cannot rotate log {} -> {}: {e}",
                self.path.display(),
                first.display()
            );
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => {
                state.file = file;
                state.size = 0;
            }
            Err(e) => eprintln!("cannot reopen log file: {e}"),
        }
    }
}

fn backup_path(path: &Path, n: u32) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(format!(".{n}"));
    PathBuf::from(os)
}

impl log::Log for FileLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let line = format_record(record);
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let written = state
            .file
            .write_all(line.as_bytes())
            .map(|()| line.len() as u64);
        if let Ok(written) = written {
            state.size += written;
            self.rotate(&mut state);
        }
    }
    fn flush(&self) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let _ = state.file.flush();
    }
}

/// Formats a record like env_logger's default: `[2026-08-19T08:00:00Z LEVEL target] message`.
fn format_record(record: &log::Record) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "[{} {}  {}] {}\n",
        utc_format(now),
        record.level(),
        record.target(),
        record.args()
    )
}

/// Formats a unix timestamp as UTC in ISO 8601 (HH:MM:SS) with a date
/// (YYYY-MM-DD) using the civil-from-days algorithm (Howard Hinnant).
fn utc_format(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert a day count since 1970-01-01 to a civil date (Gregorian).
/// Made `pub(crate)` for the S3 client (SigV4 timestamps).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Log;

    #[test]
    fn poison_then_log_recovers() {
        // A thread panicking while holding the logger's mutex must not
        // take logging down: the guard is recovered with `into_inner`.
        let handle = std::thread::spawn(|| {
            let _g = LOGGER.inner.lock().unwrap();
            panic!("poison");
        });
        handle.join().unwrap_err();
        let record = log::Record::builder()
            .args(format_args!("poison test"))
            .level(log::Level::Info)
            .build();
        LOGGER.log(&record);
        LOGGER.flush();
        assert!(LOGGER.enabled(record.metadata()));
    }

    #[test]
    fn file_logger_recovers_from_poisoned_mutex() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-log-poison-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay.log");
        let logger = std::sync::Arc::new(FileLogger::open(path.clone(), 1 << 20, 4).unwrap());
        let logger_for_thread = std::sync::Arc::clone(&logger);
        let handle = std::thread::spawn(move || {
            let _g = logger_for_thread.inner.lock().unwrap();
            panic!("poison");
        });
        handle.join().unwrap_err();
        let record = log::Record::builder()
            .args(format_args!("after poison"))
            .level(log::Level::Info)
            .build();
        logger.log(&record);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("after poison"),
            "the record must still be written after the poison"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn utc_format_is_stable() {
        assert_eq!(utc_format(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_format(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(
            utc_format(1_700_000_000 + 86_400 * 40),
            "2023-12-24T22:13:20Z"
        );
    }

    #[test]
    fn rotation_keeps_bounded_backups() {
        let dir = std::env::temp_dir().join("nostrfy-log-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrfy.log");
        let _ = FileLogger::open(path.clone(), 8, 3).unwrap(); // rotate at 8 bytes
        log::set_logger(&LOGGER).ok();
        log::set_max_level(log::LevelFilter::Info);
        install_file_logger(path.clone(), 8, 3).unwrap();
        for i in 0..6 {
            log::info!("log line number {i}");
        }
        // The log file itself must not grow unbounded.
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(
            size <= 8,
            "current file should be rotated at 8 bytes, got {size}"
        );
        // Backups exist and are bounded.
        assert!(path.with_file_name("nostrfy.log.1").exists() || backup_path(&path, 1).exists());
        assert!(!backup_path(&path, 4).exists(), "only 3 backups are kept");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
