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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Logger failures (write, rotate, reopen) since the process start. The
/// logger cannot report through itself; this counter is exported by the
/// stats file and `/metrics` (`nostrfy_log_errors`) so monitoring can alert
/// when the log is no longer being written (e.g. a full disk).
static LOG_ERRORS: AtomicU64 = AtomicU64::new(0);

/// The number of logger failures recorded so far.
pub fn log_errors() -> u64 {
    LOG_ERRORS.load(Ordering::Relaxed)
}

fn bump_log_error() {
    // Saturate instead of wrapping, like the stats counters: a wrapped
    // value would hide that the logger is failing.
    let current = LOG_ERRORS.load(Ordering::Relaxed);
    if current != u64::MAX {
        LOG_ERRORS.store(current.saturating_add(1), Ordering::Relaxed);
    }
}

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
/// `info`), matching the previous env_logger behaviour; see
/// [`parse_max_level`] for the accepted directive forms.
pub fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = log::set_logger(&LOGGER);
        let level = std::env::var("RUST_LOG")
            .ok()
            .map(|v| parse_max_level(&v))
            .unwrap_or(log::LevelFilter::Info);
        log::set_max_level(level);
    });
}

/// The global maximum level for a `RUST_LOG` value. Full env_logger
/// directive semantics are out of scope — the process is a single binary,
/// `nostrfy`, whose records all carry the `nostrfy` or `nostrfy::module`
/// target — so this supports the documented forms: a bare level (`debug`),
/// comma-separated directives (`nostrfy=debug,nostrfy::server=trace`) and
/// a bare crate/module name (env_logger's shorthand for `=trace`). When a
/// specific directive matches the crate, the most specific (longest) target
/// wins over the bare default; a target that does not name this crate is
/// ignored, because it cannot filter `nostrfy` records and treating it as
/// the global level would silently change the relay's log volume. Without
/// any usable directive the default is `info`.
fn parse_max_level(value: &str) -> log::LevelFilter {
    fn matches_crate(target: &str) -> bool {
        target == "nostrfy" || target.starts_with("nostrfy::")
    }
    let mut bare: Option<log::LevelFilter> = None;
    let mut targeted: Option<(usize, log::LevelFilter)> = None;
    for directive in value.split(',') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }
        match directive.split_once('=') {
            None => match directive.parse::<log::LevelFilter>() {
                Ok(level) => bare = Some(level),
                // A bare target (`RUST_LOG=nostrfy`) is env_logger's
                // shorthand for the most verbose level for that target.
                Err(_) if matches_crate(directive) => {
                    targeted = Some((directive.len(), log::LevelFilter::Trace));
                }
                Err(_) => {}
            },
            Some((target, level)) => {
                let target = target.trim();
                if !matches_crate(target) {
                    continue;
                }
                let Ok(level) = level.trim().parse::<log::LevelFilter>() else {
                    continue;
                };
                // Ties go to the later directive (env_logger applies the
                // last matching directive).
                if targeted.is_none_or(|(len, _)| target.len() >= len) {
                    targeted = Some((target.len(), level));
                }
            }
        }
    }
    targeted
        .map(|(_, level)| level)
        .or(bare)
        .unwrap_or(log::LevelFilter::Info)
}

/// Installs a rotating file backend (used in daemon mode).
pub fn install_file_logger(path: PathBuf, max_size: u64, max_files: u32) -> anyhow::Result<()> {
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
    /// Whether the last write failed (reported once per failure streak, so
    /// a full disk cannot flood the log with one line per record).
    write_failed: bool,
    /// Whether the last rotation failed (same one-report-per-streak rule).
    rotate_failed: bool,
}

impl FileLogger {
    fn open(path: PathBuf, max_size: u64, max_files: u32) -> anyhow::Result<FileLogger> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(FileLogger {
            path,
            max_size,
            max_files: max_files.max(1),
            inner: Mutex::new(FileState {
                file,
                size,
                write_failed: false,
                rotate_failed: false,
            }),
        })
    }

    /// Records a logger failure without recursing through the logging
    /// macros: the counter is bumped, the message goes to stderr and a
    /// single marker line is appended directly to the log file (best
    /// effort, so the reason survives when stderr is /dev/null in daemon
    /// mode even though normal records cannot be written).
    fn emergency(&self, message: &str) {
        bump_log_error();
        eprintln!("nostrfy: {message}");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("[{} ERROR nostrfy::logging] {message}\n", utc_format(now));
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    fn rotate(&self, state: &mut FileState) {
        if self.max_size == 0 || state.size < self.max_size {
            return;
        }
        // Shift the backups up: `.N-1` -> `.N`, `.1` -> `.2`, etc. Only the
        // generations that actually exist are touched: the old loop probed
        // every index below `max_log_files`, so a large configured ceiling
        // turned each rotation into thousands of stat/rename calls while
        // holding the logger mutex. Enumerating the directory is O(files).
        let dir = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let mut existing: Vec<u32> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| backup_index(&self.path, &entry.path()))
            .collect();
        existing.sort_unstable();
        // Descending so `.N` is moved before `.N-1` overwrites it. A
        // generation above the current ceiling is left in place (the same
        // as before) until a later shift overwrites it.
        let mut failure: Option<String> = None;
        for i in existing.into_iter().rev() {
            if i >= self.max_files {
                continue;
            }
            let from = backup_path(&self.path, i);
            let to = backup_path(&self.path, i + 1);
            if let Err(e) = std::fs::rename(&from, &to) {
                let message = format!("cannot rotate log backup {}: {e}", from.display());
                failure.get_or_insert(message);
            }
        }
        // The current file becomes `.1` and a fresh one is opened. A failed
        // rename is recorded (the old log content between the rotation size
        // and the failure would otherwise be silently lost).
        let first = backup_path(&self.path, 1);
        let rotated = match std::fs::rename(&self.path, &first) {
            Ok(()) => true,
            Err(e) => {
                failure.get_or_insert_with(|| {
                    format!(
                        "cannot rotate log {} -> {}: {e}",
                        self.path.display(),
                        first.display()
                    )
                });
                false
            }
        };
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => {
                state.file = file;
                // Only a successful rotation may reset the size counter: a
                // failed rename leaves the (still oversized) current file
                // in place, and resetting to 0 would stop rotation attempts
                // while the log grows unbounded.
                if rotated {
                    state.size = 0;
                }
            }
            Err(e) => {
                failure.get_or_insert_with(|| format!("cannot reopen log file: {e}"));
            }
        }
        match failure {
            // One marker line per failure streak: while the file stays
            // oversized, every record retries the rotation and reporting
            // each attempt would flood the log.
            Some(message) => {
                if !state.rotate_failed {
                    state.rotate_failed = true;
                    self.emergency(&message);
                }
            }
            None => state.rotate_failed = false,
        }
    }
}

fn backup_path(path: &Path, n: u32) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(format!(".{n}"));
    PathBuf::from(os)
}

/// The backup generation a directory entry represents for `path`
/// (`nostrfy.log.3` -> `3`), or `None` for any other file.
fn backup_index(path: &Path, candidate: &Path) -> Option<u32> {
    let name = path.file_name()?.to_str()?;
    candidate
        .file_name()?
        .to_str()?
        .strip_prefix(name)?
        .strip_prefix('.')?
        .parse()
        .ok()
}

impl log::Log for FileLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let line = format_record(record);
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match state.file.write_all(line.as_bytes()) {
            Ok(()) => {
                state.write_failed = false;
                state.size += line.len() as u64;
                self.rotate(&mut state);
            }
            Err(e) => {
                // The logger cannot report through itself (that would
                // recurse): a marker goes directly to the log file (best
                // effort) plus stderr, once per failure streak.
                if !state.write_failed {
                    state.write_failed = true;
                    self.emergency(&format!("cannot write the log file: {e}"));
                }
            }
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
    fn emergency_fallback_appends_a_marker_and_counts() {
        // The logger cannot log its own failure. When the normal write path
        // fails the reason must still reach the log file (daemon stderr is
        // /dev/null) and the counter must move so monitoring can alert.
        let dir = std::env::temp_dir().join("nostrfy-log-emergency-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay.log");
        let logger = FileLogger::open(path.clone(), 1 << 20, 4).unwrap();
        let before = log_errors();
        logger.emergency("cannot write the log file: test failure");
        assert!(
            log_errors() > before,
            "a logger failure must move the log_errors counter"
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("cannot write the log file: test failure"),
            "the marker must be appended directly to the log file: {text:?}"
        );
        assert!(
            text.contains("ERROR nostrfy::logging"),
            "the marker must carry level and target: {text:?}"
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

    #[test]
    fn rust_log_parses_bare_levels_and_directives() {
        use log::LevelFilter;
        assert_eq!(parse_max_level("debug"), LevelFilter::Debug);
        assert_eq!(parse_max_level("off"), LevelFilter::Off);
        // The documented directive form: nostrfy=debug.
        assert_eq!(parse_max_level("nostrfy=debug"), LevelFilter::Debug);
        assert_eq!(parse_max_level("nostrfy::server=trace"), LevelFilter::Trace);
        // A bare crate/module name is env_logger's shorthand for trace.
        assert_eq!(parse_max_level("nostrfy"), LevelFilter::Trace);
        // The most specific matching directive wins over the bare default.
        assert_eq!(
            parse_max_level("nostrfy=info,nostrfy::server=trace"),
            LevelFilter::Trace
        );
        assert_eq!(
            parse_max_level("nostrfy::server=trace,nostrfy=info"),
            LevelFilter::Trace
        );
        // Unrelated targets cannot change the relay's level.
        assert_eq!(parse_max_level("hyper=debug"), LevelFilter::Info);
        assert_eq!(parse_max_level("info,hyper=debug"), LevelFilter::Info);
        // Garbage keeps the default.
        assert_eq!(parse_max_level("not-a-level"), LevelFilter::Info);
        assert_eq!(parse_max_level("nostrfy=not-a-level"), LevelFilter::Info);
        // Later directives win on ties.
        assert_eq!(
            parse_max_level("nostrfy=debug,nostrfy=info"),
            LevelFilter::Info
        );
    }

    #[test]
    fn rotation_shifts_only_existing_backups_with_a_large_ceiling() {
        // Regression: the shift loop probed every index below
        // `max_log_files`, so a large configured ceiling made each rotation
        // walk thousands of names under the logger mutex. Existing backups
        // must still shift up across a gap.
        let dir = std::env::temp_dir().join("nostrfy-log-large-ceiling-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrfy.log");
        std::fs::write(&path, "current").unwrap();
        std::fs::write(backup_path(&path, 1), "one").unwrap();
        // A gap at .2 and a high existing generation from an earlier run.
        std::fs::write(backup_path(&path, 3), "three").unwrap();

        let logger = FileLogger::open(path.clone(), 4, 1000).unwrap();
        {
            let mut state = logger.inner.lock().unwrap();
            state.size = 100; // force a rotation on the next record
        }
        let record = log::Record::builder()
            .args(format_args!("rotate now"))
            .level(log::Level::Info)
            .build();
        logger.log(&record);

        assert!(
            backup_path(&path, 1).exists(),
            "the current file becomes .1"
        );
        assert!(backup_path(&path, 2).exists(), ".1 must shift to .2");
        assert!(backup_path(&path, 4).exists(), ".3 must shift to .4");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
