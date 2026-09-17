//! Command-line interface: configuration handling, daemon
//! management and the foreground server entry point.

use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use log::{error, info, warn};

use crate::config::{Config, DEFAULT_CONFIG};
use anyhow::anyhow;

use crate::error::{Result, config_err};
use crate::server::run_server;

#[derive(Debug, Parser)]
#[command(
    name = "nostrfy",
    version,
    about = "A minimal and stable Nostr relay server"
)]
pub struct Cli {
    #[arg(long, default_value = DEFAULT_CONFIG, value_name = "PATH")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
    /// Set when the process is the daemon child (after daemonization).
    #[arg(skip)]
    pub daemonized: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default nostrfy.toml and exit.
    Init,
    /// Generate a relay secret key for NIP-29 and write it into nostrfy.toml
    /// (asks for confirmation when relay.private_key is already set).
    #[command(name = "genkey")]
    GenKey,
    /// Start the relay as a daemon (or in the foreground with --foreground).
    Start {
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the running daemon.
    Stop,
    /// Stop the daemon and start it again (reloads nostrfy.toml).
    Restart,
    /// Show live statistics of the running daemon.
    Stats,
    /// Validate nostrfy.toml and exit.
    Check,
    /// Manage the Blossom upload allowlist (npub1... or hex pubkeys).
    #[command(name = "blossom")]
    Blossom {
        #[command(subcommand)]
        action: BlossomAction,
    },
    /// Manage the relay pubkey allow/deny lists (npub1... or hex pubkeys).
    #[command(name = "relay")]
    Relay {
        #[command(subcommand)]
        action: RelayAction,
    },
    /// Manage the persisted access-control state (blocked-IP recovery).
    #[command(name = "access")]
    Access {
        #[command(subcommand)]
        action: AccessAction,
    },
    /// Update the relay binary to the latest release (or a given version).
    ///
    /// Downloads the GitHub release asset for this platform and atomically
    /// replaces the running binary; the new version applies on the next
    /// start (or after `nostrfy restart` when a daemon is running).
    #[command(name = "upgrade")]
    Upgrade {
        /// Version to install (e.g. "0.1.3"; default: the latest release).
        version: Option<String>,
        /// Reinstall even when the binary is already at the target version.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum BlossomAction {
    /// Allow a pubkey to upload (add to the Blossom upload allowlist) and
    /// reload the daemon.
    Allow { pubkey: String },
    /// Deny a pubkey again (remove from the Blossom upload allowlist).
    Deny { pubkey: String },
    /// Show the current Blossom upload allowlist.
    List,
}

#[derive(Debug, Subcommand)]
pub enum RelayAction {
    /// Allow a pubkey to publish (add to the relay allow list) and reload
    /// the daemon. Takes effect when `restrict_relay = true`.
    Allow { pubkey: String },
    /// Deny a pubkey (add to the deny list): its events are always
    /// rejected, even without `restrict_relay`.
    Deny { pubkey: String },
    /// Show the relay allow/deny lists and `restrict_relay`.
    List,
}

#[derive(Debug, Subcommand)]
pub enum AccessAction {
    /// Remove an IP from the persisted NIP-86 blocked-IP list. Recovery for
    /// an operator whose own address was blocked (the management API is
    /// then unreachable): edits the database directly. A running daemon
    /// must be restarted for the change to apply.
    #[command(name = "unblockip")]
    Unblockip { ip: String },
}

impl Cli {
    /// Runs every synchronous step of the command. For `start`/`restart` in
    /// daemon mode the parent process terminates inside this call and only
    /// the daemon child continues; the caller then starts the async runtime
    /// and calls [`Cli::serve`].
    pub fn prepare(&mut self) -> Result<()> {
        match &self.command {
            Command::Init => return init_config(&self.config),
            Command::GenKey => return self.genkey(),
            Command::Check => {
                let cfg = self.load_config()?;
                cfg.validate()?;
                print_line(&format!("configuration OK: {}", cfg.relay.name));
                return Ok(());
            }
            Command::Stop => return self.stop(),
            Command::Stats => return self.stats(),
            // The foreground start also validates the config and rejects
            // a second instance: two processes on the same LMDB env would
            // fight over the lock.
            Command::Start { foreground: true } => {
                let cfg = self.load_config()?;
                cfg.validate()?;
                if let Some(pid) = running_pid(&cfg.daemon.pid_file) {
                    return Err(config_err(format!(
                        "already running (pid {pid}); use 'nostrfy stop' or 'nostrfy restart'"
                    )));
                }
                return Ok(());
            }
            Command::Blossom { action } => return self.blossom_allowlist(action),
            Command::Relay { action } => return self.relay_access(action),
            Command::Access { action } => {
                return match action {
                    AccessAction::Unblockip { ip } => self.access_unblockip(ip),
                };
            }
            Command::Upgrade { version, force } => return self.upgrade(version.as_deref(), *force),
            _ => {}
        }

        self.config = absolutize(&self.config);
        let cfg = self.load_config()?;
        // Validate before daemonizing AND before stopping a running daemon:
        // a restart whose replacement config has a typo must leave the old
        // instance serving (the command exits non-zero, the relay stays up).
        cfg.validate()?;
        if matches!(self.command, Command::Restart) {
            // The replacement is known-good: now stop the old daemon. `stop`
            // keeps its lenient pid-file lookup, so a config that was broken
            // by the edit is still stoppable through the normal `stop`.
            self.stop()?;
        }
        if let Some(pid) = running_pid(&cfg.daemon.pid_file) {
            return Err(config_err(format!(
                "already running (pid {pid}); use 'nostrfy stop' or 'nostrfy restart'"
            )));
        }
        // Fail before forking when another process already holds the port:
        // the child's bind error only reaches the log (stderr is /dev/null)
        // and the readiness probe below would connect to the foreign
        // listener and report a false success.
        ensure_port_available(&cfg)?;
        self.daemonize(&cfg)?;
        Ok(())
    }

    /// Runs the relay server. Only reached in foreground mode or in the
    /// daemon child process.
    pub async fn serve(&self) -> Result<()> {
        match self.command {
            Command::Start { .. } | Command::Restart => {
                if !self.config.exists() {
                    Config::write_default(&self.config)?;
                    info!("created default configuration at {}", self.config.display());
                }
                let cfg = self.load_config()?;
                cfg.validate()?;
                // Foreground mode (including the recommended systemd unit)
                // writes the pid file too, so the CLI lifecycle commands
                // (`stats`, `stop`, `restart`) can find the instance. The
                // daemon child already owns the file written by `daemonize`;
                // the guard removes the foreground file on exit and refuses
                // to overwrite a live daemon's pid file.
                let _pid_guard = if self.daemonized {
                    None
                } else {
                    Some(PidFileGuard::create(&cfg.daemon.pid_file)?)
                };
                let db = open_db(&cfg)?;
                run_server(self.config.clone(), cfg, db).await
            }
            _ => Ok(()),
        }
    }

    /// Runs [`Cli::serve`] and logs a terminal error through the configured
    /// logger before returning it. After daemonization the process stderr is
    /// /dev/null, so a startup failure (an unopenable database, a bind
    /// error) would otherwise leave no trace anywhere.
    pub async fn serve_logged(&self) -> Result<()> {
        match self.serve().await {
            Ok(()) => Ok(()),
            Err(e) => {
                error!("error: {e}");
                Err(e)
            }
        }
    }

    fn load_config(&self) -> Result<Config> {
        let mut cfg = Config::load(&self.config)?;
        cfg.absolutize_paths(&self.config);
        Ok(cfg)
    }

    fn daemonize(&mut self, cfg: &Config) -> Result<()> {
        // All logging goes through the custom logger to the log file (with
        // rotation); the daemon's stdio is pointed at /dev/null so the
        // inherited descriptors do not keep the file open across rotations.
        if let Some(dir) = cfg.daemon.log_file.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                config_err(format!(
                    "cannot create log directory {}: {e}",
                    dir.display()
                ))
            })?;
        }
        crate::logging::install_file_logger(
            cfg.daemon.log_file.clone(),
            cfg.daemon.max_log_size_bytes,
            cfg.daemon.max_log_files,
        )
        .map_err(|e| {
            config_err(format!(
                "cannot open {}: {e}",
                cfg.daemon.log_file.display()
            ))
        })?;
        let devnull = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|e| config_err(format!("cannot open /dev/null: {e}")))?;

        let daemon = Daemonize::new()
            .pid_file(&cfg.daemon.pid_file)
            .working_directory("/")
            .stdout(devnull.try_clone()?)
            .stderr(devnull);

        match daemon.execute() {
            // Parent: the daemon has forked and the first child exited.
            // Report the pid and terminate, so the foreground `nostrfy
            // start`/`restart` returns with a clear message. The daemon
            // child may die later while binding the port or opening the
            // database (its stderr is /dev/null), so do not report success
            // until the listener actually accepts a connection.
            daemonize::Outcome::Parent(result) => {
                result.map_err(|e| config_err(format!("failed to daemonize: {e}")))?;
                let pid = wait_for_pid_file(&cfg.daemon.pid_file);
                if let Err(e) = wait_for_ready(cfg, pid) {
                    // A dead child must not leave its pid file behind: the
                    // next `start` would refuse to run (and `stop` would
                    // signal a recycled pid) until it is cleaned up. The
                    // reason for the death is in the daemon log.
                    if pid.is_none_or(|pid| !process_alive(pid)) {
                        let _ = std::fs::remove_file(&cfg.daemon.pid_file);
                    }
                    return Err(e);
                }
                match pid {
                    Some(pid) => print_line(&format!("nostrfy started (pid {pid})")),
                    None => print_line("nostrfy started"),
                }
                flush_stdout();
                std::process::exit(0);
            }
            // Only the daemon child reaches this point.
            daemonize::Outcome::Child(result) => {
                result.map_err(|e| config_err(format!("failed to daemonize: {e}")))?;
                self.daemonized = true;
                info!(
                    "daemon started (pid {}), log: {}",
                    std::process::id(),
                    cfg.daemon.log_file.display()
                );
                Ok(())
            }
        }
    }

    fn stop(&self) -> Result<()> {
        // The config may have been broken by the very edit that made a
        // restart necessary: a running daemon must still be stoppable.
        let pid_file = self.stop_pid_file();
        let pid = match running_pid(&pid_file) {
            Some(pid) => pid,
            None => {
                print_line("nostrfy is not running");
                return Ok(());
            }
        };
        print_line(&format!("stopping nostrfy (pid {pid})"));
        let ret = signal_process(pid, libc::SIGTERM);
        if ret != 0 {
            return Err(anyhow!(format!(
                "cannot signal pid {pid}: {}",
                std::io::Error::last_os_error()
            )));
        }
        if !wait_for_stop(&pid_file) {
            return Err(anyhow!(format!("daemon (pid {pid}) did not stop in time")));
        }
        print_line("nostrfy stopped");
        Ok(())
    }

    /// The pid file `stop`/`restart` use. Normally it comes from the parsed
    /// config; when the config cannot be parsed (e.g. it was edited into an
    /// invalid state), fall back to a lenient scan of the raw TOML for just
    /// `daemon.pid_file`, and finally to the compiled-in default. The chosen
    /// source is logged so `stop`/`restart` are never silently pointing at
    /// the wrong process.
    fn stop_pid_file(&self) -> PathBuf {
        match self.load_config() {
            Ok(cfg) => cfg.daemon.pid_file,
            Err(e) => {
                warn!(
                    "cannot load {} ({e}); using a lenient daemon.pid_file lookup",
                    self.config.display()
                );
                if let Some(path) = lenient_pid_file(&self.config) {
                    warn!(
                        "using daemon.pid_file extracted from the raw config: {}",
                        path.display()
                    );
                    path
                } else {
                    let path = resolve_config_path(&self.config, Path::new("./nostrfy.pid"));
                    warn!(
                        "no usable daemon.pid_file in the raw config; using the default {}",
                        path.display()
                    );
                    path
                }
            }
        }
    }

    fn stats(&self) -> Result<()> {
        let cfg = self.load_config()?;
        if !cfg.daemon.stats_file.exists() {
            return Err(config_err("nostrfy is not running (no stats file)"));
        }
        let raw = std::fs::read_to_string(&cfg.daemon.stats_file)?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        // The file is only refreshed while the daemon runs. `written_at`
        // (Unix seconds) is the snapshot's own timestamp; a stats file from
        // before the field existed falls back to the file's modification
        // time, so a fresh snapshot is not rejected just for lacking the
        // marker.
        let written_at = value
            .get("written_at")
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                std::fs::metadata(&cfg.daemon.stats_file)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
            });
        if let Some(reason) = stats_stale_reason(
            &cfg,
            running_pid(&cfg.daemon.pid_file).is_some(),
            written_at,
        ) {
            return Err(config_err(reason));
        }
        print_line(&serde_json::to_string_pretty(&value)?);
        Ok(())
    }

    /// `nostrfy blossom allow/deny/list`: manages the Blossom upload allowlist.
    /// The list lives in the relay database (LMDB) — never the config file —
    /// so it survives restarts and is shared with the running daemon. The
    /// daemon is reloaded via SIGHUP so changes apply without a restart.
    fn blossom_allowlist(&self, action: &BlossomAction) -> Result<()> {
        if !self.config.exists() {
            return Err(config_err(format!(
                "{} not found; run 'nostrfy init' first",
                self.config.display()
            )));
        }
        let cfg = self.load_config()?;
        if let BlossomAction::Allow { pubkey } | BlossomAction::Deny { pubkey } = action
            && !is_pubkey_or_npub(pubkey)
        {
            return Err(config_err(format!(
                "{pubkey:?} is not an npub1... or 64-hex pubkey"
            )));
        }
        let mut entries = load_blossom_allow(&cfg)?;
        match action {
            BlossomAction::Allow { pubkey } => {
                let hex = normalize_pubkey(pubkey);
                if !entries.iter().any(|e| e == &hex) {
                    entries.push(hex.clone());
                    save_blossom_allow(&cfg, &entries)?;
                    print_line(&format!("allowed {hex} to upload (added to the allowlist)"));
                } else {
                    print_line(&format!("{hex} is already allowed"));
                }
            }
            BlossomAction::Deny { pubkey } => {
                let hex = normalize_pubkey(pubkey);
                let before = entries.len();
                entries.retain(|e| e != &hex);
                if entries.len() != before {
                    save_blossom_allow(&cfg, &entries)?;
                    print_line(&format!("denied {hex} (removed from the allowlist)"));
                } else {
                    print_line(&format!("{hex} was not in the allowlist"));
                }
            }
            BlossomAction::List => {
                if entries.is_empty() {
                    print_line("the Blossom upload allowlist is empty");
                } else {
                    for entry in &entries {
                        print_line(entry);
                    }
                }
                print_line(&format!(
                    "restrict_uploads = {}",
                    cfg.blossom.restrict_uploads
                ));
                return Ok(());
            }
        }
        // Reload the running daemon so the new list applies immediately.
        match running_pid(&cfg.daemon.pid_file) {
            Some(pid) => {
                let ret = signal_process(pid, libc::SIGHUP);
                if ret == 0 {
                    print_line(&format!("the running daemon (pid {pid}) was reloaded"));
                } else {
                    print_line(
                        "warning: could not signal the running daemon; run 'nostrfy restart' to apply",
                    );
                }
            }
            None => {
                print_line("no daemon is running; the change applies on the next start");
            }
        }
        Ok(())
    }

    /// `nostrfy relay allow/deny/list`: manages the relay pubkey allow/deny
    /// lists. They live in the relay database (LMDB) — never the config
    /// file — and the daemon is reloaded via SIGHUP so changes apply
    /// immediately.
    fn relay_access(&self, action: &RelayAction) -> Result<()> {
        if !self.config.exists() {
            return Err(config_err(format!(
                "{} not found; run 'nostrfy init' first",
                self.config.display()
            )));
        }
        let cfg = self.load_config()?;
        if let RelayAction::Allow { pubkey } | RelayAction::Deny { pubkey } = action
            && !is_pubkey_or_npub(pubkey)
        {
            return Err(config_err(format!(
                "{pubkey:?} is not an npub1... or 64-hex pubkey"
            )));
        }
        let (mut deny, mut allow) = load_relay_pubkeys(&cfg)?;
        let mut changed = false;
        match action {
            RelayAction::Allow { pubkey } => {
                let hex = normalize_pubkey(pubkey);
                // Removing the pubkey from the deny list is itself a change
                // that must be persisted even when it is already allowed
                // (e.g. after a NIP-86 `banpubkey` put it on both lists).
                let deny_before = deny.len();
                deny.retain(|(p, _)| p != &hex);
                let was_denied = deny.len() != deny_before;
                changed |= was_denied;
                if !allow.iter().any(|(p, _)| p == &hex) {
                    allow.push((hex.clone(), String::new()));
                    changed = true;
                    print_line(&format!("allowed {hex} to publish"));
                } else if was_denied {
                    print_line(&format!(
                        "{hex} is already allowed; removed it from the deny list"
                    ));
                } else {
                    print_line(&format!("{hex} is already allowed"));
                }
            }
            RelayAction::Deny { pubkey } => {
                let hex = normalize_pubkey(pubkey);
                // Symmetric: removing an existing allow entry is a change.
                let allow_before = allow.len();
                allow.retain(|(p, _)| p != &hex);
                let was_allowed = allow.len() != allow_before;
                changed |= was_allowed;
                if !deny.iter().any(|(p, _)| p == &hex) {
                    deny.push((hex.clone(), String::new()));
                    changed = true;
                    print_line(&format!("denied {hex}: its events are now rejected"));
                } else if was_allowed {
                    print_line(&format!(
                        "{hex} is already denied; removed it from the allow list"
                    ));
                } else {
                    print_line(&format!("{hex} is already denied"));
                }
            }
            RelayAction::List => {
                print_line("allow list:");
                if allow.is_empty() {
                    print_line("  (empty)");
                } else {
                    for (p, _) in &allow {
                        print_line(&format!("  {p}"));
                    }
                }
                print_line("deny list:");
                if deny.is_empty() {
                    print_line("  (empty)");
                } else {
                    for (p, _) in &deny {
                        print_line(&format!("  {p}"));
                    }
                }
                print_line(&format!("restrict_relay = {}", cfg.access.restrict_relay));
                return Ok(());
            }
        }
        if changed {
            save_relay_pubkeys(&cfg, &deny, &allow)?;
        }
        // Reload the running daemon so the new lists apply immediately.
        match running_pid(&cfg.daemon.pid_file) {
            Some(pid) => {
                let ret = signal_process(pid, libc::SIGHUP);
                if ret == 0 {
                    print_line(&format!("the running daemon (pid {pid}) was reloaded"));
                } else {
                    print_line(
                        "warning: could not signal the running daemon; run 'nostrfy restart' to apply",
                    );
                }
            }
            None => {
                print_line("no daemon is running; the change applies on the next start");
            }
        }
        Ok(())
    }

    /// `nostrfy access unblockip <ip>`: removes an address from the
    /// persisted NIP-86 blocked-IP list by editing the relay database
    /// directly. This is the recovery path for an operator whose own
    /// address was blocked (`blockip` refuses the management connection
    /// too, so the RPC cannot undo it). The running daemon keeps its
    /// in-memory list: the command tells the operator to restart, which is
    /// the only reload that applies blocked-IP changes.
    fn access_unblockip(&self, ip: &str) -> Result<()> {
        if !self.config.exists() {
            return Err(config_err(format!(
                "{} not found; run 'nostrfy init' first",
                self.config.display()
            )));
        }
        let cfg = self.load_config()?;
        let parsed: std::net::IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| config_err(format!("{ip:?} is not an IP address")))?;
        let parsed = crate::util::normalize_ip(parsed);
        let env = open_db_env(&cfg)?;
        let mut wtxn = env.write_txn()?;
        let access = env
            .create_database::<heed::types::Bytes, heed::types::Bytes>(&mut wtxn, Some("access"))?;
        let Some(raw) = access.get(&wtxn, b"access")? else {
            print_line(&format!(
                "{parsed} is not blocked (no persisted access state)"
            ));
            return Ok(());
        };
        let mut control: crate::config::AccessControl = serde_json::from_slice(raw)?;
        let before = control.blocked_ips.entries().len();
        control.blocked_ips.remove(parsed);
        if control.blocked_ips.entries().len() == before {
            print_line(&format!("{parsed} is not blocked"));
            return Ok(());
        }
        // Disk-full guard like the server write paths (an mmap commit on a
        // full disk risks SIGBUS).
        crate::db::store::check_env_space(&env)?;
        access.put(&mut wtxn, b"access", &serde_json::to_vec(&control)?)?;
        wtxn.commit()?;
        print_line(&format!("unblocked {parsed} in the persisted access state"));
        // The daemon holds the list in memory; blocked-IP changes are
        // applied at startup, not by a config reload.
        match running_pid(&cfg.daemon.pid_file) {
            Some(pid) => print_line(&format!(
                "the running daemon (pid {pid}) must be restarted for the change to apply: \
                 run 'nostrfy restart' (or 'systemctl restart nostrfy')"
            )),
            None => print_line("no daemon is running; the change applies on the next start"),
        }
        Ok(())
    }

    /// `nostrfy upgrade`: replaces the relay binary with a GitHub release
    /// asset (the version given on the command line, or the latest release).
    /// The download is written to a temp file next to the current
    /// executable (created with O_EXCL, so a planted symlink is never
    /// followed), its sha256 is verified against the published checksum,
    /// the binary is proven to run (`--version` probe with a deadline),
    /// and it is atomically renamed over the binary with an fsync of both
    /// the file and the directory — a crash or power loss mid-upgrade
    /// leaves the old binary intact. A running daemon keeps using the old
    /// file (already mapped); the operator is reminded to `restart` to
    /// apply the update.
    fn upgrade(&self, version: Option<&str>, force: bool) -> Result<()> {
        const REPO: &str = "iqbqioza/nostrfy";
        const MAX_ASSET_BYTES: u64 = 256 * 1024 * 1024;

        let current = env!("CARGO_PKG_VERSION");
        let Some(asset) = upgrade_asset_name(std::env::consts::OS, std::env::consts::ARCH) else {
            return Err(config_err(format!(
                "upgrade is not supported on {}-{}; install manually from \
                 https://github.com/{REPO}/releases",
                std::env::consts::OS,
                std::env::consts::ARCH
            )));
        };
        let target = match version {
            Some(v) => v.trim_start_matches('v').to_string(),
            None => latest_release_version(REPO)?,
        };
        let tag = format!("v{target}");
        if target == current {
            if !force {
                print_line(&format!(
                    "nostrfy {current} is already the latest version; use --force to reinstall"
                ));
                flush_stdout();
                return Ok(());
            }
        } else if version.is_none() && !force && version_gt(current, &target) {
            // No explicit version and no --force: never downgrade a newer
            // local build to the latest release (e.g. a dev build newer
            // than the newest published tag). --force bypasses the guard.
            print_line(&format!(
                "the installed binary ({current}) is newer than the latest release ({target}); \
                 nothing to upgrade (use --force to downgrade)"
            ));
            flush_stdout();
            return Ok(());
        }
        if target != current {
            print_line(&format!("upgrading nostrfy {current} -> {target}"));
        } else {
            print_line(&format!("reinstalling nostrfy {target}"));
        }
        let exe = std::env::current_exe()?;
        let dir = exe
            .parent()
            .ok_or_else(|| anyhow!("cannot locate the binary's directory"))?;
        // Best-effort cleanup of temp files left behind by a hard-killed
        // previous upgrade (same pattern, any pid).
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(".nostrfy-upgrade-") && name.ends_with("-tmp") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let tmp = dir.join(format!(".nostrfy-upgrade-{}-tmp", std::process::id()));
        let url = format!("https://github.com/{REPO}/releases/download/{tag}/{asset}");
        print_line(&format!("downloading {url} ..."));
        flush_stdout();
        // Timeouts for every network step: a blackholed connection must not
        // hang the CLI forever (ureq's default agent has no read timeout).
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(120))
            .timeout_write(Duration::from_secs(120))
            .build();
        let result = (|| -> Result<()> {
            let response = agent
                .get(&url)
                .set("User-Agent", "nostrfy-upgrade")
                .call()
                .map_err(|e| anyhow!(format!("download failed: {e}")))?;
            if response.status() != 200 {
                return Err(anyhow!(format!(
                    "download failed: HTTP {}",
                    response.status()
                )));
            }
            let mut reader = response.into_reader();
            // create_new (O_EXCL): never follow a pre-planted symlink or
            // truncate an existing file.
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| anyhow!(format!("cannot create {}: {e}", tmp.display())))?;
            // Stream with a hard byte cap: the trait-object reader cannot
            // be `take()`d, and a huge (or hostile) response must not be
            // buffered or written out unbounded.
            let mut buf = [0u8; 64 * 1024];
            let mut copied: u64 = 0;
            use std::io::{Read, Write};
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                copied += n as u64;
                if copied > MAX_ASSET_BYTES {
                    return Err(anyhow!("the downloaded binary is too large"));
                }
                out.write_all(&buf[..n])?;
            }
            // The release pipeline publishes <asset>.sha256 next to the
            // binary (install.sh verifies it the same way): verify the
            // digest BEFORE executing anything downloaded.
            let checksum = agent
                .get(&format!("{url}.sha256"))
                .set("User-Agent", "nostrfy-upgrade")
                .call()
                .map_err(|e| anyhow!(format!("cannot fetch the checksum: {e}")))?
                .into_string()
                .map_err(|e| anyhow!(format!("invalid checksum response: {e}")))?;
            let expected = checksum
                .split_whitespace()
                .next()
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == 32)
                .ok_or_else(|| anyhow!("the published checksum is not a sha256"))?;
            out.sync_all()?;
            drop(out);
            let actual = {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                let mut f = std::fs::File::open(&tmp)?;
                std::io::copy(&mut f, &mut hasher)?;
                hasher.finalize().to_vec()
            };
            if actual != expected {
                return Err(anyhow!(
                    "sha256 of the downloaded binary does not match the published checksum; \
                     keeping the current binary"
                ));
            }
            // Make it executable and prove it runs before replacing the
            // live binary.
            let mut perms = std::fs::metadata(&tmp)?.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(0o755);
            }
            std::fs::set_permissions(&tmp, perms)?;
            // The probe runs with a hard deadline: a downloaded binary that hangs
            // must not hang the CLI, and the child process is killed on
            // timeout instead of being left orphaned.
            let mut child = std::process::Command::new(&tmp)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| anyhow!(format!("downloaded binary does not run: {e}")))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let probe_ok = loop {
                match child.try_wait()? {
                    Some(status) => break status.success(),
                    None => {
                        if std::time::Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            break false;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            };
            if !probe_ok {
                return Err(anyhow!(
                    "downloaded binary failed or timed out in its version check; \
                     keeping the current binary"
                ));
            };
            std::fs::rename(&tmp, &exe)?;
            // fsync the directory so the rename survives a power loss, not
            // just a process crash.
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result?;
        print_line(&format!("replaced {} with nostrfy {target}", exe.display()));
        // A running daemon has the old binary mapped already: tell the
        // operator to restart to apply the update.
        if self.config.exists()
            && let Ok(cfg) = self.load_config()
            && let Some(pid) = running_pid(&cfg.daemon.pid_file)
        {
            print_line(&format!(
                "a daemon is running (pid {pid}) and still uses the old binary; \
                 run 'nostrfy restart' to apply the update"
            ));
        }
        flush_stdout();
        Ok(())
    }

    /// `nostrfy genkey`: generates a relay secret key (for NIP-29 group
    /// metadata and NIP-43 membership events) and writes it into
    /// `relay.private_key` of the config file, preserving the rest of the
    /// file. When `relay.private_key` is already set, the operator is asked
    /// to confirm the overwrite (y/N).
    fn genkey(&self) -> Result<()> {
        if !self.config.exists() {
            return Err(config_err(format!(
                "{} not found; run 'nostrfy init' first",
                self.config.display()
            )));
        }
        let existing = Config::load(&self.config)?.relay.private_key.clone();
        let key = generate_secret_key_hex()?;

        if !existing.is_empty() {
            let prefix: String = existing.chars().take(8).collect();
            print_line(&format!(
                "relay.private_key is already set ({}...). Overwrite it? [y/N]",
                prefix
            ));
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                print_line("aborted: relay.private_key unchanged");
                return Ok(());
            }
        }

        // Write the key into the config atomically (a crash mid-write must
        // not truncate the file) with the secret never world-readable,
        // then restrict the config itself to 0600 — a shared or loosely
        // defaulted umask must not leave the private key readable by
        // other users on the host.
        let text = std::fs::read_to_string(&self.config)?;
        crate::config::write_text_atomic(&self.config, &set_private_key_in_text(&text, &key))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&self.config, std::fs::Permissions::from_mode(0o600))?;

        // Print the relay's pubkey too: it is safe to share and useful for
        // advertising the relay's `self` identity (NIP-11).
        let pubkey = match secp256k1::SecretKey::from_slice(&hex::decode(&key).unwrap()) {
            Ok(secret) => {
                let secp = secp256k1::Secp256k1::new();
                let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &secret.secret_bytes())
                    .map(|k| secp256k1::XOnlyPublicKey::from_keypair(&k).0.to_string());
                keypair.unwrap_or_default()
            }
            Err(_) => String::new(),
        };
        print_line(&format!(
            "wrote relay.private_key to {}",
            self.config.display()
        ));
        if !pubkey.is_empty() {
            print_line(&format!("relay pubkey (NIP-11 \"self\"): {pubkey}"));
        }
        Ok(())
    }
}

/// The foreground process's pid file: `start --foreground` (including the
/// recommended systemd unit) writes it so `nostrfy stats`/`stop`/`restart`
/// can observe the instance, and removes it when the process exits. A live
/// daemon's pid file is never overwritten.
#[derive(Debug)]
struct PidFileGuard {
    path: PathBuf,
}

impl PidFileGuard {
    fn create(path: &Path) -> Result<Self> {
        if let Some(pid) = running_pid(path) {
            return Err(config_err(format!(
                "already running (pid {pid}); use 'nostrfy stop' or 'nostrfy restart'"
            )));
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| config_err(format!("cannot create {}: {e}", parent.display())))?;
        }
        // A stale pid file (a dead pid) is overwritten; the live-pid check
        // above and this write are not atomic, but the caller has already
        // validated the config and no live instance exists.
        std::fs::write(path, format!("{}\n", std::process::id())).map_err(|e| {
            config_err(format!("cannot write the pid file {}: {e}", path.display()))
        })?;
        Ok(PidFileGuard {
            path: path.to_path_buf(),
        })
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The address used for a pre-flight bind check and the readiness probe: a
/// wildcard bind ("" / "0.0.0.0" / "::") is probed over loopback, which the
/// wildcard listener also accepts.
fn probe_host(host: &str) -> String {
    match host.trim() {
        "" | "0.0.0.0" => "127.0.0.1".to_string(),
        "::" | "[::]" => "::1".to_string(),
        other => other.trim_matches(['[', ']']).to_string(),
    }
}

/// Fails when `server.host:server.port` cannot be bound (another process
/// already holds it). Run before daemonizing: the daemon child's bind
/// failure is only visible in the log, and the readiness probe would
/// connect to the foreign listener and report a false success.
fn ensure_port_available(cfg: &Config) -> Result<()> {
    let host = probe_host(&cfg.server.host);
    let addrs = (host.as_str(), cfg.server.port)
        .to_socket_addrs()
        .map_err(|e| {
            config_err(format!(
                "cannot resolve {}:{}: {e}",
                cfg.server.host, cfg.server.port
            ))
        })?;
    let mut last_error = None;
    let mut resolved = false;
    for addr in addrs {
        resolved = true;
        match std::net::TcpListener::bind(addr) {
            // The port is free: the listener is closed immediately so the
            // daemon child can bind it.
            Ok(listener) => {
                drop(listener);
                return Ok(());
            }
            Err(e) => last_error = Some(e),
        }
    }
    if !resolved {
        return Err(config_err(format!(
            "cannot resolve {}: no address",
            cfg.server.host
        )));
    }
    Err(config_err(format!(
        "cannot bind to {}:{}: {} (is another process already using the port?)",
        cfg.server.host,
        cfg.server.port,
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "bind failed".to_string())
    )))
}

fn open_db(cfg: &Config) -> Result<crate::db::DbClient> {
    let db = crate::db::DbClient::open(
        &cfg.database,
        cfg.nip_enabled(40),
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cfg.database.db_request_timeout_secs,
        cfg.database.max_indexed_words,
        cfg.database.max_db_queue_msgs,
        cfg.database.max_db_queue_events,
    )?;
    // The API reader queue cap is independent from the WebSocket-side caps.
    db.set_max_api_pending(cfg.limits.max_api_queue_msgs);
    Ok(db)
}

/// Prints a line to stdout, ignoring broken-pipe errors (e.g. `nostrfy stats
/// | head`): a closed pipe must not panic the process like `println!` does.
fn print_line(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout(), "{text}");
}

/// Flushes stdout so a completion message survives a `process::exit` (which
/// runs no destructors and would otherwise drop a buffered write).
fn flush_stdout() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Waits up to one second for the daemon's pid file to appear (the daemon
/// writes it just after the first child exits, so the parent can read it a
/// moment early) and returns the pid when the daemon is alive.
fn wait_for_pid_file(path: &Path) -> Option<u32> {
    for _ in 0..100 {
        if let Some(pid) = running_pid(path) {
            return Some(pid);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

/// Waits up to 10 seconds for the freshly daemonized child to accept a TCP
/// connection on the configured `server.host:server.port`. Once the daemon
/// has forked, the parent has no other way to observe startup: the child's
/// stderr points at /dev/null, so a bind/DB failure would otherwise be
/// reported as `nostrfy started`. `server.api_host` needs no separate
/// probe: it splits the same port by Host header, so one listener serves
/// both names.
fn wait_for_ready(cfg: &Config, pid: Option<u32>) -> Result<()> {
    wait_for_ready_within(cfg, pid, Duration::from_secs(10))
}

fn wait_for_ready_within(cfg: &Config, pid: Option<u32>, timeout: Duration) -> Result<()> {
    // A wildcard bind address is not connectable: probe loopback, which the
    // wildcard listener also accepts.
    let host = probe_host(&cfg.server.host);
    let started = Instant::now();
    let deadline = started + timeout;
    loop {
        // A child that already exited can never become ready (and an
        // unwritable pid file must not make us wait for the whole timeout).
        // A pid file that never appears within the grace means the child
        // died before writing it.
        let pid = pid.or_else(|| running_pid(&cfg.daemon.pid_file));
        let grace_elapsed = started.elapsed() >= PID_FILE_GRACE;
        if !child_alive(&cfg.daemon.pid_file, pid, grace_elapsed) {
            return Err(config_err(format!(
                "nostrfy exited before it became ready; see {} for the error",
                cfg.daemon.log_file.display()
            )));
        }
        let addrs: Vec<std::net::SocketAddr> = (host.as_str(), cfg.server.port)
            .to_socket_addrs()
            .map(|addrs| addrs.collect())
            .unwrap_or_default();
        for addr in addrs {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
                // The connect may have reached a *foreign* listener while
                // our child died on the bind (the probe cannot tell whose
                // listener answered): settle briefly and re-check the child
                // before reporting success.
                std::thread::sleep(READY_STABILIZE);
                let pid = pid.or_else(|| running_pid(&cfg.daemon.pid_file));
                if !child_alive(
                    &cfg.daemon.pid_file,
                    pid,
                    started.elapsed() >= PID_FILE_GRACE,
                ) {
                    return Err(config_err(format!(
                        "nostrfy exited during startup (something is listening on {}:{}, but \
                         the child died); see {} for the error",
                        cfg.server.host,
                        cfg.server.port,
                        cfg.daemon.log_file.display()
                    )));
                }
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(config_err(format!(
                "nostrfy did not become ready within {timeout:?}: nothing is listening on \
                 {}:{} (see {} for the daemon's error)",
                cfg.server.host,
                cfg.server.port,
                cfg.daemon.log_file.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Grace for the pid file to appear (and for a connected probe to settle)
/// before a missing pid file or a dying child is reported: the daemonize
/// crate writes the pid file before the child binds, so a file that never
/// appears means the child died on the way.
const PID_FILE_GRACE: Duration = Duration::from_secs(1);
/// After the readiness probe connects, the child is re-checked after this
/// settle window (see `wait_for_ready_within`).
const READY_STABILIZE: Duration = Duration::from_millis(250);

/// Whether the freshly forked child is still alive. `pid` is the pid read
/// from the pid file, or `None` while the file has not appeared yet; a
/// missing file after `pid_grace_elapsed` means the child died before
/// writing it (the daemonize crate neither truncates the file on exit nor
/// removes it).
fn child_alive(pid_file: &Path, pid: Option<u32>, pid_grace_elapsed: bool) -> bool {
    match pid {
        Some(pid) => process_alive(pid),
        None => match pid_file.exists() {
            true => running_pid(pid_file).is_some(),
            false => !pid_grace_elapsed,
        },
    }
}

fn init_config(path: &Path) -> Result<()> {
    Config::write_default(path)?;
    print_line(&format!("wrote {}", path.display()));
    Ok(())
}

/// Parses "X.Y.Z" into numeric parts, for the upgrade version comparison.
fn version_parse(v: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// Whether `a` is strictly newer than `b` (numeric X.Y.Z comparison;
/// unparsable versions compare as equal, so a bad tag never triggers an
/// unwanted downgrade).
fn version_gt(a: &str, b: &str) -> bool {
    let (Some(a), Some(b)) = (version_parse(a), version_parse(b)) else {
        return false;
    };
    a > b
}

/// The GitHub release asset name for a platform, mirroring install.sh
/// (e.g. "nostrfy-linux-x86_64"). `None` when the platform has no
/// prebuilt asset.
fn upgrade_asset_name(os: &str, arch: &str) -> Option<String> {
    let asset = match (os, arch) {
        ("linux", "x86_64") => "nostrfy-linux-x86_64",
        ("linux", "aarch64") => "nostrfy-linux-aarch64",
        ("freebsd", "x86_64") => "nostrfy-freebsd-x86_64",
        _ => return None,
    };
    Some(asset.into())
}

/// The tag of the latest GitHub release (without the leading "v").
fn latest_release_version(repo: &str) -> Result<String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(60))
        .timeout_write(Duration::from_secs(60))
        .build();
    let response = agent
        .get(&url)
        .set("User-Agent", "nostrfy-upgrade")
        .call()
        .map_err(|e| anyhow!(format!("cannot query the latest release: {e}")))?;
    let value: serde_json::Value = serde_json::from_reader(response.into_reader())
        .map_err(|e| anyhow!(format!("invalid release response: {e}")))?;
    value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .map(|t| t.trim_start_matches('v').to_string())
        .ok_or_else(|| anyhow!("the release response has no tag_name"))
}

/// Generates a random secp256k1 secret key as lowercase hex (64 chars),
/// retrying if the random bytes happen to be out of the valid range.
fn generate_secret_key_hex() -> Result<String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| anyhow!(format!("cannot read random bytes: {e}")))?;
        if let Ok(secret) = secp256k1::SecretKey::from_slice(&bytes) {
            return Ok(hex::encode(secret.secret_bytes()));
        }
    }
    Err(anyhow!("failed to generate a valid secret key"))
}

/// Replaces (or inserts) the `relay.private_key` value in a config file's
/// text, preserving every other line, comment and section. Delegates to the
/// shared [`crate::config::set_relay_field_in_text`] helper.
fn set_private_key_in_text(text: &str, key: &str) -> String {
    crate::config::set_relay_field_in_text(text, "private_key", key)
}

/// Resolves a possibly relative path against the current directory so that it
/// stays valid after the daemon changes its working directory.
fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

/// Resolves a path from the config file against the config file's directory,
/// exactly like [`Config::absolutize_paths`] does for the normal loader (the
/// daemon runs with CWD `/`, so a config-relative pid file must not depend on
/// the caller's cwd).
fn resolve_config_path(config_path: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    let base = match config_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            std::fs::canonicalize(parent).unwrap_or_else(|_| PathBuf::from(parent))
        }
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    base.join(path)
}

/// Extracts `daemon.pid_file` from the raw config text without parsing the
/// whole file, so `stop`/`restart` still find the daemon when an unrelated
/// edit left the TOML unparseable. Only a simple `pid_file = "..."` inside
/// the `[daemon]` table is recognized (comments and inline comments are
/// stripped); anything fancier falls back to the default path.
fn lenient_pid_file(config_path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(config_path).ok()?;
    let mut in_daemon = false;
    for line in text.lines() {
        // Strip comments before looking for a section header or assignment
        // (handles `[daemon] # comment` and `pid_file = "x" # comment`).
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_daemon = section.trim() == "daemon";
            continue;
        }
        if !in_daemon {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "pid_file" {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or("");
        if value.is_empty() {
            return None;
        }
        return Some(resolve_config_path(config_path, Path::new(value)));
    }
    None
}

/// `None` when a parsed stats snapshot may be printed as current; otherwise
/// why it must be rejected. The stats file is only refreshed while the daemon
/// runs, so without this check `nostrfy stats` presents the counters of a
/// dead (or hung) daemon as live data.
fn stats_stale_reason(cfg: &Config, running: bool, written_at: Option<u64>) -> Option<String> {
    if !running {
        return Some(format!(
            "the daemon is not running; {} only holds a stale snapshot",
            cfg.daemon.stats_file.display()
        ));
    }
    let Some(written_at) = written_at else {
        return Some(format!(
            "{} has no written_at timestamp and its modification time is unreadable; \
             statistics are stale",
            cfg.daemon.stats_file.display()
        ));
    };
    let age = crate::util::unix_now().saturating_sub(written_at);
    // Three write intervals of slack: one missed write is a hiccup, three in
    // a row mean the writer is gone.
    let max_age = cfg.daemon.stats_interval_secs.saturating_mul(3).max(1);
    if age > max_age {
        return Some(format!(
            "statistics are stale (written {age}s ago, more than {max_age}s = 3 x \
             daemon.stats_interval_secs); is the daemon running?"
        ));
    }
    None
}

fn running_pid(pid_file: &Path) -> Option<u32> {
    let pid = std::fs::read_to_string(pid_file)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    if pid == 0 {
        return None;
    }
    if process_alive(pid) { Some(pid) } else { None }
}

#[cfg(target_os = "linux")]
fn signal_process(pid: u32, signal: libc::c_int) -> libc::c_int {
    // A pidfd remains attached to the process opened here, so PID reuse
    // cannot redirect the signal after the pid-file check.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 {
        return -1;
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        ) as libc::c_int
    };
    unsafe {
        libc::close(pidfd as libc::c_int);
    }
    result
}

#[cfg(not(target_os = "linux"))]
fn signal_process(pid: u32, signal: libc::c_int) -> libc::c_int {
    // pidfd is Linux-specific; retain the existing Unix signal mechanism on
    // platforms without it.
    unsafe { libc::kill(pid as i32, signal) }
}

/// Opens the relay database environment for a short-lived CLI access
/// (read/write of the Blossom allowlist key). The map is opened at the
/// same size ceiling as the daemon, so the existing database is never
/// touched with incompatible settings.
fn open_db_env(cfg: &Config) -> Result<heed::Env> {
    // The server creates the database directory at startup; the CLI
    // commands must be able to run on a fresh install too (e.g. before
    // the first start).
    std::fs::create_dir_all(&cfg.database.path)?;
    let mut map_size = (cfg.database.max_map_size as u64)
        .max(cfg.database.map_size as u64)
        .max(16 * 1024 * 1024);
    if usize::BITS < 64 {
        map_size = map_size.min(2u64 * 1024 * 1024 * 1024);
    }
    // SAFETY: the env is closed when the returned handle drops, before the
    // process exits.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            // Mirror the store's floor: 18 named tables, plus the word
            // index when search is on. A lower value made opening an
            // existing database fail with MDB_DBS_FULL (the CLI commands
            // must open the same tables the server created).
            .max_dbs(cfg.database.max_dbs.max(19))
            .max_readers(cfg.database.max_readers.max(8))
            .map_size(map_size as usize)
            .open(&cfg.database.path)?
    };
    Ok(env)
}

/// Loads the persisted Blossom upload allowlist (hex pubkeys).
fn load_blossom_allow(cfg: &Config) -> Result<Vec<String>> {
    let env = open_db_env(cfg)?;
    // `create_database` opens an existing table or creates a missing one,
    // exactly like the relay server does at startup — old databases that
    // predate the table must keep working.
    let mut wtxn = env.write_txn()?;
    let access =
        env.create_database::<heed::types::Bytes, heed::types::Bytes>(&mut wtxn, Some("access"))?;
    let list = match access.get(&wtxn, b"blossom_allow")? {
        Some(raw) => serde_json::from_slice(raw)?,
        None => Vec::new(),
    };
    wtxn.commit()?;
    Ok(list)
}

/// Persists the Blossom upload allowlist (hex pubkeys).
fn save_blossom_allow(cfg: &Config, entries: &[String]) -> Result<()> {
    let env = open_db_env(cfg)?;
    // Disk-full guard like the server write paths: an mmap commit on a
    // full disk raises SIGBUS instead of failing cleanly.
    crate::db::store::check_env_space(&env)?;
    let mut wtxn = env.write_txn()?;
    let access =
        env.create_database::<heed::types::Bytes, heed::types::Bytes>(&mut wtxn, Some("access"))?;
    access.put(&mut wtxn, b"blossom_allow", &serde_json::to_vec(entries)?)?;
    wtxn.commit()?;
    Ok(())
}

/// Loads the persisted relay pubkey access lists ((deny, allow), each a
/// (pubkey, reason) pair) from the relay database.
fn load_relay_pubkeys(cfg: &Config) -> Result<crate::db::store::RelayPubkeyLists> {
    let env = open_db_env(cfg)?;
    // The table is created in its own transaction, committed before the
    // migration runs (LMDB allows a single writer at a time).
    {
        let mut wtxn = env.write_txn()?;
        env.create_database::<heed::types::Bytes, heed::types::Bytes>(&mut wtxn, Some("access"))?;
        wtxn.commit()?;
    }
    // Same one-time migration the server runs: a CLI write before the
    // first post-upgrade server start must not lose legacy entries.
    let rtxn = env.read_txn()?;
    let access = env
        .open_database::<heed::types::Bytes, heed::types::Bytes>(&rtxn, Some("access"))?
        .ok_or_else(|| anyhow::anyhow!("access table was not created"))?;
    drop(rtxn);
    crate::db::store::migrate_access_pubkeys(&env, &access)?;
    let rtxn = env.read_txn()?;
    let lists = match access.get(&rtxn, b"relay_pubkeys")? {
        Some(raw) => {
            let value: serde_json::Value = serde_json::from_slice(raw)?;
            let deny = serde_json::from_value(value.get("deny").cloned().unwrap_or_default())?;
            let allow = serde_json::from_value(value.get("allow").cloned().unwrap_or_default())?;
            (deny, allow)
        }
        None => (Vec::new(), Vec::new()),
    };
    Ok(lists)
}

/// Persists the relay pubkey access lists ((deny, allow), (pubkey, reason)
/// pairs) in the relay database.
fn save_relay_pubkeys(
    cfg: &Config,
    deny: &[(String, String)],
    allow: &[(String, String)],
) -> Result<()> {
    let env = open_db_env(cfg)?;
    // Same disk-full guard as `save_blossom_allow` above.
    crate::db::store::check_env_space(&env)?;
    let mut wtxn = env.write_txn()?;
    let access =
        env.create_database::<heed::types::Bytes, heed::types::Bytes>(&mut wtxn, Some("access"))?;
    let data = serde_json::to_vec(&serde_json::json!({ "deny": deny, "allow": allow }))?;
    access.put(&mut wtxn, b"relay_pubkeys", &data)?;
    wtxn.commit()?;
    Ok(())
}

/// Normalizes an npub1... or 64-hex pubkey into its lowercase hex form.
fn normalize_pubkey(value: &str) -> String {
    if value.len() == 64 {
        return value.to_ascii_lowercase();
    }
    crate::nips::nip19::parse_nip19(value)
        .ok()
        .and_then(|e| match e {
            crate::nips::nip19::Nip19Entity::Pubkey(pk) => Some(hex::encode(pk)),
            _ => None,
        })
        .unwrap_or_else(|| value.to_ascii_lowercase())
}

/// Whether a string is a 64-hex pubkey or a parseable `npub1...`.
fn is_pubkey_or_npub(value: &str) -> bool {
    crate::config::is_pubkey_or_npub(value)
}

/// Checks whether a process is alive with `kill(pid, 0)`. The process name
/// is cross-checked so that a stale pid file whose pid was reused by an
/// unrelated process is not mistaken for a running relay (which would make
/// `start` refuse and `stop` signal an innocent process).
fn process_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for the existence of the process.
    let alive = {
        let ret = unsafe { libc::kill(pid as i32, 0) };
        ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    };
    if !alive {
        return false;
    }
    // Best-effort name check: a reused pid running a different program is
    // not our daemon.
    match process_name(pid) {
        Some(name) => name == "nostrfy",
        None => true,
    }
}

/// The process name of `pid`: `/proc/<pid>/comm` on Linux, the
/// `kern.proc.pid.<pid>.comm` sysctl on FreeBSD (both are best-effort; a
/// platform without either returns `None` and the pid is trusted).
#[cfg(target_os = "linux")]
fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// FreeBSD: the `sysctl` MIB `kern.proc.pid.<pid>.comm` returns the
/// process name.
#[cfg(target_os = "freebsd")]
fn process_name(pid: u32) -> Option<String> {
    use std::ffi::CString;
    let mib = CString::new(format!("kern.proc.pid.{pid}.comm")).ok()?;
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    // SAFETY: sysctlbyname writes into the provided buffer, which stays
    // alive for the call; the value is read back as bytes afterwards.
    let ret = unsafe {
        libc::sysctlbyname(
            mib.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    std::str::from_utf8(&buf[..len])
        .ok()
        .map(|s| s.trim().to_string())
}

/// Any other platform: no name check, the pid is trusted.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn process_name(_pid: u32) -> Option<String> {
    None
}

/// Waits up to 10 seconds for the daemon to exit (the pid file to disappear).
/// Returns `true` when the daemon stopped, `false` when it is still running.
fn wait_for_stop(pid_file: &Path) -> bool {
    for _ in 0..100 {
        let gone = std::fs::read_to_string(pid_file)
            .ok()
            .and_then(|p| p.trim().parse::<u32>().ok())
            .map(|pid| !process_alive(pid))
            .unwrap_or(true);
        if gone {
            let _ = std::fs::remove_file(pid_file);
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    error!(
        "daemon did not stop in time; pid file {} still exists",
        pid_file.display()
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn upgrade_asset_names_cover_the_release_platforms() {
        assert_eq!(
            upgrade_asset_name("linux", "x86_64").as_deref(),
            Some("nostrfy-linux-x86_64")
        );
        assert_eq!(
            upgrade_asset_name("linux", "aarch64").as_deref(),
            Some("nostrfy-linux-aarch64")
        );
        assert_eq!(
            upgrade_asset_name("freebsd", "x86_64").as_deref(),
            Some("nostrfy-freebsd-x86_64")
        );
        assert!(upgrade_asset_name("windows", "x86_64").is_none());
        assert!(upgrade_asset_name("linux", "riscv64").is_none());
    }

    #[test]
    fn upgrade_version_comparison() {
        assert!(version_gt("0.1.4", "0.1.3"));
        assert!(version_gt("0.2.0", "0.1.99"));
        assert!(version_gt("1.0.0", "0.9.9"));
        assert!(!version_gt("0.1.3", "0.1.3"));
        assert!(!version_gt("0.1.2", "0.1.3"));
        // Unparsable versions never trigger a downgrade.
        assert!(!version_gt("dev", "0.1.3"));
    }

    #[test]
    fn genkey_writes_private_key_with_0600_permissions() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-genkey-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("nostrfy.toml");
        std::fs::write(
            &config_path,
            "[relay]
name = \"nostrfy\"\n",
        )
        .unwrap();
        let mut cli = Cli {
            config: config_path.clone(),
            command: Command::GenKey,
            daemonized: false,
        };
        cli.prepare().unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&config_path).unwrap().permissions(),
        ) & 0o777;
        assert_eq!(
            mode, 0o600,
            "a config with a private key must not be world-readable"
        );
        let text = std::fs::read_to_string(&config_path).unwrap();
        let key_value = text
            .lines()
            .find(|l| l.starts_with("private_key"))
            .map(|l| l.split('"').nth(1).unwrap_or(""))
            .unwrap_or("");
        assert_eq!(key_value.len(), 64, "a 64-hex key must have been written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replaces_existing_private_key_preserving_comments() {
        let text = "# comment\n[relay]\nname = \"nostrfy\"\n# my key\nprivate_key = \"\"\npublic_url = \"wss://x\"\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!("private_key = \"{KEY}\"")));
        assert!(!out.contains("private_key = \"\""));
        // Comments and unrelated lines survive.
        assert!(out.contains("# comment"));
        assert!(out.contains("# my key"));
        assert!(out.contains("name = \"nostrfy\""));
        assert!(out.contains("public_url = \"wss://x\""));
    }

    #[test]
    fn inserts_private_key_after_relay_header() {
        let text = "[relay]\nname = \"nostrfy\"\n\n[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!(
            "[relay]\nprivate_key = \"{KEY}\"\nname = \"nostrfy\""
        )));
        assert!(out.contains("[server]\nport = 8080"));
    }

    #[test]
    fn appends_relay_section_when_missing() {
        let text = "[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.ends_with(&format!("[relay]\nprivate_key = \"{KEY}\"\n")));
        assert!(out.starts_with("[server]\nport = 8080\n"));
    }

    #[test]
    fn relay_header_at_eof_without_newline_stays_valid_toml() {
        // [relay] as the last line with no trailing newline: the key must be
        // inserted on a new line, not glued to the header.
        let text = "[server]\nport = 8080\n[relay]";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!("[relay]\nprivate_key = \"{KEY}\"\n")));
        // The result must parse as valid TOML.
        assert!(toml::from_str::<toml::Value>(&out).is_ok());
    }

    #[test]
    fn relay_in_comment_or_string_is_not_a_header() {
        // A `[relay]` mention inside a comment or a string value must not be
        // treated as the section header.
        let text =
            "# [relay] mentioned in a comment\nname = \"x [relay] y\"\n[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.ends_with(&format!("[relay]\nprivate_key = \"{KEY}\"\n")));
        assert!(out.starts_with("# [relay] mentioned in a comment\n"));
        assert!(toml::from_str::<toml::Value>(&out).is_ok());
    }

    #[test]
    fn relay_header_with_inline_comment_is_recognized() {
        // `[relay]# a trailing comment` is a valid TOML header and must be
        // recognized as the `[relay]` section; before the fix the key was
        // appended as a *second* `[relay]` section, breaking the file with
        // a duplicate key.
        let text = "[relay]# my relay\nname = \"nostrfy\"\n[server]\nport = 8080\n";
        let out = set_private_key_in_text(text, KEY);
        assert!(out.contains(&format!("[relay]# my relay\nprivate_key = \"{KEY}\"")));
        assert!(out.contains("[server]\nport = 8080"));
        assert!(toml::from_str::<toml::Value>(&out).is_ok());
    }

    #[test]
    fn generated_key_is_valid_hex() {
        let key = generate_secret_key_hex().unwrap();
        assert_eq!(key.len(), 64);
        assert!(hex::decode(&key).is_ok());
        assert!(secp256k1::SecretKey::from_slice(&hex::decode(&key).unwrap()).is_ok());
    }

    #[test]
    fn relay_access_persists_removal_from_the_other_list() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-relay-access-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("nostrfy.toml");
        let db_path = dir.join("db");
        std::fs::write(
            &config_path,
            format!("[database]\npath = {:?}\n", db_path.display().to_string()),
        )
        .unwrap();
        let cli = Cli {
            config: config_path,
            command: Command::Check,
            daemonized: false,
        };
        let cfg = cli.load_config().unwrap();
        let hex = "ab".repeat(32);

        // The NIP-86 state: the pubkey is on both lists. `relay allow` must
        // remove the deny entry and persist that removal.
        save_relay_pubkeys(
            &cfg,
            &[(hex.clone(), String::new())],
            &[(hex.clone(), String::new())],
        )
        .unwrap();
        cli.relay_access(&RelayAction::Allow {
            pubkey: hex.clone(),
        })
        .unwrap();
        let (deny, allow) = load_relay_pubkeys(&cfg).unwrap();
        assert!(
            !deny.iter().any(|(p, _)| p == &hex),
            "allow must remove the deny entry"
        );
        assert!(allow.iter().any(|(p, _)| p == &hex));

        // Symmetric: `relay deny` must remove and persist an allow entry.
        save_relay_pubkeys(
            &cfg,
            &[(hex.clone(), String::new())],
            &[(hex.clone(), String::new())],
        )
        .unwrap();
        cli.relay_access(&RelayAction::Deny {
            pubkey: hex.clone(),
        })
        .unwrap();
        let (deny, allow) = load_relay_pubkeys(&cfg).unwrap();
        assert!(
            !allow.iter().any(|(p, _)| p == &hex),
            "deny must remove the allow entry"
        );
        assert!(deny.iter().any(|(p, _)| p == &hex));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lenient_pid_file_survives_a_broken_config() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-lenient-pid-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("nostrfy.toml");

        // Unparseable TOML (unclosed table header) with a valid daemon
        // section: `stop` must still find the pid file.
        std::fs::write(
            &config_path,
            "[server\nport = 8080\n\n[daemon]\npid_file = \"/tmp/nostrfy-lenient.pid\" # c\n",
        )
        .unwrap();
        assert!(Config::load(&config_path).is_err());
        assert_eq!(
            lenient_pid_file(&config_path).as_deref(),
            Some(Path::new("/tmp/nostrfy-lenient.pid"))
        );

        // A pid_file outside [daemon] (e.g. a deprecated spelling) must not
        // be picked up by the lenient scan.
        std::fs::write(&config_path, "[server]\npid_file = \"/tmp/wrong.pid\"\n").unwrap();
        assert!(lenient_pid_file(&config_path).is_none());

        // Relative paths resolve against the config directory, matching the
        // normal loader.
        std::fs::write(&config_path, "[daemon]\npid_file = \"run.pid\"\n").unwrap();
        let pid = lenient_pid_file(&config_path).unwrap();
        assert_eq!(pid.file_name().unwrap(), "run.pid");
        assert_eq!(
            pid.parent().unwrap(),
            std::fs::canonicalize(&dir).unwrap(),
            "relative pid files must be anchored to the config directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stats_staleness_detection() {
        let mut cfg = Config::default();
        cfg.daemon.stats_interval_secs = 5;
        cfg.daemon.stats_file = PathBuf::from("/tmp/nostrfy-stats.json");
        let now = crate::util::unix_now();

        assert!(
            stats_stale_reason(&cfg, true, Some(now)).is_none(),
            "a fresh snapshot of a running daemon is printable"
        );
        assert!(
            stats_stale_reason(&cfg, true, Some(now.saturating_sub(10))).is_none(),
            "one missed write interval is still within the 3x slack"
        );
        let reason = stats_stale_reason(&cfg, true, Some(now.saturating_sub(60))).unwrap();
        assert!(reason.contains("stale"), "{reason}");
        let reason = stats_stale_reason(&cfg, false, Some(now)).unwrap();
        assert!(reason.contains("not running"), "{reason}");
        let reason = stats_stale_reason(&cfg, true, None).unwrap();
        assert!(reason.contains("stale"), "{reason}");
    }

    #[test]
    fn readiness_probe_detects_a_listener_and_its_absence() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut cfg = Config::default();
        cfg.daemon.pid_file =
            std::env::temp_dir().join(format!("nostrfy-ready-{:x}-{id}.pid", std::process::id()));
        let _ = std::fs::remove_file(&cfg.daemon.pid_file);

        // A live listener is detected.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        cfg.server.host = "127.0.0.1".into();
        cfg.server.port = listener.local_addr().unwrap().port();
        wait_for_ready_within(&cfg, None, Duration::from_secs(1)).unwrap();

        // A wildcard bind is probed over loopback.
        let wildcard = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        cfg.server.host = "0.0.0.0".into();
        cfg.server.port = wildcard.local_addr().unwrap().port();
        wait_for_ready_within(&cfg, None, Duration::from_secs(1)).unwrap();
        drop(wildcard);

        // A free (closed) port fails with a clear message.
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let free_port = free.local_addr().unwrap().port();
        drop(free);
        cfg.server.host = "127.0.0.1".into();
        cfg.server.port = free_port;
        let err = wait_for_ready_within(&cfg, None, Duration::from_millis(300)).unwrap_err();
        assert!(err.to_string().contains("did not become ready"), "{err}");
    }

    #[test]
    fn readiness_probe_rejects_a_dead_child_on_an_occupied_port() {
        // The child dies on bind while a foreign process already holds the
        // port: the connect succeeds, but the stale pid file pointing at a
        // dead pid must turn that into a failure (not a false "started").
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = Config::default();
        cfg.server.host = "127.0.0.1".into();
        cfg.server.port = listener.local_addr().unwrap().port();
        cfg.daemon.pid_file = std::env::temp_dir().join(format!(
            "nostrfy-ready-dead-{:x}-{id}.pid",
            std::process::id()
        ));
        std::fs::write(&cfg.daemon.pid_file, "999999999\n").unwrap();

        let err = wait_for_ready_within(&cfg, None, Duration::from_secs(1)).unwrap_err();
        assert!(
            err.to_string().contains("exited before it became ready"),
            "{err}"
        );
        let _ = std::fs::remove_file(&cfg.daemon.pid_file);
    }

    #[test]
    fn child_alive_treats_a_missing_pid_file_after_the_grace_as_death() {
        let path =
            std::env::temp_dir().join(format!("nostrfy-child-alive-{:x}.pid", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(
            child_alive(&path, None, false),
            "while the pid file may still appear the child is starting"
        );
        assert!(
            !child_alive(&path, None, true),
            "a pid file that never appeared within the grace means the child died"
        );
        // A pid file with a dead pid is death even within the grace.
        std::fs::write(&path, "999999999\n").unwrap();
        assert!(!child_alive(&path, None, false));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn readiness_probe_rejects_a_dead_child_behind_a_live_listener() {
        // The stabilization re-check: a live listener answered, but the
        // child is dead, so the probe must fail (not report "started").
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = Config::default();
        cfg.server.host = "127.0.0.1".into();
        cfg.server.port = listener.local_addr().unwrap().port();
        cfg.daemon.pid_file = std::env::temp_dir().join(format!(
            "nostrfy-ready-dead-explicit-{:x}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&cfg.daemon.pid_file);
        let err =
            wait_for_ready_within(&cfg, Some(999_999_999), Duration::from_secs(1)).unwrap_err();
        assert!(
            err.to_string().contains("exited before it became ready"),
            "{err}"
        );
    }

    #[test]
    fn ensure_port_available_rejects_an_occupied_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = Config::default();
        cfg.server.host = "127.0.0.1".into();
        cfg.server.port = listener.local_addr().unwrap().port();
        let err = ensure_port_available(&cfg).unwrap_err();
        assert!(err.to_string().contains("cannot bind"), "{err}");
        drop(listener);
        // Once the listener is closed the port is free again.
        assert!(
            ensure_port_available(&cfg).is_ok(),
            "a released port must pass the pre-flight check"
        );
    }

    #[test]
    fn prepare_rejects_an_occupied_port_without_daemonizing() {
        // Regression: `nostrfy start` used to fork first and rely on the
        // readiness probe, which connected to the foreign listener holding
        // the port and reported a false success while our child died.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-occupied-port-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config_path = dir.join("nostrfy.toml");
        std::fs::write(
            &config_path,
            format!(
                "[server]\nhost = \"127.0.0.1\"\nport = {}\n",
                listener.local_addr().unwrap().port()
            ),
        )
        .unwrap();
        let mut cli = Cli {
            config: config_path,
            command: Command::Start { foreground: false },
            daemonized: false,
        };
        let err = cli.prepare().unwrap_err();
        assert!(err.to_string().contains("cannot bind"), "{err}");
        assert!(!cli.daemonized, "the parent must not have forked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_file_guard_writes_removes_and_protects_a_live_daemon() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-pid-guard-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("nostrfy.pid");
        {
            let _guard = PidFileGuard::create(&pid_file).unwrap();
            assert_eq!(
                std::fs::read_to_string(&pid_file).unwrap().trim(),
                std::process::id().to_string(),
                "foreground mode must write its own pid"
            );
        }
        assert!(
            !pid_file.exists(),
            "the guard must remove the pid file when the process exits"
        );

        // A live daemon's pid file must never be overwritten. The fake
        // process carries the expected `nostrfy` comm name.
        let Some(mut daemon) = spawn_fake_nostrfy(&dir) else {
            return;
        };
        std::fs::write(&pid_file, format!("{}\n", daemon.id())).unwrap();
        let err = PidFileGuard::create(&pid_file).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");
        let _ = daemon.kill();
        let _ = daemon.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_validates_before_stopping_a_running_daemon() {
        // Regression: `restart` used to stop the daemon first and then fail
        // on a TOML typo, leaving the relay down. With a live daemon and an
        // invalid replacement config, prepare must fail without signalling
        // the daemon.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-restart-validate-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let Some(mut daemon) = spawn_fake_nostrfy(&dir) else {
            return;
        };
        let pid_file = dir.join("nostrfy.pid");
        std::fs::write(&pid_file, format!("{}\n", daemon.id())).unwrap();
        assert!(
            running_pid(&pid_file).is_some(),
            "the fake daemon must be detectable"
        );
        let config_path = dir.join("nostrfy.toml");
        std::fs::write(
            &config_path,
            format!(
                "[daemon]\npid_file = {:?}\n[limits]\nmax_connections = 0\n",
                pid_file.display().to_string()
            ),
        )
        .unwrap();
        let mut cli = Cli {
            config: config_path,
            command: Command::Restart,
            daemonized: false,
        };
        let err = cli.prepare().unwrap_err();
        assert!(err.to_string().contains("max_connections"), "{err}");
        assert!(
            running_pid(&pid_file).is_some(),
            "the old daemon must keep running when the new config is invalid"
        );
        let _ = daemon.kill();
        let _ = daemon.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_unblockip_removes_the_persisted_entry() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-access-unblockip-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("nostrfy.toml");
        let db_path = dir.join("db");
        std::fs::write(
            &config_path,
            format!("[database]\npath = {:?}\n", db_path.display().to_string()),
        )
        .unwrap();
        let cli = Cli {
            config: config_path,
            command: Command::Check,
            daemonized: false,
        };
        let cfg = cli.load_config().unwrap();
        // Seed the persisted blob with a blocked IP (the state a NIP-86
        // blockip leaves behind).
        {
            let env = open_db_env(&cfg).unwrap();
            let mut wtxn = env.write_txn().unwrap();
            let access = env
                .create_database::<heed::types::Bytes, heed::types::Bytes>(
                    &mut wtxn,
                    Some("access"),
                )
                .unwrap();
            let mut control = crate::config::AccessControl::default();
            control
                .blocked_ips
                .push("203.0.113.9".into(), "self-lockout".into());
            access
                .put(&mut wtxn, b"access", &serde_json::to_vec(&control).unwrap())
                .unwrap();
            wtxn.commit().unwrap();
        }
        // The v4-mapped spelling must remove the same address.
        cli.access_unblockip("::ffff:203.0.113.9").unwrap();
        let env = open_db_env(&cfg).unwrap();
        let rtxn = env.read_txn().unwrap();
        let access = env
            .open_database::<heed::types::Bytes, heed::types::Bytes>(&rtxn, Some("access"))
            .unwrap()
            .unwrap();
        let raw = access.get(&rtxn, b"access").unwrap().unwrap();
        let control: crate::config::AccessControl = serde_json::from_slice(raw).unwrap();
        assert!(
            control.blocked_ips.entries().is_empty(),
            "the entry must be removed from the persisted state"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serve_logged_records_an_unopenable_database_reason() {
        // After daemonization the process stderr is /dev/null: a database
        // that cannot be opened must leave its reason in the log file.
        crate::logging::init();
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-serve-logged-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // `database.path` points at a regular file: opening the LMDB
        // environment must fail.
        let db_file = dir.join("not-a-directory");
        std::fs::write(&db_file, b"x").unwrap();
        let config_path = dir.join("nostrfy.toml");
        std::fs::write(
            &config_path,
            format!("[database]\npath = {:?}\n", db_file.display().to_string()),
        )
        .unwrap();
        let log_path = dir.join("nostrfy.log");
        crate::logging::install_file_logger(log_path.clone(), 1 << 20, 4).unwrap();
        let cli = Cli {
            config: config_path,
            command: Command::Start { foreground: true },
            daemonized: false,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(cli.serve_logged()).unwrap_err();
        let pid_file = cli.load_config().unwrap().daemon.pid_file;
        assert!(
            !pid_file.exists(),
            "the foreground pid file must be removed on a startup failure"
        );
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            log.contains(&err.to_string()),
            "the startup error must reach the log file: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in for a running daemon: a copy of `sleep` whose comm name is
    /// `nostrfy`, so `process_alive`'s name check accepts it. `None` when no
    /// usable `sleep` binary exists.
    #[cfg(target_os = "linux")]
    fn spawn_fake_nostrfy(dir: &Path) -> Option<std::process::Child> {
        let source = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|path| Path::new(path).exists())?;
        let fake = dir.join("nostrfy");
        std::fs::copy(source, &fake).ok()?;
        let child = std::process::Command::new(&fake).arg("60").spawn().ok()?;
        // The comm name is set at exec; wait until it is visible so
        // `running_pid` does not race the spawn.
        for _ in 0..100 {
            if process_name(child.id()).as_deref() == Some("nostrfy") {
                return Some(child);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    /// Non-Linux: no cheap comm-name stand-in, the tests skip.
    #[cfg(not(target_os = "linux"))]
    fn spawn_fake_nostrfy(_dir: &Path) -> Option<std::process::Child> {
        None
    }
}
