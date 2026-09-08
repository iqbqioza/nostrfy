//! Command-line interface: configuration handling, daemon
//! management and the foreground server entry point.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use log::{error, info};

use crate::config::{Config, DEFAULT_CONFIG};
use crate::error::{Error, Result};
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
                    return Err(Error::Config(format!(
                        "already running (pid {pid}); use 'nostrfy stop' or 'nostrfy restart'"
                    )));
                }
                return Ok(());
            }
            Command::Blossom { action } => return self.blossom_allowlist(action),
            Command::Relay { action } => return self.relay_access(action),
            Command::Upgrade { version, force } => return self.upgrade(version.as_deref(), *force),
            _ => {}
        }

        if matches!(self.command, Command::Restart) {
            let _ = self.stop();
        }

        self.config = absolutize(&self.config);
        let cfg = self.load_config()?;
        // Validate before daemonizing: an invalid config must fail loudly in
        // the foreground (the parent), not silently in the daemon child
        // whose stderr is already pointed at /dev/null.
        cfg.validate()?;
        if let Some(pid) = running_pid(&cfg.daemon.pid_file) {
            return Err(Error::Config(format!(
                "already running (pid {pid}); use 'nostrfy stop' or 'nostrfy restart'"
            )));
        }
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
                let db = open_db(&cfg)?;
                run_server(self.config.clone(), cfg, db).await
            }
            _ => Ok(()),
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
                Error::Config(format!(
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
            Error::Config(format!(
                "cannot open {}: {e}",
                cfg.daemon.log_file.display()
            ))
        })?;
        let devnull = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|e| Error::Config(format!("cannot open /dev/null: {e}")))?;

        let daemon = Daemonize::new()
            .pid_file(&cfg.daemon.pid_file)
            .working_directory("/")
            .stdout(devnull.try_clone()?)
            .stderr(devnull);

        match daemon.execute() {
            // Parent: the daemon has forked and the first child exited.
            // Report the pid (read from the pid file, which the daemon
            // writes just after the first child exits) and terminate, so the
            // foreground `nostrfy start`/`restart` returns with a clear
            // message instead of silently.
            daemonize::Outcome::Parent(result) => {
                result.map_err(|e| Error::Config(format!("failed to daemonize: {e}")))?;
                match wait_for_pid_file(&cfg.daemon.pid_file) {
                    Some(pid) => print_line(&format!("nostrfy started (pid {pid})")),
                    None => print_line("nostrfy started"),
                }
                flush_stdout();
                std::process::exit(0);
            }
            // Only the daemon child reaches this point.
            daemonize::Outcome::Child(result) => {
                result.map_err(|e| Error::Config(format!("failed to daemonize: {e}")))?;
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
        let pid = match running_pid(&self.load_config()?.daemon.pid_file) {
            Some(pid) => pid,
            None => {
                print_line("nostrfy is not running");
                return Ok(());
            }
        };
        print_line(&format!("stopping nostrfy (pid {pid})"));
        // SAFETY: `kill` only touches the targeted process id.
        let ret = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        if ret != 0 {
            return Err(Error::Other(format!(
                "cannot signal pid {pid}: {}",
                std::io::Error::last_os_error()
            )));
        }
        if !wait_for_stop(&self.load_config()?.daemon.pid_file) {
            return Err(Error::Other(format!(
                "daemon (pid {pid}) did not stop in time"
            )));
        }
        print_line("nostrfy stopped");
        Ok(())
    }

    fn stats(&self) -> Result<()> {
        let cfg = self.load_config()?;
        if !cfg.daemon.stats_file.exists() {
            return Err(Error::Config(
                "nostrfy is not running (no stats file)".into(),
            ));
        }
        let raw = std::fs::read_to_string(&cfg.daemon.stats_file)?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        print_line(&serde_json::to_string_pretty(&value)?);
        Ok(())
    }

    /// `nostrfy blossom allow/deny/list`: manages the Blossom upload allowlist.
    /// The list lives in the relay database (LMDB) — never the config file —
    /// so it survives restarts and is shared with the running daemon. The
    /// daemon is reloaded via SIGHUP so changes apply without a restart.
    fn blossom_allowlist(&self, action: &BlossomAction) -> Result<()> {
        if !self.config.exists() {
            return Err(Error::Config(format!(
                "{} not found; run 'nostrfy init' first",
                self.config.display()
            )));
        }
        let cfg = self.load_config()?;
        if let BlossomAction::Allow { pubkey } | BlossomAction::Deny { pubkey } = action
            && !is_pubkey_or_npub(pubkey)
        {
            return Err(Error::Config(format!(
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
                let ret = unsafe { libc::kill(pid as i32, libc::SIGHUP) };
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
            return Err(Error::Config(format!(
                "{} not found; run 'nostrfy init' first",
                self.config.display()
            )));
        }
        let cfg = self.load_config()?;
        if let RelayAction::Allow { pubkey } | RelayAction::Deny { pubkey } = action
            && !is_pubkey_or_npub(pubkey)
        {
            return Err(Error::Config(format!(
                "{pubkey:?} is not an npub1... or 64-hex pubkey"
            )));
        }
        let (mut deny, mut allow) = load_relay_pubkeys(&cfg)?;
        let mut changed = false;
        match action {
            RelayAction::Allow { pubkey } => {
                let hex = normalize_pubkey(pubkey);
                deny.retain(|(p, _)| p != &hex);
                if !allow.iter().any(|(p, _)| p == &hex) {
                    allow.push((hex.clone(), String::new()));
                    changed = true;
                    print_line(&format!("allowed {hex} to publish"));
                } else {
                    print_line(&format!("{hex} is already allowed"));
                }
            }
            RelayAction::Deny { pubkey } => {
                let hex = normalize_pubkey(pubkey);
                allow.retain(|(p, _)| p != &hex);
                if !deny.iter().any(|(p, _)| p == &hex) {
                    deny.push((hex.clone(), String::new()));
                    changed = true;
                    print_line(&format!("denied {hex}: its events are now rejected"));
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
                let ret = unsafe { libc::kill(pid as i32, libc::SIGHUP) };
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
            return Err(Error::Config(format!(
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
        let exe = std::env::current_exe().map_err(Error::Io)?;
        let dir = exe
            .parent()
            .ok_or_else(|| Error::Other("cannot locate the binary's directory".into()))?;
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
                .map_err(|e| Error::Other(format!("download failed: {e}")))?;
            if response.status() != 200 {
                return Err(Error::Other(format!(
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
                .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp.display())))?;
            // Stream with a hard byte cap: the trait-object reader cannot
            // be `take()`d, and a huge (or hostile) response must not be
            // buffered or written out unbounded.
            let mut buf = [0u8; 64 * 1024];
            let mut copied: u64 = 0;
            use std::io::{Read, Write};
            loop {
                let n = reader.read(&mut buf).map_err(Error::Io)?;
                if n == 0 {
                    break;
                }
                copied += n as u64;
                if copied > MAX_ASSET_BYTES {
                    return Err(Error::Other("the downloaded binary is too large".into()));
                }
                out.write_all(&buf[..n]).map_err(Error::Io)?;
            }
            // The release pipeline publishes <asset>.sha256 next to the
            // binary (install.sh verifies it the same way): verify the
            // digest BEFORE executing anything downloaded.
            let checksum = agent
                .get(&format!("{url}.sha256"))
                .set("User-Agent", "nostrfy-upgrade")
                .call()
                .map_err(|e| Error::Other(format!("cannot fetch the checksum: {e}")))?
                .into_string()
                .map_err(|e| Error::Other(format!("invalid checksum response: {e}")))?;
            let expected = checksum
                .split_whitespace()
                .next()
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == 32)
                .ok_or_else(|| Error::Other("the published checksum is not a sha256".into()))?;
            out.sync_all().map_err(Error::Io)?;
            drop(out);
            let actual = {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                let mut f = std::fs::File::open(&tmp).map_err(Error::Io)?;
                std::io::copy(&mut f, &mut hasher).map_err(Error::Io)?;
                hasher.finalize().to_vec()
            };
            if actual != expected {
                return Err(Error::Other(
                    "sha256 of the downloaded binary does not match the published checksum; \
                     keeping the current binary"
                        .into(),
                ));
            }
            // Make it executable and prove it runs before replacing the
            // live binary.
            let mut perms = std::fs::metadata(&tmp).map_err(Error::Io)?.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(0o755);
            }
            std::fs::set_permissions(&tmp, perms).map_err(Error::Io)?;
            // The probe runs with a hard deadline: a downloaded binary that hangs
            // must not hang the CLI, and the child process is killed on
            // timeout instead of being left orphaned.
            let mut child = std::process::Command::new(&tmp)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| Error::Other(format!("downloaded binary does not run: {e}")))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let probe_ok = loop {
                match child.try_wait().map_err(Error::Io)? {
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
                return Err(Error::Other(
                    "downloaded binary failed or timed out in its version check; \
                     keeping the current binary"
                        .into(),
                ));
            };
            std::fs::rename(&tmp, &exe).map_err(Error::Io)?;
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
            return Err(Error::Config(format!(
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
            std::io::stdin().read_line(&mut answer).map_err(Error::Io)?;
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

fn init_config(path: &Path) -> Result<()> {
    match Config::write_default(path) {
        Ok(()) => print_line(&format!("wrote {}", path.display())),
        Err(Error::Config(msg)) => {
            error!("{msg}");
            std::process::exit(1);
        }
        Err(e) => return Err(e),
    }
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
        .map_err(|e| Error::Other(format!("cannot query the latest release: {e}")))?;
    let value: serde_json::Value = serde_json::from_reader(response.into_reader())
        .map_err(|e| Error::Other(format!("invalid release response: {e}")))?;
    value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .map(|t| t.trim_start_matches('v').to_string())
        .ok_or_else(|| Error::Other("the release response has no tag_name".into()))
}

/// Generates a random secp256k1 secret key as lowercase hex (64 chars),
/// retrying if the random bytes happen to be out of the valid range.
fn generate_secret_key_hex() -> Result<String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| Error::Other(format!("cannot read random bytes: {e}")))?;
        if let Ok(secret) = secp256k1::SecretKey::from_slice(&bytes) {
            return Ok(hex::encode(secret.secret_bytes()));
        }
    }
    Err(Error::Other("failed to generate a valid secret key".into()))
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
            .max_dbs(cfg.database.max_dbs.max(16))
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
        .expect("access table created above");
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
}
