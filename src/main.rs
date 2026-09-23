//! nostrfy: a minimal, stable Nostr relay server.
//!
//! See the `cli` module for the subcommands (`start`/`stop`/`restart`/
//! `stats`/`check`/`init`) and `server` for the HTTP/WebSocket front.

mod audit;
mod cli;
mod config;
mod conn;
mod db;
mod error;
mod event;
mod filter;
#[cfg(test)]
mod fuzz_tests;
mod logging;
mod migrate;
mod nips;
#[cfg(test)]
mod prop_tests;
mod relay;
mod server;
mod stats;
mod strfry_config;
mod util;
mod ws;

use clap::Parser;

use crate::cli::Cli;

fn main() {
    // Log every panic so that a fault in any task is visible in the logs
    // (spawned tasks are contained; the relay keeps serving). `log_panic`
    // never blocks on the logger mutex: the hook runs before the unwind,
    // so a panic inside a log backend still holds it.
    std::panic::set_hook(Box::new(|info| {
        crate::logging::log_panic(&format!("panic: {info}"));
    }));
    crate::logging::init();

    let mut cli = Cli::parse();
    if let Err(e) = cli.prepare() {
        // Log through the logger (which falls back to stderr before a file
        // backend is installed) so the reason survives daemonization.
        log::error!("error: {e}");
        std::process::exit(1);
    }

    // Reached in foreground mode or in the daemon child process. The runtime
    // must be created after daemonization because the fork inherits the
    // runtime context of the parent thread.
    let rt = tokio::runtime::Runtime::new().expect("cannot create tokio runtime");
    if rt.block_on(cli.serve_logged()).is_err() {
        // `serve_logged` already logged the reason (to the log file after
        // daemonization, to stderr in the foreground); only the exit status
        // is left.
        std::process::exit(1);
    }
}
