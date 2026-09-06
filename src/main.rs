//! nostrfy: a minimal, stable Nostr relay server.
//!
//! See the `cli` module for the subcommands (`start`/`stop`/`restart`/
//! `stats`/`check`/`init`) and `server` for the HTTP/WebSocket front.

mod audit;
mod cli;
mod config;
mod db;
mod error;
mod event;
mod filter;
mod logging;
mod nips;
mod relay;
mod server;
mod stats;
mod util;
mod ws;

use clap::Parser;

use crate::cli::Cli;

fn main() {
    // Log every panic so that a fault in any task is visible in the logs
    // (spawned tasks are contained; the relay keeps serving).
    std::panic::set_hook(Box::new(|info| {
        log::error!("panic: {info}");
    }));
    crate::logging::init();

    let mut cli = Cli::parse();
    if let Err(e) = cli.prepare() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // Reached in foreground mode or in the daemon child process. The runtime
    // must be created after daemonization because the fork inherits the
    // runtime context of the parent thread.
    let rt = tokio::runtime::Runtime::new().expect("cannot create tokio runtime");
    if let Err(e) = rt.block_on(cli.serve()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
