//! Invisibool CLI entry point.
//!
//! Parses the [`cli::args::Cli`] surface, builds the production
//! [`OsKeychain`] + [`StdVaultIo`] traits, and dispatches via
//! [`cli::commands::run_with_defaults`]. Process exit code comes
//! from the command handler (see `cli::commands` for the table).

mod cli;

use clap::Parser;

fn main() {
    let cli = cli::args::Cli::parse();
    std::process::exit(cli::commands::run_with_defaults(cli));
}
