//! CLI module tree. Three submodules:
//!
//! - [`args`] - the `clap` derive definitions (CLI surface).
//! - [`secret_input`] - TTY-prompt-or-stdin-pipe reader that produces
//!   the registered value as a `Zeroizing<String>`. The value never
//!   enters argv, env, or a file under this code path.
//! - [`commands`] - the three command functions
//!   (`register`/`list`/`forget`), each taking a `&dyn KeychainBackend`
//!   so tests can swap [`invisibool_engine::keychain::InMemoryKeychain`]
//!   in for the production [`invisibool_engine::keychain::OsKeychain`].

pub mod args;
pub mod commands;
pub mod secret_input;
