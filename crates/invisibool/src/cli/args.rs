//! `clap` derive definitions for `invisibool`.
//!
//! Surface (M1 chunk 19):
//!
//! ```text
//! invisibool [--vault <PATH>] <SUBCOMMAND>
//!
//!   register <LABEL>     Add a new secret to the vault (value via TTY prompt or stdin pipe).
//!   list                 Print labels + kinds for every entry. Never prints the value.
//!   forget <LABEL>       Remove an entry. Exits 4 if the label does not exist.
//! ```
//!
//! ## Security-critical clap shape
//!
//! `register` has **exactly one argument**: the positional `LABEL`.
//! There is NO `--value`, `--secret`, `--password`, `--from-env`, or
//! `--from-file` flag, and the design forbids adding any. Reason: a
//! flag whose value is the secret would put the secret in `argv`,
//! visible to every other user via `/proc/<pid>/cmdline` (Linux),
//! `ps aux` (Unix), or Task Manager command-line columns (Windows),
//! and into shell history files (`.bash_history`, `.zsh_history`).
//! The register-subcommand-shape pin test in this file fails if
//! anyone ever adds such a flag.
//!
//! ## `--vault` placement
//!
//! `--vault` is a top-level flag, not redeclared per subcommand, so
//! it can appear before or after the subcommand:
//!
//! ```text
//! invisibool --vault /tmp/v.bin register my-token
//! invisibool register my-token --vault /tmp/v.bin   # SAME COMMAND
//! ```
//!
//! Path resolution: if `--vault` is set, the CLI uses that path
//! verbatim. Otherwise it calls
//! [`invisibool_engine::vault::default_vault_path`]. Either way the
//! path is opened through the same `Vault::open` entry point, which
//! enforces the AEAD magic-bytes check and the file-mode discipline
//! from chunk 18; `--vault` does not bypass those format checks.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "invisibool",
    about = "Local, privacy-first secrets and PII scrubber for LLM prompts.",
    version
)]
pub struct Cli {
    /// Override the default vault file location. If unset, the CLI
    /// uses the platform-default path (see
    /// `invisibool_engine::vault::default_vault_path`). The path is
    /// opened through `Vault::open` with the same magic-bytes /
    /// AEAD-format checks regardless of where it came from; pointing
    /// `--vault` at a non-vault file fails safely (BadMagic) rather
    /// than corrupting anything.
    #[arg(long, value_name = "PATH", global = true)]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Add a new secret to the vault.
    ///
    /// The secret value is read from stdin: if stdin is a terminal,
    /// the CLI prompts with no echo (via rpassword); if stdin is
    /// piped from another process, the CLI reads until EOF and
    /// strips a single trailing newline. The value is NEVER taken
    /// from a command-line argument, environment variable, or file
    /// path - this is the chunk-19 secret-input contract and is
    /// pinned by a structural clap-shape test.
    Register {
        /// The label this secret is registered under (printed by
        /// `list`, referenced by `forget`). Not secret.
        #[arg(value_name = "LABEL")]
        label: String,
    },
    /// Print every registered entry's label and kind. Never prints
    /// the registered value (the underlying API has no value field
    /// at the projection layer).
    List,
    /// Remove the entry with the given label. Exits 4 if no entry
    /// matches the label (not silent: the user knows their `forget`
    /// did not change the vault).
    Forget {
        /// The label whose entry to remove.
        #[arg(value_name = "LABEL")]
        label: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    // ----- LOAD-BEARING: register has exactly one argument -----
    //
    // The register subcommand must take ONLY the LABEL positional.
    // If anyone ever adds `--value`, `--secret`, `--from-env`, or
    // any other value-carrying flag, the secret-input contract is
    // broken: the value would land in argv, visible via
    // /proc/<pid>/cmdline, `ps`, Task Manager, and shell history.
    // This test fails if any non-help argument appears on
    // `register` beyond the LABEL positional.
    #[test]
    fn register_subcommand_has_no_value_carrying_argument() {
        let cmd = Cli::command();
        let register = cmd
            .find_subcommand("register")
            .expect("the register subcommand must exist");
        // clap auto-adds --help on every subcommand; filter it out
        // so the test compares only OUR declarations. If clap ever
        // adds another auto-arg with a name other than "help",
        // this filter needs revisiting; the assertion message
        // surfaces the actual id list to make that easy to spot.
        let our_args: Vec<&clap::Arg> = register
            .get_arguments()
            .filter(|a| a.get_id() != "help")
            .collect();
        assert_eq!(
            our_args.len(),
            1,
            "register must declare exactly ONE argument (LABEL positional); \
             adding a value-carrying flag would expose the secret via argv. \
             Found args: {:?}",
            our_args
                .iter()
                .map(|a| a.get_id().as_str())
                .collect::<Vec<_>>()
        );
        let only = our_args[0];
        assert!(
            only.is_positional(),
            "register's only arg must be positional (LABEL); a named option \
             would accept a value on the command line. Got: {:?}",
            only.get_id().as_str()
        );
        assert_eq!(
            only.get_id().as_str(),
            "label",
            "register's positional must be named 'label'"
        );
    }

    // ----- forget shape: one positional (LABEL), no other args -----
    //
    // Mirror of the register pin so a similar drift on forget is
    // caught immediately. `forget` does not take a secret value, so
    // the argv-leak hazard is less acute, but keeping the surface
    // narrow keeps the parser predictable.
    #[test]
    fn forget_subcommand_has_exactly_one_positional() {
        let cmd = Cli::command();
        let forget = cmd
            .find_subcommand("forget")
            .expect("the forget subcommand must exist");
        let our_args: Vec<&clap::Arg> = forget
            .get_arguments()
            .filter(|a| a.get_id() != "help")
            .collect();
        assert_eq!(our_args.len(), 1);
        assert!(our_args[0].is_positional());
        assert_eq!(our_args[0].get_id().as_str(), "label");
    }

    // ----- list shape: no positional / option args -----
    #[test]
    fn list_subcommand_takes_no_arguments() {
        let cmd = Cli::command();
        let list = cmd
            .find_subcommand("list")
            .expect("the list subcommand must exist");
        let our_args: Vec<&clap::Arg> = list
            .get_arguments()
            .filter(|a| a.get_id() != "help" && a.get_id() != "vault")
            .collect();
        assert!(
            our_args.is_empty(),
            "list must take no arguments beyond the global --vault flag; \
             found: {:?}",
            our_args
                .iter()
                .map(|a| a.get_id().as_str())
                .collect::<Vec<_>>()
        );
    }

    // ----- clap self-test: the derived parser is internally consistent -----
    #[test]
    fn clap_command_passes_internal_assertions() {
        Cli::command().debug_assert();
    }
}
