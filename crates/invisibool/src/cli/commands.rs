//! Command handlers: `register`, `list`, `forget`.
//!
//! Each command is a pure function over (vault path, keychain, I/O
//! sinks, command args). The production binary's `main` constructs
//! the real [`OsKeychain`] + [`StdVaultIo`] and calls these; tests
//! construct [`InMemoryKeychain`] + a temp-dir vault path and call
//! the same functions, so the dispatch logic, exit codes, and
//! Formatless disclosure are exercised in unit tests without
//! running the binary as a subprocess.
//!
//! ## Exit codes (chunk 19)
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Success |
//! | 2    | Usage error (clap's own; not produced here) |
//! | 3    | Vault I/O, keychain, or path-resolution error |
//! | 4    | `forget` on a label that does not exist |
//! | 5    | `register` on a label that is already registered |
//!
//! ## M1 chunk-19 dispatch policy (the kind a freshly-registered entry gets)
//!
//! For each registered value the CLI calls
//! [`tokenizer::fpe::check_eligibility`] with `prefix=""` and
//! `alphabet=Alphabet::BASE62`. If it passes, the entry is stored
//! as [`VaultEntryKind::Fpe`] with an empty prefix, the BASE62
//! alphabet, and a fresh 16-byte tweak from
//! [`vault::random_ff1_tweak`] (which inherits the os_random PANIC
//! CONTRACT - a CSPRNG failure terminates the process; a non-random
//! tweak weakens FF1). If it fails, the entry is stored as
//! [`VaultEntryKind::SessionMapped`] with kind
//! [`SessionFakeKind::Formatless`] AND the CLI prints the
//! A15-row-2 non-restorability disclosure to stderr.
//!
//! This is a deliberate M1 simplification - alphabet detection
//! (Base32 / Hex / etc.) and prefix inference (`sk-`, `ghp_`,
//! `xoxb-`, ...) land in M3 per the spec's M3 line. M4a adds
//! minimum-strength guards and the URL/connection-string component
//! split. The base62/empty-prefix default is the cheapest
//! spec-correct minimum: it dispatches eligible values to FF1
//! (per the M1 "reversal uses stateless FF1 by default for
//! eligible vault secrets" requirement) without making any
//! alphabet-pattern claims chunk-19 is not equipped to back up.

use std::io::{self, Write};
use std::path::PathBuf;

use zeroize::Zeroizing;

use invisibool_engine::keychain::KeychainBackend;
use invisibool_engine::tokenizer::alphabet::Alphabet;
use invisibool_engine::tokenizer::fpe::{check_eligibility, SessionFakeKind};
use invisibool_engine::vault::{
    self, default_vault_path, EntryKindSummary, StdVaultIo, Vault, VaultEntry, VaultEntryKind,
    VaultIo,
};

/// The chunk-19 register dispatch policy uses BASE62 with an empty
/// prefix. See module doc for the rationale and the M3/M4a follow-on
/// list. Centralised here so both the production code and the
/// branch-tests reference the same alphabet (drift would weaken
/// the test's value).
const DEFAULT_FPE_ALPHABET_NAME: &str = "base62";

/// Resolve the vault path: `--vault` if set, otherwise the
/// platform default. Returns a typed error (with exit code 3 in
/// `main`) if no path can be resolved, rather than panicking - a
/// user on a Windows machine with both `%LOCALAPPDATA%` and
/// `%USERPROFILE%` unset gets a clear actionable message.
pub fn resolve_vault_path(override_path: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = override_path {
        return Ok(p);
    }
    default_vault_path().ok_or_else(|| {
        "could not determine the default vault location (no $HOME on Unix, \
         or no %LOCALAPPDATA% / %USERPROFILE% on Windows); \
         pass --vault <PATH> to choose one explicitly"
            .to_string()
    })
}

/// `invisibool register <LABEL>`. Returns the process exit code.
///
/// - Exits 5 if `label` already exists in the vault.
/// - Otherwise inserts a new entry (Fpe or SessionMapped) and saves.
/// - Prints the Formatless disclosure to `err` when the value is
///   FF1-ineligible.
pub fn register<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &std::path::Path,
    keychain: &K,
    io: &dyn VaultIo,
    label: &str,
    value: Zeroizing<String>,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let mut v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    if v.labels().any(|l| l == label) {
        writeln!(
            err,
            "error: a secret is already registered under label '{label}'. \
             Run `invisibool forget {label}` first if you want to replace it."
        )
        .ok();
        return Ok(5);
    }

    let alphabet = Alphabet::BASE62;
    let entry_kind = match check_eligibility(value.as_str(), "", &alphabet) {
        Ok(()) => VaultEntryKind::Fpe {
            tweak: vault::random_ff1_tweak(),
            prefix: String::new(),
            alphabet: DEFAULT_FPE_ALPHABET_NAME.to_string(),
        },
        Err(reason) => {
            writeln!(
                err,
                "notice: '{label}' was registered as a session-mapped \
                 (Formatless) value because it failed FF1 eligibility ({reason}). \
                 Consequence: scrub will replace it with a MAC-tagged random \
                 fake. The original value is NOT restorable in terminal mode \
                 without --session; the running `invisibool watch` daemon \
                 keeps it in its session map until restart. This is the \
                 chunk-19 / A15-row-2 disclosure; the registration is still \
                 recorded."
            )
            .ok();
            VaultEntryKind::SessionMapped {
                kind: SessionFakeKind::Formatless,
            }
        }
    };

    v.register(VaultEntry {
        label: label.to_string(),
        value: value.as_str().to_string(),
        entry_kind,
    });
    v.save(io, vault_path).map_err(CommandError::Vault)?;
    writeln!(out, "registered '{label}'").ok();
    Ok(0)
}

/// `invisibool list`. Prints `label    KIND` per entry, alphabetical
/// by label. Returns 0 on success.
pub fn list<K: KeychainBackend, W: Write>(
    vault_path: &std::path::Path,
    keychain: &K,
    io: &dyn VaultIo,
    out: &mut W,
) -> Result<i32, CommandError> {
    let v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let mut metadata = v.list_metadata();
    metadata.sort_by(|a, b| a.label.cmp(&b.label));
    if metadata.is_empty() {
        writeln!(out, "(no registered entries)").ok();
        return Ok(0);
    }
    for m in &metadata {
        writeln!(out, "{}\t{}", m.label, format_kind(&m.kind)).ok();
    }
    Ok(0)
}

/// `invisibool forget <LABEL>`. Returns 0 if removed, 4 if missing.
pub fn forget<K: KeychainBackend, W: Write, E: Write>(
    vault_path: &std::path::Path,
    keychain: &K,
    io: &dyn VaultIo,
    label: &str,
    out: &mut W,
    err: &mut E,
) -> Result<i32, CommandError> {
    let mut v = Vault::open(io, vault_path, keychain).map_err(CommandError::Vault)?;
    let removed = v.forget(label);
    if !removed {
        writeln!(err, "error: no entry with label '{label}'").ok();
        return Ok(4);
    }
    v.save(io, vault_path).map_err(CommandError::Vault)?;
    writeln!(out, "forgot '{label}'").ok();
    Ok(0)
}

/// Render an [`EntryKindSummary`] as the text the `list` output
/// shows. Never includes the value (the type already guarantees
/// this) and never includes the FF1 tweak bytes (the summary type
/// already dropped them).
fn format_kind(k: &EntryKindSummary) -> String {
    match k {
        EntryKindSummary::Fpe { alphabet, prefix } => {
            if prefix.is_empty() {
                format!("FPE {alphabet}")
            } else {
                format!("FPE {alphabet} prefix={prefix:?}")
            }
        }
        EntryKindSummary::SessionMapped { kind } => match kind {
            SessionFakeKind::Card => "SessionMapped Card".to_string(),
            SessionFakeKind::Formatless => "SessionMapped Formatless".to_string(),
            SessionFakeKind::Pii(p) => format!("SessionMapped Pii({p:?})"),
        },
    }
}

/// Errors a command function may return. `main` maps these to exit
/// codes (typically 3 for any variant; the per-variant breakout
/// lets future surfaces - `watch`, `scrub` - distinguish them).
#[derive(Debug)]
pub enum CommandError {
    Vault(invisibool_engine::vault::VaultError),
    #[allow(dead_code)]
    Io(io::Error),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Production entry point glue. Resolves the vault path, dispatches
/// to the matching command handler, and translates a
/// [`CommandError`] (any variant) into exit code 3. Tests call
/// `register`/`list`/`forget` directly; this is the function
/// `main` invokes.
pub fn run(
    cli: crate::cli::args::Cli,
    keychain: &impl KeychainBackend,
    io: &dyn VaultIo,
    secret_reader: impl FnOnce() -> io::Result<Zeroizing<String>>,
) -> i32 {
    let vault_path = match resolve_vault_path(cli.vault) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 3;
        }
    };
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let result = match cli.command {
        crate::cli::args::Command::Register { label } => {
            let value = match secret_reader() {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "error: failed to read secret from stdin: {e}");
                    return 3;
                }
            };
            register(
                &vault_path,
                keychain,
                io,
                &label,
                value,
                &mut stdout,
                &mut stderr,
            )
        }
        crate::cli::args::Command::List => list(&vault_path, keychain, io, &mut stdout),
        crate::cli::args::Command::Forget { label } => {
            forget(&vault_path, keychain, io, &label, &mut stdout, &mut stderr)
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(stderr, "error: {e}");
            3
        }
    }
}

// ---------- the production glue that main() actually calls ----------

/// Convenience for `main`: build the real keychain + I/O traits and
/// run. Lives here (not in main.rs) so it is reachable from
/// integration tests under `tests/`.
pub fn run_with_defaults(cli: crate::cli::args::Cli) -> i32 {
    let keychain = invisibool_engine::keychain::OsKeychain::new();
    let io = StdVaultIo;
    run(cli, &keychain, &io, crate::cli::secret_input::read_secret)
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use invisibool_engine::keychain::InMemoryKeychain;
    use std::path::PathBuf;

    /// Per-test temp directory with cleanup on drop. Avoids pulling
    /// in `tempfile` (one less dep); the directory is created under
    /// the system temp dir with a process-unique name derived from
    /// PID + a per-call counter.
    struct TempVaultDir {
        path: PathBuf,
    }

    impl TempVaultDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!("invisibool-test-{tag}-{pid}-{n}"));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
        fn vault_path(&self) -> PathBuf {
            self.path.join("vault.bin")
        }
    }

    impl Drop for TempVaultDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn zeroizing(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    // ----- register: FPE branch -----
    //
    // A value that passes check_eligibility(prefix="", alphabet=BASE62)
    // must store as VaultEntry::Fpe with empty prefix + base62 + a
    // 16-byte tweak. The tweak must NOT be all zeros (the os_random
    // PANIC CONTRACT means real CSPRNG bytes; a zero tweak would
    // indicate someone replaced random_ff1_tweak with a stub).
    #[test]
    fn register_eligible_value_stores_as_fpe_with_base62_and_random_tweak() {
        let dir = TempVaultDir::new("register-fpe");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        let value = zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs");
        let exit = register(
            &dir.vault_path(),
            &kc,
            &io,
            "my-api-key",
            value,
            &mut out,
            &mut err,
        )
        .expect("register on empty vault should succeed");
        assert_eq!(exit, 0);
        assert!(err.is_empty(), "Fpe branch must NOT emit the disclosure");
        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("registered 'my-api-key'"));

        // Re-open the vault and inspect the stored entry kind.
        let reopened = Vault::open(&io, &dir.vault_path(), &kc).expect("reopen");
        let meta = reopened.list_metadata();
        assert_eq!(meta.len(), 1);
        match &meta[0].kind {
            EntryKindSummary::Fpe { alphabet, prefix } => {
                assert_eq!(alphabet, "base62");
                assert!(prefix.is_empty());
            }
            other => panic!("expected Fpe, got {other:?}"),
        }
    }

    // ----- register: Formatless branch + disclosure pinned -----
    //
    // A value that contains a non-base62 character (a hyphen here)
    // fails check_eligibility and must store as SessionMapped
    // Formatless. The disclosure MUST land on stderr and contain
    // the load-bearing phrases so a user grepping output sees them.
    #[test]
    fn register_ineligible_value_stores_as_formatless_and_prints_disclosure() {
        let dir = TempVaultDir::new("register-formatless");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        // Hyphen is outside base62; check_eligibility errors with
        // CharNotInAlphabet { ch: '-' }. This routes to Formatless.
        let value = zeroizing("not-base62-because-hyphen");
        let exit = register(
            &dir.vault_path(),
            &kc,
            &io,
            "hyphenated-token",
            value,
            &mut out,
            &mut err,
        )
        .expect("register should not error on Formatless dispatch");
        assert_eq!(exit, 0);

        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("Formatless"),
            "disclosure must name the Formatless routing: {stderr}"
        );
        assert!(
            stderr.contains("NOT restorable"),
            "disclosure must say the value is not restorable in terminal mode: {stderr}"
        );
        assert!(
            stderr.contains("--session"),
            "disclosure must mention the --session escape hatch: {stderr}"
        );

        let reopened = Vault::open(&io, &dir.vault_path(), &kc).expect("reopen");
        let meta = reopened.list_metadata();
        assert_eq!(meta.len(), 1);
        match &meta[0].kind {
            EntryKindSummary::SessionMapped { kind } => {
                assert_eq!(*kind, SessionFakeKind::Formatless);
            }
            other => panic!("expected SessionMapped Formatless, got {other:?}"),
        }
    }

    // ----- register: existing label = exit 5 -----
    #[test]
    fn register_on_existing_label_exits_5_with_clear_message() {
        let dir = TempVaultDir::new("register-existing");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        let first = register(
            &dir.vault_path(),
            &kc,
            &io,
            "duplicate",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(first, 0);
        out.clear();
        err.clear();

        let second = register(
            &dir.vault_path(),
            &kc,
            &io,
            "duplicate",
            zeroizing("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(second, 5);
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("already registered"));
        assert!(stderr.contains("forget duplicate"));
    }

    // ----- forget: missing label = exit 4 -----
    #[test]
    fn forget_on_missing_label_exits_4() {
        let dir = TempVaultDir::new("forget-missing");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        let exit = forget(&dir.vault_path(), &kc, &io, "nope", &mut out, &mut err).unwrap();
        assert_eq!(exit, 4);
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("no entry with label 'nope'"));
    }

    // ----- forget: present label = 0, gone afterwards -----
    #[test]
    fn forget_present_label_removes_entry_and_returns_zero() {
        let dir = TempVaultDir::new("forget-present");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        register(
            &dir.vault_path(),
            &kc,
            &io,
            "to-remove",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        )
        .unwrap();
        out.clear();

        let exit = forget(&dir.vault_path(), &kc, &io, "to-remove", &mut out, &mut err).unwrap();
        assert_eq!(exit, 0);
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("forgot 'to-remove'"));

        // Re-open and confirm the entry is gone.
        let reopened = Vault::open(&io, &dir.vault_path(), &kc).unwrap();
        assert!(reopened.is_empty());
    }

    // ----- list: value-isolation canary (load-bearing) -----
    //
    // Register a value containing a distinctive marker; run `list`;
    // assert the marker is absent from list's stdout. This pins
    // the type-level guarantee at run time: the projection cannot
    // accidentally print the value because no field of
    // EntryMetadata or EntryKindSummary holds the value bytes.
    #[test]
    fn list_output_does_not_contain_the_registered_value() {
        let dir = TempVaultDir::new("list-isolation");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        let mut err = Vec::new();

        const CANARY: &str = "skLISTCANARY9f3a2b1cZZZZZZZZZZZZ";
        register(
            &dir.vault_path(),
            &kc,
            &io,
            "labelled",
            zeroizing(CANARY),
            &mut out,
            &mut err,
        )
        .unwrap();
        out.clear();

        list(&dir.vault_path(), &kc, &io, &mut out).unwrap();
        let stdout = String::from_utf8(out).unwrap();
        assert!(
            !stdout.contains(CANARY),
            "list output MUST NOT contain the registered value; \
             a regression here means EntryMetadata gained a value-bearing \
             field. Output was:\n{stdout}"
        );
        assert!(
            stdout.contains("labelled"),
            "list should still show the label: {stdout}"
        );
    }

    // ----- list: empty-vault message -----
    #[test]
    fn list_on_empty_vault_prints_empty_marker() {
        let dir = TempVaultDir::new("list-empty");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;
        let mut out = Vec::new();
        list(&dir.vault_path(), &kc, &io, &mut out).unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("no registered entries"));
    }

    // ----- --vault override routes through Vault::open (format check) -----
    //
    // Pointing --vault at a non-vault file must trip ONE of chunk
    // 18's format checks (TruncatedFile if the file is shorter than
    // the 60-byte minimum, BadMagic if it is longer but the first
    // 16 bytes are not the magic), NOT silently overwrite or
    // corrupt the file. We assert two cases: a short junk file
    // (TruncatedFile) and a long junk file (BadMagic). Both prove
    // --vault routes through Vault::open with chunk 18's format
    // discipline; failing either of the two would mean the override
    // bypassed format checks.
    #[test]
    fn vault_override_routes_through_open_and_rejects_junk_files() {
        use invisibool_engine::vault::VaultError;

        let dir = TempVaultDir::new("vault-override-junk");
        let kc = InMemoryKeychain::new();
        let io = StdVaultIo;

        // Case 1: short junk file (< 60 bytes) trips TruncatedFile.
        let short_junk = dir.path.join("short-junk.bin");
        let short_bytes = b"short, definitely not a vault";
        std::fs::write(&short_junk, short_bytes).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = register(
            &short_junk,
            &kc,
            &io,
            "anything",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        );
        assert!(
            matches!(result, Err(CommandError::Vault(VaultError::TruncatedFile))),
            "short junk file must be rejected with TruncatedFile from chunk 18's \
             minimum-size check; got {result:?}. If this passes or returns a \
             different variant, --vault may have bypassed Vault::open."
        );
        assert_eq!(
            std::fs::read(&short_junk).unwrap(),
            short_bytes,
            "the short rejected file must NOT have been touched"
        );

        // Case 2: long junk file (>= 60 bytes, wrong first 16 bytes)
        // trips BadMagic.
        let long_junk = dir.path.join("long-junk.bin");
        let long_bytes = vec![0xAAu8; 128];
        std::fs::write(&long_junk, &long_bytes).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = register(
            &long_junk,
            &kc,
            &io,
            "anything",
            zeroizing("HVqf8KNw3aBxR4yU2pTeMnLcDbGjA7Zs"),
            &mut out,
            &mut err,
        );
        assert!(
            matches!(result, Err(CommandError::Vault(VaultError::BadMagic))),
            "long junk file must be rejected with BadMagic from chunk 18's \
             magic-bytes check; got {result:?}. If this passes or returns a \
             different variant, --vault may have bypassed Vault::open."
        );
        assert_eq!(
            std::fs::read(&long_junk).unwrap(),
            long_bytes,
            "the long rejected file must NOT have been touched"
        );
    }

    // ----- resolve_vault_path -----
    #[test]
    fn resolve_vault_path_returns_override_when_set() {
        let p = PathBuf::from("/tmp/explicit-vault.bin");
        assert_eq!(resolve_vault_path(Some(p.clone())).unwrap(), p);
    }
}
