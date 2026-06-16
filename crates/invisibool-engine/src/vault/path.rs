//! Platform-appropriate default location for the vault file.
//!
//! Hand-rolled resolver (no `directories` / `dirs` / `dirs-sys` /
//! `option-ext` transitive). The platform-path crates pulled in
//! `option-ext` under MPL-2.0 transitively via `dirs-sys`, which is
//! copyleft and not on the project's permissive-only license
//! allowlist. Rolling our own resolver drops three transitive crates
//! and a copyleft license from the dep tree, and trades them for ~40
//! lines of `#[cfg(target_os)]` branches that resolve the documented
//! platform locations:
//!
//! - **Linux** (and other unixes): `$XDG_DATA_HOME/invisibool/` if
//!   `XDG_DATA_HOME` is set and absolute, else `$HOME/.local/share/invisibool/`.
//!   Per the XDG Base Directory Specification, a relative
//!   `XDG_DATA_HOME` is invalid and must be ignored.
//! - **macOS**: `$HOME/Library/Application Support/invisibool/`.
//! - **Windows**: `%LOCALAPPDATA%\invisibool\` if set, else
//!   `%USERPROFILE%\AppData\Local\invisibool\`. We read the env vars
//!   directly rather than calling the Win32 known-folder API
//!   (`SHGetKnownFolderPath`); env vars are slightly less robust (a
//!   user who has unset both LOCALAPPDATA and USERPROFILE gets `None`
//!   from this resolver, where the Win32 API would still return the
//!   profile path) but they avoid pulling in `windows-sys` /
//!   `winapi` as a dependency. For a secrets tool the smaller
//!   dependency footprint is worth more than the edge-case
//!   robustness; the future M1 CLI surfaces the `None` case as a
//!   clear error and points the user at `--vault <path>`.
//!
//! ## Testing
//!
//! Each platform branch is factored as a pure helper that takes the
//! relevant env-var values as `Option<&OsStr>` arguments. The
//! `default_vault_dir` entry point reads the env vars and forwards
//! to the matching helper. Tests call the helpers directly with
//! synthetic inputs, so a single Linux CI runner exercises every
//! platform's resolution logic - no env-var mutation race, no
//! Windows-specific test runner needed for the Windows branch.

use std::ffi::OsStr;
use std::path::PathBuf;

/// Default vault file path for the current user on the current
/// platform. Returns `None` only when no usable path can be resolved
/// (e.g. `$HOME` is unset on Unix, both `%LOCALAPPDATA%` and
/// `%USERPROFILE%` are unset on Windows). The CLI surfaces `None`
/// as a clear error along the lines of "could not determine vault
/// location; set XDG_DATA_HOME or pass --vault <path>" rather than
/// panicking.
pub fn default_vault_path() -> Option<PathBuf> {
    default_vault_dir().map(|d| d.join("vault.bin"))
}

#[cfg(target_os = "linux")]
fn default_vault_dir() -> Option<PathBuf> {
    linux_vault_dir(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

#[cfg(target_os = "macos")]
fn default_vault_dir() -> Option<PathBuf> {
    macos_vault_dir(std::env::var_os("HOME").as_deref())
}

#[cfg(target_os = "windows")]
fn default_vault_dir() -> Option<PathBuf> {
    windows_vault_dir(
        std::env::var_os("LOCALAPPDATA").as_deref(),
        std::env::var_os("USERPROFILE").as_deref(),
    )
}

// Other unixes (BSDs, illumos, etc.): fall through to the Linux
// XDG convention. `watch` only supports Windows / macOS / X11, but
// terminal `scrub` / `restore` can run anywhere; an unspecified
// unix gets the standard XDG layout.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn default_vault_dir() -> Option<PathBuf> {
    linux_vault_dir(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

// ---------- pure platform helpers ----------
//
// Each helper takes the relevant env-var values explicitly so it's
// testable without env-var mutation. `#[allow(dead_code)]` because
// only the matching platform's helper is reachable from
// `default_vault_dir` in production; on other platforms each helper
// is reachable only through the test module.

#[allow(dead_code)]
fn linux_vault_dir(xdg_data_home: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    // Per the XDG Base Directory Specification: $XDG_DATA_HOME is
    // valid only when set to an absolute path. A relative value is
    // ignored and the resolver falls back to $HOME/.local/share.
    if let Some(xdg) = xdg_data_home {
        let xdg = PathBuf::from(xdg);
        if xdg.is_absolute() {
            return Some(xdg.join("invisibool"));
        }
    }
    let home = home?;
    Some(
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("invisibool"),
    )
}

#[allow(dead_code)]
fn macos_vault_dir(home: Option<&OsStr>) -> Option<PathBuf> {
    let home = home?;
    Some(
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("invisibool"),
    )
}

#[allow(dead_code)]
fn windows_vault_dir(
    local_app_data: Option<&OsStr>,
    user_profile: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(local_app_data) = local_app_data {
        return Some(PathBuf::from(local_app_data).join("invisibool"));
    }
    let user_profile = user_profile?;
    Some(
        PathBuf::from(user_profile)
            .join("AppData")
            .join("Local")
            .join("invisibool"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- existing-API tests: default_vault_path on the current platform -----

    #[test]
    fn default_vault_path_returns_some_on_a_machine_with_a_home_dir() {
        let path =
            default_vault_path().expect("the test runner should have a resolvable home directory");
        assert!(
            path.ends_with("vault.bin"),
            "default vault path should end with vault.bin, got {path:?}"
        );
    }

    #[test]
    fn default_vault_path_contains_the_invisibool_segment() {
        let path = default_vault_path().expect("home directory should resolve");
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("invisibool"),
            "default vault path should contain 'invisibool' segment: {path_str}"
        );
    }

    // ----- byte-identical path pins -----
    //
    // These pin the resolved path strings to exactly what the
    // previous `directories`-based resolver produced. A future
    // refactor that silently relocates the vault would fail one of
    // these tests immediately. The paths are constructed via
    // `PathBuf::join` so they use the test runner's native
    // separator; the resolver does the same, so the comparison is
    // byte-equal on the runner regardless of which platform we are
    // pinning.

    #[test]
    fn linux_resolves_to_xdg_default_with_only_home_set() {
        let got = linux_vault_dir(None, Some(OsStr::new("/home/u")));
        let want = PathBuf::from("/home/u")
            .join(".local")
            .join("share")
            .join("invisibool");
        assert_eq!(got.as_deref(), Some(want.as_path()));
    }

    #[test]
    fn linux_resolves_under_xdg_data_home_when_set_absolute() {
        let got = linux_vault_dir(Some(OsStr::new("/srv/data")), Some(OsStr::new("/home/u")));
        let want = PathBuf::from("/srv/data").join("invisibool");
        assert_eq!(got.as_deref(), Some(want.as_path()));
    }

    #[test]
    fn linux_ignores_relative_xdg_data_home_per_spec() {
        // Per the XDG Base Directory Spec, a relative XDG_DATA_HOME
        // is invalid and must be ignored. Without this branch a user
        // who sets `XDG_DATA_HOME=mydata` in their shell would get
        // the vault written to whatever the cwd was at CLI launch,
        // which is the silent-misplacement failure mode this test
        // pins against.
        let got =
            linux_vault_dir(Some(OsStr::new("mydata")), Some(OsStr::new("/home/u")));
        let want = PathBuf::from("/home/u")
            .join(".local")
            .join("share")
            .join("invisibool");
        assert_eq!(
            got.as_deref(),
            Some(want.as_path()),
            "relative XDG_DATA_HOME must be ignored; expected the home fallback"
        );
    }

    #[test]
    fn linux_returns_none_when_both_home_and_xdg_are_unset() {
        let got = linux_vault_dir(None, None);
        assert!(
            got.is_none(),
            "no $HOME and no $XDG_DATA_HOME must yield None, not a panic and not a guess"
        );
    }

    #[test]
    fn macos_resolves_to_application_support_path() {
        let got = macos_vault_dir(Some(OsStr::new("/Users/u")));
        let want = PathBuf::from("/Users/u")
            .join("Library")
            .join("Application Support")
            .join("invisibool");
        assert_eq!(got.as_deref(), Some(want.as_path()));
    }

    #[test]
    fn macos_returns_none_when_home_is_unset() {
        let got = macos_vault_dir(None);
        assert!(got.is_none());
    }

    #[test]
    fn windows_resolves_under_localappdata_when_set() {
        let got = windows_vault_dir(
            Some(OsStr::new(r"C:\Users\u\AppData\Local")),
            Some(OsStr::new(r"C:\Users\u")),
        );
        let want = PathBuf::from(r"C:\Users\u\AppData\Local").join("invisibool");
        assert_eq!(got.as_deref(), Some(want.as_path()));
    }

    #[test]
    fn windows_falls_back_to_userprofile_when_localappdata_is_unset() {
        let got = windows_vault_dir(None, Some(OsStr::new(r"C:\Users\u")));
        let want = PathBuf::from(r"C:\Users\u")
            .join("AppData")
            .join("Local")
            .join("invisibool");
        assert_eq!(got.as_deref(), Some(want.as_path()));
    }

    #[test]
    fn windows_returns_none_when_both_env_vars_are_unset() {
        let got = windows_vault_dir(None, None);
        assert!(
            got.is_none(),
            "no %LOCALAPPDATA% and no %USERPROFILE% must yield None, not a panic"
        );
    }
}
