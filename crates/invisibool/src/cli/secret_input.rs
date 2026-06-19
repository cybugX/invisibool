//! Read a registered secret value from standard input.
//!
//! ## Two modes, one return type
//!
//! - **TTY**: when stdin is a terminal, the CLI calls
//!   [`rpassword::prompt_password`] which turns echo off on the
//!   terminal, prints `"Secret: "`, reads one line, restores echo,
//!   and returns the typed string. The user sees no keystrokes.
//! - **Pipe**: when stdin is piped from another process or
//!   redirected from a file, the CLI reads the whole stream to EOF
//!   and **strips ONE trailing newline** (`"\n"` or `"\r\n"`).
//!
//! Both paths produce a [`Zeroizing<String>`], so the value is wiped
//! from memory when it drops.
//!
//! ## Trailing-newline strip - deliberate choice, documented surprise
//!
//! M1 secrets are short, single-line tokens (API keys, bearer
//! tokens, connection-string credential components). Almost every
//! way of producing one ends the stream with a `\n` (the shell's
//! `echo`, a `cat` of a file with a trailing newline, a Python
//! `print()` of a token). Treating that newline as part of the
//! secret would silently corrupt almost every legitimate use of
//! piped input.
//!
//! BUT: a secret that legitimately ends in whitespace (rare but
//! possible) loses one trailing newline character through this
//! stripper. The CLI's `register --help` text and the chunk-19
//! disclosure mention this rule explicitly so it is not a silent
//! surprise. Future surfaces (M4a's `register --update`,
//! `register --from-file`) revisit the policy with explicit flags
//! (`--no-strip-newline`, etc.); chunk-19 hard-codes the strip.
//!
//! ## What this module does NOT do
//!
//! - Read `$INVISIBOOL_SECRET` or any other environment variable.
//!   Env vars are visible to child processes and many log
//!   aggregators capture process env.
//! - Accept the value as a command-line argument. argv is visible
//!   via `/proc/<pid>/cmdline`, `ps aux`, Task Manager command-line
//!   columns, and shell history files.
//! - Read the value from a file path passed on the command line. A
//!   pasted file path would route through the same argv-exposure
//!   path; the user can still `cat` a file into stdin if they want
//!   that workflow, but the CLI does not surface a flag for it.
//!
//! The clap shape pin test in [`super::args`] enforces the
//! "register has exactly one argument" rule at the type level so
//! none of the above can be added without the test failing.

use std::io::{self, IsTerminal, Read};

use zeroize::Zeroizing;

/// Prompt for a secret on a TTY, or read one from a stdin pipe.
///
/// Returns the secret as a [`Zeroizing<String>`]. Errors are
/// propagated from the underlying I/O (rpassword's prompt error in
/// TTY mode, or `io::stdin().read_to_string` in pipe mode).
pub fn read_secret() -> io::Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        read_secret_tty()
    } else {
        read_secret_pipe(&mut io::stdin().lock())
    }
}

/// TTY path: no-echo prompt via rpassword.
fn read_secret_tty() -> io::Result<Zeroizing<String>> {
    let raw = rpassword::prompt_password("Secret: ")?;
    Ok(Zeroizing::new(raw))
}

/// Pipe path: read everything to EOF, then strip one trailing
/// newline (`\n` or `\r\n`). Factored out so the unit test below can
/// drive it with an in-memory reader without faking a pipe.
pub(crate) fn read_secret_pipe<R: Read>(reader: &mut R) -> io::Result<Zeroizing<String>> {
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(Zeroizing::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn pipe_mode_reads_value_and_strips_trailing_lf() {
        let mut input = Cursor::new(b"sk-canary-pipe-only\n".to_vec());
        let secret = read_secret_pipe(&mut input).expect("pipe read ok");
        assert_eq!(
            secret.as_str(),
            "sk-canary-pipe-only",
            "the single trailing LF must be stripped"
        );
    }

    #[test]
    fn pipe_mode_strips_trailing_crlf() {
        let mut input = Cursor::new(b"sk-canary-crlf\r\n".to_vec());
        let secret = read_secret_pipe(&mut input).expect("pipe read ok");
        assert_eq!(
            secret.as_str(),
            "sk-canary-crlf",
            "the single trailing CRLF must be stripped"
        );
    }

    #[test]
    fn pipe_mode_strips_only_one_trailing_newline() {
        // Two trailing newlines: one is the convention-strip, the
        // other is intentional content. We strip ONE so the user's
        // trailing-blank-line value survives. Documented surprise:
        // someone whose secret ends in '\n' loses exactly one char.
        let mut input = Cursor::new(b"value-with-blank\n\n".to_vec());
        let secret = read_secret_pipe(&mut input).expect("pipe read ok");
        assert_eq!(secret.as_str(), "value-with-blank\n");
    }

    #[test]
    fn pipe_mode_preserves_value_without_trailing_newline() {
        let mut input = Cursor::new(b"no-newline-at-end".to_vec());
        let secret = read_secret_pipe(&mut input).expect("pipe read ok");
        assert_eq!(secret.as_str(), "no-newline-at-end");
    }

    #[test]
    fn pipe_mode_yields_empty_string_on_empty_input() {
        let mut input = Cursor::new(Vec::<u8>::new());
        let secret = read_secret_pipe(&mut input).expect("pipe read ok");
        assert_eq!(secret.as_str(), "");
    }
}
