#!/usr/bin/env bash
# Invisibool — M0a gate demo.
#
# What this script proves:
#   M0a built the project's scaffold and CI/dev tooling — there is no
#   secret detection / tokenization / vault code yet. So this demo cannot
#   show a real secret being scrubbed. What it CAN show is that the whole
#   build/test/lint suite, plus every gate that will guard future code,
#   runs cleanly inside a reproducible Docker container before any engine
#   code exists. From M0b onward, every line of real code goes through the
#   same gates you watch pass below.
#
# Run from the repo root:
#   ./demo/m0a.sh
#
# Requirements on the reviewer's machine: Docker + git. Nothing else.
# Rust, cargo-deny, cargo-audit, gitleaks all live inside the container.

set -euo pipefail

# Locate the repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Colours when stdout is a TTY; plain text when piped or NO_COLOR set.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
    BOLD=""; DIM=""; GREEN=""; YELLOW=""; RESET=""
fi

section() {
    printf '\n%s━━ %s %s\n' "$BOLD" "$1" "$RESET"
}

note() {
    printf '%s%s%s\n' "$DIM" "$1" "$RESET"
}

require() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'Missing required tool: %s\n' "$1" >&2
        printf 'This demo needs Docker + git on the host. Install %s, then re-run.\n' "$1" >&2
        exit 1
    }
}

# ----- Preflight on the host -------------------------------------------------

require docker
require git

# Resolve host UID/GID via these specific env-var names because the obvious
# `UID`/`GID` are readonly bash builtins and would silently fail to export.
export HOST_UID="$(id -u)"
export HOST_GID="$(id -g)"

section "0 / 6   Build the pinned dev container (cached after first run)"
note "Pinned: Rust 1.96.0 (base image by manifest digest), cargo-deny 0.19.8,"
note "cargo-audit 0.22.2, gitleaks 8.30.1 — each binary SHA-256-checked."
docker compose build dev >/dev/null
note "Container ready as invisibool-dev:latest."

# ----- All gates inside the container ---------------------------------------

run_in_container() {
    docker compose run --rm dev bash -c "$1"
}

section "1 / 6   Pinned tool versions inside the container"
note "Same binaries CI uses — every SHA matches Dockerfile.dev and .github/workflows/ci.yml."
run_in_container '
    rustc --version
    cargo-deny --version
    cargo-audit --version
    printf "gitleaks "; gitleaks version
'

section "2 / 6   The Rust workspace compiles"
note "Two crates: invisibool-engine (library, forbids unsafe code) and invisibool (the CLI binary)."
note "Both empty stubs in M0a — M0b will add detection, tokenization, vault."
run_in_container '
    cargo check --workspace --all-targets
    cargo test  --workspace --all-targets
'
note "No tests yet — M0b adds property tests next to every engine feature."

section "3 / 6   Code style and lint gates"
note "Same gates that will guard every future commit."
run_in_container '
    cargo fmt   --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
'

section "4 / 6   Supply-chain gates: cargo deny + cargo audit"
note "deny.toml: license allowlist (permissive only), advisory blocks, only crates.io as a registry."
note "cargo audit fetches the RustSec advisory DB. On the M0a dep-free scaffold both gates pass trivially —"
note "that is structural, not a mystery success. Once M0b adds real deps both gates start meaning something."
run_in_container '
    cargo deny  check
    cargo audit
'

section "5 / 6   Secret scan: gitleaks over full history"
note "Allowlist is narrowly path-scoped to tests/fixtures/ and rules/secrets.toml only."
note "No broad allowlists — a secret scrubber'\''s repo must not defang the very scanner it depends on."
run_in_container '
    gitleaks detect --no-banner --redact --source .
'

section "6 / 6   The invisibool CLI binary runs"
note "Binary stub — M1 will replace this with the real CLI (scrub/restore/register/watch/...)."
run_in_container '
    cargo run --quiet -p invisibool
'

printf '\n%s%sM0a gate demo: every check above PASSED.%s\n' "$BOLD" "$GREEN" "$RESET"
printf '%sThe scaffold is the deliverable for this gate. M0b adds the engine.%s\n\n' "$DIM" "$RESET"
