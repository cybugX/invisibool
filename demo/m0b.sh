#!/usr/bin/env bash
# Invisibool - M0b gate demo.
#
# Runs the on-screen demonstrations for the M0b gate review:
#
#   1. The engine, on stage: a real-shaped registered token is
#      scrubbed (original out, same-length fake in its place); a
#      short Formatless secret is fail-closed to the
#      `[INVISIBOOL_UNRESTORABLE]` placeholder rather than passed
#      through. Restore brings the FF1 token back byte-exact.
#
#   2. The full leak harness: 9 integration tests, each with a fresh
#      runtime canary, each asserting the canary plaintext is absent
#      from every output channel except the intended restore stream.
#      With --nocapture the per-round "OK" lines surface so the
#      reviewer watches every test actually exercise the engine.
#
# Run from the repo root:
#   ./demo/m0b.sh
#
# Requirements on the reviewer's machine: Docker + git. Nothing else.
# Rust, the engine code, and every test live inside the container.

set -euo pipefail

# Locate the repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Colours: enabled only when stdout is a real TTY and NO_COLOR is
# unset. Piping the script to a file or running under NO_COLOR=1
# leaves every colour variable empty, so the output is plain ASCII.
BOLD=$'\e[1m'
DIM=$'\e[2m'
GREEN=$'\e[32m'
RESET=$'\e[0m'
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    BOLD=""; DIM=""; GREEN=""; RESET=""
fi

# Run a cargo invocation inside the dev container. The wrapper
# propagates this script's own TTY/NO_COLOR state down to cargo:
# docker-compose.yml sets CARGO_TERM_COLOR=always for interactive
# development, so we override back to `never` whenever this script's
# stdout is not a TTY (piped to a file, captured in CI logs, run
# under NO_COLOR=1). That makes cargo's `Finished` / `Running` /
# test-pass lines come through as plain text in those cases.
#
# Helper-function shape (rather than an array of extra args) so the
# script stays compatible with bash 3.2 - macOS still ships it as
# /bin/bash, and `set -u` + empty-array expansion errors there.
run_in_container() {
    if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
        docker compose run --rm -e CARGO_TERM_COLOR=never dev "$@"
    else
        docker compose run --rm dev "$@"
    fi
}

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

# ----- Preflight -------------------------------------------------------------

require docker
require git

# Resolve host UID/GID via these specific env-var names because the obvious
# `UID`/`GID` are readonly bash builtins and would silently fail to export.
export HOST_UID="$(id -u)"
export HOST_GID="$(id -g)"

section "0 / 3   Build the pinned dev container (cached after first run)"
note "Pinned: Rust 1.96.0 (base image by manifest digest) plus the engine"
note "dependency tree (aho-corasick, regex, fpe, aes, hkdf, hmac, sha2,"
note "subtle, zeroize, secrecy, serde) - same image CI uses."
docker compose build dev >/dev/null
note "Container ready as invisibool-dev:latest."

# ----- Scenario binary --------------------------------------------------------

section "1 / 3   The engine, on stage"
note "What you should see below: scenario 1 prints BEFORE / SCRUB / RESTORE for"
note "a runtime API-key-shaped canary, then checks the restored bytes equal the"
note "original byte-for-byte. Scenario 2 prints BEFORE / SCRUB for a short PIN"
note "and verifies the [INVISIBOOL_UNRESTORABLE] placeholder replaced it."
note "Canaries are generated fresh from the system clock + PID on every run -"
note "re-run this script and the BEFORE bytes will change."
run_in_container cargo run --quiet --example m0b_demo -p invisibool-engine

# ----- Leak harness ----------------------------------------------------------

section "2 / 3   Leak harness: 9 integration tests with fresh runtime canaries"
note "Each test generates its own canary, runs the engine end-to-end, and"
note "asserts the canary plaintext is absent from every escape channel:"
note "the scrub output, the EngineScrubResult Debug, each ScrubNotice"
note "Debug, the registered-value set Debug, and the redaction placeholder."
note "The three adversarial fail-closed tests prove the engine redacts"
note "rather than passes the canary through when no fake can be produced."
note "--nocapture surfaces each per-round 'OK' line so you watch the work."
run_in_container cargo test -p invisibool-engine --test leak_harness -- --nocapture

# ----- Summary ---------------------------------------------------------------

section "3 / 3   Summary"
printf '%s%sM0b gate demo: every check above PASSED.%s\n' "$BOLD" "$GREEN" "$RESET"
printf '%sThe engine is the deliverable for this gate. See docs/M0b_GATE_REVIEW.md for%s\n' "$DIM" "$RESET"
printf '%sthe accompanying plain-English explanation, top-3 uncertainties, and the test%s\n' "$DIM" "$RESET"
printf '%sand bench numbers that back the gate.%s\n\n' "$DIM" "$RESET"
