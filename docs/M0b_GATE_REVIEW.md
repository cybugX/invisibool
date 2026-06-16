# M0b gate review packet

This file is the human reviewer's reading material for the M0b
gate. Four pieces:

| # | Deliverable | Lives at |
|---|---|---|
| (a) | Plain-English explanation of what was built and why | This file, below |
| (b) | A runnable demo the reviewer executes themselves | `demo/m0b.sh` |
| (c) | Top three uncertainties / riskiest assumptions | This file, below |
| (d) | What could go wrong + how it was tested + actual numbers | This file, below |

The full design rationale, security posture, structure-as-built,
and prior-art positioning are in `docs/THREAT_MODEL.md`,
`docs/ARCHITECTURE.md`, and `docs/PRIOR_ART.md` respectively.
Those three are the "code-side" deliverables; this file is the
"review-side" packet.

---

## (a) Plain-English: what the engine does, no jargon

Imagine you're about to paste a prompt into ChatGPT or Claude, and
that prompt contains a secret - an API key, a password, a credit
card number. Once you hit send, that secret is in the LLM
provider's logs, your corporate proxy's audit trail, and possibly
their training data. You can't take it back. Most "AI privacy" tools
solve this by **redacting** the secret - they paste `[REDACTED]`
in place of your token and hope the LLM still understands the
prompt. That works for prose, but it breaks for anything where the
LLM needs the secret to do its job (debug an API error, parse a
config file, explain a stack trace).

Invisibool's engine takes a different approach: it **replaces** the
secret with a fake of the same shape - a fake that looks like a
real API key, has the same length, the same character class, the
same prefix - before the prompt goes anywhere. The LLM sees the
fake, processes it normally, and produces a reply. When the reply
comes back, the engine **restores** the original secret in place of
the fake. From your side, the LLM appears to have processed the
real secret. From the LLM's side, the real secret never existed.

The engine ships two reversibility modes:

- **Stateless mode.** A registered value is encrypted into its fake
  using a cryptographic scheme (format-preserving encryption - the
  fake is a deterministic bijection of the real). Any process that
  has the same vault keys can decrypt the fake back to the real,
  with no shared session state needed. This is the mode the future
  CLI will use by default - `invisibool scrub` and `invisibool
  restore` in two separate processes will round-trip secrets
  without any extra state.

- **Session mode.** When a value can't go through the stateless
  cryptographic path (passwords with special characters, very short
  PINs, structured PII), the engine remembers the `(real → fake)`
  pair in an in-memory map and brings the original back on
  restore. This works inside one long-lived process - the future
  clipboard `watch` daemon will use it - but doesn't survive across
  separate CLI invocations until the future `--session` flag lands.

A third behaviour: **fail-closed redaction**. When the engine
cannot produce a valid fake (a corrupt vault entry, a card layout
the generator doesn't recognise, a value too short to carry the
cryptographic signature), it does **not** pass the real value
through with a warning. It removes the value from the output and
replaces it with `[INVISIBOOL_UNRESTORABLE]`. The end-of-scrub
notice tells the user exactly which value was lost. The rule is
"never leak the real secret"; the cost is "you have to register a
longer value or accept that one value is unscrubbable".

**What the engine is at M0b.** A Rust library:
`invisibool-engine`. It has detection (an exact matcher that fires
on values the user has registered byte-for-byte; a pattern matcher
that's built but not yet hooked into the scrub pass until M2), a
tokenizer dispatch (FF1 cryptographic substitution for eligible
values, reserved-range fakes for emails / IPv4 / phones / cards,
MAC-tagged fakes for long Formatless values, fail-closed redaction
otherwise), an in-memory session map with LRU + TTL bounds, and
the scrub / restore public API. It has 140 unit tests, 9
integration "leak harness" tests with fresh runtime canaries on
every PR, a Criterion benchmark suite over a committed corpus, and
a CI suite that includes `cargo deny`, `cargo audit`, and gitleaks
with a narrowly path-scoped allowlist.

**What is explicitly NOT in M0b.** The CLI binary, the clipboard
`watch` daemon, the AEAD-encrypted vault file, the OS-keychain
integration, the `--session` flag for cross-process session
round-trip, the pattern rule corpus (`rules/secrets.toml`),
`rotate-key`, `forget --purge`, and the published latency numbers
in a README - all planned for later milestones (M1 / M2 / M4a /
M4c). The engine alone is the M0b deliverable.

---

## (b) The demo - `demo/m0b.sh`

Run it yourself from the repo root:

```
./demo/m0b.sh
```

The script needs Docker + git on your machine; Rust and the engine
code live inside the pinned dev container. You'll watch three
things happen:

1. **Scenario 1: FF1 round-trip.** A runtime-generated
   API-key-shaped canary (e.g. `sk-test-DEMOWXNddqh2eybWGKnh`) is
   registered in a fresh engine, then scrubbed inside a sample
   prompt. The script prints BEFORE / SCRUB / RESTORE side-by-side
   so you can read the canary disappear, see a different but
   same-length fake (`sk-test-jD3AEjDTOsVaHDNcMRFM`) appear in its
   place, and watch restore bring the original bytes back. An
   explicit `restored bytes == original bytes?` check fires; the
   scenario ends in `[PASS]` or `[FAIL]`.

2. **Scenario 2: fail-closed redaction.** A runtime-generated
   4-character PIN is registered as a Formatless value (too short
   to carry a MAC tail). The script prints BEFORE / SCRUB; the PIN
   is gone from the output and `[INVISIBOOL_UNRESTORABLE]` sits in
   its place. Checks confirm the original PIN is absent from the
   output, the placeholder is present, and a typed
   `RedactedFormatless` notice fired. `[PASS]` or `[FAIL]`.

3. **The leak harness.** `cargo test --test leak_harness --
   --nocapture` runs in the container so you watch every per-round
   `leak-harness <path> round <N> OK` line as the 9 tests
   exercise the engine. Three of those tests are the adversarial
   fail-closed branches - they specifically test that a fresh
   canary cannot survive the redaction path.

Canaries in scenarios 1 and 2 are generated fresh from the system
clock + the process id on every invocation, so the BEFORE bytes
change every time you re-run the demo. Nothing canary-shaped is
ever committed to the repo.

If any check fails the script exits non-zero with the failing
scenario's output still on screen.

---

## (c) Top three uncertainties / riskiest assumptions

These are the three places the engine's design or its test
coverage is weakest. They are all documented in
`docs/THREAT_MODEL.md`; surfacing them here so the reviewer
specifically asks about them rather than discovering them later.

**1. The engine-level idempotence test passes trivially at M0b.**
The engine claims `scrub(scrub(x)) == scrub(x)` and a unit test
asserts it. But at M0b the engine's detection uses only
exact-match, so the first scrub replaces the registered value with
a fake the Aho-Corasick automaton cannot find; the second scrub's
input contains zero matches; the test passes without ever calling
`IdempotenceContext::classify`. The per-candidate idempotence
proof - the load-bearing one - lives in `idempotence.rs`'s unit
tests and DOES run, so the *property* is genuinely tested. But the
*engine-level integration test* would also pass if someone
accidentally reversed the engine's classify-then-tokenize order.
M2 wires the pattern matcher into the engine and must add an
engine-level test where the input contains only fakes (which the
pattern matcher would still match) so a reordering is caught.
Threat-model Row 12 documents this.

**2. Formatless restorability is in-process only.** Long
Formatless values (e.g. passphrases) get a MAC-tagged fake of
matching length, which is restorable through an in-memory session
map. But there's no on-disk session file yet - that arrives with
M1's `--session` flag. A user running the (future) CLI in two
separate processes (`invisibool scrub` then `invisibool restore`
minutes later) will NOT round-trip Formatless values today. The
engine emits a `SessionMappedUnrestorable` notice at scrub time so
the user is told plainly. This is acceptable for a library-only
M0b deliverable, but it is a real limitation that the M1 CLI will
need to close cleanly. Threat-model Row 9 documents this.

**3. The CI bench-regression tripwire is in bootstrap state.** The
committed `bench-baseline.json` carries
`pending_first_ci_baseline: true`. The regression script reads
that flag and prints informational numbers without firing the
tripwire. The first real baseline only takes effect when a
maintainer runs the `workflow_dispatch` `bench-baseline-regen` job
on the pinned runner class and commits the JSON it emits. So the
p50 < 1 ms / p99 < 5 ms per-call latency target is currently the
**design budget**, not a measured-and-validated CI-enforced
number. Local bench medians on a developer box (see (d) below)
are in the right neighbourhood but cannot stand in for the CI
baseline; the published two-number README pair will land at M4c.
The runbook for refreshing the baseline lives at
`docs/RUNBOOK_baseline_refresh.md`.

---

## (d) What could go wrong, how it was tested, actual numbers

### The three failure modes the project actively guards against

**(1) A real value leaks into the scrub output.** This is the
worst failure - the engine claims to scrub but a real secret
appears in the output anyway. Tested by the integration leak
harness (`crates/invisibool-engine/tests/leak_harness.rs`). On
every PR, 9 tests run with fresh runtime canaries:

| Test | What it asserts |
|---|---|
| `ff1_path_does_not_leak_and_round_trips` | FF1 scrub removes canary; restore brings it back; canary absent from every Debug surface during scrub. |
| `pii_email_path_does_not_leak` | Reserved-range email fake emitted; canary absent from every channel. |
| `card_path_does_not_leak` | Test-BIN card fake emitted; canary absent from every channel. |
| `formatless_long_body_mac_fake_does_not_leak` | MAC-tagged fake emitted; verifies under the session MAC key; canary absent from every channel. |
| `formatless_short_body_carveout_redacts_and_does_not_leak` | Carve-out: redaction placeholder emitted; `RedactedFormatless` notice fires; canary absent from every channel. |
| `ff1_eligibility_failure_redacts_and_does_not_leak` | FF1 eligibility re-check failure: placeholder emitted; `RedactedInternalFailure` notice fires; canary absent. |
| `card_layout_mismatch_redacts_and_does_not_leak` | Unrecognised card layout (Amex 15-digit): placeholder emitted; `RedactedInternalFailure` notice fires; canary absent. |
| `formatless_mac_fake_round_trips_through_session_map` | In-process session-mode round-trip: scrub-with-session emits MAC-fake stored in map; restore-with-session brings the canary back. |
| `redaction_placeholder_is_not_a_real_secret_shape` | Placeholder is ASCII, bracketed, and contains the project marker - pinned so a future change to it doesn't silently break downstream consumers. |

Each test loops `ROUNDS = 8` times with independently-generated
canaries. The "absent from every channel" check covers
`scrub.output`, the `{:?}` debug-format of `EngineScrubResult`,
each `ScrubNotice`'s individual debug-format, the debug-format of
the registered-value set, and the redaction placeholder itself.

**(2) A scrub call falls outside the per-call latency budget.**
Tested by Criterion benches (`crates/invisibool-engine/benches/scrub.rs`)
over a committed corpus
(`crates/invisibool-engine/tests/fixtures/`) on every PR. The
tripwire script (`scripts/bench-regression.py`) compares
per-bench medians against a committed baseline and fails iff
measured > 2× baseline. Currently in bootstrap state - see
uncertainty (3) above and the runbook for the path to a real
baseline.

**(3) The engine ships with an unsafe dependency or an unaudited
license.** Tested by `cargo deny check` (license allowlist,
multiple-version warn, only crates.io as a registry; configured
in `deny.toml`) and `cargo audit` (RustSec advisory DB). Both run
on every PR. `#![forbid(unsafe_code)]` at the crate root means the
engine itself cannot compile with any `unsafe` block.

### Actual numbers (as of this packet)

**Test counts** (from `cargo test --workspace` on a clean build):

| Suite | Tests | Notes |
|---|---|---|
| `invisibool-engine` lib | 140 | unit tests for detection, tokenization, idempotence, session map, engine |
| `invisibool-engine` integration | 9 | leak harness (`tests/leak_harness.rs`) |
| `invisibool` (CLI crate) | 0 | skeleton only; M1 fills this in |
| **Total** | **149** | all passing |

**Bench medians** (local WSL box, `cargo bench -p
invisibool-engine --bench scrub`, sample size 10, NOT
CI-validated):

| Bench | Input | Hits | Median | Throughput |
|---|---|---|---|---|
| `prose_2kb_three_secrets` | 2,048 B | 3 | ~26.5 µs | ~74 MiB/s |
| `source_64kb_no_secrets` | 65,536 B | 0 | ~1.75 µs | ~35 GiB/s |
| `log_1mb_no_secrets` | 1,048,576 B | 0 | ~46.4 µs | ~21 GiB/s |

The prose-with-3-secrets case is the primary latency target -
~26.5 µs sits well inside the p50 < 1 ms design budget. The
no-secrets cases dwarf the throughput because the matcher's
no-match path is essentially a memcmp pass.

**CI gates currently green:**
- `cargo fmt --check`
- `cargo clippy -D warnings`
- `cargo test --workspace`
- `cargo deny check`
- `cargo audit`
- `gitleaks detect` (over full git history, narrowly path-scoped
  allowlist at `crates/invisibool-engine/tests/fixtures/.*` +
  `rules/secrets.toml`)
- Leak harness (9 tests, `--nocapture`)
- Bench regression script (bootstrap mode - informational
  numbers, tripwire skipped pending first real baseline)

**Dependency footprint** of the engine crate (direct, by category):

| Category | Crates |
|---|---|
| Detection | `aho-corasick`, `regex` |
| Cryptography (audited, no hand-rolled) | `fpe`, `aes`, `hmac`, `sha2`, `hkdf`, `subtle` |
| Memory safety of secret bytes | `secrecy`, `zeroize` |
| Serialization (for future session-file hooks) | `serde`, `serde_json` |
| Dev-only (not shipped) | `criterion` |

Zero network dependencies in the engine crate. Verified by
inspection of `Cargo.toml` and confirmed by `cargo deny check` on
every PR.

---

## What the gate is, and what comes after

When the reviewer signs off on this packet - by running the demo
and confirming the four deliverables listed in this file's header
table are in place - M0b is closed and M1 starts. M1 brings the CLI surface
(`scrub`/`restore`/`register`/`list`/`forget`), the clipboard
`watch` daemon, the minimal AEAD-encrypted vault file behind the
OS-keychain trait, the `--session` flag for cross-process Formatless
round-trip, and the new threat-model rows that become live when
each of those surfaces ships.

Until then, the engine library described here is the M0b
deliverable and nothing more. Per the project's gate-review
protocol, no M1 code is written before this gate closes.
