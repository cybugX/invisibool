# Architecture

This document describes what the engine **is** and **does** — the
modules, the types, and the data flow from an input string to a
scrubbed output and back. It does not make security claims; for the
properties the engine is designed to give you (and the residuals it
does not), read `docs/THREAT_MODEL.md` alongside this file.

The scope is the M0b engine library — the surface-agnostic core that
later surfaces (the CLI, the clipboard `watch` daemon, a possible
future browser extension or traffic proxy) will reuse. The shape
described here is the shape of `crates/invisibool-engine/`.

## Workspace layout

The repository is a two-crate Cargo workspace:

| Crate | Purpose | M0b state |
|---|---|---|
| `invisibool-engine` | Library: detection, tokenization, fail-closed scrub/restore API | **Live** |
| `invisibool` | Binary: CLI, daemon, IPC, clipboard | **Skeleton only** — the M1 milestone fills this in |

The engine crate has zero network dependencies and carries
`#![forbid(unsafe_code)]`. The binary crate exists as a workspace
member so CI's `clippy -D warnings` and `cargo deny` policies cover
it from M0a forward.

## End-to-end data flow

### Scrub

The engine's scrub call walks the input left-to-right, dispatches
each exact-match hit through the idempotence classifier, then
through the tokenizer that matches the registration's kind. (At
M0b only the exact matcher is wired into this pass; pattern
detection is built but not invoked here — see the Detection layer
below.)

```
                          ┌──────────────────────┐
                          │   detect-then-       │
                          │  classify-then-      │
                          │     tokenize         │
                          └──────────────────────┘

  input ──► ExactMatcher ──► for each hit ──► IdempotenceContext.classify ─┐
   str    (Aho-Corasick)                                                    │
                                                                            │
                                            ┌───────────────────────────────┴──┐
                                            │                                  │
                                       NoOp(_): already                  decision = Scrub
                                       a fake. Pass                            │
                                       through unchanged.                      ▼
                                                                  ┌──────────────────────┐
                                                                  │  dispatch by kind:   │
                                                                  │  ─ FF1 (FpeReg)      │
                                                                  │  ─ PII (reserved)    │
                                                                  │  ─ Card (test BIN)   │
                                                                  │  ─ Formatless        │
                                                                  │    (MAC-tagged fake) │
                                                                  └──────────┬───────────┘
                                                                             │
                                                            ┌────────────────┴────────────┐
                                                            │                             │
                                                       fake produced               generator returned None
                                                            │                             │
                                                            ▼                             ▼
                                                   emit fake into                emit REDACTION_PLACEHOLDER
                                                   output; if session-           into output; push typed
                                                   mode, store (real,fake)       Redacted* ScrubNotice
                                                   in session map; else push
                                                   SessionMappedUnrestorable
                                                   notice
                                                            │                             │
                                                            └──────────────┬──────────────┘
                                                                           ▼
                                                              EngineScrubResult { output,
                                                                                  scrubbed_count,
                                                                                  notices }
```

Two scrub entry points share the same machinery via a private
`scrub_impl`:

- `Engine::scrub(&self, input)` — stateless. Session-mapped fakes
  (PII, Card, Formatless) are emitted with a
  `SessionMappedUnrestorable` notice because the engine has no place
  to store the (real, fake) pair for later restore.
- `Engine::scrub_with_session(&self, input, &mut SessionMap, Instant)`
  — same path with a caller-owned session map threaded through.
  Each session-mapped (real, fake) pair is stored in the map; the
  unrestorable notice is suppressed because the fake **is**
  restorable in-process via the caller's map.

### Restore

Restore is the dual but is not symmetric — it does not need
detection because the candidates are already in the input:

```
  input ─► (session-mode only) walk session.entries() for fakes ──► replace
   str       present in input; touch last_touched on each hit          │
                                                                       │
                                                                       ▼
        scan for substrings matching each FpeRegistration's profile
        (prefix + body_length + alphabet) ──► trial-decrypt body
                                              under each profile-
                                              matching registration's
                                              tweak; accept the match
                                              whose plaintext equals
                                              the registered value
                                              (constant-time compare)
                                                                       │
                                                                       ▼
                                                          EngineRestoreResult
                                                          { output, restored_count }
```

- `Engine::restore(&self, input)` — stateless FF1 restore only.
  Non-FF1 fakes (reserved-range, MAC-tagged) pass through unchanged.
- `Engine::restore_with_session(&self, input, &mut SessionMap, Instant)`
  — runs the session-map replacement pass first, then the FF1 pass
  over the result.

The two passes compose because the FF1 fake space (specific prefix +
body length + alphabet) and the session-stored fake space do not
overlap.

## Detection layer

`crates/invisibool-engine/src/detection/`

### Exact-match — `ExactMatcher` over a precompiled Aho-Corasick automaton

The exact matcher builds one Aho-Corasick automaton over the full
registered-value set when `Engine::new` runs. Each registered value
gets a `value_id` that the engine maps back to the right
registration via the engine's `value_id_to_ref` vector. Scanning is
O(input length + total matches) and runs once per scrub call.

### Pattern matching — `PatternMatcher` over one linear-time `RegexSet`

The pattern matcher is built but not yet wired into the engine's
scrub pass. The rule corpus (a set of public-format regexes for
detected-but-unregistered secrets) lands at M2; until then the
engine's detection pass uses exact-match alone. The matcher's
linear-time `RegexSet` design — no backtracking — pre-empts the
ReDoS class of attacks that would otherwise be possible on a
user-controlled prompt.

### `Detector` and overlap resolution

`detection::Detector` is the small front-end that, once M2 wires
the rule corpus, will run both matchers on the same input and
reconcile overlaps. The reconciliation policy is implemented now
and covered by unit tests in `detection::mod`; it only fires in
production once both matchers actually run together at M2. The
policy:

1. **Span length will win first.** A longer match beats a shorter
   one from a different matcher — so a registered prefix
   (e.g. `"AKIA"`) will not shadow a full-token pattern hit
   (`AKIA + 16 chars`).
2. **Within a tie, exact-match confidence beats pattern confidence.**
   Exact match is "this is on the user's vault"; a pattern hit is
   "this looks like a credential of this shape". The vault is the
   ground truth.

## Idempotence layer

`crates/invisibool-engine/src/idempotence.rs`

After detection, each candidate is classified by
`IdempotenceContext::classify` before any tokenizer touches it. The
three checks run in this order, and the first one that decides
ends the classification:

1. **Exact-match precedence.** If the candidate is byte-for-byte
   equal to a registered value, it is scrubbed normally. This rule
   sits at the top so a registered secret can never be "recognised
   as a fake" by the later checks; the vault always wins.
2. **Reserved-range membership.** If the candidate sits inside a
   reserved range (`@example.com` and friends, RFC 5737 test-net
   addresses, the 555-01XX phone exchange, the `4242` test BIN),
   it is already one of the engine's reserved-range fakes — emit
   unchanged.
3. **MAC verification.** If the candidate's tail verifies as a
   truncated keyed MAC over the preceding bytes, it is one of the
   engine's MAC-tagged self-authenticating fakes — emit unchanged.

A candidate that passes none of the three is the input "this is a
real secret, please scrub it" and the tokenizer dispatch runs.

The short-fake carve-out: candidates too short to embed a MAC tail
return false on check (c) without panicking, and idempotence falls
through to the other checks. Such fakes are not stateless-idempotent
in two-command CLI flow; the unrestorability is disclosed to the
user.

## Tokenizer dispatch

`crates/invisibool-engine/src/tokenizer/`

A registered value is one of two variants:

```
pub enum RegisteredValue {
    Fpe(FpeRegistration),         // → tokenizer/fpe.rs
    SessionMapped(SessionRegistration),
}

pub enum SessionFakeKind {
    Card,                         // → tokenizer/reserved.rs::fake_card_visa16
    Pii(PiiKind),                 // → tokenizer/reserved.rs::fake_{email,ipv4,phone}
    Formatless,                   // → tokenizer/mac.rs::make_macfake
}
```

### FF1 — `tokenizer/fpe.rs`

NIST SP 800-38G FF1-AES256 via the `fpe` crate. The FF1 subkey is
derived from the vault key by HKDF-SHA-256 with a versioned info
label (`invisibool-ff1-key-v1`) so the derivation can be rotated
without rotating the vault key. Per registered value, a 16-byte
tweak generated at registration parameterises a distinct
pseudorandom permutation, which prevents cross-value linkability
even when alphabets match.

FF1 eligibility is enforced twice: at registration (the future M4a
`register` command) and at scrub time as a safety net. The
scrub-time re-check exists for the rare case of a corrupt or
migrated vault entry — the engine fails closed if that re-check
fails. Restore decrypts a candidate's body with each
profile-matching registration's tweak and accepts the match whose
plaintext equals the registered value via `subtle::ConstantTimeEq`.

The `Alphabet` type (`tokenizer/alphabet.rs`) is the parameter to
FF1 and the MAC primitive. Construction of a custom alphabet
validates ASCII-only, no whitespace, distinct symbols, and radix in
[2, 65535] — the NIST SP 800-38G domain bounds.

### Reserved-range — `tokenizer/reserved.rs`

Deterministic generators that produce fakes inside well-known
no-collision ranges:

| Kind | Range | Why |
|---|---|---|
| Email | `@example.com` | Documentation domain, never delivers |
| IPv4 | RFC 5737 TEST-NET-1/2/3 | Reserved for documentation, never routes |
| Phone | `+1-555-01XX` | Reserved test exchange |
| Card | `4242 ...` (test BIN) | Public test BIN; Luhn-valid; never charges a real card |

Cards never go through FF1 because the card-number domain is too
small for FF1's bijection to be safe against a guess-and-check
attacker. Cards always take the reserved-range path.

### MAC-tagged fake — `tokenizer/mac.rs::make_macfake`

For Formatless values long enough to carry a MAC tail, the engine
emits a length-matched fake of the form `body || tail`:

- `body` (`N - K` characters) is derived deterministically from
  `HKDF-SHA-256(salt=empty, ikm=session_mac_key, info=real_value)`
  over the chosen alphabet's symbols.
- `tail` (`K` characters) is the truncated keyed MAC
  `HMAC-SHA-256(session_mac_key, body)` encoded in the alphabet.
- `K` is the smallest count of alphabet symbols whose information
  content reaches 32 bits (`K = ceil(32 / log2(radix))`).
- `N` is the registered value's length, so the fake is the same
  length as the real value.

The idempotence layer's check (c) recognises any string of length
`>= K` whose tail equals the keyed MAC of its preceding bytes — that
is, it accepts every fake `make_macfake` emits, regardless of
whether the (real, fake) pair is in any session map. The MAC scheme
is the engine's "this is one of ours" signal in stateless flows.

Values too short to carry the K-character tail trigger the
short-fake carve-out: `make_macfake` returns `None`, the engine
fails closed with `REDACTION_PLACEHOLDER` + a
`ScrubNotice::RedactedFormatless` notice.

### Session map — `tokenizer/session.rs`

`SessionMap` is a bounded bidirectional `{real ↔ fake}` map with
LRU + TTL eviction. Every public operation takes an explicit
`Instant`, so the map has no internal clock — tests construct
successive `Instant`s by adding `Duration`s, production callers
pass `Instant::now()`. Real values inside the map are
`Zeroizing`-wrapped; eviction paths (LRU, TTL prune, explicit
`clear`, collision overwrite, `Drop`) wipe both the `Entry`-side
copy and the plaintext `by_real` HashMap key.

At M0b the session map is wired into the engine via
`Engine::scrub_with_session` and `Engine::restore_with_session`.
The caller owns the `SessionMap`. The M1 `watch` daemon will hold
one open across clipboard events; the M1 CLI `--session` flag will
serialise it (AEAD-encrypted, `0600` permissions) to disk so a
two-command terminal flow can restore across processes.

## Fail-closed contract

`Engine::scrub` never returns a result whose `output` contains an
unscrubbed registered value. Three engine branches cannot produce
a valid fake; each fails CLOSED by replacing the candidate with
`REDACTION_PLACEHOLDER` (`[INVISIBOOL_UNRESTORABLE]`) and emitting
a typed `ScrubNotice` so the end-of-scrub disclosure surfaces what
was lost:

| Branch | Cause | Notice variant |
|---|---|---|
| FF1 eligibility failure at scrub time | Vault inconsistency: registration-time eligibility passed but scrub-time re-check failed (corrupt or migrated entry) | `RedactedInternalFailure` |
| Session-mapped Card with unsupported layout | `fake_card_visa16` only recognises the 16-digit Visa shape; a 15-digit Amex registration returns `None` | `RedactedInternalFailure` |
| Formatless short-fake carve-out | Registered value too short to carry a MAC tail (`len <= K`) | `RedactedFormatless` |

The integration test under `tests/leak_harness.rs` exercises each
branch with fresh runtime canaries on every PR. What that test
proves (and crucially, does *not* prove) is detailed in
`docs/THREAT_MODEL.md`.

## Restore: stateless vs session mode

The two restore entry points cover the two operating regimes the
engine supports today:

| Mode | API | What gets restored |
|---|---|---|
| Stateless | `Engine::restore(input)` | FF1 fakes only. Non-FF1 fakes (reserved-range, MAC-tagged) pass through unchanged — idempotence recognises them as fakes so they're safe to leave in place. |
| Session | `Engine::restore_with_session(input, &mut SessionMap, Instant)` | First pass: every session-stored fake is replaced by its registered real value. Second pass: FF1 restore over the result. Each session lookup touches the entry's `last_touched` so frequently-restored pairs keep their LRU/TTL standing. |

The session-mode restore is in-process only — it depends on a live
session map. A two-command CLI flow that scrubs in process A and
restores in process B cannot use session-mode at M0b. The M1 CLI's
`--session` flag will close that gap.

## Module map

For navigation:

```
crates/invisibool-engine/src/
├── lib.rs                          # re-exports Engine; #![forbid(unsafe_code)]
├── engine.rs                       # Engine, ScrubResult, RestoreResult,
│                                   # ScrubNotice, REDACTION_PLACEHOLDER,
│                                   # SessionStore (internal scrub-mode switch)
├── idempotence.rs                  # IdempotenceContext / IdempotenceDecision
│                                   # / three-check classify
├── detection/
│   ├── mod.rs                      # Detector + overlap resolution tests
│   ├── exact.rs                    # ExactMatcher (Aho-Corasick)
│   └── pattern.rs                  # PatternMatcher (RegexSet)
└── tokenizer/
    ├── mod.rs                      # module wiring
    ├── alphabet.rs                 # Alphabet + named constants + validation
    ├── fpe.rs                      # FpeTokenizer + RegisteredValue +
    │                               # FpeRegistration / SessionRegistration
    │                               # (manual Debug, value redacted)
    ├── reserved.rs                 # fake_email / fake_ipv4 / fake_phone /
    │                               # fake_card_visa16
    ├── mac.rs                      # mac_tail / verify / make_macfake
    └── session.rs                  # SessionMap (LRU + TTL,
                                    # zeroize on eviction)
```

The integration leak harness lives next to the crate, not in `src/`:

```
crates/invisibool-engine/
├── benches/
│   ├── scrub.rs                    # Criterion bench (uses tests/fixtures/)
│   └── ...
├── examples/
│   └── gen_bench_fixtures.rs       # deterministic generator
└── tests/
    ├── fixtures/                   # committed bench corpus
    │   ├── prose_2kb.txt
    │   ├── source_64kb.rs
    │   ├── log_1mb.log
    │   └── README.md
    └── leak_harness.rs             # runtime-canary harness, 9 tests
```

## What is not in the engine at M0b

These pieces have load-bearing roles in the project but are
explicitly out of scope for the M0b engine crate. Each will arrive
at its named milestone and plug into the engine via the public
types above:

- **CLI surface** (`crates/invisibool/src/main.rs`) — M1 brings
  `scrub` / `restore` / `register` / `list` / `forget`. M4a adds
  `rename` / `rotate-key`.
- **Clipboard `watch` daemon** — M1. Long-lived process, holds an
  `Engine` and a `SessionMap` open across events, talks to the CLI
  via a peer-checked Unix domain socket / Windows named pipe.
  Wayland is detected and refused; Windows / macOS / X11 are the
  v1 platforms.
- **Vault file** (AEAD-encrypted, OS-keychain-backed) — M1 brings a
  minimal vault for FF1 registered values. M4a hardens it
  (Argon2id passphrase fallback, auto-lock, strength guards on
  `register`, the `--no-exact-vault` opt-out).
- **`--session` flag** — M1. Writes an AEAD-encrypted session file
  (mode `0600`, TTL-bounded) so two-command CLI invocations can
  round-trip session-mapped fakes.
- **Pattern rule corpus** — M2. Wires `rules/secrets.toml` into
  the detection pass and adds the engine-level idempotence test
  that the current pattern-rule-less engine can't yet make
  load-bearing.
- **Browser extension / traffic proxy / document mocking** — out
  of scope for the M0–M4 CLI scrubber entirely; they are separate
  future projects that will reuse the same engine crate.
