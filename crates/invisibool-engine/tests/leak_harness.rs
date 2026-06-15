//! Leak harness.
//!
//! Asserts the engine's privacy contract on a fresh canary per run:
//! a registered value's plaintext appears only on restore's intended
//! primary output channel — never in scrub output, never in the
//! `{:?}` debug-format of any engine result or registration, never in
//! the engine's `REDACTION_PLACEHOLDER` sentinel.
//!
//! Canaries are generated at runtime from the system clock and the
//! process id; nothing in this file embeds a canary string in source.
//! Per-test progress is logged without ever printing the canary itself,
//! so even `cargo test -- --nocapture` cannot turn the harness into a
//! leak channel of its own.
//!
//! Coverage. The harness splits into two groups: the happy paths
//! (a fake IS produced and the canary must not survive) and the
//! adversarial fail-closed paths (the engine cannot produce a fake
//! and must redact rather than pass the canary through).
//!
//! Happy paths:
//!
//! - FF1 round-trip: scrub removes the canary, restore brings it back
//!   verbatim, and no intermediate Debug surface ever held the value.
//! - PII (email): the reserved-range generator emits a fake into the
//!   public test domain; the canary itself must not survive the scrub.
//! - Card: the test-BIN generator emits a `4242 ...` fake; the canary
//!   must not survive.
//!
//! Fail-closed paths — the leak class this harness exists to catch.
//! Each of the three branches replaces the canary with
//! `REDACTION_PLACEHOLDER` and emits a typed notice; the harness pins
//! both the leak-contract and the notice-shape:
//!
//! - Formatless registration → `ScrubNotice::RedactedFormatless`.
//! - FF1 eligibility re-check failure at scrub time (corrupt or
//!   migrated vault entry) → `ScrubNotice::RedactedInternalFailure`.
//! - Session-mapped Card whose layout the `fake_card_visa16` generator
//!   does not understand (e.g. an Amex 15-digit registration) →
//!   `ScrubNotice::RedactedInternalFailure`.
//!
//! Each test runs `ROUNDS` times with independent canaries so a one-in-
//! a-bunch lucky alignment cannot mask a leak.

use invisibool_engine::engine::{
    Engine, EngineRestoreResult, EngineScrubResult, ScrubNotice, REDACTION_PLACEHOLDER,
};
use invisibool_engine::tokenizer::alphabet::Alphabet;
use invisibool_engine::tokenizer::fpe::{
    FpeRegistration, InMemoryKeyProvider, PiiKind, RegisteredValue, SessionFakeKind,
    SessionRegistration, TWEAK_LEN,
};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const ROUNDS: usize = 8;
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// ---------- per-run canary entropy ----------

fn seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    let pid = u64::from(std::process::id());
    nanos
        .wrapping_mul(0x9E3779B97F4A7C15)
        .wrapping_add(pid.wrapping_mul(0xC2B2AE3D27D4EB4F))
        | 1
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn base62_body(state: &mut u64, len: usize) -> String {
    let mut body = String::with_capacity(len);
    for _ in 0..len {
        let n = xorshift(state);
        body.push(BASE62[(n as usize) % BASE62.len()] as char);
    }
    body
}

fn lowercase_alnum(state: &mut u64, len: usize) -> String {
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let n = xorshift(state);
        s.push(LOWER[(n as usize) % LOWER.len()] as char);
    }
    s
}

fn digits(state: &mut u64, len: usize) -> String {
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let n = xorshift(state);
        s.push((b'0' + (n % 10) as u8) as char);
    }
    s
}

// ---------- shared assertions ----------

/// The canary plaintext must not appear in any escape channel:
///
/// - the primary `scrub.output` string,
/// - the top-level `EngineScrubResult` debug-format,
/// - each individual `ScrubNotice` debug-format (belt-and-braces: a
///   future variant that adds a value-carrying field is caught even if
///   the top-level Debug elides it),
/// - the debug-format of the registered-value set,
/// - or the `REDACTION_PLACEHOLDER` sentinel (pinned so a future
///   templated placeholder can't accidentally interpolate the canary).
///
/// Restore output is intentionally excluded — that is the one channel
/// the canary is supposed to come back through.
fn assert_no_leak_in_scrub(
    canary: &str,
    scrub: &EngineScrubResult,
    registrations: &[RegisteredValue],
    path: &str,
    round: usize,
) {
    assert!(
        !scrub.output.contains(canary),
        "[{path} #{round}] scrub.output leaked the canary plaintext",
    );
    let dbg_result = format!("{scrub:?}");
    assert!(
        !dbg_result.contains(canary),
        "[{path} #{round}] EngineScrubResult Debug leaked the canary plaintext",
    );
    for (i, notice) in scrub.notices.iter().enumerate() {
        let dbg_notice = format!("{notice:?}");
        assert!(
            !dbg_notice.contains(canary),
            "[{path} #{round}] ScrubNotice #{i} Debug leaked the canary plaintext",
        );
    }
    let dbg_regs = format!("{registrations:?}");
    assert!(
        !dbg_regs.contains(canary),
        "[{path} #{round}] registered-value Debug leaked the canary plaintext",
    );
    assert!(
        !REDACTION_PLACEHOLDER.contains(canary),
        "[{path} #{round}] REDACTION_PLACEHOLDER unexpectedly contains the canary",
    );
}

/// Helper for the three fail-closed branches. They share the same
/// shape: scrub must remove the canary, emit REDACTION_PLACEHOLDER in
/// its place, and emit at least one notice of the expected variant.
fn assert_failclose_branch(
    scrub: &EngineScrubResult,
    canary: &str,
    expect: FailCloseVariant,
    path: &str,
    round: usize,
) {
    assert_eq!(scrub.scrubbed_count, 1, "[{path} #{round}] scrub miss");
    assert!(
        scrub.output.contains(REDACTION_PLACEHOLDER),
        "[{path} #{round}] redaction placeholder not emitted; output was: {}",
        // Don't print the output verbatim if it contains the canary —
        // but at this point we've already asserted it doesn't via the
        // caller's earlier assert_no_leak_in_scrub call. Still, defend
        // in depth by replacing the canary with a sentinel before
        // formatting.
        scrub.output.replace(canary, "<canary-elided>"),
    );
    let matched = scrub.notices.iter().any(|n| {
        matches!(
            (expect, n),
            (
                FailCloseVariant::Formatless,
                ScrubNotice::RedactedFormatless { .. }
            ) | (
                FailCloseVariant::InternalFailure,
                ScrubNotice::RedactedInternalFailure { .. }
            )
        )
    });
    assert!(
        matched,
        "[{path} #{round}] expected a {expect:?} notice; got {:?}",
        scrub.notices,
    );
}

#[derive(Copy, Clone, Debug)]
enum FailCloseVariant {
    Formatless,
    InternalFailure,
}

fn build_engine(registered: Vec<RegisteredValue>) -> (Engine, Vec<RegisteredValue>) {
    let key_provider = InMemoryKeyProvider::new(vec![0xa5u8; 32]);
    // Clone the registrations so we can both move them into the engine
    // and keep a copy to debug-format below the engine call.
    let dbg_copy = clone_registered(&registered);
    let engine = Engine::new(
        &key_provider,
        registered,
        Vec::new(),
        b"leak-harness-mac-key".to_vec(),
    )
    .expect("engine builds");
    (engine, dbg_copy)
}

fn clone_registered(src: &[RegisteredValue]) -> Vec<RegisteredValue> {
    src.iter()
        .map(|r| match r {
            RegisteredValue::Fpe(f) => RegisteredValue::Fpe(FpeRegistration {
                label: f.label.clone(),
                value: Zeroizing::new(f.value.to_string()),
                tweak: f.tweak,
                alphabet: f.alphabet.clone(),
                prefix: f.prefix.clone(),
            }),
            RegisteredValue::SessionMapped(s) => {
                RegisteredValue::SessionMapped(SessionRegistration {
                    label: s.label.clone(),
                    value: Zeroizing::new(s.value.to_string()),
                    kind: s.kind,
                })
            }
        })
        .collect()
}

// ---------- the four scrub paths ----------

#[test]
fn ff1_path_does_not_leak_and_round_trips() {
    let mut state = seed();
    for round in 0..ROUNDS {
        let body = base62_body(&mut state, 20);
        let canary = format!("cnry-{body}");
        let input = format!("the canary is {canary} please scrub it");

        let mut tweak = [0u8; TWEAK_LEN];
        tweak[0] = round as u8;
        let registered = vec![RegisteredValue::Fpe(FpeRegistration {
            label: format!("ff1-canary-{round}"),
            value: Zeroizing::new(canary.clone()),
            tweak,
            alphabet: Alphabet::BASE62,
            prefix: "cnry-".to_string(),
        })];
        let (engine, regs_dbg) = build_engine(registered);

        let scrub = engine.scrub(&input);
        assert_eq!(scrub.scrubbed_count, 1, "FF1 round {round} scrub miss");
        assert_no_leak_in_scrub(&canary, &scrub, &regs_dbg, "ff1", round);

        // Restore is the intended channel; the canary IS allowed here.
        let restored: EngineRestoreResult = engine.restore(&scrub.output);
        assert_eq!(restored.restored_count, 1, "FF1 round {round} restore miss");
        assert_eq!(
            restored.output, input,
            "FF1 round {round} restore did not round-trip"
        );

        println!("leak-harness ff1 round {round} OK");
    }
}

#[test]
fn pii_email_path_does_not_leak() {
    let mut state = seed();
    for round in 0..ROUNDS {
        let local = lowercase_alnum(&mut state, 10);
        let canary = format!("{local}@example.com");
        let input = format!("ping {canary} about the issue");

        let registered = vec![RegisteredValue::SessionMapped(SessionRegistration {
            label: format!("pii-canary-{round}"),
            value: Zeroizing::new(canary.clone()),
            kind: SessionFakeKind::Pii(PiiKind::Email),
        })];
        let (engine, regs_dbg) = build_engine(registered);

        let scrub = engine.scrub(&input);
        assert_eq!(scrub.scrubbed_count, 1, "PII round {round} scrub miss");
        assert_no_leak_in_scrub(&canary, &scrub, &regs_dbg, "pii-email", round);

        // PII does not round-trip in stateless mode at this layer; the
        // engine emits a notice instead. The harness's job is just to
        // confirm no leak.
        println!("leak-harness pii-email round {round} OK");
    }
}

#[test]
fn card_path_does_not_leak() {
    let mut state = seed();
    for round in 0..ROUNDS {
        // 4xxx xxxx xxxx xxxx — Visa shape, runtime-generated digits.
        // The leading 4 is fixed (Visa BIN); the remaining 15 are random
        // so the canary is fresh per round.
        let mut canary = String::with_capacity(19);
        canary.push('4');
        let body = digits(&mut state, 15);
        for (i, ch) in body.chars().enumerate() {
            if i % 4 == 3 {
                canary.push(' ');
            }
            canary.push(ch);
        }
        let input = format!("card is {canary} on file");

        let registered = vec![RegisteredValue::SessionMapped(SessionRegistration {
            label: format!("card-canary-{round}"),
            value: Zeroizing::new(canary.clone()),
            kind: SessionFakeKind::Card,
        })];
        let (engine, regs_dbg) = build_engine(registered);

        let scrub = engine.scrub(&input);
        assert_eq!(scrub.scrubbed_count, 1, "card round {round} scrub miss");
        assert_no_leak_in_scrub(&canary, &scrub, &regs_dbg, "card", round);

        println!("leak-harness card round {round} OK");
    }
}

// ---------- fail-closed branches (the leak class this harness exists for) ----------
//
// Three engine branches replace the original value with REDACTION_PLACEHOLDER
// when a fake cannot be produced. The harness exercises each by name —
// these are the paths that USED to be capable of leaking a real secret
// back through to the LLM and that the engine's fail-closed contract
// turned into redactions instead. Each test asserts both the leak-
// contract (canary absent from every escape channel) and the contract-
// shape (placeholder present + the expected notice variant fired).

#[test]
fn formatless_path_redacts_and_does_not_leak() {
    let mut state = seed();
    for round in 0..ROUNDS {
        // A short alphabetic string is FF1-ineligible (domain too small),
        // which is exactly the case the engine routes to Formatless and
        // fails closed by replacing with REDACTION_PLACEHOLDER.
        let canary = lowercase_alnum(&mut state, 6);
        let input = format!("pin is {canary} keep secret");

        let registered = vec![RegisteredValue::SessionMapped(SessionRegistration {
            label: format!("formatless-canary-{round}"),
            value: Zeroizing::new(canary.clone()),
            kind: SessionFakeKind::Formatless,
        })];
        let (engine, regs_dbg) = build_engine(registered);

        let scrub = engine.scrub(&input);
        assert_no_leak_in_scrub(&canary, &scrub, &regs_dbg, "formatless", round);
        assert_failclose_branch(
            &scrub,
            &canary,
            FailCloseVariant::Formatless,
            "formatless",
            round,
        );

        println!("leak-harness formatless round {round} OK");
    }
}

#[test]
fn ff1_eligibility_failure_redacts_and_does_not_leak() {
    // FF1 eligibility is checked at registration AND re-checked at
    // scrub time. If a corrupt or migrated vault entry slips a value
    // through that fails the scrub-time re-check, the engine MUST
    // redact rather than let the value pass through. The smallest way
    // to trigger this is to register a value whose `prefix` equals the
    // whole value — body length 0, so radix^0 = 1 is below the FF1
    // domain floor and the eligibility check fails at scrub time.
    let mut state = seed();
    for round in 0..ROUNDS {
        // 3-char BASE62 body: 62^3 = 238_328 < the 10^6 FF1 domain
        // floor, so eligibility fails at scrub time. The prefix is a
        // benign fixed label (not the canary) so the harness's Debug
        // pin only fires on the real value, not on prefix metadata.
        let body = base62_body(&mut state, 3);
        let canary = format!("brkn-{body}");

        let input = format!("the broken token is {canary} here");

        let mut tweak = [0u8; TWEAK_LEN];
        tweak[0] = round as u8;
        let registered = vec![RegisteredValue::Fpe(FpeRegistration {
            label: format!("ff1-err-canary-{round}"),
            value: Zeroizing::new(canary.clone()),
            tweak,
            alphabet: Alphabet::BASE62,
            prefix: "brkn-".to_string(),
        })];
        let (engine, regs_dbg) = build_engine(registered);

        let scrub = engine.scrub(&input);
        assert_no_leak_in_scrub(&canary, &scrub, &regs_dbg, "ff1-error", round);
        assert_failclose_branch(
            &scrub,
            &canary,
            FailCloseVariant::InternalFailure,
            "ff1-error",
            round,
        );

        println!("leak-harness ff1-error round {round} OK");
    }
}

#[test]
fn card_layout_mismatch_redacts_and_does_not_leak() {
    // The session-mapped card generator only understands the 16-digit
    // Visa shape `4xxx xxxx xxxx xxxx`. An Amex-shaped 15-digit
    // registration (`3xxx xxxxxx xxxxx`) routes into the Card path,
    // `fake_card_visa16` returns None, and the engine fails closed —
    // the canary must not survive.
    let mut state = seed();
    for round in 0..ROUNDS {
        let mut canary = String::with_capacity(17);
        canary.push('3');
        canary.push_str(&digits(&mut state, 3));
        canary.push(' ');
        canary.push_str(&digits(&mut state, 6));
        canary.push(' ');
        canary.push_str(&digits(&mut state, 5));
        let input = format!("my card is {canary} on file");

        let registered = vec![RegisteredValue::SessionMapped(SessionRegistration {
            label: format!("card-non16-canary-{round}"),
            value: Zeroizing::new(canary.clone()),
            kind: SessionFakeKind::Card,
        })];
        let (engine, regs_dbg) = build_engine(registered);

        let scrub = engine.scrub(&input);
        assert_no_leak_in_scrub(&canary, &scrub, &regs_dbg, "card-non16", round);
        assert_failclose_branch(
            &scrub,
            &canary,
            FailCloseVariant::InternalFailure,
            "card-non16",
            round,
        );

        println!("leak-harness card-non16 round {round} OK");
    }
}

#[test]
fn redaction_placeholder_is_not_a_real_secret_shape() {
    // The sentinel must be distinctive and ASCII-only so downstream
    // tooling can match it without false positives. Pinning the literal
    // here means a future drift in the engine constant trips a clear
    // leak-harness failure rather than a subtle behaviour change.
    assert!(REDACTION_PLACEHOLDER.is_ascii());
    assert!(REDACTION_PLACEHOLDER.starts_with('['));
    assert!(REDACTION_PLACEHOLDER.ends_with(']'));
    assert!(REDACTION_PLACEHOLDER.contains("INVISIBOOL"));
}
