//! M0b gate demo. Executes the engine-level scenarios that
//! `demo/m0b.sh` wraps for the human reviewer:
//!
//!   1. FF1 round-trip on a registered API-key-shaped value: a
//!      runtime canary is registered, scrubbed (original gone, a
//!      same-length fake in its place), and restored byte-exact.
//!
//!   2. Fail-closed redaction on a short Formatless value (a PIN
//!      below the BASE62 MAC-tail floor of K=6): the engine emits
//!      the `[INVISIBOOL_UNRESTORABLE]` placeholder plus a typed
//!      `RedactedFormatless` notice. The original PIN must not
//!      survive.
//!
//! Each scenario prints BEFORE / SCRUB / (RESTORE) / CHECK lines and
//! ends in a `[PASS]` or `[FAIL]` marker. The binary exits non-zero
//! if any check fails so the demo wrapper propagates the failure.
//!
//! Canaries are generated at runtime from the system clock and the
//! process id; nothing in this file embeds a canary string in
//! source. Re-running the binary produces fresh canaries each time -
//! the reviewer can verify by running the demo twice and seeing the
//! BEFORE bytes change.
//!
//! Run inside the dev container (the wrapper does this for you):
//!     cargo run --example m0b_demo -p invisibool-engine

use invisibool_engine::engine::{Engine, ScrubNotice, REDACTION_PLACEHOLDER};
use invisibool_engine::tokenizer::alphabet::Alphabet;
use invisibool_engine::tokenizer::fpe::{
    FpeRegistration, InMemoryKeyProvider, RegisteredValue, SessionFakeKind, SessionRegistration,
    TWEAK_LEN,
};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn main() {
    let mut state = seed();
    println!();
    let s1 = scenario_1_ff1_round_trip(&mut state);
    println!();
    let s2 = scenario_2_formatless_fail_closed(&mut state);
    println!();
    let overall = s1 && s2;
    if overall {
        println!("==> all engine-demo scenarios PASSED");
        std::process::exit(0);
    } else {
        println!("==> at least one engine-demo scenario FAILED");
        std::process::exit(1);
    }
}

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

fn random_body(state: &mut u64, alphabet: &[u8], len: usize) -> String {
    (0..len)
        .map(|_| alphabet[(xorshift(state) as usize) % alphabet.len()] as char)
        .collect()
}

// ---------- Scenario 1: FF1 round-trip ----------

fn scenario_1_ff1_round_trip(state: &mut u64) -> bool {
    println!("--- Scenario 1: FF1 round-trip on a registered API-key-shaped value");

    // Canary shape: sk-test- + DEMO + 16 random BASE62 chars. The
    // literal "DEMO" makes the runtime canary visually obvious as a
    // demo value rather than a real key. Body length 20 is far above
    // the FF1 minimum domain.
    let body = format!("DEMO{}", random_body(state, BASE62, 16));
    let canary = format!("sk-test-{body}");
    let input = format!("the api token is {canary} for the staging deploy");

    let key_provider = InMemoryKeyProvider::new(vec![0xa5u8; 32]);
    let mut tweak = [0u8; TWEAK_LEN];
    tweak[0] = 0x11;
    let engine = Engine::new(
        &key_provider,
        vec![RegisteredValue::Fpe(FpeRegistration {
            label: "staging-api-token".to_string(),
            value: Zeroizing::new(canary.clone()),
            tweak,
            alphabet: Alphabet::BASE62,
            prefix: "sk-test-".to_string(),
        })],
        vec![],
        b"m0b-demo-mac-key".to_vec(),
    )
    .expect("engine builds");

    println!("  BEFORE   {input}");

    let scrubbed = engine.scrub(&input);
    println!("  SCRUB    {}", scrubbed.output);

    let original_gone = !scrubbed.output.contains(&canary);
    let fake_same_length = scrubbed.output.len() == input.len();
    println!(
        "  CHECK    original '{canary}' absent from scrub output?  {}",
        bool_str(original_gone)
    );
    println!(
        "  CHECK    fake preserved input length ({} bytes)?  {}",
        input.len(),
        bool_str(fake_same_length)
    );

    let restored = engine.restore(&scrubbed.output);
    println!("  RESTORE  {}", restored.output);

    let byte_exact = restored.output == input;
    println!(
        "  CHECK    restored bytes == original bytes?  {}",
        bool_str(byte_exact)
    );

    let pass = original_gone && fake_same_length && byte_exact;
    println!("  Result:  {}", pass_fail_str(pass));
    pass
}

// ---------- Scenario 2: Fail-closed Formatless ----------

fn scenario_2_formatless_fail_closed(state: &mut u64) -> bool {
    println!("--- Scenario 2: short Formatless value fails closed (PIN -> redaction)");

    // 4-char alphanumeric PIN - below the 6-char BASE62 MAC-tail
    // floor, so `make_macfake` returns None and the engine fails
    // closed with the redaction placeholder + a RedactedFormatless
    // notice. The original PIN must not survive in the output.
    let pin = random_body(state, LOWER_ALNUM, 4);
    let input = format!("my pin is {pin} please don't leak it");

    let key_provider = InMemoryKeyProvider::new(vec![0xa5u8; 32]);
    let engine = Engine::new(
        &key_provider,
        vec![RegisteredValue::SessionMapped(SessionRegistration {
            label: "pin-demo".to_string(),
            value: Zeroizing::new(pin.clone()),
            kind: SessionFakeKind::Formatless,
        })],
        vec![],
        b"m0b-demo-mac-key".to_vec(),
    )
    .expect("engine builds");

    println!("  BEFORE   {input}");

    let scrubbed = engine.scrub(&input);
    println!("  SCRUB    {}", scrubbed.output);

    let original_gone = !scrubbed.output.contains(&pin);
    let placeholder_present = scrubbed.output.contains(REDACTION_PLACEHOLDER);
    let notice_fired = scrubbed
        .notices
        .iter()
        .any(|n| matches!(n, ScrubNotice::RedactedFormatless { .. }));

    println!(
        "  CHECK    original PIN '{pin}' absent from output?  {}",
        bool_str(original_gone)
    );
    println!(
        "  CHECK    redaction placeholder present?  {}",
        bool_str(placeholder_present)
    );
    println!(
        "  CHECK    RedactedFormatless notice emitted?  {}",
        bool_str(notice_fired)
    );

    let pass = original_gone && placeholder_present && notice_fired;
    println!("  Result:  {}", pass_fail_str(pass));
    pass
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "YES"
    } else {
        "NO "
    }
}

fn pass_fail_str(b: bool) -> &'static str {
    if b {
        "[PASS]"
    } else {
        "[FAIL]"
    }
}
