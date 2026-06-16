//! Reserved-range fake generators.
//!
//! - Emails: `@example.com` domain (RFC 2606). Local-part is 10 lowercase
//!   letters derived from the seed.
//! - IPv4 addresses: 192.0.2.0/24 (RFC 5737 TEST-NET-1). The final octet
//!   is derived from the seed, giving 256 distinct fakes.
//! - Phone numbers: 555-01XX (the NANPA / IETF reserved exchange for
//!   fictional use). Two digits derived from the seed give 100 distinct
//!   fakes. M0b ships the 7-character local form only; full layouts
//!   (with area codes) can be added when callers need them.
//! - Card numbers (Visa-style, 16 digits): test BIN 4242 + 11
//!   seed-derived digits + Luhn check digit. The fake preserves the
//!   separator layout of the original input (spaces, hyphens, or none),
//!   so a "4111 1111 1111 1111" input produces a "4242 ABCD EFGH IJKM"-
//!   shaped output (digits A..M derived from seed).
//!
//! All generators are pure functions of their seed: identical seed bytes
//! always produce identical output. SHA-256 is used internally for
//! seed-to-digit derivation; the choice of hash is not part of the
//! public API and may change without a semver bump.

use sha2::{Digest, Sha256};

const EMAIL_DOMAIN: &str = "@example.com";
const EMAIL_LOCAL_LEN: usize = 10;
const IPV4_RFC5737_PREFIX: &str = "192.0.2.";
const PHONE_RESERVED_PREFIX: &str = "555-01";
const CARD_VISA_TEST_BIN: &str = "4242";
const CARD_VISA_DIGIT_COUNT: usize = 16;

/// Fake email address in the RFC 2606 `example.com` reserved domain. The
/// 10-character local part is lowercase ASCII letters derived
/// deterministically from `seed`.
pub fn fake_email(seed: &[u8]) -> String {
    let hash = Sha256::digest(seed);
    let mut out = String::with_capacity(EMAIL_LOCAL_LEN + EMAIL_DOMAIN.len());
    for byte in hash.iter().take(EMAIL_LOCAL_LEN) {
        // Map each hash byte to one of 26 lowercase letters. The modular
        // bias across 26 values is negligible for this use; this is
        // identifier generation, not a cryptographic random source.
        out.push(char::from(b'a' + byte % 26));
    }
    out.push_str(EMAIL_DOMAIN);
    out
}

/// Fake IPv4 address in the RFC 5737 TEST-NET-1 range (192.0.2.0/24).
/// The final octet (0..=255) is derived from `seed`.
pub fn fake_ipv4(seed: &[u8]) -> String {
    let hash = Sha256::digest(seed);
    format!("{}{}", IPV4_RFC5737_PREFIX, hash[0])
}

/// Fake phone number using the 555-01XX reserved exchange (NANPA / IETF
/// fictional-use range). Two seed-derived digits give 100 distinct fakes.
pub fn fake_phone(seed: &[u8]) -> String {
    let hash = Sha256::digest(seed);
    let suffix = hash[0] % 100;
    format!("{}{:02}", PHONE_RESERVED_PREFIX, suffix)
}

/// Luhn-valid Visa-style fake card number in the 4242 test BIN. The fake
/// reproduces the separator layout of `original` (e.g. "4242 4242 4242
/// 4242" or "4242-4242-4242-4242" or "4242424242424242"). Returns `None`
/// if `original` does not contain exactly 16 digits; other card formats
/// (Amex 15-digit, etc.) can be added in later milestones.
pub fn fake_card_visa16(seed: &[u8], original: &str) -> Option<String> {
    let chars: Vec<char> = original.chars().collect();
    let digit_count = chars.iter().filter(|c| c.is_ascii_digit()).count();
    if digit_count != CARD_VISA_DIGIT_COUNT {
        return None;
    }

    // Build the 16-digit fake: 4 BIN digits + 11 seed-derived digits + 1
    // Luhn check digit. We compute the first 15 then derive the 16th so
    // the whole number is Luhn-valid.
    let hash = Sha256::digest(seed);
    let mut digits = String::with_capacity(CARD_VISA_DIGIT_COUNT);
    digits.push_str(CARD_VISA_TEST_BIN);
    for byte in hash.iter().take(11) {
        digits.push(char::from(b'0' + byte % 10));
    }
    digits.push(char::from(b'0' + luhn_check_digit(&digits)));

    // Overlay the original's separator layout onto the 16-digit string.
    let mut out = String::with_capacity(chars.len());
    let mut digit_iter = digits.chars();
    for c in &chars {
        if c.is_ascii_digit() {
            out.push(
                digit_iter
                    .next()
                    .expect("digit count matched 16 above; iterator cannot be exhausted early"),
            );
        } else {
            out.push(*c);
        }
    }
    Some(out)
}

/// Compute the Luhn check digit (0..=9) for a partial card number. The
/// returned digit, when appended to `digits`, makes the resulting number
/// Luhn-valid. `digits` must contain only ASCII digit characters.
fn luhn_check_digit(digits: &str) -> u8 {
    // Standard Luhn computation. The check digit will sit at position 0
    // from the right; this routine's input digits will sit at positions
    // n, n-1, ..., 1. Digits at odd positions from the right (1, 3, ...)
    // are doubled; doubled values > 9 sum their digits (equivalent to
    // subtracting 9).
    let mut sum = 0u32;
    let n = digits.len();
    for (i, c) in digits.chars().enumerate() {
        let d = c
            .to_digit(10)
            .expect("digits parameter contains only ASCII digit characters");
        let position_from_right = n - i;
        let v = if position_from_right % 2 == 0 {
            d
        } else {
            d * 2
        };
        sum += if v > 9 { v - 9 } else { v };
    }
    u8::try_from((10 - sum % 10) % 10).expect("modulo-10 result fits in u8")
}

/// Returns true when `digits` (ASCII-digit-only) passes the Luhn checksum.
pub fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let n = digits.len();
    for (i, c) in digits.chars().enumerate() {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        // Position 0 from the right is the check digit (not doubled);
        // positions 1, 3, 5, ... are doubled.
        let position_from_right = n - 1 - i;
        let v = if position_from_right % 2 == 0 {
            d
        } else {
            d * 2
        };
        sum += if v > 9 { v - 9 } else { v };
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Email -----

    #[test]
    fn email_lands_in_example_com_domain() {
        let fake = fake_email(b"some-real-email@user.com");
        assert!(fake.ends_with("@example.com"));
    }

    #[test]
    fn email_local_part_is_lowercase_letters_of_fixed_length() {
        let fake = fake_email(b"seed");
        let local = fake.strip_suffix("@example.com").unwrap();
        assert_eq!(local.len(), 10);
        assert!(local.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn email_is_deterministic_in_seed() {
        assert_eq!(fake_email(b"alice"), fake_email(b"alice"));
    }

    #[test]
    fn email_different_seeds_yield_different_locals() {
        assert_ne!(fake_email(b"alice"), fake_email(b"bob"));
    }

    // ----- IPv4 -----

    #[test]
    fn ipv4_lands_in_rfc5737_testnet1() {
        for seed in [b"a".as_slice(), b"bb", b"ccc", b"long-seed-here"] {
            let fake = fake_ipv4(seed);
            assert!(fake.starts_with("192.0.2."), "got {fake}");
            let last = fake.strip_prefix("192.0.2.").unwrap();
            let n: u32 = last.parse().expect("last octet must be numeric");
            assert!(n <= 255);
        }
    }

    #[test]
    fn ipv4_is_deterministic_in_seed() {
        assert_eq!(fake_ipv4(b"some-ip"), fake_ipv4(b"some-ip"));
    }

    // ----- Phone -----

    #[test]
    fn phone_lands_in_555_01_reserved_exchange() {
        for seed in [b"x".as_slice(), b"yy", b"zzz", b"alice@example.com"] {
            let fake = fake_phone(seed);
            assert!(fake.starts_with("555-01"), "got {fake}");
            assert_eq!(fake.len(), 8); // "555-01XX"
            let suffix = fake.strip_prefix("555-01").unwrap();
            assert_eq!(suffix.len(), 2);
            assert!(suffix.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn phone_is_deterministic_in_seed() {
        assert_eq!(fake_phone(b"555-1234"), fake_phone(b"555-1234"));
    }

    // ----- Card -----

    #[test]
    fn card_visa16_uses_4242_test_bin() {
        let fake = fake_card_visa16(b"seed", "4242 4242 4242 4242").unwrap();
        let digits: String = fake.chars().filter(|c| c.is_ascii_digit()).collect();
        assert!(digits.starts_with("4242"));
    }

    #[test]
    fn card_visa16_is_luhn_valid() {
        // Use a non-test input so the Luhn check exercises a real
        // computation rather than echoing back a known test card.
        let fake = fake_card_visa16(b"seed", "1234567890123456").unwrap();
        let digits: String = fake.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits.len(), 16);
        assert!(luhn_valid(&digits), "Luhn failed for {digits}");
    }

    #[test]
    fn card_visa16_preserves_separator_layout_spaces() {
        let fake = fake_card_visa16(b"seed", "4111 1111 1111 1111").unwrap();
        assert_eq!(fake.len(), "4111 1111 1111 1111".len());
        assert_eq!(fake.chars().nth(4), Some(' '));
        assert_eq!(fake.chars().nth(9), Some(' '));
        assert_eq!(fake.chars().nth(14), Some(' '));
    }

    #[test]
    fn card_visa16_preserves_separator_layout_hyphens() {
        let fake = fake_card_visa16(b"seed", "4242-1234-5678-9012").unwrap();
        assert_eq!(fake.chars().nth(4), Some('-'));
        assert_eq!(fake.chars().nth(9), Some('-'));
        assert_eq!(fake.chars().nth(14), Some('-'));
    }

    #[test]
    fn card_visa16_preserves_no_separator_layout() {
        let fake = fake_card_visa16(b"seed", "4242424242424242").unwrap();
        assert_eq!(fake.len(), 16);
        assert!(fake.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn card_visa16_is_deterministic_in_seed() {
        assert_eq!(
            fake_card_visa16(b"seed", "4242 4242 4242 4242"),
            fake_card_visa16(b"seed", "4242 4242 4242 4242"),
        );
    }

    #[test]
    fn card_visa16_different_seeds_yield_different_digits() {
        // Same layout, different seed → different digits (collision is
        // negligible).
        let a = fake_card_visa16(b"alpha", "4242 4242 4242 4242").unwrap();
        let b = fake_card_visa16(b"beta", "4242 4242 4242 4242").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn card_visa16_rejects_non_16_digit_input() {
        // 15 digits (Amex-shaped) - out of scope for M0b's Visa-only generator.
        assert!(fake_card_visa16(b"seed", "3782 822463 10005").is_none());
        // 8 digits
        assert!(fake_card_visa16(b"seed", "12345678").is_none());
        // empty
        assert!(fake_card_visa16(b"seed", "").is_none());
    }

    // ----- Luhn helpers -----

    #[test]
    fn luhn_valid_recognises_stripes_documented_test_card() {
        assert!(luhn_valid("4242424242424242"));
    }

    #[test]
    fn luhn_valid_rejects_off_by_one_card() {
        assert!(!luhn_valid("4242424242424241"));
    }

    #[test]
    fn luhn_check_digit_completes_known_card() {
        // 424242424242424 (15 digits) + check = 4242424242424242.
        assert_eq!(luhn_check_digit("424242424242424"), 2);
    }
}
