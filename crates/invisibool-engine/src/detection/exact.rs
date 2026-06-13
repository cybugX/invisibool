//! Exact-match detection over registered vault values.
//!
//! One precompiled Aho-Corasick automaton scans the full input in linear
//! time and reports every leftmost-longest non-overlapping match. This is
//! the highest-confidence detector per build-prompt §A5 (no guessing,
//! near-zero false positives for the user's own data) and the differentiator
//! versus detection-only tools.
//!
//! Per build-prompt §A4.5 rule 1, the automaton is built ONCE at
//! load/update time and reused across every scan — never rebuilt per
//! request.

use aho_corasick::{AhoCorasick, MatchKind as AcMatchKind};

use super::{Match, MatchKind};

/// A precompiled exact-match detector over a snapshot of registered values.
///
/// Build once, scan many times. Rebuild only when the registered value set
/// changes (e.g. `register` / `forget` from the future CLI in M1).
pub struct ExactMatcher {
    /// `None` when the registered value set is empty. Avoiding the
    /// Aho-Corasick build for an empty vault keeps both startup and scan
    /// allocation-free in the "vault not populated yet" case rather than
    /// fighting AC's "I need at least one pattern" error.
    automaton: Option<AhoCorasick>,
}

impl ExactMatcher {
    /// Build a fresh matcher over registered values in the given order.
    /// Each value's index in this iterator is its `value_id` in returned
    /// matches.
    ///
    /// Match policy: **leftmost-longest** — when registered "abc" and
    /// "abcdef" both match at the same offset, "abcdef" wins. Substituting
    /// the longer registered value is the safer default because picking
    /// the shorter one would leave a partial-secret tail in the output.
    pub fn build<I, S>(values: I) -> Result<Self, aho_corasick::BuildError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let patterns: Vec<Vec<u8>> = values.into_iter().map(|s| s.as_ref().to_vec()).collect();

        let automaton = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(AcMatchKind::LeftmostLongest)
                    .build(&patterns)?,
            )
        };

        Ok(Self { automaton })
    }

    /// Scan an input string and return all leftmost-longest non-overlapping
    /// matches in source order. Empty when no values were registered, or
    /// no value appears in the input.
    pub fn scan(&self, input: &str) -> Vec<Match> {
        let Some(ac) = self.automaton.as_ref() else {
            return Vec::new();
        };

        ac.find_iter(input)
            .map(|m| Match {
                start: m.start(),
                end: m.end(),
                kind: MatchKind::Exact {
                    value_id: m.pattern().as_usize(),
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_vault_returns_no_matches() {
        let m = ExactMatcher::build::<_, &str>(std::iter::empty()).unwrap();
        assert_eq!(m.scan("any input at all"), vec![]);
    }

    #[test]
    fn single_value_single_hit() {
        let m = ExactMatcher::build(["sk-secret-key-abc"]).unwrap();
        let hits = m.scan("here is sk-secret-key-abc inline");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].start, 8);
        assert_eq!(hits[0].end, 8 + "sk-secret-key-abc".len());
        assert_eq!(hits[0].kind, MatchKind::Exact { value_id: 0 });
    }

    #[test]
    fn single_value_no_hit() {
        let m = ExactMatcher::build(["sk-secret-key-abc"]).unwrap();
        assert_eq!(m.scan("unrelated text"), vec![]);
    }

    #[test]
    fn empty_input_returns_no_matches() {
        let m = ExactMatcher::build(["anything"]).unwrap();
        assert_eq!(m.scan(""), vec![]);
    }

    #[test]
    fn multiple_non_overlapping_hits_in_source_order() {
        let m = ExactMatcher::build(["alpha", "beta"]).unwrap();
        let hits = m.scan("alpha then beta then alpha again");
        // Three hits in source order: alpha@0, beta@11, alpha@21
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].kind, MatchKind::Exact { value_id: 0 });
        assert_eq!(hits[0].start, 0);
        assert_eq!(hits[1].kind, MatchKind::Exact { value_id: 1 });
        assert_eq!(hits[1].start, 11);
        assert_eq!(hits[2].kind, MatchKind::Exact { value_id: 0 });
        assert_eq!(hits[2].start, 21);
    }

    #[test]
    fn longest_match_wins_at_same_offset() {
        // Both "abc" and "abcdef" registered; input contains "abcdef".
        // Leftmost-longest must pick "abcdef" — picking the shorter would
        // leave "def" un-scrubbed in the output, the failure mode this
        // policy exists to prevent.
        let m = ExactMatcher::build(["abc", "abcdef"]).unwrap();
        let hits = m.scan("xxx abcdef yyy");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].start, 4);
        assert_eq!(hits[0].end, 10);
        // value_id 1 is "abcdef" (registered second).
        assert_eq!(hits[0].kind, MatchKind::Exact { value_id: 1 });
    }

    #[test]
    fn shorter_match_fires_when_longer_does_not_fit() {
        // Same registration as above; this input has only "abc", so we fall
        // through to value_id 0.
        let m = ExactMatcher::build(["abc", "abcdef"]).unwrap();
        let hits = m.scan("xxx abc yyy");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].start, 4);
        assert_eq!(hits[0].end, 7);
        assert_eq!(hits[0].kind, MatchKind::Exact { value_id: 0 });
    }

    #[test]
    fn value_id_tracks_registration_order() {
        // The value_id must correspond to the registration index so callers
        // can map back to their own label / metadata.
        let m = ExactMatcher::build(["foo", "bar", "baz"]).unwrap();
        let hits = m.scan("baz then foo then bar");
        assert_eq!(hits[0].kind, MatchKind::Exact { value_id: 2 }); // baz
        assert_eq!(hits[1].kind, MatchKind::Exact { value_id: 0 }); // foo
        assert_eq!(hits[2].kind, MatchKind::Exact { value_id: 1 }); // bar
    }

    #[test]
    fn byte_offsets_correct_through_multibyte_utf8() {
        // 'é' is 2 bytes in UTF-8. The pattern "alpha" starts after
        // "héllo " — verify the byte slice round-trips correctly rather
        // than hard-coding the offset.
        let m = ExactMatcher::build(["alpha"]).unwrap();
        let input = "héllo alpha";
        let hits = m.scan(input);
        assert_eq!(hits.len(), 1);
        assert_eq!(&input.as_bytes()[hits[0].start..hits[0].end], b"alpha");
    }
}
