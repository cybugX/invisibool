//! Detection layer: locate spans of input text that match either a
//! registered exact value (`ExactMatcher`) or a configured regex rule
//! (`PatternMatcher`). `Detector` runs both and resolves overlaps using
//! the longest-span-then-highest-confidence rule.
//!
//! Public types: `Match`, `MatchKind`, `Confidence`, `Detector`,
//! `ExactMatcher`, `PatternMatcher`.

mod exact;
mod pattern;

pub use exact::ExactMatcher;
pub use pattern::PatternMatcher;

/// A located match within an input text. Byte offsets, half-open
/// (`[start, end)`), into the original UTF-8 input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Byte offset of the match start (inclusive).
    pub start: usize,
    /// Byte offset of the match end (exclusive).
    pub end: usize,
    /// Which detector found this match and the detector-local identifier.
    pub kind: MatchKind,
}

impl Match {
    /// Length of the match in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Convenience predicate; should not occur for current matchers.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Which detector produced a `Match`, plus the detector-local identifier
/// (registered-value index for `Exact`, rule index for `Pattern`).
///
/// `#[non_exhaustive]` because M2 will add an entropy-backstop variant;
/// callers must handle unknown variants rather than break on milestone
/// bumps. Within this crate the exhaustive match in `Self::confidence`
/// enforces that any new variant gets an explicit confidence assignment.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchKind {
    /// An exact registered vault value matched.
    Exact { value_id: usize },
    /// A configured pattern rule matched.
    Pattern { rule_id: usize },
}

impl MatchKind {
    /// Confidence the underlying detector has in this match. Used by
    /// `Detector::scan` as the tiebreaker when two overlapping matches
    /// have the same span length.
    pub fn confidence(&self) -> Confidence {
        match self {
            MatchKind::Exact { .. } => Confidence::Certain,
            MatchKind::Pattern { .. } => Confidence::High,
        }
    }
}

/// Detector confidence ordering. Higher variants beat lower ones in
/// overlap resolution when span lengths tie. Exact match is `Certain`,
/// pattern rules are `High`. M2 will add `Medium` for the entropy
/// backstop - declaration order determines the derived `Ord`, so
/// inserting Medium before High keeps comparisons stable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    High,
    Certain,
}

/// Combined detector. Runs `ExactMatcher` and `PatternMatcher`, resolves
/// overlaps (longest-span first; on a length tie, higher confidence wins;
/// on both tied, leftmost wins), and returns non-overlapping matches in
/// source order.
pub struct Detector {
    exact: ExactMatcher,
    pattern: PatternMatcher,
}

impl Detector {
    pub fn new(exact: ExactMatcher, pattern: PatternMatcher) -> Self {
        Self { exact, pattern }
    }

    pub fn scan(&self, input: &str) -> Vec<Match> {
        let mut all: Vec<Match> = self.exact.scan(input);
        all.extend(self.pattern.scan(input));

        // Sort most-desirable-first: longest span, then highest confidence,
        // then leftmost. The greedy walk below then picks each candidate iff
        // it doesn't overlap any already-kept (more desirable) match.
        all.sort_by(|a, b| {
            b.len()
                .cmp(&a.len())
                .then_with(|| b.kind.confidence().cmp(&a.kind.confidence()))
                .then_with(|| a.start.cmp(&b.start))
        });

        let mut kept: Vec<Match> = Vec::new();
        for cand in all {
            if !kept.iter().any(|k| overlaps(&cand, k)) {
                kept.push(cand);
            }
        }

        // Restore source order for downstream consumers.
        kept.sort_by_key(|m| m.start);
        kept
    }
}

fn overlaps(a: &Match, b: &Match) -> bool {
    a.start < b.end && b.start < a.end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_exact() -> ExactMatcher {
        ExactMatcher::build::<_, &str>(std::iter::empty()).unwrap()
    }

    fn empty_pattern() -> PatternMatcher {
        PatternMatcher::build::<_, &str>(std::iter::empty()).unwrap()
    }

    // ----- Confidence -----

    #[test]
    fn confidence_certain_beats_high() {
        assert!(Confidence::Certain > Confidence::High);
    }

    #[test]
    fn matchkind_confidence_maps_correctly() {
        assert_eq!(
            MatchKind::Exact { value_id: 0 }.confidence(),
            Confidence::Certain
        );
        assert_eq!(
            MatchKind::Pattern { rule_id: 0 }.confidence(),
            Confidence::High
        );
    }

    // ----- Detector -----

    #[test]
    fn empty_both_yields_no_matches() {
        let d = Detector::new(empty_exact(), empty_pattern());
        assert_eq!(d.scan("any input here"), vec![]);
    }

    #[test]
    fn exact_only_passes_through() {
        let d = Detector::new(
            ExactMatcher::build(["registered-secret"]).unwrap(),
            empty_pattern(),
        );
        let hits = d.scan("see registered-secret here");
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].kind, MatchKind::Exact { value_id: 0 }));
    }

    #[test]
    fn pattern_only_passes_through() {
        let d = Detector::new(
            empty_exact(),
            PatternMatcher::build([r"\bAKIA[A-Z2-7]{16}\b"]).unwrap(),
        );
        let hits = d.scan("see AKIAAQUICKFOXEXAMPLE here");
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].kind, MatchKind::Pattern { rule_id: 0 }));
    }

    #[test]
    fn non_overlapping_exact_and_pattern_both_surface_in_source_order() {
        let d = Detector::new(
            ExactMatcher::build(["secret"]).unwrap(),
            PatternMatcher::build([r"\bAKIA[A-Z2-7]{16}\b"]).unwrap(),
        );
        let hits = d.scan("the secret then AKIAAQUICKFOXEXAMPLE also");
        assert_eq!(hits.len(), 2);
        assert!(hits[0].start < hits[1].start);
        assert!(matches!(hits[0].kind, MatchKind::Exact { .. }));
        assert!(matches!(hits[1].kind, MatchKind::Pattern { .. }));
    }

    #[test]
    fn exact_wins_when_same_span_as_pattern() {
        let d = Detector::new(
            ExactMatcher::build(["AKIAAQUICKFOXEXAMPLE"]).unwrap(),
            PatternMatcher::build([r"\bAKIA[A-Z2-7]{16}\b"]).unwrap(),
        );
        let hits = d.scan("see AKIAAQUICKFOXEXAMPLE here");
        // Both detectors match the same 20-byte span; the tiebreaker
        // is confidence, and exact-match has higher confidence than a
        // pattern hit (the value is on the user's vault, not inferred).
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].kind, MatchKind::Exact { .. }));
    }

    #[test]
    fn longer_pattern_wins_over_shorter_exact() {
        // Exact is just "AKIA" (4 bytes). Pattern matches the full
        // "AKIAAQUICKFOXEXAMPLE" (20 bytes). Span length is the first
        // tiebreaker - the longer span wins over the higher-confidence
        // shorter one, so a registered prefix can't shadow a full hit.
        let d = Detector::new(
            ExactMatcher::build(["AKIA"]).unwrap(),
            PatternMatcher::build([r"\bAKIA[A-Z2-7]{16}\b"]).unwrap(),
        );
        let hits = d.scan("see AKIAAQUICKFOXEXAMPLE here");
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].kind, MatchKind::Pattern { .. }));
        assert_eq!(hits[0].len(), 20);
    }

    #[test]
    fn longer_exact_wins_over_shorter_pattern() {
        // Exact is the full "myappdata" (9 bytes). Pattern matches the
        // "data" suffix (4 bytes). Exact wins on both length AND confidence.
        let d = Detector::new(
            ExactMatcher::build(["myappdata"]).unwrap(),
            PatternMatcher::build(["data"]).unwrap(),
        );
        let hits = d.scan("see myappdata here");
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].kind, MatchKind::Exact { .. }));
        assert_eq!(hits[0].len(), 9);
    }
}
