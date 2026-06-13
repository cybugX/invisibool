//! Detection layer: locate spans of input text that match either a
//! registered exact value (`ExactMatcher`) or a known pattern
//! (`PatternMatcher` — M0b chunk 3). M0b ships the infrastructure for both;
//! the real pattern rule corpus arrives in M2.

mod exact;

pub use exact::ExactMatcher;

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
/// that maps back to which registered value or rule fired.
///
/// `#[non_exhaustive]` because M0b chunk 3 adds a `Pattern` variant and M2
/// may add an entropy-backstop variant; callers must handle unknown
/// variants rather than match exhaustively across milestones.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchKind {
    /// An exact registered vault value matched.
    /// `value_id` is the index into the slice passed to `ExactMatcher::build`.
    Exact { value_id: usize },
}
