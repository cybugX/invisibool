//! Pattern detection over compiled regex rules.
//!
//! Per build-prompt §A5 / §A4.5 rule 2: one `RegexSet` over all configured
//! rules, scanned in a single linear pass that tells us WHICH rules
//! matched. To recover WHERE each match landed we then run only the
//! matched rules' individual `Regex::find_iter`. In the common
//! "no secrets in this prompt" case the RegexSet pass is the only work
//! done — zero per-rule iteration.
//!
//! The `regex` crate is non-backtracking by construction, so ReDoS is
//! ruled out at the type-system level (no further config needed).
//!
//! **M0b ships the infrastructure with toy test rules only.** The real
//! corpus (OpenAI, Anthropic, AWS, ...) lives in M2's `rules/secrets.toml`.

use regex::{Regex, RegexSet};

use super::{Match, MatchKind};

/// A precompiled pattern matcher over a snapshot of configured rules.
pub struct PatternMatcher {
    /// `None` when no rules are configured. Mirrors `ExactMatcher`'s
    /// empty-vault short-circuit: no `RegexSet` build, no per-scan cost.
    set: Option<RegexSet>,
    /// One compiled `Regex` per rule, parallel to the `RegexSet`. Indexed
    /// by the rule_id reported by `RegexSet::matches`.
    rules: Vec<Regex>,
}

impl PatternMatcher {
    /// Build a matcher over the given rule patterns, in order. Each rule's
    /// index becomes its `rule_id` in returned matches.
    pub fn build<I, S>(rules: I) -> Result<Self, regex::Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let rule_strs: Vec<String> = rules.into_iter().map(|s| s.as_ref().to_owned()).collect();

        if rule_strs.is_empty() {
            return Ok(Self {
                set: None,
                rules: Vec::new(),
            });
        }

        let set = RegexSet::new(&rule_strs)?;
        let rules: Vec<Regex> = rule_strs
            .iter()
            .map(|s| Regex::new(s))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            set: Some(set),
            rules,
        })
    }

    /// Scan an input string. Returns all rule matches in source order.
    pub fn scan(&self, input: &str) -> Vec<Match> {
        let Some(set) = self.set.as_ref() else {
            return Vec::new();
        };

        let matched = set.matches(input);
        if !matched.matched_any() {
            // RegexSet's fast path: zero per-rule iteration when nothing fires.
            return Vec::new();
        }

        let mut result = Vec::new();
        for rule_id in matched.iter() {
            for m in self.rules[rule_id].find_iter(input) {
                result.push(Match {
                    start: m.start(),
                    end: m.end(),
                    kind: MatchKind::Pattern { rule_id },
                });
            }
        }

        // Stable source-order output; overlap resolution is the Detector's job.
        result.sort_by_key(|m| m.start);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS access key matching the gitleaks default rule: base32 chars only.
    /// Same shape as the M0a gate-fire proof.
    const AWS: &str = r"\bAKIA[A-Z2-7]{16}\b";
    /// Anthropic-style key.
    const ANTHROPIC: &str = r"\bsk-ant-[A-Za-z0-9]{20,}\b";

    #[test]
    fn empty_corpus_returns_no_matches() {
        let m = PatternMatcher::build::<_, &str>(std::iter::empty()).unwrap();
        assert_eq!(m.scan("AKIAAQUICKFOXEXAMPLE and sk-ant-something"), vec![]);
    }

    #[test]
    fn single_rule_single_hit() {
        let m = PatternMatcher::build([AWS]).unwrap();
        let hits = m.scan("here is AKIAAQUICKFOXEXAMPLE in text");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].start, 8);
        assert_eq!(hits[0].end, 8 + "AKIAAQUICKFOXEXAMPLE".len());
        assert_eq!(hits[0].kind, MatchKind::Pattern { rule_id: 0 });
    }

    #[test]
    fn single_rule_multiple_hits_in_source_order() {
        let m = PatternMatcher::build([AWS]).unwrap();
        // Two valid AWS-shaped keys (base32, both 20 chars total).
        let hits = m.scan("AKIAAQUICKFOXEXAMPLE then AKIAOTHERKEYHEXAMPLE");
        assert_eq!(hits.len(), 2);
        assert!(hits[0].start < hits[1].start);
        assert_eq!(hits[0].kind, MatchKind::Pattern { rule_id: 0 });
        assert_eq!(hits[1].kind, MatchKind::Pattern { rule_id: 0 });
    }

    #[test]
    fn multiple_rules_each_match_their_own() {
        let m = PatternMatcher::build([AWS, ANTHROPIC]).unwrap();
        let hits = m.scan("AKIAAQUICKFOXEXAMPLE then sk-ant-abcdef0123456789ABCDEF here");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].kind, MatchKind::Pattern { rule_id: 0 });
        assert_eq!(hits[1].kind, MatchKind::Pattern { rule_id: 1 });
    }

    #[test]
    fn no_rule_matches_takes_the_fast_path() {
        let m = PatternMatcher::build([AWS, ANTHROPIC]).unwrap();
        // Nothing secret-shaped here.
        assert_eq!(
            m.scan("the quick brown fox jumps over the lazy dog"),
            vec![]
        );
    }

    #[test]
    fn invalid_regex_returns_error_not_panic() {
        let result = PatternMatcher::build(["[unclosed-character-class"]);
        assert!(result.is_err());
    }

    #[test]
    fn byte_offsets_correct_through_multibyte_utf8() {
        let m = PatternMatcher::build([AWS]).unwrap();
        let input = "héllo AKIAAQUICKFOXEXAMPLE done";
        let hits = m.scan(input);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            &input.as_bytes()[hits[0].start..hits[0].end],
            b"AKIAAQUICKFOXEXAMPLE"
        );
    }
}
