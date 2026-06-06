//! Blacklist/whitelist matcher subsystem (RAN-413 G0.2).
//!
//! Four matcher kinds — literal, glob, regex, command-prefix.
//! Precedence rule: deny > allow > default. First deny wins; otherwise first allow wins.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum RuleMatcher {
    Literal(String),
    Glob(globset::GlobMatcher),
    Regex(regex::Regex),
    CommandPrefix(String),
}

impl RuleMatcher {
    pub fn matches(&self, command: &str) -> bool {
        match self {
            RuleMatcher::Literal(s) => command == s,
            RuleMatcher::Glob(g) => g.is_match(command),
            RuleMatcher::Regex(r) => r.is_match(command),
            RuleMatcher::CommandPrefix(p) => command
                .strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(' ')),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListRule {
    pub id: String,
    pub matcher: RuleMatcher,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Deny {
        rule_id: String,
        reason: Option<String>,
    },
    Allow {
        rule_id: String,
        reason: Option<String>,
    },
    NoMatch,
}

pub fn evaluate(command: &str, blacklist: &[ListRule], whitelist: &[ListRule]) -> Decision {
    // Precedence: deny beats allow.
    for r in blacklist {
        if r.matcher.matches(command) {
            return Decision::Deny {
                rule_id: r.id.clone(),
                reason: r.reason.clone(),
            };
        }
    }
    for r in whitelist {
        if r.matcher.matches(command) {
            return Decision::Allow {
                rule_id: r.id.clone(),
                reason: r.reason.clone(),
            };
        }
    }
    Decision::NoMatch
}

/// Serialized form used in TOML. Converts to ListRule via TryFrom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRuleSpec {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String, // "literal" | "glob" | "regex" | "command_prefix"
    pub pattern: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("rule {id}: unknown matcher type {kind:?}")]
    UnknownKind { id: String, kind: String },
    #[error("rule {id}: invalid regex: {source}")]
    InvalidRegex { id: String, source: regex::Error },
    #[error("rule {id}: invalid glob: {source}")]
    InvalidGlob { id: String, source: globset::Error },
}

impl TryFrom<ListRuleSpec> for ListRule {
    type Error = SpecError;
    fn try_from(spec: ListRuleSpec) -> Result<Self, Self::Error> {
        let matcher = match spec.kind.as_str() {
            "literal" => RuleMatcher::Literal(spec.pattern),
            "command_prefix" => RuleMatcher::CommandPrefix(spec.pattern),
            "regex" => RuleMatcher::Regex(regex::Regex::new(&spec.pattern).map_err(|e| {
                SpecError::InvalidRegex {
                    id: spec.id.clone(),
                    source: e,
                }
            })?),
            "glob" => RuleMatcher::Glob(
                globset::Glob::new(&spec.pattern)
                    .map_err(|e| SpecError::InvalidGlob {
                        id: spec.id.clone(),
                        source: e,
                    })?
                    .compile_matcher(),
            ),
            k => {
                return Err(SpecError::UnknownKind {
                    id: spec.id,
                    kind: k.to_string(),
                })
            }
        };
        Ok(ListRule {
            id: spec.id,
            matcher,
            reason: spec.reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(id: &str, pat: &str) -> ListRule {
        ListRule {
            id: id.into(),
            matcher: RuleMatcher::Literal(pat.into()),
            reason: None,
        }
    }

    #[test]
    fn deny_beats_allow_on_same_command() {
        let bl = vec![lit("deny-1", "rm -rf /")];
        let wl = vec![lit("allow-1", "rm -rf /")];
        match evaluate("rm -rf /", &bl, &wl) {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, "deny-1"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn allow_only_returns_allow() {
        let bl: Vec<ListRule> = vec![];
        let wl = vec![lit("ok", "ls -la")];
        match evaluate("ls -la", &bl, &wl) {
            Decision::Allow { rule_id, .. } => assert_eq!(rule_id, "ok"),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn no_match_when_neither() {
        let bl = vec![lit("x", "rm -rf /")];
        let wl = vec![lit("y", "ls -la")];
        assert_eq!(evaluate("echo hi", &bl, &wl), Decision::NoMatch);
    }

    #[test]
    fn first_deny_wins_stable_order() {
        let bl = vec![lit("first", "rm -rf /"), lit("second", "rm -rf /")];
        match evaluate("rm -rf /", &bl, &[]) {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, "first"),
            other => panic!("expected Deny first, got {other:?}"),
        }
    }

    #[test]
    fn command_prefix_matches_with_and_without_args() {
        let bl = vec![ListRule {
            id: "cp".into(),
            matcher: RuleMatcher::CommandPrefix("git push --force".into()),
            reason: None,
        }];
        assert!(matches!(
            evaluate("git push --force", &bl, &[]),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            evaluate("git push --force origin main", &bl, &[]),
            Decision::Deny { .. }
        ));
        assert!(matches!(evaluate("git push", &bl, &[]), Decision::NoMatch));
    }

    #[test]
    fn glob_matches_paths() {
        let g = globset::Glob::new("rm -rf */build")
            .unwrap()
            .compile_matcher();
        let bl = vec![ListRule {
            id: "g".into(),
            matcher: RuleMatcher::Glob(g),
            reason: None,
        }];
        assert!(matches!(
            evaluate("rm -rf ./build", &bl, &[]),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            evaluate("rm -rf foo/build", &bl, &[]),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            evaluate("rm -rf foo", &bl, &[]),
            Decision::NoMatch
        ));
    }

    #[test]
    fn regex_matches_drop_table() {
        let r = regex::Regex::new("(?i)drop\\s+(table|database)").unwrap();
        let bl = vec![ListRule {
            id: "sql".into(),
            matcher: RuleMatcher::Regex(r),
            reason: None,
        }];
        assert!(matches!(
            evaluate("DROP TABLE users", &bl, &[]),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            evaluate("drop database x", &bl, &[]),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn try_from_unknown_kind_errors() {
        let spec = ListRuleSpec {
            id: "x".into(),
            kind: "exact".into(),
            pattern: "x".into(),
            reason: None,
        };
        assert!(matches!(
            ListRule::try_from(spec),
            Err(SpecError::UnknownKind { .. })
        ));
    }

    #[test]
    fn try_from_invalid_regex_errors() {
        let spec = ListRuleSpec {
            id: "bad".into(),
            kind: "regex".into(),
            pattern: "(unclosed".into(),
            reason: None,
        };
        assert!(matches!(
            ListRule::try_from(spec),
            Err(SpecError::InvalidRegex { .. })
        ));
    }

    proptest::proptest! {
        #[test]
        fn deterministic_on_repeated_calls(cmd in "[a-z ]{1,40}", bl_size in 0u32..20, wl_size in 0u32..20) {
            let bl: Vec<ListRule> = (0..bl_size)
                .map(|i| lit(&format!("bl{i}"), &format!("denied{i}")))
                .collect();
            let wl: Vec<ListRule> = (0..wl_size)
                .map(|i| lit(&format!("wl{i}"), &format!("allowed{i}")))
                .collect();
            let d1 = evaluate(&cmd, &bl, &wl);
            let d2 = evaluate(&cmd, &bl, &wl);
            proptest::prop_assert_eq!(d1, d2);
        }

        #[test]
        fn precedence_deny_wins(idx in 0u32..10) {
            let cmd = format!("collide-{idx}");
            let bl = vec![lit("deny", &cmd)];
            let wl = vec![lit("allow", &cmd)];
            match evaluate(&cmd, &bl, &wl) {
                Decision::Deny { .. } => {}
                other => panic!("expected Deny, got {other:?}"),
            }
        }
    }
}
