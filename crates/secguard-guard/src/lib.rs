//! Destructive command detection.
//!
//! Three-phase classification: policy allowlist -> heuristic rules -> ML brain.

pub mod ast;
pub mod config;
pub mod heuristic;
pub mod policy;
pub mod rm;
pub mod rule_id;
pub mod rules;

#[cfg(feature = "ml")]
mod brain;

pub use config::GuardConfig;
pub use rule_id::RuleId;

/// Result of guard classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Command is safe to execute.
    Safe,
    /// Command is destructive — includes human-readable reason.
    Destructive(String),
}

/// Which phase produced the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    Policy,
    Heuristic,
    /// Brain returned destructive with confidence >= threshold.
    Brain,
    /// Brain ran, label was safe.
    BrainSafe,
    /// Brain returned destructive but confidence < threshold — treated as safe.
    BrainLowConfidence,
    /// Model file missing or init failed.
    BrainNotLoaded,
    /// Model loaded but produced a token outside the valid label set.
    BrainMalformed,
    /// ML feature not compiled in; heuristic/policy did not trigger.
    Default,
}

/// Verdict with source information for telemetry.
#[derive(Debug, Clone)]
pub struct VerdictDetail {
    pub verdict: Verdict,
    pub source: VerdictSource,
    /// ML confidence score (0.0–1.0), only set when source is Brain.
    pub confidence: Option<f32>,
    /// Machine-readable rule identifier — populated when a rule fires.
    /// `None` when no rule matched (Safe by default), when the verdict came
    /// from the policy allowlist, or when the brain produced a Safe label.
    pub rule_id: Option<RuleId>,
}

/// Classify a shell command through all enabled phases.
pub fn check(cmd: &str) -> Verdict {
    check_detailed(cmd, &GuardConfig::default()).verdict
}

/// Classify with custom configuration.
pub fn check_with_config(cmd: &str, config: &GuardConfig) -> Verdict {
    check_detailed(cmd, config).verdict
}

/// Classify with full detail (verdict + source + confidence + rule_id).
///
/// Pipeline:
///   1. Policy allowlist — known-safe operations short-circuit early.
///   2. AST parse → flat list of effective commands (wrappers unwrapped,
///      cwd tracked, span classified).
///   3. Predicate rules in [`crate::rules`] applied to each command.
///   4. Asymmetric fail-open on parse error: if the source contains a
///      destructive trigger keyword, return Destructive with reason
///      `parse_error_after_trigger`; otherwise allow.
///   5. ML brain (if enabled) on commands not flagged by rules.
pub fn check_detailed(cmd: &str, config: &GuardConfig) -> VerdictDetail {
    if policy::is_safe_by_policy(cmd, config) {
        return VerdictDetail {
            verdict: Verdict::Safe,
            source: VerdictSource::Policy,
            confidence: None,
            rule_id: None,
        };
    }

    let (commands, had_parse_issue) = match ast::parse(cmd) {
        ast::ParseOutcome::Ok(c) => (c, false),
        ast::ParseOutcome::Partial { commands, .. } => (commands, true),
        ast::ParseOutcome::Failed => (Vec::new(), true),
    };

    for ec in &commands {
        if ec.span != ast::SpanKind::Executed {
            continue;
        }
        if let Some((rule_id, reason)) = rules::classify(ec, config) {
            return VerdictDetail {
                verdict: Verdict::Destructive(reason),
                source: VerdictSource::Heuristic,
                confidence: None,
                rule_id: Some(rule_id),
            };
        }
    }

    // Asymmetric fail-open: a malformed command that mentions a
    // destructive trigger keyword surfaces as an ask, not a silent
    // allow. Without trigger words, malformed input is the agent's
    // problem (the shell will refuse it anyway).
    if had_parse_issue && has_trigger_keyword(cmd) {
        return VerdictDetail {
            verdict: Verdict::Destructive(
                "parse error in input that mentions a destructive keyword \
                 (asymmetric fail-open)"
                    .into(),
            ),
            source: VerdictSource::Heuristic,
            confidence: None,
            rule_id: None,
        };
    }

    #[cfg(feature = "ml")]
    {
        return match brain::classify(cmd) {
            brain::BrainOutcome::Destructive { reason, confidence } => VerdictDetail {
                verdict: Verdict::Destructive(reason),
                source: VerdictSource::Brain,
                confidence: Some(confidence),
                rule_id: Some(RuleId::Brain),
            },
            brain::BrainOutcome::LowConfidence { confidence } => VerdictDetail {
                verdict: Verdict::Safe,
                source: VerdictSource::BrainLowConfidence,
                confidence: Some(confidence),
                rule_id: None,
            },
            brain::BrainOutcome::Safe { confidence } => VerdictDetail {
                verdict: Verdict::Safe,
                source: VerdictSource::BrainSafe,
                confidence: Some(confidence),
                rule_id: None,
            },
            brain::BrainOutcome::NotLoaded => VerdictDetail {
                verdict: Verdict::Safe,
                source: VerdictSource::BrainNotLoaded,
                confidence: None,
                rule_id: None,
            },
            brain::BrainOutcome::MalformedOutput => VerdictDetail {
                verdict: Verdict::Safe,
                source: VerdictSource::BrainMalformed,
                confidence: None,
                rule_id: None,
            },
        };
    }

    #[allow(unreachable_code)]
    VerdictDetail {
        verdict: Verdict::Safe,
        source: VerdictSource::Default,
        confidence: None,
        rule_id: None,
    }
}

/// Quick substring scan for destructive trigger keywords. Used by the
/// asymmetric-fail-open path: a malformed command that mentions any of
/// these words is escalated to ask, while malformed-but-benign input is
/// left to the shell's own syntax check.
fn has_trigger_keyword(cmd: &str) -> bool {
    const TRIGGERS: &[&str] = &[
        "rm",
        "unlink",
        "rmdir",
        "shred",
        "drop",
        "truncate",
        "delete",
        "destroy",
        "purge",
        "terminate",
        "force",
        "reset",
        "rebase",
        "amend",
        "uninstall",
        "filter-branch",
        "filter-repo",
        "FLUSHALL",
        "FLUSHDB",
        "SHUTDOWN",
        "dropDatabase",
        "deleteMany",
        "eval",
        "sudo",
    ];
    TRIGGERS.iter().any(|t| cmd.contains(t))
}
