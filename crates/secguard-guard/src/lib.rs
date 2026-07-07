//! Destructive command detection.
//!
//! Three-phase classification: policy allowlist -> heuristic rules -> ML brain.

pub mod ast;
pub mod config;
pub mod heuristic;
pub mod matcher;
pub mod policy;
pub mod rm;
pub mod rule_id;
pub mod rules;
pub mod scoring;

#[cfg(feature = "ml")]
mod brain;

pub use config::GuardConfig;
pub use rule_id::RuleId;
pub use scoring::{Action, Decision};

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
    /// Blast × reversibility action (RAN-414). Derived from the firing
    /// rule's [`RuleId::score`] through the config-resolved policy matrix.
    /// Safe verdicts are always [`Action::Allow`]; destructive verdicts with
    /// no `rule_id` (explicit config denies, fail-open) are [`Action::Block`].
    pub action: Action,
}

impl VerdictDetail {
    /// Construct a detail, deriving `action` from the verdict + rule.
    /// Single source of truth for the verdict → action mapping.
    fn new(
        verdict: Verdict,
        source: VerdictSource,
        confidence: Option<f32>,
        rule_id: Option<RuleId>,
        config: &GuardConfig,
    ) -> Self {
        let action = match (&verdict, rule_id) {
            (Verdict::Safe, _) => Action::Allow,
            (Verdict::Destructive(_), Some(r)) => config.scoring.action_for(r.score()),
            // Explicit config denies and asymmetric fail-open carry no rule
            // id; they are fail-safe blocks by construction.
            (Verdict::Destructive(_), None) => Action::Block,
        };
        Self {
            verdict,
            source,
            confidence,
            rule_id,
            action,
        }
    }
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
    let lists = config::build_rule_lists(config);
    match matcher::evaluate(cmd, &lists.deny.commands, &[]) {
        matcher::Decision::Deny { rule_id, reason } => {
            let detail = reason
                .map(|r| format!("config deny command rule {rule_id}: {r}"))
                .unwrap_or_else(|| format!("config deny command rule {rule_id}"));
            return VerdictDetail::new(
                Verdict::Destructive(detail),
                VerdictSource::Heuristic,
                None,
                None,
                config,
            );
        }
        matcher::Decision::Allow { .. } | matcher::Decision::NoMatch => {}
    }
    match matcher::evaluate(cmd, &lists.deny.secrets, &[]) {
        matcher::Decision::Deny { rule_id, reason } => {
            let detail = reason
                .map(|r| format!("config deny secret rule {rule_id}: {r}"))
                .unwrap_or_else(|| format!("config deny secret rule {rule_id}"));
            return VerdictDetail::new(
                Verdict::Destructive(detail),
                VerdictSource::Heuristic,
                None,
                None,
                config,
            );
        }
        matcher::Decision::Allow { .. } | matcher::Decision::NoMatch => {}
    }

    let parsed = ast::parse(cmd);
    let commands = parsed.commands;
    let had_parse_issue = parsed.had_error;

    for ec in &commands {
        if ec.span != ast::SpanKind::Executed {
            continue;
        }
        if let Some((_rule_id, reason)) = rules::classify_configured_path_deny(ec, config) {
            return VerdictDetail::new(
                Verdict::Destructive(reason),
                VerdictSource::Heuristic,
                None,
                None,
                config,
            );
        }
    }

    match matcher::evaluate(cmd, &[], &lists.allow.commands) {
        matcher::Decision::Allow { .. } => {
            return VerdictDetail::new(Verdict::Safe, VerdictSource::Policy, None, None, config);
        }
        matcher::Decision::Deny { .. } | matcher::Decision::NoMatch => {}
    }

    if policy::is_safe_by_policy(cmd, config) {
        return VerdictDetail::new(Verdict::Safe, VerdictSource::Policy, None, None, config);
    }

    for ec in &commands {
        if ec.span != ast::SpanKind::Executed {
            continue;
        }
        if let Some((rule_id, reason)) = rules::classify(ec, config) {
            return VerdictDetail::new(
                Verdict::Destructive(reason),
                VerdictSource::Heuristic,
                None,
                Some(rule_id),
                config,
            );
        }
    }

    // Asymmetric fail-open: a malformed command that mentions a
    // destructive trigger keyword surfaces as an ask, not a silent
    // allow. Without trigger words, malformed input is the agent's
    // problem (the shell will refuse it anyway).
    if had_parse_issue && has_trigger_keyword(cmd) {
        return VerdictDetail::new(
            Verdict::Destructive(
                "parse error in input that mentions a destructive keyword \
                 (asymmetric fail-open)"
                    .into(),
            ),
            VerdictSource::Heuristic,
            None,
            None,
            config,
        );
    }

    #[cfg(feature = "ml")]
    {
        return match brain::classify(cmd) {
            brain::BrainOutcome::Destructive { reason, confidence } => VerdictDetail::new(
                Verdict::Destructive(reason),
                VerdictSource::Brain,
                Some(confidence),
                Some(RuleId::Brain),
                config,
            ),
            brain::BrainOutcome::LowConfidence { confidence } => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainLowConfidence,
                Some(confidence),
                None,
                config,
            ),
            brain::BrainOutcome::Safe { confidence } => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainSafe,
                Some(confidence),
                None,
                config,
            ),
            brain::BrainOutcome::NotLoaded => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainNotLoaded,
                None,
                None,
                config,
            ),
            brain::BrainOutcome::MalformedOutput => VerdictDetail::new(
                Verdict::Safe,
                VerdictSource::BrainMalformed,
                None,
                None,
                config,
            ),
        };
    }

    #[allow(unreachable_code)]
    VerdictDetail::new(Verdict::Safe, VerdictSource::Default, None, None, config)
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
