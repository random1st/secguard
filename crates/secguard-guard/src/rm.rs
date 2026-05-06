//! `rm` / `unlink` / `rmdir` classifier — thin wrapper over the AST
//! pipeline.
//!
//! All the substantive operand-classification logic now lives in
//! [`crate::rules::rule_rm_family`]; this module retains the public
//! [`check_rm`] entry point and the [`RmCheck`] enum so existing
//! integration tests and external callers keep working unchanged. The
//! function delegates to [`crate::ast::parse`] + [`crate::rules::classify`]
//! and reports whether any rm-family command was located and its
//! verdict.

use crate::ast::{self, EffectiveCommand, ParseOutcome, SpanKind};
use crate::config::GuardConfig;
use crate::rule_id::RuleId;

pub type RuleHit = (RuleId, String);

/// Outcome of the rm classifier.
///
/// * `Destructive` — an rm-family command was found and classified as
///   destructive (catastrophic operand, no-preserve-root, or operand
///   outside the safe-paths allowlist).
/// * `Safe` — an rm-family command was found and every operand cleared
///   under the configured safe paths. Caller should not fall back to
///   substring matching.
/// * `NotFound` — no rm-family command at command position. The command
///   may still contain an rm inside an unparseable wrapper or as data;
///   `heuristic.rs` decides what to do with that case.
#[derive(Debug)]
pub enum RmCheck {
    Destructive(RuleHit),
    Safe,
    NotFound,
}

/// Classify the rm-family commands in `cmd`. Walks every effective
/// command produced by the AST pipeline; the first rm-family command
/// to fire a destructive verdict wins. If at least one rm-family
/// command was located and none fired, the result is `Safe`. Otherwise
/// `NotFound`.
pub fn check_rm(cmd: &str, config: &GuardConfig) -> RmCheck {
    let commands = match ast::parse(cmd) {
        ParseOutcome::Ok(c) | ParseOutcome::Partial { commands: c, .. } => c,
        ParseOutcome::Failed => return RmCheck::NotFound,
    };
    let mut found_any_rm = false;
    for ec in &commands {
        if !is_rm_family(ec) {
            continue;
        }
        found_any_rm = true;
        if let Some(hit) = crate::rules::classify(ec, config) {
            return RmCheck::Destructive(hit);
        }
    }
    if found_any_rm {
        RmCheck::Safe
    } else {
        RmCheck::NotFound
    }
}

fn is_rm_family(ec: &EffectiveCommand) -> bool {
    if ec.span != SpanKind::Executed {
        return false;
    }
    matches!(ec.head(), Some("rm" | "unlink" | "rmdir"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GuardConfig {
        GuardConfig::default()
    }

    fn destructive(cmd: &str) -> bool {
        matches!(check_rm(cmd, &cfg()), RmCheck::Destructive(_))
    }

    fn cleared(cmd: &str) -> bool {
        matches!(check_rm(cmd, &cfg()), RmCheck::Safe)
    }

    fn not_found(cmd: &str) -> bool {
        matches!(check_rm(cmd, &cfg()), RmCheck::NotFound)
    }

    // Behavioural contract preserved across the migration.

    #[test]
    fn home_subpath_is_destructive() {
        assert!(destructive("rm -rf $HOME/build-tools"));
        assert!(destructive("rm -rf ${HOME}/foo"));
        assert!(destructive("rm -rf ~/dist-old"));
    }

    #[test]
    fn etc_subpath_is_destructive() {
        assert!(destructive("rm -rf /etc/build-system"));
        assert!(destructive("rm -rf /etc"));
        assert!(destructive("rm -rf /usr/local"));
    }

    #[test]
    fn path_traversal_is_destructive() {
        assert!(destructive("rm -rf /tmp/../etc"));
        assert!(destructive("rm -rf foo/../bar"));
    }

    #[test]
    fn split_flags_are_recognised() {
        assert!(destructive("rm -r -f /etc"));
        assert!(destructive("rm --recursive --force /etc"));
        assert!(destructive("rm -fr /var/log"));
        assert!(destructive("rm -Rf /etc"));
    }

    #[test]
    fn no_preserve_root_is_always_destructive() {
        assert!(destructive("rm -rf / --no-preserve-root"));
        assert!(destructive("rm --no-preserve-root -rf /tmp/foo"));
    }

    #[test]
    fn unlink_and_rmdir_target_catastrophic_path() {
        assert!(destructive("unlink /etc/passwd"));
        assert!(destructive("rmdir /etc"));
    }

    #[test]
    fn safe_relative_targets() {
        assert!(cleared("rm -rf build"));
        assert!(cleared("rm -rf ./build"));
        assert!(cleared("rm -rf node_modules"));
        assert!(cleared("rm -rf dist"));
        assert!(cleared("rm -rf target/debug"));
        assert!(cleared("rm -rf __pycache__"));
    }

    #[test]
    fn safe_tmp_subdirs() {
        assert!(cleared("rm -rf /tmp/foo"));
        assert!(cleared("rm --recursive --force /tmp/foo"));
        assert!(cleared("rm -rf /var/tmp/build"));
        assert!(cleared("rm -rf /private/tmp/x"));
    }

    #[test]
    fn unsafe_tmp_root_itself() {
        assert!(destructive("rm -rf /tmp"));
        assert!(destructive("rm -rf /var/tmp"));
    }

    #[test]
    fn shared_root_glob_is_not_safe() {
        assert!(destructive("rm -rf /tmp/*"));
        assert!(destructive("rm -rf /var/tmp/*"));
    }

    #[test]
    fn plain_rm_against_catastrophic_path_is_destructive() {
        // Non-recursive rm of a system file must still be flagged.
        assert!(destructive("rm /etc/passwd"));
        assert!(destructive("unlink /etc/hosts"));
    }

    #[test]
    fn plain_rm_against_safe_target_is_safe() {
        // Plain non-recursive rm is ambiguous without cwd context;
        // outside catastrophic paths we defer.
        assert!(cleared("rm somefile.txt"));
    }

    #[test]
    fn double_dash_separates_flags_and_operands() {
        assert!(destructive("rm -rf -- /etc"));
        assert!(cleared("rm -rf -- build"));
    }

    #[test]
    fn cd_then_rm_carries_cwd() {
        // Compound `cd /tmp && rm -rf x` — relative operand resolved
        // against /tmp via the AST walker's cwd-tracking.
        assert!(cleared("cd /tmp && rm -rf ci-results"));
    }

    #[test]
    fn subshell_isolates_cwd() {
        // `(cd /tmp && rm -rf x); rm -rf y` — the second rm is at
        // cwd=None and y is relative, no safe pattern matches.
        let result = check_rm("(cd /tmp && rm -rf x); rm -rf y", &cfg());
        assert!(matches!(result, RmCheck::Destructive(_)));
    }

    #[test]
    fn malformed_quoting_without_rm_is_not_found() {
        assert!(not_found("echo 'unterminated"));
    }

    #[test]
    fn compound_command_does_not_fold_trailing_tokens() {
        assert!(cleared("rm -rf node_modules ; ls /etc"));
        assert!(cleared("rm -rf build && echo ok"));
        assert!(cleared("rm -rf dist || echo failed"));
    }

    #[test]
    fn compound_command_catches_destructive_in_later_segment() {
        assert!(destructive("rm -rf node_modules ; rm -rf /etc"));
        assert!(destructive("rm -rf build && rm -rf /etc"));
    }

    #[test]
    fn glued_operators_split_correctly() {
        assert!(cleared("rm -rf node_modules; ls /etc"));
        assert!(cleared("rm -rf node_modules&& echo ok"));
        assert!(destructive("rm -rf node_modules;rm -rf /etc"));
    }

    #[test]
    fn leading_var_assignments_are_skipped() {
        assert!(destructive("FOO=1 rm -rf /etc"));
        assert!(cleared("FOO=1 rm -rf build"));
    }
}
