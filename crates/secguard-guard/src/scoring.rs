//! Blast-radius × reversibility scoring (RAN-414).
//!
//! Replaces the binary block/allow model with a 2D score per rule. Each
//! [`crate::rule_id::RuleId`] declares a [`Decision`] via `RuleId::score`;
//! the [`default_action_for`] lookup table maps that decision to an
//! [`Action`]. The default policy is overridable per cell through the
//! `[scoring]` config section ([`crate::config::ScoringConfig`]).

use serde::{Deserialize, Serialize};

/// A rule's 2D damage assessment. Both axes are `0..=4`.
///
/// * `blast` — scope of damage: 0 = local file, 1 = local repo state,
///   2 = local machine / global state, 3 = single remote/cloud resource,
///   4 = multi-tenant / shared infrastructure.
/// * `reversibility` — how recoverable: 0 = permanent, 1 = hard
///   (backup/manual), 2 = moderate, 3 = easy rollback, 4 = instant undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub blast: u8,
    pub reversibility: u8,
}

impl Decision {
    /// Const constructor. Debug-asserts both axes are within `0..=4`.
    pub const fn new(blast: u8, reversibility: u8) -> Self {
        debug_assert!(blast <= 4 && reversibility <= 4);
        Self {
            blast,
            reversibility,
        }
    }
}

/// Final action, ordered by severity: `Allow < Warn < Confirm < Block`.
///
/// `Ord` is load-bearing — the monotonicity proptest relies on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Warn,
    Confirm,
    Block,
}

/// Default policy matrix.
///
/// `risk = blast + (4 - reversibility)`, bucketed: Allow `<=1`,
/// Warn `2..=3`, Confirm `4..=5`, Block `>=6`. The construction is monotone
/// on both axes: increasing `blast` never lowers severity, and increasing
/// `reversibility` never raises it.
///
/// ```text
///         rev0     rev1     rev2     rev3     rev4
/// b0   Confirm  Warn     Warn     Allow    Allow
/// b1   Confirm  Confirm  Warn     Warn     Allow
/// b2   Block    Confirm  Confirm  Warn     Warn
/// b3   Block    Block    Confirm  Confirm  Warn
/// b4   Block    Block    Block    Confirm  Confirm
/// ```
pub const fn default_action_for(d: Decision) -> Action {
    let risk = d.blast + (4 - d.reversibility);
    if risk <= 1 {
        Action::Allow
    } else if risk <= 3 {
        Action::Warn
    } else if risk <= 5 {
        Action::Confirm
    } else {
        Action::Block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Test class 1: unit scoring of representative heuristics ──────────
    // Verifies RuleId::score() returns the calibrated decision. Full
    // coverage is guaranteed structurally by the exhaustive match in
    // `RuleId::score` (omitting a variant is a compile error).
    #[test]
    fn rule_scores_match_calibration() {
        use crate::rule_id::RuleId;
        assert_eq!(RuleId::RmRf.score(), Decision::new(3, 0));
        assert_eq!(RuleId::SqlDestructive.score(), Decision::new(4, 0));
        assert_eq!(RuleId::OrmMigration.score(), Decision::new(2, 2));
        assert_eq!(RuleId::NoVerify.score(), Decision::new(1, 3));
        assert_eq!(RuleId::SaasDestroy.score(), Decision::new(3, 0));
        assert_eq!(RuleId::GitResetHard.score(), Decision::new(1, 0));
        assert_eq!(RuleId::HelmMutation.score(), Decision::new(3, 2));
        assert_eq!(RuleId::Brain.score(), Decision::new(2, 1));
    }

    #[test]
    fn calibrated_actions_demonstrate_spread() {
        // The point of the matrix: not everything blocks.
        use crate::rule_id::RuleId;
        assert_eq!(default_action_for(RuleId::RmRf.score()), Action::Block);
        assert_eq!(
            default_action_for(RuleId::SqlDestructive.score()),
            Action::Block
        );
        // OrmMigration is the headline false-positive reducer: was Block,
        // now Confirm (up/down migrations make it reversible).
        assert_eq!(
            default_action_for(RuleId::OrmMigration.score()),
            Action::Confirm
        );
        assert_eq!(default_action_for(RuleId::NoVerify.score()), Action::Warn);
        assert_eq!(
            default_action_for(RuleId::HelmMutation.score()),
            Action::Confirm
        );
    }

    // ── Test class 2: snapshot of all 25 (blast, reversibility) combos ───
    #[test]
    fn lookup_table_snapshot_all_25_cells() {
        use Action::*;
        // rows = blast 0..=4, cols = reversibility 0..=4.
        const EXPECTED: [[Action; 5]; 5] = [
            [Confirm, Warn, Warn, Allow, Allow],
            [Confirm, Confirm, Warn, Warn, Allow],
            [Block, Confirm, Confirm, Warn, Warn],
            [Block, Block, Confirm, Confirm, Warn],
            [Block, Block, Block, Confirm, Confirm],
        ];
        for blast in 0u8..=4 {
            for rev in 0u8..=4 {
                assert_eq!(
                    default_action_for(Decision::new(blast, rev)),
                    EXPECTED[blast as usize][rev as usize],
                    "mismatch at (blast={blast}, reversibility={rev})"
                );
            }
        }
    }

    // ── Test class 5: monotonicity invariants ────────────────────────────
    proptest! {
        #[test]
        fn monotone_in_blast(r in 0u8..=4, b1 in 0u8..=4, b2 in 0u8..=4) {
            // For fixed reversibility, higher blast never lowers severity.
            let (lo, hi) = if b1 <= b2 { (b1, b2) } else { (b2, b1) };
            prop_assert!(
                default_action_for(Decision::new(lo, r))
                    <= default_action_for(Decision::new(hi, r))
            );
        }

        #[test]
        fn antimonotone_in_reversibility(b in 0u8..=4, r1 in 0u8..=4, r2 in 0u8..=4) {
            // For fixed blast, higher reversibility never raises severity.
            let (lo, hi) = if r1 <= r2 { (r1, r2) } else { (r2, r1) };
            prop_assert!(
                default_action_for(Decision::new(b, lo))
                    >= default_action_for(Decision::new(b, hi))
            );
        }
    }
}
