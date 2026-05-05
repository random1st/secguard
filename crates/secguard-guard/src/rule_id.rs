//! Machine-readable rule identifiers for telemetry and shadow-mode analytics.
//!
//! Granular reason codes shadow the bash-guard taxonomy where rules overlap so
//! the imported fixtures can map cleanly. Codes for rules we do not yet
//! implement are intentionally absent — the fixture runner will report those as
//! baseline mismatches.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    GitForcePush,
    GitResetHard,
    GitResetMerge,
    GitCleanForce,
    GitCheckoutPathspec,
    GitRestorePathspec,
    GitBranchForceDelete,
    GitStashLoss,
    GitHistoryRewrite,
    RmRf,
    RmRecursive,
    FindDelete,
    Shred,
    SqlDestructive,
    DockerPrune,
    PipeToShell,
    NoVerify,
    HttpDeleteExternal,
    UnsafeKill,
    AwsS3Rm,
    GhDestructive,
    SaasDestroy,
    Brain,
}

impl RuleId {
    pub const fn as_code(self) -> &'static str {
        match self {
            RuleId::GitForcePush => "git.force_push",
            RuleId::GitResetHard => "git.reset_hard",
            RuleId::GitResetMerge => "git.reset_merge",
            RuleId::GitCleanForce => "git.clean_force",
            RuleId::GitCheckoutPathspec => "git.checkout_pathspec",
            RuleId::GitRestorePathspec => "git.restore_pathspec",
            RuleId::GitBranchForceDelete => "git.branch_force_delete",
            RuleId::GitStashLoss => "git.stash_loss",
            RuleId::GitHistoryRewrite => "git.history_rewrite",
            RuleId::RmRf => "rm.rf",
            RuleId::RmRecursive => "rm.recursive",
            RuleId::FindDelete => "rm.find_delete",
            RuleId::Shred => "rm.shred",
            RuleId::SqlDestructive => "db_client.sql_destructive",
            RuleId::DockerPrune => "infra.docker_system_prune",
            RuleId::PipeToShell => "infra.pipe_to_shell",
            RuleId::NoVerify => "guard.no_verify",
            RuleId::HttpDeleteExternal => "infra.cloud_api_mutation",
            RuleId::UnsafeKill => "infra.unsafe_kill",
            RuleId::AwsS3Rm => "infra.aws_s3_rm",
            RuleId::GhDestructive => "infra.gh_destructive",
            RuleId::SaasDestroy => "paas.destroy",
            RuleId::Brain => "brain.classification",
        }
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_code())
    }
}
