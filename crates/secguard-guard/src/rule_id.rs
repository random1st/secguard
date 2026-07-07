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
    IndirectUnresolved,
    NoVerify,
    HttpDeleteExternal,
    UnsafeKill,
    AwsS3Rm,
    GhDestructive,
    SaasDestroy,
    TerraformMutation,
    RedisDestructive,
    OpensearchMutation,
    MongoDestructive,
    OrmMigration,
    SupabaseDbMutation,
    HelmMutation,
    KubectlMutation,
    DockerPush,
    GsutilMutation,
    GraphqlMutation,
    ChmodWorldWritable,
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
            RuleId::IndirectUnresolved => "infra.indirect_unresolved",
            RuleId::NoVerify => "guard.no_verify",
            RuleId::HttpDeleteExternal => "infra.cloud_api_mutation",
            RuleId::UnsafeKill => "infra.unsafe_kill",
            RuleId::AwsS3Rm => "infra.aws_s3_rm",
            RuleId::GhDestructive => "infra.gh_destructive",
            RuleId::SaasDestroy => "paas.destroy",
            RuleId::TerraformMutation => "infra.terraform_mutation",
            RuleId::RedisDestructive => "db_client.redis_destructive",
            RuleId::OpensearchMutation => "infra.opensearch_mutation",
            RuleId::MongoDestructive => "infra.mongo_destructive",
            RuleId::OrmMigration => "supabase.orm_migration",
            RuleId::SupabaseDbMutation => "supabase.db_mutation",
            RuleId::HelmMutation => "infra.helm_mutation",
            RuleId::KubectlMutation => "infra.kubectl_destructive",
            RuleId::DockerPush => "infra.docker_destructive",
            RuleId::GsutilMutation => "infra.gsutil_mutation",
            RuleId::GraphqlMutation => "infra.cloud_api_mutation",
            RuleId::ChmodWorldWritable => "fs.chmod_world_writable",
            RuleId::Brain => "brain.classification",
        }
    }
}

impl RuleId {
    /// 2D damage score for this rule (RAN-414).
    ///
    /// Exhaustive `match` with **no wildcard arm**: adding a [`RuleId`]
    /// variant without a score here is a compile error (E0004,
    /// non-exhaustive match). This is the type-system enforcement for
    /// "every rule must declare a blast × reversibility score" — there is
    /// no runtime fallback to forget. See `docs/scoring.md`.
    pub const fn score(self) -> crate::scoring::Decision {
        use crate::scoring::Decision as D;
        match self {
            // Git — mostly local repo state; reflog/up-down make many recoverable.
            RuleId::GitForcePush => D::new(3, 2),
            // `git reset --hard` discards uncommitted working-tree changes,
            // which the reflog does NOT recover (it tracks commits, not the
            // working tree) — reversibility 0, not 2. `--merge` only drops
            // merge state and refuses to clobber local edits, so it stays at 2.
            RuleId::GitResetHard => D::new(1, 0),
            RuleId::GitResetMerge => D::new(1, 2),
            RuleId::GitCleanForce => D::new(1, 0), // untracked files: no git recovery
            RuleId::GitCheckoutPathspec => D::new(1, 1),
            RuleId::GitRestorePathspec => D::new(1, 1),
            RuleId::GitBranchForceDelete => D::new(1, 2),
            RuleId::GitStashLoss => D::new(1, 1),
            RuleId::GitHistoryRewrite => D::new(3, 1), // rewrites shared history
            // rm family — rm.rs only emits these for non-safe (dangerous) paths.
            RuleId::RmRf => D::new(3, 0),
            RuleId::RmRecursive => D::new(2, 0),
            RuleId::FindDelete => D::new(2, 0),
            RuleId::Shred => D::new(1, 0), // single file, intentionally permanent
            // Databases — data loss, frequently prod, no assumed backup.
            RuleId::SqlDestructive => D::new(4, 0),
            RuleId::RedisDestructive => D::new(4, 0),
            RuleId::MongoDestructive => D::new(4, 0),
            RuleId::OpensearchMutation => D::new(3, 1),
            // Local infra / arbitrary exec.
            RuleId::DockerPrune => D::new(2, 2), // re-pullable
            RuleId::PipeToShell => D::new(3, 1), // arbitrary remote code
            RuleId::IndirectUnresolved => D::new(2, 1),
            RuleId::NoVerify => D::new(1, 3), // skips hooks; commit recoverable
            RuleId::UnsafeKill => D::new(2, 3), // process restartable
            // Cloud / remote resources.
            RuleId::HttpDeleteExternal => D::new(3, 1),
            RuleId::AwsS3Rm => D::new(3, 0),
            RuleId::GhDestructive => D::new(3, 1),
            RuleId::TerraformMutation => D::new(3, 1),
            RuleId::HelmMutation => D::new(3, 2), // helm rollback exists
            RuleId::KubectlMutation => D::new(3, 2), // re-apply manifest
            RuleId::DockerPush => D::new(2, 2),   // registry tag overwrite
            RuleId::GsutilMutation => D::new(3, 0),
            RuleId::GraphqlMutation => D::new(3, 1),
            // PaaS / managed DB.
            RuleId::SaasDestroy => D::new(3, 0),
            RuleId::SupabaseDbMutation => D::new(4, 0),
            RuleId::OrmMigration => D::new(2, 2), // up/down migrations
            // World-writable perms: broad security exposure; original per-file
            // modes are not cheaply restorable after a recursive blanket chmod.
            RuleId::ChmodWorldWritable => D::new(3, 1),
            // ML catch-all — conservative default for flagged unknowns.
            RuleId::Brain => D::new(2, 1),
        }
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_code())
    }
}
