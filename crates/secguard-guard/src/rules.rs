//! Predicate-style destructive-command rules over [`EffectiveCommand`].
//!
//! Each rule is a pure function from a parsed command to an optional
//! [`RuleHit`]. The dispatcher in [`crate::lib::check_detailed`] walks
//! every effective command produced by [`crate::ast::parse`] and runs
//! the rules in declaration order; the first match wins.
//!
//! All shell-words tokenisation, wrapper unwrapping, and cwd tracking
//! happens once in [`crate::ast`]; rules see clean argv + context and
//! do not touch raw command strings.

use crate::ast::{EffectiveCommand, SpanKind};
use crate::config::GuardConfig;
use crate::matcher::{self, ListRule};
use crate::rule_id::RuleId;

pub type RuleHit = (RuleId, String);

/// Run all predicate rules over `cmd` and return the first match.
pub fn classify(cmd: &EffectiveCommand, config: &GuardConfig) -> Option<RuleHit> {
    if cmd.span != SpanKind::Executed {
        return None;
    }
    if cmd.argv.is_empty() {
        return None;
    }
    for rule in RULES {
        if let Some(hit) = rule(cmd, config) {
            return Some(hit);
        }
    }
    None
}

/// Configured path denies must run before configured command allows in
/// `check_detailed`, so expose just that narrow predicate separately from the
/// default heuristic dispatcher.
pub(crate) fn classify_configured_path_deny(
    cmd: &EffectiveCommand,
    config: &GuardConfig,
) -> Option<RuleHit> {
    if cmd.span != SpanKind::Executed {
        return None;
    }
    let head = cmd.head()?;
    if !matches!(head, "rm" | "unlink" | "rmdir") {
        return None;
    }

    let parsed = parse_rm_args(head, cmd.args());
    let effective_operands = effectivise_operands(&parsed.operands, cmd.cwd.as_deref());
    let lists = crate::config::build_rule_lists(config);
    configured_path_deny(head, &parsed, &effective_operands, &lists.deny.paths)
}

type Rule = fn(&EffectiveCommand, &GuardConfig) -> Option<RuleHit>;

const RULES: &[Rule] = &[
    rule_git_checkout,
    rule_git_clean,
    rule_git_restore,
    rule_git_stash_loss,
    rule_git_branch_force_delete,
    rule_git_history_rewrite,
    rule_git_push,
    rule_git_reset,
    rule_bfg,
    rule_rm_family,
    rule_chmod_world_writable,
    rule_sql_destructive,
    rule_unsafe_kill,
    rule_docker,
    rule_pipe_to_shell,
    rule_shred,
    rule_no_verify,
    rule_opensearch_mutation,
    rule_http_delete_external,
    rule_terraform_mutation,
    rule_redis_destructive,
    rule_mongo_destructive,
    rule_orm_migration,
    rule_supabase_db_mutation,
    rule_heroku_pg_reset,
    rule_helm_mutation,
    rule_kubectl_destructive,
    rule_gsutil_mutation,
    rule_netlify_sites_delete,
    rule_railway_down,
    rule_graphql_mutation,
    rule_aws_s3_rm,
    rule_gh_destructive,
    rule_saas_destroy,
];

// ── chmod ────────────────────────────────────────────────────────────

/// Flags `chmod` that grants world-write in a way that is almost always a
/// mistake: recursively (`chmod -R 777`, `-R a+rwx`, `-R o+w`) or a
/// world-writable mode on a catastrophic path (`chmod 777 /`). Ordinary
/// `chmod +x`, `644`, `755`, `u+x`, or `777` on a single local file pass.
fn rule_chmod_world_writable(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head()? != "chmod" {
        return None;
    }
    let args = c.args();

    let recursive = args.iter().any(|a| {
        a == "--recursive"
            || (a.starts_with('-') && !a.starts_with("--") && (a.contains('R') || a.contains('r')))
    });

    let non_flags: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    // The mode is the first non-flag token; the rest are path operands.
    let mode = non_flags.first().copied()?;
    if !mode_is_world_writable(mode) {
        return None;
    }

    if recursive {
        return Some((
            RuleId::ChmodWorldWritable,
            format!("chmod recursive world-writable ({mode})"),
        ));
    }

    for &op in non_flags.iter().skip(1) {
        if is_catastrophic_path(op) {
            return Some((
                RuleId::ChmodWorldWritable,
                format!("chmod world-writable on catastrophic path: {op}"),
            ));
        }
    }

    None
}

/// A mode string grants write to "others" (world-writable). Handles octal
/// (`777`, `0666`, `2777`) via bit 2 of the last digit, plus common symbolic
/// forms (`o+w`, `a+w`, `a+rwx`, `+rwx`, `o=rwx`).
fn mode_is_world_writable(mode: &str) -> bool {
    let is_octal = !mode.is_empty()
        && (3..=4).contains(&mode.len())
        && mode.bytes().all(|b| b.is_ascii_digit());
    if is_octal {
        if let Some(last) = mode.chars().last().and_then(|c| c.to_digit(8)) {
            return last & 0o2 != 0;
        }
        return false;
    }
    mode.contains("o+w")
        || mode.contains("a+w")
        || mode.contains("a+rwx")
        || mode.contains("+rwx")
        || mode.contains("o=rwx")
}

// ── git ──────────────────────────────────────────────────────────────

fn rule_git_checkout(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") {
        return None;
    }
    let args = c.args();
    if args.first().map(String::as_str) != Some("checkout") {
        return None;
    }
    let rest = &args[1..];
    if rest.iter().any(|t| t == "-f" || t == "--force") {
        return Some((
            RuleId::GitCheckoutPathspec,
            "git checkout -f (force overwrites worktree)".into(),
        ));
    }
    if let Some(sep_idx) = rest.iter().position(|t| t == "--") {
        if rest.get(sep_idx + 1).is_some() {
            return Some((
                RuleId::GitCheckoutPathspec,
                "git checkout -- <pathspec> (discards uncommitted changes)".into(),
            ));
        }
    }
    if rest.iter().any(|t| t == ".") {
        return Some((
            RuleId::GitCheckoutPathspec,
            "git checkout . (discards uncommitted changes)".into(),
        ));
    }
    None
}

fn rule_git_clean(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") || c.args().first().map(String::as_str) != Some("clean") {
        return None;
    }
    let mut force = false;
    let mut dry_run = false;
    for t in &c.args()[1..] {
        if t == "--dry-run" {
            dry_run = true;
            continue;
        }
        if t == "--force" {
            force = true;
            continue;
        }
        if let Some(short) = t.strip_prefix('-') {
            if short.starts_with('-') {
                continue;
            }
            for ch in short.chars() {
                match ch {
                    'f' | 'd' | 'x' => force = true,
                    'n' => dry_run = true,
                    _ => {}
                }
            }
        }
    }
    if force && !dry_run {
        Some((
            RuleId::GitCleanForce,
            "git clean -f (removes untracked files permanently)".into(),
        ))
    } else {
        None
    }
}

fn rule_git_restore(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") || c.args().first().map(String::as_str) != Some("restore") {
        return None;
    }
    let rest = &c.args()[1..];
    // `git restore --staged .` only un-stages (reversible). `git
    // restore --source=<ref> .` is an intentional restore from that
    // ref, not a discard of uncommitted changes — allow.
    if rest
        .iter()
        .any(|t| t == "--staged" || t == "-S" || t == "--source" || t.starts_with("--source="))
    {
        return None;
    }
    if rest.iter().any(|t| t == ".") {
        return Some((
            RuleId::GitRestorePathspec,
            "git restore . (discards uncommitted changes)".into(),
        ));
    }
    None
}

fn rule_git_stash_loss(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") || c.args().first().map(String::as_str) != Some("stash") {
        return None;
    }
    if c.args()
        .get(1)
        .map(String::as_str)
        .is_some_and(|s| s == "drop" || s == "clear")
    {
        return Some((
            RuleId::GitStashLoss,
            "git stash drop/clear (permanently deletes stashed work)".into(),
        ));
    }
    None
}

fn rule_git_branch_force_delete(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") || c.args().first().map(String::as_str) != Some("branch") {
        return None;
    }
    let rest = &c.args()[1..];
    if rest.iter().any(|t| t == "-D")
        || (rest.iter().any(|t| t == "--delete") && rest.iter().any(|t| t == "--force"))
    {
        return Some((
            RuleId::GitBranchForceDelete,
            "git branch -D (force-deletes branch without merge check)".into(),
        ));
    }
    None
}

fn rule_git_history_rewrite(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") {
        return None;
    }
    let sub = c.args().first().map(String::as_str);
    match sub {
        Some("rebase") => Some((
            RuleId::GitHistoryRewrite,
            "git rebase (rewrites commit history)".into(),
        )),
        Some("filter-branch") => Some((
            RuleId::GitHistoryRewrite,
            "git filter-branch (rewrites entire history)".into(),
        )),
        Some("filter-repo") => {
            if c.args().iter().any(|t| t == "--analyze") {
                None
            } else {
                Some((
                    RuleId::GitHistoryRewrite,
                    "git filter-repo (rewrites entire history)".into(),
                ))
            }
        }
        _ => None,
    }
}

fn rule_git_push(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") || c.args().first().map(String::as_str) != Some("push") {
        return None;
    }
    let rest = &c.args()[1..];
    let has_force = rest.iter().any(|t| {
        t == "--force"
            || t == "--force-with-lease"
            || t == "-f"
            || (t.starts_with('-') && !t.starts_with("--") && t.contains('f'))
    });
    let has_mirror = rest.iter().any(|t| t == "--mirror");
    let has_delete = rest.iter().any(|t| t == "--delete" || t == "-d");
    let plus_ref = rest.iter().any(|t| {
        t.strip_prefix('+').is_some_and(|rest| {
            rest.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '/')
        })
    });
    let colon_ref = rest.iter().any(|t| t.starts_with(':') && t.len() > 1);

    if has_force {
        return Some((
            RuleId::GitForcePush,
            "git push --force (overwrites remote history)".into(),
        ));
    }
    if has_mirror {
        return Some((
            RuleId::GitForcePush,
            "git push --mirror (overwrites every remote ref)".into(),
        ));
    }
    if has_delete {
        return Some((
            RuleId::GitHistoryRewrite,
            "git push --delete (deletes remote ref)".into(),
        ));
    }
    if colon_ref {
        return Some((
            RuleId::GitHistoryRewrite,
            "git push :ref (refspec form deletes remote ref)".into(),
        ));
    }
    if plus_ref {
        return Some((
            RuleId::GitForcePush,
            "git push +ref (refspec leading + forces non-FF)".into(),
        ));
    }
    None
}

fn rule_git_reset(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("git") || c.args().first().map(String::as_str) != Some("reset") {
        return None;
    }
    let rest = &c.args()[1..];
    if rest.iter().any(|t| t == "--hard") {
        return Some((
            RuleId::GitResetHard,
            "git reset --hard (discards all uncommitted changes)".into(),
        ));
    }
    if rest.iter().any(|t| t == "--merge") {
        return Some((
            RuleId::GitResetMerge,
            "git reset --merge (discards merge state)".into(),
        ));
    }
    None
}

fn rule_bfg(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("bfg") {
        return None;
    }
    let has_action = c
        .args()
        .iter()
        .any(|t| t != "--help" && t != "-h" && t != "--version" && t != "-V");
    if has_action {
        Some((
            RuleId::GitHistoryRewrite,
            "bfg (Repo-Cleaner — rewrites history)".into(),
        ))
    } else {
        None
    }
}

// ── rm / unlink / rmdir ─────────────────────────────────────────────

fn rule_rm_family(c: &EffectiveCommand, config: &GuardConfig) -> Option<RuleHit> {
    let head = c.head()?;
    if !matches!(head, "rm" | "unlink" | "rmdir") {
        return None;
    }
    let parsed = parse_rm_args(head, c.args());

    if parsed.no_preserve_root {
        return Some((
            RuleId::RmRf,
            format!(
                "{head} --no-preserve-root (explicit override): {}",
                join_operands(&parsed.operands)
            ),
        ));
    }

    let effective_operands = effectivise_operands(&parsed.operands, c.cwd.as_deref());
    for op in &effective_operands {
        if is_catastrophic_path(op) {
            return Some((RuleId::RmRf, format!("{head} of catastrophic path: {op}")));
        }
    }

    let lists = crate::config::build_rule_lists(config);
    if let Some(hit) = configured_path_deny(head, &parsed, &effective_operands, &lists.deny.paths) {
        return Some(hit);
    }

    if head == "rm" && !parsed.recursive {
        return None;
    }

    // Remote / chrooted commands disable the local safe-paths allowlist.
    let local_paths_apply = !c.remote && !c.chrooted;
    let all_safe = !effective_operands.is_empty()
        && effective_operands.iter().all(|op| {
            if local_paths_apply {
                path_allowed_by_config(op, &lists.allow.paths)
                    || is_safe_operand(op, &config.safe_rm_patterns)
            } else {
                false
            }
        });
    if all_safe {
        return None;
    }

    let rule = if parsed.recursive {
        RuleId::RmRf
    } else {
        RuleId::RmRecursive
    };
    let label = if parsed.recursive { "rm -rf" } else { head };
    let suffix = if parsed.recursive {
        "(recursive force delete)"
    } else if head == "unlink" {
        "(targeted file deletion)"
    } else if head == "rmdir" {
        "(directory deletion)"
    } else {
        "(deletion outside safe paths)"
    };
    Some((
        rule,
        format!("{label} {suffix}: {}", join_operands(&parsed.operands)),
    ))
}

fn configured_path_deny(
    head: &str,
    parsed: &RmArgs,
    operands: &[String],
    deny_paths: &[ListRule],
) -> Option<RuleHit> {
    for op in operands {
        if let matcher::Decision::Deny { rule_id, reason } = matcher::evaluate(op, deny_paths, &[])
        {
            let detail = reason
                .map(|r| format!("config deny path rule {rule_id} on {op}: {r}"))
                .unwrap_or_else(|| format!("config deny path rule {rule_id} on {op}"));
            return Some((rm_rule_id(head, parsed), detail));
        }
    }
    None
}

fn path_allowed_by_config(operand: &str, allow_paths: &[ListRule]) -> bool {
    matches!(
        matcher::evaluate(operand, &[], allow_paths),
        matcher::Decision::Allow { .. }
    )
}

fn rm_rule_id(head: &str, parsed: &RmArgs) -> RuleId {
    if head == "rm" && parsed.recursive {
        RuleId::RmRf
    } else {
        RuleId::RmRecursive
    }
}

#[derive(Default, Debug)]
struct RmArgs {
    recursive: bool,
    #[allow(dead_code)]
    force: bool,
    no_preserve_root: bool,
    operands: Vec<String>,
}

fn parse_rm_args(rm_name: &str, args: &[String]) -> RmArgs {
    let mut out = RmArgs::default();
    if rm_name == "unlink" || rm_name == "rmdir" {
        for a in args {
            if !a.starts_with('-') {
                out.operands.push(a.clone());
            }
        }
        return out;
    }
    let mut after_double_dash = false;
    for a in args {
        if after_double_dash {
            out.operands.push(a.clone());
            continue;
        }
        if a == "--" {
            after_double_dash = true;
            continue;
        }
        if a == "--no-preserve-root" {
            out.no_preserve_root = true;
            continue;
        }
        if a == "--preserve-root" {
            continue;
        }
        if a == "--recursive" || a == "--Recursive" {
            out.recursive = true;
            continue;
        }
        if a == "--force" {
            out.force = true;
            continue;
        }
        if matches!(
            a.as_str(),
            "--dir" | "--interactive" | "--verbose" | "--one-file-system"
        ) {
            continue;
        }
        if let Some(short) = a.strip_prefix('-') {
            if short.is_empty() || short.starts_with('-') {
                out.operands.push(a.clone());
                continue;
            }
            let mut consumed = true;
            for ch in short.chars() {
                match ch {
                    'r' | 'R' => out.recursive = true,
                    'f' => out.force = true,
                    'i' | 'I' | 'v' | 'd' => {}
                    _ => {
                        consumed = false;
                        break;
                    }
                }
            }
            if consumed {
                continue;
            }
            out.operands.push(a.clone());
            continue;
        }
        out.operands.push(a.clone());
    }
    out
}

/// Resolve relative operands against `cwd` so an `rm -rf ci-results`
/// after `cd /tmp` is checked as `/tmp/ci-results`. Absolute and shell-
/// variable operands pass through unchanged.
fn effectivise_operands(operands: &[String], cwd: Option<&str>) -> Vec<String> {
    operands.iter().map(|op| effective_path(op, cwd)).collect()
}

fn effective_path(operand: &str, cwd: Option<&str>) -> String {
    let Some(cwd) = cwd else {
        return operand.to_string();
    };
    if operand == "." || operand == "./" {
        return cwd.to_string();
    }
    if operand.starts_with('/') || operand.starts_with('~') || operand.starts_with('$') {
        return operand.to_string();
    }
    let stripped = operand.strip_prefix("./").unwrap_or(operand);
    let cwd = cwd.trim_end_matches('/');
    format!("{cwd}/{stripped}")
}

fn join_operands(operands: &[String]) -> String {
    if operands.is_empty() {
        "(no operand)".into()
    } else {
        operands.join(", ")
    }
}

fn is_catastrophic_path(operand: &str) -> bool {
    if operand.contains("..") {
        return true;
    }
    const EXACT_ROOTS: &[&str] = &[
        "/",
        "//",
        "*",
        "/*",
        "$HOME",
        "${HOME}",
        "~",
        "/etc",
        "/usr",
        "/var",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/opt",
        "/boot",
        "/root",
        "/System",
        "/Library",
        "/Applications",
        "/Users",
        "/home",
    ];
    if EXACT_ROOTS.contains(&operand) {
        return true;
    }
    const CATASTROPHIC_PREFIXES: &[&str] = &[
        "$HOME/",
        "${HOME}/",
        "~/",
        "/etc/",
        "/usr/",
        "/var/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib64/",
        "/opt/",
        "/boot/",
        "/root/",
        "/System/",
        "/Library/",
        "/Applications/",
        "/Users/",
        "/home/",
    ];
    for p in CATASTROPHIC_PREFIXES {
        if operand.starts_with(p) {
            if *p == "/var/" && operand.starts_with("/var/tmp/") {
                return false;
            }
            return true;
        }
    }
    false
}

fn is_safe_operand(operand: &str, safe_patterns: &[String]) -> bool {
    if operand.contains("..") {
        return false;
    }
    const ABSOLUTE_SAFE_ROOTS: &[&str] = &["/tmp/", "/var/tmp/", "/private/tmp/"];
    for root in ABSOLUTE_SAFE_ROOTS {
        if operand == &root[..root.len() - 1] || operand == *root {
            return false;
        }
        if let Some(rest) = operand.strip_prefix(root) {
            if rest.is_empty() {
                return false;
            }
            let first_component = rest.split('/').next().unwrap_or("");
            if first_component.contains(['*', '?', '[', '{']) {
                return false;
            }
            return true;
        }
    }
    if operand.starts_with('/') || operand.starts_with('~') || operand.starts_with('$') {
        return false;
    }
    let normalized = operand.strip_prefix("./").unwrap_or(operand);
    // Allow simple relative globs that include literal text (`*.log`,
    // `tmp-*`). Reject pure `*` / `**` / `*/*` — too broad.
    let has_glob = normalized.contains(['*', '?', '[']);
    if has_glob {
        let has_literal = normalized
            .chars()
            .any(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
        let has_slash = normalized.contains('/');
        if has_literal && !has_slash {
            return true;
        }
        return false;
    }
    for sp in safe_patterns {
        if sp.starts_with('/') {
            continue;
        }
        let pattern = sp.trim_end_matches('/');
        if normalized == pattern {
            return true;
        }
        let prefix = format!("{pattern}/");
        if normalized.starts_with(&prefix) {
            return true;
        }
    }
    false
}

// ── SQL / kill / docker / find / pipe-to-shell / shred / no-verify ──

fn rule_sql_destructive(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    let joined = c.argv.join(" ").to_ascii_lowercase();
    if joined.contains("drop table")
        || joined.contains("drop database")
        || joined.contains("drop view")
        || joined.contains("drop index")
        || joined.contains("truncate ")
        || joined.contains("delete from ")
    {
        Some((
            RuleId::SqlDestructive,
            "SQL destructive operation (DROP/TRUNCATE/DELETE FROM)".into(),
        ))
    } else {
        None
    }
}

fn rule_unsafe_kill(c: &EffectiveCommand, config: &GuardConfig) -> Option<RuleHit> {
    let head = c.head()?;
    if !matches!(head, "pkill" | "killall" | "kill") {
        return None;
    }
    if matches!(head, "pkill" | "killall") {
        let matches_safe = c
            .args()
            .iter()
            .any(|t| !t.starts_with('-') && config.safe_kill_targets.iter().any(|s| s == t));
        if matches_safe {
            return None;
        }
    }
    Some((
        RuleId::UnsafeKill,
        "process termination outside safe_kill_targets".into(),
    ))
}

fn rule_docker(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("docker") {
        return None;
    }
    const DOCKER_FLAG_VALS: &[&str] = &[
        "-H",
        "--host",
        "--context",
        "--config",
        "--log-level",
        "--tls-cacert",
        "--tls-cert",
        "--tls-key",
    ];
    let pos = positional_after_flags(c.args(), DOCKER_FLAG_VALS);
    let first = pos.first().copied();
    let second = pos.get(1).copied();
    match (first, second) {
        (Some("system" | "volume"), Some("prune")) => Some((
            RuleId::DockerPrune,
            "docker prune (removes containers/volumes permanently)".into(),
        )),
        (Some("push"), Some(_)) => Some((
            RuleId::DockerPush,
            "docker push (publishes image to registry)".into(),
        )),
        (Some("rm"), _) | (Some("container"), Some("rm")) => Some((
            RuleId::SaasDestroy,
            "container destruction (docker rm)".into(),
        )),
        _ => None,
    }
}

fn rule_pipe_to_shell(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    // The AST walker emits a synthetic `__pipe_to_shell__` command
    // when it detects a pipeline shape `curl URL | bash` (non-literal
    // upstream feeding a shell). The walker also re-parses literal
    // upstreams like `echo "rm -rf /" | bash` directly, so those are
    // handled by other rules.
    if c.head() == Some("__pipe_to_shell__") {
        let url = c.args().first().map(String::as_str).unwrap_or("");
        return Some((
            RuleId::PipeToShell,
            format!("pipe to shell (curl/wget URL → bash): {url}"),
        ));
    }
    // The walker also emits `__eval_dynamic__` for `eval "$X"` /
    // `eval $(cmd)` where the executed body is unknown at parse time.
    // Treat as destructive: agent could be expanding hidden state,
    // and conservative ask is safer than silent allow.
    if c.head() == Some("__eval_dynamic__") {
        let body = c.args().first().map(String::as_str).unwrap_or("");
        return Some((
            RuleId::PipeToShell,
            format!("eval of dynamic input (unknown body): {body}"),
        ));
    }
    // `a="rm -rf /"; $a` and `bash -c "$a"` with `a` unbound (or set
    // via read/$(cmd)) reach here. With a known binding the AST
    // walker resolves textually; only opaque indirection lands as
    // this marker — guard semantics prefer a conservative ask over
    // silent allow.
    if c.head() == Some("__indirect_unresolved__") {
        let body = c.args().first().map(String::as_str).unwrap_or("");
        return Some((
            RuleId::IndirectUnresolved,
            format!("indirect command via unresolved variable: {body}"),
        ));
    }
    None
}

fn rule_shred(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() == Some("shred") {
        Some((
            RuleId::Shred,
            "shred (irreversible file destruction)".into(),
        ))
    } else {
        None
    }
}

fn rule_no_verify(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.args().iter().any(|t| t == "--no-verify") {
        Some((RuleId::NoVerify, "--no-verify (skips safety hooks)".into()))
    } else {
        None
    }
}

// ── HTTP / cloud APIs / GraphQL ─────────────────────────────────────

fn rule_opensearch_mutation(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("curl") && c.head() != Some("http") && c.head() != Some("httpie") {
        return None;
    }
    let joined = c.argv.join(" ");
    let lower = joined.to_ascii_lowercase();
    let looks_like_es_or_os = lower.contains(":9200")
        || lower.contains(":9243")
        || lower.contains("elastic")
        || lower.contains("opensearch")
        || lower.contains("//es.")
        || lower.contains("//os.");
    if !looks_like_es_or_os {
        return None;
    }
    let mutating = joined.contains("-X DELETE")
        || joined.contains("-XDELETE")
        || joined.contains("-X POST")
        || joined.contains("-XPOST")
        || joined.contains("-X PUT")
        || joined.contains("-XPUT")
        || joined.contains("-X PATCH")
        || joined.contains("-XPATCH")
        || joined.contains("--request DELETE")
        || joined.contains("--request POST")
        || joined.contains("--request PUT")
        || joined.contains("--request PATCH")
        || c.args().iter().any(|t| t == "-d" || t == "--data");
    if !mutating {
        return None;
    }
    if is_localhost(&lower) {
        return None;
    }
    Some((
        RuleId::OpensearchMutation,
        "ElasticSearch/OpenSearch mutating HTTP request (DELETE/POST/PUT/PATCH)".into(),
    ))
}

fn rule_http_delete_external(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    let head = c.head()?;
    if head != "curl" && head != "http" && head != "httpie" {
        return None;
    }
    let joined = c.argv.join(" ");
    let lower = joined.to_ascii_lowercase();
    let has_curl_delete = head == "curl"
        && (joined.contains("-X DELETE")
            || joined.contains("-XDELETE")
            || joined.contains("--request DELETE")
            || joined.contains("-X delete")
            || joined.contains("--request delete"));
    let has_httpie_delete =
        head == "http" && c.args().iter().any(|t| t == "DELETE" || t == "delete");
    if !has_curl_delete && !has_httpie_delete {
        return None;
    }
    if is_localhost(&lower) {
        return None;
    }
    Some((
        RuleId::HttpDeleteExternal,
        "HTTP DELETE to external service (deletes remote data)".into(),
    ))
}

fn rule_graphql_mutation(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("curl") {
        return None;
    }
    let joined = c.argv.join(" ");
    if !joined.contains("graphql") && !joined.contains("/graphql") {
        return None;
    }
    let lower = joined.to_ascii_lowercase();
    if is_localhost(&lower) {
        return None;
    }
    let posty = joined.contains("-X POST")
        || joined.contains("-XPOST")
        || joined.contains("--request POST")
        || c.args().iter().any(|t| t == "-d" || t == "--data");
    if !posty {
        return None;
    }
    if !contains_graphql_mutation_keyword(&lower) {
        return None;
    }
    if lower.contains("delete")
        || lower.contains("destroy")
        || lower.contains("remove")
        || lower.contains("drop")
        || lower.contains("purge")
        || lower.contains("terminate")
    {
        Some((
            RuleId::GraphqlMutation,
            "GraphQL mutation with delete/destroy in body".into(),
        ))
    } else {
        None
    }
}

fn contains_graphql_mutation_keyword(lower: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = lower[from..].find("mutation") {
        let abs = from + pos;
        let before_ok = abs == 0
            || !lower
                .as_bytes()
                .get(abs - 1)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        let after_idx = abs + "mutation".len();
        let after_ok = lower
            .as_bytes()
            .get(after_idx)
            .map(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
            .unwrap_or(true);
        if before_ok && after_ok {
            return true;
        }
        from = abs + 1;
    }
    false
}

fn is_localhost(lower: &str) -> bool {
    lower.contains("localhost")
        || lower.contains("127.0.0.1")
        || lower.contains("[::1]")
        || lower.contains("0.0.0.0")
}

// ── Cloud / infra CLIs ──────────────────────────────────────────────

fn rule_terraform_mutation(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    let head = c.head()?;
    if head != "terraform" && head != "tofu" {
        return None;
    }
    if matches!(
        c.args().first().map(String::as_str),
        Some("apply" | "destroy")
    ) {
        Some((
            RuleId::TerraformMutation,
            format!("{head} {} (mutates infrastructure)", c.args()[0]),
        ))
    } else {
        None
    }
}

fn rule_redis_destructive(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("redis-cli") {
        return None;
    }
    for t in c.args() {
        let upper = t.to_ascii_uppercase();
        if matches!(
            upper.as_str(),
            "FLUSHALL" | "FLUSHDB" | "SHUTDOWN" | "MIGRATE"
        ) {
            return Some((
                RuleId::RedisDestructive,
                format!("redis-cli {upper} (data destruction / server shutdown)"),
            ));
        }
    }
    None
}

fn rule_mongo_destructive(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    let head = c.head()?;
    if head != "mongo" && head != "mongosh" {
        return None;
    }
    let mut iter = c.args().iter().peekable();
    while let Some(t) = iter.next() {
        let body: Option<&str> = if t == "--eval" || t == "-e" {
            iter.next().map(String::as_str)
        } else if let Some(rest) = t.strip_prefix("--eval=") {
            Some(rest)
        } else {
            None
        };
        if let Some(body) = body {
            if body.contains(".drop(")
                || body.contains(".dropDatabase(")
                || body.contains(".deleteMany(")
                || body.contains(".deleteOne(")
                || body.contains(".dropCollection(")
            {
                return Some((
                    RuleId::MongoDestructive,
                    "mongo destructive op (drop/deleteMany)".into(),
                ));
            }
        }
    }
    None
}

fn rule_orm_migration(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    let head = c.head()?;
    let positional: Vec<&str> = c
        .args()
        .iter()
        .filter(|t| !t.starts_with('-'))
        .map(String::as_str)
        .collect();
    let sub1 = positional.first().copied();
    let sub2 = positional.get(1).copied();
    let reason = match (head, sub1, sub2) {
        ("alembic", Some("upgrade"), _) | ("alembic", Some("downgrade"), _) => {
            Some("alembic upgrade/downgrade (schema migration)")
        }
        ("prisma", Some("db"), Some("push")) | ("prisma", Some("db"), Some("seed")) => {
            Some("prisma db push (schema migration)")
        }
        ("prisma", Some("migrate"), Some("deploy"))
        | ("prisma", Some("migrate"), Some("reset"))
        | ("prisma", Some("migrate"), Some("resolve")) => Some("prisma migrate (schema migration)"),
        ("drizzle-kit", Some("push"), _) | ("drizzle-kit", Some("migrate"), _) => {
            Some("drizzle-kit push/migrate (schema migration)")
        }
        ("knex", Some(s), _) if s.starts_with("migrate:") => {
            Some("knex migrate:* (schema migration)")
        }
        ("goose", Some("up"), _)
        | ("goose", Some("down"), _)
        | ("goose", Some("reset"), _)
        | ("goose", Some("redo"), _) => Some("goose migration"),
        ("python" | "python3", Some(s), Some("migrate")) if s.ends_with("manage.py") => {
            Some("django manage.py migrate (schema migration)")
        }
        ("./manage.py" | "manage.py", Some("migrate"), _) => {
            Some("django manage.py migrate (schema migration)")
        }
        _ => None,
    };
    reason.map(|r| (RuleId::OrmMigration, r.into()))
}

fn rule_supabase_db_mutation(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("supabase") {
        return None;
    }
    let pos: Vec<&str> = c
        .args()
        .iter()
        .filter(|t| !t.starts_with('-'))
        .map(String::as_str)
        .collect();
    let leaks_db_url = c
        .args()
        .iter()
        .any(|t| t == "--db-url" || t.starts_with("--db-url="));
    if leaks_db_url {
        return Some((
            RuleId::SupabaseDbMutation,
            "supabase --db-url (leaks DB connection string)".into(),
        ));
    }
    match (pos.first().copied(), pos.get(1).copied()) {
        (Some("db"), Some("push")) => Some((
            RuleId::SupabaseDbMutation,
            "supabase db push (mutates remote schema)".into(),
        )),
        (Some("db"), Some("reset")) => Some((
            RuleId::SupabaseDbMutation,
            "supabase db reset (destroys remote DB)".into(),
        )),
        (Some("migration"), Some("repair")) => Some((
            RuleId::SupabaseDbMutation,
            "supabase migration repair (rewrites migration history)".into(),
        )),
        _ => None,
    }
}

fn rule_heroku_pg_reset(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("heroku") {
        return None;
    }
    if c.args()
        .iter()
        .any(|t| t == "pg:reset" || t == "apps:destroy")
    {
        Some((
            RuleId::SaasDestroy,
            "heroku pg:reset / apps:destroy (destructive)".into(),
        ))
    } else {
        None
    }
}

fn rule_helm_mutation(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("helm") {
        return None;
    }
    const HELM_FLAG_VALS: &[&str] = &[
        "-n",
        "--namespace",
        "--kubeconfig",
        "--kube-context",
        "--registry-config",
        "--repository-cache",
        "--repository-config",
        "--burst-limit",
        "--qps",
    ];
    let positional = positional_after_flags(c.args(), HELM_FLAG_VALS);
    match positional.first().copied() {
        Some("install" | "upgrade" | "uninstall" | "delete" | "rollback") => Some((
            RuleId::HelmMutation,
            format!("helm {} (cluster mutation)", positional[0]),
        )),
        _ => None,
    }
}

fn rule_kubectl_destructive(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("kubectl") {
        return None;
    }
    const KUBECTL_FLAG_VALS: &[&str] = &[
        "-n",
        "--namespace",
        "--context",
        "--cluster",
        "--user",
        "--kubeconfig",
        "--token",
        "--server",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--as",
        "--as-group",
        "-o",
        "--output",
    ];
    let positional = positional_after_flags(c.args(), KUBECTL_FLAG_VALS);
    let sub1 = positional.first().copied();
    let sub2 = positional.get(1).copied();
    let dest = matches!(
        sub1,
        Some(
            "apply"
                | "delete"
                | "patch"
                | "replace"
                | "edit"
                | "drain"
                | "cordon"
                | "uncordon"
                | "scale"
                | "annotate"
                | "label"
                | "create"
                | "set"
                | "autoscale"
                | "taint"
                | "expose"
                | "run"
        )
    ) || (sub1 == Some("rollout") && matches!(sub2, Some("restart" | "undo" | "pause")));
    if dest {
        return Some((
            RuleId::KubectlMutation,
            format!("kubectl {} (cluster mutation)", sub1.unwrap_or("?")),
        ));
    }
    // Carve-out: read-only verbs handled by policy.rs; anything else
    // not matched here is non-destructive (apply/etc list above is
    // explicit).
    None
}

fn rule_gsutil_mutation(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("gsutil") {
        return None;
    }
    const GSUTIL_FLAG_VALS: &[&str] = &["-h", "-D", "-DD", "-o", "-i", "-u"];
    let positional = positional_after_flags(c.args(), GSUTIL_FLAG_VALS);
    let first = positional.first().copied();
    if first == Some("rm") {
        return Some((
            RuleId::GsutilMutation,
            "gsutil rm (deletes GCS object)".into(),
        ));
    }
    if first == Some("rsync") && c.args().iter().any(|t| t == "-d") {
        return Some((
            RuleId::GsutilMutation,
            "gsutil rsync -d (mirror with delete)".into(),
        ));
    }
    if matches!(first, Some("rb" | "mv")) {
        return Some((
            RuleId::GsutilMutation,
            format!("gsutil {} (bucket mutation)", first.unwrap_or("?")),
        ));
    }
    None
}

fn rule_netlify_sites_delete(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("netlify") {
        return None;
    }
    if c.args()
        .iter()
        .any(|t| t.ends_with(":delete") || t.ends_with(":destroy") || t.ends_with(":remove"))
    {
        Some((RuleId::SaasDestroy, "netlify *:delete / *:destroy".into()))
    } else {
        None
    }
}

fn rule_railway_down(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("railway") {
        return None;
    }
    if c.args().first().map(String::as_str) == Some("down") {
        Some((
            RuleId::SaasDestroy,
            "external service tear-down (railway down)".into(),
        ))
    } else {
        None
    }
}

fn rule_aws_s3_rm(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("aws") {
        return None;
    }
    let mut saw_s3 = false;
    let mut saw_rm = false;
    for t in c.args() {
        if t == "s3" {
            saw_s3 = true;
        } else if saw_s3 && t == "rm" {
            saw_rm = true;
        }
    }
    if saw_s3 && saw_rm {
        Some((
            RuleId::AwsS3Rm,
            "external service data deletion (aws s3 rm)".into(),
        ))
    } else {
        None
    }
}

fn rule_gh_destructive(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    if c.head() != Some("gh") {
        return None;
    }
    let pos: Vec<&str> = c
        .args()
        .iter()
        .filter(|t| !t.starts_with('-'))
        .map(String::as_str)
        .collect();
    match (pos.first().copied(), pos.get(1).copied()) {
        (Some("repo"), Some("delete")) => Some((
            RuleId::GhDestructive,
            "GitHub CLI destructive operation (gh repo delete)".into(),
        )),
        (Some("release"), Some("delete")) => Some((
            RuleId::GhDestructive,
            "GitHub CLI destructive operation (gh release delete)".into(),
        )),
        (Some("run"), Some("delete")) => Some((
            RuleId::GhDestructive,
            "GitHub CLI destructive operation (gh run delete)".into(),
        )),
        _ => None,
    }
}

fn rule_saas_destroy(c: &EffectiveCommand, _: &GuardConfig) -> Option<RuleHit> {
    let head = c.head()?;
    const SAAS_CLIS: &[&str] = &[
        "stripe",
        "aws",
        "gcloud",
        "az",
        "firebase",
        "heroku",
        "fly",
        "flyctl",
        "vercel",
        "twilio",
        "sendgrid",
        "cloudflare",
        "wrangler",
        "supabase",
        "planetscale",
        "render",
        "pscale",
        "ibmcloud",
        "oci",
        "doctl",
        "linode-cli",
        "railway",
    ];
    if !SAAS_CLIS.contains(&head) {
        return None;
    }
    // gcloud storage rm and ibmcloud cluster-rm are special-cased.
    if head == "gcloud" {
        let pos: Vec<&str> = c
            .args()
            .iter()
            .filter(|t| !t.starts_with('-'))
            .map(String::as_str)
            .collect();
        if pos.first().copied() == Some("storage") && pos.contains(&"rm") {
            return Some((
                RuleId::SaasDestroy,
                "external service data deletion (gcloud storage rm)".into(),
            ));
        }
    }
    if head == "ibmcloud" && c.args().iter().any(|t| t.starts_with("cluster-rm")) {
        return Some((
            RuleId::SaasDestroy,
            "external service data deletion (ibmcloud cluster-rm)".into(),
        ));
    }
    const DESTRUCTIVE_VERBS: &[&str] = &[
        "delete",
        "remove",
        "destroy",
        "purge",
        "terminate",
        "cancel",
        "void",
        "archive",
        "revoke",
        "deactivate",
        "unsubscribe",
        "detach",
        "disassociate",
        "deregister",
        "drain",
        "cordon",
    ];
    for t in c.args() {
        let lower = t.to_ascii_lowercase();
        // bare verbs: `delete`, `destroy`, ...
        if DESTRUCTIVE_VERBS.contains(&lower.as_str()) {
            return Some((
                RuleId::SaasDestroy,
                format!("external service data deletion ({head} {lower})"),
            ));
        }
        // colon-suffix forms: `apps:destroy`, `pg:reset`, `sites:delete`.
        if let Some((_, suffix)) = lower.split_once(':') {
            if DESTRUCTIVE_VERBS.contains(&suffix) {
                return Some((
                    RuleId::SaasDestroy,
                    format!("external service data deletion ({head} {lower})"),
                ));
            }
        }
        // hyphenated AWS-style forms: `delete-volume`, `remove-tags`,
        // `terminate-instances`, etc. Prefix-match against verb list.
        for verb in DESTRUCTIVE_VERBS {
            let prefix = format!("{verb}-");
            if lower.starts_with(&prefix) {
                return Some((
                    RuleId::SaasDestroy,
                    format!("external service data deletion ({head} {lower})"),
                ));
            }
        }
    }
    None
}

fn positional_after_flags<'a>(args: &'a [String], flags_with_val: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(t) = iter.next() {
        let s = t.as_str();
        if !s.starts_with('-') {
            out.push(s);
            continue;
        }
        if s.contains('=') {
            continue;
        }
        if flags_with_val.contains(&s) {
            iter.next();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parse;

    fn classify_str(cmd: &str) -> Option<RuleHit> {
        let cfg = GuardConfig::default();
        let cmds = parse(cmd).commands;
        for c in &cmds {
            if let Some(hit) = classify(c, &cfg) {
                return Some(hit);
            }
        }
        None
    }

    fn destructive(cmd: &str) -> bool {
        classify_str(cmd).is_some()
    }
    fn safe(cmd: &str) -> bool {
        classify_str(cmd).is_none()
    }

    #[test]
    fn chmod_recursive_world_writable_blocks() {
        assert!(destructive("chmod -R 777 /"));
        assert!(destructive("chmod -R 777 mydir"));
        assert!(destructive("chmod -R a+rwx build"));
        assert!(destructive("sudo chmod -R 777 /etc"));
        let (id, _) = classify_str("chmod -R 777 /").unwrap();
        assert_eq!(id, RuleId::ChmodWorldWritable);
    }

    #[test]
    fn chmod_world_writable_on_root_blocks() {
        assert!(destructive("chmod 777 /"));
    }

    #[test]
    fn chmod_ordinary_is_safe() {
        assert!(safe("chmod +x script.sh"));
        assert!(safe("chmod 644 file.txt"));
        assert!(safe("chmod 755 bin/tool"));
        assert!(safe("chmod u+x run.sh"));
        // Non-recursive 777 on a single local file is sloppy but low-risk —
        // not flagged, to keep false positives down.
        assert!(safe("chmod 777 localfile"));
    }

    // Smoke tests across rule families. The full unit-test suite for
    // each rule lives in heuristic.rs (legacy) and rm.rs (legacy)
    // until those are deleted.

    #[test]
    fn rm_rf_etc() {
        let (id, _) = classify_str("rm -rf /etc").unwrap();
        assert_eq!(id, RuleId::RmRf);
    }

    #[test]
    fn rm_safe_in_cwd_after_cd() {
        // `cd /tmp && rm -rf ci-results` — relative operand resolved
        // against cwd, /tmp/ci-results is in safe roots.
        assert!(safe("cd /tmp && rm -rf ci-results"));
    }

    #[test]
    fn rm_in_subshell_with_cd() {
        assert!(safe("(cd /tmp && rm -rf x)"));
    }

    #[test]
    fn bash_c_safe_path() {
        assert!(safe("bash -c 'rm -rf /tmp/cache'"));
    }

    #[test]
    fn bash_c_destructive() {
        assert!(destructive("bash -c 'rm -rf /etc/nginx'"));
    }

    #[test]
    fn ssh_remote_rm_disables_safe_paths() {
        // /tmp on a remote host is NOT safe to wipe locally — we don't
        // know the remote's state. ssh-marked commands ignore the
        // local safe-paths allowlist.
        assert!(destructive("ssh prod 'rm -rf /tmp/foo'"));
    }

    #[test]
    fn heredoc_body_not_classified() {
        // `cat <<EOF\nrm -rf /\nEOF` — the body is data; only `cat`
        // is an executed command.
        assert!(safe("cat <<EOF\nrm -rf /\nEOF"));
    }

    #[test]
    fn quoted_string_in_git_commit_is_data() {
        // The argv of `git commit -m "fix rm -rf"` carries the message
        // as a single string token. No rm command appears.
        assert!(safe("git commit -m 'fix rm -rf detection'"));
    }

    #[test]
    fn echo_with_rm_in_message() {
        assert!(safe("echo \"rm -rf is dangerous\""));
    }

    #[test]
    fn relative_glob_with_extension() {
        assert!(safe("rm -rf *.log"));
    }

    #[test]
    fn pure_glob_rejected() {
        assert!(destructive("rm -rf *"));
    }

    #[test]
    fn helm_with_namespace_flag() {
        let (id, _) = classify_str("helm -n prod upgrade my-release charts/app").unwrap();
        assert_eq!(id, RuleId::HelmMutation);
    }

    #[test]
    fn kubectl_with_namespace_flag() {
        let (id, _) = classify_str("kubectl -n prod apply -f manifest.yaml").unwrap();
        assert_eq!(id, RuleId::KubectlMutation);
    }

    #[test]
    fn docker_push_with_host_flag() {
        let (id, _) = classify_str("docker -H tcp://prod:2376 push myreg.io/img:tag").unwrap();
        assert_eq!(id, RuleId::DockerPush);
    }

    #[test]
    fn graphql_mutation_via_curl() {
        let (id, _) = classify_str(
            "curl -X POST https://api.example.com/graphql -d '{\"query\":\"mutation { volumeDelete(id:1) }\"}'",
        )
        .unwrap();
        assert_eq!(id, RuleId::GraphqlMutation);
    }

    #[test]
    fn graphql_no_curl_no_fire() {
        assert!(safe("echo \"mutation { delete(id:1) }\" -d body"));
    }

    #[test]
    fn supabase_db_reset_granular() {
        let (id, _) = classify_str("supabase db reset --linked").unwrap();
        assert_eq!(id, RuleId::SupabaseDbMutation);
    }

    #[test]
    fn alembic_upgrade() {
        let (id, _) = classify_str("alembic upgrade head").unwrap();
        assert_eq!(id, RuleId::OrmMigration);
    }
}
