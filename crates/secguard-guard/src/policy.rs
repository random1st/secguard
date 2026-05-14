//! Policy allowlist: operations that are always safe.

use crate::config::GuardConfig;

pub fn is_safe_by_policy(cmd: &str, config: &GuardConfig) -> bool {
    let parts = split_command_parts(cmd);

    if parts.is_empty() {
        return false;
    }

    parts
        .iter()
        .all(|part| is_single_command_safe(part, config))
}

pub(crate) fn split_command_parts(cmd: &str) -> Vec<&str> {
    cmd.split("&&")
        .flat_map(|s| s.split("||"))
        .flat_map(|s| s.split(';'))
        .flat_map(|s| s.split('|'))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_single_command_safe(cmd: &str, config: &GuardConfig) -> bool {
    if is_safe_kill_command(cmd, config) {
        return true;
    }
    if cmd.starts_with("git push") && is_safe_git_push(cmd) {
        return true;
    }
    if cmd.starts_with("kubectl ") {
        let safe_ops = [
            "get ",
            "describe ",
            "logs ",
            "port-forward ",
            "top ",
            "config ",
            "version",
            "api-resources",
            "explain ",
        ];
        return safe_ops.iter().any(|s| cmd.contains(s));
    }
    // gws (Google Workspace CLI) — always safe
    if cmd.starts_with("gws ") {
        return true;
    }
    // diana CLI — safe unless the rest contains " rm " or "delete"
    if cmd.starts_with("diana ") {
        let rest = &cmd["diana ".len()..];
        return !rest.contains(" rm ") && !rest.contains("delete");
    }
    // psql DB client — safe for read/query use; reject if command contains
    // destructive SQL keywords (drop, delete, truncate, alter).
    if cmd.starts_with("psql ") || cmd.starts_with("psql -") || cmd == "psql" {
        let lower = cmd.to_ascii_lowercase();
        let has_destructive_sql = [
            "drop ",
            "drop;",
            "delete ",
            "delete;",
            "truncate ",
            "truncate;",
            "alter ",
            "alter;",
        ]
        .iter()
        .any(|kw| lower.contains(kw));
        return !has_destructive_sql;
    }
    // terraform — only read/inspect subcommands are safe
    if cmd.starts_with("terraform ") {
        let safe_subs = [
            "plan",
            "show",
            "output",
            "validate",
            "state list",
            "state show",
            "fmt",
            "version",
        ];
        let rest = cmd["terraform ".len()..].trim_start();
        return safe_subs
            .iter()
            .any(|s| rest == *s || rest.starts_with(&format!("{s} ")));
    }
    // brew — only read/install subcommands are safe; uninstall/cleanup are destructive
    if cmd.starts_with("brew ") {
        let safe_subs = [
            "install", "upgrade", "list", "info", "search", "update", "outdated", "tap", "leaves",
        ];
        let rest = cmd["brew ".len()..].trim_start();
        return safe_subs
            .iter()
            .any(|s| rest == *s || rest.starts_with(&format!("{s} ")));
    }
    // Package managers — safe subcommands only
    if is_safe_package_manager_command(cmd) {
        return true;
    }
    // User-defined safe prefixes from config
    for prefix in &config.safe_command_prefixes {
        let prefix = prefix.trim();
        if !prefix.is_empty() && cmd.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Returns true when the command is a safe subcommand of a package manager
/// (cargo, npm, bun, yarn, pnpm, pip, uv).
///
/// Conservative: only read/build/install subcommands are allowed.
/// Destructive ones (cargo clean, npm uninstall, pip uninstall, etc.) are NOT included.
fn is_safe_package_manager_command(cmd: &str) -> bool {
    const SAFE_SUBCOMMANDS: &[&str] = &[
        "build", "check", "test", "install", "ci", "add", "sync", "run", "list", "show", "info",
        "search", "version", "--help",
    ];
    const MANAGERS: &[&str] = &["cargo", "npm", "bun", "yarn", "pnpm", "pip", "uv"];

    for mgr in MANAGERS {
        let prefix = format!("{mgr} ");
        if let Some(rest) = cmd.strip_prefix(prefix.as_str()) {
            let rest = rest.trim_start();
            return SAFE_SUBCOMMANDS
                .iter()
                .any(|sub| rest == *sub || rest.starts_with(&format!("{sub} ")));
        }
    }
    false
}

/// `git push` is safe-by-policy only when it has none of the destructive
/// shapes the heuristic phase will later flag. The earlier version only
/// rejected `--force`/`-f`, which let `git push -d`, `git push --delete`,
/// `git push origin :branch`, and `git push origin +ref` through. The
/// previous tokenisation used `split_whitespace` and missed quoted
/// refspecs (`"+main"`, `":branch"`) — the shell strips the quotes
/// before git ever sees them, so policy must do the same.
fn is_safe_git_push(cmd: &str) -> bool {
    let Ok(tokens) = shell_words::split(cmd) else {
        return false;
    };
    if tokens.len() < 2 || tokens[0] != "git" || tokens[1] != "push" {
        return false;
    }
    for t in tokens.iter().skip(2) {
        let s = t.as_str();
        if s == "--force"
            || s == "--force-with-lease"
            || s == "-f"
            || s == "-d"
            || s == "--delete"
            || s == "--mirror"
            || s == "--prune"
        {
            return false;
        }
        // Combined short flags like `-uf`, `-fu`, `-fdn`.
        if let Some(short) = s.strip_prefix('-') {
            if !short.starts_with('-') && short.contains('f') {
                return false;
            }
            if !short.starts_with('-') && short.contains('d') && !short.contains('n') {
                // `-d` alone in a group means delete; `-dn` would be a
                // dry-run combination that doesn't apply to push (push
                // has no -n), but we keep the safe carve-out narrow.
                return false;
            }
        }
        // Refspec forms: leading `+` forces per-ref, leading `:` deletes
        // a remote ref. Allow numeric tags (`+1.2.3`) by accepting any
        // alphanumeric or path-separator first char after the marker.
        if let Some(rest) = s.strip_prefix('+') {
            let first = rest.chars().next().unwrap_or(' ');
            if first.is_ascii_alphanumeric() || first == '/' {
                return false;
            }
        }
        if s.starts_with(':') && s.len() > 1 {
            return false;
        }
    }
    true
}

#[allow(dead_code)]
pub(crate) fn is_kill_command(cmd: &str) -> bool {
    cmd.split_whitespace()
        .next()
        .is_some_and(|program| matches!(program, "pkill" | "killall" | "kill"))
}

pub(crate) fn is_safe_kill_command(cmd: &str, config: &GuardConfig) -> bool {
    let mut tokens = cmd.split_whitespace();
    let Some(program) = tokens.next() else {
        return false;
    };

    if !matches!(program, "pkill" | "killall") {
        return false;
    }

    tokens
        .filter(|token| !token.starts_with('-'))
        .any(|target| config.safe_kill_targets.iter().any(|safe| target == safe))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GuardConfig {
        GuardConfig::default()
    }

    #[test]
    fn safe_git_push() {
        assert!(is_safe_by_policy("git push origin main", &cfg()));
    }

    #[test]
    fn unsafe_force_push() {
        assert!(!is_safe_by_policy("git push --force origin main", &cfg()));
    }

    #[test]
    fn safe_kubectl_get() {
        assert!(is_safe_by_policy("kubectl get pods", &cfg()));
    }

    #[test]
    fn safe_compound() {
        assert!(is_safe_by_policy(
            "git push origin main && kubectl get pods",
            &cfg()
        ));
    }

    #[test]
    fn safe_kill() {
        assert!(is_safe_by_policy("pkill node", &cfg()));
        assert!(is_safe_by_policy("killall python", &cfg()));
        assert!(!is_safe_by_policy("pkill postgres", &cfg()));
        assert!(!is_safe_by_policy("kill 12345", &cfg()));
    }

    // ── New policy rules ──────────────────────────────────────────────────

    // gws
    #[test]
    fn gws_is_policy_safe() {
        assert!(is_safe_by_policy("gws send-mail foo", &cfg()));
        assert!(is_safe_by_policy("gws list-calendars", &cfg()));
    }

    // diana
    #[test]
    fn diana_is_policy_safe() {
        assert!(is_safe_by_policy("diana search RAN-296", &cfg()));
        assert!(is_safe_by_policy("diana router", &cfg()));
    }

    #[test]
    fn diana_with_rm_is_not_policy_safe() {
        assert!(!is_safe_by_policy("diana store rm foo", &cfg()));
    }

    #[test]
    fn diana_with_delete_is_not_policy_safe() {
        assert!(!is_safe_by_policy("diana store delete foo", &cfg()));
    }

    // psql
    #[test]
    fn psql_is_policy_safe() {
        assert!(is_safe_by_policy("psql -c 'select 1'", &cfg()));
        assert!(is_safe_by_policy("psql -U postgres mydb", &cfg()));
    }

    #[test]
    fn psql_with_drop_table_is_not_policy_safe() {
        assert!(!is_safe_by_policy("psql -c 'DROP TABLE users'", &cfg()));
        assert!(!is_safe_by_policy("psql -c 'delete from foo'", &cfg()));
        assert!(!is_safe_by_policy("psql -c 'truncate logs'", &cfg()));
    }

    // terraform
    #[test]
    fn terraform_plan_is_policy_safe() {
        assert!(is_safe_by_policy("terraform plan", &cfg()));
        assert!(is_safe_by_policy(
            "terraform plan -var-file=foo.tfvars",
            &cfg()
        ));
        assert!(is_safe_by_policy("terraform show", &cfg()));
        assert!(is_safe_by_policy("terraform validate", &cfg()));
        assert!(is_safe_by_policy("terraform fmt", &cfg()));
        assert!(is_safe_by_policy("terraform version", &cfg()));
        assert!(is_safe_by_policy("terraform output -json", &cfg()));
        assert!(is_safe_by_policy("terraform state list", &cfg()));
        assert!(is_safe_by_policy(
            "terraform state show aws_s3_bucket.b",
            &cfg()
        ));
    }

    #[test]
    fn terraform_apply_is_not_policy_safe() {
        assert!(!is_safe_by_policy("terraform apply", &cfg()));
        assert!(!is_safe_by_policy("terraform destroy", &cfg()));
        assert!(!is_safe_by_policy("terraform taint foo", &cfg()));
        assert!(!is_safe_by_policy("terraform import foo bar", &cfg()));
    }

    // brew
    #[test]
    fn brew_install_is_policy_safe() {
        assert!(is_safe_by_policy("brew install ripgrep", &cfg()));
        assert!(is_safe_by_policy("brew upgrade", &cfg()));
        assert!(is_safe_by_policy("brew list", &cfg()));
        assert!(is_safe_by_policy("brew info git", &cfg()));
        assert!(is_safe_by_policy("brew search fd", &cfg()));
        assert!(is_safe_by_policy("brew update", &cfg()));
        assert!(is_safe_by_policy("brew outdated", &cfg()));
        assert!(is_safe_by_policy("brew tap homebrew/cask", &cfg()));
        assert!(is_safe_by_policy("brew leaves", &cfg()));
    }

    #[test]
    fn brew_uninstall_is_not_policy_safe() {
        assert!(!is_safe_by_policy("brew uninstall ripgrep", &cfg()));
        assert!(!is_safe_by_policy("brew cleanup", &cfg()));
    }

    // package managers
    #[test]
    fn cargo_safe_subcommands() {
        assert!(is_safe_by_policy("cargo build", &cfg()));
        assert!(is_safe_by_policy("cargo check", &cfg()));
        assert!(is_safe_by_policy("cargo test", &cfg()));
        assert!(is_safe_by_policy("cargo run --release", &cfg()));
        assert!(is_safe_by_policy("cargo list", &cfg()));
        assert!(is_safe_by_policy("cargo --help", &cfg()));
    }

    #[test]
    fn cargo_clean_is_not_policy_safe() {
        assert!(!is_safe_by_policy("cargo clean", &cfg()));
    }

    #[test]
    fn npm_safe_subcommands() {
        assert!(is_safe_by_policy("npm install", &cfg()));
        assert!(is_safe_by_policy("npm ci", &cfg()));
        assert!(is_safe_by_policy("npm run build", &cfg()));
        assert!(is_safe_by_policy("npm test", &cfg()));
        assert!(is_safe_by_policy("npm list", &cfg()));
    }

    #[test]
    fn npm_uninstall_is_not_policy_safe() {
        assert!(!is_safe_by_policy("npm uninstall lodash", &cfg()));
    }

    #[test]
    fn bun_safe_subcommands() {
        assert!(is_safe_by_policy("bun install", &cfg()));
        assert!(is_safe_by_policy("bun run dev", &cfg()));
        assert!(is_safe_by_policy("bun test", &cfg()));
        assert!(is_safe_by_policy("bun add react", &cfg()));
    }

    #[test]
    fn pip_safe_subcommands() {
        assert!(is_safe_by_policy("pip install requests", &cfg()));
        assert!(is_safe_by_policy("pip list", &cfg()));
        assert!(is_safe_by_policy("pip show requests", &cfg()));
        assert!(is_safe_by_policy("pip search requests", &cfg()));
    }

    #[test]
    fn pip_uninstall_is_not_policy_safe() {
        assert!(!is_safe_by_policy("pip uninstall requests", &cfg()));
    }

    #[test]
    fn uv_safe_subcommands() {
        assert!(is_safe_by_policy("uv sync", &cfg()));
        assert!(is_safe_by_policy("uv add ruff", &cfg()));
        assert!(is_safe_by_policy("uv run ruff check", &cfg()));
    }

    // user config prefixes
    #[test]
    fn user_config_prefix_allows_matching_command() {
        let mut cfg = cfg();
        cfg.safe_command_prefixes = vec!["rclone copy".into(), "tailscale status".into()];
        assert!(is_safe_by_policy("rclone copy src dst", &cfg));
        assert!(is_safe_by_policy("tailscale status", &cfg));
    }

    #[test]
    fn user_config_prefix_does_not_allow_rm() {
        let mut cfg = cfg();
        cfg.safe_command_prefixes = vec!["rclone copy".into()];
        assert!(!is_safe_by_policy("rm -rf /", &cfg));
    }

    // ── Tribunal-2: quoted refspec bypass ───────────────────────────────

    #[test]
    fn quoted_plus_refspec_is_not_policy_safe() {
        // The shell strips quotes before git sees the refspec, so policy
        // must shell-tokenise to match. Naive split_whitespace would keep
        // the literal `"` and start_with('+') would fail.
        assert!(!is_safe_by_policy("git push origin \"+main\"", &cfg()));
        assert!(!is_safe_by_policy("git push origin '+main'", &cfg()));
    }

    #[test]
    fn quoted_colon_refspec_is_not_policy_safe() {
        assert!(!is_safe_by_policy("git push origin \":branch\"", &cfg()));
        assert!(!is_safe_by_policy("git push origin ':branch'", &cfg()));
    }

    #[test]
    fn combined_short_force_is_not_policy_safe() {
        // `-uf` and `-fu` group the force flag with --set-upstream.
        assert!(!is_safe_by_policy("git push -uf origin main", &cfg()));
        assert!(!is_safe_by_policy("git push -fu origin main", &cfg()));
    }

    #[test]
    fn trailing_dash_f_is_not_policy_safe() {
        // `git push origin main -f` — trailing -f, no following token.
        assert!(!is_safe_by_policy("git push origin main -f", &cfg()));
    }

    #[test]
    fn delete_long_form_is_not_policy_safe() {
        assert!(!is_safe_by_policy(
            "git push origin --delete feature",
            &cfg()
        ));
    }

    #[test]
    fn delete_short_form_is_not_policy_safe() {
        assert!(!is_safe_by_policy("git push origin -d feature", &cfg()));
    }

    #[test]
    fn mirror_is_not_policy_safe() {
        assert!(!is_safe_by_policy("git push --mirror origin", &cfg()));
    }

    #[test]
    fn numeric_plus_refspec_is_not_policy_safe() {
        // `+1.2.3` is a tag-style ref, force-push form. Earlier policy
        // required first char to be alphabetic and let it slip.
        assert!(!is_safe_by_policy("git push origin +1.2.3", &cfg()));
    }
}
