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

    #[test]
    fn psql_is_not_policy_safe() {
        assert!(!is_safe_by_policy("psql -c 'select 1'", &cfg()));
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
