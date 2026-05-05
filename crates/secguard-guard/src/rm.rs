//! Token-level operand classifier for `rm` / `unlink` / `rmdir`.
//!
//! Replaces the old substring match in `heuristic.rs` that mis-classified
//! commands like `rm -rf $HOME/build-tools` as safe just because the literal
//! `build` appeared anywhere in the string. The classifier here:
//!
//! 1. Tokenises with `shell-words` (no shell expansion — variables stay
//!    literal: `$HOME` is treated as a textual marker, not a real path).
//! 2. Walks tokens to recognise the rm-family command, its flags, and its
//!    operands, including split short flags (`rm -r -f`) and long flags
//!    (`--recursive`, `--force`).
//! 3. Classifies each operand against a hardcoded catastrophic-path table
//!    (`/`, `$HOME/`, `~/`, `/etc/`, ...) and a safe-roots table built from
//!    the project config plus a small fixed allowlist (`/tmp/`, `/var/tmp/`,
//!    `/private/tmp/`).
//!
//! The full POSIX/bash AST + symlink + cwd-aware semantics live in proposal
//! 001 (`docs/proposals/001-ast-parser-and-wrapper-unwrap.md`); this module
//! is intentionally narrower.

use crate::config::GuardConfig;
use crate::rule_id::RuleId;

pub type RuleHit = (RuleId, String);

/// Outcome of the token-level rm classifier.
///
/// Three distinct states matter for downstream callers:
/// * `Destructive` — an rm-family command was located at a command position
///   AND its operands resolve to a catastrophic or non-safe target. Caller
///   should short-circuit and return this verdict.
/// * `Safe` — an rm-family command was located AND every operand is provably
///   safe under the configured patterns. Caller should NOT fall back to
///   wrapper-level substring matching: the precise classifier already had
///   the final word.
/// * `NotFound` — no rm-family command at a command position. The command
///   may still contain a wrapped rm (`bash -c 'rm ...'`, `sudo rm ...` after
///   `env FOO=1`, etc.); these cases are out of scope for this classifier
///   and will be resolved properly once the AST/wrapper-unwrap pass lands
///   (proposal 001). Until then, callers may apply a substring fallback.
#[derive(Debug)]
pub enum RmCheck {
    Destructive(RuleHit),
    Safe,
    NotFound,
}

/// Classify the rm-family commands in `cmd`. Walks every command segment
/// separated by `&&`, `||`, `;`, `|`, or bare `&` and returns:
/// * the first `Destructive` hit found (so multi-segment commands cannot
///   hide a destructive rm behind a safe one);
/// * `Safe` if at least one segment had an rm-family command and every such
///   segment cleared;
/// * `NotFound` if no segment had an rm-family command at command position.
pub fn check_rm(cmd: &str, config: &GuardConfig) -> RmCheck {
    // shell-words only splits on whitespace, so glued operators like
    // `node_modules;` and `node_modules&&` would be treated as a single
    // token. Pre-insert spaces around shell control operators outside
    // quoted regions before tokenising. Quoted operators (`"a;b"`) are
    // preserved.
    let normalised = pre_split_operators(cmd);
    let tokens = match shell_words::split(&normalised) {
        Ok(t) => t,
        Err(_) => return tokenise_fallback(cmd),
    };

    let mut found_any_rm = false;
    for segment in split_at_separators(&tokens) {
        if segment.is_empty() {
            continue;
        }
        match classify_segment(segment, config) {
            SegmentResult::Destructive(hit) => return RmCheck::Destructive(hit),
            SegmentResult::Safe => {
                found_any_rm = true;
            }
            SegmentResult::NotRm => {}
        }
    }

    if found_any_rm {
        RmCheck::Safe
    } else {
        RmCheck::NotFound
    }
}

enum SegmentResult {
    Destructive(RuleHit),
    Safe,
    NotRm,
}

/// Classify a single command segment. The first token (after leading
/// wrappers stripped at this level — none for now) must be the rm-family
/// command; later tokens are flags + operands.
fn classify_segment(segment: &[String], config: &GuardConfig) -> SegmentResult {
    let Some((idx, rm_name)) = first_rm_at_head(segment) else {
        return SegmentResult::NotRm;
    };
    let args = &segment[idx + 1..];
    let parsed = parse_rm_args(rm_name, args);

    // `--no-preserve-root` is a strong signal regardless of operand: nobody
    // sets it accidentally. Check first, before any safe early-return.
    if parsed.no_preserve_root {
        return SegmentResult::Destructive((
            RuleId::RmRf,
            format!(
                "{rm_name} --no-preserve-root (explicit override of root protection): {}",
                join_operands(&parsed.operands)
            ),
        ));
    }

    // Catastrophic operands are destructive even for non-recursive rm
    // (`rm /etc/passwd` is destructive; `rm /etc` is destructive).
    for op in &parsed.operands {
        if is_catastrophic_path(op) {
            return SegmentResult::Destructive((
                RuleId::RmRf,
                format!("{rm_name} of catastrophic path: {op}"),
            ));
        }
    }

    // For plain non-recursive `rm` against non-catastrophic operands we
    // defer — single-file deletions are ambiguous without cwd context.
    if rm_name == "rm" && !parsed.recursive {
        return SegmentResult::Safe;
    }

    let all_operands_safe = !parsed.operands.is_empty()
        && parsed
            .operands
            .iter()
            .all(|op| is_safe_operand(op, &config.safe_rm_patterns));
    if all_operands_safe {
        return SegmentResult::Safe;
    }

    let recursive = parsed.recursive;
    let rule = if recursive {
        RuleId::RmRf
    } else {
        RuleId::RmRecursive
    };
    let label = if recursive {
        "rm -rf".to_string()
    } else {
        rm_name.to_string()
    };
    let suffix = if recursive {
        "(recursive force delete)"
    } else if rm_name == "unlink" {
        "(targeted file deletion)"
    } else if rm_name == "rmdir" {
        "(directory deletion)"
    } else {
        "(deletion outside safe paths)"
    };
    SegmentResult::Destructive((
        rule,
        format!("{label} {suffix}: {}", join_operands(&parsed.operands)),
    ))
}

/// Insert spaces around shell control operators in `cmd` outside quoted
/// regions, so `shell-words::split` produces standalone separator tokens
/// even when the user did not put whitespace around them
/// (`rm foo;ls bar` → `rm foo ; ls bar`).
///
/// Tracks single/double quote state and backslash escapes. Operators
/// recognised: `;`, `|`, `||`, `&`, `&&`. Redirect operators (`>`, `<`,
/// `>>`, `<<`, `<<<`, `&>`) are NOT treated as command separators — they
/// parameterise the current command — but the leading `&` of `&>` is not
/// a real background marker, so that case must skip splitting. We handle
/// it by peeking for `&>` / `&<` and leaving them alone.
fn pre_split_operators(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len() + 16);
    let bytes = cmd.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if escape {
            out.push(c);
            escape = false;
            i += 1;
            continue;
        }
        match c {
            '\\' if !in_single => {
                out.push(c);
                escape = true;
                i += 1;
            }
            '\'' if !in_double => {
                out.push(c);
                in_single = !in_single;
                i += 1;
            }
            '"' if !in_single => {
                out.push(c);
                in_double = !in_double;
                i += 1;
            }
            ';' | '|' | '&' if !in_single && !in_double => {
                let next = bytes.get(i + 1).map(|&b| b as char);
                // `&>` or `&>>` — redirect, not background separator.
                if c == '&' && matches!(next, Some('>')) {
                    out.push(c);
                    i += 1;
                    continue;
                }
                out.push(' ');
                out.push(c);
                if let Some(n) = next {
                    if n == c {
                        // `&&`, `||`
                        out.push(n);
                        i += 1;
                    }
                }
                out.push(' ');
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Split a flat token list into command segments at shell separators.
/// Treats `&&`, `||`, `;`, `|`, bare `&` as boundaries between commands.
/// Subshell markers `(`, `)`, `{`, `}` also terminate a segment so trailing
/// commands inside them don't get folded in. Heredoc/redirect tokens stay
/// attached — they don't introduce a new command, they parameterise the
/// current one.
fn split_at_separators(tokens: &[String]) -> Vec<&[String]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, t) in tokens.iter().enumerate() {
        if matches!(
            t.as_str(),
            "&&" | "||" | ";" | "|" | "&" | "(" | ")" | "{" | "}"
        ) {
            if i > start {
                out.push(&tokens[start..i]);
            }
            start = i + 1;
        }
    }
    if start < tokens.len() {
        out.push(&tokens[start..]);
    }
    out
}

/// Inspect a segment and return Some((idx, rm_name)) iff the first non-
/// assignment token is an rm-family command. Skips leading shell-style
/// variable assignments like `FOO=bar rm ...` so they don't mask rm.
fn first_rm_at_head(segment: &[String]) -> Option<(usize, &'static str)> {
    let mut idx = 0;
    while idx < segment.len() {
        let t = &segment[idx];
        if is_var_assignment(t) {
            idx += 1;
            continue;
        }
        return match t.as_str() {
            "rm" => Some((idx, "rm")),
            "unlink" => Some((idx, "unlink")),
            "rmdir" => Some((idx, "rmdir")),
            _ => None,
        };
    }
    None
}

fn is_var_assignment(token: &str) -> bool {
    if let Some(eq) = token.find('=') {
        if eq == 0 {
            return false;
        }
        let lhs = &token[..eq];
        return lhs.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
            && lhs.chars().next().is_some_and(|c| !c.is_ascii_digit());
    }
    false
}

/// Best-effort path when `shell-words::split` rejects unbalanced quotes.
/// We still want to *ask* on a malformed string that mentions an rm-family
/// command — fail-open here would re-introduce the original FN.
fn tokenise_fallback(cmd: &str) -> RmCheck {
    let stripped = cmd.trim_start();
    let starts_rm = stripped.starts_with("rm ")
        || stripped.starts_with("rm\t")
        || stripped.starts_with("unlink ")
        || stripped.starts_with("rmdir ")
        || stripped.contains("&& rm ")
        || stripped.contains("|| rm ")
        || stripped.contains("; rm ")
        || stripped.contains("| rm ");
    if !starts_rm {
        return RmCheck::NotFound;
    }
    RmCheck::Destructive((
        RuleId::RmRf,
        "rm-family invocation in malformed quoting (cannot parse operands; ask)".into(),
    ))
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
    if rm_name == "rmdir" || rm_name == "unlink" {
        // unlink/rmdir don't have rf semantics; treat any operand as the
        // target. unlink targets a file, rmdir targets an empty dir, but
        // both still hit catastrophic paths if pointed there.
        out.recursive = false;
        for a in args {
            if a.starts_with('-') {
                continue;
            }
            out.operands.push(a.clone());
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
            // explicit opt-in to default; nothing to flip
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
        if a == "--dir" || a == "--interactive" || a == "--verbose" || a == "--one-file-system" {
            // recognised but irrelevant flags; do not consume operand position
            continue;
        }
        if let Some(short) = a.strip_prefix('-') {
            if short.is_empty() || short.starts_with('-') {
                // already handled long-form above; literal `-` is stdin
                out.operands.push(a.clone());
                continue;
            }
            // grouped short flags: -rf, -fr, -r, -f, -rfv, etc.
            let mut consumed = true;
            for c in short.chars() {
                match c {
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
            // Unknown flag — treat as operand to be safe. False positive is
            // better than letting an unknown flag mask a destructive target.
            out.operands.push(a.clone());
            continue;
        }
        out.operands.push(a.clone());
    }
    out
}

fn join_operands(operands: &[String]) -> String {
    if operands.is_empty() {
        "(no operand)".into()
    } else {
        operands.join(", ")
    }
}

/// Catastrophic = always destructive when used as the target of an rm-family
/// command, regardless of recursion. Covers exact roots, home variants, and
/// catastrophic prefixes. Path traversal (`..`) is also catastrophic because
/// the resolved target is unknown without doing real filesystem work.
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
            // Carve out per-user temp under /var: `/var/tmp/...` is handled
            // by the absolute safe-roots check below in is_safe_operand and
            // shouldn't be flagged here. Same logic applied to /var/log
            // would be wrong (we want to flag /var/log/) so this carve-out
            // only fires for /var/tmp/ and /private/tmp/ via the safe-roots
            // check downstream, NOT here.
            if *p == "/var/" && operand.starts_with("/var/tmp/") {
                return false;
            }
            return true;
        }
    }

    false
}

/// `operand` is provably safe iff it is rooted in one of the safe paths
/// from `safe_patterns` (relative names like `build`, `node_modules`) or
/// inside one of the hardcoded ABSOLUTE_SAFE_ROOTS — and contains no `..`.
fn is_safe_operand(operand: &str, safe_patterns: &[String]) -> bool {
    if operand.contains("..") {
        return false;
    }

    const ABSOLUTE_SAFE_ROOTS: &[&str] = &["/tmp/", "/var/tmp/", "/private/tmp/"];

    for root in ABSOLUTE_SAFE_ROOTS {
        if operand == &root[..root.len() - 1] {
            // `/tmp` or `/var/tmp` — deleting the root itself is NOT safe.
            return false;
        }
        if operand == *root {
            // Trailing-slash variant — same; deleting the whole tmp root.
            return false;
        }
        if let Some(rest) = operand.strip_prefix(root) {
            if rest.is_empty() {
                return false;
            }
            // Reject root-wide globs like `/tmp/*`, `/tmp/?`, `/tmp/[a-z]`,
            // `/tmp/{a,b}` — these wipe whatever any other process has
            // dropped in the shared root, not just the user's own files.
            // Concrete subdirs (`/tmp/build`, `/tmp/build/sub`) are still
            // allowed; a glob is only the FIRST path component.
            let first_component = rest.split('/').next().unwrap_or("");
            if first_component.contains(['*', '?', '[', '{']) {
                return false;
            }
            return true;
        }
    }

    // Reject absolute paths that are not in the safe-roots list above.
    if operand.starts_with('/') {
        return false;
    }

    // Reject home-anchored paths.
    if operand.starts_with('~') || operand.starts_with('$') {
        return false;
    }

    // Relative path: strip a leading `./` for matching.
    let normalized = operand.strip_prefix("./").unwrap_or(operand);

    // safe_patterns entries are either absolute (e.g. "/tmp/") or relative
    // (e.g. "build"). Absolute entries are handled by ABSOLUTE_SAFE_ROOTS;
    // here we only consider relative patterns.
    for sp in safe_patterns {
        if sp.starts_with('/') {
            continue;
        }
        let pattern = sp.trim_end_matches('/');
        if normalized == pattern {
            return true;
        }
        // Strict subdirectory match: `target/debug` allows `target/debug/foo`.
        let prefix = format!("{pattern}/");
        if normalized.starts_with(&prefix) {
            return true;
        }
    }

    false
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

    #[test]
    fn home_subpath_is_destructive() {
        assert!(destructive("rm -rf $HOME/build-tools"));
        assert!(destructive("rm -rf ${HOME}/foo"));
        assert!(destructive("rm -rf ~/dist-old"));
        assert!(destructive("rm -rf $HOME/node_modules"));
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
        assert!(destructive("unlink ~/.ssh/authorized_keys"));
    }

    #[test]
    fn safe_relative_targets() {
        assert!(!destructive("rm -rf build"));
        assert!(!destructive("rm -rf ./build"));
        assert!(!destructive("rm -rf node_modules"));
        assert!(!destructive("rm -rf dist"));
        assert!(!destructive("rm -rf target/debug"));
        assert!(!destructive("rm -rf target/debug/incremental"));
        assert!(!destructive("rm -rf __pycache__"));
    }

    #[test]
    fn safe_tmp_subdirs() {
        assert!(!destructive("rm -rf /tmp/foo"));
        assert!(!destructive("rm --recursive --force /tmp/foo"));
        assert!(!destructive("rm -rf /var/tmp/build"));
        assert!(!destructive("rm -rf /private/tmp/x"));
    }

    #[test]
    fn unsafe_tmp_root_itself() {
        assert!(destructive("rm -rf /tmp"));
        assert!(destructive("rm -rf /var/tmp"));
    }

    #[test]
    fn rm_without_recursion_clears_for_non_catastrophic() {
        // Plain non-recursive rm against a non-catastrophic operand is
        // ambiguous without cwd context — we defer (Safe). Catastrophic
        // operands are flagged earlier; see
        // `plain_rm_against_catastrophic_path_is_destructive`.
        assert!(cleared("rm somefile.txt"));
        assert!(cleared("rm ./build/output.o"));
    }

    #[test]
    fn double_dash_separates_flags_and_operands() {
        assert!(destructive("rm -rf -- /etc"));
        assert!(!destructive("rm -rf -- build"));
    }

    #[test]
    fn unknown_flag_treated_as_operand() {
        // Better to ask than to silently treat `--bogus` as a flag.
        assert!(destructive("rm -rf --bogus /etc"));
    }

    #[test]
    fn malformed_quoting_with_rm_asks() {
        // shell-words rejects unbalanced quotes — still flag rm-family.
        assert!(destructive("rm -rf 'unterminated"));
    }

    #[test]
    fn malformed_quoting_without_rm_is_not_found() {
        assert!(not_found("echo 'unterminated"));
    }

    #[test]
    fn catastrophic_prefix_requires_path_separator() {
        // Without the trailing slash the catastrophic-prefix table would
        // match `/etcetera` as if it were `/etc`. The slash terminator in
        // our prefix list (`/etc/`) is what enforces the path-component
        // boundary.
        assert!(!is_catastrophic_path("/etcetera"));
        assert!(is_catastrophic_path("/etc"));
        assert!(is_catastrophic_path("/etc/passwd"));
    }

    #[test]
    fn arbitrary_absolute_path_is_not_safe_but_not_catastrophic() {
        // /srv and /data aren't in our catastrophic table, so a random
        // path under them isn't tagged as a catastrophic OS path. They're
        // also not in the safe-roots allowlist, so the verdict is still
        // destructive — we ask the user.
        assert!(!is_catastrophic_path("/srv/myapp"));
        assert!(!is_safe_operand("/srv/myapp", &cfg().safe_rm_patterns));
        assert!(destructive("rm -rf /srv/myapp"));
    }

    #[test]
    fn plain_rm_against_catastrophic_path_is_destructive() {
        // tribunal RAN-354 finding #1 — non-recursive rm of a system file
        // must still be flagged. Was previously cleared by an early Safe
        // return that ran before the catastrophic-operand check.
        assert!(destructive("rm /etc/passwd"));
        assert!(destructive("rm /etc/shadow"));
        assert!(destructive("unlink /etc/hosts"));
    }

    #[test]
    fn shared_root_glob_is_not_safe() {
        // tribunal RAN-354 finding #2 — `/tmp/*` looked safe under the
        // earlier prefix-based safe-roots check because the rest after
        // `/tmp/` was non-empty. A glob as the first component wipes
        // every other process's tmp data, so reject.
        assert!(!is_safe_operand("/tmp/*", &cfg().safe_rm_patterns));
        assert!(!is_safe_operand("/tmp/?", &cfg().safe_rm_patterns));
        assert!(!is_safe_operand("/tmp/[a-z]", &cfg().safe_rm_patterns));
        assert!(!is_safe_operand("/var/tmp/*", &cfg().safe_rm_patterns));
        assert!(!is_safe_operand("/private/tmp/*", &cfg().safe_rm_patterns));
        assert!(destructive("rm -rf /tmp/*"));
        assert!(destructive("rm -rf /var/tmp/*"));
        // Concrete subdir + trailing glob is still safe; the user owns it.
        assert!(is_safe_operand("/tmp/build/*", &cfg().safe_rm_patterns));
    }

    #[test]
    fn compound_command_does_not_fold_trailing_tokens_into_rm() {
        // tribunal RAN-354 finding #3 — old parser swallowed `; ls /etc`
        // as operands of the first rm, fabricating a destructive verdict
        // on a benign compound. With segment-aware parsing, only operands
        // belonging to the rm command are inspected.
        assert!(cleared("rm -rf node_modules ; ls /etc"));
        assert!(cleared("rm -rf build && echo ok"));
        assert!(cleared("rm -rf dist || echo failed"));
        assert!(cleared("rm -rf node_modules | tee log.txt"));
    }

    #[test]
    fn compound_command_catches_destructive_in_later_segment() {
        // Gemini RAN-354 finding #2 — first-match-wins on a single rm
        // segment must NOT mask a destructive rm in a later segment.
        // Each segment is classified independently.
        assert!(destructive("rm -rf node_modules ; rm -rf /etc"));
        assert!(destructive("rm -rf build && rm -rf /etc"));
        assert!(destructive("echo ok ; rm -rf /etc"));
    }

    #[test]
    fn leading_var_assignments_are_skipped() {
        // A shell-style env-prefix (`FOO=1 rm ...`) is not a wrapper
        // — it's just the same rm with extra environment. We must still
        // see the rm and classify operands correctly.
        assert!(destructive("FOO=1 rm -rf /etc"));
        assert!(destructive("FOO=1 BAR=2 rm -rf /etc"));
        assert!(cleared("FOO=1 rm -rf build"));
    }

    #[test]
    fn glued_operators_split_correctly() {
        // tribunal RAN-354 second-pass — operators without surrounding
        // whitespace must still terminate the rm operand list.
        assert!(cleared("rm -rf node_modules; ls /etc"));
        assert!(cleared("rm -rf node_modules ;ls /etc"));
        assert!(cleared("rm -rf node_modules;ls /etc"));
        assert!(cleared("rm -rf node_modules&& echo ok"));
        assert!(cleared("rm -rf node_modules&&echo ok"));
        assert!(cleared("rm -rf dist|| echo failed"));
        assert!(cleared("rm -rf node_modules|tee log.txt"));
    }

    #[test]
    fn glued_operators_still_catch_destructive_followups() {
        // Even with glued separators, a destructive rm in a later
        // segment must be flagged.
        assert!(destructive("rm -rf node_modules;rm -rf /etc"));
        assert!(destructive("rm -rf build&&rm -rf /etc"));
        assert!(destructive("echo ok;rm -rf /etc"));
    }

    #[test]
    fn background_separator_terminates_rm() {
        // Bare `&` puts the rm in the background and starts a new
        // command — operands of the new command must not fold into rm.
        assert!(cleared("rm -rf node_modules & ls /etc"));
        assert!(cleared("rm -rf node_modules& ls /etc"));
        assert!(destructive("rm -rf node_modules & rm -rf /etc"));
    }

    #[test]
    fn separator_inside_quoted_string_is_not_a_split_point() {
        // A quoted `;` or `&&` is content, not a separator. The pre-
        // splitter must respect single + double quoting. These commands
        // do NOT contain rm-family at command position, so check_rm
        // returns NotFound — exactly what we want (no spurious split
        // produced an artificial rm segment).
        assert!(not_found("git commit -m \"fix; cleanup\""));
        assert!(not_found("git commit -m 'rm -rf; safety'"));
        // Once the user invokes rm directly, we still classify it
        // — quoting around the operand is stripped by shell-words.
        assert!(destructive("rm -rf '/etc'"));
    }

    #[test]
    fn redirect_ampersand_greater_is_not_split_as_background() {
        // `&>` is a bash redirect, not a background separator. The
        // pre-splitter intentionally skips it (no segment break here).
        // Full redirect-aware handling — recognising `&>` and its target
        // as redirect-not-operand — is proposal-001 territory; for now
        // we conservatively classify the whole call as destructive
        // because `/dev/null` ends up parsed as an rm operand. Test
        // fixes the BEHAVIOUR explicitly so a future improvement is
        // visible as a baseline shift, not a silent bug.
        assert!(destructive("rm -rf build &> /dev/null"));
    }
}
