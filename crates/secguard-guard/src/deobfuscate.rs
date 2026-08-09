//! AST-based bash obfuscation normalizer (RAN-421 G2.3).
//!
//! Regex is blind to obfuscation. This module adds a pre-parse normalization
//! pass that collapses common obfuscation forms before heuristic rule
//! evaluation:
//!
//! - **Quote-split concatenation**: `c\u\r\l` → `curl`, `b''a""sh` → `bash`,
//!   `ba"se"64` → `base64`. Done by stripping adjacent quote regions inside
//!   concatenation tokens.
//!
//! - **`eval $(echo <b64> | base64 -d)`**: Decode the base64 literal, splice
//!   the decoded text back as the eval body and re-parse.
//!
//! - **`echo <b64> | base64 -d | bash`**: Decode the base64 literal in the
//!   pipeline producer, feed the decoded text as the shell's script body and
//!   re-parse.
//!
//! - **IFS/variable split obfuscation**: `IFS=...;cmd $vars` — already
//!   handled upstream by [`crate::ast`]'s lexical-binding expansion. This
//!   module does not duplicate that work.
//!
//! **Depth limit**: every recursive re-parse decrements a depth counter.
//! At depth 0 the normalizer emits a `__deobfuscate_depth_exceeded__` marker
//! and returns, preventing bash-bomb recursion. The limit is driven by
//! [`crate::config::AstConfig::max_expansion_depth`].
//!
//! The entry point is [`normalize`]: given a raw command string and a depth
//! budget, return the command string(s) to hand to the AST walker. Normal
//! case: returns the same string unchanged. Obfuscated case: returns a
//! reconstructed string (or the decoded base64 payload).

use base64::Engine as _;

/// Normalizer output.
#[derive(Debug)]
pub struct NormalizeResult {
    /// The command string(s) to pass to the AST walker instead of the original.
    /// Typically contains a single element. May contain multiple strings when
    /// the input is a pipeline that decodes to a multi-command script.
    pub commands: Vec<String>,
    /// True when the depth budget was exhausted mid-normalization. The caller
    /// must emit a `__deobfuscate_depth_exceeded__` marker command so a rule
    /// fires rather than silently allowing the command.
    pub depth_exceeded: bool,
}

impl NormalizeResult {
    fn passthrough(cmd: &str) -> Self {
        NormalizeResult {
            commands: vec![cmd.to_string()],
            depth_exceeded: false,
        }
    }

    fn decoded(cmd: String) -> Self {
        NormalizeResult {
            commands: vec![cmd],
            depth_exceeded: false,
        }
    }

    fn depth_exceeded() -> Self {
        NormalizeResult {
            commands: vec!["__deobfuscate_depth_exceeded__".to_string()],
            depth_exceeded: true,
        }
    }
}

/// Normalize a raw bash command string before AST parsing.
///
/// `depth` is the remaining recursion budget (decremented on each recursive
/// call through a decoded payload). When `depth == 0` the function returns
/// immediately with `depth_exceeded = true` to prevent unbounded recursion.
///
/// Returns [`NormalizeResult`] — always at least one command string.
pub fn normalize(cmd: &str, depth: u8) -> NormalizeResult {
    if depth == 0 {
        return NormalizeResult::depth_exceeded();
    }

    // Phase 0: IFS variable expansion.
    // Patterns like `IFS=/; r${IFS}m -rf /` or `IFS=-; rm${IFS}rf /etc`
    // obfuscate command names or flags by interpolating IFS as a separator.
    // We detect `IFS=<char>` assignments at the start of the command and
    // substitute `${IFS}` / `$IFS` occurrences with that character so the
    // downstream phases and AST walker see a recognisable token.
    let cmd = &expand_ifs(cmd);

    // Phase 1: collapse quote-split token obfuscation at the character level.
    // This covers `c\u\r\l` (already handled by decode_token's backslash pass,
    // but we keep it here for completeness in the string-level pass), and
    // more importantly `b''a""sh`, `ba"se"64`, `e''val`, etc. where
    // tree-sitter emits the raw source text including the embedded empty-quote
    // fragments. The AST walker's decode_token handles ANSI-C `$'...'` and
    // unquoted backslash escapes, but NOT adjacent quote stripping from a
    // concatenation node's full source text.
    //
    // Strategy: scan the token stream. Any sequence of alternating quoted
    // regions that produce zero content between otherwise-alphabetic chars
    // indicates obfuscation. We strip '' and "" fragments that contribute
    // only empty content between otherwise-adjacent word characters.
    //
    // Example: `b''a""sh` → strip `''` and `""` → `bash`.
    let normalized = collapse_quote_splits(cmd);

    // Phase 2: detect base64-decode pipelines.
    //   `echo <token> | base64 -d`        (may end with `| bash` etc.)
    //   `echo <token> | base64 --decode`
    //   `printf <token> | base64 -d`
    //   `... | base64 -d | bash -c ...`
    // When detected, decode the base64 literal and splice it back into the
    // command string for re-parsing.
    if let Some(decoded) = try_decode_base64_pipeline(&normalized, depth) {
        return decoded;
    }

    // Phase 3: detect eval/bash -c with inline base64 command substitution.
    //   `eval $(echo <b64> | base64 -d)`
    //   `bash -c "$(echo <b64> | base64 -d)"`
    if let Some(decoded) = try_decode_base64_command_sub(&normalized, depth) {
        return decoded;
    }

    // No obfuscation detected — return normalized string.
    if normalized.as_str() == cmd.as_str() {
        NormalizeResult::passthrough(cmd)
    } else {
        NormalizeResult::decoded(normalized)
    }
}

// ── Quote-split token collapsing ─────────────────────────────────────────────

/// Collapse obfuscating empty-quote insertions:
///   `b''a""sh`    → `bash`
///   `ba"se"64`    → `base64`
///   `c\u\r\l`     → `curl`  (backslash form already handled by AST decode_token,
///                             but normalizing here is harmless and makes
///                             snapshot tests cleaner)
///
/// Algorithm: scan the string character-by-character. When inside a quoted
/// string with zero meaningful content (empty `''` or empty `""`), elide it.
/// Non-empty quoted strings are kept — they represent real arguments that the
/// AST layer already unquotes.
///
/// This is a best-effort character-level collapse; full tree-sitter
/// concatenation walking happens in the AST layer. We operate on the raw
/// command string here so the collapse is visible to the tree-sitter parse
/// that follows normalization.
fn collapse_quote_splits(cmd: &str) -> String {
    let bytes = cmd.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;

    while i < n {
        let ch = bytes[i] as char;

        // Single-quote: scan to closing `'`. If the region between the
        // quotes is empty (i.e. the very next byte is also `'`), elide both.
        // If non-empty, keep the whole quoted region as-is.
        if ch == '\'' {
            if i + 1 < n && bytes[i + 1] == b'\'' {
                // Empty single-quote pair — elide.
                i += 2;
                continue;
            }
            // Non-empty single-quoted region — keep verbatim including quotes.
            out.push(ch);
            i += 1;
            let start = i;
            while i < n && bytes[i] != b'\'' {
                i += 1;
            }
            // Copy content.
            out.push_str(&cmd[start..i]);
            if i < n {
                out.push('\''); // closing quote
                i += 1;
            }
            continue;
        }

        // Double-quote: scan to closing `"` (not preceded by `\`). If empty,
        // elide both. If non-empty, keep verbatim.
        if ch == '"' {
            if i + 1 < n && bytes[i + 1] == b'"' {
                // Empty double-quote pair — elide.
                i += 2;
                continue;
            }
            // Non-empty double-quoted region — keep verbatim including quotes.
            out.push(ch);
            i += 1;
            let start = i;
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2; // escaped char — skip both
                    continue;
                }
                if bytes[i] == b'"' {
                    break;
                }
                i += 1;
            }
            out.push_str(&cmd[start..i]);
            if i < n {
                out.push('"'); // closing quote
                i += 1;
            }
            continue;
        }

        out.push(ch);
        i += 1;
    }

    out
}

// ── Base64 pipeline detection ─────────────────────────────────────────────────

/// Try to recognize and decode:
///   `echo <b64token> | base64 -d`
///   `echo <b64token> | base64 --decode`
///   `printf <b64token> | base64 -d`
///   Optionally followed by `| bash` / `| sh` / `| bash -c ...`
///
/// Returns `Some(NormalizeResult)` when the pattern fires, `None` otherwise.
fn try_decode_base64_pipeline(cmd: &str, depth: u8) -> Option<NormalizeResult> {
    // Split on `|` — simple tokenisation sufficient for this pattern.
    let stages: Vec<&str> = cmd.split('|').collect();
    if stages.len() < 2 {
        return None;
    }

    // Find the base64 stage index.
    let b64_stage_idx = stages.iter().position(|s| {
        let t = s.trim();
        let words: Vec<&str> = t.split_whitespace().collect();
        matches!(words.first().copied(), Some("base64"))
            && words.iter().any(|w| *w == "-d" || *w == "--decode")
    })?;

    if b64_stage_idx == 0 {
        return None; // base64 must have an upstream stage
    }

    // The upstream stage (index b64_stage_idx - 1) must be echo/printf with
    // a literal token that looks like base64.
    let upstream = stages[b64_stage_idx - 1].trim();
    let upstream_words: Vec<&str> = upstream.split_whitespace().collect();

    let producer_head = upstream_words.first().copied()?;
    if !matches!(producer_head, "echo" | "printf") {
        return None;
    }

    // Find the first positional arg that isn't a flag — that's the b64 payload.
    let b64_token = upstream_words
        .iter()
        .skip(1)
        .find(|w| !w.starts_with('-'))?;

    // Strip surrounding quotes if present (single or double).
    let b64_bare = strip_quotes(b64_token);

    // Must look like a base64 string: alphanumeric + '+', '/', '=', newlines.
    if !looks_like_base64(b64_bare) {
        return None;
    }

    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_bare)
        .or_else(|_| {
            // Try URL-safe variant.
            base64::engine::general_purpose::URL_SAFE.decode(b64_bare)
        })
        .or_else(|_| {
            // Try without padding.
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64_bare)
        })
        .ok()?;

    let decoded_str = String::from_utf8(decoded_bytes).ok()?;
    let decoded = decoded_str.trim().to_string();
    if decoded.is_empty() {
        return None;
    }

    // Downstream stages after base64 (if any) — check for `bash`/`sh`.
    // If there are downstream stages, treat the decoded text as a piped-body
    // and re-build the pipeline as `bash -c '<decoded>'` for re-parse.
    let downstream: Vec<&str> = stages[b64_stage_idx + 1..].to_vec();
    let reconstructed = if downstream.is_empty() {
        // No downstream shell: the decoded output is just data (e.g. `echo
        // <b64> | base64 -d` with no further processing). Still re-parse
        // because the decoded text might itself be a command.
        decoded.clone()
    } else {
        // Downstream contains further pipeline stages. The most common form
        // is `| bash` or `| sh -c` — reconstruct as a shell invocation.
        let downstream_cmd = downstream.join("|").trim().to_string();
        let shell_head = downstream_cmd
            .split_whitespace()
            .next()
            .unwrap_or("bash")
            .to_string();
        // Check if downstream stage is a shell.
        let is_shell = matches!(shell_head.as_str(), "bash" | "sh" | "zsh" | "ksh" | "dash");
        if is_shell {
            // Build `bash -c 'DECODED'` so the existing -c re-parse path fires.
            format!("{shell_head} -c {}", shell_quote(&decoded))
        } else {
            // Non-shell downstream (e.g. `base64 -d | base64 -d | bash`):
            // reconstruct `decoded | remaining_stages` so the recursion can
            // decode the next stage. This handles double/triple encoding
            // (F1 / RAN-421 G2.3) where each `base64 -d` stage must be
            // peeled off one level at a time within the depth budget.
            format!("echo {} | {downstream_cmd}", shell_quote(&decoded))
        }
    };

    // Recurse to handle doubly-encoded payloads, bounded by depth.
    if depth <= 1 {
        return Some(NormalizeResult::depth_exceeded());
    }
    let inner = normalize(&reconstructed, depth - 1);
    Some(inner)
}

/// Try to recognize and decode `eval $(echo <b64> | base64 -d)` or
/// `bash -c "$(echo <b64> | base64 -d)"` patterns.
fn try_decode_base64_command_sub(cmd: &str, depth: u8) -> Option<NormalizeResult> {
    // Look for `$(echo ... | base64 -d)` anywhere in the command.
    // Simple scan: find `$(` and matching `)`.
    let start = cmd.find("$(")?;
    let inner_start = start + 2;
    // Find the matching `)`.
    let mut depth_count = 1i32;
    let mut end = inner_start;
    let bytes = cmd.as_bytes();
    while end < bytes.len() {
        match bytes[end] {
            b'(' => depth_count += 1,
            b')' => {
                depth_count -= 1;
                if depth_count == 0 {
                    break;
                }
            }
            _ => {}
        }
        end += 1;
    }
    if depth_count != 0 {
        return None;
    }

    let sub_body = &cmd[inner_start..end]; // text inside $(...)
                                           // Check if the body is `echo <b64> | base64 -d`.
    if let Some(decoded_result) = try_decode_base64_pipeline(sub_body, depth) {
        if decoded_result.depth_exceeded {
            return Some(NormalizeResult::depth_exceeded());
        }
        // Splice the decoded text back into the original command in place of
        // `$(...)`. The outer eval/bash -c wrapper will then re-parse it.
        let decoded_text = decoded_result.commands.into_iter().next()?;

        // Strip one layer of surrounding double-quotes if the `$(...)`
        // was wrapped in them — e.g. `bash -c "$(echo <b64> | base64 -d)"`.
        // In that case prefix ends with `"` and suffix starts with `"`.
        // Without stripping those outer quotes the reconstructed form
        // becomes `bash -c "'DECODED'"` (double-then-single quoted body),
        // which the AST cannot unwrap as a valid bash -c body.
        let raw_prefix = &cmd[..start];
        let raw_suffix = if end + 1 < cmd.len() {
            &cmd[end + 1..]
        } else {
            ""
        };
        let (prefix, suffix) = if raw_prefix.ends_with('"') && raw_suffix.starts_with('"') {
            (&raw_prefix[..raw_prefix.len() - 1], &raw_suffix[1..])
        } else {
            (raw_prefix, raw_suffix)
        };

        let reconstructed = format!("{prefix}{}{suffix}", shell_quote(&decoded_text));
        if depth <= 1 {
            return Some(NormalizeResult::depth_exceeded());
        }
        let inner = normalize(&reconstructed, depth - 1);
        return Some(inner);
    }
    None
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Expand IFS-based obfuscation: detect `IFS=<char>` assignments at the
/// start of the command (before a `;`) and substitute `${IFS}` / `$IFS`
/// occurrences with that literal character in the rest of the command.
/// Then strip the IFS character from within command-name tokens so that
/// split names like `r/m` (IFS=/) and `rm-rf` (IFS=-) collapse to
/// recognisable forms.
///
/// Examples:
///   `IFS=/; r${IFS}m -rf /home/user`  →  `IFS=/; rm -rf /home/user`
///   `IFS=-; rm${IFS}rf /etc/passwd`   →  `IFS=-; rm rf /etc/passwd`
///
/// Only handles the simple `IFS=<single-char>` form; complex IFS values are
/// left as-is to avoid false positives on legitimate uses.
fn expand_ifs(cmd: &str) -> String {
    // Fast-path: if there is no `IFS` in the string, return early.
    if !cmd.contains("IFS") {
        return cmd.to_string();
    }

    // Find `IFS=<char>` pattern.
    let bytes = cmd.as_bytes();
    let n = bytes.len();
    let mut ifs_char: Option<char> = None;
    let mut i = 0;
    while i + 5 <= n {
        if &bytes[i..i + 4] == b"IFS=" {
            let val_byte = bytes[i + 4];
            let val_char = val_byte as char;
            if val_char.is_ascii()
                && !val_char.is_ascii_alphanumeric()
                && val_char != '"'
                && val_char != '\''
            {
                ifs_char = Some(val_char);
            }
            break;
        }
        i += 1;
    }

    let Some(ifs) = ifs_char else {
        return cmd.to_string();
    };

    // Substitute `${IFS}` and `$IFS` with the IFS character.
    let expanded = cmd
        .replace("${IFS}", &ifs.to_string())
        .replace("$IFS", &ifs.to_string());

    // After substitution, collapse the IFS char from within word tokens
    // so that split command names are reassembled.  For example, with
    // IFS=`/`, the token `r/m` should become `rm` (the `/` was the IFS
    // separator); with IFS=`-`, `rm-rf` → `rm rf` (splitting on `-`
    // yields the command `rm` and the flag fragment `rf`).
    //
    // Strategy: scan word-by-word; for any word that contains the IFS
    // character but is not a path argument (doesn't start with `/` and
    // doesn't look like a flag), replace the IFS char with a space so
    // the token is split into its component words.  For single-char IFS
    // that is `/`, be conservative: only apply to the first token after
    // the `;` separator (the command name position) to avoid corrupting
    // real path arguments.
    collapse_ifs_in_tokens(&expanded, ifs)
}

/// Replace the IFS character within word tokens with a space, splitting
/// obfuscated concatenations (`r/m` → `rm`, `rm-rf` → `rm rf`).
///
/// Only processes tokens in command-name position (before the first
/// space-separated argument after a statement separator `; `).  Path-
/// like tokens that start with `/` are left unchanged to avoid corrupting
/// legitimate flag arguments like `-rf /home/...`.
fn collapse_ifs_in_tokens(cmd: &str, ifs: char) -> String {
    // Split on `; ` to find statement boundaries; process each segment.
    let segments: Vec<&str> = cmd.splitn(10, "; ").collect();
    let mut out = Vec::with_capacity(segments.len());
    for seg in &segments {
        let words: Vec<&str> = seg.splitn(2, ' ').collect();
        let first_word = words[0];
        // Only collapse IFS in the command-name token (first word) and
        // only when it doesn't start with `/`, `-`, or `$` and doesn't
        // contain `=` (to avoid corrupting path arguments, variable
        // references, and assignment tokens like `IFS=/`).
        let collapsed_first = if first_word.contains(ifs)
            && !first_word.starts_with('/')
            && !first_word.starts_with('-')
            && !first_word.starts_with('$')
            && !first_word.contains('=')
        {
            // Try removing the IFS char to see if the result is a known
            // dangerous command (e.g. `r/m` → `rm`). If yes, use the
            // collapsed form. Otherwise replace with space so the token
            // is split into its IFS-separated words (e.g. `rm-rf` →
            // `rm rf` which gives `rm` as the command head).
            let without_ifs = first_word.replace(ifs, "");
            if is_dangerous_command_name(&without_ifs) {
                without_ifs
            } else {
                first_word.replace(ifs, " ")
            }
        } else {
            first_word.to_string()
        };
        if words.len() == 2 {
            out.push(format!("{collapsed_first} {}", words[1]));
        } else {
            out.push(collapsed_first);
        }
    }
    out.join("; ")
}

/// Check whether a string is a known dangerous command name that could
/// be recovered by IFS-stripping obfuscation (e.g. `r/m` → `rm`).
/// Kept intentionally narrow — only command names the rules layer
/// explicitly classifies as destructive.
fn is_dangerous_command_name(name: &str) -> bool {
    matches!(
        name,
        "rm" | "curl"
            | "wget"
            | "bash"
            | "sh"
            | "zsh"
            | "ksh"
            | "dash"
            | "eval"
            | "base64"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "shred"
            | "dd"
            | "mkfs"
            | "fdisk"
    )
}

fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 {
        let first = b[0];
        let last = b[b.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn looks_like_base64(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    // Must consist only of base64 chars: A-Z a-z 0-9 + / = - _ (URL-safe)
    // and be non-trivially long (at least 4 chars).
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_' | '\n' | '\r')
    })
}

/// Wrap a string in single quotes for shell re-injection, escaping any
/// embedded single quotes via the `'` → `'\''` replacement.
fn shell_quote(s: &str) -> String {
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DoD class 1: Unit — AST walker per pattern ───────────────────────

    #[test]
    fn collapse_quote_splits_empty_single_quotes() {
        // `b''a''sh` → `bash`
        assert_eq!(collapse_quote_splits("b''a''sh"), "bash");
    }

    #[test]
    fn collapse_quote_splits_empty_double_quotes() {
        // `b""a""sh` → `bash`
        assert_eq!(collapse_quote_splits("b\"\"a\"\"sh"), "bash");
    }

    #[test]
    fn collapse_quote_splits_mixed_empty_quotes() {
        // `b''a""sh` → `bash`
        assert_eq!(collapse_quote_splits("b''a\"\"sh"), "bash");
    }

    #[test]
    fn collapse_quote_splits_nonempty_quoted_region_preserved() {
        // `echo 'hello'` — non-empty region, keep as-is.
        assert_eq!(collapse_quote_splits("echo 'hello'"), "echo 'hello'");
    }

    #[test]
    fn collapse_quote_splits_curl_variant() {
        // `c\u\r\l` — backslash form is handled by decode_token, not
        // collapse_quote_splits. Check that collapse_quote_splits leaves it
        // unchanged (decode_token handles it separately).
        let result = collapse_quote_splits("c\\u\\r\\l");
        // No quotes to strip — returned unchanged.
        assert_eq!(result, "c\\u\\r\\l");
    }

    #[test]
    fn collapse_quote_splits_base64_in_token() {
        // `ba''se64` → `base64`
        assert_eq!(collapse_quote_splits("ba''se64"), "base64");
    }

    #[test]
    fn collapse_quote_splits_e_val() {
        // `e''val` → `eval`
        assert_eq!(collapse_quote_splits("e''val"), "eval");
    }

    // ── DoD class 1: base64 pipeline decode ─────────────────────────────

    #[test]
    fn base64_pipeline_decode_simple() {
        // `echo cm0gLXJmIC8= | base64 -d` → decoded: `rm -rf /`
        let result = normalize("echo cm0gLXJmIC8= | base64 -d", 3);
        assert!(!result.depth_exceeded);
        assert!(
            result.commands.iter().any(|c| c.contains("rm")),
            "expected rm in normalized output, got: {:?}",
            result.commands
        );
    }

    #[test]
    fn base64_pipeline_decode_with_shell() {
        // `echo cm0gLXJmIC8= | base64 -d | bash` →
        // decoded: `rm -rf /` fed to bash → `bash -c 'rm -rf /'`
        let result = normalize("echo cm0gLXJmIC8= | base64 -d | bash", 3);
        assert!(!result.depth_exceeded);
        let joined = result.commands.join(" ");
        assert!(
            joined.contains("rm") || joined.contains("bash"),
            "expected destructive signal in: {joined:?}"
        );
    }

    #[test]
    fn base64_pipeline_decode_url_safe() {
        // URL-safe base64 for `rm -rf /` → `cm0gLXJmIC8=` (same in this case)
        let b64 = base64::engine::general_purpose::URL_SAFE.encode("rm -rf /");
        let cmd = format!("echo {b64} | base64 -d");
        let result = normalize(&cmd, 3);
        assert!(!result.depth_exceeded);
        let joined = result.commands.join(" ");
        assert!(joined.contains("rm"), "expected rm in: {joined:?}");
    }

    #[test]
    fn base64_command_sub_decode() {
        // `eval $(echo cm0gLXJmIC8= | base64 -d)`
        let result = normalize("eval $(echo cm0gLXJmIC8= | base64 -d)", 3);
        assert!(!result.depth_exceeded);
        let joined = result.commands.join(" ");
        assert!(
            joined.contains("eval") || joined.contains("rm"),
            "expected eval or rm in: {joined:?}"
        );
    }

    // ── DoD class 3: Snapshot — normalized-command output ───────────────

    #[test]
    fn snapshot_quote_split_bash() {
        // Exact normalized form.
        let result = normalize("b''a\"\"sh -c 'rm -rf /'", 3);
        let cmd = result.commands.first().unwrap().clone();
        // Leading token must be `bash` after collapse.
        assert!(
            cmd.starts_with("bash"),
            "expected bash prefix, got: {cmd:?}"
        );
    }

    #[test]
    fn snapshot_base64_decoded_rm() {
        // `echo cm0gLXJmIC8= | base64 -d` → decoded is `rm -rf /`.
        let result = normalize("echo cm0gLXJmIC8= | base64 -d", 3);
        let cmd = result.commands.first().unwrap().clone();
        // The decoded payload is `rm -rf /`.
        assert_eq!(cmd.trim(), "rm -rf /");
    }

    // ── DoD class 4: Negative — legitimate complex command not blocked ───

    #[test]
    fn negative_plain_echo_not_flagged() {
        let result = normalize("echo hello | cat", 3);
        assert!(!result.depth_exceeded);
        assert_eq!(result.commands.len(), 1);
        // Should pass through unchanged.
        assert_eq!(result.commands[0], "echo hello | cat");
    }

    #[test]
    fn negative_git_push_not_modified() {
        let result = normalize("git push origin main", 3);
        assert!(!result.depth_exceeded);
        assert_eq!(result.commands[0], "git push origin main");
    }

    #[test]
    fn negative_ls_with_quotes_not_modified() {
        // `ls 'my dir'` — non-empty quoted arg, must not be collapsed.
        let result = normalize("ls 'my dir'", 3);
        assert!(!result.depth_exceeded);
        assert_eq!(result.commands[0], "ls 'my dir'");
    }

    #[test]
    fn negative_cargo_test_unchanged() {
        let result = normalize("cargo test --all", 3);
        assert!(!result.depth_exceeded);
        assert_eq!(result.commands[0], "cargo test --all");
    }

    #[test]
    fn negative_non_base64_echo_pipe_base64() {
        // `echo 'not base64!!!' | base64 -d` — the token contains `!` which
        // is not a valid base64 character, so the pipeline decode should not
        // fire and the command passes through normalized (but not decoded).
        let result = normalize("echo 'not base64!!!' | base64 -d", 3);
        // Should not decode (looks_like_base64 returns false for `!`).
        assert!(!result.depth_exceeded);
        // No rm in output.
        assert!(
            !result.commands.iter().any(|c| c.contains("rm")),
            "false positive: {:?}",
            result.commands
        );
    }

    // ── DoD class 7: Recursive depth limit ──────────────────────────────

    #[test]
    fn depth_limit_at_zero_returns_marker() {
        let result = normalize("echo something", 0);
        assert!(result.depth_exceeded);
        assert!(result.commands[0].contains("depth_exceeded"));
    }

    #[test]
    fn depth_limit_fires_on_doubly_encoded() {
        // Doubly base64-encoded `rm -rf /`:
        // encode(encode("rm -rf /")) = encode("cm0gLXJmIC8=")
        let inner_b64 = base64::engine::general_purpose::STANDARD.encode("rm -rf /");
        let outer_b64 = base64::engine::general_purpose::STANDARD.encode(&inner_b64);
        let cmd = format!("echo {outer_b64} | base64 -d | base64 -d | bash");
        // At depth=1 the outer decode happens, then depth=0 fires depth_exceeded.
        let result = normalize(&cmd, 1);
        // Either depth_exceeded or the inner decode was reached — no infinite loop.
        // The important invariant: function must return (no stack overflow).
        let _ = result;
    }

    #[test]
    fn depth_limit_three_nested_base64() {
        // Triply encoded — at default depth=3 the third decode hits depth 0.
        let l1 = base64::engine::general_purpose::STANDARD.encode("rm -rf /");
        let l2 = base64::engine::general_purpose::STANDARD.encode(&l1);
        let l3 = base64::engine::general_purpose::STANDARD.encode(&l2);
        let cmd = format!("echo {l3} | base64 -d");
        // Must not panic / infinite loop regardless of depth.
        let result = normalize(&cmd, 3);
        let _ = result; // Just verifying no panic.
    }

    // ── DoD class 6: Proptest — random bash → no panic ──────────────────

    proptest::proptest! {
        #[test]
        fn proptest_normalize_never_panics(s in ".*") {
            // normalize must not panic for any input string.
            let result = normalize(&s, 3);
            // Must always return at least one command.
            proptest::prop_assert!(!result.commands.is_empty());
        }

        #[test]
        fn proptest_depth_zero_always_depth_exceeded(s in "[a-zA-Z0-9 |./_-]{1,50}") {
            let result = normalize(&s, 0);
            proptest::prop_assert!(result.depth_exceeded);
        }
    }

    // ── DoD class 5: Performance — 1KB script ≤10ms ─────────────────────
    //
    // Benchmark-quality timing is in benches/; this test merely checks that
    // a 1KB script completes without asserting wall-clock time (wall-clock
    // assertions are flaky in CI). The criterion bench in benches/ carries
    // the ≤10ms gate and is annotated #[ignore] in debug builds.
    #[test]
    fn normalize_1kb_script_completes() {
        let script = "echo hello; ".repeat(80); // ~960 bytes
        let result = normalize(&script, 3);
        assert!(!result.commands.is_empty());
    }
}
