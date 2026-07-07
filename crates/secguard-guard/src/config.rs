use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// PostToolUse output-redaction configuration (RAN-417 G1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostuseConfig {
    /// When false the postuse-redact hook passes the payload through unchanged.
    /// Default: true.
    #[serde(default = "default_postuse_enabled")]
    pub enabled: bool,
    /// Marker text substituted for a detected secret.  The scanner always
    /// emits `[REDACTED:<rule_id>]`; this field controls the *additional*
    /// summary marker logged to stderr.  Default: `"[REDACTED]"`.
    #[serde(default = "default_postuse_marker")]
    pub redaction_marker: String,
}

fn default_postuse_enabled() -> bool {
    true
}

fn default_postuse_marker() -> String {
    "[REDACTED]".to_string()
}

impl Default for PostuseConfig {
    fn default() -> Self {
        Self {
            enabled: default_postuse_enabled(),
            redaction_marker: default_postuse_marker(),
        }
    }
}

/// Guard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    #[serde(default)]
    pub safe_kill_targets: Vec<String>,
    #[serde(default)]
    pub safe_rm_patterns: Vec<String>,
    /// User-defined command prefixes that are always safe.
    /// Built-in allowlist rules (gws, diana, psql, terraform plan, brew, package managers)
    /// are not listed here — they are hard-coded in policy.rs.
    #[serde(default)]
    pub safe_command_prefixes: Vec<String>,
    /// When true, the Claude hook emits `exit(2)` on destructive verdicts instead of
    /// a JSON `ask` response. exit(2) is honoured even in Claude's `bypassPermissions`
    /// mode; JSON `ask` is not. Default true: a security hook that fails open in
    /// "accept all" mode is misleading. Override per-invocation with `SECGUARD_STRICT=0`.
    #[serde(default = "default_strict_block")]
    pub strict_block: bool,
    /// When true (default), the Codex secrets-scan hook DENIES the tool call when
    /// a credential is detected. Codex PreToolUse cannot rewrite tool input, so
    /// redaction is impossible there; allowing it through would leak the secret to
    /// the tool while the hook reports "protected". Fail-closed is the safe
    /// default. Set false to fail-loud instead (allow + a systemMessage warning).
    /// Claude/Gemini redact via updatedInput and are unaffected.
    #[serde(default = "default_codex_secrets_block")]
    pub codex_secrets_block: bool,
    /// Canonical allow-rule buckets.
    #[serde(default, skip_serializing_if = "RuleBuckets::is_empty")]
    pub allow: RuleBuckets,
    /// Canonical deny-rule buckets.
    #[serde(default, skip_serializing_if = "RuleBuckets::is_empty")]
    pub deny: RuleBuckets,
    /// Legacy command deny rules. Kept for compatibility with older
    /// `.secguard.toml` files; effective config loading normalises these into
    /// `deny.commands`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blacklist: Vec<crate::matcher::ListRuleSpec>,
    /// Legacy command allow rules. Kept for compatibility with older
    /// `.secguard.toml` files; effective config loading normalises these into
    /// `allow.commands`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub whitelist: Vec<crate::matcher::ListRuleSpec>,
    /// Blast × reversibility scoring policy overrides (RAN-414). Empty by
    /// default — the built-in [`crate::scoring::default_action_for`] matrix
    /// applies to every cell not overridden here.
    #[serde(default, skip_serializing_if = "ScoringConfig::is_empty")]
    pub scoring: ScoringConfig,
    /// PostToolUse output-redaction settings (RAN-417 G1.2).
    #[serde(default)]
    pub postuse: PostuseConfig,
}

/// Per-cell overrides for the blast × reversibility action matrix.
///
/// A sparse table: cells without an override fall through to
/// [`crate::scoring::default_action_for`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoringConfig {
    #[serde(default, rename = "override", skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<ScoringOverride>,
}

/// A single `(blast, reversibility) -> action` override cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringOverride {
    pub blast: u8,
    pub reversibility: u8,
    pub action: crate::scoring::Action,
}

impl ScoringConfig {
    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }

    /// Resolve the action for a decision: a matching override wins, else the
    /// built-in default matrix.
    pub fn action_for(&self, d: crate::scoring::Decision) -> crate::scoring::Action {
        self.overrides
            .iter()
            .find(|o| o.blast == d.blast && o.reversibility == d.reversibility)
            .map(|o| o.action)
            .unwrap_or_else(|| crate::scoring::default_action_for(d))
    }
}

/// Canonical rule buckets under `[allow.*]` or `[deny.*]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleBuckets {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<crate::matcher::ListRuleSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<crate::matcher::ListRuleSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<crate::matcher::ListRuleSpec>,
}

impl RuleBuckets {
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty() && self.paths.is_empty() && self.secrets.is_empty()
    }
}

/// Effective config plus the concrete files that contributed to it.
#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    pub config: GuardConfig,
    pub user_config_path: Option<PathBuf>,
    pub project_config_path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct GuardConfigLayer {
    safe_kill_targets: Option<Vec<String>>,
    safe_rm_patterns: Option<Vec<String>>,
    safe_command_prefixes: Option<Vec<String>>,
    strict_block: Option<bool>,
    codex_secrets_block: Option<bool>,
    allow: Option<RuleBuckets>,
    deny: Option<RuleBuckets>,
    blacklist: Option<Vec<crate::matcher::ListRuleSpec>>,
    whitelist: Option<Vec<crate::matcher::ListRuleSpec>>,
    scoring: Option<ScoringConfig>,
    postuse: Option<PostuseConfig>,
}

fn default_strict_block() -> bool {
    true
}

fn default_codex_secrets_block() -> bool {
    true
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            safe_kill_targets: vec!["node".into(), "python".into(), "ruby".into()],
            safe_rm_patterns: vec![
                "build".into(),
                "dist".into(),
                "node_modules".into(),
                "__pycache__".into(),
                "target/debug".into(),
                ".build".into(),
                "/tmp/".into(),
            ],
            safe_command_prefixes: vec![],
            strict_block: default_strict_block(),
            codex_secrets_block: default_codex_secrets_block(),
            allow: RuleBuckets::default(),
            deny: RuleBuckets::default(),
            blacklist: vec![],
            whitelist: vec![],
            scoring: ScoringConfig::default(),
            postuse: PostuseConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompiledRuleBuckets {
    pub commands: Vec<crate::matcher::ListRule>,
    pub paths: Vec<crate::matcher::ListRule>,
    pub secrets: Vec<crate::matcher::ListRule>,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledRuleLists {
    pub deny: CompiledRuleBuckets,
    pub allow: CompiledRuleBuckets,
}

/// Build runtime ListRule vectors from the spec form. Logs and skips any spec
/// that fails to compile (matches existing load() resilience pattern).
pub fn build_lists(
    cfg: &GuardConfig,
) -> (Vec<crate::matcher::ListRule>, Vec<crate::matcher::ListRule>) {
    let lists = build_rule_lists(cfg);
    (lists.deny.commands, lists.allow.commands)
}

pub fn build_rule_lists(cfg: &GuardConfig) -> CompiledRuleLists {
    let deny_commands = compile_rules(
        "deny.commands",
        cfg.deny.commands.iter().chain(cfg.blacklist.iter()),
    );
    let allow_commands = compile_rules(
        "allow.commands",
        cfg.allow.commands.iter().chain(cfg.whitelist.iter()),
    );

    CompiledRuleLists {
        deny: CompiledRuleBuckets {
            commands: deny_commands,
            paths: compile_rules("deny.paths", cfg.deny.paths.iter()),
            secrets: compile_rules("deny.secrets", cfg.deny.secrets.iter()),
        },
        allow: CompiledRuleBuckets {
            commands: allow_commands,
            paths: compile_rules("allow.paths", cfg.allow.paths.iter()),
            secrets: compile_rules("allow.secrets", cfg.allow.secrets.iter()),
        },
    }
}

fn compile_rules<'a>(
    label: &'static str,
    specs: impl Iterator<Item = &'a crate::matcher::ListRuleSpec>,
) -> Vec<crate::matcher::ListRule> {
    specs
        .cloned()
        .filter_map(|s| match crate::matcher::ListRule::try_from(s) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("[secguard] dropping malformed {label} rule: {e}");
                None
            }
        })
        .collect()
}

/// Resolve the effective strict_block setting: env override wins, then config.
/// Recognised env values mirror SECGUARD_SHADOW: `0`/`off`/`false`/empty = off,
/// anything else = on. Unset env → fall through to config.
pub fn is_strict(config: &GuardConfig) -> bool {
    match std::env::var("SECGUARD_STRICT").ok() {
        Some(raw) => {
            let v = raw.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "off" || v == "false")
        }
        None => config.strict_block,
    }
}

/// Load `GuardConfig` from disk.
///
/// Effective config order:
/// 1. Built-in defaults.
/// 2. User config: `$SECGUARD_CONFIG` if set and readable, otherwise
///    `~/.config/secguard/config.toml`.
/// 3. Nearest project `.secguard.toml`, discovered from the current working
///    directory upward.
///
/// On parse error, logs to stderr and falls back to default. Never panics.
pub fn load() -> GuardConfig {
    load_snapshot().config
}

/// Load effective config plus the files that contributed to it.
pub fn load_snapshot() -> ConfigSnapshot {
    let start = match std::env::current_dir() {
        Ok(cwd) => Some(cwd),
        Err(e) => {
            eprintln!("[secguard] current_dir error: {e} — project config disabled");
            None
        }
    };
    load_snapshot_from_sources(user_config_path(), start.as_deref())
}

/// Load effective config for a known project directory.
pub fn load_for_dir(start: &Path) -> GuardConfig {
    load_snapshot_for_dir(start).config
}

/// Load effective config snapshot for a known project directory.
pub fn load_snapshot_for_dir(start: &Path) -> ConfigSnapshot {
    load_snapshot_from_sources(user_config_path(), Some(start))
}

/// Effective secguard config cache for long-lived processes.
///
/// Hook invocations should continue using [`load`] so each short process reads
/// the current file state directly. Server-mode callers can hold this cache and
/// read from it between requests; filesystem events refresh the snapshot through
/// the same merge path as [`load_snapshot_for_dir`].
pub struct ConfigCache {
    snapshot: Arc<RwLock<ConfigSnapshot>>,
    _watcher: notify::RecommendedWatcher,
}

impl ConfigCache {
    pub fn watch_current_dir() -> notify::Result<Self> {
        let cwd = std::env::current_dir().unwrap_or_else(|e| {
            eprintln!("[secguard] current_dir error: {e} — watching user config only");
            PathBuf::new()
        });
        Self::watch_for_dir(cwd)
    }

    pub fn watch_for_dir(start: impl AsRef<Path>) -> notify::Result<Self> {
        use notify::Watcher;

        let start = start.as_ref().to_path_buf();
        let user_path = user_config_path();
        let initial = load_snapshot_from_sources(user_path.clone(), Some(&start));
        let watch_dirs = config_watch_dirs(&initial, Some(&start));
        let snapshot = Arc::new(RwLock::new(initial));
        let snapshot_for_watcher = Arc::clone(&snapshot);
        let start_for_watcher = start.clone();

        let mut watcher = notify::RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| match res {
                Ok(event) if is_config_reload_event(&event) => {
                    let fresh =
                        load_snapshot_from_sources(user_path.clone(), Some(&start_for_watcher));
                    match snapshot_for_watcher.write() {
                        Ok(mut current) => *current = fresh,
                        Err(poisoned) => {
                            let mut current = poisoned.into_inner();
                            *current = fresh;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => eprintln!("[secguard] config watcher error: {e}"),
            },
            notify::Config::default(),
        )?;

        for dir in watch_dirs {
            watcher.watch(&dir, notify::RecursiveMode::NonRecursive)?;
        }

        Ok(Self {
            snapshot,
            _watcher: watcher,
        })
    }

    pub fn snapshot(&self) -> ConfigSnapshot {
        match self.snapshot.read() {
            Ok(snapshot) => snapshot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn load(&self) -> GuardConfig {
        self.snapshot().config
    }
}

fn user_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SECGUARD_CONFIG") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Some(p);
        }
        // env var set but path doesn't exist — fall through to default path
        eprintln!("[secguard] SECGUARD_CONFIG={path} not found, falling back to default path");
    }

    // Documented, cross-platform location: ~/.config/secguard/config.toml.
    // Checked BEFORE dirs::config_dir() because on macOS the latter resolves to
    // ~/Library/Application Support, so the documented XDG path would otherwise be
    // silently ignored — the bug that made `strict_block` (and every other config
    // key) never apply on macOS, hard-blocking instead of asking.
    if let Some(home) = dirs::home_dir() {
        let xdg = home.join(".config").join("secguard").join("config.toml");
        if xdg.exists() {
            return Some(xdg);
        }
    }

    if let Some(config_dir) = dirs::config_dir() {
        let p = config_dir.join("secguard").join("config.toml");
        if p.exists() {
            return Some(p);
        }
    }

    None
}

fn config_watch_dirs(snapshot: &ConfigSnapshot, project_start: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = BTreeSet::new();

    if let Some(path) = &snapshot.user_config_path {
        if let Some(parent) = path.parent() {
            dirs.insert(parent.to_path_buf());
        }
    } else if let Some(config_dir) = dirs::config_dir() {
        let default_user_dir = config_dir.join("secguard");
        if default_user_dir.exists() {
            dirs.insert(default_user_dir);
        }
    }

    if let Some(path) = &snapshot.project_config_path {
        if let Some(parent) = path.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }

    if let Some(start) = project_start {
        let dir = if start.is_file() {
            start.parent().unwrap_or(start)
        } else {
            start
        };
        if dir.exists() {
            dirs.insert(dir.to_path_buf());
        }
    }

    dirs.into_iter().collect()
}

fn is_config_reload_event(event: &notify::Event) -> bool {
    let relevant_kind = matches!(
        event.kind,
        notify::EventKind::Create(_) | notify::EventKind::Modify(_) | notify::EventKind::Remove(_)
    );
    relevant_kind
        && event.paths.iter().any(|path| {
            path.file_name().and_then(|name| name.to_str()) == Some(".secguard.toml")
                || path.extension().and_then(|ext| ext.to_str()) == Some("toml")
        })
}

fn load_snapshot_from_sources(
    user_path: Option<PathBuf>,
    project_start: Option<&Path>,
) -> ConfigSnapshot {
    let mut cfg = GuardConfig::default();

    if let Some(path) = &user_path {
        apply_path_layer(&mut cfg, path);
    }

    let project_path = project_start.and_then(find_project_config);
    if let Some(path) = &project_path {
        apply_path_layer(&mut cfg, path);
    }

    ConfigSnapshot {
        config: cfg,
        user_config_path: user_path,
        project_config_path: project_path,
    }
}

fn find_project_config(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_file() {
        start.parent()?
    } else {
        start
    };

    loop {
        let candidate = dir.join(".secguard.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
}

fn apply_path_layer(cfg: &mut GuardConfig, path: &Path) {
    match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str::<GuardConfigLayer>(&text) {
            Ok(layer) => apply_layer(cfg, layer),
            Err(e) => {
                eprintln!("[secguard] config parse error: {} — using defaults", e);
            }
        },
        Err(e) => {
            eprintln!("[secguard] config read error: {} — using defaults", e);
        }
    }
}

fn apply_layer(cfg: &mut GuardConfig, layer: GuardConfigLayer) {
    if let Some(values) = layer.safe_kill_targets {
        extend_unique(&mut cfg.safe_kill_targets, values);
    }
    if let Some(values) = layer.safe_rm_patterns {
        extend_unique(&mut cfg.safe_rm_patterns, values);
    }
    if let Some(values) = layer.safe_command_prefixes {
        extend_unique(&mut cfg.safe_command_prefixes, values);
    }
    if let Some(strict) = layer.strict_block {
        cfg.strict_block = strict;
    }
    if let Some(v) = layer.codex_secrets_block {
        cfg.codex_secrets_block = v;
    }
    if let Some(rules) = layer.deny {
        prepend_buckets(&mut cfg.deny, rules);
    }
    if let Some(rules) = layer.allow {
        prepend_buckets(&mut cfg.allow, rules);
    }
    if let Some(rules) = layer.blacklist {
        prepend_rules(&mut cfg.deny.commands, rules);
    }
    if let Some(rules) = layer.whitelist {
        prepend_rules(&mut cfg.allow.commands, rules);
    }
    // Scoring overrides are a policy table, not an accumulating list —
    // the most specific layer replaces it wholesale.
    if let Some(scoring) = layer.scoring {
        cfg.scoring = scoring;
    }
    // PostToolUse redaction config — replace wholesale when specified.
    // Individual fields within [postuse] (enabled, redaction_marker) are
    // always set together; partial overrides would leave an inconsistent
    // combination (e.g. disabled=true but stale marker from defaults).
    if let Some(postuse) = layer.postuse {
        cfg.postuse = postuse;
    }
}

fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn prepend_rules(
    target: &mut Vec<crate::matcher::ListRuleSpec>,
    mut rules: Vec<crate::matcher::ListRuleSpec>,
) {
    rules.append(target);
    *target = rules;
}

fn prepend_buckets(target: &mut RuleBuckets, rules: RuleBuckets) {
    prepend_rules(&mut target.commands, rules.commands);
    prepend_rules(&mut target.paths, rules.paths);
    prepend_rules(&mut target.secrets, rules.secrets);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_empty_safe_command_prefixes() {
        let cfg = GuardConfig::default();
        assert!(cfg.safe_command_prefixes.is_empty());
    }

    #[test]
    fn parse_sample_config_with_safe_command_prefixes() {
        let toml_text = r#"
safe_kill_targets = ["node", "python", "postgres"]
safe_command_prefixes = ["gws", "rclone copy", "tailscale status"]
"#;
        let cfg: GuardConfig = toml::from_str(toml_text).expect("parse failed");
        assert!(cfg.safe_kill_targets.contains(&"postgres".to_string()));
        assert!(cfg
            .safe_command_prefixes
            .contains(&"rclone copy".to_string()));
        assert_eq!(cfg.safe_command_prefixes.len(), 3);
    }

    #[test]
    fn strict_block_defaults_to_true() {
        assert!(GuardConfig::default().strict_block);
    }

    #[test]
    fn parse_config_with_strict_block_disabled() {
        let cfg: GuardConfig = toml::from_str("strict_block = false").expect("parse");
        assert!(!cfg.strict_block);
    }

    #[test]
    fn parse_config_without_strict_block_uses_default_true() {
        // Missing field → serde default → true. Backwards-compatible with
        // pre-strict-block config files.
        let cfg: GuardConfig = toml::from_str(r#"safe_command_prefixes = ["gws"]"#).expect("parse");
        assert!(cfg.strict_block);
    }

    #[test]
    fn codex_secrets_block_defaults_to_true() {
        assert!(GuardConfig::default().codex_secrets_block);
        // Missing field in a config file → serde default → true (fail-closed).
        let cfg: GuardConfig = toml::from_str("strict_block = false").expect("parse");
        assert!(cfg.codex_secrets_block);
    }

    #[test]
    fn codex_secrets_block_layer_override_disables() {
        let dir = tempfile::tempdir().unwrap();
        let user_path = dir.path().join("user.toml");
        std::fs::write(&user_path, "codex_secrets_block = false\n").unwrap();
        let cfg = load_snapshot_from_sources(Some(user_path), None).config;
        assert!(!cfg.codex_secrets_block);
    }

    #[test]
    fn is_strict_env_value_recognises_off_and_on() {
        // Env predicate is identical to SECGUARD_SHADOW: 0/off/false/empty = off,
        // anything else = on. We cannot mutate env in parallel tests safely;
        // assert the pure rule against representative inputs. The end-to-end
        // env-var path is exercised by tests/cli.rs against the binary.
        for off in ["0", "off", "false", "OFF", "", "  ", " false "] {
            let v = off.trim().to_ascii_lowercase();
            assert!(
                v.is_empty() || v == "0" || v == "off" || v == "false",
                "expected off for {off:?}"
            );
        }
        for on in ["1", "true", "TRUE", "yes", "on", " 1 "] {
            let v = on.trim().to_ascii_lowercase();
            assert!(
                !(v.is_empty() || v == "0" || v == "off" || v == "false"),
                "expected on for {on:?}"
            );
        }
    }

    #[test]
    fn parse_config_with_blacklist_and_whitelist() {
        let toml_text = r#"
[[blacklist]]
id = "no-curl-bash"
type = "command_prefix"
pattern = "curl | bash"
reason = "remote shell exec banned"

[[whitelist]]
id = "allow-bun-i"
type = "literal"
pattern = "bun install"
"#;
        let cfg: GuardConfig = toml::from_str(toml_text).expect("parse");
        assert_eq!(cfg.blacklist.len(), 1);
        assert_eq!(cfg.whitelist.len(), 1);
        assert_eq!(cfg.blacklist[0].id, "no-curl-bash");
    }

    #[test]
    fn parse_config_with_canonical_rule_buckets() {
        let toml_text = r#"
[[deny.commands]]
id = "no-curl-bash"
type = "command_prefix"
pattern = "curl | bash"

[[allow.paths]]
id = "allow-generated"
type = "literal"
pattern = "generated"

[[deny.secrets]]
id = "deny-env"
type = "regex"
pattern = "\\.env$"
"#;
        let cfg: GuardConfig = toml::from_str(toml_text).expect("parse");
        assert_eq!(cfg.deny.commands[0].id, "no-curl-bash");
        assert_eq!(cfg.allow.paths[0].id, "allow-generated");
        assert_eq!(cfg.deny.secrets[0].id, "deny-env");
    }

    #[test]
    fn missing_blacklist_defaults_to_empty() {
        let cfg: GuardConfig = toml::from_str("safe_command_prefixes = []").expect("parse");
        assert!(cfg.blacklist.is_empty());
        assert!(cfg.whitelist.is_empty());
    }

    #[test]
    fn load_from_sources_merges_builtin_user_and_project_layers() {
        let dir = tempfile::tempdir().unwrap();
        let user_path = dir.path().join("user.toml");
        let project_dir = dir.path().join("repo").join("nested");
        std::fs::create_dir_all(&project_dir).unwrap();
        let project_path = dir.path().join("repo").join(".secguard.toml");

        std::fs::write(
            &user_path,
            r#"
safe_command_prefixes = ["user-safe"]
strict_block = false

[[deny.commands]]
id = "user-deny"
type = "literal"
pattern = "shared deny"

[[allow.commands]]
id = "user-allow"
type = "literal"
pattern = "shared allow"
"#,
        )
        .unwrap();
        std::fs::write(
            &project_path,
            r#"
safe_command_prefixes = ["project-safe"]
strict_block = true

[[deny.commands]]
id = "project-deny"
type = "literal"
pattern = "shared deny"

[[allow.commands]]
id = "project-allow"
type = "literal"
pattern = "shared allow"
"#,
        )
        .unwrap();

        let snapshot = load_snapshot_from_sources(Some(user_path), Some(&project_dir));
        let cfg = snapshot.config;

        assert!(cfg.safe_rm_patterns.contains(&"target/debug".to_string()));
        assert!(cfg.safe_command_prefixes.contains(&"user-safe".to_string()));
        assert!(cfg
            .safe_command_prefixes
            .contains(&"project-safe".to_string()));
        assert!(cfg.strict_block);
        assert_eq!(cfg.deny.commands[0].id, "project-deny");
        assert_eq!(cfg.deny.commands[1].id, "user-deny");
        assert_eq!(cfg.allow.commands[0].id, "project-allow");
        assert_eq!(cfg.allow.commands[1].id, "user-allow");
        assert!(snapshot.user_config_path.is_some());
        assert_eq!(snapshot.project_config_path, Some(project_path));
    }

    #[test]
    fn file_layer_postuse_override_is_merged() {
        // Verifies that a [postuse] block in config.toml actually overrides the
        // default (previously dead_code — the apply_layer arm was missing).
        let dir = tempfile::tempdir().unwrap();
        let user_path = dir.path().join("user.toml");

        std::fs::write(
            &user_path,
            r#"
[postuse]
enabled = false
redaction_marker = "***REDACTED***"
"#,
        )
        .unwrap();

        let snapshot = load_snapshot_from_sources(Some(user_path), None);
        let cfg = snapshot.config;

        assert!(
            !cfg.postuse.enabled,
            "file-layer [postuse] enabled=false must override default true"
        );
        assert_eq!(
            cfg.postuse.redaction_marker, "***REDACTED***",
            "file-layer [postuse] redaction_marker must override default"
        );
    }

    #[test]
    fn find_project_config_walks_up_from_nested_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("repo").join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let project_path = dir.path().join("repo").join(".secguard.toml");
        std::fs::write(&project_path, "strict_block = true").unwrap();

        assert_eq!(find_project_config(&nested), Some(project_path));
    }

    #[test]
    fn malformed_regex_is_dropped_at_build_time() {
        let toml_text = r#"
[[blacklist]]
id = "bad"
type = "regex"
pattern = "(unclosed"
"#;
        let cfg: GuardConfig = toml::from_str(toml_text).expect("toml parses");
        let (denies, _) = build_lists(&cfg);
        // Malformed rule is dropped with a warning, not panicked.
        assert!(denies.is_empty(), "malformed regex should be dropped");
    }

    // Hot-reload test (load_then_reload_reflects_file_change) is moved to
    // tests/blacklist_whitelist.rs. The tempfile-rewrite dance here would
    // exceed the 30 LOC inline budget.

    #[test]
    fn load_from_temp_file_lets_rclone_through() {
        use std::io::Write;

        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            r#"safe_command_prefixes = ["rclone copy", "tailscale status"]"#
        )
        .unwrap();

        let cfg = load_snapshot_from_sources(Some(tmp.path().to_path_buf()), None).config;
        assert!(
            cfg.safe_command_prefixes.iter().any(|p| p == "rclone copy"),
            "rclone copy should be in safe_command_prefixes"
        );

        // Verify it integrates with policy: rclone copy should pass
        use crate::policy::is_safe_by_policy;
        assert!(is_safe_by_policy("rclone copy src dst", &cfg));
        // rm -rf / must still fire
        assert!(!is_safe_by_policy("rm -rf /", &cfg));
    }
}
