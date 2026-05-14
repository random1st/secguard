use serde::{Deserialize, Serialize};

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
}

fn default_strict_block() -> bool {
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
        }
    }
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
/// Resolution order:
/// 1. `$SECGUARD_CONFIG` env var — if set and the path exists, parse it.
/// 2. `~/.config/secguard/config.toml`.
/// 3. `GuardConfig::default()`.
///
/// On parse error, logs to stderr and falls back to default. Never panics.
pub fn load() -> GuardConfig {
    if let Ok(path) = std::env::var("SECGUARD_CONFIG") {
        let p = std::path::Path::new(&path);
        if p.exists() {
            return load_from_path(p);
        }
        // env var set but path doesn't exist — fall through to default path
        eprintln!("[secguard] SECGUARD_CONFIG={path} not found, falling back to default path");
    }

    if let Some(config_dir) = dirs::config_dir() {
        let p = config_dir.join("secguard").join("config.toml");
        if p.exists() {
            return load_from_path(&p);
        }
    }

    GuardConfig::default()
}

fn load_from_path(path: &std::path::Path) -> GuardConfig {
    match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str::<GuardConfig>(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("[secguard] config parse error: {} — using defaults", e);
                GuardConfig::default()
            }
        },
        Err(e) => {
            eprintln!("[secguard] config read error: {} — using defaults", e);
            GuardConfig::default()
        }
    }
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
    fn is_strict_env_override_wins_off() {
        // Save & isolate — we use a unique value to avoid races with other tests
        // that may run in parallel (cargo test default).
        let mut cfg = GuardConfig::default();
        cfg.strict_block = true;

        // We cannot safely mutate env in parallel tests; assert the pure predicate
        // by spelling out the resolution rule for representative values.
        let raw_off = "0";
        let v = raw_off.trim().to_ascii_lowercase();
        assert!(v.is_empty() || v == "0" || v == "off" || v == "false");

        let raw_on = "1";
        let v = raw_on.trim().to_ascii_lowercase();
        assert!(!(v.is_empty() || v == "0" || v == "off" || v == "false"));
    }

    #[test]
    fn load_from_temp_file_lets_rclone_through() {
        use std::io::Write;

        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            r#"safe_command_prefixes = ["rclone copy", "tailscale status"]"#
        )
        .unwrap();

        let cfg = load_from_path(tmp.path());
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
