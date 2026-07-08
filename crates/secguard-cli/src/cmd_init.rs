use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum InitTarget {
    #[default]
    Claude,
    Gemini,
    Codex,
}

pub fn run(target: InitTarget, global: bool) -> anyhow::Result<()> {
    match target {
        InitTarget::Claude => install_claude(global),
        InitTarget::Gemini => install_gemini(global),
        InitTarget::Codex => install_codex(global),
    }
}

fn install_claude(global: bool) -> anyhow::Result<()> {
    let settings_path = settings_path(global, ".claude", "settings.json")?;
    let scope = scope_label(global);
    let bin = current_bin();

    let guard_hook = serde_json::json!({
        "type": "command",
        "command": format!("{bin} hook guard --target claude")
    });
    let secrets_hook = serde_json::json!({
        "type": "command",
        "command": format!("{bin} hook secrets-scan --target claude")
    });

    let mut settings = load_json_object(&settings_path)?;
    let pre = ensure_json_array(&mut settings, &["hooks", "PreToolUse"])?;

    if json_hooks_installed(pre, "secguard hook") {
        eprintln!("secguard hooks already installed in {scope} Claude settings");
        return Ok(());
    }

    pre.push(serde_json::json!({
        "matcher": "Bash",
        "hooks": [guard_hook]
    }));
    pre.push(serde_json::json!({
        "matcher": "Bash|Edit|Write|Agent|mcp__*",
        "hooks": [secrets_hook]
    }));

    write_json(&settings_path, &settings)?;

    eprintln!("Installed secguard hooks to {}", settings_path.display());
    eprintln!("  - client: Claude Code");
    eprintln!("  - guard: Bash commands checked for destructive ops");
    eprintln!("  - secrets-scan: credentials redacted from tool input");

    maybe_offer_model_download()?;
    Ok(())
}

fn install_gemini(global: bool) -> anyhow::Result<()> {
    let settings_path = settings_path(global, ".gemini", "settings.json")?;
    let scope = scope_label(global);
    let bin = current_bin();

    let guard_hook = serde_json::json!({
        "type": "command",
        "command": format!("{bin} hook guard --target gemini")
    });
    let secrets_hook = serde_json::json!({
        "type": "command",
        "command": format!("{bin} hook secrets-scan --target gemini")
    });

    let mut settings = load_json_object(&settings_path)?;
    ensure_json_object(&mut settings, &["hooksConfig"])?
        .insert("enabled".into(), serde_json::Value::Bool(true));

    let before_tool = ensure_json_array(&mut settings, &["hooks", "BeforeTool"])?;
    if json_hooks_installed(before_tool, "secguard hook") {
        eprintln!("secguard hooks already installed in {scope} Gemini settings");
        return Ok(());
    }

    before_tool.push(serde_json::json!({
        "matcher": "run_shell_command",
        "hooks": [guard_hook]
    }));
    before_tool.push(serde_json::json!({
        "matcher": ".*",
        "hooks": [secrets_hook]
    }));

    write_json(&settings_path, &settings)?;

    eprintln!("Installed secguard hooks to {}", settings_path.display());
    eprintln!("  - client: Gemini CLI");
    eprintln!("  - guard: run_shell_command checked before execution");
    eprintln!("  - secrets-scan: credentials redacted from tool input");

    maybe_offer_model_download()?;
    Ok(())
}

fn install_codex(global: bool) -> anyhow::Result<()> {
    let config_path = settings_path(global, ".codex", "config.toml")?;
    let hooks_path = settings_path(global, ".codex", "hooks.json")?;
    let scope = scope_label(global);
    let bin = current_bin();
    let marker = "secguard hook";

    let config = if config_path.exists() {
        fs::read_to_string(&config_path)?
    } else {
        String::new()
    };

    let hooks_enabled = codex_hooks_enabled(&config);
    if !matches!(hooks_enabled, Some(true)) {
        eprintln!(
            "Warning: Codex hooks support is not confirmed in {}. Expected `[features] codex_hooks = true`, but secguard hooks will be written anyway.",
            config_path.display()
        );
    }

    let guard_hook = serde_json::json!({
        "type": "command",
        "command": format!("{bin} hook guard --target codex")
    });

    let mut hooks = load_json_object(&hooks_path)?;
    let pre = ensure_json_array(&mut hooks, &["hooks", "PreToolUse"])?;

    if json_hooks_installed(pre, marker) {
        eprintln!("secguard hooks already installed in {scope} Codex hooks");
        return Ok(());
    }

    pre.push(serde_json::json!({
        "matcher": "Bash",
        "hooks": [guard_hook]
    }));

    if let Some(parent) = hooks_path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_json(&hooks_path, &hooks)?;

    eprintln!("Installed secguard hooks to {}", hooks_path.display());
    eprintln!("  - client: Codex");
    eprintln!("  - guard: Bash commands checked for destructive ops");
    eprintln!(
        "  - secrets-scan: not installed for Codex (PreToolUse does not support input rewriting)"
    );

    Ok(())
}

fn load_json_object(path: &Path) -> anyhow::Result<serde_json::Value> {
    if path.exists() {
        let content = fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;
        if !value.is_object() {
            anyhow::bail!("{} is not a JSON object", path.display());
        }
        Ok(value)
    } else {
        Ok(serde_json::json!({}))
    }
}

fn write_json(path: &Path, value: &serde_json::Value) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let formatted = serde_json::to_string_pretty(value)?;
    fs::write(path, formatted)?;
    Ok(())
}

fn ensure_json_object<'a>(
    root: &'a mut serde_json::Value,
    path: &[&str],
) -> anyhow::Result<&'a mut serde_json::Map<String, serde_json::Value>> {
    let mut current = root;
    for key in path {
        let obj = current
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("{} is not an object", key))?;
        current = obj
            .entry((*key).to_string())
            .or_insert_with(|| serde_json::json!({}));
    }
    current
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not an object", path.join(".")))
}

fn ensure_json_array<'a>(
    root: &'a mut serde_json::Value,
    path: &[&str],
) -> anyhow::Result<&'a mut Vec<serde_json::Value>> {
    if path.is_empty() {
        anyhow::bail!("path cannot be empty");
    }

    let (parents, last) = path.split_at(path.len() - 1);
    let current = ensure_json_object(root, parents)?;
    let entry = current
        .entry(last[0].to_string())
        .or_insert_with(|| serde_json::json!([]));
    entry
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not an array", path.join(".")))
}

fn json_hooks_installed(entries: &[serde_json::Value], marker: &str) -> bool {
    entries.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|hooks| hooks.as_array())
            .map(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(|command| command.as_str())
                        .map(|command| command.contains(marker))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    })
}

fn settings_path(global: bool, dir: &str, file: &str) -> anyhow::Result<PathBuf> {
    if global {
        Ok(dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("no home directory"))?
            .join(dir)
            .join(file))
    } else {
        Ok(PathBuf::from(dir).join(file))
    }
}

fn scope_label(global: bool) -> &'static str {
    if global {
        "global"
    } else {
        "project"
    }
}

fn current_bin() -> String {
    std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("secguard"))
        .to_string_lossy()
        .into_owned()
}

fn codex_hooks_enabled(config: &str) -> Option<bool> {
    let mut in_features = false;

    for raw_line in config.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            in_features = line == "[features]";
            continue;
        }

        if in_features && line.starts_with("codex_hooks") {
            let (_, value) = line.split_once('=')?;
            return match value.trim() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            };
        }
    }

    None
}

fn maybe_offer_model_download() -> anyhow::Result<()> {
    use std::io::IsTerminal;

    let model_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".secguard")
        .join("models")
        .join("secguard-guard.gguf");
    if !model_path.exists() {
        if !std::io::stdin().is_terminal() {
            eprintln!();
            eprintln!("ML model not found. Run `secguard model` to download secguard-guard.gguf (~774MB).");
            return Ok(());
        }
        eprintln!();
        eprintln!("ML model not found. Download secguard-guard.gguf (~774MB)?");
        eprintln!("This enables L3 (ML) destructive command detection.");
        eprint!("Download now? [Y/n] ");
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_ok() {
            let answer = answer.trim().to_lowercase();
            if answer.is_empty() || answer == "y" || answer == "yes" {
                crate::cmd_model::run(None, crate::cmd_model::ModelTarget::Guard)?;
            } else {
                eprintln!("Skipped. Run `secguard model` later to download.");
            }
        }
    }

    Ok(())
}
