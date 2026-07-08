#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum HookTarget {
    Claude,
    Codex,
    Gemini,
}

pub fn incoming_hook_event_name(v: &serde_json::Value) -> String {
    v.get("hook_event_name")
        .or_else(|| v.get("hookEventName"))
        .and_then(|value| value.as_str())
        .unwrap_or("PreToolUse")
        .to_string()
}

pub fn guard_block(target: HookTarget, hook_event_name: &str, reason: &str) -> serde_json::Value {
    match target {
        HookTarget::Codex => serde_json::json!({
            "decision": "deny",
            "reason": reason,
            "systemMessage": reason,
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        }),
        _ => serde_json::json!({
            "decision": "ask",
            "reason": reason,
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "permissionDecision": "ask",
                "permissionDecisionReason": reason
            }
        }),
    }
}

pub fn secrets_redacted(
    target: HookTarget,
    hook_event_name: &str,
    context: &str,
    updated_input: serde_json::Value,
) -> serde_json::Value {
    match target {
        HookTarget::Codex => serde_json::json!({
            "decision": "allow",
            "reason": context,
            "systemMessage": context,
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "permissionDecision": "allow",
                "permissionDecisionReason": context,
                "updatedInput": updated_input,
                "additionalContext": context
            }
        }),
        _ => serde_json::json!({
            "decision": "allow",
            "reason": context,
            "hookSpecificOutput": {
                "hookEventName": hook_event_name,
                "permissionDecision": "allow",
                "permissionDecisionReason": context,
                "updatedInput": updated_input,
                "additionalContext": context
            }
        }),
    }
}

pub fn text_to_check(tool_name: &str, value: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Bash" => extract_command(value),
        "run_shell_command" | "shell" => extract_command(value),
        name if name.starts_with("mcp__") => {
            let tool_input = value
                .get("tool_input")
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .unwrap_or_default();
            Some(format!("{name} {tool_input}"))
        }
        other if other.to_ascii_lowercase().contains("shell") => extract_command(value),
        _ => None,
    }
}

fn extract_command(value: &serde_json::Value) -> Option<String> {
    value
        .get("tool_input")
        .and_then(|v| v.get("command").or_else(|| v.get("cmd")))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}
