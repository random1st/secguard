# diana-guard

Runtime security guard for Diana's hook pipeline. Provides:

- **Destructive-command guard** — blocks or asks before rm -rf, cloud destructive ops, DB drops, etc.
- **Secrets scan** — regex-based credential detection on tool inputs (PreToolUse)
- **PostToolUse output redaction** — redacts credentials from tool *responses* before they reach the agent context window

Exposed through `diana dev hook guard`, `diana dev hook secrets-scan`, and `diana dev hook post-use`.

---

## Configuration

User config: `~/.config/secguard/config.toml`  
Project config: `.secguard.toml` (discovered upward from CWD)  
Env override: `SECGUARD_CONFIG=<path>`

Layers merge in order: built-in defaults → user config → project config. Later layers win.

---

## `[postuse]` — PostToolUse output redaction

Activated by the `diana dev hook post-use` hook, registered on the **PostToolUse** phase (Claude), **AfterTool** (Gemini), and **PostToolUse** (Codex).

The hook reads `tool_response` from stdin, redacts any detected credentials in-place across all string leaves, and emits `updatedOutput` JSON so the redacted value replaces the original in the agent context window. If nothing is found, the hook exits silently (pass-through). Parse failures are fail-open: logged to stderr, payload passed through unchanged.

### Config options

```toml
[postuse]
# Set to false to disable output redaction entirely (pass-through).
# Default: true
enabled = true

# Text appended to the stderr summary line when redactions occur.
# The scanner itself always substitutes [REDACTED:<rule_id>] in the output.
# Default: "[REDACTED]"
redaction_marker = "[REDACTED]"
```

### Per-agent hook registration

The reconciler (`diana hooks install`) writes the following to each agent's settings file.

**Claude — `~/.claude/settings.json` (PostToolUse)**

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash|Read|mcp__*",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/random1st/bin/diana dev hook --target claude post-use"
          }
        ]
      }
    ]
  }
}
```

**Gemini — `~/.gemini/settings.json` (AfterTool)**

```json
{
  "hooks": {
    "AfterTool": [
      {
        "matcher": "run_shell_command|Read|mcp__*",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/random1st/bin/diana dev hook --target gemini post-use"
          }
        ]
      }
    ]
  }
}
```

**Codex — `~/.codex/hooks.json` (PostToolUse)**

Codex only honours Bash-equivalent matchers; Read and mcp__ are collapsed to Bash by the reconciler:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/random1st/bin/diana dev hook --target codex post-use"
          }
        ]
      }
    ]
  }
}
```

### Sample redaction

Input from Claude (PostToolUse for a Bash `env` command):

```json
{
  "hook_event_name": "PostToolUse",
  "tool_name": "Bash",
  "tool_response": {
    "output": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nPATH=/usr/bin"
  }
}
```

Hook output (written to stdout; Claude replaces `tool_response` with `updatedOutput`):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "updatedOutput": {
      "output": "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key]\nPATH=/usr/bin"
    }
  }
}
```

Stderr log line:

```
[diana-guard] [REDACTED] PostToolUse redacted 1 credential(s) in tool_response. Types: aws-access-key
```

---

## Matcher coverage (PostToolUse)

| Tool class    | Why included                                          |
|---------------|-------------------------------------------------------|
| `Bash`        | stdout/stderr can contain env dumps, curl responses, API keys |
| `Read`        | raw file contents (`.env`, credentials files)         |
| `mcp__*`      | MCP server responses (tokens, API payloads)           |
| `Edit/Write`  | excluded — no meaningful output to redact             |

---

## Tuning, not disabling

Per `CLAUDE.md`: never disable the guard entirely. To suppress false positives:

- Add a project-level `.secguard.toml` with `[postuse] enabled = false` to opt out for a specific repo.
- Use `SECGUARD_SHADOW=1` for dry-run mode (logs findings, does not redact).
- File a rule exception in `~/.config/secguard/config.toml` under `[[allow.secrets]]`.
