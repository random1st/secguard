# secguard

3-level security guard for AI coding agents. Catches leaked credentials and blocks destructive shell commands before they execute.

Built for [Claude Code](https://claude.ai/code), Gemini CLI, and Codex workflows. Also works anywhere: CI pipelines, git pre-commit, standalone CLI.

## What it does

Two guards, three levels of detection each.

**Secrets scanning.** Catches credentials before they leak into logs, tool output, or cloud APIs. 150+ regex patterns: AWS access keys (`AKIA*`), Stripe (`sk_live_*`, `pk_live_*`), GitHub PATs (`ghp_*`, `github_pat_*`), Anthropic/OpenAI API keys, Slack tokens, JWTs, private key blocks, database connection strings (postgres, mysql, mongodb, redis), SendGrid, Twilio, npm/PyPI tokens, generic `password=`/`secret=` assignments. Keyword pre-filter skips regex when no relevant substring exists (fast on large inputs). High-entropy token detection (Shannon entropy >= 3.5 bits/char, 16+ chars) picks up things regex misses. Optional ML classifier as final pass.

**Destructive command guard.** Blocks commands that delete data, rewrite history, or bypass safety checks. Three phases run in order; first match wins:

*Phase 0: Policy allowlist.* Some operations are always safe. Configured process cleanup (`pkill`/`killall` targets from `safe_kill_targets`), `git push` without `--force`, and read-only kubectl (`get`, `describe`, `logs`) can pass here. Compound commands (`&&`, `||`, `;`, `|`) are split and every part must pass independently.

*Phase 1: Heuristic rules.* 40+ patterns, zero latency:
- Git: `checkout .`, `clean`, `reset --hard`, `push --force`, `branch -D`, `rebase`, `stash drop/clear`
- Filesystem: `rm -rf` (with configurable safe paths for build dirs), `rm -r`, `find -delete`, `shred`
- SQL: `DROP TABLE`, `DROP DATABASE`, `TRUNCATE` (including commands run via database CLIs such as `psql`)
- Docker: `system prune`, `volume prune`
- Remote exec: `curl | bash`, `wget | sh`
- Hook bypass: `--no-verify`
- HTTP DELETE to non-localhost URLs (curl, httpie)
- SaaS CLIs (22 tools: aws, gcloud, stripe, firebase, vercel, netlify, heroku, fly, supabase, planetscale, etc.) with destructive subcommands (`delete`, `remove`, `destroy`, `purge`, `terminate`)
- GitHub CLI: only truly destructive ops (`gh repo delete`, `gh release delete`); `gh pr close` passes through

`rm -rf build`, `rm -rf node_modules`, `rm -rf target/debug` are safe by default. Configurable via `GuardConfig`.

*Phase 2: ML brain.* Qwen3.5-0.8B Q8 GGUF (~800 MB, fine-tuned LoRA on 21K labeled commands) classifies commands the heuristics don't cover. 85% confidence threshold. Optional; falls back to heuristic-only when absent.

## How to use it

Seven modes, same codebase.

**Claude Code hook** (`secguard init --global`). Registers as a PreToolUse hook. Guard checks every Bash command before execution; secrets-scan redacts credentials from Bash/Edit/Write/Agent/MCP tool input. Blocked commands get `permissionDecision: "ask"` so the user sees the warning and decides.

**Gemini CLI hook** (`secguard init gemini --global`). Registers `BeforeTool` hooks in `~/.gemini/settings.json`. Guard checks `run_shell_command` before execution; secrets-scan redacts credentials from all tool input using the same hook runtime.

**Codex hook** (`secguard init codex --global`). Registers `PreToolUse` hook in `~/.codex/hooks.json`. Uses `permissionDecision: "deny"` + `systemMessage` (Codex ignores `"ask"`). Secrets-scan is disabled for Codex because its PreToolUse contract doesn't support input rewriting.

**HTTP server** (`secguard-server --port 8080`). Axum-based service exposing `POST /hook/guard` and `POST /hook/secrets-scan` with Claude Code HTTP hooks compatibility. Bearer token auth via `SECGUARD_TOKEN`. Prometheus metrics at `/metrics`. Health probes at `/healthz` and `/readyz`. Deploy as Docker image or Helm chart for team-wide protection.

**Standalone CLI.** Pipe a command into `secguard guard`, pipe text into `secguard scan`. Exit code 0 = safe, 1 = problem found. Works in scripts, Makefiles, anywhere.

**Git pre-commit.** Run `secguard scan --dir .` in a pre-commit hook. Catches credentials before they reach the repo.

**CI/CD.** Same `secguard scan --dir ./src --format json` in your pipeline. JSON output includes file, line number, rule ID. Non-zero exit fails the build.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/diana-random1st/secguard/main/install.sh | sh
```

Detects OS/arch, downloads the right binary, verifies it against `checksums-sha256.txt`, then installs to `/usr/local/bin`.

Or manually pick your platform:

```bash
# macOS Apple Silicon
curl -sL https://github.com/diana-random1st/secguard/releases/latest/download/secguard-aarch64-apple-darwin.tar.gz | tar xz
sudo mv secguard /usr/local/bin/

# macOS Intel
curl -sL https://github.com/diana-random1st/secguard/releases/latest/download/secguard-x86_64-apple-darwin.tar.gz | tar xz
sudo mv secguard /usr/local/bin/

# Linux x64
curl -sL https://github.com/diana-random1st/secguard/releases/latest/download/secguard-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv secguard /usr/local/bin/
```

From source:

```bash
cargo install --path crates/secguard-cli
```

## Setup for Claude Code

```bash
secguard init --global
```

Writes two PreToolUse hooks to `~/.claude/settings.json`:
- **guard** on Bash — checks commands before execution
- **secrets-scan** on Bash/Edit/Write/Agent/MCP — redacts credentials from tool input

If the ML model isn't installed, `init` will offer to download it.

Project-level install (without `--global`) writes to `.claude/settings.json` in the current directory.

## Setup for Gemini CLI

```bash
secguard init gemini --global
```

Writes two `BeforeTool` hooks to `~/.gemini/settings.json`:
- **guard** on `run_shell_command` — checks commands before execution
- **secrets-scan** on `.*` — redacts credentials from tool input

Project-level install (without `--global`) writes to `.gemini/settings.json` in the current directory.

The hook runtime understands both Claude Code `PreToolUse` payloads and Gemini `BeforeTool` payloads.

## Setup for Codex

```bash
secguard init codex --global
```

Checks `~/.codex/config.toml` for:
- **hooks support** — expects `[features] codex_hooks = true`

Then writes one `PreToolUse` hook to `~/.codex/hooks.json`:
- **guard** on Bash — checks commands before execution

Secrets-scan is intentionally not installed for Codex because the current `PreToolUse` hook contract can block tool calls but cannot rewrite tool input.

If hook support is not enabled in `config.toml`, `secguard` prints a warning but still writes the hook file.

Project-level install (without `--global`) writes to `.codex/hooks.json` in the current directory and checks `.codex/config.toml` in the same directory.

## ML models (optional)

```bash
secguard model
```

Downloads `secguard-guard.gguf` (~800 MB, Qwen3.5-0.8B fine-tuned, Q8 GGUF) from [HuggingFace](https://huggingface.co/random1st/secguard-models) to `~/.secguard/models/`. The guard works fine without it; the model catches edge cases that heuristics don't cover.

OpenAI Privacy Filter can be installed as a separate local bundle:

```bash
secguard model --model privacy-filter
```

This downloads the q4 ONNX bundle from [openai/privacy-filter](https://huggingface.co/openai/privacy-filter) to `~/.secguard/models/openai-privacy-filter/`. It is a PII token-classification model for external local redaction runtimes; the current Rust secrets scanner does not automatically execute this model.

## Self-update

```bash
secguard update              # check GitHub Releases; verify checksum; atomically replace if newer
secguard update --check-only # print status, don't touch the binary
```

The hook path also runs a throttled (once per 7 days) detached check in the background and, on subsequent invocations, prints a single stderr line if a newer release is available. The marker lives at `~/.secguard/.update-available`. Nothing is downloaded or replaced without an explicit `secguard update`.

## HTTP server & k8s deployment

```bash
# Local Docker (multi-arch image — linux/amd64, linux/arm64)
docker run -p 8080:8080 -e SECGUARD_TOKEN=your-token \
  ghcr.io/diana-random1st/secguard:latest

# Kubernetes (Helm OCI registry)
helm install secguard \
  oci://ghcr.io/diana-random1st/charts/secguard \
  --version 0.4.0 \
  --set auth.token=your-token \
  --set target=claude

# Or pin to a specific image tag and install from local checkout:
helm install secguard ./deploy/helm/secguard \
  --set image.tag=0.4.0 \
  --set auth.token=your-token \
  --set target=claude
```

Image tags follow semver: `0.4.0` (exact), `0.4` (latest patch in minor), `latest` (most recent release). The OCI Helm registry mirrors the same scheme. Both are published by `release.yml` on every `v*` tag.

Then point Claude Code HTTP hooks to it:

```json
{
  "type": "http",
  "url": "http://secguard:8080/hook/guard",
  "timeout": 30,
  "headers": {"Authorization": "Bearer $SECGUARD_TOKEN"}
}
```

The Helm chart requires bearer auth by default. For trusted local/dev clusters only, set `--set auth.required=false`.

Endpoints:
- `POST /hook/guard` — destructive command check
- `POST /hook/secrets-scan` — credential redaction (Claude/Gemini; Codex block-only)
- `GET /healthz`, `/readyz` — k8s probes
- `GET /metrics` — Prometheus counters + latency histograms

## Telemetry

Every hook invocation writes a JSONL line to `~/.secguard/telemetry.jsonl`. Guard command text is redacted with the secrets scanner and truncated before it is written:

```json
{"ts":"2026-04-19T07:00:00Z","mode":"guard","tool_name":"Bash","command":"rm -rf /","verdict":"destructive","verdict_source":"heuristic","reason":"rm -rf (recursive force delete)","rule_id":"rm.rf","latency_us":42,"target":"claude"}
```

Each event includes a machine-readable `rule_id` (e.g. `git.force_push`, `rm.rf`, `infra.aws_s3_rm`) so you can group false positives/negatives without parsing the human-readable `reason`.

Disable with `SECGUARD_TELEMETRY=off`. Useful for false-positive analysis and training data collection.

## Shadow mode

Set `SECGUARD_SHADOW=1` to put the Bash guard into observe-only mode. The guard still classifies every command and logs what it *would* have decided, but it never blocks — every command is allowed through.

```bash
export SECGUARD_SHADOW=1
# Now every Claude/Gemini/Codex Bash invocation is permitted; telemetry
# records the would-be decision so you can audit before promoting.
```

Telemetry events emitted while shadow mode is on carry two extra fields:

```json
{"...":"...","would_decide":"ask","shadow":true}
```

Use this to roll out new rules safely: enable shadow, run a workload, inspect `~/.secguard/telemetry.jsonl` for `"would_decide":"ask"` entries, then unset `SECGUARD_SHADOW` to enforce.

Recognised off values: `0`, `off`, `false`, empty, unset. Anything else (`1`, `true`, `yes`, etc.) turns shadow on.

**Scope.** Shadow mode is honoured by the `secguard` CLI's hook handler (Claude Code, Gemini CLI, Codex CLI integrations). The `secguard-server` HTTP variant ignores it: server deployments are typically central choke points where opaque fail-open is undesirable. If you need observe-only behavior in the server, scope it per-deployment via reverse proxy or a dedicated route.

## Standalone usage

```bash
# Check a command
echo "rm -rf /" | secguard guard
# exit 1: DESTRUCTIVE: rm -rf (recursive force delete)

echo "cargo test --all" | secguard guard
# exit 0: safe

# Scan for secrets
cat .env | secguard scan

# Scan a directory
secguard scan --dir ./src

# JSON output
secguard scan --dir ./src --format json
```

## Architecture

```
secguard-brain     GGUF inference engine (llama.cpp, optional Metal GPU)
secguard-secrets   150+ regex patterns + entropy detection + ML fallback
secguard-guard     policy allowlist + 40 heuristic rules + ML classifier
secguard-cli       CLI binary, Claude Code / Codex / Gemini hook protocols
secguard-server    axum HTTP server with Prometheus metrics + bearer auth
```

Default build (`cargo install secguard-cli`) includes L1 (regex) and L2 (heuristic) only. Zero native dependencies.

For ML support: `cargo install secguard-cli --features ml,metal`

## Feature flags

| Flag | What it adds |
|------|-------------|
| `ml` | GGUF brain classifier for secrets + guard |
| `metal` | Apple Silicon GPU acceleration for inference |

## Author

Built by [@random1st](https://t.me/toxic_ai_random1st) — Telegram channel about AI agents, local models, and building tools that actually work.

## License

Apache 2.0 + Commons Clause — free to use, modify, fork; not for resale as a product or service.
