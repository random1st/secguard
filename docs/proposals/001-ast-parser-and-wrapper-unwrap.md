# Proposal 001: AST parsing + wrapper unwrap (structural FN/FP fix)

**Status:** **Implemented** in commit landing 2026-05-06. Parser choice: tree-sitter-bash (the only maintained Rust-accessible option; conch-parser abandoned, custom = greenfield CVE risk per tribunal-1).
**Authors:** @random1st
**Result:**
- `crates/secguard-guard/src/ast.rs` — tree-sitter-bash parser, span classifier, wrapper unwrap (sudo/doas/env/command/builtin/exec/bash-c/sh-c/zsh-c/eval/timeout/nohup/time/nice/ionice/setsid/flock/ssh/chroot/xargs/parallel/watch/find -delete/find -exec/busybox), cwd-tracking, pipeline pipe-to-shell shape detection with literal upstream re-parse.
- `crates/secguard-guard/src/rules.rs` — 35 predicate rules over `EffectiveCommand`. No more shell-words boilerplate per rule.
- `crates/secguard-guard/src/heuristic.rs` — shrunk from 2263 → 825 LOC; thin wrapper around the new pipeline, kept full integration test suite.
- `crates/secguard-guard/src/rm.rs` — shrunk from 818 → 220 LOC; thin wrapper too.
- `crates/secguard-guard/src/lib.rs::check_detailed` — pipeline now: policy → ast::parse → rules::classify → asymmetric fail-open → ML brain.
- Fixture baseline: 149/155 → **153/155 (98.7%)**, default-rule FP=0 (was 5).
- Tests: 198 unit (was 162) + 1 fixture_runner + 45 cli e2e + 21 secrets.

The 2 remaining mismatches both need runtime data we don't get: cwd from hook input (`cwd_is_home_rm_dot`) and semantic SSH remote-cmd analysis (`gcloud_compute_ssh_destructive`).

Tribunal-355 caught 5 verified bypasses on the first pass (REJECT CRITICAL): command substitution skipped, wrapper flag-with-value not consumed, relative cd left stale state, eval dynamic missed, doctest broken. All addressed in the same commit with regression tests.

## Problem

Текущая guard-логика — substring-match по строке (`crates/secguard-guard/src/heuristic.rs`, `policy.rs`). Это значит две structural дыры:

**FP (heredoc):**
```bash
cat <<'EOF'
rm -rf /
EOF
```
Мы зафлажим как destructive, но это литерал в heredoc-body, не выполняется.

**FN (wrappers):**
```bash
eval "$RM_CMD"                    # FN — мы не знаем что внутри $RM_CMD
bash -c 'rm -rf /'                # ловим случайно по substring "rm -rf"
xargs rm -rf                      # FN если target — placeholder
find / -delete                    # ловим по "-delete" substring
find / -exec rm {} \;             # FN — exec не парсим
ssh prod-host "rm -rf /var"       # FN
sudo rm -rf /                     # ловим случайно
```

**FN (compound через subshells):**
```bash
$(rm -rf /)                       # split на ; не работает, $() не покрыт
`rm -rf /`                        # backticks не покрыты
echo "$(rm -rf /)"                # nested
<(rm -rf /)                       # process substitution
```

Tribunal (Codex HIGH, Gemini MEDIUM) единогласно: **AST + wrapper unwrap — реальный security multiplier**.

## Pre-decision: какой Rust shell parser

Это **отдельный S5D**, который должен пройти **до** имплементации. Без него выбор подхода будет случайным.

### Варианты

| # | Опция | Плюсы | Минусы | Risk |
|---|---|---|---|---|
| 1 | `conch-parser` crate | Единственный реальный POSIX-parser в Rust | Последний релиз 2018, POSIX-only, без bash extensions, неподдерживается | HIGH — пропустит heredoc/process-sub/many bashisms |
| 2 | Минимальный свой parser на nom/winnow | Full control, узкое покрытие под наши нужды | Писать с нуля, parser-bugs sneak as security vulnerabilities | HIGH — long-term maintenance burden |
| 3 | Go-сайдкар с `mvdan/sh` | Mature parser, full bash support | Ломает «один Rust binary», +overhead на IPC, deploy complexity | MEDIUM — operational, не security |
| 4 | `bash -n` как pre-filter | Реальный bash, бесплатно | Только syntax-check, без spans/operands/wrappers — недостаточно | LOW — но недостаточно для задачи |
| 5 | `tree-sitter-bash` через `tree-sitter` crate | Mature, Rust-native, used by ed/zed/helix, обновляется | Tree-sitter не shell-aware (no execution semantics), heredoc handling has known issues (#282/#283) | MEDIUM |

### Гибридный подход (моя рекомендация)

**Phase 1 — quick-reject + token-level (без full AST):**
- `shell-words` для токенизации
- Token-walk для wrapper unwrap (sudo, bash -c с literal arg, eval с literal arg, xargs)
- Heredoc detection через примитивный matcher (`<<EOF`, `<<-EOF`, `<<'EOF'` → skip body до closing tag)
- Process substitution `$(...)` и backticks через regex-extract + recursive parse

Это закрывает 80% случаев без зависимости от шаткого парсера.

**Phase 2 — only if Phase 1 fixture-rate < 90%:**
- Tree-sitter-bash как опциональный feature flag
- Asymmetric fail-open ловит случаи где парсер ломается

**Why hybrid:** избегаем dead-end (#1 conch-parser) и over-investment (#2 свой parser). Tree-sitter — реальный fallback если token-level недостаточно.

## Decision needed before code

1. ❓ Phase 1 token-level vs Phase 2 tree-sitter — стартуем с какого?
2. ❓ Если token-level не хватит — tree-sitter feature flag или Go-сайдкар?
3. ❓ Какой fixture pass-rate threshold считаем acceptance (80%? 90%? 95%)?

## Implementation plan (after decision)

### 1. Parser/span abstraction

```rust
// crates/secguard-guard/src/parser.rs
pub struct ParsedCommand {
    pub argv: Vec<String>,
    pub span: SpanKind,
    pub via_wrapper: Option<WrapperKind>,
    pub remote: bool,
    pub chrooted: bool,
}

pub enum SpanKind {
    Executed,       // top-level CallExpr, pipe stages, $()
    Data,           // quoted strings, assignment RHS
    HeredocBody,    // heredoc body — rules don't apply
    InlineCode,     // other contexts
}

pub enum WrapperKind {
    Sudo, Doas, Env, Command, Builtin, Exec,
    BashC, ShC, ZshC,
    Eval,
    Xargs, Parallel, Watch,
    FindExec, FindDelete,
    Ssh, Chroot,
    Timeout, Nohup, Time, Nice, Ionice, Setsid, Flock,
}

pub fn parse(cmd: &str) -> Vec<ParsedCommand>;
```

### 2. Wrapper unwrap pass — minimum coverage

| Wrapper | Unwrap behavior |
|---|---|
| `sudo`, `doas`, `env FOO=1`, `command`, `builtin`, `exec` | Skip wrapper + flags, unwrap inner command |
| `bash -c "..."`, `sh -c`, `zsh -c` | Re-parse argument as bash, recursive unwrap |
| `eval "..."` | Re-parse if literal; if `$VAR` or non-literal → ask `eval_dynamic` |
| `xargs <cmd>`, `parallel <cmd>`, `watch <cmd>` | Mark `StdinArgs=true`, ask if cmd is destructive trigger |
| `find ... -exec <cmd> {} \;` | Synthesize virtual cmd with search roots as args |
| `find ... -delete` | Synthesize virtual `rm -rf` |
| `ssh host "..."` | Re-parse argument; mark `Remote=true` (local safe-paths don't apply) |
| `chroot /path "..."` | Re-parse; mark `Chrooted=true` |
| `timeout`, `nohup`, `time`, `nice`, `ionice`, `setsid`, `flock` | Skip wrapper + flags, unwrap inner |

### 3. Asymmetric fail-open

```rust
// pseudocode
let trigger_keywords = compile_regex(r"\b(rm|unlink|rmdir|shred|drop|truncate|delete|...)\b");

if !trigger_keywords.is_match(cmd) {
    return Verdict::Safe;  // quick-reject, no parsing needed
}

match parse(cmd) {
    Ok(parsed) => evaluate_rules(parsed),
    Err(parse_err) => {
        // asymmetric fail-open
        if parse_err.position < trigger_keyword_position {
            Verdict::Safe  // parse failed before trigger, agent's bash is malformed anyway
        } else {
            Verdict::Destructive {
                reason: format!("parse error after trigger keyword: {parse_err}"),
                rule_id: RuleId::ParseErrorAfterTrigger,
            }
        }
    }
}
```

### 4. Pipe-to-shell literal re-parse

```bash
echo "rm -rf /" | bash      # → re-parse "rm -rf /" as bash, evaluate
echo "$VAR" | bash           # → ask, dynamic upstream
grep ... | bash              # → ask, non-literal upstream
cat script.sh | bash         # → ask, file content unknown
curl https://... | bash      # already caught by existing rule
```

Pipeline detection:
- Parse pipeline stages
- If last stage is `bash`/`sh`/`zsh` без `-c`:
  - All upstream literal stages → re-parse as bash
  - Any non-literal upstream → `ask` with reason `pipe_to_shell_dynamic`

## Acceptance criteria

- [ ] S5D decision recorded в этом файле (Phase 1 approach + threshold)
- [ ] `crates/secguard-guard/src/parser.rs` с `ParsedCommand`, `SpanKind`, `WrapperKind`
- [ ] **Heredoc test** (FP fix):
  ```rust
  let cmd = "cat <<'EOF'\nrm -rf /\nEOF";
  assert_eq!(check(cmd), Verdict::Safe);  // span = HeredocBody
  ```
- [ ] **Wrapper test cases** (все Destructive):
  - [ ] `sudo rm -rf /`
  - [ ] `bash -c 'rm -rf /etc'`
  - [ ] `eval 'rm -rf /'`
  - [ ] `xargs rm -rf`
  - [ ] `find / -delete`
  - [ ] `find / -exec rm {} \;`
  - [ ] `ssh prod-host 'rm -rf /var'`
  - [ ] `timeout 10 bash -c "rm -rf /"`
  - [ ] `nohup nice rm -rf /etc`
- [ ] **Asymmetric fail-open**: malformed bash без trigger → Safe; с `rm` → Destructive
- [ ] **Pipe-to-shell**: `echo "rm -rf /" | bash` → Destructive
- [ ] bash-guard fixtures pass-rate ≥ threshold (TBD после S5D)
- [ ] Все 22 существующих теста в `heuristic.rs` продолжают проходить

## Decomposition (sub-issues когда Linear лимит снимется)

1. Parser abstraction + token-level + heredoc detection
2. Wrapper unwrap pass (минимум: sudo, bash -c, eval, xargs, find, ssh, timeout)
3. Asymmetric fail-open + quick-reject regex
4. Pipe-to-shell re-parse
5. (optional Phase 2) tree-sitter-bash feature flag

## References

- Tribunal output 2026-05-04: Codex (HIGH) + Gemini (MEDIUM), оба сошлись на AST как foundation
- bash-guard `src/parser.go` + `src/unwrap.go` — референс реализации (MIT, attribution required)
- bash-guard `DESIGN.md` секции:
  - "Span Classification: Four Categories"
  - "Unwrap Handling: Executor Wrappers"
  - "Fail-Open Semantics: Asymmetric Design"
  - "Pipeline-to-Shell Evaluators"
- Текущий код:
  - `crates/secguard-guard/src/heuristic.rs` (substring-based)
  - `crates/secguard-guard/src/policy.rs:17` (string-split на &&/||/;/|)
  - `crates/secguard-guard/src/lib.rs:53` (3-phase entry point)

## Open questions

1. Tree-sitter-bash в production? Зависимость на C-runtime (tree-sitter), увеличивает binary size. Acceptable?
2. Process substitution `<(cmd)` и `>(cmd)` — Phase 1 или Phase 2?
3. ZSH-specific syntax (e.g. `=(...)`, `==~`) — не поддерживаем или ask?
4. Whether to backport AST changes into Phase 1 (`heuristic.rs`) or build parallel pipeline (`crates/secguard-guard/src/v2/`) and switch via feature flag?
