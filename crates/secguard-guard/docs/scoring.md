# Blast-radius × reversibility scoring (RAN-414)

The guard replaces a binary *block / allow* decision with a 2D score per
rule. `rm -rf ./build/tmp` is not `rm -rf /` — scoring lets the guard say
*allow*, *warn*, *confirm*, or *block* instead of one blunt block, removing
false positives and giving later features (auto-stash, Trash redirect,
prompt-confirm) a place to hook in.

## The two axes

Each rule declares a `Decision { blast, reversibility }` via
[`RuleId::score`](../src/rule_id.rs). Both axes are `0..=4`.

| value | `blast` (scope of damage) | `reversibility` (how recoverable) |
|------:|---------------------------|-----------------------------------|
| 0 | local file / cwd artifact | permanent, unrecoverable |
| 1 | local repo / project state | hard — backup or manual recovery |
| 2 | local machine / global state | moderate effort |
| 3 | single remote / cloud resource | easy rollback |
| 4 | multi-tenant / shared infra | instant undo |

## The default policy matrix

`default_action_for(Decision)` maps a score to an
`Action ∈ {Allow, Warn, Confirm, Block}` via
`risk = blast + (4 - reversibility)`, bucketed:

- `risk ≤ 1` → **Allow**
- `risk 2..=3` → **Warn**
- `risk 4..=5` → **Confirm**
- `risk ≥ 6` → **Block**

|            | rev 0 | rev 1 | rev 2 | rev 3 | rev 4 |
|-----------:|:-----:|:-----:|:-----:|:-----:|:-----:|
| **blast 0** | Confirm | Warn | Warn | Allow | Allow |
| **blast 1** | Confirm | Confirm | Warn | Warn | Allow |
| **blast 2** | Block | Confirm | Confirm | Warn | Warn |
| **blast 3** | Block | Block | Confirm | Confirm | Warn |
| **blast 4** | Block | Block | Block | Confirm | Confirm |

The construction is **monotone on both axes**: raising `blast` never lowers
severity, and raising `reversibility` never raises it. This invariant is
enforced by a proptest in [`src/scoring.rs`](../src/scoring.rs).

## Per-rule calibration

Scores live in [`RuleId::score`](../src/rule_id.rs). Highlights:

| rule | (blast, rev) | default action | rationale |
|------|:------------:|:--------------:|-----------|
| `RmRf` | (3, 0) | Block | catastrophic path (rm.rs only emits for non-safe targets) |
| `SqlDestructive`, `RedisDestructive`, `MongoDestructive`, `SupabaseDbMutation` | (4, 0) | Block | data loss, frequently prod, no assumed backup |
| `SaasDestroy`, `AwsS3Rm`, `GsutilMutation` | (3, 0) | Block | remote resource destroy, permanent |
| `PipeToShell` | (3, 1) | Block | arbitrary remote code execution |
| `GitHistoryRewrite` | (3, 1) | Block | rewrites shared history |
| `HelmMutation`, `KubectlMutation` | (3, 2) | Confirm | rollback / re-apply exists |
| `GitForcePush` | (3, 2) | Confirm | wide but recoverable on the remote |
| `OrmMigration` | (2, 2) | **Confirm** | up/down migrations — was a hard block under the binary model; the headline false-positive reducer |
| `GitResetHard`, `GitResetMerge` | (1, 2) | Warn | reflog recovery |
| `UnsafeKill` | (2, 3) | Warn | process restartable |
| `NoVerify` | (1, 3) | Warn | skips hooks; the commit itself is recoverable |

## Config override

The default matrix is overridable per cell through the `[scoring]` section of
`~/.config/secguard/config.toml` (or a project `.secguard.toml`). Overrides
are a sparse table — only listed cells change; the rest fall through to the
default matrix. The most specific config layer **replaces** the table
wholesale (it is policy, not an accumulating list).

```toml
# Downgrade "single remote resource, permanent" from Block to Warn.
[[scoring.override]]
blast = 3
reversibility = 0
action = "warn"   # one of: allow | warn | confirm | block
```

## Compile-time guarantee

`RuleId::score` is an exhaustive `match` with **no wildcard arm**. Adding a
`RuleId` variant without a score arm is a compile error (`E0004`,
non-exhaustive patterns) — there is no runtime fallback that could silently
forget a rule's score. The compiler is the test: the type system enforces the
"every rule must declare a score" invariant directly, so no separate test is
needed (or able) to pin it.

The one way to defeat this is to add a `_ => …` wildcard arm to
`RuleId::score`. No automated test can catch that — a wildcard compiles
cleanly — so **reviewers must reject any wildcard arm in `score()`**. (An
earlier `trybuild` fixture was removed: it only proved that `rustc` rejects a
non-exhaustive match on an unrelated demo enum, not that `score()` itself
stays wildcard-free, and its committed `.stderr` was rustc-version-brittle.)

## Surfacing

`check_detailed` exposes the resolved `Action` on `VerdictDetail.action`. The
verdict → action mapping is centralized in `VerdictDetail::new`: safe verdicts
are always `Allow`; destructive verdicts with a `rule_id` are scored through
the config matrix; destructive verdicts without a `rule_id` (explicit config
denies, asymmetric parse-error fail-open) are fail-safe `Block`. Acting on
`Warn` / `Confirm` (auto-stash, Trash redirect, prompt-confirm) is deferred
future work — today the CLI hook still branches on `Verdict::Destructive`.
