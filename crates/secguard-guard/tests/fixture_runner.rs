//! Replay the bash-guard JSON fixture corpus against secguard's current rules.
//!
//! These fixtures encode one shell command + expected decision (`allow` /
//! `ask`) + a granular `reason_code` per case. They were imported from
//! https://github.com/CodeAlive-AI/ai-driven-development (MIT, see NOTICE.md
//! in the fixtures directory).
//!
//! The test does NOT fail on individual mismatches — many fixtures cover rule
//! families secguard does not yet implement (Terraform, ORM migrations,
//! OpenSearch, Mongo, GraphQL mutations, ...). Instead it prints a baseline
//! summary per rule family and asserts only on a small set of invariants we
//! already know we pass.
//!
//! Run with:
//!     cargo test -p secguard-guard --test fixture_runner -- --nocapture
//!
//! The `--nocapture` flag is needed to see the per-rule breakdown, otherwise
//! cargo swallows stdout for passing tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    #[allow(dead_code)]
    description: String,
    input: FixtureInput,
    expect: FixtureExpect,
}

#[derive(Debug, Deserialize)]
struct FixtureInput {
    #[allow(dead_code)]
    tool_name: String,
    tool_input: FixtureToolInput,
    #[allow(dead_code)]
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureToolInput {
    command: String,
}

#[derive(Debug, Deserialize)]
struct FixtureExpect {
    decision: String,
    #[serde(default = "default_rule")]
    rule: String,
    #[serde(default)]
    #[allow(dead_code)]
    reason_code: Option<String>,
}

fn default_rule() -> String {
    "default".into()
}

#[derive(Default)]
struct RuleStats {
    total: usize,
    matched: usize,
    fp: usize,  // expected allow, we said destructive
    fn_: usize, // expected ask, we said safe
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("bash_guard_fixtures")
}

fn load_fixtures() -> Vec<(PathBuf, Fixture)> {
    let dir = fixtures_dir();
    assert!(
        dir.exists(),
        "fixtures dir missing: {} (did NOTICE.md get lost?)",
        dir.display()
    );

    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("read fixtures dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let fx: Fixture = serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        out.push((path, fx));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Map secguard's verdict onto the `allow` / `ask` decision space the
/// fixtures use. We treat `Verdict::Destructive` as `ask` regardless of
/// downstream target (Codex deny is a transport detail, not a decision).
fn our_decision(cmd: &str) -> &'static str {
    match secguard_guard::check(cmd) {
        secguard_guard::Verdict::Safe => "allow",
        secguard_guard::Verdict::Destructive(_) => "ask",
    }
}

#[test]
fn fixture_baseline_matches_known_invariants() {
    let fixtures = load_fixtures();
    assert!(
        fixtures.len() >= 100,
        "expected at least 100 fixtures, found {}",
        fixtures.len()
    );

    let mut by_rule: BTreeMap<String, RuleStats> = BTreeMap::new();
    let mut total = 0usize;
    let mut matched = 0usize;
    let mut mismatched_examples: Vec<(String, &str, &str, String)> = Vec::new();

    for (path, fx) in &fixtures {
        total += 1;
        let stats = by_rule.entry(fx.expect.rule.clone()).or_default();
        stats.total += 1;

        let actual = our_decision(&fx.input.tool_input.command);
        let expected: &str = fx.expect.decision.as_str();

        if actual == expected {
            matched += 1;
            stats.matched += 1;
        } else {
            // false positive = expected allow, we say ask
            // false negative = expected ask, we say allow
            if expected == "allow" && actual == "ask" {
                stats.fp += 1;
            } else if expected == "ask" && actual == "allow" {
                stats.fn_ += 1;
            }
            if mismatched_examples.len() < 20 {
                mismatched_examples.push((
                    fx.name.clone(),
                    expected,
                    actual,
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("?")
                        .to_string(),
                ));
            }
        }
    }

    // Print baseline summary so reviewers can track regressions vs improvements.
    eprintln!("\n--- bash-guard fixture baseline ---");
    eprintln!(
        "total: {total}, matched: {matched} ({:.1}%)",
        percent(matched, total)
    );
    eprintln!("\nby rule family:");
    for (rule, stats) in &by_rule {
        eprintln!(
            "  {rule:<12} total={:<3} matched={:<3} ({:.0}%)  FP={}  FN={}",
            stats.total,
            stats.matched,
            percent(stats.matched, stats.total),
            stats.fp,
            stats.fn_
        );
    }
    eprintln!("\nfirst {} mismatches:", mismatched_examples.len());
    for (name, expected, actual, file) in &mismatched_examples {
        eprintln!("  expected={expected} actual={actual}  {name}  ({file})");
    }
    eprintln!("--- end baseline ---\n");

    // Hard invariants — these MUST hold even though full-corpus parity is a
    // non-goal for this PR. If any of these regress, something broke.
    let force_push = by_rule.get("git").map(|s| s.matched > 0).unwrap_or(false);
    assert!(force_push, "no git fixtures matched — git rules regressed");

    let docker = by_rule.get("infra").map(|s| s.matched).unwrap_or(0);
    assert!(
        docker > 0,
        "no infra fixtures matched — at least docker_system_prune must pass"
    );

    // Forbid silent regression of total match rate below the recorded
    // baseline. Update this number in the same commit that intentionally
    // lowers it. Initial baseline measured 2026-05-05 on 155 fixtures = 97.
    // Set the floor 2 below baseline to absorb cwd/non-determinism noise
    // without permitting silent rule-coverage regressions.
    const BASELINE_MATCHED_FLOOR: usize = 95;
    assert!(
        matched >= BASELINE_MATCHED_FLOOR,
        "match rate regressed: matched={matched} < floor={BASELINE_MATCHED_FLOOR}. \
         If this is intentional, lower the floor in the same commit."
    );
}

fn percent(num: usize, denom: usize) -> f64 {
    if denom == 0 {
        0.0
    } else {
        100.0 * (num as f64) / (denom as f64)
    }
}
