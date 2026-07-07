//! RAN-413 G0.2 — criterion benchmark: matcher lookup on 1000 rules.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secguard_guard::matcher::{evaluate, ListRule, ListRuleSpec};

fn build_1000() -> Vec<ListRule> {
    let mut rules = Vec::with_capacity(1000);
    for i in 0..250 {
        rules.push(
            ListRule::try_from(ListRuleSpec {
                id: format!("lit-{i}"),
                kind: "literal".into(),
                pattern: format!("literal-cmd-{i}"),
                reason: None,
            })
            .unwrap(),
        );
        rules.push(
            ListRule::try_from(ListRuleSpec {
                id: format!("glob-{i}"),
                kind: "glob".into(),
                pattern: format!("glob-{i}-*"),
                reason: None,
            })
            .unwrap(),
        );
        rules.push(
            ListRule::try_from(ListRuleSpec {
                id: format!("re-{i}"),
                kind: "regex".into(),
                pattern: format!("^re-cmd-{i}$"),
                reason: None,
            })
            .unwrap(),
        );
        rules.push(
            ListRule::try_from(ListRuleSpec {
                id: format!("cp-{i}"),
                kind: "command_prefix".into(),
                pattern: format!("cp-cmd-{i}"),
                reason: None,
            })
            .unwrap(),
        );
    }
    rules
}

fn bench_evaluate_worst_case(c: &mut Criterion) {
    let blacklist = build_1000();
    let whitelist: Vec<ListRule> = vec![];
    let command = "this-command-matches-nothing-in-the-list";
    c.bench_function("evaluate worst case 1000 rules", |b| {
        b.iter(|| {
            let _ = evaluate(
                black_box(command),
                black_box(&blacklist),
                black_box(&whitelist),
            );
        })
    });
}

criterion_group!(benches, bench_evaluate_worst_case);
criterion_main!(benches);
