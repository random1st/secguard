//! RAN-413 G0.2 — integration tests: TOML on disk → load → evaluate.

use secguard_guard::config::{build_lists, load, load_for_dir};
use secguard_guard::matcher::{evaluate, Decision};
use secguard_guard::{check_with_config, GuardConfig, Verdict};
use std::io::Write;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn write_config(text: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "{text}").unwrap();
    f.flush().unwrap();
    f
}

fn with_config<R>(path: &std::path::Path, f: impl FnOnce() -> R) -> R {
    let _guard = ENV_LOCK.lock().unwrap();
    let prev = std::env::var("SECGUARD_CONFIG").ok();
    std::env::set_var("SECGUARD_CONFIG", path);
    let result = f();
    match prev {
        Some(v) => std::env::set_var("SECGUARD_CONFIG", v),
        None => std::env::remove_var("SECGUARD_CONFIG"),
    }
    result
}

fn config_from(text: &str) -> GuardConfig {
    toml::from_str(text).expect("test config parses")
}

#[test]
fn deny_blocks_command() {
    let f = write_config(
        r#"
[[blacklist]]
id = "curl-bash"
type = "command_prefix"
pattern = "curl | bash"
reason = "remote shell exec banned"
"#,
    );
    with_config(f.path(), || {
        let cfg = load();
        let (deny, allow) = build_lists(&cfg);
        match evaluate("curl | bash payload.sh", &deny, &allow) {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, "curl-bash"),
            other => panic!("expected Deny, got {other:?}"),
        }
    });
}

#[test]
fn allow_passes_otherwise_dangerous() {
    let f = write_config(
        r#"
[[whitelist]]
id = "bun-install"
type = "literal"
pattern = "bun install"
"#,
    );
    with_config(f.path(), || {
        let cfg = load();
        let (deny, allow) = build_lists(&cfg);
        assert!(matches!(
            evaluate("bun install", &deny, &allow),
            Decision::Allow { .. }
        ));
    });
}

#[test]
fn check_with_config_applies_deny_before_policy_allowlist() {
    let cfg = config_from(
        r#"
[[blacklist]]
id = "no-gws-send"
type = "command_prefix"
pattern = "gws send-mail"
reason = "mail sends require explicit review"
"#,
    );

    match check_with_config("gws send-mail roman@example.com", &cfg) {
        Verdict::Destructive(reason) => {
            assert!(
                reason.contains("no-gws-send"),
                "reason should name deny rule: {reason}"
            );
        }
        other => panic!("expected config deny to override policy allowlist, got {other:?}"),
    }
}

#[test]
fn check_with_config_applies_allow_before_default_rules() {
    let cfg = config_from(
        r#"
[[whitelist]]
id = "allow-local-target-clean"
type = "literal"
pattern = "rm -rf target/debug"
reason = "local build cache"
"#,
    );

    assert_eq!(
        check_with_config("rm -rf target/debug", &cfg),
        Verdict::Safe
    );
}

#[test]
fn check_with_config_keeps_deny_over_allow() {
    let cfg = config_from(
        r#"
[[blacklist]]
id = "deny-rm"
type = "literal"
pattern = "rm -rf target/debug"

[[whitelist]]
id = "allow-rm"
type = "literal"
pattern = "rm -rf target/debug"
"#,
    );

    match check_with_config("rm -rf target/debug", &cfg) {
        Verdict::Destructive(reason) => {
            assert!(
                reason.contains("deny-rm"),
                "reason should name deny rule: {reason}"
            );
        }
        other => panic!("expected deny to beat allow, got {other:?}"),
    }
}

#[test]
fn reload_reflects_file_change() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        r#"
[[blacklist]]
id = "first"
type = "literal"
pattern = "drop A"
"#,
    )
    .unwrap();

    with_config(&path, || {
        let cfg = load();
        let (deny1, _) = build_lists(&cfg);
        assert_eq!(deny1.len(), 1);
        assert_eq!(deny1[0].id, "first");

        // Rewrite the file with a different rule.
        fs::write(
            &path,
            r#"
[[blacklist]]
id = "second"
type = "literal"
pattern = "drop B"
"#,
        )
        .unwrap();

        let cfg2 = load();
        let (deny2, _) = build_lists(&cfg2);
        assert_eq!(deny2.len(), 1);
        assert_eq!(
            deny2[0].id, "second",
            "load() should re-read file every call"
        );
    });
}

#[test]
fn watched_config_cache_reflects_file_change() {
    use secguard_guard::config::ConfigCache;
    use std::{fs, thread, time};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        r#"
[[deny.commands]]
id = "first"
type = "literal"
pattern = "drop A"
"#,
    )
    .unwrap();

    with_config(&path, || {
        let cache = ConfigCache::watch_for_dir(dir.path()).expect("watcher starts");
        let (deny1, _) = build_lists(&cache.load());
        assert_eq!(deny1[0].id, "first");

        fs::write(
            &path,
            r#"
[[deny.commands]]
id = "second"
type = "literal"
pattern = "drop B"
"#,
        )
        .unwrap();

        let deadline = time::Instant::now() + time::Duration::from_secs(3);
        loop {
            let (deny2, _) = build_lists(&cache.load());
            if deny2.first().is_some_and(|rule| rule.id == "second") {
                break;
            }
            assert!(
                time::Instant::now() < deadline,
                "notify-backed cache did not observe config rewrite"
            );
            thread::sleep(time::Duration::from_millis(25));
        }
    });
}

#[test]
fn project_config_precedes_user_config_in_same_rule_class() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let user_path = dir.path().join("user.toml");
    let project_root = dir.path().join("repo");
    let nested = project_root.join("nested");
    fs::create_dir_all(&nested).unwrap();

    fs::write(
        &user_path,
        r#"
[[whitelist]]
id = "user-allow"
type = "literal"
pattern = "cargo test"
"#,
    )
    .unwrap();
    fs::write(
        project_root.join(".secguard.toml"),
        r#"
[[whitelist]]
id = "project-allow"
type = "literal"
pattern = "cargo test"
"#,
    )
    .unwrap();

    with_config(&user_path, || {
        let cfg = load_for_dir(&nested);
        let (deny, allow) = build_lists(&cfg);
        match evaluate("cargo test", &deny, &allow) {
            Decision::Allow { rule_id, .. } => assert_eq!(rule_id, "project-allow"),
            other => panic!("expected project allow to win, got {other:?}"),
        }
    });
}

#[test]
fn deny_path_blocks_safe_rm_operand() {
    let cfg = config_from(
        r#"
[[deny.paths]]
id = "deny-target-debug"
type = "literal"
pattern = "target/debug"
reason = "debug cache protected for repro"
"#,
    );

    match check_with_config("rm -rf target/debug", &cfg) {
        Verdict::Destructive(reason) => {
            assert!(
                reason.contains("deny-target-debug"),
                "reason should name deny path rule: {reason}"
            );
        }
        other => panic!("expected deny path to beat safe rm defaults, got {other:?}"),
    }
}

#[test]
fn allow_path_extends_safe_rm_operands() {
    let cfg = config_from(
        r#"
[[allow.paths]]
id = "allow-generated-cache"
type = "literal"
pattern = "generated-cache"
reason = "local regenerated artifacts"
"#,
    );

    assert_eq!(
        check_with_config("rm -rf generated-cache", &cfg),
        Verdict::Safe
    );
}

#[test]
fn allow_path_cannot_override_catastrophic_path() {
    let cfg = config_from(
        r#"
[[allow.paths]]
id = "allow-etc"
type = "literal"
pattern = "/etc"
"#,
    );

    assert!(matches!(
        check_with_config("rm -rf /etc", &cfg),
        Verdict::Destructive(_)
    ));
}

#[test]
fn deny_secret_blocks_policy_safe_raw_command() {
    let cfg = config_from(
        r#"
[[deny.secrets]]
id = "deny-recipient"
type = "regex"
pattern = "roman@example\\.com"
reason = "recipient contains protected address"
"#,
    );

    match check_with_config("gws send-mail roman@example.com", &cfg) {
        Verdict::Destructive(reason) => {
            assert!(
                reason.contains("deny-recipient"),
                "reason should name deny secret rule: {reason}"
            );
        }
        other => panic!("expected deny secret to beat policy allowlist, got {other:?}"),
    }
}

#[test]
fn allow_secret_does_not_mark_destructive_command_safe() {
    let cfg = config_from(
        r#"
[[allow.secrets]]
id = "allow-token-word"
type = "literal"
pattern = "TOKEN"
"#,
    );

    assert!(matches!(
        check_with_config("rm -rf /etc TOKEN", &cfg),
        Verdict::Destructive(_)
    ));
}
