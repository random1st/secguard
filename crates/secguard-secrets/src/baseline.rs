//! Secrets baseline (`.secguard-baseline.json`) — RAN-415.
//!
//! A `detect-secrets`-style allowlist of *known* (usually legacy) findings, so
//! adopting the scanner in an existing repo does not block on pre-existing
//! secrets. A baselined finding is reported as `known` and does not fail the
//! scan; anything new still does.
//!
//! Each entry is keyed by `(file, fingerprint)` where the fingerprint is a
//! content hash of `(rule_id, secret)` — deliberately **not** line-based, so an
//! edit that shifts a secret up or down a file does not invalidate its baseline
//! entry. The line number is retained as human-facing metadata only.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Baseline schema version. Bump on any breaking format change; older/newer
/// versions are rejected by [`Baseline::from_json`] with a clear error.
pub const SCHEMA_VERSION: u32 = 1;

/// Canonical baseline filename, resolved at the repo root.
pub const BASELINE_FILENAME: &str = ".secguard-baseline.json";

/// Content fingerprint of a finding: `sha256(rule_id \0 secret)`, lowercase hex.
///
/// Excludes the line number and file path so the same secret stays stably
/// identified across edits that move it. The file path is tracked separately on
/// the [`BaselineEntry`] so the *same* secret in two files is two entries.
pub fn fingerprint(rule_id: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(secret.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One known finding recorded in the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// `sha256(rule_id \0 secret)` hex — see [`fingerprint`].
    pub fingerprint: String,
    /// Repo-relative path of the file the secret was found in.
    pub file: String,
    /// 1-based line number (human-facing metadata; not part of identity).
    pub line: usize,
    /// The rule that matched (e.g. `aws_access_key`).
    pub rule_id: String,
}

/// The on-disk baseline document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version — validated on load.
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<BaselineEntry>,
}

/// Errors from loading or validating a baseline file.
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("baseline is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("baseline schema version {found} is not supported (this build supports {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("failed to read baseline file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl Baseline {
    /// Build a fresh baseline at the current schema version.
    pub fn new(entries: Vec<BaselineEntry>) -> Self {
        Self {
            version: SCHEMA_VERSION,
            entries,
        }
    }

    /// Parse and validate a baseline from JSON text. Rejects malformed JSON and
    /// unsupported schema versions with an actionable message.
    pub fn from_json(text: &str) -> Result<Self, BaselineError> {
        let baseline: Baseline = serde_json::from_str(text)?;
        if baseline.version != SCHEMA_VERSION {
            return Err(BaselineError::UnsupportedVersion {
                found: baseline.version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(baseline)
    }

    /// Serialize to stable, pretty JSON with a trailing newline (diff-friendly).
    pub fn to_json_pretty(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("baseline serializes");
        s.push('\n');
        s
    }

    /// Fast `(file, fingerprint)` membership set for scan-time filtering.
    pub fn known_index(&self) -> HashSet<(&str, &str)> {
        self.entries
            .iter()
            .map(|e| (e.file.as_str(), e.fingerprint.as_str()))
            .collect()
    }

    /// True when a finding `(file, rule_id, secret)` is already baselined.
    pub fn is_known(&self, file: &str, rule_id: &str, secret: &str) -> bool {
        let fp = fingerprint(rule_id, secret);
        self.entries
            .iter()
            .any(|e| e.file == file && e.fingerprint == fp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test class 1: deterministic fingerprint ──────────────────────────
    #[test]
    fn fingerprint_is_deterministic() {
        let a = fingerprint("aws_access_key", "AKIAIOSFODNN7EXAMPLE");
        let b = fingerprint("aws_access_key", "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn fingerprint_separates_rule_and_secret() {
        // The NUL separator prevents (rule="a", secret="bc") colliding with
        // (rule="ab", secret="c").
        assert_ne!(fingerprint("a", "bc"), fingerprint("ab", "c"));
    }

    #[test]
    fn fingerprint_changes_with_secret() {
        assert_ne!(
            fingerprint("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
            fingerprint("aws_access_key", "AKIAIOSFODNN7DIFFERENT")
        );
    }

    // ── Test class 3: JSON format snapshot ───────────────────────────────
    #[test]
    fn json_format_snapshot() {
        let baseline = Baseline::new(vec![BaselineEntry {
            fingerprint: "deadbeef".into(),
            file: "src/config.rs".into(),
            line: 42,
            rule_id: "aws_access_key".into(),
        }]);
        let expected = "{\n  \"version\": 1,\n  \"entries\": [\n    {\n      \"fingerprint\": \"deadbeef\",\n      \"file\": \"src/config.rs\",\n      \"line\": 42,\n      \"rule_id\": \"aws_access_key\"\n    }\n  ]\n}\n";
        assert_eq!(baseline.to_json_pretty(), expected);
    }

    #[test]
    fn json_round_trips() {
        let baseline = Baseline::new(vec![BaselineEntry {
            fingerprint: fingerprint("github_pat", "ghp_example"),
            file: "a.rs".into(),
            line: 1,
            rule_id: "github_pat".into(),
        }]);
        let parsed = Baseline::from_json(&baseline.to_json_pretty()).unwrap();
        assert_eq!(parsed.entries, baseline.entries);
        assert_eq!(parsed.version, SCHEMA_VERSION);
    }

    // ── Test class 4: corrupted / unsupported baseline → clear error ─────
    #[test]
    fn corrupted_json_is_clear_error() {
        let err = Baseline::from_json("{ this is not json").unwrap_err();
        assert!(matches!(err, BaselineError::Parse(_)));
        assert!(err.to_string().contains("not valid JSON"));
    }

    #[test]
    fn unsupported_version_is_clear_error() {
        let err = Baseline::from_json(r#"{"version": 999, "entries": []}"#).unwrap_err();
        match err {
            BaselineError::UnsupportedVersion { found, supported } => {
                assert_eq!(found, 999);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
        assert!(Baseline::from_json(r#"{"version": 999, "entries": []}"#)
            .unwrap_err()
            .to_string()
            .contains("not supported"));
    }

    #[test]
    fn is_known_matches_file_and_content() {
        let baseline = Baseline::new(vec![BaselineEntry {
            fingerprint: fingerprint("aws_access_key", "SECRET"),
            file: "src/a.rs".into(),
            line: 10,
            rule_id: "aws_access_key".into(),
        }]);
        assert!(baseline.is_known("src/a.rs", "aws_access_key", "SECRET"));
        // Same secret, different file → not known.
        assert!(!baseline.is_known("src/b.rs", "aws_access_key", "SECRET"));
        // Different secret, same file → not known.
        assert!(!baseline.is_known("src/a.rs", "aws_access_key", "OTHER"));
    }
}
