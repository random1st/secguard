//! Findings cache — stores the last blocked commands so `secguard allow add <id>`
//! can resolve the pattern without the user retyping it (RAN-416 G1.1).
//!
//! ## Design
//! - `finding_id`: first 12 hex chars of SHA-256(`rule_id|cmd|cwd`).
//!   Same inputs → same id; different cmd or cwd → different id.
//! - Storage: `~/.cache/secguard/findings.json` — a JSON array of the last 100
//!   entries. New entries are prepended; tail beyond 100 is truncated.
//! - TTL: 24 hours. Entries older than 24h are dropped on every read/write.
//! - Failure mode: fail-open. A write error is logged to stderr and silently
//!   ignored — the hook must never block because the cache is unavailable.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Maximum entries kept in the cache.
const MAX_ENTRIES: usize = 100;

/// Time-to-live for each entry.
const TTL_HOURS: i64 = 24;

/// Stable finding identifier: first 12 hex chars of SHA-256(`rule_id|cmd|cwd`).
///
/// The 12-char prefix gives 48 bits — collision probability < 1 in 10^10 across
/// the typical 100-entry cache window.  Deterministic: same inputs always produce
/// the same id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingId(pub String);

impl FindingId {
    /// Derive the finding id from its three stable inputs.
    ///
    /// `rule_id` — human-readable rule code (e.g. `"rm.rf"`).
    /// `command` — the verbatim command string (not truncated/redacted).
    /// `cwd`     — current working directory at block time.
    pub fn new(rule_id: &str, command: &str, cwd: &Path) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(b"|");
        hasher.update(command.as_bytes());
        hasher.update(b"|");
        hasher.update(cwd.to_string_lossy().as_bytes());
        let hash = hasher.finalize();
        // First 12 hex chars = 6 bytes = 48 bits of disambiguation.
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        Self(hex[..12].to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single cached finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEntry {
    /// Stable 12-char hex id.
    pub finding_id: String,
    /// The rule code that fired (e.g. `"rm.rf"`).
    pub rule_id: String,
    /// The command that was blocked (verbatim, not redacted).
    pub command: String,
    /// The working directory at block time.
    pub cwd: String,
    /// The pattern to add to the allowlist (same as command for literal rules).
    pub pattern_to_allow: String,
    /// When this entry was created (RFC 3339).
    pub timestamp: DateTime<Utc>,
}

impl FindingEntry {
    /// Build a new entry, deriving the finding_id and pattern from the inputs.
    ///
    /// `pattern_to_allow` is the literal command string: `secguard allow add <id>`
    /// appends it as a `literal` allow rule so the exact blocked command passes.
    /// If a broader pattern is needed, the user can invoke `secguard allow add`
    /// with `--type glob`/`--type regex` directly.
    pub fn new(rule_id: &str, command: &str, cwd: &Path) -> Self {
        let id = FindingId::new(rule_id, command, cwd);
        Self {
            finding_id: id.0,
            rule_id: rule_id.to_string(),
            command: command.to_string(),
            cwd: cwd.to_string_lossy().into_owned(),
            pattern_to_allow: command.to_string(),
            timestamp: Utc::now(),
        }
    }
}

/// JSON-file backed cache of recent blocked findings.
pub struct FindingsCache {
    path: PathBuf,
}

impl FindingsCache {
    /// Locate the default cache file: `~/.cache/secguard/findings.json`.
    /// Falls back to a temp path when the home directory is unavailable.
    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
            .unwrap_or_else(std::env::temp_dir)
            .join("secguard")
            .join("findings.json")
    }

    /// Open (or create) the cache at the given path.
    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// Open the default cache.
    /// Open the cache at its conventional path.
    ///
    /// Named `at_default_path` rather than `default`: an inherent `default`
    /// shadows `Default::default` at the call site, and a reader cannot tell
    /// which one they are getting. This one does I/O, so the confusion is not
    /// cosmetic.
    pub fn at_default_path() -> Self {
        Self::open(Self::default_path())
    }

    /// Persist a new finding.  Creates parent directories if needed.
    /// Silently ignores I/O errors — callers must not block on cache writes.
    pub fn push(&self, entry: FindingEntry) {
        let mut entries = self.read_valid();
        // Prepend: newest first.
        entries.insert(0, entry);
        // Truncate to the cap.
        entries.truncate(MAX_ENTRIES);
        self.write(&entries);
    }

    /// Resolve a finding_id to its entry.  Returns `None` when the id is
    /// unknown or the entry has expired.
    pub fn get(&self, finding_id: &str) -> Option<FindingEntry> {
        self.read_valid()
            .into_iter()
            .find(|e| e.finding_id == finding_id)
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    /// Read the cache file, drop expired entries, return live ones.
    fn read_valid(&self) -> Vec<FindingEntry> {
        let entries = self.read_raw().unwrap_or_default();
        let cutoff = Utc::now() - Duration::hours(TTL_HOURS);
        entries
            .into_iter()
            .filter(|e| e.timestamp > cutoff)
            .collect()
    }

    fn read_raw(&self) -> Option<Vec<FindingEntry>> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn write(&self, entries: &[FindingEntry]) {
        if let Some(parent) = self.path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("[diana-guard/findings] could not create cache dir: {e}");
                return;
            }
        }
        match serde_json::to_string_pretty(entries) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    eprintln!("[diana-guard/findings] could not write cache: {e}");
                }
            }
            Err(e) => eprintln!("[diana-guard/findings] could not serialize findings: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_cwd() -> PathBuf {
        PathBuf::from("/repo/project")
    }

    // ── DoD 1: deterministic finding_id ──────────────────────────────────────

    #[test]
    fn finding_id_same_inputs_same_id() {
        let cwd = dummy_cwd();
        let a = FindingId::new("rm.rf", "rm -rf ./dist", &cwd);
        let b = FindingId::new("rm.rf", "rm -rf ./dist", &cwd);
        assert_eq!(a, b);
    }

    #[test]
    fn finding_id_different_command_different_id() {
        let cwd = dummy_cwd();
        let a = FindingId::new("rm.rf", "rm -rf ./dist", &cwd);
        let b = FindingId::new("rm.rf", "rm -rf ./target", &cwd);
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_different_rule_different_id() {
        let cwd = dummy_cwd();
        let a = FindingId::new("rm.rf", "rm -rf ./dist", &cwd);
        let b = FindingId::new("git.force_push", "rm -rf ./dist", &cwd);
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_different_cwd_different_id() {
        let a = FindingId::new("rm.rf", "rm -rf ./dist", &PathBuf::from("/repo/a"));
        let b = FindingId::new("rm.rf", "rm -rf ./dist", &PathBuf::from("/repo/b"));
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_is_12_hex_chars() {
        let id = FindingId::new("rm.rf", "rm -rf /", &dummy_cwd());
        assert_eq!(id.as_str().len(), 12);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── DoD 4: invalid finding_id → clear error, no panic ────────────────────

    #[test]
    fn cache_get_unknown_id_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FindingsCache::open(dir.path().join("findings.json"));
        assert!(cache.get("deadbeef0000").is_none());
    }

    #[test]
    fn cache_get_on_empty_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");
        std::fs::write(&path, "").unwrap();
        let cache = FindingsCache::open(path);
        assert!(cache.get("aabbccdd0011").is_none());
    }

    #[test]
    fn cache_get_on_corrupt_json_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");
        std::fs::write(&path, "not json at all {{{").unwrap();
        let cache = FindingsCache::open(path);
        assert!(cache.get("aabbccdd0011").is_none());
    }

    // ── DoD 2: push → get roundtrip ─────────────────────────────────────────

    #[test]
    fn cache_push_and_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FindingsCache::open(dir.path().join("findings.json"));

        let entry = FindingEntry::new("rm.rf", "rm -rf ./dist", &dummy_cwd());
        let id = entry.finding_id.clone();
        cache.push(entry);

        let found = cache.get(&id).expect("entry should be found after push");
        assert_eq!(found.rule_id, "rm.rf");
        assert_eq!(found.command, "rm -rf ./dist");
        assert_eq!(found.pattern_to_allow, "rm -rf ./dist");
    }

    // ── DoD 5: TTL expiry ───────────────────────────────────────────────────

    #[test]
    fn cache_ttl_expired_entry_is_not_returned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");

        // Write an entry with a timestamp 25 hours in the past.
        let expired_at = Utc::now() - Duration::hours(25);
        let entry = FindingEntry {
            finding_id: "aabbccdd0011".to_string(),
            rule_id: "rm.rf".to_string(),
            command: "rm -rf ./old".to_string(),
            cwd: "/repo".to_string(),
            pattern_to_allow: "rm -rf ./old".to_string(),
            timestamp: expired_at,
        };
        let json = serde_json::to_string(&vec![entry]).unwrap();
        std::fs::write(&path, json).unwrap();

        let cache = FindingsCache::open(path);
        assert!(
            cache.get("aabbccdd0011").is_none(),
            "expired entry must not be returned"
        );
    }

    #[test]
    fn cache_ttl_fresh_entry_is_returned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");

        let entry = FindingEntry::new("rm.rf", "rm -rf ./fresh", &dummy_cwd());
        let id = entry.finding_id.clone();
        let json = serde_json::to_string(&vec![entry]).unwrap();
        std::fs::write(&path, json).unwrap();

        let cache = FindingsCache::open(path);
        assert!(cache.get(&id).is_some(), "fresh entry must be returned");
    }

    // ── Cap at MAX_ENTRIES ───────────────────────────────────────────────────

    #[test]
    fn cache_does_not_exceed_max_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FindingsCache::open(dir.path().join("findings.json"));

        for i in 0..120usize {
            let cmd = format!("rm -rf ./file{i}");
            cache.push(FindingEntry::new("rm.rf", &cmd, &dummy_cwd()));
        }

        let entries = cache.read_valid();
        assert!(
            entries.len() <= MAX_ENTRIES,
            "cache must not exceed {MAX_ENTRIES} entries, got {}",
            entries.len()
        );
    }
}
