//! Repo-wide secret scan + baseline filtering/audit — RAN-415 slice 2a.
//!
//! [`scan_repo`] walks a directory (gitignore-aware, hidden files skipped),
//! runs the [`Scanner`] over each UTF-8 text file, and resolves each match to a
//! repo-relative `file:line`. The pure functions [`build_baseline`],
//! [`partition_known`], and [`stale_entries`] turn those findings into a
//! [`Baseline`], filter a fresh scan against one, and audit a baseline for
//! entries that no longer reproduce.

use crate::baseline::{fingerprint, Baseline, BaselineEntry};
use crate::scanner::Scanner;
use ignore::WalkBuilder;
use std::path::Path;

/// Files larger than this are skipped (likely data/binaries, not source).
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// A secret located at a concrete `file:line`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFinding {
    /// Repo-relative path.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    pub rule_id: String,
    /// The matched secret text (used to compute the fingerprint).
    pub secret: String,
}

impl FileFinding {
    /// Content fingerprint for this finding — see [`crate::baseline::fingerprint`].
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.rule_id, &self.secret)
    }
}

/// 1-based line number of byte offset `offset` within `text`.
fn byte_to_line(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Walk `root` and return every secret found, sorted by `(file, line, rule_id)`
/// for deterministic baseline output. Respects `.gitignore` and skips hidden
/// files, non-UTF-8 (binary) files, and files larger than [`MAX_FILE_BYTES`].
pub fn scan_repo(root: &Path, scanner: &Scanner) -> Vec<FileFinding> {
    let mut findings = Vec::new();

    // require_git(false): honour .gitignore/.ignore even outside a git repo
    // (e.g. a freshly cloned tree or a subdir scan), matching ripgrep/CI
    // secret-scanner conventions. Hidden files (.git, .secguard-baseline.json)
    // stay skipped by the default hidden filter. Trade-off: a gitignored .env
    // is not baselined — but it is also never shared via the repo.
    for result in WalkBuilder::new(root).require_git(false).build() {
        let entry = match result {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[secguard] scan walk error: {e}");
                continue;
            }
        };
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        if entry.metadata().map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue, // non-UTF-8 / unreadable → skip (binary)
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();

        for f in scanner.scan(&content) {
            findings.push(FileFinding {
                file: rel.clone(),
                line: byte_to_line(&content, f.start),
                rule_id: f.rule_id,
                secret: content[f.start..f.end].to_string(),
            });
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    findings
}

/// Build a baseline from a set of findings.
pub fn build_baseline(findings: &[FileFinding]) -> Baseline {
    Baseline::new(
        findings
            .iter()
            .map(|f| BaselineEntry {
                fingerprint: f.fingerprint(),
                file: f.file.clone(),
                line: f.line,
                rule_id: f.rule_id.clone(),
            })
            .collect(),
    )
}

/// Split findings into `(known, novel)` against a baseline. Known findings are
/// already recorded `(file, fingerprint)` pairs; novel ones are not.
pub fn partition_known<'a>(
    findings: &'a [FileFinding],
    baseline: &Baseline,
) -> (Vec<&'a FileFinding>, Vec<&'a FileFinding>) {
    let known_set = baseline.known_index();
    findings.iter().partition(|f| {
        let fp = f.fingerprint();
        known_set.contains(&(f.file.as_str(), fp.as_str()))
    })
}

/// Baseline entries that no longer appear in a fresh scan (stale: the file
/// changed or the secret was removed). Used by `baseline audit`.
pub fn stale_entries<'a>(
    baseline: &'a Baseline,
    findings: &[FileFinding],
) -> Vec<&'a BaselineEntry> {
    let fresh: std::collections::HashSet<(String, String)> = findings
        .iter()
        .map(|f| (f.file.clone(), f.fingerprint()))
        .collect();
    baseline
        .entries
        .iter()
        .filter(|e| !fresh.contains(&(e.file.clone(), e.fingerprint.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn aws_key() -> String {
        // Built at runtime so the literal does not trip the scanner on this file.
        format!("AKIA{}", "IOSFODNN7EXAMPLE")
    }

    #[test]
    fn byte_to_line_counts_newlines() {
        let text = "a\nb\nc";
        assert_eq!(byte_to_line(text, 0), 1);
        assert_eq!(byte_to_line(text, 2), 2); // 'b'
        assert_eq!(byte_to_line(text, 4), 3); // 'c'
        assert_eq!(byte_to_line(text, 999), 3); // clamps
    }

    // ── Test class 2: baseline → scan → findings filtered (integration) ──
    #[test]
    fn scan_then_baseline_filters_known_leaves_novel() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("config.sh")).unwrap();
        writeln!(f, "# comment line").unwrap();
        writeln!(f, "export AWS_ACCESS_KEY_ID={}", aws_key()).unwrap();
        drop(f);

        let scanner = Scanner::new();
        let findings = scan_repo(dir.path(), &scanner);
        assert_eq!(findings.len(), 1, "should find the planted AWS key");
        assert_eq!(findings[0].file, "config.sh");
        assert_eq!(findings[0].line, 2, "key is on line 2");
        assert_eq!(findings[0].rule_id, "aws_access_key");

        // Baseline the existing finding, re-scan: it is now known, nothing novel.
        let baseline = build_baseline(&findings);
        let rescan = scan_repo(dir.path(), &scanner);
        let (known, novel) = partition_known(&rescan, &baseline);
        assert_eq!(known.len(), 1);
        assert!(novel.is_empty(), "baselined finding must not be novel");

        // Add a NEW secret → it shows up as novel, the old one stays known.
        let mut f2 = std::fs::File::create(dir.path().join("extra.sh")).unwrap();
        let stripe = format!("sk_live_{}", "abc123def456ghi789jkl012");
        writeln!(f2, "STRIPE={stripe}").unwrap();
        drop(f2);
        let rescan2 = scan_repo(dir.path(), &scanner);
        let (known2, novel2) = partition_known(&rescan2, &baseline);
        assert_eq!(known2.len(), 1, "AWS key still known");
        assert_eq!(novel2.len(), 1, "new stripe key is novel");
        assert_eq!(novel2[0].file, "extra.sh");
    }

    // ── Test class 5: audit stale entry detection ────────────────────────
    #[test]
    fn stale_entries_detects_removed_finding() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("config.sh")).unwrap();
        writeln!(f, "export AWS_ACCESS_KEY_ID={}", aws_key()).unwrap();
        drop(f);

        let scanner = Scanner::new();
        let baseline = build_baseline(&scan_repo(dir.path(), &scanner));
        assert_eq!(baseline.entries.len(), 1);

        // Remove the secret from the file → the baseline entry is now stale.
        std::fs::write(dir.path().join("config.sh"), "# cleaned up\n").unwrap();
        let fresh = scan_repo(dir.path(), &scanner);
        assert!(fresh.is_empty());

        let stale = stale_entries(&baseline, &fresh);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].file, "config.sh");
        assert_eq!(stale[0].rule_id, "aws_access_key");
    }

    #[test]
    fn gitignored_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "secrets.env\n").unwrap();
        std::fs::write(
            dir.path().join("secrets.env"),
            format!("KEY={}\n", aws_key()),
        )
        .unwrap();
        let findings = scan_repo(dir.path(), &Scanner::new());
        assert!(
            findings.is_empty(),
            "gitignored file must not be scanned, got {findings:?}"
        );
    }
}
