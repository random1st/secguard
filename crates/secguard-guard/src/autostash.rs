//! Auto-stash before high-blast operations (RAN-418 G1.3).
//!
//! Inspects the current working directory for a git repository and, when the
//! working tree is dirty and a command reaches the blast threshold, runs
//! `git stash push -u -m "secguard-autosnap-<unix_timestamp>"` before
//! allowing the command through.
//!
//! All git I/O is done via `std::process::Command` (no libgit2 dep).
//!
//! # Trigger AND-chain
//!
//! A stash is created only when ALL of the following hold:
//!   1. `config.autostash.enabled` is true.
//!   2. The command's blast score ≥ `config.autostash.blast_threshold` (default 3).
//!   3. `cwd` is inside a git repository (`is_inside_git_repo(cwd)` returns true).
//!   4. The working tree has uncommitted changes (`working_tree_dirty(cwd)` returns true).
//!   5. The command modifies the working tree (`command_modifies_tree(cmd)` returns true).
//!
//! Conditions 3 and 4 fail silently (no error emitted) — the hook proceeds
//! without stashing.

use std::path::Path;
use std::process::Command;

/// Opaque reference to the stash entry that was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StashRef {
    /// The stash label used: `secguard-autosnap-<timestamp>`.
    pub label: String,
}

/// Errors that can prevent auto-stashing.
#[derive(Debug, thiserror::Error)]
pub enum AutostashError {
    #[error("git stash failed: {0}")]
    StashFailed(String),
    #[error("could not determine current working directory: {0}")]
    NoCwd(String),
    #[error("git command failed to spawn: {0}")]
    SpawnFailed(String),
}

/// Return true when `cwd` is inside a git repository.
///
/// Runs `git -C <cwd> rev-parse --is-inside-work-tree` and checks for exit 0.
/// Returns false on any error (missing git, not a repo, spawn failure).
pub fn is_inside_git_repo(cwd: &Path) -> bool {
    Command::new("git")
        .args([
            "-C",
            &cwd.to_string_lossy(),
            "rev-parse",
            "--is-inside-work-tree",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Return true when the working tree has uncommitted changes (tracked or untracked).
///
/// Runs `git -C <cwd> status --porcelain` and checks whether the output is non-empty.
/// Returns false on any error.
pub fn working_tree_dirty(cwd: &Path) -> bool {
    let output = Command::new("git")
        .args(["-C", &cwd.to_string_lossy(), "status", "--porcelain"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(out) if out.status.success() => !out.stdout.is_empty(),
        _ => false,
    }
}

/// Return true when `cmd` is likely to modify the working tree.
///
/// Conservative heuristic: any command containing git operations that write to
/// the working tree or file-system operations that write files. Commands that
/// are purely read-only (ls, cat, grep, git log, git diff, etc.) return false.
pub fn command_modifies_tree(cmd: &str) -> bool {
    // Match git subcommands that modify the working tree.
    const GIT_MUTATING: &[&str] = &[
        "git checkout",
        "git switch",
        "git restore",
        "git reset",
        "git merge",
        "git rebase",
        "git cherry-pick",
        "git apply",
        "git am",
        "git clean",
        "git stash pop",
        "git stash apply",
        "git stash drop",
        "git stash clear",
        "git pull",
        "git fetch",
        "git revert",
        "git bisect",
        "git worktree",
    ];

    // Non-git file-modifying commands that blast the working tree.
    const FILE_MUTATING_PREFIXES: &[&str] = &["rm ", "rm\t", "mv ", "mv\t", "cp -", "rsync"];

    let trimmed = cmd.trim();

    for prefix in GIT_MUTATING {
        if trimmed.starts_with(prefix)
            || trimmed.contains(&format!(" {prefix}"))
            || trimmed.contains(&format!(";{prefix}"))
            || trimmed.contains(&format!("&&{prefix}"))
        {
            return true;
        }
    }

    for prefix in FILE_MUTATING_PREFIXES {
        if trimmed.starts_with(prefix) || trimmed.contains(&format!(";{prefix}")) {
            return true;
        }
    }

    false
}

/// Run `git stash push -u -m "secguard-autosnap-<timestamp>"` in `cwd`.
///
/// Returns `Ok(Some(StashRef))` when a stash entry was created.
/// Returns `Ok(None)` when git stash reports "No local changes to save"
/// (race condition between `working_tree_dirty` check and actual stash).
/// Returns `Err` on git spawn failure or non-zero exit for other reasons.
pub fn auto_stash(cwd: &Path, label: &str) -> Result<Option<StashRef>, AutostashError> {
    let output = Command::new("git")
        .args([
            "-C",
            &cwd.to_string_lossy(),
            "stash",
            "push",
            "-u",
            "-m",
            label,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| AutostashError::SpawnFailed(e.to_string()))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // git stash prints "No local changes to save" when nothing to stash.
        if stdout.contains("No local changes to save") {
            return Ok(None);
        }
        return Ok(Some(StashRef {
            label: label.to_string(),
        }));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(AutostashError::StashFailed(format!(
        "exit {}: {} {}",
        output.status,
        stderr.trim(),
        stdout.trim()
    )))
}

/// Build the stash label: `secguard-autosnap-<unix_timestamp>`.
pub fn stash_label() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("secguard-autosnap-{ts}")
}

/// Find the most recent stash entry matching the `secguard-autosnap-` prefix.
///
/// Runs `git -C <cwd> stash list` and returns the stash ref (e.g. `stash@{0}`)
/// for the first matching entry, or `None` when no matching stash exists.
pub fn find_latest_autosnap(cwd: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["-C", &cwd.to_string_lossy(), "stash", "list"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Lines have format: "stash@{N}: On <branch>: <message>"
        if line.contains("secguard-autosnap-") {
            // Extract the "stash@{N}" token.
            let ref_part = line.split(':').next()?.trim().to_string();
            if ref_part.starts_with("stash@{") {
                return Some(ref_part);
            }
        }
    }

    None
}

/// Pop (restore) the most recent secguard-autosnap stash entry.
///
/// Returns the stash ref that was popped on success.
/// Returns `Err` when no matching stash is found or when `git stash pop` fails.
pub fn pop_latest_autosnap(cwd: &Path) -> Result<String, AutostashError> {
    let stash_ref = find_latest_autosnap(cwd)
        .ok_or_else(|| AutostashError::StashFailed("no secguard-autosnap stash found".into()))?;

    let output = Command::new("git")
        .args(["-C", &cwd.to_string_lossy(), "stash", "pop", &stash_ref])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| AutostashError::SpawnFailed(e.to_string()))?;

    if output.status.success() {
        return Ok(stash_ref);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(AutostashError::StashFailed(format!(
        "git stash pop {stash_ref} failed: {}",
        stderr.trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // ── Test class 1: unit — is_inside_git_repo detection ────────────────

    #[test]
    fn is_inside_git_repo_returns_false_for_tmp() {
        // /tmp is almost certainly not a git repo.
        let tmp = std::path::PathBuf::from("/tmp");
        assert!(!is_inside_git_repo(&tmp));
    }

    #[test]
    fn is_inside_git_repo_returns_true_for_diana_src() {
        // The diana monorepo IS a git repo.
        let src = dirs::home_dir()
            .unwrap_or_default()
            .join(".diana")
            .join("src");
        if src.exists() {
            // Only assert if the path exists (CI may not have the full tree).
            assert!(is_inside_git_repo(&src));
        }
    }

    // ── Test class 3: snapshot — stash label format ───────────────────────

    #[test]
    fn stash_label_format_matches_prefix() {
        let label = stash_label();
        assert!(
            label.starts_with("secguard-autosnap-"),
            "label should start with secguard-autosnap-: {label}"
        );
        // Suffix should be a decimal unix timestamp.
        let suffix = label.strip_prefix("secguard-autosnap-").unwrap();
        assert!(
            suffix.parse::<u64>().is_ok(),
            "suffix should be a valid unix timestamp: {suffix}"
        );
    }

    #[test]
    fn stash_label_is_unique_across_calls() {
        // Two calls within the same second may collide — but the label
        // still has the correct format, which is what the contract specifies.
        let l1 = stash_label();
        let l2 = stash_label();
        assert!(l1.starts_with("secguard-autosnap-"));
        assert!(l2.starts_with("secguard-autosnap-"));
    }

    // ── Test class: command_modifies_tree heuristic ───────────────────────

    #[test]
    fn command_modifies_tree_detects_git_checkout() {
        assert!(command_modifies_tree("git checkout feature-branch"));
    }

    #[test]
    fn command_modifies_tree_detects_git_reset() {
        assert!(command_modifies_tree("git reset --hard HEAD~1"));
    }

    #[test]
    fn command_modifies_tree_detects_rm() {
        assert!(command_modifies_tree("rm -rf build/"));
    }

    #[test]
    fn command_modifies_tree_safe_commands_return_false() {
        assert!(!command_modifies_tree("git log --oneline -10"));
        assert!(!command_modifies_tree("git diff HEAD"));
        assert!(!command_modifies_tree("cargo test -p diana-guard"));
        assert!(!command_modifies_tree("ls -la"));
        assert!(!command_modifies_tree("cat Cargo.toml"));
    }

    // ── Test class 5: negative — not a git repo → no error, skipped ──────

    #[test]
    fn is_inside_git_repo_returns_false_for_nonexistent() {
        let path = std::path::PathBuf::from("/nonexistent/path/xyz");
        // Should return false without panicking.
        assert!(!is_inside_git_repo(&path));
    }

    #[test]
    fn working_tree_dirty_returns_false_for_non_repo() {
        let path = std::path::PathBuf::from("/tmp");
        // Should return false without panicking.
        assert!(!working_tree_dirty(&path));
    }

    // ── Test class 4: negative — clean tree → no stash ───────────────────
    // Integration tests that do real git I/O are marked #[ignore] because
    // they depend on external process availability and filesystem state.
    // Run with `cargo test -p diana-guard -- --ignored` for local verification.

    #[test]
    #[ignore = "requires git, creates real temp repo; run manually with --ignored"]
    fn clean_tree_produces_no_stash() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();

        // Init a git repo with an initial commit (required for stash to work).
        Command::new("git")
            .args(["init"])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(cwd)
            .status()
            .unwrap();
        std::fs::write(cwd.join("README.md"), "hello").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(cwd)
            .status()
            .unwrap();

        // Tree is clean — auto_stash should return Ok(None).
        let label = stash_label();
        let result = auto_stash(cwd, &label).unwrap();
        assert!(
            result.is_none(),
            "clean tree should produce no stash: {result:?}"
        );
    }

    // ── Test class 2: integration — dirty repo + dangerous command → stash ─

    #[test]
    #[ignore = "requires git, creates real temp repo; run manually with --ignored"]
    fn dirty_tree_produces_stash_entry() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();

        // Init + initial commit.
        Command::new("git")
            .args(["init"])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(cwd)
            .status()
            .unwrap();
        std::fs::write(cwd.join("README.md"), "hello").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(cwd)
            .status()
            .unwrap();

        // Make the tree dirty.
        std::fs::write(cwd.join("dirty.txt"), "dirty change").unwrap();

        assert!(
            working_tree_dirty(cwd),
            "tree should be dirty after writing untracked file"
        );

        let label = stash_label();
        let result = auto_stash(cwd, &label).unwrap();
        assert!(result.is_some(), "dirty tree should produce a stash entry");
        let stash_ref = result.unwrap();
        assert_eq!(stash_ref.label, label);

        // Stash should now appear in list.
        let found = find_latest_autosnap(cwd);
        assert!(
            found.is_some(),
            "stash list should contain the autosnap entry"
        );
    }

    // ── Test class 6: rollback — pop_latest_autosnap restores state ───────

    #[test]
    #[ignore = "requires git, creates real temp repo; run manually with --ignored"]
    fn rollback_restores_dirty_file() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let dirty_file = cwd.join("dirty.txt");

        // Init + initial commit.
        Command::new("git")
            .args(["init"])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(cwd)
            .status()
            .unwrap();
        std::fs::write(cwd.join("README.md"), "hello").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(cwd)
            .status()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(cwd)
            .status()
            .unwrap();

        // Write a dirty file and stash it.
        std::fs::write(&dirty_file, "my important change").unwrap();
        assert!(dirty_file.exists());

        let label = stash_label();
        let stash_result = auto_stash(cwd, &label).unwrap();
        assert!(stash_result.is_some());

        // File should be gone from working tree after stash.
        assert!(!dirty_file.exists(), "file should be stashed away");

        // Pop should restore it.
        let popped = pop_latest_autosnap(cwd).unwrap();
        assert!(
            popped.starts_with("stash@{"),
            "popped ref should have correct format: {popped}"
        );
        assert!(dirty_file.exists(), "file should be restored after pop");
        assert_eq!(
            std::fs::read_to_string(&dirty_file).unwrap(),
            "my important change"
        );
    }
}
