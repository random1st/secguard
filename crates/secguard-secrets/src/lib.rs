//! Secret and credential detection.
//!
//! Scans text for API keys, tokens, connection strings, and other credentials.

pub mod baseline;
pub mod redactor;
pub mod repo;
pub mod rules;
pub mod scanner;

pub use baseline::{Baseline, BaselineEntry, BaselineError};
pub use redactor::{redact, redact_value};
pub use repo::{build_baseline, partition_known, scan_repo, stale_entries, FileFinding};
pub use scanner::{Finding, Scanner};
