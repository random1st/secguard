//! Structured telemetry for secguard hook invocations.
//!
//! Appends JSONL events to `~/.secguard/telemetry.jsonl`.
//! Disabled with `SECGUARD_TELEMETRY=off`. Never blocks the hook.

use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct GuardEvent {
    pub ts: String,
    pub mode: &'static str,
    pub tool_name: String,
    pub command: String,
    pub verdict: &'static str,
    pub verdict_source: String,
    pub reason: Option<String>,
    /// Machine-readable rule code, e.g. `git.force_push`. None when no rule matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<&'static str>,
    pub confidence: Option<f32>,
    pub latency_us: u128,
    pub target: String,
    /// In shadow mode, this records what the guard *would* have decided
    /// (`"ask"`, `"deny"`, or `"allow"`) while the actual response is always
    /// `allow`. Absent when shadow mode is not active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_decide: Option<&'static str>,
    /// `true` iff the event was emitted in shadow mode (always-allow override).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub shadow: bool,
}

#[derive(Debug, Serialize)]
pub struct SecretsEvent {
    pub ts: String,
    pub mode: &'static str,
    pub findings_count: usize,
    pub rule_ids: Vec<String>,
    pub latency_us: u128,
    pub target: String,
}

fn is_enabled() -> bool {
    std::env::var("SECGUARD_TELEMETRY")
        .map(|v| v != "off" && v != "false" && v != "0")
        .unwrap_or(true)
}

fn telemetry_path() -> Option<std::path::PathBuf> {
    let dir = dirs::home_dir()?.join(".secguard");
    Some(dir.join("telemetry.jsonl"))
}

pub fn now_iso() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let days = (secs / 86_400) as i64;
    let (y, mo, day) = civil_from_days(days);
    let h = (secs / 3600) % 24;
    let mi = (secs / 60) % 60;
    let s = secs % 60;
    format!("{y:04}-{mo:02}-{day:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Civil calendar date from days since 1970-01-01. Hinnant's algorithm.
/// Correct for any proleptic Gregorian date.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = (y + if m <= 2 { 1 } else { 0 }) as i32;
    (y, m, d)
}

pub fn emit_guard(event: &GuardEvent) {
    if !is_enabled() {
        return;
    }
    emit_json(event);
}

pub fn emit_secrets(event: &SecretsEvent) {
    if !is_enabled() {
        return;
    }
    emit_json(event);
}

fn emit_json<T: Serialize>(event: &T) {
    let Some(path) = telemetry_path() else {
        return;
    };
    let line = match serde_json::to_string(event) {
        Ok(s) => s,
        Err(e) => {
            log::debug!("[telemetry] serialize error: {e}");
            return;
        }
    };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{line}");
        }
        Err(e) => {
            log::debug!("[telemetry] write error: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::civil_from_days;

    #[test]
    fn epoch_is_1970_01_01() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn leap_day_2024() {
        // 2024-02-29 = day 19782 since epoch
        assert_eq!(civil_from_days(19782), (2024, 2, 29));
    }

    #[test]
    fn known_date_2026_04_23() {
        // 2026-04-23 = day 20566 since epoch
        assert_eq!(civil_from_days(20566), (2026, 4, 23));
    }
}
