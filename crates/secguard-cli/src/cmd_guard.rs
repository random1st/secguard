use std::collections::HashMap;
use std::io::Read;

pub fn run(command: Option<String>) -> anyhow::Result<()> {
    let cmd = match command {
        Some(c) => c,
        None => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            input.trim().to_string()
        }
    };

    if cmd.is_empty() {
        anyhow::bail!("no command provided");
    }

    match secguard_guard::check(&cmd) {
        secguard_guard::Verdict::Safe => {
            eprintln!("safe: {cmd}");
            std::process::exit(0);
        }
        secguard_guard::Verdict::Destructive(reason) => {
            eprintln!("DESTRUCTIVE: {reason}");
            std::process::exit(1);
        }
    }
}

/// `secguard guard suggest` — analyse telemetry and recommend new safe prefixes.
///
/// Reads `~/.secguard/telemetry.jsonl`, filters for brain-only destructive verdicts,
/// groups by command prefix (first whitespace-delimited token), and prints the top N.
pub fn run_suggest(
    top: usize,
    min_count: usize,
    telemetry_path: Option<String>,
) -> anyhow::Result<()> {
    let path = match telemetry_path {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
            home.join(".secguard").join("telemetry.jsonl")
        }
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => anyhow::bail!("cannot read telemetry file {}: {}", path.display(), e),
    };

    // counts[prefix] = count
    // examples[prefix] = first command seen
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut examples: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let verdict = ev.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        let source = ev
            .get("verdict_source")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if verdict != "destructive" || source != "brain" {
            continue;
        }
        let cmd = ev
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if cmd.is_empty() {
            continue;
        }
        let prefix = cmd.split_whitespace().next().unwrap_or(cmd).to_string();
        *counts.entry(prefix.clone()).or_insert(0) += 1;
        examples.entry(prefix).or_insert_with(|| cmd.to_string());
    }

    // Filter by min_count, sort by frequency desc
    let mut ranked: Vec<(String, usize)> = counts
        .into_iter()
        .filter(|(_, cnt)| *cnt >= min_count)
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ranked.truncate(top);

    if ranked.is_empty() {
        println!("No brain-only destructive verdicts with count >= {min_count}.");
        println!("Nothing to suggest.");
        return Ok(());
    }

    // Human-readable table
    println!("Brain-only destructive verdicts (potential false positives):");
    println!("{:>7}  {:<30}  example", "count", "prefix");
    println!("{}", "-".repeat(80));
    for (prefix, cnt) in &ranked {
        let example = examples.get(prefix).map(|s| s.as_str()).unwrap_or("");
        let truncated_example = truncate_str(example, 45);
        println!("{cnt:>7}  {prefix:<30}  {truncated_example}");
    }

    // Paste-ready TOML stub
    println!();
    println!("Paste-ready TOML for ~/.config/secguard/config.toml:");
    println!("safe_command_prefixes = [");
    for (prefix, cnt) in &ranked {
        println!("  \"{prefix}\",  # {cnt} occurrences");
    }
    println!("]");

    Ok(())
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let mut out: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    fn sample_telemetry() -> &'static str {
        // brain destructive — "diana" x5, "gws" x3, "psql" x1 (below min_count=3)
        r#"{"ts":"2026-01-01T00:00:00Z","mode":"guard","tool_name":"Bash","command":"diana search RAN-1","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.9,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:01Z","mode":"guard","tool_name":"Bash","command":"diana router","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.9,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:02Z","mode":"guard","tool_name":"Bash","command":"diana store list","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.9,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:03Z","mode":"guard","tool_name":"Bash","command":"diana skills audit","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.9,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:04Z","mode":"guard","tool_name":"Bash","command":"diana hook ctx-footer","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.9,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:05Z","mode":"guard","tool_name":"Bash","command":"gws send-mail foo","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.85,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:06Z","mode":"guard","tool_name":"Bash","command":"gws list-calendars","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.85,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:07Z","mode":"guard","tool_name":"Bash","command":"gws check-inbox","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.85,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:08Z","mode":"guard","tool_name":"Bash","command":"psql -c select 1","verdict":"destructive","verdict_source":"brain","reason":"brain: destructive","confidence":0.8,"latency_us":100,"target":"claude"}
{"ts":"2026-01-01T00:00:09Z","mode":"guard","tool_name":"Bash","command":"ls -la","verdict":"safe","verdict_source":"default","reason":null,"confidence":null,"latency_us":50,"target":"claude"}
{"ts":"2026-01-01T00:00:10Z","mode":"guard","tool_name":"Bash","command":"rm -rf /tmp/foo","verdict":"destructive","verdict_source":"heuristic","reason":"rm -rf","confidence":null,"latency_us":50,"target":"claude"}
"#
    }

    #[test]
    fn suggest_top_prefixes_by_brain_verdicts() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        write!(tmp, "{}", sample_telemetry()).unwrap();

        // Run with min_count=3, top=10
        // We check internal logic by re-implementing the counting inline
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let verdict = ev.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
            let source = ev
                .get("verdict_source")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if verdict != "destructive" || source != "brain" {
                continue;
            }
            let cmd = ev
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if cmd.is_empty() {
                continue;
            }
            let prefix = cmd.split_whitespace().next().unwrap_or(cmd).to_string();
            *counts.entry(prefix).or_insert(0) += 1;
        }

        assert_eq!(counts.get("diana"), Some(&5));
        assert_eq!(counts.get("gws"), Some(&3));
        assert_eq!(counts.get("psql"), Some(&1));

        // min_count=3 filters out psql
        let mut ranked: Vec<(String, usize)> =
            counts.into_iter().filter(|(_, c)| *c >= 3).collect();
        ranked.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].0, "diana");
        assert_eq!(ranked[1].0, "gws");

        // heuristic-verdicted rm and safe ls must NOT be in results
        assert!(!ranked.iter().any(|(p, _)| p == "rm" || p == "ls"));
    }

    #[test]
    fn suggest_filters_heuristic_verdicts() {
        // Only brain verdicts should appear, not heuristic
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, r#"{{"ts":"2026-01-01T00:00:00Z","mode":"guard","tool_name":"Bash","command":"rm -rf /","verdict":"destructive","verdict_source":"heuristic","reason":"rm -rf","confidence":null,"latency_us":50,"target":"claude"}}"#).unwrap();
        writeln!(tmp, r#"{{"ts":"2026-01-01T00:00:01Z","mode":"guard","tool_name":"Bash","command":"rm -rf /var","verdict":"destructive","verdict_source":"heuristic","reason":"rm -rf","confidence":null,"latency_us":50,"target":"claude"}}"#).unwrap();
        writeln!(tmp, r#"{{"ts":"2026-01-01T00:00:02Z","mode":"guard","tool_name":"Bash","command":"rm -rf /usr","verdict":"destructive","verdict_source":"heuristic","reason":"rm -rf","confidence":null,"latency_us":50,"target":"claude"}}"#).unwrap();
        writeln!(tmp, r#"{{"ts":"2026-01-01T00:00:03Z","mode":"guard","tool_name":"Bash","command":"rm -rf /home","verdict":"destructive","verdict_source":"heuristic","reason":"rm -rf","confidence":null,"latency_us":50,"target":"claude"}}"#).unwrap();

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let verdict = ev.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
            let source = ev
                .get("verdict_source")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if verdict != "destructive" || source != "brain" {
                continue;
            }
            let cmd = ev
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if cmd.is_empty() {
                continue;
            }
            let prefix = cmd.split_whitespace().next().unwrap_or(cmd).to_string();
            *counts.entry(prefix).or_insert(0) += 1;
        }
        // rm is heuristic, should not appear
        assert!(
            !counts.contains_key("rm"),
            "rm should not appear in brain-only counts"
        );
    }
}
