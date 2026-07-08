use std::io::Read;

pub fn run(dir: Option<String>, format: &str) -> anyhow::Result<()> {
    let scanner = secguard_secrets::Scanner::new();

    if let Some(dir) = dir {
        scan_directory(&scanner, &dir, format)?;
    } else {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        let findings = scanner.scan(&input);
        print_findings(&findings, format);
        if !findings.is_empty() {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn scan_directory(
    scanner: &secguard_secrets::Scanner,
    dir: &str,
    format: &str,
) -> anyhow::Result<()> {
    let mut found_any = false;
    for entry in walkdir(dir)? {
        let content = match std::fs::read_to_string(&entry) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let findings = scanner.scan(&content);
        if !findings.is_empty() {
            found_any = true;
            if format == "json" {
                for f in &findings {
                    let json = serde_json::json!({
                        "file": entry,
                        "rule": f.rule_id,
                        "description": f.description,
                        "line": content[..f.start].matches('\n').count() + 1,
                        "preview": f.matched_preview,
                    });
                    println!("{}", serde_json::to_string(&json)?);
                }
            } else {
                eprintln!("{}:", entry);
                for f in &findings {
                    let line = content[..f.start].matches('\n').count() + 1;
                    eprintln!(
                        "  line {}: {} [{}] ({})",
                        line, f.description, f.rule_id, f.matched_preview
                    );
                }
            }
        }
    }
    if found_any {
        std::process::exit(1);
    }
    Ok(())
}

fn walkdir(dir: &str) -> anyhow::Result<Vec<String>> {
    let mut files = Vec::new();
    walk_recursive(dir, &mut files)?;
    Ok(files)
}

fn walk_recursive(dir: &str, files: &mut Vec<String>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();

        if path.is_dir() {
            if matches!(
                name.as_ref(),
                ".git" | ".hg" | ".svn" | "node_modules" | "target" | "__pycache__"
            ) {
                continue;
            }
            walk_recursive(&path.to_string_lossy(), files)?;
        } else if path.is_file() {
            files.push(path.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

fn print_findings(findings: &[secguard_secrets::Finding], format: &str) {
    if format == "json" {
        for f in findings {
            let json = serde_json::json!({
                "rule": f.rule_id,
                "description": f.description,
                "start": f.start,
                "end": f.end,
                "preview": f.matched_preview,
            });
            println!("{}", serde_json::to_string(&json).unwrap_or_default());
        }
    } else {
        for f in findings {
            eprintln!("[{}] {} ({})", f.rule_id, f.description, f.matched_preview);
        }
    }
}
