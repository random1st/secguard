use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::ValueEnum;

const SECGUARD_REPO: &str = "random1st/secguard-models";
const PRIVACY_FILTER_REPO: &str = "openai/privacy-filter";

const GUARD_FILES: &[ModelFile] = &[ModelFile {
    remote_path: "secguard-guard.gguf",
    local_path: "secguard-guard.gguf",
}];

const PRIVACY_FILTER_FILES: &[ModelFile] = &[
    ModelFile {
        remote_path: "config.json",
        local_path: "openai-privacy-filter/config.json",
    },
    ModelFile {
        remote_path: "tokenizer.json",
        local_path: "openai-privacy-filter/tokenizer.json",
    },
    ModelFile {
        remote_path: "tokenizer_config.json",
        local_path: "openai-privacy-filter/tokenizer_config.json",
    },
    ModelFile {
        remote_path: "viterbi_calibration.json",
        local_path: "openai-privacy-filter/viterbi_calibration.json",
    },
    ModelFile {
        remote_path: "onnx/model_q4.onnx",
        local_path: "openai-privacy-filter/onnx/model_q4.onnx",
    },
    ModelFile {
        remote_path: "onnx/model_q4.onnx_data",
        local_path: "openai-privacy-filter/onnx/model_q4.onnx_data",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ModelTarget {
    /// secguard's GGUF guard classifier.
    Guard,
    /// OpenAI Privacy Filter q4 ONNX bundle for local PII redaction runtimes.
    PrivacyFilter,
}

#[derive(Clone, Copy)]
struct ModelFile {
    remote_path: &'static str,
    local_path: &'static str,
}

struct ModelBundle {
    display_name: &'static str,
    repo: &'static str,
    marker_name: &'static str,
    files: &'static [ModelFile],
}

impl ModelTarget {
    fn bundle(self) -> ModelBundle {
        match self {
            Self::Guard => ModelBundle {
                display_name: "secguard guard classifier",
                repo: SECGUARD_REPO,
                marker_name: ".installed",
                files: GUARD_FILES,
            },
            Self::PrivacyFilter => ModelBundle {
                display_name: "OpenAI Privacy Filter q4 ONNX bundle",
                repo: PRIVACY_FILTER_REPO,
                marker_name: ".installed-openai-privacy-filter",
                files: PRIVACY_FILTER_FILES,
            },
        }
    }
}

fn models_dir() -> PathBuf {
    dirs::home_dir()
        .expect("no home directory")
        .join(".secguard")
        .join("models")
}

fn sidecar_path(dest: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let file_name = dest
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("invalid model destination: {}", dest.display()))?
        .to_string_lossy();
    Ok(dest.with_file_name(format!("{file_name}{suffix}")))
}

fn head(url: &str) -> anyhow::Result<(String, u64)> {
    let out = std::process::Command::new("curl")
        .args(["-sIL", url])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("HEAD request failed for {url}");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // HF LFS files: the canonical fingerprint lives on the hub redirect as
    // `x-linked-etag` / `x-linked-size`. The final CDN hop may omit ETag
    // entirely and its own `content-length` is what we verify on download.
    // Prefer x-linked-* when present; fall back to standard headers.
    let mut etag: Option<String> = None;
    let mut x_linked_etag: Option<String> = None;
    let mut length: Option<u64> = None;
    let mut x_linked_size: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        let Some(colon) = line.find(':') else {
            continue;
        };
        let (name, value) = line.split_at(colon);
        let value = value[1..].trim();
        let clean = |v: &str| v.trim_start_matches("W/").trim_matches('"').to_string();
        match name.trim().to_ascii_lowercase().as_str() {
            "etag" => etag = Some(clean(value)),
            "x-linked-etag" => x_linked_etag = Some(clean(value)),
            "content-length" => length = value.parse::<u64>().ok(),
            "x-linked-size" => x_linked_size = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    match (x_linked_etag.or(etag), x_linked_size.or(length)) {
        (Some(e), Some(l)) => Ok((e, l)),
        _ => anyhow::bail!("could not parse ETag/Content-Length from HEAD response for {url}"),
    }
}

pub fn run(dir: Option<String>, target_model: ModelTarget) -> anyhow::Result<()> {
    let target = dir.map(PathBuf::from).unwrap_or_else(models_dir);
    fs::create_dir_all(&target)?;
    let bundle = target_model.bundle();

    eprintln!(
        "Installing {} from huggingface:{}\n",
        bundle.display_name, bundle.repo
    );

    for file in bundle.files {
        let dest = target.join(file.local_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let part = sidecar_path(&dest, ".part")?;
        let meta = sidecar_path(&dest, ".part.etag")?;
        let url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            bundle.repo, file.remote_path
        );

        eprintln!("{}: checking remote...", file.local_path);
        let (remote_etag, remote_size) = head(&url)?;

        if dest.exists() {
            let size = fs::metadata(&dest)?.len();
            if size == remote_size {
                eprintln!(
                    "{}: already up to date ({:.1}MB), skipping",
                    file.local_path,
                    size as f64 / 1024.0 / 1024.0
                );
                continue;
            }
            eprintln!(
                "{}: local size {size}B != remote {remote_size}B — discarding and re-downloading",
                file.local_path
            );
            fs::remove_file(&dest)?;
            let _ = fs::remove_file(&part);
            let _ = fs::remove_file(&meta);
        }

        if part.exists() {
            let stored = fs::read_to_string(&meta).ok().map(|s| s.trim().to_string());
            let matches = stored.as_deref() == Some(remote_etag.as_str());
            let part_size = fs::metadata(&part)?.len();

            if !matches {
                eprintln!(
                    "{}: stale partial (different version) — restarting",
                    file.local_path
                );
                fs::remove_file(&part)?;
                let _ = fs::remove_file(&meta);
            } else if part_size > remote_size {
                eprintln!(
                    "{}: partial larger than remote — restarting",
                    file.local_path
                );
                fs::remove_file(&part)?;
                let _ = fs::remove_file(&meta);
            } else {
                eprintln!(
                    "{}: resuming from {:.1}MB / {:.1}MB...",
                    file.local_path,
                    part_size as f64 / 1024.0 / 1024.0,
                    remote_size as f64 / 1024.0 / 1024.0,
                );
            }
        }

        if !part.exists() {
            eprintln!(
                "{}: downloading (~{:.0}MB)...",
                file.local_path,
                remote_size as f64 / 1024.0 / 1024.0
            );
        }

        fs::write(&meta, &remote_etag)?;

        let status = std::process::Command::new("curl")
            .args(["-fL", "-#", "-C", "-", "-o"])
            .arg(&part)
            .arg(&url)
            .stdin(std::process::Stdio::null())
            .status()?;

        if !status.success() {
            anyhow::bail!(
                "download failed for {} (run again to resume)",
                file.local_path
            );
        }

        let size = fs::metadata(&part)?.len();
        if size != remote_size {
            anyhow::bail!(
                "{}: downloaded {:.1}MB but expected {:.1}MB (run again to resume)",
                file.local_path,
                size as f64 / 1024.0 / 1024.0,
                remote_size as f64 / 1024.0 / 1024.0
            );
        }

        fs::rename(&part, &dest)?;
        let _ = fs::remove_file(&meta);
        eprintln!(
            "{}: done ({:.1}MB)",
            file.local_path,
            size as f64 / 1024.0 / 1024.0
        );
    }

    eprintln!("\nModels installed to: {}", target.display());
    let mut f = fs::File::create(target.join(bundle.marker_name))?;
    writeln!(f, "huggingface:{}", bundle.repo)?;
    writeln!(f, "bundle:{}", bundle.display_name)?;

    Ok(())
}
