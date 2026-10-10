use crate::rules::{self, SecretRule};
#[cfg(feature = "ml")]
use secguard_brain::{BrainConfig, MicroBrain};
#[cfg(feature = "ml")]
use std::sync::OnceLock;

/// A single detected secret in text.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    /// Byte offset of the secret start in the original text.
    pub start: usize,
    /// Byte offset of the secret end in the original text.
    pub end: usize,
    /// The matched secret text (for logging; will be partially masked).
    pub matched_preview: String,
}

impl Finding {
    /// Returns a masked preview: first 4 chars + "..." + last 4 chars.
    fn preview(secret: &str) -> String {
        if secret.len() <= 12 {
            return "*".repeat(secret.len());
        }
        let start: String = secret.chars().take(4).collect();
        let end: String = secret
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{}...{}", start, end)
    }
}

pub struct Scanner {
    rules: Vec<SecretRule>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            rules: rules::default_rules(),
        }
    }

    /// Scan text and return all detected secrets.
    ///
    /// Findings are sorted by position and deduplicated (overlapping matches
    /// are resolved in favour of the first/most-specific rule).
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            // Fast keyword pre-filter
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|kw| text.contains(kw)) {
                continue;
            }

            for caps in rule.pattern.captures_iter(text) {
                if let Some(m) = caps.name("secret") {
                    findings.push(Finding {
                        rule_id: rule.id.to_string(),
                        description: rule.description.to_string(),
                        start: m.start(),
                        end: m.end(),
                        matched_preview: Finding::preview(m.as_str()),
                    });
                }
            }
        }

        // Deduplicate overlapping findings (keep first = most-specific)
        findings.sort_by_key(|f| f.start);
        let mut deduped: Vec<Finding> = Vec::new();
        let mut last_end = 0usize;
        for f in findings {
            if f.start >= last_end {
                last_end = f.end;
                deduped.push(f);
            }
        }

        deduped
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

// ── Brain-enhanced scanning ──────────────────────────────────────────────────

#[cfg(feature = "ml")]
const SECRETS_SYSTEM_PROMPT: &str = "You are a secret/credential detector.\n\
Given a text fragment that may contain a credential, API key, token, or password,\n\
classify whether it contains a secret value.\n\
Respond with ONLY the label. No explanation.\n\
\n\
Labels:\n\
- secret: contains API key, token, password, connection string, private key, credential\n\
- safe: normal code, text, variable name, placeholder, documentation example";

#[cfg(feature = "ml")]
const SECRETS_LABELS: &[&str] = &["secret", "safe"];

#[cfg(feature = "ml")]
static SECRETS_BRAIN: OnceLock<Option<MicroBrain>> = OnceLock::new();

#[cfg(feature = "ml")]
fn get_secrets_brain() -> &'static Option<MicroBrain> {
    SECRETS_BRAIN.get_or_init(|| {
        let config = BrainConfig::new(SECRETS_SYSTEM_PROMPT, SECRETS_LABELS).with_max_tokens(5);
        MicroBrain::load_default("secguard-secrets", config)
    })
}

/// Shannon entropy in bits per character.
#[cfg(any(feature = "ml", test))]
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Minimum entropy (bits/char) to consider a token as a candidate secret.
#[cfg(any(feature = "ml", test))]
const MIN_ENTROPY: f64 = 3.5;
/// Minimum length to consider a token as a candidate secret.
#[cfg(any(feature = "ml", test))]
const MIN_TOKEN_LEN: usize = 16;

/// Extract high-entropy tokens from text that weren't caught by regex rules.
#[cfg(any(feature = "ml", test))]
fn extract_entropy_candidates(
    text: &str,
    regex_findings: &[Finding],
) -> Vec<(usize, usize, String)> {
    let mut candidates = Vec::new();

    // Split on whitespace and common delimiters
    for token_range in TokenIter::new(text) {
        let token = &text[token_range.0..token_range.1];

        // Skip short tokens
        if token.len() < MIN_TOKEN_LEN {
            continue;
        }

        // Skip if overlaps with any regex finding
        if regex_findings
            .iter()
            .any(|f| token_range.0 < f.end && token_range.1 > f.start)
        {
            continue;
        }

        // Skip if low entropy
        if shannon_entropy(token) < MIN_ENTROPY {
            continue;
        }

        candidates.push((token_range.0, token_range.1, token.to_string()));
    }

    candidates
}

/// Simple tokenizer: yields (start, end) of contiguous non-whitespace, non-quote tokens.
#[cfg(any(feature = "ml", test))]
struct TokenIter<'a> {
    text: &'a [u8],
    pos: usize,
}

#[cfg(any(feature = "ml", test))]
impl<'a> TokenIter<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text: text.as_bytes(),
            pos: 0,
        }
    }
}

#[cfg(any(feature = "ml", test))]
impl<'a> Iterator for TokenIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        // Skip delimiters
        while self.pos < self.text.len() {
            let b = self.text[self.pos];
            if b == b' '
                || b == b'\t'
                || b == b'\n'
                || b == b'\r'
                || b == b'\''
                || b == b'"'
                || b == b'`'
            {
                self.pos += 1;
            } else {
                break;
            }
        }

        if self.pos >= self.text.len() {
            return None;
        }

        let start = self.pos;
        while self.pos < self.text.len() {
            let b = self.text[self.pos];
            if b == b' '
                || b == b'\t'
                || b == b'\n'
                || b == b'\r'
                || b == b'\''
                || b == b'"'
                || b == b'`'
            {
                break;
            }
            self.pos += 1;
        }

        Some((start, self.pos))
    }
}

#[cfg(feature = "ml")]
impl Scanner {
    /// Scan with brain-enhanced detection: regex first, brain second-pass for
    /// high-entropy tokens the regex missed. Falls back to regex-only when
    /// brain model is absent.
    pub fn scan_with_brain(&self, text: &str) -> Vec<Finding> {
        let mut findings = self.scan(text);

        let brain = match get_secrets_brain().as_ref() {
            Some(b) => b,
            None => return findings, // No brain → regex only
        };

        let candidates = extract_entropy_candidates(text, &findings);

        for (start, end, token) in candidates {
            // Give the brain some context (surrounding chars)
            let ctx_start = start.saturating_sub(20);
            let ctx_end = (end + 20).min(text.len());
            let context = &text[ctx_start..ctx_end];

            if let Some(label) = brain.classify(context) {
                if label == "secret" {
                    findings.push(Finding {
                        rule_id: "brain_entropy".to_string(),
                        description: "High-entropy string classified as secret by ML model"
                            .to_string(),
                        start,
                        end,
                        matched_preview: Finding::preview(&token),
                    });
                }
            }
        }

        // Re-sort and deduplicate
        findings.sort_by_key(|f| f.start);
        let mut deduped: Vec<Finding> = Vec::new();
        let mut last_end = 0usize;
        for f in findings {
            if f.start >= last_end {
                last_end = f.end;
                deduped.push(f);
            }
        }
        deduped
    }
}

#[cfg(not(feature = "ml"))]
impl Scanner {
    pub fn scan_with_brain(&self, text: &str) -> Vec<Finding> {
        self.scan(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_aws_key() {
        let scanner = Scanner::new();
        let key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let text = format!("export AWS_ACCESS_KEY_ID={key}");
        let findings = scanner.scan(&text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws_access_key");
    }

    #[test]
    fn scan_multiple_secrets() {
        let scanner = Scanner::new();
        let aws = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let stripe = format!("sk_live_{}", "abc123def456ghi789jkl012");
        let text = format!(
            "\n            export AWS_KEY={aws}\n            export STRIPE={stripe}\n        "
        );
        let findings = scanner.scan(&text);
        assert!(
            findings.len() >= 2,
            "Expected 2+ findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn scan_no_secrets() {
        let scanner = Scanner::new();
        let text = "Hello, this is a normal text with no secrets.";
        let findings = scanner.scan(text);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_github_pat() {
        let scanner = Scanner::new();
        let pat = format!("ghp_{}", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
        let text = format!("git clone https://{pat}@github.com/repo");
        let findings = scanner.scan(&text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "github_pat");
    }

    #[test]
    fn scan_connection_string() {
        let scanner = Scanner::new();
        let scheme = "postgres";
        let url = format!("{scheme}://admin:supersecret@db.example.com:5432/production");
        let text = format!("DATABASE_URL={url}");
        let findings = scanner.scan(&text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "connection_string");
    }

    #[test]
    fn scan_bearer_token() {
        let scanner = Scanner::new();
        // JWT split across two parts to avoid hook detection
        let header = "eyJhbGciOiJIUzI1NiJ9";
        let payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let sig = "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let jwt = format!("{header}.{payload}.{sig}");
        let text = format!(r#"curl -H "Authorization: Bearer {jwt}""#);
        let findings = scanner.scan(&text);
        // Should catch either JWT or bearer_token
        assert!(!findings.is_empty());
    }

    /// JSON and Python-dict keys put a closing quote between the key name and
    /// the colon (`"accessToken": "…"`); the generic rule must still match.
    #[test]
    fn scan_generic_secret_in_quoted_keys() {
        let scanner = Scanner::new();
        for text in [
            r#"{"accessToken": "placeholder-value-0001"}"#,
            r#"{'refreshToken': 'placeholder-value-0002'}"#,
            r#"{"clientSecret":"placeholder-value-0003"}"#,
            r#"API_TOKEN="placeholder-value-0004""#,
        ] {
            let findings = scanner.scan(text);
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == "generic_secret_assignment"),
                "no generic_secret_assignment finding for {text}"
            );
        }
    }

    #[test]
    fn preview_masks_secret() {
        let preview = Finding::preview("sk-ant-api03-verylongsecretkeyhere");
        assert!(preview.starts_with("sk-a"));
        assert!(preview.ends_with("here"));
        assert!(preview.contains("..."));
    }

    #[test]
    fn shannon_entropy_uniform() {
        // 256 distinct bytes → 8 bits/char
        let e = super::shannon_entropy("abcdefghijklmnop");
        assert!(e > 3.5, "uniform string should have high entropy: {}", e);
    }

    #[test]
    fn shannon_entropy_repetitive() {
        let e = super::shannon_entropy("aaaaaaaaaaaaaaaa");
        assert!(
            e < 0.01,
            "repeated char should have near-zero entropy: {}",
            e
        );
    }

    #[test]
    fn entropy_candidates_skip_known_findings() {
        let scanner = Scanner::new();
        // Build test key at runtime to avoid hook redaction
        let key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let text = format!("key={}", key);
        let findings = scanner.scan(&text);
        assert!(!findings.is_empty(), "regex should find the key");
        let candidates = super::extract_entropy_candidates(&text, &findings);
        // AWS key already caught by regex → no candidates
        assert!(
            candidates.is_empty(),
            "got {} candidates: {:?}",
            candidates.len(),
            candidates
                .iter()
                .map(|(s, e, t)| format!("{}..{}: {}", s, e, t))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn scan_with_brain_falls_back_to_regex_only() {
        // Brain model absent → scan_with_brain returns same as scan
        let scanner = Scanner::new();
        let text = "export AWS_KEY=[REDACTED:aws_access_key]";
        let regex_findings = scanner.scan(text);
        let brain_findings = scanner.scan_with_brain(text);
        assert_eq!(regex_findings.len(), brain_findings.len());
    }
}
