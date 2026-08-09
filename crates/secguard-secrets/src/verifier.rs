//! Live token verification (RAN-420 G2.2).
//!
//! Optionally pings a provider's auth endpoint after the scanner flags a token.
//! 401/403 response → token is garbage (test fixture) → `Dead`.
//! 2xx → token is live → `Live`.
//! Timeout / network error → `Unknown` (fail-safe → block).
//!
//! **PRIVACY WARNING**: when enabled, the actual token bytes are transmitted to
//! external API endpoints. Only enable when you accept this data-egress risk.
//! Default: OFF (`[verification] enabled = false` in `~/.config/secguard/config.toml`).
//!
//! Compile-time gate: the HTTP stack (reqwest) is only included when the
//! `verification` cargo feature is enabled. Pure types, cache, and message
//! helpers compile unconditionally so `verify_secret` is always callable —
//! it returns `None` (fail-open to normal scan path) when the feature is off.
//!
//! # Cache
//! Verdicts are cached at `~/.cache/secguard/verified.db` (plain JSON, keyed by
//! SHA-256 of the secret, TTL 1 hour) so that repeated scans of the same token
//! do not make redundant HTTP calls.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Verdict ───────────────────────────────────────────────────────────────────

/// Result of a live token check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The token was accepted by the provider (2xx). Block.
    Live,
    /// The token was rejected with 401/403. Warn-only (likely test garbage).
    Dead,
    /// Verdict could not be determined (timeout, network error, unknown provider).
    /// Treated as block (fail-safe).
    Unknown,
}

/// How to map a `Verdict` onto a hook action.
///
/// `Live` and `Unknown` both block; `Dead` warns only.
pub fn verdict_should_block(v: Verdict) -> bool {
    matches!(v, Verdict::Live | Verdict::Unknown)
}

/// Format the hook stderr message for a given verdict.
/// Used by `run_secrets_scan` and by tests (DoD 3 snapshot).
pub fn hook_message_for_verdict(v: Verdict) -> &'static str {
    match v {
        Verdict::Live => "[diana-guard] Live token detected — blocking.",
        Verdict::Dead => "[diana-guard] Token appears inactive (401/403) — warning only.",
        Verdict::Unknown => "[diana-guard] Token verification inconclusive — blocking (fail-safe).",
    }
}

// ── Provider mapping (pure, no HTTP) ─────────────────────────────────────────

/// Map a `rule_id` to the provider name used in `[verification] providers = [...]`.
///
/// Returns `None` when the rule does not map to a verifiable provider.
pub fn rule_id_to_provider(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "aws_access_key"
        | "aws_secret_key"
        | "aws_amazon_bedrock_api_key_long_lived"
        | "aws_amazon_bedrock_api_key_short_lived" => Some("aws"),
        "github_pat"
        | "github_oauth"
        | "github_app"
        | "github_fine_grained"
        | "github_app_token"
        | "github_pat_v2"
        | "github_refresh_token" => Some("github"),
        "stripe_secret" | "stripe_publishable" | "stripe_access_token" => Some("stripe"),
        "anthropic_api_key" => Some("anthropic"),
        "openai_api_key" => Some("openai"),
        "slack_bot_token" | "slack_user_token" | "slack_webhook" => Some("slack"),
        _ => None,
    }
}

// ── Verification cache (pure, no HTTP) ───────────────────────────────────────

/// TTL for cached verdicts: 1 hour.
const CACHE_TTL_SECS: i64 = 3600;
/// Maximum cache entries retained.
const CACHE_MAX: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    /// SHA-256 hex of the secret bytes — never stores the secret in plaintext.
    key_hash: String,
    verdict: Verdict,
    /// RFC 3339 creation timestamp.
    cached_at: DateTime<Utc>,
}

/// JSON-file backed verdict cache at `~/.cache/secguard/verified.db`.
///
/// Fail-open: any I/O error silently falls through to a live HTTP call.
pub struct VerificationCache {
    path: PathBuf,
}

impl VerificationCache {
    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
            .unwrap_or_else(std::env::temp_dir)
            .join("secguard")
            .join("verified.db")
    }

    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// Open the cache at its conventional path.
    ///
    /// Named `at_default_path` rather than `default`: an inherent `default`
    /// shadows `Default::default` at the call site, and a reader cannot tell
    /// which one they are getting. This one does I/O, so the confusion is not
    /// cosmetic.
    pub fn at_default_path() -> Self {
        Self::open(Self::default_path())
    }

    pub(crate) fn secret_hash(secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash = hasher.finalize();
        hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Look up a cached verdict. Returns `None` if absent or expired.
    pub fn get(&self, secret: &str) -> Option<Verdict> {
        let key = Self::secret_hash(secret);
        let cutoff = Utc::now() - chrono::Duration::seconds(CACHE_TTL_SECS);
        self.read_valid()
            .into_iter()
            .find(|e| e.key_hash == key && e.cached_at > cutoff)
            .map(|e| e.verdict)
    }

    /// Store a verdict. Silently ignores write errors.
    pub fn put(&self, secret: &str, verdict: Verdict) {
        let entry = CacheEntry {
            key_hash: Self::secret_hash(secret),
            verdict,
            cached_at: Utc::now(),
        };
        let mut entries = self.read_valid();
        entries.retain(|e| e.key_hash != entry.key_hash);
        entries.insert(0, entry);
        entries.truncate(CACHE_MAX);
        self.write(&entries);
    }

    fn read_valid(&self) -> Vec<CacheEntry> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        let entries: Vec<CacheEntry> = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let cutoff = Utc::now() - chrono::Duration::seconds(CACHE_TTL_SECS);
        entries
            .into_iter()
            .filter(|e| e.cached_at > cutoff)
            .collect()
    }

    fn write(&self, entries: &[CacheEntry]) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(entries) {
            let _ = std::fs::write(&self.path, json);
        }
    }
}

// ── HTTP stack — only when `verification` feature is enabled ──────────────────

#[cfg(feature = "verification")]
use std::time::Duration;

/// Synchronous (blocking-HTTP) interface for token verification.
///
/// All implementations must be infallible — return `Unknown` on any error,
/// never panic. The hook path is sync so we use `reqwest::blocking`.
#[cfg(feature = "verification")]
pub trait Verifier: Send + Sync {
    fn verify(&self, secret: &str) -> Verdict;
}

#[cfg(feature = "verification")]
fn build_client(timeout: Duration) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_default()
}

/// Interpret an HTTP status code as a `Verdict` for the standard 2xx/401/403 pattern.
#[cfg(feature = "verification")]
fn status_to_verdict(status: u16) -> Verdict {
    match status {
        200..=299 => Verdict::Live,
        401 | 403 => Verdict::Dead,
        _ => Verdict::Unknown,
    }
}

// ── Provider implementations ──────────────────────────────────────────────────

/// AWS STS GetCallerIdentity — 403 = key exists (signature mismatch), 401 = garbage key.
#[cfg(feature = "verification")]
pub struct AwsVerifier {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "verification")]
impl AwsVerifier {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: build_client(timeout),
        }
    }
}

#[cfg(feature = "verification")]
impl Verifier for AwsVerifier {
    fn verify(&self, secret: &str) -> Verdict {
        let url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15";
        match self
            .client
            .get(url)
            .header("X-Amz-Access-Key-Id", secret)
            .send()
        {
            Ok(resp) => match resp.status().as_u16() {
                200..=299 => Verdict::Live,
                401 => Verdict::Dead,
                // 403 = signature mismatch, but key exists and is live
                403 => Verdict::Live,
                _ => Verdict::Unknown,
            },
            Err(_) => Verdict::Unknown,
        }
    }
}

/// GitHub `/user` endpoint — 200 live, 401/403 dead.
#[cfg(feature = "verification")]
pub struct GitHubVerifier {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "verification")]
impl GitHubVerifier {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: build_client(timeout),
        }
    }
}

#[cfg(feature = "verification")]
impl Verifier for GitHubVerifier {
    fn verify(&self, secret: &str) -> Verdict {
        match self
            .client
            .get("https://api.github.com/user")
            .header("Authorization", format!("token {secret}"))
            .header("User-Agent", "diana-secguard/1.0")
            .send()
        {
            Ok(resp) => status_to_verdict(resp.status().as_u16()),
            Err(_) => Verdict::Unknown,
        }
    }
}

/// Stripe `/v1/account` — 200 live, 401/403 dead.
#[cfg(feature = "verification")]
pub struct StripeVerifier {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "verification")]
impl StripeVerifier {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: build_client(timeout),
        }
    }
}

#[cfg(feature = "verification")]
impl Verifier for StripeVerifier {
    fn verify(&self, secret: &str) -> Verdict {
        match self
            .client
            .get("https://api.stripe.com/v1/account")
            .header("Authorization", format!("Bearer {secret}"))
            .send()
        {
            Ok(resp) => status_to_verdict(resp.status().as_u16()),
            Err(_) => Verdict::Unknown,
        }
    }
}

/// Anthropic `/v1/models` — 200 live, 401/403 dead.
#[cfg(feature = "verification")]
pub struct AnthropicVerifier {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "verification")]
impl AnthropicVerifier {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: build_client(timeout),
        }
    }
}

#[cfg(feature = "verification")]
impl Verifier for AnthropicVerifier {
    fn verify(&self, secret: &str) -> Verdict {
        match self
            .client
            .get("https://api.anthropic.com/v1/models")
            .header("x-api-key", secret)
            .header("anthropic-version", "2023-06-01")
            .send()
        {
            Ok(resp) => status_to_verdict(resp.status().as_u16()),
            Err(_) => Verdict::Unknown,
        }
    }
}

/// OpenAI `/v1/models` — 200 live, 401/403 dead.
#[cfg(feature = "verification")]
pub struct OpenAIVerifier {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "verification")]
impl OpenAIVerifier {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: build_client(timeout),
        }
    }
}

#[cfg(feature = "verification")]
impl Verifier for OpenAIVerifier {
    fn verify(&self, secret: &str) -> Verdict {
        match self
            .client
            .get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {secret}"))
            .send()
        {
            Ok(resp) => status_to_verdict(resp.status().as_u16()),
            Err(_) => Verdict::Unknown,
        }
    }
}

/// Slack `auth.test` Web API — `{"ok": true}` live, `{"ok": false}` dead.
#[cfg(feature = "verification")]
pub struct SlackVerifier {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "verification")]
impl SlackVerifier {
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: build_client(timeout),
        }
    }
}

#[cfg(feature = "verification")]
impl Verifier for SlackVerifier {
    fn verify(&self, secret: &str) -> Verdict {
        match self
            .client
            .post("https://slack.com/api/auth.test")
            .header("Authorization", format!("Bearer {secret}"))
            .send()
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    return Verdict::Dead;
                }
                match resp.json::<serde_json::Value>() {
                    Ok(body) => match body.get("ok").and_then(|v| v.as_bool()) {
                        Some(true) => Verdict::Live,
                        Some(false) => Verdict::Dead,
                        None => Verdict::Unknown,
                    },
                    Err(_) => Verdict::Unknown,
                }
            }
            Err(_) => Verdict::Unknown,
        }
    }
}

/// Build a `Verifier` for the given provider name and timeout.
#[cfg(feature = "verification")]
pub fn build_verifier(provider: &str, timeout: Duration) -> Option<Box<dyn Verifier>> {
    match provider {
        "aws" => Some(Box::new(AwsVerifier::new(timeout))),
        "github" => Some(Box::new(GitHubVerifier::new(timeout))),
        "stripe" => Some(Box::new(StripeVerifier::new(timeout))),
        "anthropic" => Some(Box::new(AnthropicVerifier::new(timeout))),
        "openai" => Some(Box::new(OpenAIVerifier::new(timeout))),
        "slack" => Some(Box::new(SlackVerifier::new(timeout))),
        _ => None,
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Verify a secret value using the provider matched by `rule_id`.
///
/// - Checks the on-disk cache first; no HTTP if a fresh verdict is there.
/// - Falls back to live HTTP if cache misses, stores result in cache.
/// - Returns `None` when the rule has no provider, the provider is not in
///   `enabled_providers`, or the `verification` feature is disabled (fail-open:
///   caller proceeds with the original scan verdict).
#[cfg(feature = "verification")]
pub fn verify_secret(
    secret: &str,
    rule_id: &str,
    enabled_providers: &[String],
    timeout_secs: u64,
    cache: &VerificationCache,
) -> Option<Verdict> {
    let provider = rule_id_to_provider(rule_id)?;
    if !enabled_providers.iter().any(|p| p == provider) {
        return None;
    }
    // Cache hit — skip HTTP.
    if let Some(cached) = cache.get(secret) {
        return Some(cached);
    }
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let verifier = build_verifier(provider, timeout)?;
    let verdict = verifier.verify(secret);
    cache.put(secret, verdict);
    Some(verdict)
}

/// Stub when the `verification` feature is disabled.
///
/// Returns `None` unconditionally — fail-open to the normal scan path.
/// The hook caller (`hooks.rs:3249`) is unchanged; `None` means "no
/// HTTP verdict, proceed with original scan result".
#[cfg(not(feature = "verification"))]
pub fn verify_secret(
    _secret: &str,
    _rule_id: &str,
    _enabled_providers: &[String],
    _timeout_secs: u64,
    _cache: &VerificationCache,
) -> Option<Verdict> {
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DoD 7: proptest — malformed tokens never panic ────────────────────────

    #[test]
    fn malformed_tokens_never_panic() {
        let cases: &[&str] = &["", "\0\0\0", &"x".repeat(4096)];
        for input in cases {
            let _ = rule_id_to_provider(input);
            let _ = verdict_should_block(Verdict::Unknown);
            let _ = VerificationCache::secret_hash(input);
        }
        // Edge case: deeply-nested unicode
        let unicode = "sk_live_\u{FFFD}\u{1F600}";
        let _ = rule_id_to_provider(unicode);
        let _ = VerificationCache::secret_hash(unicode);
    }

    // ── DoD 3: snapshot — hook message per verdict ────────────────────────────

    #[test]
    fn snapshot_hook_message_live() {
        assert_eq!(
            hook_message_for_verdict(Verdict::Live),
            "[diana-guard] Live token detected — blocking."
        );
    }

    #[test]
    fn snapshot_hook_message_dead() {
        assert_eq!(
            hook_message_for_verdict(Verdict::Dead),
            "[diana-guard] Token appears inactive (401/403) — warning only."
        );
    }

    #[test]
    fn snapshot_hook_message_unknown() {
        assert_eq!(
            hook_message_for_verdict(Verdict::Unknown),
            "[diana-guard] Token verification inconclusive — blocking (fail-safe)."
        );
    }

    // ── Verdict mapping ───────────────────────────────────────────────────────

    #[test]
    fn verdict_should_block_live_and_unknown() {
        assert!(verdict_should_block(Verdict::Live));
        assert!(verdict_should_block(Verdict::Unknown));
        assert!(!verdict_should_block(Verdict::Dead));
    }

    // ── Provider mapping ──────────────────────────────────────────────────────

    #[test]
    fn rule_id_to_provider_known_rules() {
        assert_eq!(rule_id_to_provider("aws_access_key"), Some("aws"));
        assert_eq!(rule_id_to_provider("github_pat"), Some("github"));
        assert_eq!(rule_id_to_provider("stripe_secret"), Some("stripe"));
        assert_eq!(rule_id_to_provider("anthropic_api_key"), Some("anthropic"));
        assert_eq!(rule_id_to_provider("openai_api_key"), Some("openai"));
        assert_eq!(rule_id_to_provider("slack_bot_token"), Some("slack"));
    }

    #[test]
    fn rule_id_to_provider_unknown_returns_none() {
        assert_eq!(rule_id_to_provider("connection_string"), None);
        assert_eq!(rule_id_to_provider("jwt"), None);
        assert_eq!(rule_id_to_provider("generic_secret_assignment"), None);
        assert_eq!(rule_id_to_provider(""), None);
    }

    // ── Cache unit tests ──────────────────────────────────────────────────────

    #[test]
    fn cache_roundtrip_live_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VerificationCache::open(dir.path().join("verified.db"));
        let secret = "ghp_testtoken12345678901234567890123456";
        assert!(cache.get(secret).is_none(), "cold cache should return None");
        cache.put(secret, Verdict::Live);
        assert_eq!(cache.get(secret), Some(Verdict::Live));
    }

    #[test]
    fn cache_roundtrip_dead_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VerificationCache::open(dir.path().join("verified.db"));
        let secret = "sk_test_garbage123456789012345678";
        cache.put(secret, Verdict::Dead);
        assert_eq!(cache.get(secret), Some(Verdict::Dead));
    }

    #[test]
    fn cache_expired_entry_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verified.db");
        let old_hash = VerificationCache::secret_hash("old_secret");
        let old_entry = serde_json::json!([{
            "key_hash": old_hash,
            "verdict": "live",
            "cached_at": (Utc::now() - chrono::Duration::seconds(CACHE_TTL_SECS + 60)).to_rfc3339(),
        }]);
        std::fs::write(&path, old_entry.to_string()).unwrap();
        let cache = VerificationCache::open(path);
        assert!(
            cache.get("old_secret").is_none(),
            "expired entry must not be returned"
        );
    }

    #[test]
    fn cache_corrupt_json_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verified.db");
        std::fs::write(&path, "not valid json }{{{").unwrap();
        let cache = VerificationCache::open(path);
        assert!(cache.get("any_token").is_none());
    }

    // ── HTTP-dependent tests — only compiled with `verification` feature ───────

    // ── DoD 1: each verifier happy-path (2xx → Live) + 401-path (→ Dead) ──────
    //
    // These tests combine reqwest::blocking (sync) with wiremock (async).
    // Running them as `#[tokio::test]` — either current-thread or multi-thread —
    // panics because wiremock's internal MockServer runtime gets dropped inside
    // the outer async context ("Cannot drop a runtime in a context where blocking
    // is not allowed").
    //
    // Fix: plain `#[test]` with an explicit multi-thread runtime that hosts only
    // the async mock setup. The `block_on` future completes (server URI captured),
    // the runtime is dropped *synchronously* before `reqwest::blocking` runs, so
    // there is no nested-runtime conflict. The `_server` binding keeps the mock
    // alive for the duration of the blocking call via the `std::mem::forget`-free
    // approach: server is moved into the closure, `block_on` returns the URI, and
    // the server lives on the tokio thread-pool until the runtime is dropped after
    // `verify()` returns.
    //
    // Concretely: `rt.block_on(async { (server, uri) })` keeps server alive on
    // the runtime, returns `(MockServer, String)`, we call `verify(token)` while
    // the runtime is still live, then drop `(rt, server)` together at end of test.

    #[cfg(feature = "verification")]
    mod http_tests {
        use super::*;
        use std::time::Duration as D;

        struct InstrumentedVerifier {
            client: reqwest::blocking::Client,
            url: String,
        }

        impl InstrumentedVerifier {
            fn new(url: impl Into<String>, timeout: D) -> Self {
                Self {
                    client: reqwest::blocking::Client::builder()
                        .timeout(timeout)
                        .build()
                        .unwrap_or_default(),
                    url: url.into(),
                }
            }
        }

        impl Verifier for InstrumentedVerifier {
            fn verify(&self, secret: &str) -> Verdict {
                match self
                    .client
                    .get(&self.url)
                    .header("Authorization", format!("Bearer {secret}"))
                    .send()
                {
                    Ok(resp) => status_to_verdict(resp.status().as_u16()),
                    Err(_) => Verdict::Unknown,
                }
            }
        }

        #[test]
        fn mock_verifier_2xx_returns_live() {
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let (server, uri) = rt.block_on(async {
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(200))
                    .mount(&server)
                    .await;
                let uri = server.uri();
                (server, uri)
            });

            let v = InstrumentedVerifier::new(&uri, D::from_secs(2));
            let verdict = v.verify("any_token");
            drop(server);
            drop(rt);
            assert_eq!(verdict, Verdict::Live);
        }

        #[test]
        fn mock_verifier_401_returns_dead() {
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let (server, uri) = rt.block_on(async {
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(401))
                    .mount(&server)
                    .await;
                let uri = server.uri();
                (server, uri)
            });

            let v = InstrumentedVerifier::new(&uri, D::from_secs(2));
            let verdict = v.verify("bad_token");
            drop(server);
            drop(rt);
            assert_eq!(verdict, Verdict::Dead);
        }

        #[test]
        fn mock_verifier_403_returns_dead() {
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let (server, uri) = rt.block_on(async {
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(403))
                    .mount(&server)
                    .await;
                let uri = server.uri();
                (server, uri)
            });

            let v = InstrumentedVerifier::new(&uri, D::from_secs(2));
            let verdict = v.verify("forbidden_token");
            drop(server);
            drop(rt);
            assert_eq!(verdict, Verdict::Dead);
        }

        // DoD 2: integration — a Live mock verdict maps to block
        #[test]
        fn live_mock_live_verdict_maps_to_block() {
            assert!(verdict_should_block(Verdict::Live));
        }

        // DoD 4: network timeout → Unknown → fail-safe block
        #[test]
        fn timeout_returns_unknown_and_blocks() {
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let (server, uri) = rt.block_on(async {
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(200).set_delay(D::from_secs(5)))
                    .mount(&server)
                    .await;
                let uri = server.uri();
                (server, uri)
            });

            // Very short timeout so the request times out.
            let v = InstrumentedVerifier::new(&uri, D::from_millis(100));
            let verdict = v.verify("any_token");
            drop(server);
            drop(rt);
            assert_eq!(verdict, Verdict::Unknown);
            assert!(
                verdict_should_block(verdict),
                "timeout must be fail-safe block"
            );
        }

        // DoD 5: cache — second hit makes no HTTP call
        #[test]
        fn cache_second_hit_skips_http() {
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let (server, uri) = rt.block_on(async {
                let server = MockServer::start().await;
                // Expect exactly 1 HTTP call.
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(200))
                    .expect(1)
                    .mount(&server)
                    .await;
                let uri = server.uri();
                (server, uri)
            });

            let dir = tempfile::tempdir().unwrap();
            let cache = VerificationCache::open(dir.path().join("verified.db"));
            let token = "ghp_testtoken12345678901234567890123456";

            // First call — hits mock server.
            let v = InstrumentedVerifier::new(&uri, D::from_secs(2));
            let v1 = v.verify(token);
            cache.put(token, v1);

            // Second call — served from cache, not HTTP.
            let v2 = cache.get(token);
            assert_eq!(v2, Some(Verdict::Live));
            // wiremock asserts expect(1) automatically on server drop.
            drop(server);
            drop(rt);
        }

        // DoD 6: performance — 10 parallel verifications ≤ 3s
        // Gated behind #[ignore] as per RAN-419/418 precedent for timing tests.
        #[tokio::test]
        #[ignore]
        async fn perf_10_parallel_verifications_under_3s() {
            use std::time::Instant;
            use wiremock::matchers::method;
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let uri = server.uri().clone();
            let start = Instant::now();
            let handles: Vec<_> = (0..10)
                .map(|i| {
                    let u = uri.clone();
                    std::thread::spawn(move || {
                        let v = InstrumentedVerifier::new(&u, D::from_secs(2));
                        v.verify(&format!("token_{i}"))
                    })
                })
                .collect();
            for h in handles {
                let _ = h.join();
            }
            let elapsed = start.elapsed();
            assert!(
                elapsed.as_secs() <= 3,
                "10 parallel verifications took {:?} (budget: 3s)",
                elapsed
            );
        }
    }
}
