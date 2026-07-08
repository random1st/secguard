use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;

use crate::metrics::{OutcomeLabels, RuleLabels, VerdictLabels};
use crate::response;
use crate::state::AppState;

pub async fn guard(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tool_name = body.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");

    let Some(text) = response::text_to_check(tool_name, &body) else {
        state
            .metrics
            .guard_requests
            .get_or_create(&VerdictLabels {
                verdict: "skipped".into(),
            })
            .inc();
        return (StatusCode::OK, Json(serde_json::json!({})));
    };

    if text.is_empty() {
        state
            .metrics
            .guard_requests
            .get_or_create(&VerdictLabels {
                verdict: "skipped".into(),
            })
            .inc();
        return (StatusCode::OK, Json(serde_json::json!({})));
    }

    let start = std::time::Instant::now();
    let detail = secguard_guard::check_detailed(&text, &state.guard_config);
    let elapsed = start.elapsed().as_secs_f64();
    state.metrics.guard_duration.observe(elapsed);

    let source = serde_json::to_string(&detail.source).unwrap_or_default();
    let rule_id_str = detail
        .rule_id
        .map(|id| format!("\"{}\"", id.as_code()))
        .unwrap_or_else(|| "null".into());

    match &detail.verdict {
        secguard_guard::Verdict::Destructive(reason) => {
            state
                .metrics
                .guard_requests
                .get_or_create(&VerdictLabels {
                    verdict: "destructive".into(),
                })
                .inc();

            let display = redact_and_truncate(&text, &state.scanner, 200);

            log::info!(
                "{{\"mode\":\"guard\",\"verdict\":\"destructive\",\"source\":{},\"rule_id\":{},\"command\":{},\"reason\":{},\"latency_ms\":{:.3}}}",
                source,
                rule_id_str,
                serde_json::to_string(&display).unwrap_or_default(),
                serde_json::to_string(reason).unwrap_or_default(),
                elapsed * 1000.0,
            );

            let reason_text = format!("\u{26a0}\u{fe0f} Destructive: {reason}\nCommand: {display}");
            let hook_event_name = response::incoming_hook_event_name(&body);
            let json = response::guard_block(state.target, &hook_event_name, &reason_text);
            (StatusCode::OK, Json(json))
        }
        secguard_guard::Verdict::Safe => {
            state
                .metrics
                .guard_requests
                .get_or_create(&VerdictLabels {
                    verdict: "safe".into(),
                })
                .inc();

            log::debug!(
                "{{\"mode\":\"guard\",\"verdict\":\"safe\",\"source\":{},\"latency_ms\":{:.3}}}",
                source,
                elapsed * 1000.0,
            );

            (StatusCode::OK, Json(serde_json::json!({})))
        }
    }
}

pub async fn secrets_scan(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut input_clone = body
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let start = std::time::Instant::now();
    let findings = secguard_secrets::redact_value(&mut input_clone, &state.scanner);
    let elapsed = start.elapsed().as_secs_f64();
    state.metrics.secrets_duration.observe(elapsed);

    if findings.is_empty() {
        state
            .metrics
            .secrets_requests
            .get_or_create(&OutcomeLabels {
                outcome: "clean".into(),
            })
            .inc();
        return (StatusCode::OK, Json(serde_json::json!({})));
    }

    state
        .metrics
        .secrets_requests
        .get_or_create(&OutcomeLabels {
            outcome: "redacted".into(),
        })
        .inc();

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    for finding in &findings {
        state
            .metrics
            .secrets_findings
            .get_or_create(&RuleLabels {
                rule_id: finding.rule_id.clone(),
            })
            .inc();
    }

    log::info!(
        "{{\"mode\":\"secrets-scan\",\"findings\":{},\"rule_ids\":{},\"latency_ms\":{:.3}}}",
        findings.len(),
        serde_json::to_string(&rule_ids).unwrap_or_default(),
        elapsed * 1000.0,
    );

    let types: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    let unique_types: std::collections::BTreeSet<&str> = types.into_iter().collect();
    let context = format!(
        "[secguard] Redacted {} credential(s). Types: {}",
        findings.len(),
        unique_types.into_iter().collect::<Vec<_>>().join(", ")
    );

    let hook_event_name = response::incoming_hook_event_name(&body);
    let json = response::secrets_redacted(state.target, &hook_event_name, &context, input_clone);
    (StatusCode::OK, Json(json))
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let mut truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        truncated.push_str("...");
    }
    truncated
}

fn redact_and_truncate(
    text: &str,
    scanner: &secguard_secrets::Scanner,
    max_chars: usize,
) -> String {
    let findings = scanner.scan(text);
    truncate_chars(&secguard_secrets::redact(text, &findings), max_chars)
}
