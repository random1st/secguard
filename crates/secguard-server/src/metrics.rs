use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::Mutex;

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct VerdictLabels {
    pub verdict: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct OutcomeLabels {
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct RuleLabels {
    pub rule_id: String,
}

pub struct Metrics {
    registry: Mutex<Registry>,
    pub guard_requests: Family<VerdictLabels, Counter>,
    pub secrets_requests: Family<OutcomeLabels, Counter>,
    pub secrets_findings: Family<RuleLabels, Counter>,
    pub guard_duration: Histogram,
    pub secrets_duration: Histogram,
    pub auth_failures: Counter,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let guard_requests = Family::<VerdictLabels, Counter>::default();
        registry.register(
            "secguard_guard_requests",
            "Total guard check requests",
            guard_requests.clone(),
        );

        let secrets_requests = Family::<OutcomeLabels, Counter>::default();
        registry.register(
            "secguard_secrets_requests",
            "Total secrets scan requests",
            secrets_requests.clone(),
        );

        let secrets_findings = Family::<RuleLabels, Counter>::default();
        registry.register(
            "secguard_secrets_findings",
            "Total individual secret findings",
            secrets_findings.clone(),
        );

        let guard_duration = Histogram::new(exponential_buckets(0.0001, 2.0, 16));
        registry.register(
            "secguard_guard_duration_seconds",
            "Guard check latency",
            guard_duration.clone(),
        );

        let secrets_duration = Histogram::new(exponential_buckets(0.0001, 2.0, 16));
        registry.register(
            "secguard_secrets_duration_seconds",
            "Secrets scan latency",
            secrets_duration.clone(),
        );

        let auth_failures = Counter::default();
        registry.register(
            "secguard_auth_failures",
            "Authentication failures",
            auth_failures.clone(),
        );

        Self {
            registry: Mutex::new(registry),
            guard_requests,
            secrets_requests,
            secrets_findings,
            guard_duration,
            secrets_duration,
            auth_failures,
        }
    }

    pub fn encode(&self) -> String {
        let registry = self.registry.lock().unwrap();
        let mut buf = String::new();
        encode(&mut buf, &registry).unwrap();
        buf
    }
}
