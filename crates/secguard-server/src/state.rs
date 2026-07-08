use std::sync::Arc;

use crate::metrics::Metrics;
use crate::response::HookTarget;

pub struct AppState {
    pub scanner: secguard_secrets::Scanner,
    pub guard_config: secguard_guard::GuardConfig,
    pub target: HookTarget,
    pub metrics: Metrics,
    pub auth_token: Option<String>,
}

impl AppState {
    pub fn new(target: HookTarget, guard_config: secguard_guard::GuardConfig) -> Arc<Self> {
        let auth_token = std::env::var("SECGUARD_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        if auth_token.is_some() {
            log::info!("bearer token auth enabled for /hook/* endpoints");
        } else {
            log::info!("no SECGUARD_TOKEN set — auth disabled");
        }

        Arc::new(Self {
            scanner: secguard_secrets::Scanner::new(),
            guard_config,
            target,
            metrics: Metrics::new(),
            auth_token,
        })
    }
}
