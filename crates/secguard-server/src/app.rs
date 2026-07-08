use axum::{middleware, routing, Router};
use std::sync::Arc;

use crate::auth;
use crate::handlers;
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    let hook_routes = Router::new()
        .route("/hook/guard", routing::post(handlers::hook::guard))
        .route(
            "/hook/secrets-scan",
            routing::post(handlers::hook::secrets_scan),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::bearer_auth,
        ));

    let public_routes = Router::new()
        .route("/healthz", routing::get(handlers::health::healthz))
        .route("/readyz", routing::get(handlers::health::readyz))
        .route("/metrics", routing::get(handlers::health::metrics));

    Router::new()
        .merge(hook_routes)
        .merge(public_routes)
        .with_state(state)
}
