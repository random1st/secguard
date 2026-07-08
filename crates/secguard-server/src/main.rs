use clap::Parser;

mod app;
mod auth;
mod handlers;
mod metrics;
mod response;
mod state;

#[derive(Parser)]
#[command(
    name = "secguard-server",
    version,
    about = "HTTP server for secguard security hooks"
)]
struct Cli {
    /// Listen port
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Output format target
    #[arg(long, value_enum, default_value_t = response::HookTarget::Claude)]
    target: response::HookTarget,

    /// Guard config JSON file (optional)
    #[arg(long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let guard_config = match &cli.config {
        Some(path) => {
            let content = std::fs::read_to_string(path)?;
            serde_json::from_str(&content)?
        }
        None => secguard_guard::GuardConfig::default(),
    };

    let state = state::AppState::new(cli.target, guard_config);
    let app = app::router(state);

    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    log::info!("secguard-server listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    log::info!("shutdown signal received");
}
