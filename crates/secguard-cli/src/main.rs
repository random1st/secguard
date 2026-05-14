use clap::{Parser, Subcommand};

mod cmd_guard;
mod cmd_init;
pub(crate) mod cmd_model;
mod cmd_scan;
pub(crate) mod cmd_update;
mod hook;
mod telemetry;

#[derive(Parser)]
#[command(
    name = "secguard",
    version,
    about = "3-level security toolkit for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan text or files for secrets
    Scan {
        /// Directory to scan (default: read from stdin)
        #[arg(long)]
        dir: Option<String>,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Check if a shell command is destructive
    Guard {
        #[command(subcommand)]
        subcommand: Option<GuardSubcommand>,
        /// Command to check (reads from stdin if not provided; only valid without subcommand)
        command: Option<String>,
    },
    /// Claude Code / Gemini CLI / Codex hook mode (reads hook JSON from stdin)
    Hook {
        /// Hook type
        #[arg(value_enum)]
        mode: hook::HookMode,
        /// Target client (affects output format)
        #[arg(long, value_enum, default_value_t = hook::HookTarget::Claude)]
        target: hook::HookTarget,
    },
    /// Download optional ML model bundles from Hugging Face
    Model {
        /// Model bundle to install
        #[arg(long, value_enum, default_value_t = cmd_model::ModelTarget::Guard)]
        model: cmd_model::ModelTarget,
        /// Target directory (default: ~/.secguard/models/)
        #[arg(long)]
        dir: Option<String>,
    },
    /// Install secguard into Claude Code, Gemini CLI, or Codex config
    Init {
        /// Target client
        #[arg(value_enum, default_value_t = cmd_init::InitTarget::Claude)]
        target: cmd_init::InitTarget,
        /// Install to the user's global client config instead of the project-local config
        #[arg(long)]
        global: bool,
    },
    /// Check for a newer release on GitHub and optionally self-update
    Update {
        /// Only print the status; do not download or replace the binary.
        #[arg(long)]
        check_only: bool,
        /// Detached background mode: write ~/.secguard/.update-available and exit silently.
        #[arg(long, hide = true)]
        background: bool,
    },
}

#[derive(Subcommand)]
enum GuardSubcommand {
    /// Analyse telemetry and suggest safe_command_prefixes for config.toml
    Suggest {
        /// Number of top prefixes to show
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Minimum occurrence count to include a prefix
        #[arg(long, default_value_t = 3)]
        min_count: usize,
        /// Path to telemetry JSONL file (default: ~/.secguard/telemetry.jsonl)
        #[arg(long)]
        telemetry: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan { dir, format } => cmd_scan::run(dir, &format),
        Commands::Guard {
            subcommand,
            command,
        } => match subcommand {
            Some(GuardSubcommand::Suggest {
                top,
                min_count,
                telemetry,
            }) => cmd_guard::run_suggest(top, min_count, telemetry),
            None => cmd_guard::run(command),
        },
        Commands::Hook { mode, target } => hook::run(mode, target),
        Commands::Model { model, dir } => cmd_model::run(dir, model),
        Commands::Init { target, global } => cmd_init::run(target, global),
        Commands::Update {
            check_only,
            background,
        } => cmd_update::run(check_only, background),
    };

    // Flush stdout/stderr then use _exit to skip C++ global destructors that
    // trigger a Metal backend cleanup abort in llama-cpp-2 when ml is enabled.
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            let _ = std::io::stderr().flush();
            1
        }
    };
    unsafe { libc::_exit(code) }
}
