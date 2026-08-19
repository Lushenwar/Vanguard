//! `vanguardd` — the runtime daemon.
//!
//! Boot order matters: verify the chain, refuse to serve on a break, load the
//! tool registry, hand the runtime to its own thread, and only then open the
//! socket. Nothing can talk to a runtime whose ledger has not been proven.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tracing::{error, info};

use vanguard::api::{server, Handle};
use vanguard::clock::Clock;
use vanguard::config::{Config, APP_NAME};
use vanguard::fsm::engine::Limits;
use vanguard::ledger::{key, Ledger};
use vanguard::runtime::Runtime;
use vanguard::sandbox::{Sandbox, ToolRegistry};

#[derive(Parser, Debug)]
#[command(
    name = "vanguardd",
    about = "Vanguard deterministic agent state engine"
)]
struct Args {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Verify the ledger and exit without serving.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(args).await {
        Ok(code) => code,
        Err(e) => {
            error!("{e}");
            ExitCode::from(1)
        }
    }
}

async fn run(args: Args) -> vanguard::Result<ExitCode> {
    let config = Config::load(args.config.as_deref())?;
    init_tracing(&config.runtime.log_level);

    let key = key::load_or_create(&config.runtime.state_dir)?;
    let ledger_path = config.ledger_path();
    let ledger = Ledger::open(&ledger_path, key)?;

    // Verify before serving, always. Appending to a ledger whose chain is
    // already broken would bury the break under valid-looking events and make
    // the original tampering harder, not easier, to find.
    match ledger.verify() {
        Ok(v) => info!(
            events = v.events,
            head = %vanguard::ledger::event::hex(&v.head_hash),
            "ledger chain verified"
        ),
        Err(e) => {
            error!("{e}");
            error!("refusing to serve on a broken ledger; inspect with `vgctl verify`");
            return Ok(ExitCode::from(3));
        }
    }

    if args.check {
        return Ok(ExitCode::SUCCESS);
    }

    let limits: Limits = config.fsm_limits();

    let sandbox =
        Sandbox::new(config.sandbox_fuel()).map_err(|e| vanguard::Error::Config(e.to_string()))?;
    let mut tools = ToolRegistry::new(sandbox);
    let tools_dir = config.tools_dir();
    let loaded = tools.load_dir(&tools_dir)?;
    info!(
        count = loaded,
        dir = %tools_dir.display(),
        fuel = config.sandbox.fuel,
        "tool registry loaded"
    );
    if loaded == 0 {
        // Worth saying out loud: an empty registry is a working configuration
        // that refuses every tool, which looks identical to a broken one.
        info!("no tools registered; every EXECUTE_TOOL proposal will be rejected");
    }

    let runtime = Runtime::new(ledger, limits, Clock::new(), tools);
    let (handle, runtime_thread) = Handle::spawn(runtime, config.limits.max_context_tokens);

    // Bind before announcing: "ready" should mean the socket is accepting, not
    // that we are about to try.
    let listener = server::bind(&config.control_endpoint()).await?;
    info!(
        app = APP_NAME,
        ledger = %ledger_path.display(),
        endpoint = %listener.endpoint()?,
        max_steps = limits.max_steps,
        "vanguardd ready"
    );

    let result = server::serve(listener, handle.clone(), async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
    })
    .await;

    // Dropping every handle closes the command channel, which is what tells the
    // runtime thread to finish. Joining before exit means an in-flight commit
    // completes rather than dying with the process.
    drop(handle);
    let _ = runtime_thread.join();

    result.map(|()| ExitCode::SUCCESS)
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
