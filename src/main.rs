//! `vanguardd` — the runtime daemon.
//!
//! Phase 0/1 scope: boot, open the ledger, prove the hash chain, and hold the
//! session runtime. The gRPC control plane that lets anything talk to it lands
//! in Phase 4; until then `vgctl` drives the same engine directly against the
//! ledger file.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tracing::{error, info};

use vanguard::clock::Clock;
use vanguard::config::{Config, APP_NAME};
use vanguard::fsm::engine::Limits;
use vanguard::ledger::{key, Ledger};
use vanguard::runtime::Runtime;

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
    let _runtime = Runtime::new(ledger, limits, Clock::new());

    info!(
        app = APP_NAME,
        ledger = %ledger_path.display(),
        socket = %config.runtime.socket.display(),
        max_steps = limits.max_steps,
        "vanguardd ready"
    );
    // ponytail: nothing to serve until the Phase 4 control plane exists, so the
    // daemon parks on the shutdown signal. The socket bind goes here.
    info!("no control plane yet (Phase 4); waiting for shutdown signal");

    tokio::signal::ctrl_c()
        .await
        .map_err(vanguard::Error::from)?;
    info!("shutting down");
    Ok(ExitCode::SUCCESS)
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
