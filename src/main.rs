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
use vanguard::telemetry::{self, audit::JsonlSink};

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
    // Held for the whole process: dropping it flushes buffered spans, and
    // dropping it early would silently stop trace export while everything still
    // looked like it was working.
    let _telemetry = telemetry::init(&config.runtime.log_level, &config.telemetry)?;

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

    // Parsed at boot so a malformed rule stops the daemon here, with the rule
    // quoted, rather than silently denying everything at runtime.
    let egress = config.egress_policy()?;
    let (enforceable, unenforceable) = vanguard::egress::filter::triage(&egress);
    info!(
        rules = egress.entries().len(),
        enforceable_at_socket = enforceable,
        ebpf = vanguard::egress::filter::Filter::available(),
        "egress policy loaded"
    );
    if egress.is_empty() {
        // The safe default, and indistinguishable from a broken config unless
        // someone says so.
        info!("egress allowlist is empty: every destination is denied");
    }
    for rule in &unenforceable {
        tracing::warn!(rule = %rule.rule, why = rule.why, "egress rule is not enforced here");
    }
    if !egress.is_empty() && !vanguard::egress::filter::Filter::available() {
        tracing::warn!(
            "no socket-layer egress filter in this build; today nothing in a tool \
             can open a socket anyway, because the wasm linker grants no host bindings"
        );
    }

    let runtime = Runtime::new(ledger, limits, Clock::new(), tools);
    let (handle, runtime_thread) = Handle::spawn(runtime, config.limits.max_context_tokens);

    // The audit exporter runs alongside the server rather than inside it: it
    // must keep draining while requests are in flight, and it must get a final
    // drain after they stop.
    let (audit_stop, audit_rx) = tokio::sync::mpsc::channel(1);
    let audit_task = if config.telemetry.audit_enabled() {
        let sink = JsonlSink::open(&config.telemetry.audit_log)?;
        info!(path = %sink.path().display(), "audit export enabled");
        Some(tokio::spawn(telemetry::run_exporter(
            handle.clone(),
            Box::new(sink),
            std::time::Duration::from_millis(config.telemetry.audit_interval_ms),
            config.telemetry.audit_batch,
            audit_rx,
        )))
    } else {
        info!("audit export disabled; set telemetry.audit_log to turn it on");
        None
    };

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

    // Stop and drain the exporter before the runtime goes away — it reads
    // through the same handle, so the order is load-bearing. Without the final
    // drain, a clean shutdown would leave the last interval's events unexported
    // and an operator could not tell that from a crash.
    if let Some(task) = audit_task {
        let _ = audit_stop.send(()).await;
        let _ = task.await;
    }

    // Dropping every handle closes the command channel, which is what tells the
    // runtime thread to finish. Joining before exit means an in-flight commit
    // completes rather than dying with the process.
    drop(audit_stop);
    drop(handle);
    let _ = runtime_thread.join();

    result.map(|()| ExitCode::SUCCESS)
}
