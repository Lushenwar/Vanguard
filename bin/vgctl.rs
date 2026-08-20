//! `vgctl` — administration, audit, and the control-plane client.
//!
//! Commands split into two families, and the split is deliberate.
//!
//! **Daemon-backed** — `health`, `state`, `propose`, `watch` — go over the
//! control plane. These need live runtime state, and there is no honest way to
//! answer them from a file.
//!
//! **Offline** — `verify`, `ledger`, `context`, `replay` — read the ledger
//! directly. That is not a fallback for a missing daemon; it is the property
//! that makes the ledger auditable at all. Verification and replay must be
//! possible without trusting, or even running, the process that wrote the log.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use vanguard::api::pb::{
    HealthRequest, LedgerRequest, ProposalRequest, ReplayRequest, StateRequest,
};
use vanguard::api::{self, Client};
use vanguard::clock::Clock;
use vanguard::config::Config;
use vanguard::egress::filter::{self, Filter};
use vanguard::error::Error;
use vanguard::fsm::engine::Decision;
use vanguard::fsm::state::{Event, Origin};
use vanguard::ledger::event::hex;
use vanguard::ledger::{key, replay, Ledger};
use vanguard::runtime::Runtime;
use vanguard::sandbox::{Sandbox, ToolRegistry};
use vanguard::telemetry::audit::{self, AuditSink, JsonlSink};

/// Exit codes, as documented in CLAUDE.md.
mod code {
    pub const OK: u8 = 0;
    pub const RUNTIME: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const CHAIN_BROKEN: u8 = 3;
    pub const UNREACHABLE: u8 = 4;
    pub const REJECTED: u8 = 5;
}

#[derive(Parser, Debug)]
#[command(name = "vgctl", about = "Vanguard control and audit CLI")]
struct Args {
    #[arg(long, value_name = "PATH", global = true)]
    config: Option<PathBuf>,

    /// Ledger file. Overrides the path derived from the config's state_dir.
    #[arg(long, value_name = "PATH", global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Daemon liveness, ledger head, and the registered tool set.
    Health,
    /// Live FSM state and step performance metrics for one session.
    State {
        #[arg(long)]
        session_id: String,
    },
    /// Submit a proposal, without a model in the loop.
    Propose {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        event: String,
        #[arg(long, default_value = "{}")]
        payload: String,
        /// Drive the engine directly against the ledger file instead of the
        /// daemon. Requires exclusive access to the database.
        #[arg(long)]
        offline: bool,
        /// Claimed origin. Offline only: over the control plane, origin is a
        /// property of the transport and cannot be asserted by a caller.
        #[arg(long, default_value = "PROPOSER")]
        origin: String,
    },
    /// Tail ledger events as they commit.
    Watch {
        #[arg(long)]
        session_id: Option<String>,
        /// Send the existing log before streaming live events.
        #[arg(long)]
        from_start: bool,
        /// Stop after N events. Without this it runs until interrupted.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Recompute the hash chain from genesis. Offline.
    Verify,
    /// Dump ledger events. Offline.
    Ledger {
        #[arg(long)]
        session_id: Option<String>,
        /// Show only the newest N events.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Render the bounded context window a proposer would be given. Offline.
    Context {
        #[arg(long)]
        session_id: String,
        /// Token budget. Defaults to the config's limits.max_context_tokens.
        #[arg(long)]
        max_tokens: Option<usize>,
        /// Print only the accounting, not the window itself.
        #[arg(long)]
        stats: bool,
    },
    /// Ask the egress policy whether a destination is permitted. Offline.
    ///
    /// The policy is pure, so this answers exactly what an enforcement point
    /// would answer -- no daemon and no network involved.
    Egress {
        /// `host`, `host:port`, `1.2.3.4:443`, or `[::1]:443`.
        #[arg(long)]
        target: String,
        /// Port to assume when the target does not carry one.
        #[arg(long, default_value_t = 443)]
        port: u16,
    },
    /// Drain unexported ledger events into a JSONL audit file. Offline.
    ///
    /// Shares its cursor with the daemon's exporter when pointed at the same
    /// file, so running this by hand does not re-send what has already gone.
    Export {
        #[arg(long, value_name = "PATH")]
        to: PathBuf,
        /// Events per batch.
        #[arg(long, default_value_t = 512)]
        batch: usize,
    },
    /// Fold the ledger back through the FSM and report any divergence.
    Replay {
        #[arg(long)]
        session_id: Option<String>,
        /// Ask the running daemon instead of reading the file directly.
        #[arg(long)]
        live: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(args).await {
        Ok(c) => ExitCode::from(c),
        Err(e) => {
            eprintln!("vgctl: {e}");
            ExitCode::from(match e {
                Error::ChainBroken { .. } | Error::CorruptRow { .. } => code::CHAIN_BROKEN,
                Error::Unreachable { .. } => code::UNREACHABLE,
                _ => code::RUNTIME,
            })
        }
    }
}

async fn run(args: Args) -> vanguard::Result<u8> {
    let config = Config::load(args.config.as_deref())?;
    let db_path = args.db.clone().unwrap_or_else(|| config.ledger_path());
    let limits = config.fsm_limits();

    match args.command {
        // ------------------------------------------------ daemon-backed
        Command::Health => {
            let mut client = client(&config).await?;
            let h = client
                .health(HealthRequest {})
                .await
                .map_err(rpc)?
                .into_inner();

            println!("version {}", h.version);
            println!("uptime  {}s", h.uptime_secs);
            println!("head    seq={} hash={}", h.head_seq, h.head_hash);
            println!(
                "chain   {}",
                if h.chain_verified {
                    "verified"
                } else {
                    "BROKEN — run `vgctl verify`"
                }
            );
            println!("sessions {}", h.sessions);
            println!(
                "tools   {} registered: {}",
                h.tools.len(),
                if h.tools.is_empty() {
                    "(none; every tool call is refused)".to_string()
                } else {
                    h.tools.join(", ")
                }
            );
            // A daemon that is up but sitting on a broken chain is not healthy,
            // whatever else it answered.
            Ok(if h.chain_verified {
                code::OK
            } else {
                code::CHAIN_BROKEN
            })
        }

        Command::State { session_id } => {
            let mut client = client(&config).await?;
            let s = client
                .get_state(StateRequest { session_id })
                .await
                .map_err(rpc)?
                .into_inner();

            println!("session {}", s.session_id);
            println!("state   {}", s.state);
            println!("steps   {}/{}", s.steps, s.max_steps);
            println!(
                "rejects {}/{} consecutive",
                s.consecutive_rejects, s.max_consecutive_rejects
            );
            println!("events  {}", s.events);
            println!(
                "context {}/{} tokens",
                s.context_tokens, s.max_context_tokens
            );
            println!(
                "step    last {} mean {}",
                micros(s.last_step_nanos),
                micros(s.mean_step_nanos)
            );
            Ok(code::OK)
        }

        Command::Propose {
            session_id,
            event,
            payload,
            offline,
            origin,
        } => {
            let event_enum = Event::parse(&event.to_uppercase())
                .ok_or_else(|| Error::Config(format!("unknown event {event:?}")))?;

            if offline {
                let origin = Origin::parse(&origin.to_uppercase())
                    .ok_or_else(|| Error::Config(format!("unknown origin {origin:?}")))?;
                let ledger = open(&db_path, &config)?;
                let mut rt = Runtime::new(ledger, limits, Clock::new(), tools(&config)?);
                rt.open_session(&session_id)?;
                let outcome = rt.submit(&session_id, event_enum, origin, payload.as_bytes())?;

                println!("seq     {}", outcome.record.seq);
                println!("state   {}", outcome.final_state());
                if let Some(run) = &outcome.tool {
                    match &run.output {
                        Ok(o) => println!(
                            "tool    {} ok, {} bytes, {} fuel, {:?}",
                            run.tool_name,
                            o.bytes.len(),
                            o.fuel_used,
                            o.elapsed
                        ),
                        Err(e) => println!("tool    {} failed: {e}", run.tool_name),
                    }
                }
                if let Some((reason, rec)) = &outcome.halt {
                    println!("halted  {} (seq {})", reason.as_str(), rec.seq);
                }
                return Ok(match outcome.decision {
                    Decision::Accept { .. } => code::OK,
                    Decision::Reject { reason } => {
                        eprintln!("vgctl: proposal rejected: {reason}");
                        code::REJECTED
                    }
                });
            }

            let mut client = client(&config).await?;
            let r = client
                .submit_proposal(ProposalRequest {
                    session_id,
                    event,
                    payload: payload.into_bytes(),
                })
                .await
                .map_err(rpc)?
                .into_inner();

            println!("seq     {}", r.seq);
            println!("state   {}", r.state);
            println!("steps   {}/{}", r.steps, r.max_steps);
            if let Some(tool) = &r.tool {
                if tool.ok {
                    println!(
                        "tool    {} ok, {} fuel, {}µs (seq {})",
                        tool.tool_name, tool.fuel_used, tool.elapsed_micros, tool.result_seq
                    );
                } else {
                    println!("tool    {} failed: {}", tool.tool_name, tool.error);
                }
            }
            if !r.halt_reason.is_empty() {
                println!("halted  {}", r.halt_reason);
            }
            Ok(if r.accepted {
                code::OK
            } else {
                eprintln!("vgctl: proposal rejected: {}", r.reject_reason);
                code::REJECTED
            })
        }

        Command::Watch {
            session_id,
            from_start,
            limit,
        } => {
            let mut client = client(&config).await?;
            let mut stream = client
                .stream_ledger(LedgerRequest {
                    session_id: session_id.unwrap_or_default(),
                    from_start,
                })
                .await
                .map_err(rpc)?
                .into_inner();

            let mut seen = 0usize;
            while let Some(event) = stream.message().await.map_err(rpc)? {
                let reason = if event.reject_reason.is_empty() {
                    "-".to_string()
                } else {
                    event.reject_reason.clone()
                };
                println!(
                    "{:>6}  {:<12} {:<14} {:<8} {:<8} {:<20} -> {}",
                    event.seq,
                    truncate(&event.session_id, 12),
                    event.event,
                    event.origin,
                    event.status,
                    reason,
                    event.to_state
                );
                seen += 1;
                if limit.is_some_and(|n| seen >= n) {
                    break;
                }
            }
            Ok(code::OK)
        }

        // ------------------------------------------------------- offline
        Command::Verify => {
            let ledger = open(&db_path, &config)?;
            let v = ledger.verify()?;
            println!("ok      {} events", v.events);
            println!("head    seq={} hash={}", v.head_seq, hex(&v.head_hash));
            Ok(code::OK)
        }

        Command::Ledger { session_id, limit } => {
            let ledger = open(&db_path, &config)?;
            let all = ledger.events(session_id.as_deref())?;
            let start = limit.map_or(0, |n| all.len().saturating_sub(n));
            for r in &all[start..] {
                let reason = r.reason.map(|x| x.as_str()).unwrap_or("-");
                println!(
                    "{:>6}  {:<12} {:<14} {:<12} {:<8} {:<20} -> {}",
                    r.seq,
                    truncate(&r.session_id, 12),
                    r.event.as_str(),
                    r.origin.as_str(),
                    r.status.as_str(),
                    reason,
                    r.to_state
                );
            }
            Ok(code::OK)
        }

        Command::Context {
            session_id,
            max_tokens,
            stats,
        } => {
            let budget = max_tokens.unwrap_or(config.limits.max_context_tokens as usize);
            let ledger = open(&db_path, &config)?;
            let rt = Runtime::new(ledger, limits, Clock::new(), tools(&config)?);
            let window = rt.context(&session_id, budget)?;

            if !stats {
                print!("{window}");
                println!("--");
            }
            println!("tokens  {}/{}", window.tokens, window.max_tokens);
            println!("live    {} events", window.tail.len());
            println!("evicted {} events", window.evicted());
            Ok(code::OK)
        }

        Command::Egress { target, port } => {
            let policy = config.egress_policy()?;
            let (host, port) = split_target(&target, port);
            let verdict = policy.decide(&host, port);

            println!("target  {host}:{port}");
            println!("rules   {}", policy.entries().len());
            println!("verdict {verdict}");

            // Say plainly whether anything is actually enforcing this, so a
            // permitted verdict is never mistaken for an enforced one.
            let (enforceable, skipped) = filter::triage(&policy);
            println!(
                "filter  {} ({enforceable} address rule(s) enforceable at the socket layer)",
                if Filter::available() {
                    "eBPF available"
                } else {
                    "eBPF unavailable in this build"
                }
            );
            for s in &skipped {
                println!("        {} — {}", s.rule, s.why);
            }

            Ok(if verdict.is_allowed() {
                code::OK
            } else {
                code::REJECTED
            })
        }

        Command::Export { to, batch } => {
            let ledger = open(&db_path, &config)?;
            let mut sink = JsonlSink::open(&to)?;
            let exported = audit::export_all(&ledger, &mut sink, batch)?;
            let cursor = ledger.export_cursor(sink.name())?;
            println!("exported {exported} events");
            println!("cursor   seq={cursor}");
            println!("sink     {}", to.display());
            Ok(code::OK)
        }

        Command::Replay { session_id, live } => {
            if live {
                let mut client = client(&config).await?;
                let summary = client
                    .trigger_replay(ReplayRequest {
                        session_id: session_id.unwrap_or_default(),
                    })
                    .await
                    .map_err(rpc)?
                    .into_inner();

                println!("events  {}", summary.events);
                println!("head    {}", summary.head_hash);
                if summary.faithful {
                    println!("replay  faithful");
                    return Ok(code::OK);
                }
                for m in &summary.mismatches {
                    eprintln!(
                        "vgctl: seq {} session {}: replay says {}, ledger says {}",
                        m.seq, m.session_id, m.expected, m.recorded
                    );
                }
                return Ok(code::CHAIN_BROKEN);
            }

            let ledger = open(&db_path, &config)?;
            let names = tools(&config)?.names();
            let summary = replay::replay(&ledger, session_id.as_deref(), &limits, &names)?;
            for (seq, session, state) in &summary.trace {
                println!("{seq:>6}  {session:<12} {state}");
            }
            println!("--");
            println!("events  {}", summary.events);
            println!("head    {}", hex(&summary.head_hash));
            for (id, view) in &summary.sessions {
                println!("final   {id} {} steps={}", view.state, view.steps);
            }
            if summary.is_faithful() {
                println!("replay  faithful");
                Ok(code::OK)
            } else {
                for m in &summary.mismatches {
                    eprintln!(
                        "vgctl: seq {} session {}: replay says {}, ledger says {}",
                        m.seq, m.session_id, m.expected, m.recorded
                    );
                }
                Ok(code::CHAIN_BROKEN)
            }
        }
    }
}

async fn client(config: &Config) -> vanguard::Result<Client> {
    api::connect(&config.control_endpoint()).await
}

/// Map a gRPC status back onto the crate's error type.
///
/// `data_loss` is preserved as a chain break so the exit code still tells an
/// operator to stop rather than retry.
fn rpc(status: tonic::Status) -> Error {
    match status.code() {
        tonic::Code::DataLoss => Error::ChainBroken {
            seq: 0,
            detail: status.message().to_string(),
        },
        tonic::Code::NotFound => Error::UnknownSession(status.message().to_string()),
        tonic::Code::Unavailable => Error::Unreachable {
            endpoint: "control plane".into(),
            detail: status.message().to_string(),
        },
        _ => Error::ControlPlane(status.message().to_string()),
    }
}

fn open(db_path: &std::path::Path, config: &Config) -> vanguard::Result<Ledger> {
    let key = key::load_or_create(&config.runtime.state_dir)?;
    Ledger::open(db_path, key)
}

/// Build the registry from the same directory the daemon reads.
///
/// `vgctl replay` needs this because a tool appearing or disappearing changes
/// which proposals the engine would authorize, and replaying against the wrong
/// set silently reports drift that is really a misconfigured CLI.
fn tools(config: &Config) -> vanguard::Result<ToolRegistry> {
    let sandbox = Sandbox::new(config.sandbox_fuel()).map_err(|e| Error::Config(e.to_string()))?;
    let mut registry = ToolRegistry::new(sandbox);
    registry.load_dir(&config.tools_dir())?;
    Ok(registry)
}

/// Split a `host:port` target, honouring bracketed IPv6.
fn split_target(target: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = target.strip_prefix('[') {
        if let Some((addr, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (addr.to_string(), port);
        }
    }
    // More than one colon and no brackets is a bare IPv6 literal, not a port.
    match target.rsplit_once(':') {
        Some(_) if target.matches(':').count() > 1 => (target.to_string(), default_port),
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(default_port)),
        None => (target.to_string(), default_port),
    }
}

fn micros(nanos: u64) -> String {
    format!("{:.1}µs", nanos as f64 / 1000.0)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

// `code::USAGE` is clap's own exit path for bad arguments; named here so the
// documented table stays complete.
const _: u8 = code::USAGE;
