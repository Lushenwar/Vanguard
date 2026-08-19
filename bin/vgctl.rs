//! `vgctl` — administration and debugging.
//!
//! Every subcommand here works directly against the ledger file. That is not a
//! stopgap for the missing control plane so much as the thing that makes the
//! ledger auditable at all: verification and replay must be possible without
//! trusting, or even running, the daemon that wrote the log.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use vanguard::clock::Clock;
use vanguard::config::Config;
use vanguard::error::Error;
use vanguard::fsm::engine::Decision;
use vanguard::fsm::state::{Event, Origin};
use vanguard::ledger::event::hex;
use vanguard::ledger::{key, replay, Ledger};
use vanguard::runtime::Runtime;
use vanguard::sandbox::{Sandbox, ToolRegistry};

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
    /// Recompute the hash chain from genesis.
    Verify,
    /// Daemon liveness and ledger head.
    Health,
    /// Current FSM state of one session.
    State {
        #[arg(long)]
        session_id: String,
    },
    /// Dump ledger events.
    Ledger {
        #[arg(long)]
        session_id: Option<String>,
        /// Show only the newest N events.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Render the bounded context window a proposer would be given.
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
    /// Fold the ledger back through the FSM and report any divergence.
    Replay {
        #[arg(long)]
        session_id: Option<String>,
    },
    /// Submit a proposal directly, without a model in the loop.
    Propose {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        event: String,
        #[arg(long, default_value = "{}")]
        payload: String,
        /// Claimed origin. Defaults to PROPOSER, which is what a model is.
        #[arg(long, default_value = "PROPOSER")]
        origin: String,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(c) => ExitCode::from(c),
        Err(e) => {
            eprintln!("vgctl: {e}");
            ExitCode::from(match e {
                Error::ChainBroken { .. } | Error::CorruptRow { .. } => code::CHAIN_BROKEN,
                _ => code::RUNTIME,
            })
        }
    }
}

fn run(args: Args) -> vanguard::Result<u8> {
    let config = Config::load(args.config.as_deref())?;
    let db_path = args.db.clone().unwrap_or_else(|| config.ledger_path());
    let limits = config.fsm_limits();

    match args.command {
        Command::Health => {
            // ponytail: no daemon to ask until Phase 4. Reporting the ledger
            // head is still the useful half, so say what is known and exit 4
            // rather than pretending the check passed.
            let ledger = open(&db_path, &config)?;
            let (seq, hash) = ledger.head();
            println!("ledger  {}", db_path.display());
            println!("head    seq={seq} hash={}", hex(&hash));
            let registry = tools(&config)?;
            println!(
                "tools   {} registered: {}",
                registry.len(),
                if registry.is_empty() {
                    "(none; every tool call is refused)".to_string()
                } else {
                    registry.names().into_iter().collect::<Vec<_>>().join(", ")
                }
            );
            eprintln!("vgctl: no control plane to query yet (Phase 4)");
            Ok(code::UNREACHABLE)
        }

        Command::Verify => {
            let ledger = open(&db_path, &config)?;
            let v = ledger.verify()?;
            println!("ok      {} events", v.events);
            println!("head    seq={} hash={}", v.head_seq, hex(&v.head_hash));
            Ok(code::OK)
        }

        Command::State { session_id } => {
            let ledger = open(&db_path, &config)?;
            let row = ledger
                .session(&session_id)?
                .ok_or(Error::UnknownSession(session_id))?;
            println!("session {}", row.id);
            println!("state   {}", row.view.state);
            println!("steps   {}/{}", row.view.steps, limits.max_steps);
            println!(
                "rejects {}/{} consecutive",
                row.view.consecutive_rejects, limits.max_consecutive_rejects
            );
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

        Command::Replay { session_id } => {
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

        Command::Propose {
            session_id,
            event,
            payload,
            origin,
        } => {
            let event = Event::parse(&event.to_uppercase())
                .ok_or_else(|| Error::Config(format!("unknown event {event:?}")))?;
            let origin = Origin::parse(&origin.to_uppercase())
                .ok_or_else(|| Error::Config(format!("unknown origin {origin:?}")))?;

            let ledger = open(&db_path, &config)?;
            let mut rt = Runtime::new(ledger, limits, Clock::new(), tools(&config)?);
            rt.open_session(&session_id)?;
            let outcome = rt.submit(&session_id, event, origin, payload.as_bytes())?;

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
            match outcome.decision {
                Decision::Accept { .. } => Ok(code::OK),
                Decision::Reject { reason } => {
                    eprintln!("vgctl: proposal rejected: {reason}");
                    Ok(code::REJECTED)
                }
            }
        }
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
