//! The runtime actor: one thread owns the `Runtime`, everyone else sends it
//! messages.
//!
//! This is the single-writer rule from CLAUDE.md made structural. Phase 0
//! satisfied it by ownership — only one `Runtime` existed — which stopped being
//! enough the moment a server could accept concurrent requests. Rather than a
//! mutex around the runtime, there is a channel into it: `SQLITE_BUSY` cannot
//! occur because there is still exactly one writer, and `seq` allocation still
//! needs no lock.
//!
//! It runs on a dedicated OS thread, not a Tokio task, because tool execution
//! is synchronous wasm that would otherwise block an executor worker for its
//! entire fuel budget.
//!
//! The thread boundary also settles the async-drop question from CLAUDE.md's
//! technical realities. A client that disconnects mid-call cancels its own
//! future, which drops a `oneshot::Sender` and nothing else; the tool call it
//! asked for is owned by this thread and runs to completion or to its fuel
//! ceiling either way. No cancellable future ever holds a wasm `Store`.

use std::time::Instant;

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::error::{Error, Result};
use crate::fsm::engine::Limits;
use crate::fsm::state::{Event, Origin};
use crate::ledger::event::Record;
use crate::ledger::replay::{self, ReplaySummary};
use crate::runtime::{Outcome, Runtime};

/// How many committed events a slow subscriber may fall behind before it is
/// dropped from the live stream.
///
/// Bounded on purpose: an unbounded buffer would let one stalled `vgctl watch`
/// grow the daemon's memory without limit. A subscriber that falls behind is
/// told it lagged and can re-request from the start, which is possible only
/// because the ledger is the durable record and the stream is a convenience.
const BROADCAST_CAPACITY: usize = 1024;

pub enum Command {
    Submit {
        session_id: String,
        event: Event,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Outcome>>,
    },
    State {
        session_id: String,
        reply: oneshot::Sender<Result<StateSnapshot>>,
    },
    Backlog {
        session_id: Option<String>,
        reply: oneshot::Sender<Result<Vec<Record>>>,
    },
    Replay {
        session_id: Option<String>,
        reply: oneshot::Sender<Result<ReplaySummary>>,
    },
    Health {
        reply: oneshot::Sender<Result<HealthSnapshot>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    pub session_id: String,
    pub state: crate::fsm::state::State,
    pub steps: u32,
    pub max_steps: u32,
    pub consecutive_rejects: u32,
    pub max_consecutive_rejects: u32,
    pub events: u64,
    /// Monotonic nanoseconds between the two newest events in this session.
    pub last_step_nanos: u64,
    pub mean_step_nanos: u64,
    pub context_tokens: u32,
    pub max_context_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub version: String,
    pub head_seq: u64,
    pub head_hash: String,
    pub chain_verified: bool,
    pub tools: Vec<String>,
    pub sessions: u64,
    pub uptime_secs: u64,
}

/// A cheap, cloneable way to talk to the runtime thread.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::Sender<Command>,
    events: broadcast::Sender<Record>,
    limits: Limits,
    max_context_tokens: u32,
}

impl Handle {
    /// Take ownership of `runtime` on a new thread and return a handle to it.
    ///
    /// The returned `JoinHandle` completes when every `Handle` has been dropped
    /// and the command channel closes, so a caller can wait for the runtime to
    /// finish committing before exiting.
    pub fn spawn(
        runtime: Runtime,
        max_context_tokens: u32,
    ) -> (Handle, std::thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(64);
        let (events, _) = broadcast::channel(BROADCAST_CAPACITY);

        let handle = Handle {
            tx,
            events: events.clone(),
            // Copied out before the runtime moves onto its thread: budgets are
            // fixed for the process, so reporting them does not need a round
            // trip through the channel.
            limits: *runtime.limits(),
            max_context_tokens,
        };

        let thread = std::thread::Builder::new()
            .name("vanguard-runtime".into())
            .spawn(move || run(runtime, rx, events, max_context_tokens))
            .expect("spawning the runtime thread");

        (handle, thread)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Record> {
        self.events.subscribe()
    }

    pub fn max_context_tokens(&self) -> u32 {
        self.max_context_tokens
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Submit a proposal. Always `Origin::Proposer`: origin is a property of
    /// this boundary, not something a caller may assert. See the note on
    /// `ProposalRequest` in the proto.
    pub async fn submit(
        &self,
        session_id: &str,
        event: Event,
        payload: Vec<u8>,
    ) -> Result<Outcome> {
        self.call(|reply| Command::Submit {
            session_id: session_id.to_string(),
            event,
            payload,
            reply,
        })
        .await
    }

    pub async fn state(&self, session_id: &str) -> Result<StateSnapshot> {
        self.call(|reply| Command::State {
            session_id: session_id.to_string(),
            reply,
        })
        .await
    }

    pub async fn backlog(&self, session_id: Option<&str>) -> Result<Vec<Record>> {
        let session_id = session_id.map(str::to_string);
        self.call(|reply| Command::Backlog { session_id, reply })
            .await
    }

    pub async fn replay(&self, session_id: Option<&str>) -> Result<ReplaySummary> {
        let session_id = session_id.map(str::to_string);
        self.call(|reply| Command::Replay { session_id, reply })
            .await
    }

    pub async fn health(&self) -> Result<HealthSnapshot> {
        self.call(|reply| Command::Health { reply }).await
    }

    async fn call<T>(&self, make: impl FnOnce(oneshot::Sender<Result<T>>) -> Command) -> Result<T> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(make(reply))
            .await
            .map_err(|_| Error::Config("runtime thread has stopped".into()))?;
        rx.await
            .map_err(|_| Error::Config("runtime thread dropped the reply".into()))?
    }
}

fn run(
    mut runtime: Runtime,
    mut rx: mpsc::Receiver<Command>,
    events: broadcast::Sender<Record>,
    max_context_tokens: u32,
) {
    let started = Instant::now();

    while let Some(command) = rx.blocking_recv() {
        match command {
            Command::Submit {
                session_id,
                event,
                payload,
                reply,
            } => {
                // Sessions are created on first contact. The alternative is a
                // separate OpenSession rpc whose only failure mode is having
                // forgotten to call it.
                let outcome = runtime
                    .open_session(&session_id)
                    .and_then(|_| runtime.submit(&session_id, event, Origin::Proposer, &payload));

                if let Ok(outcome) = &outcome {
                    // Publish after the commit, so a subscriber can never see
                    // an event that is not yet durable.
                    for record in committed_records(outcome) {
                        let _ = events.send(record);
                    }
                }
                let _ = reply.send(outcome);
            }

            Command::State { session_id, reply } => {
                let _ = reply.send(state_snapshot(&runtime, &session_id, max_context_tokens));
            }

            Command::Backlog { session_id, reply } => {
                let _ = reply.send(runtime.ledger().events(session_id.as_deref()));
            }

            Command::Replay { session_id, reply } => {
                let summary = replay::replay(
                    runtime.ledger(),
                    session_id.as_deref(),
                    runtime.limits(),
                    runtime.tool_names(),
                );
                let _ = reply.send(summary);
            }

            Command::Health { reply } => {
                let _ = reply.send(health_snapshot(&runtime, started));
            }
        }
    }
}

/// Every record one submission committed, in ledger order.
///
/// Sorted by `seq` rather than assembled in call order: a submission can commit
/// the proposal, a tool result, and an abort, and the stream has to present
/// them in the order the ledger did.
fn committed_records(outcome: &Outcome) -> Vec<Record> {
    let mut records = vec![outcome.record.clone()];
    if let Some((_, halt)) = &outcome.halt {
        records.push(halt.clone());
    }
    if let Some(run) = &outcome.tool {
        records.extend(committed_records(&run.result));
    }
    records.sort_by_key(|r| r.seq);
    records
}

fn state_snapshot(
    runtime: &Runtime,
    session_id: &str,
    max_context_tokens: u32,
) -> Result<StateSnapshot> {
    let view = runtime.session(session_id)?;
    let events = runtime.ledger().events(Some(session_id))?;
    let (last_step_nanos, mean_step_nanos) = step_timings(&events);

    let context_tokens = runtime
        .context(session_id, max_context_tokens as usize)
        .map(|w| w.tokens as u32)
        .unwrap_or(0);

    let limits = runtime.limits();
    Ok(StateSnapshot {
        session_id: session_id.to_string(),
        state: view.state,
        steps: view.steps,
        max_steps: limits.max_steps,
        consecutive_rejects: view.consecutive_rejects,
        max_consecutive_rejects: limits.max_consecutive_rejects,
        events: events.len() as u64,
        last_step_nanos,
        mean_step_nanos,
        context_tokens,
        max_context_tokens,
    })
}

/// `(newest gap, mean gap)` in monotonic nanoseconds.
///
/// Monotonic, so these are real elapsed times even if the wall clock stepped
/// mid-session. `saturating_sub` because a ledger written by an older daemon
/// run restarts its monotonic epoch at zero, which would otherwise underflow.
fn step_timings(events: &[Record]) -> (u64, u64) {
    if events.len() < 2 {
        return (0, 0);
    }
    let gaps: Vec<u64> = events
        .windows(2)
        .map(|w| w[1].mono_ns.saturating_sub(w[0].mono_ns))
        .collect();
    let last = *gaps.last().expect("len >= 2 means at least one gap");
    let mean = gaps.iter().sum::<u64>() / gaps.len() as u64;
    (last, mean)
}

fn health_snapshot(runtime: &Runtime, started: Instant) -> Result<HealthSnapshot> {
    let (head_seq, head_hash) = runtime.ledger().head();
    Ok(HealthSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        head_seq,
        head_hash: crate::ledger::event::hex(&head_hash),
        // Re-verified on demand, not cached from boot: "the chain was intact
        // when we started" is not the question an operator is asking.
        chain_verified: runtime.ledger().verify().is_ok(),
        tools: runtime.tool_names().iter().cloned().collect(),
        sessions: runtime.ledger().session_ids()?.len() as u64,
        uptime_secs: started.elapsed().as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::state::State;
    use crate::ledger::event::{Draft, Status, GENESIS};

    fn rec(seq: u64, mono_ns: u64) -> Record {
        Record::from_draft(
            Draft {
                session_id: "s".into(),
                mono_ns,
                wall_ms: 0,
                from_state: State::Planning,
                event: Event::Finish,
                origin: Origin::Proposer,
                payload: b"{}".to_vec(),
                status: Status::Accepted,
                reason: None,
                to_state: State::Done,
            },
            seq,
            GENESIS,
            b"k",
        )
    }

    #[test]
    fn step_timings_need_two_events() {
        assert_eq!(step_timings(&[]), (0, 0));
        assert_eq!(step_timings(&[rec(1, 10)]), (0, 0));
    }

    #[test]
    fn step_timings_measure_gaps_not_timestamps() {
        let events = vec![rec(1, 100), rec(2, 300), rec(3, 900)];
        assert_eq!(step_timings(&events), (600, 400));
    }

    #[test]
    fn a_restarted_monotonic_epoch_does_not_underflow() {
        // seq 3 was written by a later daemon run whose epoch restarted at 0.
        let events = vec![rec(1, 5_000), rec(2, 9_000), rec(3, 12)];
        let (last, mean) = step_timings(&events);
        assert_eq!(last, 0);
        assert_eq!(mean, 2_000);
    }
}
