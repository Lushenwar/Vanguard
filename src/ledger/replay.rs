//! Offline reconstruction: fold the ledger back through the FSM and check that
//! today's engine reaches the states the ledger says it reached.
//!
//! This is the deterministic-replayability claim made executable. It catches
//! two different problems with one pass: a ledger that was tampered with in a
//! way that still hashes (impossible without the key, but worth not assuming),
//! and an edge table that has been changed since the log was written, which
//! would silently invalidate every historical audit.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::fsm::engine::{self, Decision, Limits, SessionView};
use crate::fsm::state::State;
use crate::ledger::db::Ledger;
use crate::ledger::event::{Hash, Status, GENESIS};

/// One place where replay and the recorded ledger disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub seq: u64,
    pub session_id: String,
    pub expected: String,
    pub recorded: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySummary {
    pub events: u64,
    /// Final state per session, ordered by session id. `BTreeMap`, not
    /// `HashMap`: replay output must be byte-identical run to run, and Rust's
    /// default hasher is randomly seeded per process.
    pub sessions: BTreeMap<String, SessionView>,
    /// The state each event moved its session to, in ledger order.
    pub trace: Vec<(u64, String, State)>,
    pub head_hash: Hash,
    pub mismatches: Vec<Mismatch>,
}

impl ReplaySummary {
    pub fn is_faithful(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// Replay `session_id` (or the whole ledger when `None`).
///
/// `tools` must be the tool set that was registered when the log was written.
/// Replaying against a different set is not a bug in this function — it is the
/// divergence it exists to report, because a tool appearing or disappearing
/// changes which proposals the engine would have authorized.
pub fn replay(
    ledger: &Ledger,
    session_id: Option<&str>,
    limits: &Limits,
    tools: &BTreeSet<String>,
) -> Result<ReplaySummary> {
    let events = ledger.events(session_id)?;

    let mut sessions: BTreeMap<String, SessionView> = BTreeMap::new();
    let mut trace = Vec::with_capacity(events.len());
    let mut mismatches = Vec::new();
    let mut head_hash = GENESIS;

    for rec in &events {
        let before = *sessions.entry(rec.session_id.clone()).or_default();

        if before.state != rec.from_state {
            mismatches.push(Mismatch {
                seq: rec.seq,
                session_id: rec.session_id.clone(),
                expected: before.state.to_string(),
                recorded: rec.from_state.to_string(),
            });
        }

        let decision = engine::evaluate(before, limits, rec.event, rec.origin, &rec.payload, tools);
        let recorded_status = rec.status;
        let replayed_status = match decision {
            Decision::Accept { .. } => Status::Accepted,
            Decision::Reject { .. } => Status::Rejected,
        };
        if replayed_status != recorded_status {
            mismatches.push(Mismatch {
                seq: rec.seq,
                session_id: rec.session_id.clone(),
                expected: replayed_status.as_str().to_string(),
                recorded: recorded_status.as_str().to_string(),
            });
        }

        let after = engine::apply(before, decision);
        if after.state != rec.to_state {
            mismatches.push(Mismatch {
                seq: rec.seq,
                session_id: rec.session_id.clone(),
                expected: after.state.to_string(),
                recorded: rec.to_state.to_string(),
            });
        }

        sessions.insert(rec.session_id.clone(), after);
        trace.push((rec.seq, rec.session_id.clone(), rec.to_state));
        head_hash = rec.hash;
    }

    Ok(ReplaySummary {
        events: events.len() as u64,
        sessions,
        trace,
        head_hash,
        mismatches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;
    use crate::fsm::state::{Event, Origin};
    use crate::runtime::Runtime;
    use crate::sandbox::{Fuel, Sandbox, ToolRegistry};

    const ECHO_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $n i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $n)))
            (local.get $p))
          (func (export "run") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len)))))
    "#;

    fn registry() -> ToolRegistry {
        let mut r = ToolRegistry::new(Sandbox::new(Fuel::default()).unwrap());
        r.insert("echo", ECHO_WAT.as_bytes()).unwrap();
        r
    }

    fn echo_only() -> BTreeSet<String> {
        ["echo".to_string()].into_iter().collect()
    }

    fn recorded_run() -> Runtime {
        let mut rt = Runtime::new(
            Ledger::open_in_memory([3u8; 32]).unwrap(),
            Limits::default(),
            Clock::new(),
            registry(),
        );
        rt.open_session("a").unwrap();
        rt.open_session("b").unwrap();
        rt.submit("a", Event::Start, Origin::Proposer, b"{}")
            .unwrap();
        rt.submit("b", Event::Start, Origin::Proposer, b"{}")
            .unwrap();
        // Runs the tool and appends its TOOL_RESULT, interleaved with another
        // session so replay has to keep per-session state rather than one
        // global cursor.
        rt.submit(
            "a",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        )
        .unwrap();
        rt.submit("b", Event::ToolResult, Origin::Runtime, b"{}")
            .unwrap(); // illegal from PLANNING
        rt.submit("a", Event::Finish, Origin::Proposer, b"{}")
            .unwrap();
        rt
    }

    #[test]
    fn replay_reproduces_recorded_states() {
        let rt = recorded_run();
        let summary = replay(rt.ledger(), None, &Limits::default(), &echo_only()).unwrap();
        assert!(
            summary.is_faithful(),
            "mismatches: {:?}",
            summary.mismatches
        );
        assert_eq!(summary.sessions["a"].state, State::Done);
        assert_eq!(rt.ledger().head().1, summary.head_hash);
    }

    #[test]
    fn replay_is_byte_identical_across_runs() {
        let rt = recorded_run();
        let a = replay(rt.ledger(), None, &Limits::default(), &echo_only()).unwrap();
        let b = replay(rt.ledger(), None, &Limits::default(), &echo_only()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn per_session_replay_sees_only_that_session() {
        let rt = recorded_run();
        let summary = replay(rt.ledger(), Some("b"), &Limits::default(), &echo_only()).unwrap();
        assert!(summary.is_faithful(), "{:?}", summary.mismatches);
        assert_eq!(summary.sessions.len(), 1);
    }

    #[test]
    fn a_tighter_budget_shows_up_as_a_mismatch() {
        // Replaying with a budget tighter than the one in force when the log
        // was written: the engine now rejects what it once accepted, which is
        // precisely the class of drift this catches.
        let rt = recorded_run();
        let tight = Limits {
            max_steps: 1,
            ..Limits::default()
        };
        let summary = replay(rt.ledger(), None, &tight, &echo_only()).unwrap();
        assert!(!summary.is_faithful());
    }

    #[test]
    fn a_removed_tool_shows_up_as_a_mismatch() {
        // The audit-relevant case: a tool that existed when the session ran has
        // since been withdrawn. The log says the call was authorized; today's
        // registry says it would not be. Replay must not paper over that.
        let rt = recorded_run();
        let summary = replay(rt.ledger(), None, &Limits::default(), &BTreeSet::new()).unwrap();
        assert!(!summary.is_faithful());
        assert!(summary
            .mismatches
            .iter()
            .any(|m| m.recorded == "ACCEPTED" && m.expected == "REJECTED"));
    }
}
