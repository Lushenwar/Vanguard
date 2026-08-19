//! Replay tests: an event log plus the engine reproduces history exactly.

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use common::{echo_names, echo_registry};
use vanguard::clock::Clock;
use vanguard::fsm::engine::Limits;
use vanguard::fsm::state::{Event, Origin, State};
use vanguard::ledger::replay::replay;
use vanguard::ledger::Ledger;
use vanguard::runtime::Runtime;

const KEY: [u8; 32] = [0xa7; 32];

/// A run with every shape of event in it: accepts, a rejection, runtime-origin
/// tool results, two interleaved sessions, and a terminal state.
///
/// Returns the state sequence as the *live* runtime reached it, gathered from
/// the returned outcomes rather than from the ledger, so the comparison against
/// replay is not circular.
fn recorded_run(path: &Path) -> Vec<State> {
    let mut rt = Runtime::new(
        Ledger::open(path, KEY).unwrap(),
        Limits::default(),
        Clock::new(),
        echo_registry(),
    );
    rt.open_session("alpha").unwrap();
    rt.open_session("beta").unwrap();

    let script: &[(&str, Event, Origin, &[u8])] = &[
        ("alpha", Event::Start, Origin::Proposer, b"{}"),
        ("beta", Event::Start, Origin::Proposer, b"{}"),
        // Runs the tool and appends its own TOOL_RESULT.
        (
            "alpha",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        ),
        // Forged: ABORT is runtime-only.
        ("alpha", Event::Abort, Origin::Proposer, b"{}"),
        (
            "beta",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        ),
        (
            "alpha",
            Event::Finish,
            Origin::Proposer,
            br#"{"answer":42}"#,
        ),
    ];

    let mut states = Vec::new();
    for (session, event, origin, payload) in script {
        let out = rt.submit(session, *event, *origin, payload).unwrap();
        states.push(out.record.to_state);
        if let Some(run) = &out.tool {
            states.push(run.result.record.to_state);
        }
    }
    states
}

#[test]
fn replay_reproduces_state_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vanguard.sqlite");
    let live_states = recorded_run(&path);

    // Cold reopen: nothing carried over from the writing process except the
    // file and the key, which is the entire premise of offline replay.
    let ledger = Ledger::open(&path, KEY).unwrap();
    let summary = replay(&ledger, None, &Limits::default(), &echo_names()).unwrap();

    assert!(
        summary.is_faithful(),
        "mismatches: {:?}",
        summary.mismatches
    );
    let replayed: Vec<State> = summary.trace.iter().map(|(_, _, s)| *s).collect();
    assert_eq!(replayed, live_states, "replayed state sequence diverged");

    assert_eq!(summary.sessions["alpha"].state, State::Done);
    assert_eq!(summary.sessions["beta"].state, State::Reflecting);
    assert_eq!(summary.head_hash, ledger.head().1, "head hash must match");
}

#[test]
fn replay_is_stable_across_processes_and_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vanguard.sqlite");
    recorded_run(&path);

    let a = replay(
        &Ledger::open(&path, KEY).unwrap(),
        None,
        &Limits::default(),
        &echo_names(),
    )
    .unwrap();
    let b = replay(
        &Ledger::open(&path, KEY).unwrap(),
        None,
        &Limits::default(),
        &echo_names(),
    )
    .unwrap();
    assert_eq!(a, b);
}

#[test]
fn replay_detects_a_ledger_that_disagrees_with_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vanguard.sqlite");
    recorded_run(&path);

    // Rewrite a recorded outcome without touching its hash — this is the case
    // `verify` would also catch, but replay must catch it independently, since
    // an operator auditing behaviour may not have the key.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE events SET status = 'ACCEPTED', to_state = 'HALTED' \
             WHERE status = 'REJECTED'",
            [],
        )
        .unwrap();
    }

    let summary = replay(
        &Ledger::open(&path, KEY).unwrap(),
        None,
        &Limits::default(),
        &echo_names(),
    )
    .unwrap();
    assert!(!summary.is_faithful());
    assert!(
        summary.mismatches.iter().any(|m| m.recorded == "ACCEPTED"),
        "expected a status mismatch, got {:?}",
        summary.mismatches
    );
}

#[test]
fn replay_detects_a_tool_that_has_since_been_withdrawn() {
    // The audit-relevant case: the log says a tool call was authorized, but
    // today's registry does not contain that tool. Replay must report the
    // divergence rather than quietly reproducing the old decision.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vanguard.sqlite");
    recorded_run(&path);

    let summary = replay(
        &Ledger::open(&path, KEY).unwrap(),
        None,
        &Limits::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    assert!(!summary.is_faithful());
    assert!(summary
        .mismatches
        .iter()
        .any(|m| m.expected == "REJECTED" && m.recorded == "ACCEPTED"));
}
