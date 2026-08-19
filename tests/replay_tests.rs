//! Replay tests: an event log plus the engine reproduces history exactly.

use std::path::Path;

use vanguard::clock::Clock;
use vanguard::fsm::engine::Limits;
use vanguard::fsm::state::{Event, Origin, State};
use vanguard::ledger::replay::replay;
use vanguard::ledger::Ledger;
use vanguard::runtime::Runtime;

const KEY: [u8; 32] = [0xa7; 32];

/// A run with every shape of event in it: accepts, a rejection, a runtime
/// event, two interleaved sessions, and a terminal state.
fn recorded_run(path: &Path) -> Vec<State> {
    let mut rt = Runtime::new(
        Ledger::open(path, KEY).unwrap(),
        Limits::default(),
        Clock::new(),
    );
    rt.open_session("alpha").unwrap();
    rt.open_session("beta").unwrap();

    let script: &[(&str, Event, Origin, &[u8])] = &[
        ("alpha", Event::Start, Origin::Proposer, b"{}"),
        ("beta", Event::Start, Origin::Proposer, b"{}"),
        (
            "alpha",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        ),
        // Forged: legal edge, wrong origin.
        ("alpha", Event::ToolResult, Origin::Proposer, b"{}"),
        (
            "alpha",
            Event::ToolResult,
            Origin::Runtime,
            br#"{"out":"hi"}"#,
        ),
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
        ("beta", Event::ToolResult, Origin::Runtime, b"{}"),
    ];

    let mut states = Vec::new();
    for (session, event, origin, payload) in script {
        let out = rt.submit(session, *event, *origin, payload).unwrap();
        states.push(out.record.to_state);
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
    let summary = replay(&ledger, None, &Limits::default()).unwrap();

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

    let a = replay(&Ledger::open(&path, KEY).unwrap(), None, &Limits::default()).unwrap();
    let b = replay(&Ledger::open(&path, KEY).unwrap(), None, &Limits::default()).unwrap();
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
            "UPDATE events SET status = 'ACCEPTED', to_state = 'REFLECTING' \
             WHERE status = 'REJECTED'",
            [],
        )
        .unwrap();
    }

    let summary = replay(&Ledger::open(&path, KEY).unwrap(), None, &Limits::default()).unwrap();
    assert!(!summary.is_faithful());
    assert!(
        summary.mismatches.iter().any(|m| m.recorded == "ACCEPTED"),
        "expected a status mismatch, got {:?}",
        summary.mismatches
    );
}
