//! Phase 1 exit tests: the FSM rejects what it must, cheaply, without mutating
//! state, and the runtime writes evidence of every rejection.

mod common;

use std::collections::BTreeSet;
use std::time::Instant;

use common::{echo_names, echo_registry};
use vanguard::clock::Clock;
use vanguard::fsm::engine::{self, Decision, Limits, SessionView};
use vanguard::fsm::state::{Event, Origin, RejectReason, State};
use vanguard::fsm::transition;
use vanguard::ledger::{Ledger, Status};
use vanguard::runtime::Runtime;

const ECHO_CALL: &[u8] = br#"{"tool_name":"echo"}"#;

fn runtime_with(limits: Limits) -> Runtime {
    let ledger = Ledger::open_in_memory([0x2c; 32]).unwrap();
    let mut rt = Runtime::new(ledger, limits, Clock::new(), echo_registry());
    rt.open_session("s").unwrap();
    rt
}

fn eval(session: SessionView, limits: &Limits, event: Event, payload: &[u8]) -> Decision {
    engine::evaluate(
        session,
        limits,
        event,
        event.origin(),
        payload,
        &echo_names(),
    )
}

#[test]
fn illegal_edges_rejected_without_mutation() {
    // Sweep the entire (state, event) product. For every pair the table does
    // not contain, the engine must reject and leave state untouched.
    for from in State::ALL {
        for event in Event::ALL {
            if transition::is_legal(from, event) {
                continue;
            }
            let session = SessionView {
                state: from,
                steps: 0,
                consecutive_rejects: 0,
            };
            let decision = eval(session, &Limits::default(), event, ECHO_CALL);
            let reason = match decision {
                Decision::Reject { reason } => reason,
                Decision::Accept { .. } => panic!("({from}, {event}) was accepted but is illegal"),
            };
            assert!(
                matches!(
                    reason,
                    RejectReason::IllegalEdge | RejectReason::TerminalState
                ),
                "({from}, {event}) rejected for the wrong reason: {reason}"
            );
            assert_eq!(engine::apply(session, decision).state, from);
        }
    }
}

#[test]
fn illegal_transition_is_logged_as_evidence() {
    let mut rt = runtime_with(Limits::default());
    // FINISH from IDLE is not an edge.
    let out = rt
        .submit("s", Event::Finish, Origin::Proposer, b"{}")
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Reject {
            reason: RejectReason::IllegalEdge
        }
    );
    assert_eq!(rt.session("s").unwrap().state, State::Idle);

    let events = rt.ledger().events(Some("s")).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status, Status::Rejected);
    assert_eq!(events[0].reason, Some(RejectReason::IllegalEdge));
    assert_eq!(events[0].from_state, State::Idle);
    assert_eq!(events[0].to_state, State::Idle);
}

#[test]
fn forged_runtime_origin_rejected() {
    // TOOL_RESULT from TOOL_EXECUTION is a legal edge — the only thing wrong
    // with this proposal is who claims to be sending it. Checked at the engine
    // level because the runtime never rests in TOOL_EXECUTION: dispatch is
    // synchronous, so there is no window in which a proposal could arrive.
    let in_tool = SessionView {
        state: State::ToolExecution,
        steps: 1,
        consecutive_rejects: 0,
    };
    let forged = engine::evaluate(
        in_tool,
        &Limits::default(),
        Event::ToolResult,
        Origin::Proposer,
        br#"{"ok":true}"#,
        &echo_names(),
    );
    assert_eq!(
        forged,
        Decision::Reject {
            reason: RejectReason::ForgedOrigin
        }
    );

    // The same event from the runtime is accepted.
    let honest = engine::evaluate(
        in_tool,
        &Limits::default(),
        Event::ToolResult,
        Origin::Runtime,
        br#"{"ok":true}"#,
        &echo_names(),
    );
    assert!(honest.is_accept());
}

#[test]
fn a_proposer_cannot_abort_its_own_session() {
    // The reachable half of the same defense: ABORT is runtime-only, so a model
    // cannot end its session — and stop the ledger accruing evidence — by
    // asking to.
    let mut rt = runtime_with(Limits::default());
    rt.submit("s", Event::Start, Origin::Proposer, b"{}")
        .unwrap();

    let out = rt
        .submit("s", Event::Abort, Origin::Proposer, b"{}")
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Reject {
            reason: RejectReason::ForgedOrigin
        }
    );
    assert_eq!(rt.session("s").unwrap().state, State::Planning);
}

#[test]
fn unknown_tool_never_reaches_the_sandbox() {
    let mut rt = runtime_with(Limits::default());
    rt.submit("s", Event::Start, Origin::Proposer, b"{}")
        .unwrap();

    let out = rt
        .submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"rm_rf"}"#,
        )
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Reject {
            reason: RejectReason::UnknownTool
        }
    );
    assert!(out.tool.is_none(), "an unregistered tool must not execute");
    assert_eq!(rt.session("s").unwrap().state, State::Planning);
}

#[test]
fn step_budget_halts_session() {
    let limits = Limits {
        max_steps: 6,
        // Raised so the ABORT this test is looking for can only come from the
        // step budget, never from a rejection loop.
        max_consecutive_rejects: 1000,
        ..Limits::default()
    };
    let mut rt = runtime_with(limits);

    rt.submit("s", Event::Start, Origin::Proposer, b"{}")
        .unwrap();

    // Each EXECUTE_TOOL also produces a runtime TOOL_RESULT, which spends no
    // step. The budget must therefore stop this at 6 proposals, not 12 events.
    let mut halted = false;
    for _ in 0..20 {
        if rt.session("s").unwrap().state.is_terminal() {
            halted = true;
            break;
        }
        rt.submit("s", Event::ExecuteTool, Origin::Proposer, ECHO_CALL)
            .unwrap();
    }

    assert!(halted, "session never halted");
    let view = rt.session("s").unwrap();
    assert_eq!(view.state, State::Halted);
    assert_eq!(view.steps, limits.max_steps);

    let events = rt.ledger().events(Some("s")).unwrap();
    let abort = events.last().unwrap();
    assert_eq!(abort.event, Event::Abort);
    assert_eq!(abort.origin, Origin::Runtime);
    assert_eq!(abort.to_state, State::Halted);
    assert_eq!(rt.ledger().verify().unwrap().events, events.len() as u64);
}

#[test]
fn rejections_cannot_burn_the_step_budget() {
    let limits = Limits {
        max_steps: 3,
        max_consecutive_rejects: 1000,
        ..Limits::default()
    };
    let mut rt = runtime_with(limits);
    for _ in 0..50 {
        // Illegal from IDLE every time.
        rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
            .unwrap();
    }
    let view = rt.session("s").unwrap();
    assert_eq!(view.steps, 0, "rejections must not spend steps");
    assert_eq!(view.state, State::Idle);

    // The session is still usable: a valid proposal is accepted afterwards.
    assert!(rt
        .submit("s", Event::Start, Origin::Proposer, b"{}")
        .unwrap()
        .decision
        .is_accept());
}

#[test]
fn rejection_loop_halts_session() {
    let mut rt = runtime_with(Limits {
        max_consecutive_rejects: 3,
        ..Limits::default()
    });
    for _ in 0..3 {
        rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
            .unwrap();
    }
    assert_eq!(rt.session("s").unwrap().state, State::Halted);
}

#[test]
fn oversized_and_malformed_payloads_are_rejected() {
    let mut rt = runtime_with(Limits {
        max_payload_bytes: 16,
        ..Limits::default()
    });
    let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(64));
    assert_eq!(
        rt.submit("s", Event::Start, Origin::Proposer, big.as_bytes())
            .unwrap()
            .decision,
        Decision::Reject {
            reason: RejectReason::PayloadTooLarge
        }
    );
    assert_eq!(
        rt.submit("s", Event::Start, Origin::Proposer, b"{nope}")
            .unwrap()
            .decision,
        Decision::Reject {
            reason: RejectReason::MalformedPayload
        }
    );
    assert_eq!(rt.session("s").unwrap().state, State::Idle);
}

#[test]
fn rejection_is_decided_well_under_a_millisecond() {
    // Phase 1 exit criterion: invalid proposals are rejected in < 1 ms. The
    // measurement is of the evaluator alone, because that is the part the
    // criterion is about — the ledger append is an fsync and is bounded by the
    // disk, not by us.
    let session = SessionView {
        state: State::Planning,
        steps: 0,
        consecutive_rejects: 0,
    };
    let limits = Limits::default();
    let payload = br#"{"tool_name":"fetch_http","arguments":{"url":"https://example.com"}}"#;
    let tools: BTreeSet<String> = BTreeSet::new();

    let iterations = 10_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let d = engine::evaluate(
            session,
            &limits,
            Event::Start,
            Origin::Proposer,
            payload,
            &tools,
        );
        std::hint::black_box(d);
    }
    let per_call = start.elapsed() / iterations;
    assert!(
        per_call.as_micros() < 1_000,
        "rejection took {per_call:?} per call, budget is 1ms"
    );
}
