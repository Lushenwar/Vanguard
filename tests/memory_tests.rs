//! Phase 3 exit tests: context stays inside its token bound no matter how long
//! the session runs, and the facts that matter survive eviction.

mod common;

use common::echo_registry;
use vanguard::clock::Clock;
use vanguard::fsm::engine::Limits;
use vanguard::fsm::state::{Event, Origin, State};
use vanguard::ledger::Ledger;
use vanguard::memory::estimate_tokens;
use vanguard::runtime::Runtime;

const MAX_CONTEXT_TOKENS: usize = 8_192;
const TURNS: usize = 1_000;

/// A budget large enough that the *step* cap never fires — this test is about
/// the context bound, and a session halting at step 50 would prove nothing.
fn long_running() -> Limits {
    Limits {
        max_steps: (TURNS as u32) + 10,
        max_consecutive_rejects: 1_000_000,
        ..Limits::default()
    }
}

/// Phase 3 exit criterion: context stays within 8,192 tokens across 1,000
/// conversation turns.
#[test]
fn context_bounded_over_1000_turns() {
    // In-memory ledger: this is 2,001 events, and with synchronous=FULL on disk
    // the test would be measuring fsync rather than the pager.
    let mut rt = Runtime::new(
        Ledger::open_in_memory([0x31; 32]).unwrap(),
        long_running(),
        Clock::new(),
        echo_registry(),
    );
    rt.open_session("long").unwrap();
    rt.submit(
        "long",
        Event::Start,
        Origin::Proposer,
        br#"{"task":"summarise the quarterly filings and never touch production"}"#,
    )
    .unwrap();

    let mut peak = 0usize;
    for turn in 0..TURNS {
        // One turn = one tool call, which also appends its runtime TOOL_RESULT.
        let payload = format!(r#"{{"tool_name":"echo","arguments":{{"turn":{turn}}}}}"#);
        let out = rt
            .submit(
                "long",
                Event::ExecuteTool,
                Origin::Proposer,
                payload.as_bytes(),
            )
            .unwrap();
        assert!(
            out.decision.is_accept(),
            "turn {turn} was rejected: {:?}",
            out.decision
        );

        // Checked every turn, not just at the end: the criterion is that the
        // bound is never exceeded, and a window that overshoots in the middle
        // and recovers would still have blown a real model's context.
        let window = rt.context("long", MAX_CONTEXT_TOKENS).unwrap();
        assert!(
            window.tokens <= MAX_CONTEXT_TOKENS,
            "turn {turn}: {} tokens exceeds {MAX_CONTEXT_TOKENS}",
            window.tokens
        );
        assert!(estimate_tokens(&window.render()) <= window.tokens);
        peak = peak.max(window.tokens);
    }

    let window = rt.context("long", MAX_CONTEXT_TOKENS).unwrap();
    assert_eq!(
        rt.ledger().events(Some("long")).unwrap().len(),
        TURNS * 2 + 1
    );
    assert!(
        window.evicted() > 0,
        "with 2001 events something must have been evicted"
    );
    assert_eq!(
        window.evicted() as usize + window.tail.len(),
        TURNS * 2 + 1,
        "every event is either live or counted"
    );
    // The window should actually be using its budget, not sitting at 10%.
    assert!(peak > MAX_CONTEXT_TOKENS / 2, "peak was only {peak} tokens");
}

#[test]
fn the_task_survives_a_thousand_turns() {
    // Working-memory rot: the constraint stated in turn one is exactly the kind
    // of thing a naive sliding window drops, and exactly the kind of thing that
    // matters when it is gone.
    let mut rt = Runtime::new(
        Ledger::open_in_memory([0x32; 32]).unwrap(),
        long_running(),
        Clock::new(),
        echo_registry(),
    );
    rt.open_session("long").unwrap();
    rt.submit(
        "long",
        Event::Start,
        Origin::Proposer,
        br#"{"task":"never touch production"}"#,
    )
    .unwrap();

    for turn in 0..TURNS {
        let payload = format!(r#"{{"tool_name":"echo","arguments":{{"turn":{turn}}}}}"#);
        rt.submit(
            "long",
            Event::ExecuteTool,
            Origin::Proposer,
            payload.as_bytes(),
        )
        .unwrap();
    }

    let rendered = rt.context("long", MAX_CONTEXT_TOKENS).unwrap().render();
    assert!(
        rendered.contains("never touch production"),
        "the original task must still be in the window"
    );
    // And the evicted region is accounted for rather than silently missing.
    assert!(rendered.contains("EVICTED"));
    assert!(rendered.contains("echo="));
}

#[test]
fn the_window_is_identical_across_rebuilds() {
    // Replay depends on this: if the same ledger produced a different prompt on
    // each rebuild, the model's next proposal would not be reproducible even
    // with a perfectly faithful event log.
    let mut rt = Runtime::new(
        Ledger::open_in_memory([0x33; 32]).unwrap(),
        long_running(),
        Clock::new(),
        echo_registry(),
    );
    rt.open_session("s").unwrap();
    rt.submit("s", Event::Start, Origin::Proposer, br#"{"task":"t"}"#)
        .unwrap();
    for turn in 0..200 {
        let payload = format!(r#"{{"tool_name":"echo","arguments":{{"turn":{turn}}}}}"#);
        rt.submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            payload.as_bytes(),
        )
        .unwrap();
    }

    let a = rt.context("s", 2048).unwrap();
    let b = rt.context("s", 2048).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.render(), b.render());
}

#[test]
fn a_halted_session_still_renders() {
    // The window is also what an operator reads after something went wrong, so
    // it has to work in the states nobody plans for.
    let mut rt = Runtime::new(
        Ledger::open_in_memory([0x34; 32]).unwrap(),
        Limits {
            max_steps: 3,
            ..Limits::default()
        },
        Clock::new(),
        echo_registry(),
    );
    rt.open_session("s").unwrap();
    rt.submit("s", Event::Start, Origin::Proposer, br#"{"task":"t"}"#)
        .unwrap();
    for _ in 0..5 {
        if rt.session("s").unwrap().state.is_terminal() {
            break;
        }
        rt.submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        )
        .unwrap();
    }
    assert_eq!(rt.session("s").unwrap().state, State::Halted);

    let window = rt.context("s", 1024).unwrap();
    assert!(window.render().contains("HALTED"));
    assert!(window.fits());
}

#[test]
fn an_unusable_budget_is_an_error_not_a_silent_truncation() {
    let mut rt = Runtime::new(
        Ledger::open_in_memory([0x35; 32]).unwrap(),
        Limits::default(),
        Clock::new(),
        echo_registry(),
    );
    rt.open_session("s").unwrap();
    assert!(rt.context("s", 8).is_err());
}
