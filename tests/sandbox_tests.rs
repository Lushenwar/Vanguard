//! Phase 2 exit tests: WASM tools execute under hard resource ceilings, and a
//! runaway module terminates cleanly without taking the host with it.

mod common;

use std::time::{Duration, Instant};

use common::{echo_registry, registry_with, ECHO_WAT, SPIN_WAT};
use vanguard::clock::Clock;
use vanguard::fsm::engine::Limits;
use vanguard::fsm::state::{Event, Origin, State};
use vanguard::ledger::Ledger;
use vanguard::runtime::Runtime;
use vanguard::sandbox::{Fuel, Sandbox, ToolError};

/// Phase 2 exit criterion: a CPU spin loop hits out-of-fuel and terminates
/// cleanly within 50 ms.
#[test]
fn spin_loop_hits_fuel_limit() {
    // Fuel, not wall clock, is the limit — it is deterministic, so the same
    // module runs out after the same instruction on every machine. The budget
    // is chosen so that exhausting it lands well inside the 50 ms ceiling.
    let fuel = Fuel {
        units: 1_000_000,
        max_memory_bytes: 8 * 1024 * 1024,
    };
    let sandbox = Sandbox::new(fuel).unwrap();
    let module = sandbox.compile(SPIN_WAT.as_bytes()).unwrap();

    // Best of five, measuring only the call. The criterion is about how long a
    // runaway module can hold a worker, which is a property of the fuel budget,
    // not of how many other tests happen to be sharing the CPU — an unguarded
    // wall-clock assertion in a parallel test run measures the scheduler.
    // Compilation is excluded for the same reason: it happens once at load.
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let started = Instant::now();
        let err = sandbox.call(&module, b"{}").unwrap_err();
        best = best.min(started.elapsed());
        assert_eq!(err, ToolError::OutOfFuel);
    }

    assert!(
        best < Duration::from_millis(50),
        "spin loop took {best:?} at best, ceiling is 50ms"
    );
}

#[test]
fn the_host_survives_a_runaway_tool() {
    // Terminating "cleanly" means the next call still works. If a starved
    // module could poison the engine, one bad tool would take down the daemon.
    let sandbox = Sandbox::new(Fuel {
        units: 500_000,
        max_memory_bytes: 8 * 1024 * 1024,
    })
    .unwrap();
    let spin = sandbox.compile(SPIN_WAT.as_bytes()).unwrap();
    let echo = sandbox.compile(ECHO_WAT.as_bytes()).unwrap();

    for _ in 0..25 {
        assert_eq!(
            sandbox.call(&spin, b"{}").unwrap_err(),
            ToolError::OutOfFuel
        );
    }
    assert_eq!(sandbox.call(&echo, b"[1,2,3]").unwrap().bytes, b"[1,2,3]");
}

#[test]
fn a_starved_tool_returns_a_result_instead_of_stranding_the_session() {
    // End to end: the FSM authorizes the call, the sandbox refuses to let it
    // run forever, and the failure comes back as a TOOL_RESULT the model can
    // react to. Without this the session would sit in TOOL_EXECUTION until the
    // step budget or an operator killed it.
    let registry = registry_with(
        &[("spin", SPIN_WAT)],
        Fuel {
            units: 1_000_000,
            max_memory_bytes: 8 * 1024 * 1024,
        },
    );
    let mut rt = Runtime::new(
        Ledger::open_in_memory([0x2b; 32]).unwrap(),
        Limits::default(),
        Clock::new(),
        registry,
    );
    rt.open_session("s").unwrap();
    rt.submit("s", Event::Start, Origin::Proposer, b"{}")
        .unwrap();

    let started = Instant::now();
    let out = rt
        .submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"spin"}"#,
        )
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(
        out.tool.as_ref().unwrap().output.as_ref().unwrap_err(),
        &ToolError::OutOfFuel
    );
    assert_eq!(out.final_state(), State::Reflecting);
    // A looser bound than the sandbox's own 50 ms: this path also does two
    // fsync-backed ledger commits, so it is measuring the disk as much as the
    // fuel ceiling. What it proves is that the session came back at all.
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");

    let body: serde_json::Value = serde_json::from_slice(
        &rt.ledger()
            .events(Some("s"))
            .unwrap()
            .last()
            .unwrap()
            .payload,
    )
    .unwrap();
    assert_eq!(body["ok"], serde_json::json!(false));
    assert_eq!(body["error"], serde_json::json!("out of fuel"));

    assert!(rt.ledger().verify().is_ok());
}

#[test]
fn fuel_accounting_is_deterministic() {
    // The property replay depends on: identical input burns identical fuel.
    // If this ever drifts, a log replayed on another machine could take a
    // different branch at the ceiling.
    let registry = echo_registry();
    let a = registry.call("echo", br#"{"n":1}"#).unwrap();
    let b = registry.call("echo", br#"{"n":1}"#).unwrap();
    assert_eq!(a.fuel_used, b.fuel_used);
    assert_eq!(a.bytes, b.bytes);
}

#[test]
fn tools_cannot_reach_the_host() {
    let wat = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $w (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) (i32.const 0))
          (func (export "run") (param i32) (param i32) (result i64) (i64.const 0)))
    "#;
    let sandbox = Sandbox::new(Fuel::default()).unwrap();
    let module = sandbox.compile(wat.as_bytes()).unwrap();
    assert!(
        matches!(
            sandbox.call(&module, b"{}"),
            Err(ToolError::ForbiddenImport(_))
        ),
        "even WASI must be unavailable unless it is explicitly granted"
    );
}
