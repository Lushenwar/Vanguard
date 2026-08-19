//! Phase 4 exit tests: the control plane carries the same guarantees the
//! in-process engine does, and adds none of its own.

mod common;

use std::time::Duration;

use common::echo_registry;
use vanguard::api::pb::{
    HealthRequest, LedgerRequest, ProposalRequest, ReplayRequest, StateRequest,
};
use vanguard::api::{server, Client, Handle};
use vanguard::clock::Clock;
use vanguard::config::Endpoint;
use vanguard::fsm::engine::Limits;
use vanguard::ledger::Ledger;
use vanguard::runtime::Runtime;

const MAX_CONTEXT_TOKENS: u32 = 8192;

/// Start a daemon on an ephemeral endpoint and return a connected client.
///
/// Ephemeral rather than a fixed port: tests run in parallel, and a hard-coded
/// port makes two of them fight over it exactly often enough to look like a
/// real bug.
async fn daemon(limits: Limits) -> (Client, Handle) {
    let runtime = Runtime::new(
        Ledger::open_in_memory([0x41; 32]).unwrap(),
        limits,
        Clock::new(),
        echo_registry(),
    );
    let (handle, _thread) = Handle::spawn(runtime, MAX_CONTEXT_TOKENS);

    // On Unix the daemon serves a socket path; here the point is the roundtrip,
    // and loopback works identically on both platforms.
    let listener = server::bind(&Endpoint::Tcp("127.0.0.1:0".into()))
        .await
        .unwrap();
    let endpoint = listener.endpoint().unwrap();

    let serving = handle.clone();
    tokio::spawn(async move {
        let _ = server::serve(listener, serving, std::future::pending()).await;
    });

    // Retry briefly: the listener is bound, but tonic's server task may not
    // have polled it yet.
    for _ in 0..50 {
        if let Ok(client) = vanguard::api::connect(&endpoint).await {
            return (client, handle);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("daemon never accepted a connection at {endpoint}");
}

async fn propose(
    client: &mut Client,
    session: &str,
    event: &str,
    payload: &str,
) -> vanguard::api::pb::ProposalResponse {
    client
        .submit_proposal(ProposalRequest {
            session_id: session.into(),
            event: event.into(),
            payload: payload.as_bytes().to_vec(),
        })
        .await
        .expect("rpc")
        .into_inner()
}

/// Phase 4 exit criterion: vgctl-equivalent traffic over the socket manages
/// sessions and reports live state.
#[tokio::test]
async fn vgctl_roundtrip_over_socket() {
    let (mut client, _handle) = daemon(Limits::default()).await;

    let health = client.health(HealthRequest {}).await.unwrap().into_inner();
    assert!(health.chain_verified);
    assert_eq!(health.tools, vec!["echo".to_string()]);

    let start = propose(&mut client, "s", "START", r#"{"task":"roundtrip"}"#).await;
    assert!(start.accepted, "{}", start.reject_reason);
    assert_eq!(start.state, "PLANNING");
    assert_eq!(start.steps, 1);
    assert_eq!(start.max_steps, Limits::default().max_steps);

    let call = propose(
        &mut client,
        "s",
        "EXECUTE_TOOL",
        r#"{"tool_name":"echo","arguments":{"x":1}}"#,
    )
    .await;
    assert!(call.accepted);
    // The tool ran inside the daemon and its result is already committed.
    assert_eq!(call.state, "REFLECTING");
    let tool = call.tool.expect("tool should have been dispatched");
    assert!(tool.ok, "{}", tool.error);
    assert_eq!(tool.tool_name, "echo");
    assert!(tool.fuel_used > 0);
    assert_eq!(tool.result_seq, call.seq + 1);

    let state = client
        .get_state(StateRequest {
            session_id: "s".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(state.state, "REFLECTING");
    assert_eq!(state.steps, 2);
    assert_eq!(state.events, 3);
    assert!(state.mean_step_nanos > 0, "step metrics must be reported");
    assert!(state.context_tokens > 0);
    assert_eq!(state.max_context_tokens, MAX_CONTEXT_TOKENS);

    let replayed = client
        .trigger_replay(ReplayRequest {
            session_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(replayed.faithful, "{:?}", replayed.mismatches);
    assert_eq!(replayed.events, 3);
}

#[tokio::test]
async fn a_caller_cannot_claim_runtime_origin() {
    // The security property the missing origin field buys: there is no way to
    // express "this is a RUNTIME event" over the wire, so a caller naming a
    // runtime-only event is recorded as a proposer forging one.
    let (mut client, _handle) = daemon(Limits::default()).await;
    propose(&mut client, "s", "START", "{}").await;
    propose(&mut client, "s", "EXECUTE_TOOL", r#"{"tool_name":"echo"}"#).await;

    let forged = propose(&mut client, "s", "TOOL_RESULT", r#"{"ok":true}"#).await;
    assert!(!forged.accepted);
    assert_eq!(forged.reject_reason, "ForgedOrigin");

    let forged_abort = propose(&mut client, "s", "ABORT", "{}").await;
    assert!(!forged_abort.accepted);
    assert_eq!(forged_abort.reject_reason, "ForgedOrigin");
}

#[tokio::test]
async fn unknown_session_and_unknown_event_are_distinguished() {
    let (mut client, _handle) = daemon(Limits::default()).await;

    // An unparseable event never reaches the FSM: there is no event to record a
    // rejection against, so it fails at the edge as a client bug.
    let err = client
        .submit_proposal(ProposalRequest {
            session_id: "s".into(),
            event: "TELEPORT".into(),
            payload: b"{}".to_vec(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // A session that was never opened is not found, rather than silently
    // created by a read.
    let err = client
        .get_state(StateRequest {
            session_id: "never-existed".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn stream_ledger_replays_history_then_follows() {
    let (mut client, _handle) = daemon(Limits::default()).await;
    propose(&mut client, "s", "START", "{}").await;

    let mut stream = client
        .stream_ledger(LedgerRequest {
            session_id: "s".into(),
            from_start: true,
        })
        .await
        .unwrap()
        .into_inner();

    // The backlog arrives first.
    let first = stream.message().await.unwrap().expect("backlog event");
    assert_eq!(first.seq, 1);
    assert_eq!(first.event, "START");
    assert_eq!(first.hash.len(), 64, "hash is hex-encoded SHA-256 width");

    // Then live events, in ledger order, including the runtime-origin result
    // the caller never asked for directly.
    let mut driver = client.clone();
    tokio::spawn(async move {
        propose(&mut driver, "s", "EXECUTE_TOOL", r#"{"tool_name":"echo"}"#).await;
    });

    let second = stream.message().await.unwrap().expect("live event");
    assert_eq!(second.seq, 2);
    assert_eq!(second.event, "EXECUTE_TOOL");
    assert_eq!(second.origin, "PROPOSER");

    let third = stream.message().await.unwrap().expect("live event");
    assert_eq!(third.seq, 3);
    assert_eq!(third.event, "TOOL_RESULT");
    assert_eq!(third.origin, "RUNTIME");
}

#[tokio::test]
async fn stream_without_from_start_skips_history() {
    let (mut client, _handle) = daemon(Limits::default()).await;
    propose(&mut client, "s", "START", "{}").await;

    let mut stream = client
        .stream_ledger(LedgerRequest {
            session_id: String::new(),
            from_start: false,
        })
        .await
        .unwrap()
        .into_inner();

    let mut driver = client.clone();
    tokio::spawn(async move {
        propose(&mut driver, "s", "FINISH", "{}").await;
    });

    let event = stream.message().await.unwrap().expect("live event");
    assert_eq!(event.seq, 2, "seq 1 predates the subscription");
    assert_eq!(event.event, "FINISH");
}

#[tokio::test]
async fn a_cancelled_request_does_not_disturb_the_runtime() {
    // Async drop safety, from CLAUDE.md's technical realities. The runtime lives
    // on its own thread, so a client giving up mid-call drops a oneshot sender
    // and nothing else — the tool call completes and its event still commits.
    let (mut client, handle) = daemon(Limits::default()).await;
    propose(&mut client, "s", "START", "{}").await;

    let mut cancelling = client.clone();
    let call = tokio::time::timeout(
        Duration::from_nanos(1),
        propose(
            &mut cancelling,
            "s",
            "EXECUTE_TOOL",
            r#"{"tool_name":"echo"}"#,
        ),
    )
    .await;
    assert!(call.is_err(), "the request was meant to be abandoned");

    // The daemon is still healthy, the chain is still intact, and the abandoned
    // call's events are in the ledger rather than half-written.
    for _ in 0..50 {
        let health = handle.health().await.unwrap();
        if health.head_seq >= 3 {
            assert!(health.chain_verified);
            let state = client
                .get_state(StateRequest {
                    session_id: "s".into(),
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(state.state, "REFLECTING");
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the abandoned tool call never committed");
}

#[tokio::test]
async fn the_control_plane_cannot_bypass_a_budget() {
    // A control plane that could set state directly would make the state
    // machine advisory. The only mutation path is SubmitProposal, so the step
    // budget applies to a network caller exactly as it does in-process.
    let (mut client, _handle) = daemon(Limits {
        max_steps: 3,
        max_consecutive_rejects: 1000,
        ..Limits::default()
    })
    .await;

    propose(&mut client, "s", "START", "{}").await;
    let mut halted = false;
    for _ in 0..10 {
        let r = propose(&mut client, "s", "EXECUTE_TOOL", r#"{"tool_name":"echo"}"#).await;
        if !r.halt_reason.is_empty() || r.state == "HALTED" {
            halted = true;
            break;
        }
    }
    assert!(halted, "the step budget must halt a network-driven session");

    let state = client
        .get_state(StateRequest {
            session_id: "s".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(state.state, "HALTED");
    assert_eq!(state.steps, 3);
}
