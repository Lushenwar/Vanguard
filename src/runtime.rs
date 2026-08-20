//! The enforcer: joins the pure FSM evaluator to the durable ledger and the
//! sandbox.
//!
//! The ordering in [`Runtime::submit`] is the whole contract. Evaluate, commit,
//! *then* act. Nothing downstream — no tool dispatch, no side effect — may
//! observe a state change that is not already on disk with an event explaining
//! how it got there. Tool dispatch happens strictly after the `EXECUTE_TOOL`
//! event's transaction has committed.

use std::collections::BTreeSet;

use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::fsm::engine::{self, Decision, HaltReason, Limits, SessionView};
use crate::fsm::state::{Event, Origin, State};
use crate::ledger::event::{Draft, Record, Status};
use crate::ledger::Ledger;
use crate::memory::{self, ContextWindow};
use crate::sandbox::{ToolError, ToolOutput, ToolRegistry};

pub struct Runtime {
    ledger: Ledger,
    limits: Limits,
    clock: Clock,
    tools: ToolRegistry,
    /// Cached tool names for the evaluator. Held alongside the registry rather
    /// than rebuilt per call, and never mutated after construction, so the FSM
    /// and the dispatcher can never disagree about which tools exist.
    tool_names: BTreeSet<String>,
}

/// What one submission did.
#[derive(Debug)]
pub struct Outcome {
    pub decision: Decision,
    pub record: Record,
    /// State after the submission, any halt, and any tool round trip.
    pub session: SessionView,
    /// Present when the runtime followed the submission with its own `ABORT`.
    pub halt: Option<(HaltReason, Record)>,
    /// Present when the submission was an accepted `EXECUTE_TOOL`.
    pub tool: Option<ToolRun>,
}

/// One tool call and the `TOOL_RESULT` it produced.
#[derive(Debug)]
pub struct ToolRun {
    pub tool_name: String,
    pub output: std::result::Result<ToolOutput, ToolError>,
    /// Boxed because an `Outcome` can contain a `ToolRun` — without the
    /// indirection the type would be infinitely sized.
    pub result: Box<Outcome>,
}

impl Outcome {
    pub fn final_state(&self) -> State {
        self.session.state
    }
}

impl Runtime {
    pub fn new(ledger: Ledger, limits: Limits, clock: Clock, tools: ToolRegistry) -> Runtime {
        let tool_names = tools.names();
        Runtime {
            ledger,
            limits,
            clock,
            tools,
            tool_names,
        }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn tools(&self) -> &ToolRegistry {
        &self.tools
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn tool_names(&self) -> &BTreeSet<String> {
        &self.tool_names
    }

    /// Assemble the bounded context window a proposer would be given.
    ///
    /// The budget is a parameter rather than runtime state because the caller
    /// already holds the config, and because the same session may legitimately
    /// be rendered at different budgets — a debugging dump and a live prompt
    /// want different amounts of the same log.
    pub fn context(&self, session_id: &str, max_tokens: usize) -> Result<ContextWindow> {
        let view = self.session(session_id)?;
        // ponytail: reads the whole session log on every call, so building a
        // window once per turn is O(n^2) over a session. Fine to a few thousand
        // events; past that, keep the digest incrementally on the sessions row
        // and fetch only the tail, which is the same arithmetic the pager
        // already does one event at a time.
        let events = self.ledger.events(Some(session_id))?;
        memory::build(
            session_id,
            view.state,
            view.steps,
            self.limits.max_steps,
            &events,
            max_tokens,
        )
        .ok_or_else(|| {
            Error::Config(format!(
                "max_context_tokens must be at least {}",
                memory::MIN_TOKENS
            ))
        })
    }

    /// Create a session if it does not exist. Idempotent.
    pub fn open_session(&mut self, id: &str) -> Result<SessionView> {
        self.ledger.create_session(id, self.clock.wall_ms())?;
        Ok(self
            .ledger
            .session(id)?
            .expect("session exists immediately after creation")
            .view)
    }

    pub fn session(&self, id: &str) -> Result<SessionView> {
        Ok(self
            .ledger
            .session(id)?
            .ok_or_else(|| Error::UnknownSession(id.to_string()))?
            .view)
    }

    /// Submit one proposal.
    ///
    /// An unknown session is an `Err`, not a `REJECTED` row: a ledger event has
    /// to hang off a session, so there is nowhere to write the rejection. See
    /// SPEC CORRECTIONS #6 in CLAUDE.md.
    #[tracing::instrument(
        name = "vanguard.submit",
        skip_all,
        fields(
            session_id = %session_id,
            event = %event,
            origin = %submitted_origin,
            payload_bytes = payload.len(),
            // Filled in once the FSM has ruled; recording them up front would
            // mean guessing at the answer this span exists to report.
            seq = tracing::field::Empty,
            decision = tracing::field::Empty,
            reject_reason = tracing::field::Empty,
            to_state = tracing::field::Empty,
        )
    )]
    pub fn submit(
        &mut self,
        session_id: &str,
        event: Event,
        submitted_origin: Origin,
        payload: &[u8],
    ) -> Result<Outcome> {
        let before = self.session(session_id)?;

        let decision = engine::evaluate(
            before,
            &self.limits,
            event,
            submitted_origin,
            payload,
            &self.tool_names,
        );
        let after = engine::apply(before, decision);

        let record = self.append(
            session_id,
            before.state,
            event,
            submitted_origin,
            payload,
            decision,
            after,
        )?;

        let span = tracing::Span::current();
        span.record("seq", record.seq);
        span.record("to_state", record.to_state.as_str());
        match decision {
            Decision::Accept { .. } => span.record("decision", "ACCEPTED"),
            Decision::Reject { reason } => {
                span.record("decision", "REJECTED");
                span.record("reject_reason", reason.as_str())
            }
        };

        // Budgets are checked against the post-commit state, so the ABORT is
        // always ordered after the event that exhausted the budget. An operator
        // reading the ledger sees the cause immediately before the effect.
        let halt = match engine::halt_after(after, &self.limits) {
            None => None,
            Some(reason) => Some((reason, self.halt(session_id, after, reason)?)),
        };

        let mut session = match &halt {
            Some(_) => self.session(session_id)?,
            None => after,
        };

        // Dispatch only after the transaction above has committed, and only if
        // the session actually arrived in TOOL_EXECUTION. A halt in between
        // means the budget ran out on this very step, and running a tool for a
        // halted session is a side effect with no live state to return to.
        let tool =
            if halt.is_none() && decision.is_accept() && session.state == State::ToolExecution {
                let run = self.dispatch(session_id, payload)?;
                session = run.result.session;
                Some(run)
            } else {
                None
            };

        Ok(Outcome {
            decision,
            record,
            session,
            halt,
            tool,
        })
    }

    /// Execute the tool an accepted `EXECUTE_TOOL` named, then feed the result
    /// back as a runtime-origin `TOOL_RESULT`.
    #[tracing::instrument(
        name = "vanguard.tool",
        skip_all,
        fields(
            session_id = %session_id,
            tool_name = tracing::field::Empty,
            ok = tracing::field::Empty,
            fuel_used = tracing::field::Empty,
            error = tracing::field::Empty,
        )
    )]
    fn dispatch(&mut self, session_id: &str, payload: &[u8]) -> Result<ToolRun> {
        // `evaluate` already established that the payload names a registered
        // tool; re-deriving the name from the same bytes with the same function
        // is what keeps authorization and execution talking about one tool.
        let tool_name = engine::tool_name(payload)
            .expect("evaluator accepted an EXECUTE_TOOL without a tool_name");

        let span = tracing::Span::current();
        span.record("tool_name", tool_name.as_str());

        let output = self.tools.call(&tool_name, payload);
        match &output {
            Ok(o) => {
                span.record("ok", true);
                span.record("fuel_used", o.fuel_used);
            }
            Err(e) => {
                span.record("ok", false);
                span.record("error", e.to_string());
            }
        }

        let result_payload = match &output {
            Ok(o) => tool_result_payload(&o.bytes),
            Err(e) => tool_error_payload(&e.to_string()),
        };

        let result = self.submit(
            session_id,
            Event::ToolResult,
            Origin::Runtime,
            &result_payload,
        )?;
        Ok(ToolRun {
            tool_name,
            output,
            result: Box::new(result),
        })
    }

    /// Append the runtime's own `ABORT`. Runtime origin, so it spends no step
    /// and cannot itself be refused by the budget that triggered it.
    fn halt(
        &mut self,
        session_id: &str,
        current: SessionView,
        reason: HaltReason,
    ) -> Result<Record> {
        let payload = format!(r#"{{"reason":"{}"}}"#, reason.as_str()).into_bytes();
        let decision = engine::evaluate(
            current,
            &self.limits,
            Event::Abort,
            Origin::Runtime,
            &payload,
            &self.tool_names,
        );
        let after = engine::apply(current, decision);
        self.append(
            session_id,
            current.state,
            Event::Abort,
            Origin::Runtime,
            &payload,
            decision,
            after,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        session_id: &str,
        from_state: State,
        event: Event,
        origin: Origin,
        payload: &[u8],
        decision: Decision,
        after: SessionView,
    ) -> Result<Record> {
        let (status, reason) = match decision {
            Decision::Accept { .. } => (Status::Accepted, None),
            Decision::Reject { reason } => (Status::Rejected, Some(reason)),
        };
        let draft = Draft {
            session_id: session_id.to_string(),
            mono_ns: self.clock.mono_ns(),
            wall_ms: self.clock.wall_ms(),
            from_state,
            event,
            origin,
            payload: payload.to_vec(),
            status,
            reason,
            to_state: decision.to_state(from_state),
        };
        self.ledger.commit(draft, after)
    }
}

/// Wrap a tool's output for the ledger.
///
/// Tool output must itself be valid JSON. Anything else is reported as a failed
/// call rather than smuggled into the ledger as an opaque blob — a payload the
/// auditor cannot parse is a payload the auditor cannot audit.
fn tool_result_payload(bytes: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(value) => serde_json::json!({ "ok": true, "output": value })
            .to_string()
            .into_bytes(),
        Err(_) => tool_error_payload("tool output is not valid JSON"),
    }
}

fn tool_error_payload(message: &str) -> Vec<u8> {
    serde_json::json!({ "ok": false, "error": message })
        .to_string()
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::state::RejectReason;
    use crate::sandbox::{Fuel, Sandbox};

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

    fn runtime() -> Runtime {
        let ledger = Ledger::open_in_memory([7u8; 32]).unwrap();
        Runtime::new(ledger, Limits::default(), Clock::new(), registry())
    }

    fn started() -> Runtime {
        let mut rt = runtime();
        rt.open_session("s").unwrap();
        rt.submit("s", Event::Start, Origin::Proposer, b"{}")
            .unwrap();
        rt
    }

    #[test]
    fn accepted_proposal_moves_state_and_is_logged() {
        let rt = started();
        assert_eq!(rt.session("s").unwrap().state, State::Planning);
        let events = rt.ledger().events(Some("s")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, Status::Accepted);
        assert_eq!(events[0].to_state, State::Planning);
    }

    #[test]
    fn rejected_proposal_is_logged_without_moving_state() {
        let mut rt = started();
        let out = rt
            .submit("s", Event::ToolResult, Origin::Proposer, b"{}")
            .unwrap();
        assert_eq!(
            out.decision,
            Decision::Reject {
                reason: RejectReason::ForgedOrigin
            }
        );
        assert_eq!(rt.session("s").unwrap().state, State::Planning);

        let events = rt.ledger().events(Some("s")).unwrap();
        assert_eq!(events.len(), 2, "the rejection must still be evidence");
        assert_eq!(events[1].status, Status::Rejected);
        assert_eq!(events[1].from_state, events[1].to_state);
    }

    #[test]
    fn repeated_rejections_halt_the_session() {
        let mut rt = started();
        for _ in 0..Limits::default().max_consecutive_rejects {
            rt.submit("s", Event::ToolResult, Origin::Proposer, b"{}")
                .unwrap();
        }
        assert_eq!(rt.session("s").unwrap().state, State::Halted);

        let events = rt.ledger().events(Some("s")).unwrap();
        let last = events.last().unwrap();
        assert_eq!(last.event, Event::Abort);
        assert_eq!(last.origin, Origin::Runtime);
    }

    #[test]
    fn unknown_session_is_an_error_not_a_ledger_row() {
        let mut rt = runtime();
        let err = rt
            .submit("nope", Event::Start, Origin::Proposer, b"{}")
            .unwrap_err();
        assert!(matches!(err, Error::UnknownSession(_)));
        assert_eq!(rt.ledger().events(None).unwrap().len(), 0);
    }

    #[test]
    fn accepted_tool_call_runs_and_feeds_its_result_back() {
        let mut rt = started();
        let out = rt
            .submit(
                "s",
                Event::ExecuteTool,
                Origin::Proposer,
                br#"{"tool_name":"echo"}"#,
            )
            .unwrap();

        let run = out.tool.as_ref().expect("tool should have been dispatched");
        assert_eq!(run.tool_name, "echo");
        assert!(run.output.is_ok());

        // One proposal produced two events: the authorization and the result.
        assert_eq!(out.final_state(), State::Reflecting);
        let events = rt.ledger().events(Some("s")).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].event, Event::ExecuteTool);
        assert_eq!(events[2].event, Event::ToolResult);
        assert_eq!(events[2].origin, Origin::Runtime);

        // The echo tool returns its input, so the result carries it back.
        let body: serde_json::Value = serde_json::from_slice(&events[2].payload).unwrap();
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(body["output"]["tool_name"], serde_json::json!("echo"));
    }

    #[test]
    fn the_tool_event_is_durable_before_the_tool_runs() {
        // The EXECUTE_TOOL row must exist with an earlier seq than the result,
        // which is the observable form of "written to disk before side effects".
        let mut rt = started();
        rt.submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        )
        .unwrap();
        let events = rt.ledger().events(Some("s")).unwrap();
        let exec = events
            .iter()
            .find(|e| e.event == Event::ExecuteTool)
            .unwrap();
        let result = events
            .iter()
            .find(|e| e.event == Event::ToolResult)
            .unwrap();
        assert!(exec.seq < result.seq);
    }

    #[test]
    fn unknown_tool_is_rejected_and_never_dispatched() {
        let mut rt = started();
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
        assert!(out.tool.is_none());
        assert_eq!(rt.session("s").unwrap().state, State::Planning);
    }

    #[test]
    fn a_failing_tool_still_produces_a_tool_result() {
        // A tool that traps must not strand the session in TOOL_EXECUTION —
        // the failure has to come back as a result the model can react to.
        let trap_wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "run") (param i32) (param i32) (result i64) (unreachable)))
        "#;
        let mut registry = registry();
        registry.insert("boom", trap_wat.as_bytes()).unwrap();
        let mut rt = Runtime::new(
            Ledger::open_in_memory([9u8; 32]).unwrap(),
            Limits::default(),
            Clock::new(),
            registry,
        );
        rt.open_session("s").unwrap();
        rt.submit("s", Event::Start, Origin::Proposer, b"{}")
            .unwrap();

        let out = rt
            .submit(
                "s",
                Event::ExecuteTool,
                Origin::Proposer,
                br#"{"tool_name":"boom"}"#,
            )
            .unwrap();

        assert!(out.tool.as_ref().unwrap().output.is_err());
        assert_eq!(out.final_state(), State::Reflecting);

        let events = rt.ledger().events(Some("s")).unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&events.last().unwrap().payload).unwrap();
        assert_eq!(body["ok"], serde_json::json!(false));
        assert!(body["error"].as_str().unwrap().contains("trap"));
    }

    #[test]
    fn ledger_verifies_after_a_mixed_run() {
        let mut rt = started();
        rt.submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        )
        .unwrap();
        rt.submit("s", Event::Start, Origin::Proposer, b"{}")
            .unwrap(); // illegal
        rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
            .unwrap();

        assert_eq!(rt.session("s").unwrap().state, State::Done);
        assert!(rt.ledger().verify().is_ok());
    }
}
