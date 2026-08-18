//! The enforcer: joins the pure FSM evaluator to the durable ledger.
//!
//! The ordering in [`Runtime::submit`] is the whole contract. Evaluate, commit,
//! *then* act. Nothing downstream — no tool dispatch, no side effect — may
//! observe a state change that is not already on disk with an event explaining
//! how it got there.

use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::fsm::engine::{self, Decision, HaltReason, Limits, SessionView};
use crate::fsm::state::{Event, Origin, State};
use crate::ledger::event::{Draft, Record, Status};
use crate::ledger::Ledger;

pub struct Runtime {
    ledger: Ledger,
    limits: Limits,
    clock: Clock,
}

/// What one submission did. `halt` is present when the runtime followed the
/// submission with its own `ABORT` because a budget ran out.
#[derive(Debug)]
pub struct Outcome {
    pub decision: Decision,
    pub record: Record,
    pub session: SessionView,
    pub halt: Option<(HaltReason, Record)>,
}

impl Outcome {
    /// The state the session ended up in, after any halt.
    pub fn final_state(&self) -> State {
        self.session.state
    }
}

impl Runtime {
    pub fn new(ledger: Ledger, limits: Limits, clock: Clock) -> Runtime {
        Runtime {
            ledger,
            limits,
            clock,
        }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
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
    pub fn submit(
        &mut self,
        session_id: &str,
        event: Event,
        submitted_origin: Origin,
        payload: &[u8],
    ) -> Result<Outcome> {
        let before = self.session(session_id)?;

        let decision = engine::evaluate(before, &self.limits, event, submitted_origin, payload);
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

        // Budgets are checked against the post-commit state, so the ABORT is
        // always ordered after the event that exhausted the budget. An operator
        // reading the ledger sees the cause immediately before the effect.
        let halt = match engine::halt_after(after, &self.limits) {
            None => None,
            Some(reason) => Some((reason, self.halt(session_id, after, reason)?)),
        };

        let session = match &halt {
            Some(_) => self.session(session_id)?,
            None => after,
        };

        Ok(Outcome {
            decision,
            record,
            session,
            halt,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::state::RejectReason;

    fn runtime() -> Runtime {
        let ledger = Ledger::open_in_memory([7u8; 32]).unwrap();
        Runtime::new(ledger, Limits::default(), Clock::new())
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
        rt.submit("s", Event::ToolResult, Origin::Runtime, b"{}")
            .unwrap();
        rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
            .unwrap();

        assert_eq!(rt.session("s").unwrap().state, State::Done);
        let v = rt.ledger().verify().unwrap();
        assert_eq!(v.events, 5);
    }
}
