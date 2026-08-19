//! The proposal evaluator: a pure function from (session, limits, proposal) to
//! a decision. No clock, no disk, no allocation on the accept path.
//!
//! Purity is the reason this is testable in microseconds and the reason replay
//! can trust it. Anything that needs the world — appending to the ledger,
//! dispatching a tool, halting a session — happens in `runtime`, which calls
//! this and then acts on the answer.

use std::collections::BTreeSet;

use super::state::{Event, Origin, RejectReason, State};
use super::transition;

/// Runtime budgets. Mirrored from `config::Limits`, which owns the serde
/// derives and the TOML field names; keeping a plain copy here keeps `fsm`
/// independent of how configuration happens to be spelled on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_steps: u32,
    pub max_consecutive_rejects: u32,
    pub max_payload_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_steps: 50,
            max_consecutive_rejects: 3,
            max_payload_bytes: 65_536,
        }
    }
}

/// Everything the evaluator is allowed to know about a session.
///
/// A snapshot rather than a `&mut Session`: the evaluator must not be able to
/// mutate state, because state mutation is only legal after the ledger append
/// has committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionView {
    pub state: State,
    /// Accepted proposer events so far.
    pub steps: u32,
    /// Rejections since the last acceptance. Reset to zero on any accept.
    pub consecutive_rejects: u32,
}

impl SessionView {
    pub fn new() -> Self {
        SessionView {
            state: State::Idle,
            steps: 0,
            consecutive_rejects: 0,
        }
    }
}

impl Default for SessionView {
    fn default() -> Self {
        Self::new()
    }
}

/// The evaluator's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept {
        to: State,
        /// Whether this acceptance spends one of `max_steps`. Only proposer
        /// events do; a tool result the runtime feeds back is bookkeeping, not
        /// a step the model gets to spend.
        consumes_step: bool,
    },
    Reject {
        reason: RejectReason,
    },
}

impl Decision {
    pub fn is_accept(&self) -> bool {
        matches!(self, Decision::Accept { .. })
    }

    /// The state the session is in after this decision. Rejections do not move
    /// state, which is why `from_state == to_state` on every REJECTED row.
    pub fn to_state(&self, from: State) -> State {
        match self {
            Decision::Accept { to, .. } => *to,
            Decision::Reject { .. } => from,
        }
    }
}

/// Why the runtime is about to halt a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltReason {
    StepBudget,
    RejectLoop,
    StateTimeout,
}

impl HaltReason {
    pub fn as_str(self) -> &'static str {
        match self {
            HaltReason::StepBudget => "step budget exhausted",
            HaltReason::RejectLoop => "consecutive rejection cap reached",
            HaltReason::StateTimeout => "state timeout",
        }
    }
}

/// Evaluate one proposal.
///
/// `submitted_origin` is what the *caller* claims, not what the event actually
/// is; the mismatch between the two is the whole point of the first check.
pub fn evaluate(
    session: SessionView,
    limits: &Limits,
    event: Event,
    submitted_origin: Origin,
    payload: &[u8],
    tools: &BTreeSet<String>,
) -> Decision {
    // 1. Origin, before anything else. A proposer submitting TOOL_RESULT is a
    //    model trying to fabricate a tool it never ran; that must be rejected
    //    on identity alone, without the edge table getting a say.
    if submitted_origin != event.origin() {
        return reject(RejectReason::ForgedOrigin);
    }

    // 2. Terminal sessions are closed to everyone, including the runtime.
    if session.state.is_terminal() {
        return reject(RejectReason::TerminalState);
    }

    // 3. Size before parsing: refusing to parse an oversized payload is what
    //    keeps a hostile proposer from spending the daemon's CPU on a 4 GB
    //    nesting bomb before the limit check would have thrown it away.
    if payload.len() > limits.max_payload_bytes {
        return reject(RejectReason::PayloadTooLarge);
    }

    // 4. Payload must be valid UTF-8 JSON even though it is stored verbatim.
    //    Storing bytes we cannot parse would make the ledger unauditable.
    if !payload.is_empty() && serde_json::from_slice::<serde::de::IgnoredAny>(payload).is_err() {
        return reject(RejectReason::MalformedPayload);
    }

    // 5. A tool call must name a tool that exists. Absence of a rule is a
    //    denial, so an empty registry refuses every tool — the right posture
    //    for a runtime that has not been told what it is allowed to run.
    if event == Event::ExecuteTool {
        match tool_name(payload) {
            None => return reject(RejectReason::MalformedPayload),
            Some(name) if !tools.contains(&name) => return reject(RejectReason::UnknownTool),
            Some(_) => {}
        }
    }

    let consumes_step = event.origin() == Origin::Proposer;

    // 6. Budget. Normally the runtime halts the session the moment the last
    //    step is spent, so this is a backstop: it is reachable when the daemon
    //    crashed between appending the final step and appending its ABORT, and
    //    the session was reloaded still non-terminal.
    if consumes_step && session.steps >= limits.max_steps {
        return reject(RejectReason::StepBudgetExhausted);
    }

    // 7. Finally the edge table.
    match transition::next(session.state, event) {
        Some(to) => Decision::Accept { to, consumes_step },
        None => reject(RejectReason::IllegalEdge),
    }
}

/// Whether the runtime must now halt the session, given its state *after* a
/// decision has been applied. Returning `Some` obliges the caller to append a
/// runtime-origin `ABORT`.
pub fn halt_after(session: SessionView, limits: &Limits) -> Option<HaltReason> {
    if session.state.is_terminal() {
        return None;
    }
    if session.steps >= limits.max_steps {
        return Some(HaltReason::StepBudget);
    }
    if session.consecutive_rejects >= limits.max_consecutive_rejects {
        return Some(HaltReason::RejectLoop);
    }
    None
}

/// Apply a decision to a snapshot. Kept next to `evaluate` so the bookkeeping
/// rules — steps count accepts, rejects reset on accept — live in one place
/// instead of being re-derived by every caller.
pub fn apply(session: SessionView, decision: Decision) -> SessionView {
    match decision {
        Decision::Accept { to, consumes_step } => SessionView {
            state: to,
            steps: session.steps + u32::from(consumes_step),
            consecutive_rejects: 0,
        },
        Decision::Reject { .. } => SessionView {
            consecutive_rejects: session.consecutive_rejects + 1,
            ..session
        },
    }
}

fn reject(reason: RejectReason) -> Decision {
    Decision::Reject { reason }
}

/// The tool an `EXECUTE_TOOL` payload names, if it names one at all.
///
/// Public because the runtime needs the same answer the evaluator got: if the
/// two disagreed about which tool a payload refers to, the FSM would authorize
/// one tool and the dispatcher would run another.
pub fn tool_name(payload: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Named {
        tool_name: String,
    }
    serde_json::from_slice::<Named>(payload)
        .ok()
        .map(|n| n.tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(state: State) -> SessionView {
        SessionView {
            state,
            ..SessionView::new()
        }
    }

    fn no_tools() -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn with_echo() -> BTreeSet<String> {
        ["echo".to_string()].into_iter().collect()
    }

    fn eval(
        session: SessionView,
        limits: &Limits,
        event: Event,
        origin: Origin,
        payload: &[u8],
    ) -> Decision {
        evaluate(session, limits, event, origin, payload, &with_echo())
    }

    #[test]
    fn legal_proposer_edge_is_accepted() {
        let d = eval(
            view(State::Idle),
            &Limits::default(),
            Event::Start,
            Origin::Proposer,
            b"{}",
        );
        assert_eq!(
            d,
            Decision::Accept {
                to: State::Planning,
                consumes_step: true
            }
        );
    }

    #[test]
    fn forged_origin_beats_every_other_check() {
        // TOOL_RESULT from TOOL_EXECUTION is a legal edge, so this proposal
        // would be accepted if origin were checked later or not at all.
        let d = eval(
            view(State::ToolExecution),
            &Limits::default(),
            Event::ToolResult,
            Origin::Proposer,
            b"{}",
        );
        assert_eq!(
            d,
            Decision::Reject {
                reason: RejectReason::ForgedOrigin
            }
        );
    }

    #[test]
    fn runtime_events_do_not_spend_steps() {
        let d = eval(
            view(State::ToolExecution),
            &Limits::default(),
            Event::ToolResult,
            Origin::Runtime,
            b"{}",
        );
        assert_eq!(
            d,
            Decision::Accept {
                to: State::Reflecting,
                consumes_step: false
            }
        );
    }

    #[test]
    fn rejections_never_move_state() {
        for from in State::ALL {
            for event in Event::ALL {
                let d = eval(
                    view(from),
                    &Limits::default(),
                    event,
                    event.origin(),
                    br#"{"tool_name":"echo"}"#,
                );
                if let Decision::Reject { .. } = d {
                    assert_eq!(apply(view(from), d).state, from);
                }
            }
        }
    }

    #[test]
    fn oversized_payload_rejected_before_parsing() {
        let limits = Limits {
            max_payload_bytes: 4,
            ..Limits::default()
        };
        // Invalid JSON *and* oversized: the size check must win, proving the
        // parser never saw it.
        let d = eval(
            view(State::Idle),
            &limits,
            Event::Start,
            Origin::Proposer,
            b"not json",
        );
        assert_eq!(
            d,
            Decision::Reject {
                reason: RejectReason::PayloadTooLarge
            }
        );
    }

    #[test]
    fn malformed_payload_rejected() {
        let d = eval(
            view(State::Idle),
            &Limits::default(),
            Event::Start,
            Origin::Proposer,
            b"{oops",
        );
        assert_eq!(
            d,
            Decision::Reject {
                reason: RejectReason::MalformedPayload
            }
        );
    }

    #[test]
    fn unknown_tool_rejected() {
        let d = eval(
            view(State::Planning),
            &Limits::default(),
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"rm_rf"}"#,
        );
        assert_eq!(
            d,
            Decision::Reject {
                reason: RejectReason::UnknownTool
            }
        );
    }

    #[test]
    fn an_empty_registry_denies_every_tool() {
        // The default posture. A runtime that has not been told what it may run
        // must run nothing, not everything.
        let d = evaluate(
            view(State::Planning),
            &Limits::default(),
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
            &no_tools(),
        );
        assert_eq!(
            d,
            Decision::Reject {
                reason: RejectReason::UnknownTool
            }
        );
    }

    #[test]
    fn tool_call_without_a_tool_name_is_malformed() {
        let d = eval(
            view(State::Planning),
            &Limits::default(),
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"arguments":{}}"#,
        );
        assert_eq!(
            d,
            Decision::Reject {
                reason: RejectReason::MalformedPayload
            }
        );
    }

    #[test]
    fn known_tool_is_accepted() {
        let d = eval(
            view(State::Planning),
            &Limits::default(),
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        );
        assert_eq!(
            d,
            Decision::Accept {
                to: State::ToolExecution,
                consumes_step: true
            }
        );
    }

    #[test]
    fn exhausted_budget_rejects_without_halting_state() {
        let limits = Limits::default();
        let session = SessionView {
            state: State::Planning,
            steps: limits.max_steps,
            consecutive_rejects: 0,
        };
        let d = eval(session, &limits, Event::Finish, Origin::Proposer, b"{}");
        assert_eq!(
            d,
            Decision::Reject {
                reason: RejectReason::StepBudgetExhausted
            }
        );
        assert_eq!(apply(session, d).state, State::Planning);
    }

    #[test]
    fn accept_resets_the_reject_counter() {
        let session = SessionView {
            state: State::Idle,
            steps: 0,
            consecutive_rejects: 2,
        };
        let after = apply(
            session,
            Decision::Accept {
                to: State::Planning,
                consumes_step: true,
            },
        );
        assert_eq!(after.consecutive_rejects, 0);
        assert_eq!(after.steps, 1);
    }

    #[test]
    fn halt_after_fires_on_each_budget() {
        let limits = Limits::default();
        assert_eq!(halt_after(view(State::Planning), &limits), None);
        assert_eq!(
            halt_after(
                SessionView {
                    state: State::Planning,
                    steps: limits.max_steps,
                    consecutive_rejects: 0
                },
                &limits
            ),
            Some(HaltReason::StepBudget)
        );
        assert_eq!(
            halt_after(
                SessionView {
                    state: State::Planning,
                    steps: 0,
                    consecutive_rejects: limits.max_consecutive_rejects
                },
                &limits
            ),
            Some(HaltReason::RejectLoop)
        );
        // Already terminal: nothing left to halt.
        assert_eq!(
            halt_after(
                SessionView {
                    state: State::Done,
                    steps: limits.max_steps,
                    consecutive_rejects: 99
                },
                &limits
            ),
            None
        );
    }

    #[test]
    fn tool_name_extraction_is_strict() {
        assert_eq!(
            tool_name(br#"{"tool_name":"echo"}"#).as_deref(),
            Some("echo")
        );
        assert_eq!(tool_name(br#"{"tool_name":7}"#), None);
        assert_eq!(tool_name(b"{}"), None);
        assert_eq!(tool_name(b"garbage"), None);
    }
}
