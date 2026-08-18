//! State, event, and origin vocabulary for the FSM.
//!
//! Deliberately dependency-free: no serde, no error crate, nothing that could
//! introduce nondeterminism or a version bump into the component every other
//! subsystem's correctness rests on. Wire encodings are hand-written `as_str`
//! and `parse` pairs, which is a dozen lines and never surprises anyone.

use std::fmt;

/// The six FSM states. See CLAUDE.md, "FSM: STATES".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    Idle,
    Planning,
    ToolExecution,
    Reflecting,
    Done,
    Halted,
}

impl State {
    /// Every state, in declaration order. Used by exhaustiveness tests that
    /// sweep the full (state, event) product looking for illegal edges.
    pub const ALL: [State; 6] = [
        State::Idle,
        State::Planning,
        State::ToolExecution,
        State::Reflecting,
        State::Done,
        State::Halted,
    ];

    /// Terminal states accept no further events, ever.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Done | State::Halted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            State::Idle => "IDLE",
            State::Planning => "PLANNING",
            State::ToolExecution => "TOOL_EXECUTION",
            State::Reflecting => "REFLECTING",
            State::Done => "DONE",
            State::Halted => "HALTED",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "IDLE" => State::Idle,
            "PLANNING" => State::Planning,
            "TOOL_EXECUTION" => State::ToolExecution,
            "REFLECTING" => State::Reflecting,
            "DONE" => State::Done,
            "HALTED" => State::Halted,
            _ => return None,
        })
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who is allowed to emit an event.
///
/// This is a security boundary, not a label. The proposer plane may submit only
/// [`Origin::Proposer`] events; a runtime-origin event arriving over the
/// proposal API is what a model fabricating its own tool results looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Proposer,
    Runtime,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Proposer => "PROPOSER",
            Origin::Runtime => "RUNTIME",
        }
    }

    pub fn parse(s: &str) -> Option<Origin> {
        Some(match s {
            "PROPOSER" => Origin::Proposer,
            "RUNTIME" => Origin::Runtime,
            _ => return None,
        })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The five events. See CLAUDE.md, "FSM: EVENTS AND ORIGIN".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Event {
    Start,
    ExecuteTool,
    Finish,
    ToolResult,
    Abort,
}

impl Event {
    pub const ALL: [Event; 5] = [
        Event::Start,
        Event::ExecuteTool,
        Event::Finish,
        Event::ToolResult,
        Event::Abort,
    ];

    /// The only origin permitted to emit this event. Fixed per event, so the
    /// check is a comparison rather than a table lookup or a config toggle.
    pub fn origin(self) -> Origin {
        match self {
            Event::Start | Event::ExecuteTool | Event::Finish => Origin::Proposer,
            Event::ToolResult | Event::Abort => Origin::Runtime,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Event::Start => "START",
            Event::ExecuteTool => "EXECUTE_TOOL",
            Event::Finish => "FINISH",
            Event::ToolResult => "TOOL_RESULT",
            Event::Abort => "ABORT",
        }
    }

    pub fn parse(s: &str) -> Option<Event> {
        Some(match s {
            "START" => Event::Start,
            "EXECUTE_TOOL" => Event::ExecuteTool,
            "FINISH" => Event::Finish,
            "TOOL_RESULT" => Event::ToolResult,
            "ABORT" => Event::Abort,
            _ => return None,
        })
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Closed set of rejection reasons. See CLAUDE.md, "FSM: REJECTION REASONS".
///
/// There is no `Other` variant on purpose: an open-ended reason means audit
/// consumers cannot enumerate what a rejection can mean, and every new failure
/// mode silently collapses into the same bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RejectReason {
    IllegalEdge,
    TerminalState,
    ForgedOrigin,
    StepBudgetExhausted,
    PayloadTooLarge,
    MalformedPayload,
    UnknownTool,
    SessionUnknown,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::IllegalEdge => "IllegalEdge",
            RejectReason::TerminalState => "TerminalState",
            RejectReason::ForgedOrigin => "ForgedOrigin",
            RejectReason::StepBudgetExhausted => "StepBudgetExhausted",
            RejectReason::PayloadTooLarge => "PayloadTooLarge",
            RejectReason::MalformedPayload => "MalformedPayload",
            RejectReason::UnknownTool => "UnknownTool",
            RejectReason::SessionUnknown => "SessionUnknown",
        }
    }

    pub fn parse(s: &str) -> Option<RejectReason> {
        Some(match s {
            "IllegalEdge" => RejectReason::IllegalEdge,
            "TerminalState" => RejectReason::TerminalState,
            "ForgedOrigin" => RejectReason::ForgedOrigin,
            "StepBudgetExhausted" => RejectReason::StepBudgetExhausted,
            "PayloadTooLarge" => RejectReason::PayloadTooLarge,
            "MalformedPayload" => RejectReason::MalformedPayload,
            "UnknownTool" => RejectReason::UnknownTool,
            "SessionUnknown" => RejectReason::SessionUnknown,
            _ => return None,
        })
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_forms_round_trip() {
        for s in State::ALL {
            assert_eq!(State::parse(s.as_str()), Some(s));
        }
        for e in Event::ALL {
            assert_eq!(Event::parse(e.as_str()), Some(e));
        }
        for o in [Origin::Proposer, Origin::Runtime] {
            assert_eq!(Origin::parse(o.as_str()), Some(o));
        }
    }

    #[test]
    fn unknown_strings_do_not_parse() {
        assert_eq!(State::parse("PLANNING "), None);
        assert_eq!(State::parse("planning"), None);
        assert_eq!(Event::parse("CONTINUE"), None);
    }

    #[test]
    fn only_done_and_halted_are_terminal() {
        let terminal: Vec<State> = State::ALL.into_iter().filter(|s| s.is_terminal()).collect();
        assert_eq!(terminal, vec![State::Done, State::Halted]);
    }
}
