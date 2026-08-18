//! The legal edge set, and nothing else.
//!
//! The transition table is a `match`. A `BTreeMap` built at startup would be
//! the same data with a lookup, an allocation, and a chance of being mutated at
//! runtime; a `match` is checked by the compiler and cannot be reconfigured by
//! anything that gets loaded later, which is the property that matters for a
//! table defining a security boundary.

use super::state::{Event, State};

/// The transition function `T(S, E)`. `None` means the edge does not exist.
///
/// This is the single source of truth for CLAUDE.md's "FSM: TRANSITION TABLE".
/// Adding a state or event without touching this function is a compile error,
/// which is the point.
pub fn next(state: State, event: Event) -> Option<State> {
    // ABORT is legal from any non-terminal state and is the only edge that is
    // not a specific pair, so it is handled before the table.
    if event == Event::Abort {
        return if state.is_terminal() {
            None
        } else {
            Some(State::Halted)
        };
    }

    Some(match (state, event) {
        (State::Idle, Event::Start) => State::Planning,
        (State::Planning, Event::ExecuteTool) => State::ToolExecution,
        (State::Planning, Event::Finish) => State::Done,
        (State::ToolExecution, Event::ToolResult) => State::Reflecting,
        (State::Reflecting, Event::ExecuteTool) => State::ToolExecution,
        (State::Reflecting, Event::Finish) => State::Done,
        _ => return None,
    })
}

/// Whether the edge exists at all, ignoring budgets and origin.
pub fn is_legal(state: State, event: Event) -> bool {
    next(state, event).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::state::Origin;

    /// The table from CLAUDE.md, transcribed independently of the
    /// implementation. If the two ever disagree, one of them is a typo.
    const TABLE: &[(State, Event, State)] = &[
        (State::Idle, Event::Start, State::Planning),
        (State::Planning, Event::ExecuteTool, State::ToolExecution),
        (State::Planning, Event::Finish, State::Done),
        (State::ToolExecution, Event::ToolResult, State::Reflecting),
        (State::Reflecting, Event::ExecuteTool, State::ToolExecution),
        (State::Reflecting, Event::Finish, State::Done),
        (State::Idle, Event::Abort, State::Halted),
        (State::Planning, Event::Abort, State::Halted),
        (State::ToolExecution, Event::Abort, State::Halted),
        (State::Reflecting, Event::Abort, State::Halted),
    ];

    #[test]
    fn every_documented_edge_exists() {
        for &(from, event, to) in TABLE {
            assert_eq!(next(from, event), Some(to), "{from} --{event}--> {to}");
        }
    }

    #[test]
    fn no_undocumented_edge_exists() {
        for from in State::ALL {
            for event in Event::ALL {
                let documented = TABLE.iter().any(|&(f, e, _)| f == from && e == event);
                assert_eq!(
                    is_legal(from, event),
                    documented,
                    "({from}, {event}) legality disagrees with the documented table"
                );
            }
        }
    }

    #[test]
    fn terminal_states_have_no_outgoing_edges() {
        for from in State::ALL.into_iter().filter(|s| s.is_terminal()) {
            for event in Event::ALL {
                assert_eq!(next(from, event), None, "{from} accepted {event}");
            }
        }
    }

    #[test]
    fn no_proposer_event_reaches_halted() {
        // Only the runtime may halt a session. If a proposer event could reach
        // HALTED, a model could end its own session without the runtime
        // recording why.
        for from in State::ALL {
            for event in Event::ALL
                .into_iter()
                .filter(|e| e.origin() == Origin::Proposer)
            {
                assert_ne!(next(from, event), Some(State::Halted));
            }
        }
    }
}
