//! Vanguard: a deterministic agent state engine.
//!
//! The thesis, in one line: LLMs propose state transitions; the system executes
//! them. Everything here exists to keep control flow out of the model's hands —
//! a fixed edge set it cannot extend, budgets it cannot raise, and an
//! append-only ledger it cannot rewrite.

pub mod clock;
pub mod config;
pub mod error;
pub mod fsm;
pub mod ledger;
pub mod memory;
pub mod runtime;
pub mod sandbox;

pub use error::{Error, Result};
