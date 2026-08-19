//! Context paging: keeping the proposer's prompt inside a fixed token budget.
//!
//! There is no `eviction.rs`. The eviction policy is "keep the newest events
//! that fit, count the rest", which is a dozen lines living next to the code
//! that uses them; a separate module for one function with one caller is a file
//! to open at 3am for no reason. See SPEC CORRECTIONS #11 in CLAUDE.md.

pub mod pager;

pub use pager::{build, estimate_tokens, ContextWindow, Digest, Entry, Pinned, MIN_TOKENS};
