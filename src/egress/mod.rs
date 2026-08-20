//! Egress control: who a tool is allowed to talk to.
//!
//! Two layers, and it matters which one is doing the work.
//!
//! [`policy`] is the allowlist, and it is the shared truth: pure, deterministic,
//! testable on every platform, and the reference the kernel filter must agree
//! with. [`filter`] is the eBPF enforcement point, which exists only on Linux.
//!
//! Today neither is what stops a tool reaching the network. The wasm linker is
//! empty, so a tool has no host binding through which a socket could be opened
//! — the syscall cannot be reached rather than being blocked once attempted,
//! which is the stronger guarantee. These layers are what keeps that true the
//! day a host binding or a subprocess wrapper is added.

pub mod filter;
pub mod policy;

pub use policy::{EgressPolicy, Entry, Rule, Verdict};
