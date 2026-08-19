//! gRPC control plane.
//!
//! `actor` owns the runtime on one thread; `grpc` is a translation layer over
//! it that makes no decisions of its own. Keeping those apart is what lets the
//! single-writer guarantee be a property of the process rather than of the
//! transport that happens to be in front of it.

pub mod actor;
pub mod client;
pub mod grpc;
pub mod server;

/// Generated from `src/api/proto/vanguard.proto`.
pub mod pb {
    tonic::include_proto!("vanguard.v1");
}

pub use actor::{Handle, HealthSnapshot, StateSnapshot};
pub use client::{connect, Client};
pub use grpc::ControlService;
