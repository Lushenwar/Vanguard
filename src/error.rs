//! Crate-wide error type.
//!
//! One enum rather than per-module errors: the failure modes here are almost
//! all fatal to the daemon (a broken chain, an unreadable key, a corrupt row),
//! so callers act on them the same way and per-module types would only add
//! conversion boilerplate between layers.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(String),

    /// The hash chain does not validate. `seq` is the *first* divergent event,
    /// which is what an operator needs — later events are all downstream of it.
    #[error("ledger chain broken at seq {seq}: {detail}")]
    ChainBroken { seq: u64, detail: String },

    /// A row exists but does not decode: an unknown state string, a hash of the
    /// wrong width. Distinct from `ChainBroken` because it means the ledger was
    /// written by something other than this binary.
    #[error("corrupt ledger row at seq {seq}: {detail}")]
    CorruptRow { seq: u64, detail: String },

    #[error("unknown session: {0}")]
    UnknownSession(String),

    /// Nothing is listening on the control plane. Its own variant rather than a
    /// `Config` string because `vgctl` turns it into a distinct exit code, and
    /// matching on a message is how that silently stops working.
    #[error("cannot reach vanguardd at {endpoint}: {detail}")]
    Unreachable { endpoint: String, detail: String },

    /// The daemon answered, but with an error of its own.
    #[error("control plane: {0}")]
    ControlPlane(String),

    #[error("ledger key at {path} is readable by other users; refusing to start")]
    KeyPermissions { path: PathBuf },

    #[error("ledger key must be {expected} bytes, found {found}")]
    KeyLength { expected: usize, found: usize },
}

pub type Result<T> = std::result::Result<T, Error>;
