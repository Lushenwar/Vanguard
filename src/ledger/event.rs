//! Ledger record shape and the HMAC chain over it.
//!
//! The chain is the audit guarantee: given the key, any mutation, deletion, or
//! reordering of any event in the ledger is detectable, and the first divergent
//! `seq` names exactly where it happened.

use crate::fsm::state::{Event, Origin, RejectReason, State};

pub const HASH_LEN: usize = 32;
pub type Hash = [u8; HASH_LEN];

/// `prev_hash` of the first event. Not a random IV: a fixed genesis is what
/// lets a verifier start from nothing but the key.
pub const GENESIS: Hash = [0u8; HASH_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Accepted,
    Rejected,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Accepted => "ACCEPTED",
            Status::Rejected => "REJECTED",
        }
    }

    pub fn parse(s: &str) -> Option<Status> {
        Some(match s {
            "ACCEPTED" => Status::Accepted,
            "REJECTED" => Status::Rejected,
            _ => return None,
        })
    }
}

/// An event about to be written. Carries no `seq`, `prev_hash`, or `hash`:
/// those are assigned by the ledger, because they are the fields a caller must
/// not be able to choose.
#[derive(Debug, Clone)]
pub struct Draft {
    pub session_id: String,
    pub mono_ns: u64,
    pub wall_ms: i64,
    pub from_state: State,
    pub event: Event,
    pub origin: Origin,
    pub payload: Vec<u8>,
    pub status: Status,
    pub reason: Option<RejectReason>,
    pub to_state: State,
}

/// A committed event, exactly as stored.
#[derive(Debug, Clone)]
pub struct Record {
    pub seq: u64,
    pub session_id: String,
    pub mono_ns: u64,
    /// Wall clock, advisory only. Never hashed and never used for ordering —
    /// NTP steps and container migrations move it backwards.
    pub wall_ms: i64,
    pub from_state: State,
    pub event: Event,
    pub origin: Origin,
    pub payload: Vec<u8>,
    pub status: Status,
    pub reason: Option<RejectReason>,
    pub to_state: State,
    pub prev_hash: Hash,
    pub hash: Hash,
}

impl Record {
    pub fn from_draft(draft: Draft, seq: u64, prev_hash: Hash, key: &[u8]) -> Record {
        let mut rec = Record {
            seq,
            session_id: draft.session_id,
            mono_ns: draft.mono_ns,
            wall_ms: draft.wall_ms,
            from_state: draft.from_state,
            event: draft.event,
            origin: draft.origin,
            payload: draft.payload,
            status: draft.status,
            reason: draft.reason,
            to_state: draft.to_state,
            prev_hash,
            hash: GENESIS,
        };
        rec.hash = rec.compute_hash(key);
        rec
    }

    /// `HMAC-SHA256(key, prev_hash || preimage)`.
    pub fn compute_hash(&self, key: &[u8]) -> Hash {
        use hmac::{Mac, SimpleHmac};
        use sha2::Sha256;

        // `SimpleHmac` over `Sha256` rather than the specialised `Hmac`: both
        // are RFC 2104, and this one needs no `CoreProxy` bound gymnastics.
        let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(&self.prev_hash);
        mac.update(&self.preimage());
        mac.finalize().into_bytes().into()
    }

    /// The canonical byte encoding of everything the chain commits to.
    ///
    /// Every variable-length field is length-prefixed. Without prefixes,
    /// `("AB", "C")` and `("A", "BC")` encode identically, so a proposer who
    /// controls the payload could shift bytes across a field boundary and forge
    /// a record that hashes the same as a different one.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.payload.len());
        out.extend_from_slice(&self.seq.to_be_bytes());
        push_field(&mut out, self.session_id.as_bytes());
        out.extend_from_slice(&self.mono_ns.to_be_bytes());
        push_field(&mut out, self.from_state.as_str().as_bytes());
        push_field(&mut out, self.event.as_str().as_bytes());
        push_field(&mut out, self.origin.as_str().as_bytes());
        push_field(&mut out, self.status.as_str().as_bytes());
        push_field(
            &mut out,
            self.reason.map(|r| r.as_str()).unwrap_or("").as_bytes(),
        );
        push_field(&mut out, self.to_state.as_str().as_bytes());
        push_field(&mut out, &self.payload);
        out
    }

    /// Whether this record's stored hash matches its contents under `key`.
    pub fn verify_hash(&self, key: &[u8]) -> bool {
        // Not constant-time on purpose: both sides come from local storage, and
        // an attacker who can time this call can also read the key file.
        self.compute_hash(key) == self.hash
    }
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    // A field longer than 4 GiB cannot occur: payloads are capped far below
    // this by `limits.max_payload_bytes`, and every other field is a fixed
    // enum string or a session id.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(session: &str, payload: &[u8]) -> Record {
        Record::from_draft(
            Draft {
                session_id: session.into(),
                mono_ns: 1,
                wall_ms: 0,
                from_state: State::Idle,
                event: Event::Start,
                origin: Origin::Proposer,
                payload: payload.to_vec(),
                status: Status::Accepted,
                reason: None,
                to_state: State::Planning,
            },
            1,
            GENESIS,
            b"key",
        )
    }

    #[test]
    fn hash_verifies_against_itself() {
        assert!(rec("s", b"{}").verify_hash(b"key"));
    }

    #[test]
    fn wrong_key_fails_verification() {
        assert!(!rec("s", b"{}").verify_hash(b"other"));
    }

    #[test]
    fn one_flipped_payload_byte_changes_the_hash() {
        assert_ne!(rec("s", b"{\"a\":1}").hash, rec("s", b"{\"a\":2}").hash);
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        // The attack length-prefixing exists to stop: move a byte from the
        // session id into the payload and the concatenation is identical.
        assert_ne!(rec("ab", b"c").hash, rec("a", b"bc").hash);
    }

    #[test]
    fn hex_round_trips() {
        let h = rec("s", b"{}").hash;
        assert_eq!(unhex(&hex(&h)).unwrap(), h.to_vec());
        assert_eq!(unhex("xyz"), None);
        assert_eq!(unhex("abc"), None);
    }
}
