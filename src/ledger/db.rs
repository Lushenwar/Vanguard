//! SQLite-backed append-only event ledger.
//!
//! One `Ledger` owns one write connection and is the only thing that writes.
//! That ownership *is* the single-writer rule from CLAUDE.md: with no second
//! writer there is no `SQLITE_BUSY` to lose a commit to, and `seq` allocation
//! needs no lock beyond `&mut self`.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Error, Result};
use crate::fsm::engine::SessionView;
use crate::fsm::state::{Event, Origin, RejectReason, State};
use crate::ledger::event::{Draft, Hash, Record, Status, GENESIS, HASH_LEN};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    created_ms  INTEGER NOT NULL,
    state       TEXT    NOT NULL,
    steps       INTEGER NOT NULL DEFAULT 0,
    rejects     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    seq         INTEGER PRIMARY KEY,
    session_id  TEXT    NOT NULL REFERENCES sessions(id),
    mono_ns     INTEGER NOT NULL,
    wall_ms     INTEGER NOT NULL,
    from_state  TEXT    NOT NULL,
    event       TEXT    NOT NULL,
    origin      TEXT    NOT NULL,
    payload     BLOB    NOT NULL,
    status      TEXT    NOT NULL,
    reason      TEXT,
    to_state    TEXT    NOT NULL,
    prev_hash   BLOB    NOT NULL,
    hash        BLOB    NOT NULL
);

CREATE INDEX IF NOT EXISTS events_by_session ON events(session_id, seq);

-- How far each audit sink has been exported. One row per sink, so two sinks
-- consuming at different speeds do not interfere.
CREATE TABLE IF NOT EXISTS export_cursor (
    sink    TEXT PRIMARY KEY,
    seq     INTEGER NOT NULL
);
"#;

const SELECT_EVENT: &str = "SELECT seq, session_id, mono_ns, wall_ms, from_state, event, origin, \
                            payload, status, reason, to_state, prev_hash, hash FROM events";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub created_ms: i64,
    pub view: SessionView,
}

pub struct Ledger {
    conn: Connection,
    key: [u8; HASH_LEN],
    head_seq: u64,
    head_hash: Hash,
}

impl Ledger {
    /// Open (creating if absent) the ledger at `path`.
    ///
    /// Does not verify the chain — `verify` is separate so that `vgctl verify`
    /// can run against a ledger the daemon has already refused to boot on.
    pub fn open(path: &Path, key: [u8; HASH_LEN]) -> Result<Ledger> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        // WAL for concurrent readers; FULL because losing the trailing commits
        // to a power cut is exactly the chain break we are defending against,
        // and the last event is the one that matters most.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;

        let (head_seq, head_hash) = read_head(&conn)?;
        Ok(Ledger {
            conn,
            key,
            head_seq,
            head_hash,
        })
    }

    pub fn open_in_memory(key: [u8; HASH_LEN]) -> Result<Ledger> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Ledger {
            conn,
            key,
            head_seq: 0,
            head_hash: GENESIS,
        })
    }

    /// `(seq, hash)` of the newest event, or `(0, GENESIS)` when empty.
    pub fn head(&self) -> (u64, Hash) {
        (self.head_seq, self.head_hash)
    }

    pub fn create_session(&self, id: &str, created_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions (id, created_ms, state, steps, rejects) \
             VALUES (?1, ?2, ?3, 0, 0)",
            params![id, created_ms, State::Idle.as_str()],
        )?;
        Ok(())
    }

    pub fn session(&self, id: &str) -> Result<Option<SessionRow>> {
        self.conn
            .query_row(
                "SELECT id, created_ms, state, steps, rejects FROM sessions WHERE id = ?1",
                params![id],
                |row| {
                    let state: String = row.get(2)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        state,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .map(|(id, created_ms, state, steps, rejects)| {
                let state = State::parse(&state).ok_or_else(|| {
                    Error::Config(format!("session {id} has unknown state {state:?}"))
                })?;
                Ok(SessionRow {
                    id,
                    created_ms,
                    view: SessionView {
                        state,
                        steps: steps as u32,
                        consecutive_rejects: rejects as u32,
                    },
                })
            })
            .transpose()
    }

    pub fn session_ids(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT id FROM sessions ORDER BY id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Append one event and move the session to its post-decision state, in a
    /// single transaction.
    ///
    /// Atomicity here is what makes "zero unhandled state mutations" true: a
    /// crash can leave both written or neither, never a state change with no
    /// event explaining it. The commit returning is also the point after which
    /// a caller may trigger side effects.
    pub fn commit(&mut self, draft: Draft, session_after: SessionView) -> Result<Record> {
        let seq = self.head_seq + 1;
        let record = Record::from_draft(draft, seq, self.head_hash, &self.key);

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO events (seq, session_id, mono_ns, wall_ms, from_state, event, origin, \
             payload, status, reason, to_state, prev_hash, hash) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                record.seq as i64,
                record.session_id,
                record.mono_ns as i64,
                record.wall_ms,
                record.from_state.as_str(),
                record.event.as_str(),
                record.origin.as_str(),
                record.payload,
                record.status.as_str(),
                record.reason.map(|r| r.as_str()),
                record.to_state.as_str(),
                record.prev_hash.as_slice(),
                record.hash.as_slice(),
            ],
        )?;
        tx.execute(
            "UPDATE sessions SET state = ?1, steps = ?2, rejects = ?3 WHERE id = ?4",
            params![
                session_after.state.as_str(),
                session_after.steps as i64,
                session_after.consecutive_rejects as i64,
                record.session_id,
            ],
        )?;
        tx.commit()?;

        self.head_seq = record.seq;
        self.head_hash = record.hash;
        Ok(record)
    }

    /// All events, oldest first, optionally filtered to one session.
    pub fn events(&self, session_id: Option<&str>) -> Result<Vec<Record>> {
        let raws: Vec<RawRow> = match session_id {
            Some(id) => {
                let mut stmt = self.conn.prepare(&format!(
                    "{SELECT_EVENT} WHERE session_id = ?1 ORDER BY seq"
                ))?;
                let rows = stmt.query_map(params![id], raw_row)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let mut stmt = self.conn.prepare(&format!("{SELECT_EVENT} ORDER BY seq"))?;
                let rows = stmt.query_map([], raw_row)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        raws.into_iter().map(decode_row).collect()
    }

    /// How far `sink` has been exported. Zero when it has never run, which is
    /// the same state as a brand new sink — so a sink added later replays the
    /// whole ledger rather than starting blind at the head.
    pub fn export_cursor(&self, sink: &str) -> Result<u64> {
        let seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM export_cursor WHERE sink = ?1",
                params![sink],
                |r| r.get(0),
            )
            .optional()?;
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Record that `sink` has durably consumed everything up to `seq`.
    ///
    /// Only ever moves forward. A rewind would silently re-export, and worse,
    /// a rewind caused by a bug would look identical to normal operation.
    pub fn set_export_cursor(&self, sink: &str, seq: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO export_cursor (sink, seq) VALUES (?1, ?2) \
             ON CONFLICT(sink) DO UPDATE SET seq = max(seq, excluded.seq)",
            params![sink, seq as i64],
        )?;
        Ok(())
    }

    /// Up to `limit` events with `seq > after`, oldest first.
    pub fn events_after(&self, after: u64, limit: usize) -> Result<Vec<Record>> {
        let mut stmt = self.conn.prepare(&format!(
            "{SELECT_EVENT} WHERE seq > ?1 ORDER BY seq LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![after as i64, limit as i64], raw_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(decode_row)
            .collect()
    }

    /// Recompute the whole chain from genesis.
    ///
    /// Streams rather than loading `events()` into memory: a ledger is
    /// append-only and unbounded, and verification is exactly the operation you
    /// want to still work when it has grown large.
    pub fn verify(&self) -> Result<Verification> {
        let mut stmt = self.conn.prepare(&format!("{SELECT_EVENT} ORDER BY seq"))?;
        let rows = stmt.query_map([], raw_row)?;

        let mut prev = GENESIS;
        let mut count = 0u64;

        for raw in rows {
            let record = decode_row(raw?)?;
            let expected_seq = count + 1;

            if record.seq != expected_seq {
                return Err(Error::ChainBroken {
                    seq: record.seq,
                    detail: format!("expected seq {expected_seq}, found {}", record.seq),
                });
            }
            if record.prev_hash != prev {
                return Err(Error::ChainBroken {
                    seq: record.seq,
                    detail: "prev_hash does not match the previous event's hash".into(),
                });
            }
            if !record.verify_hash(&self.key) {
                return Err(Error::ChainBroken {
                    seq: record.seq,
                    detail: "hash does not match the record contents".into(),
                });
            }

            prev = record.hash;
            count += 1;
        }

        Ok(Verification {
            events: count,
            head_seq: count,
            head_hash: prev,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub events: u64,
    pub head_seq: u64,
    pub head_hash: Hash,
}

/// The column tuple as SQLite hands it over, before any enum parsing. Split out
/// so decoding errors surface as `CorruptRow` with a `seq` rather than as an
/// opaque `rusqlite` type error from inside a closure.
type RawRow = (
    i64,
    String,
    i64,
    i64,
    String,
    String,
    String,
    Vec<u8>,
    String,
    Option<String>,
    String,
    Vec<u8>,
    Vec<u8>,
);

fn raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn decode_row(raw: RawRow) -> Result<Record> {
    let (
        seq,
        session_id,
        mono_ns,
        wall_ms,
        from_state,
        event,
        origin,
        payload,
        status,
        reason,
        to_state,
        prev_hash,
        hash,
    ) = raw;
    let seq = seq as u64;
    let bad = |detail: String| Error::CorruptRow { seq, detail };

    Ok(Record {
        seq,
        session_id,
        mono_ns: mono_ns as u64,
        wall_ms,
        from_state: State::parse(&from_state)
            .ok_or_else(|| bad(format!("unknown from_state {from_state:?}")))?,
        event: Event::parse(&event).ok_or_else(|| bad(format!("unknown event {event:?}")))?,
        origin: Origin::parse(&origin).ok_or_else(|| bad(format!("unknown origin {origin:?}")))?,
        payload,
        status: Status::parse(&status).ok_or_else(|| bad(format!("unknown status {status:?}")))?,
        reason: reason
            .as_deref()
            .map(|r| {
                RejectReason::parse(r).ok_or_else(|| bad(format!("unknown reject reason {r:?}")))
            })
            .transpose()?,
        to_state: State::parse(&to_state)
            .ok_or_else(|| bad(format!("unknown to_state {to_state:?}")))?,
        prev_hash: to_hash(&prev_hash).ok_or_else(|| bad("prev_hash is not 32 bytes".into()))?,
        hash: to_hash(&hash).ok_or_else(|| bad("hash is not 32 bytes".into()))?,
    })
}

fn to_hash(bytes: &[u8]) -> Option<Hash> {
    <Hash>::try_from(bytes).ok()
}

fn read_head(conn: &Connection) -> Result<(u64, Hash)> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    match row {
        None => Ok((0, GENESIS)),
        Some((seq, hash)) => {
            let seq = seq as u64;
            let hash = to_hash(&hash).ok_or(Error::CorruptRow {
                seq,
                detail: "head hash is not 32 bytes".into(),
            })?;
            Ok((seq, hash))
        }
    }
}
