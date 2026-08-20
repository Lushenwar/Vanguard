//! Audit export: getting the ledger off this machine without losing any of it.
//!
//! The delivery guarantee is **at-least-once**, and that is a decision rather
//! than a limitation. A sink write and a cursor advance touch two different
//! systems — a file and SQLite — so they cannot commit atomically without
//! distributed-transaction machinery that would buy nothing here. Given that,
//! there are exactly two choices:
//!
//! * advance the cursor first, and lose records to a crash in between;
//! * write first, and re-send records after a crash in between.
//!
//! For an audit stream the second is the only defensible one. A duplicate is
//! detectable — every record carries a globally unique, monotonic `seq`, so a
//! consumer dedupes with one comparison. A missing record is undetectable by
//! definition, which is precisely the property an audit log exists to deny.
//!
//! Nothing is buffered in memory waiting to be exported. The cursor names a
//! position in the ledger, and the ledger is already durable, so the exporter
//! holds no state that a crash could take with it.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::ledger::event::{hex, Record};
use crate::ledger::Ledger;

/// Where exported records go.
pub trait AuditSink: Send {
    /// A stable name, used as the cursor key. Two sinks with the same name
    /// share a cursor and will each see only part of the stream.
    fn name(&self) -> &str;

    /// Write a batch. Must not return `Ok` until the batch is durable —
    /// returning early is what turns at-least-once into at-most-once.
    fn write(&mut self, records: &[Record]) -> Result<()>;
}

/// Newline-delimited JSON, appended to a file.
///
/// JSONL rather than a single JSON array: an array has to be rewritten to be
/// appended to, and a truncated array is unparseable, whereas a truncated JSONL
/// file loses only its last line.
pub struct JsonlSink {
    name: String,
    path: PathBuf,
    file: std::fs::File,
}

impl JsonlSink {
    pub fn open(path: &Path) -> Result<JsonlSink> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        // The cursor key is the *canonical* path, not the path as spelled.
        // `./.vanguard/audit.jsonl` and `.vanguard/audit.jsonl` are the same
        // file; keying on the spelling gives them separate cursors, and the
        // second one replays the whole ledger into a file that already has it.
        // Canonicalising after the open is safe because the file now exists.
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        Ok(JsonlSink {
            name: format!("jsonl:{}", canonical.display()),
            path: path.to_path_buf(),
            file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for JsonlSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn write(&mut self, records: &[Record]) -> Result<()> {
        let mut buffer = Vec::with_capacity(records.len() * 256);
        for record in records {
            serde_json::to_writer(&mut buffer, &exported(record))
                .map_err(|e| Error::Config(format!("serialising audit record: {e}")))?;
            buffer.push(b'\n');
        }
        self.file.write_all(&buffer)?;
        // fsync before returning: the caller advances its cursor on the
        // strength of this Ok, so a lie here loses records permanently.
        self.file.sync_all()?;
        Ok(())
    }
}

/// The exported shape of one ledger event.
///
/// `payload` is included as a UTF-8 string, not base64: it is already known to
/// be valid JSON — the FSM rejects anything else — so keeping it readable makes
/// the stream greppable, which is most of what an audit log is for.
fn exported(record: &Record) -> serde_json::Value {
    serde_json::json!({
        "seq": record.seq,
        "session_id": record.session_id,
        "mono_ns": record.mono_ns,
        "wall_ms": record.wall_ms,
        "from_state": record.from_state.as_str(),
        "event": record.event.as_str(),
        "origin": record.origin.as_str(),
        "status": record.status.as_str(),
        "reason": record.reason.map(|r| r.as_str()),
        "to_state": record.to_state.as_str(),
        "payload": String::from_utf8_lossy(&record.payload),
        "prev_hash": hex(&record.prev_hash),
        "hash": hex(&record.hash),
    })
}

/// One export pass, in three steps that must stay in this order.
///
/// Read from the cursor, write to the sink, then advance the cursor. Doing the
/// advance first is the one arrangement that can lose data.
///
/// Returns how many records were exported.
pub fn export_once(ledger: &Ledger, sink: &mut dyn AuditSink, batch: usize) -> Result<usize> {
    let cursor = ledger.export_cursor(sink.name())?;
    let records = ledger.events_after(cursor, batch)?;
    if records.is_empty() {
        return Ok(0);
    }

    sink.write(&records)?;

    let head = records.last().expect("non-empty").seq;
    ledger.set_export_cursor(sink.name(), head)?;
    Ok(records.len())
}

/// Drain everything currently in the ledger, in batches.
pub fn export_all(ledger: &Ledger, sink: &mut dyn AuditSink, batch: usize) -> Result<usize> {
    let mut total = 0;
    loop {
        let n = export_once(ledger, sink, batch)?;
        total += n;
        if n < batch {
            return Ok(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;
    use crate::fsm::engine::Limits;
    use crate::fsm::state::{Event, Origin};
    use crate::runtime::Runtime;
    use crate::sandbox::ToolRegistry;

    /// Collects in memory, and can be told to fail — the failure path is the
    /// one that decides whether this is at-least-once or at-most-once.
    struct Collector {
        name: String,
        records: Vec<Record>,
        fail_next: bool,
    }

    impl Collector {
        fn new() -> Collector {
            Collector {
                name: "test".into(),
                records: Vec::new(),
                fail_next: false,
            }
        }
    }

    impl AuditSink for Collector {
        fn name(&self) -> &str {
            &self.name
        }

        fn write(&mut self, records: &[Record]) -> Result<()> {
            if self.fail_next {
                self.fail_next = false;
                return Err(Error::Config("sink is down".into()));
            }
            self.records.extend_from_slice(records);
            Ok(())
        }
    }

    fn runtime_with(events: usize) -> Runtime {
        let mut rt = Runtime::new(
            Ledger::open_in_memory([0x61; 32]).unwrap(),
            Limits {
                max_steps: events as u32 + 10,
                max_consecutive_rejects: 1_000_000,
                ..Limits::default()
            },
            Clock::new(),
            ToolRegistry::empty().unwrap(),
        );
        rt.open_session("s").unwrap();
        for _ in 0..events {
            // Illegal from IDLE, so each submission is exactly one event and
            // the count is predictable.
            rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
                .unwrap();
        }
        rt
    }

    #[test]
    fn exports_everything_once() {
        let rt = runtime_with(10);
        let mut sink = Collector::new();
        assert_eq!(export_all(rt.ledger(), &mut sink, 4).unwrap(), 10);
        assert_eq!(sink.records.len(), 10);
        assert_eq!(
            sink.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
        // A second pass has nothing left to do.
        assert_eq!(export_all(rt.ledger(), &mut sink, 4).unwrap(), 0);
    }

    #[test]
    fn a_failed_write_does_not_advance_the_cursor() {
        // The property the whole design rests on: if the sink did not take the
        // batch, the cursor must not claim it did.
        let rt = runtime_with(5);
        let mut sink = Collector::new();
        sink.fail_next = true;

        assert!(export_once(rt.ledger(), &mut sink, 10).is_err());
        assert_eq!(rt.ledger().export_cursor("test").unwrap(), 0);

        assert_eq!(export_all(rt.ledger(), &mut sink, 10).unwrap(), 5);
        assert_eq!(sink.records.len(), 5);
    }

    #[test]
    fn a_new_sink_replays_the_whole_ledger() {
        // A sink added after the fact must not start blind at the head, or the
        // history it exists to record is the part it never sees.
        let rt = runtime_with(6);
        let mut first = Collector::new();
        export_all(rt.ledger(), &mut first, 100).unwrap();

        let mut second = Collector::new();
        second.name = "other".into();
        assert_eq!(export_all(rt.ledger(), &mut second, 100).unwrap(), 6);
    }

    #[test]
    fn the_cursor_never_rewinds() {
        let rt = runtime_with(4);
        rt.ledger().set_export_cursor("test", 4).unwrap();
        rt.ledger().set_export_cursor("test", 2).unwrap();
        assert_eq!(rt.ledger().export_cursor("test").unwrap(), 4);
    }

    #[test]
    fn jsonl_output_is_one_parseable_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let rt = runtime_with(3);

        let mut sink = JsonlSink::open(&path).unwrap();
        assert_eq!(export_all(rt.ledger(), &mut sink, 100).unwrap(), 3);
        drop(sink);

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["seq"], serde_json::json!(i + 1));
            assert_eq!(v["hash"].as_str().unwrap().len(), 64);
        }
    }

    #[test]
    fn two_spellings_of_one_path_share_a_cursor() {
        // Found the hard way: the daemon opens the path from its config
        // (`./.vanguard/audit.jsonl`) and an operator types it without the
        // leading `./`. Keyed on the spelling, the second sink replays
        // everything into a file that already has it.
        let dir = tempfile::tempdir().unwrap();
        let rt = runtime_with(4);

        let direct = dir.path().join("audit.jsonl");
        let indirect = dir.path().join(".").join("audit.jsonl");

        let mut a = JsonlSink::open(&direct).unwrap();
        assert_eq!(export_all(rt.ledger(), &mut a, 100).unwrap(), 4);
        drop(a);

        let mut b = JsonlSink::open(&indirect).unwrap();
        assert_eq!(
            export_all(rt.ledger(), &mut b, 100).unwrap(),
            0,
            "the same file must not be exported twice"
        );
        drop(b);

        assert_eq!(std::fs::read_to_string(&direct).unwrap().lines().count(), 4);
    }

    #[test]
    fn appending_to_an_existing_file_does_not_truncate_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let rt = runtime_with(2);

        let mut sink = JsonlSink::open(&path).unwrap();
        export_all(rt.ledger(), &mut sink, 100).unwrap();
        drop(sink);

        // A restart reopens the same file; the cursor means it exports nothing
        // new, and the earlier lines survive.
        let mut sink = JsonlSink::open(&path).unwrap();
        assert_eq!(export_all(rt.ledger(), &mut sink, 100).unwrap(), 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }
}
