//! Phase 0 exit tests: the ledger survives restart and detects tampering.

use std::path::{Path, PathBuf};

use vanguard::clock::Clock;
use vanguard::fsm::engine::Limits;
use vanguard::fsm::state::{Event, Origin, State};
use vanguard::ledger::Ledger;
use vanguard::runtime::Runtime;

const KEY: [u8; 32] = [0x5a; 32];

fn ledger_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("vanguard.sqlite")
}

/// Drive a session through a full accept/reject/tool-result cycle.
fn write_events(path: &Path, session: &str) -> u64 {
    let ledger = Ledger::open(path, KEY).unwrap();
    let mut rt = Runtime::new(ledger, Limits::default(), Clock::new());
    rt.open_session(session).unwrap();
    rt.submit(session, Event::Start, Origin::Proposer, b"{}")
        .unwrap();
    rt.submit(
        session,
        Event::ExecuteTool,
        Origin::Proposer,
        br#"{"tool_name":"fetch_http"}"#,
    )
    .unwrap();
    // Illegal from TOOL_EXECUTION: recorded, does not move state.
    rt.submit(session, Event::Finish, Origin::Proposer, b"{}")
        .unwrap();
    rt.submit(
        session,
        Event::ToolResult,
        Origin::Runtime,
        br#"{"ok":true}"#,
    )
    .unwrap();
    rt.ledger().head().0
}

#[test]
fn ledger_chain_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = ledger_path(&dir);

    let head_before = write_events(&path, "s1");
    assert_eq!(head_before, 4);

    // Reopen from a cold process-equivalent: new connection, no cached head.
    let reopened = Ledger::open(&path, KEY).unwrap();
    let v = reopened.verify().unwrap();
    assert_eq!(v.events, 4);
    assert_eq!(v.head_seq, head_before);
    assert_eq!(reopened.head().1, v.head_hash);

    // And the chain continues correctly across the restart boundary.
    let mut rt = Runtime::new(reopened, Limits::default(), Clock::new());
    rt.submit("s1", Event::Finish, Origin::Proposer, b"{}")
        .unwrap();
    assert_eq!(rt.session("s1").unwrap().state, State::Done);
    assert_eq!(rt.ledger().verify().unwrap().events, 5);
}

#[test]
fn tampered_payload_breaks_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = ledger_path(&dir);
    write_events(&path, "s1");

    // Rewrite one payload behind the ledger's back, exactly as an attacker with
    // filesystem access would.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let changed = conn
            .execute(
                "UPDATE events SET payload = ?1 WHERE seq = 2",
                rusqlite::params![br#"{"tool_name":"rm_rf"}"#.to_vec()],
            )
            .unwrap();
        assert_eq!(changed, 1);
    }

    let err = Ledger::open(&path, KEY).unwrap().verify().unwrap_err();
    match err {
        vanguard::Error::ChainBroken { seq, .. } => assert_eq!(seq, 2, "must name the first break"),
        other => panic!("expected ChainBroken, got {other:?}"),
    }
}

#[test]
fn deleting_an_event_breaks_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = ledger_path(&dir);
    write_events(&path, "s1");

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM events WHERE seq = 3", [])
            .unwrap();
    }

    // Gaplessness is what catches this: without the seq check, seq 4's
    // prev_hash still matches seq 2's hash only if the deletion were at the
    // tail, so both checks earn their place.
    let err = Ledger::open(&path, KEY).unwrap().verify().unwrap_err();
    assert!(
        matches!(err, vanguard::Error::ChainBroken { seq: 4, .. }),
        "{err:?}"
    );
}

#[test]
fn wrong_key_fails_the_whole_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = ledger_path(&dir);
    write_events(&path, "s1");

    let err = Ledger::open(&path, [0x11; 32])
        .unwrap()
        .verify()
        .unwrap_err();
    assert!(
        matches!(err, vanguard::Error::ChainBroken { seq: 1, .. }),
        "{err:?}"
    );
}

#[test]
fn sessions_share_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = ledger_path(&dir);
    write_events(&path, "s1");
    write_events(&path, "s2");

    let ledger = Ledger::open(&path, KEY).unwrap();
    assert_eq!(ledger.verify().unwrap().events, 8);
    // Per-session views are filtered, but the chain is global — dropping a
    // whole session would still leave a seq gap.
    assert_eq!(ledger.events(Some("s2")).unwrap().len(), 4);
    assert_eq!(ledger.session_ids().unwrap(), vec!["s1", "s2"]);
}
