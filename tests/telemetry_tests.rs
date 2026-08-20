//! Phase 6 exit tests: every operation emits its span under load, and the
//! audit stream cannot lose an event.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::echo_registry;
use tracing::subscriber::with_default;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use vanguard::clock::Clock;
use vanguard::fsm::engine::Limits;
use vanguard::fsm::state::{Event, Origin};
use vanguard::ledger::Ledger;
use vanguard::runtime::Runtime;
use vanguard::sandbox::ToolRegistry;
use vanguard::telemetry::audit::{self, AuditSink, JsonlSink};

/// Counts spans by name as they are created.
///
/// This is the only honest in-process measure of "dropped spans": whether a
/// *remote* collector received them is a property of that collector's queue,
/// but whether the instrumentation emitted one per operation at rate is
/// something this crate is responsible for.
#[derive(Clone, Default)]
struct SpanCounter {
    submits: Arc<AtomicU64>,
    tools: Arc<AtomicU64>,
}

impl<S> Layer<S> for SpanCounter
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: Context<'_, S>,
    ) {
        match attrs.metadata().name() {
            "vanguard.submit" => {
                self.submits.fetch_add(1, Ordering::Relaxed);
            }
            "vanguard.tool" => {
                self.tools.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

fn runtime(tools: ToolRegistry, max_steps: u32) -> Runtime {
    let mut rt = Runtime::new(
        Ledger::open_in_memory([0x66; 32]).unwrap(),
        Limits {
            max_steps,
            max_consecutive_rejects: 1_000_000,
            ..Limits::default()
        },
        Clock::new(),
        tools,
    );
    rt.open_session("s").unwrap();
    rt
}

/// Phase 6 exit criterion: zero dropped span events under 1,000 req/sec.
#[test]
fn no_dropped_spans_under_load() {
    const REQUESTS: u64 = 1_000;

    let counter = SpanCounter::default();
    // Scoped rather than global: other tests in this binary also emit spans,
    // and a global subscriber would let their traffic inflate this count.
    let subscriber = tracing_subscriber::registry().with(counter.clone());

    let elapsed = with_default(subscriber, || {
        let mut rt = runtime(ToolRegistry::empty().unwrap(), 10_000);
        let started = Instant::now();
        for _ in 0..REQUESTS {
            // Illegal from IDLE, so each submission is exactly one event and
            // one span, with no tool dispatch inflating either count.
            rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
                .unwrap();
        }
        let elapsed = started.elapsed();
        assert_eq!(
            rt.ledger().events(Some("s")).unwrap().len() as u64,
            REQUESTS
        );
        elapsed
    });

    let observed = counter.submits.load(Ordering::Relaxed);
    assert_eq!(
        observed, REQUESTS,
        "{} spans for {REQUESTS} operations",
        observed
    );

    let rate = REQUESTS as f64 / elapsed.as_secs_f64();
    assert!(
        rate >= 1_000.0,
        "sustained only {rate:.0} req/sec over {elapsed:?}; criterion is 1000/sec"
    );
}

#[test]
fn tool_calls_get_their_own_span() {
    let counter = SpanCounter::default();
    let subscriber = tracing_subscriber::registry().with(counter.clone());

    with_default(subscriber, || {
        let mut rt = runtime(echo_registry(), 100);
        rt.submit("s", Event::Start, Origin::Proposer, b"{}")
            .unwrap();
        for _ in 0..5 {
            rt.submit(
                "s",
                Event::ExecuteTool,
                Origin::Proposer,
                br#"{"tool_name":"echo"}"#,
            )
            .unwrap();
        }
    });

    assert_eq!(counter.tools.load(Ordering::Relaxed), 5);
    // START, then 5 tool calls, then 5 runtime TOOL_RESULTs, all of which are
    // submissions in their own right.
    assert_eq!(counter.submits.load(Ordering::Relaxed), 11);
}

/// Every ledger event reaches the sink exactly once, across a restart.
#[test]
fn audit_export_is_lossless_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut rt = runtime(echo_registry(), 10_000);

    rt.submit("s", Event::Start, Origin::Proposer, br#"{"task":"audit"}"#)
        .unwrap();
    for _ in 0..40 {
        rt.submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        )
        .unwrap();
    }
    let total = rt.ledger().events(None).unwrap().len();

    // First pass drains part of the log, then the process "dies".
    {
        let mut sink = JsonlSink::open(&path).unwrap();
        assert_eq!(audit::export_once(rt.ledger(), &mut sink, 10).unwrap(), 10);
    }

    // More events arrive while nothing is exporting.
    for _ in 0..10 {
        rt.submit(
            "s",
            Event::ExecuteTool,
            Origin::Proposer,
            br#"{"tool_name":"echo"}"#,
        )
        .unwrap();
    }
    let total = total + 20;
    assert_eq!(rt.ledger().events(None).unwrap().len(), total);

    // Restart: same file, same cursor, no gap and no restart-from-zero.
    {
        let mut sink = JsonlSink::open(&path).unwrap();
        audit::export_all(rt.ledger(), &mut sink, 7).unwrap();
    }

    let seqs = exported_seqs(&path);
    assert_eq!(
        seqs.len(),
        total,
        "exported {} of {total} events",
        seqs.len()
    );
    assert_eq!(
        seqs,
        (1..=total as u64).collect::<Vec<_>>(),
        "the exported stream must be gapless and in order"
    );
}

#[test]
fn the_exported_stream_matches_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut rt = runtime(echo_registry(), 100);

    rt.submit("s", Event::Start, Origin::Proposer, br#"{"task":"t"}"#)
        .unwrap();
    rt.submit(
        "s",
        Event::ExecuteTool,
        Origin::Proposer,
        br#"{"tool_name":"echo"}"#,
    )
    .unwrap();
    rt.submit("s", Event::ToolResult, Origin::Proposer, b"{}")
        .unwrap(); // forged, rejected

    let mut sink = JsonlSink::open(&path).unwrap();
    audit::export_all(rt.ledger(), &mut sink, 100).unwrap();
    drop(sink);

    let exported: BTreeMap<u64, serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .map(|v| (v["seq"].as_u64().unwrap(), v))
        .collect();

    for record in rt.ledger().events(None).unwrap() {
        let row = exported
            .get(&record.seq)
            .unwrap_or_else(|| panic!("seq {} missing from the audit stream", record.seq));
        assert_eq!(row["event"], record.event.as_str());
        assert_eq!(row["origin"], record.origin.as_str());
        assert_eq!(row["status"], record.status.as_str());
        assert_eq!(row["to_state"], record.to_state.as_str());
        // The hash travels with the record, so a downstream consumer can
        // re-verify the chain without access to this machine's ledger file.
        assert_eq!(
            row["hash"].as_str().unwrap(),
            vanguard::ledger::event::hex(&record.hash)
        );
    }

    // The rejected proposal is in the stream too: a rejection is evidence, and
    // an audit log that only carried successes would be worse than none.
    assert!(exported
        .values()
        .any(|v| v["status"] == "REJECTED" && v["reason"] == "ForgedOrigin"));
}

#[test]
fn a_down_sink_backs_up_rather_than_skipping() {
    // If a failed write advanced the cursor, the events in that batch would be
    // gone for good. They have to still be there when the sink recovers.
    struct Flaky {
        name: String,
        seen: Vec<u64>,
        healthy: bool,
    }

    impl AuditSink for Flaky {
        fn name(&self) -> &str {
            &self.name
        }
        fn write(&mut self, records: &[vanguard::ledger::Record]) -> vanguard::Result<()> {
            if !self.healthy {
                return Err(vanguard::Error::Config("sink is down".into()));
            }
            self.seen.extend(records.iter().map(|r| r.seq));
            Ok(())
        }
    }

    let mut rt = runtime(ToolRegistry::empty().unwrap(), 10_000);
    for _ in 0..12 {
        rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
            .unwrap();
    }

    let mut sink = Flaky {
        name: "flaky".into(),
        seen: Vec::new(),
        healthy: false,
    };
    assert!(audit::export_once(rt.ledger(), &mut sink, 5).is_err());
    assert_eq!(rt.ledger().export_cursor("flaky").unwrap(), 0);

    sink.healthy = true;
    assert_eq!(audit::export_all(rt.ledger(), &mut sink, 5).unwrap(), 12);
    assert_eq!(sink.seen, (1..=12).collect::<Vec<_>>());
}

#[test]
fn export_keeps_up_with_a_thousand_events() {
    // The audit side of the same load the span test applies: a sink draining in
    // batches must still see every event, in order, with none skipped.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut rt = runtime(ToolRegistry::empty().unwrap(), 10_000);

    let started = Instant::now();
    for _ in 0..1_000 {
        rt.submit("s", Event::Finish, Origin::Proposer, b"{}")
            .unwrap();
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "did not sustain 1000 req/sec"
    );

    let mut sink = JsonlSink::open(&path).unwrap();
    assert_eq!(
        audit::export_all(rt.ledger(), &mut sink, 128).unwrap(),
        1_000
    );
    drop(sink);

    assert_eq!(exported_seqs(&path), (1..=1_000).collect::<Vec<_>>());
}

fn exported_seqs(path: &std::path::Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
        .collect()
}
