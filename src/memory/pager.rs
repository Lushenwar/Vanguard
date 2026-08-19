//! Bounded context assembly: turn an unbounded event log into a window that
//! fits a fixed token budget.
//!
//! Two decisions shape everything here.
//!
//! **Nothing is paged to a second store.** The ledger already is the durable
//! record, on disk, addressable by `seq`. "Evicting" a cold turn means leaving
//! it out of the window, not moving bytes somewhere else. A separate spill file
//! would be a second copy of data we already have, with its own consistency
//! problem.
//!
//! **No model summarises anything.** The replacement for evicted turns is a
//! *computed digest* — counts, seq ranges, which tools ran and whether they
//! failed. It is deterministic, it replays identically, and it cannot
//! hallucinate a constraint that was never there. An LLM summariser in this
//! path is exactly the "lossy compaction cascade" in the risk taxonomy: it
//! injects invented text into the prompt that produces the next proposal.

use std::collections::BTreeMap;
use std::fmt;

use crate::fsm::state::{Event, Origin, RejectReason, State};
use crate::ledger::event::{Record, Status};

/// Below this there is not enough room for the pinned header, so a budget this
/// small is a configuration error rather than something to silently truncate.
pub const MIN_TOKENS: usize = 64;

/// Bytes per token for the built-in estimator.
///
/// Deliberately pessimistic. Real tokenizers average nearer 4 bytes/token on
/// prose, but ledger payloads are JSON — braces, quotes and colons tokenize
/// close to one-per-character. Over-counting means the window comes in *under*
/// the real limit; under-counting would break the bound this module exists to
/// guarantee, and the failure would surface as a truncated prompt at the model
/// rather than as an error here.
const BYTES_PER_TOKEN: usize = 3;

/// Upper-bound token count for `text`.
pub fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(BYTES_PER_TOKEN)
}

/// Facts that are never evicted, whatever the budget.
///
/// This is the defense against working-memory rot. The task and the live
/// budget state are what a proposal is judged against; a window that drops the
/// original task to make room for recent chatter produces a model confidently
/// working on the wrong problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub session_id: String,
    pub state: State,
    pub steps: u32,
    pub max_steps: u32,
    /// The `START` payload. Truncated only if it alone would not fit.
    pub task: String,
    pub task_truncated_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolTally {
    pub calls: u64,
    pub rejected: u64,
}

/// What the evicted prefix contained, as counts rather than prose.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Digest {
    pub from_seq: u64,
    pub to_seq: u64,
    pub events: u64,
    pub accepted: u64,
    pub rejected: u64,
    /// Tool name to call tally. `BTreeMap`, so the rendered digest is
    /// byte-identical across processes — a `HashMap` would reorder it per run
    /// and make the prompt, and therefore the model's output, nondeterministic.
    pub tools: BTreeMap<String, ToolTally>,
    pub rejections: BTreeMap<String, u64>,
}

impl Digest {
    fn add(&mut self, rec: &Record) {
        if self.events == 0 {
            self.from_seq = rec.seq;
        }
        self.to_seq = rec.seq;
        self.events += 1;

        match rec.status {
            Status::Accepted => self.accepted += 1,
            Status::Rejected => self.rejected += 1,
        }
        if let Some(reason) = rec.reason {
            *self
                .rejections
                .entry(reason.as_str().to_string())
                .or_default() += 1;
        }
        if rec.event == Event::ExecuteTool {
            if let Some(name) = crate::fsm::engine::tool_name(&rec.payload) {
                let tally = self.tools.entry(name).or_default();
                match rec.status {
                    Status::Accepted => tally.calls += 1,
                    Status::Rejected => tally.rejected += 1,
                }
            }
        }
    }

    /// Remove the newest event from the digest, because it is moving into the
    /// live tail. The inverse of `add`, so the window can be grown one entry at
    /// a time without recomputing the digest over the whole prefix each step.
    fn remove_newest(&self, rec: &Record, new_to_seq: u64) -> Digest {
        let mut d = self.clone();
        d.events = d.events.saturating_sub(1);
        d.to_seq = new_to_seq;

        match rec.status {
            Status::Accepted => d.accepted = d.accepted.saturating_sub(1),
            Status::Rejected => d.rejected = d.rejected.saturating_sub(1),
        }
        if let Some(reason) = rec.reason {
            decrement(&mut d.rejections, reason.as_str());
        }
        if rec.event == Event::ExecuteTool {
            if let Some(name) = crate::fsm::engine::tool_name(&rec.payload) {
                if let Some(tally) = d.tools.get_mut(&name) {
                    match rec.status {
                        Status::Accepted => tally.calls = tally.calls.saturating_sub(1),
                        Status::Rejected => tally.rejected = tally.rejected.saturating_sub(1),
                    }
                    if tally.calls == 0 && tally.rejected == 0 {
                        d.tools.remove(&name);
                    }
                }
            }
        }
        d
    }

    pub fn is_empty(&self) -> bool {
        self.events == 0
    }
}

fn decrement(map: &mut BTreeMap<String, u64>, key: &str) {
    if let Some(count) = map.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            map.remove(key);
        }
    }
}

/// One live event in the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub event: Event,
    pub origin: Origin,
    pub status: Status,
    pub reason: Option<RejectReason>,
    pub to_state: State,
    pub payload: String,
    pub dropped_bytes: usize,
}

/// A context window that fits its budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextWindow {
    pub pinned: Pinned,
    /// `None` when nothing was evicted.
    pub digest: Option<Digest>,
    /// Live events, oldest first.
    pub tail: Vec<Entry>,
    /// Upper-bound token count. `estimate_tokens(&render())` is never larger,
    /// because the per-section estimates each round up independently.
    pub tokens: usize,
    pub max_tokens: usize,
}

impl ContextWindow {
    pub fn render(&self) -> String {
        let mut out = render_pinned(&self.pinned);
        if let Some(digest) = &self.digest {
            out.push_str(&render_digest(digest));
        }
        for entry in &self.tail {
            out.push_str(&render_entry(entry));
        }
        out
    }

    /// Events dropped from the tail, which is what the digest covers.
    pub fn evicted(&self) -> u64 {
        self.digest.as_ref().map_or(0, |d| d.events)
    }

    pub fn fits(&self) -> bool {
        self.tokens <= self.max_tokens
    }
}

impl fmt::Display for ContextWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Build the largest window that fits `max_tokens`.
///
/// `events` must be in ledger order, oldest first. Returns `None` if
/// `max_tokens` is below [`MIN_TOKENS`].
pub fn build(
    session_id: &str,
    state: State,
    steps: u32,
    max_steps: u32,
    events: &[Record],
    max_tokens: usize,
) -> Option<ContextWindow> {
    if max_tokens < MIN_TOKENS {
        return None;
    }

    let pinned = build_pinned(session_id, state, steps, max_steps, events, max_tokens);
    let pinned_tokens = estimate_tokens(&render_pinned(&pinned));

    // Start with everything evicted, then pull events back into the tail from
    // the newest end while there is room. Growing the tail shrinks the digest,
    // so the two are traded against each other one event at a time rather than
    // recomputed from scratch.
    let mut digest = Digest::default();
    for rec in events {
        digest.add(rec);
    }

    let payload_cap = payload_token_cap(max_tokens);
    let mut tail: Vec<Entry> = Vec::new();
    let mut tail_tokens = 0usize;
    let mut taken = 0usize;

    for (i, rec) in events.iter().enumerate().rev() {
        let entry = build_entry(rec, payload_cap);
        let entry_tokens = estimate_tokens(&render_entry(&entry));

        // `to_seq` of the shrunken digest is the seq of whatever now sits just
        // before the tail, or 0 when the tail has swallowed everything.
        let new_to_seq = if i == 0 { 0 } else { events[i - 1].seq };
        let trial_digest = digest.remove_newest(rec, new_to_seq);
        let digest_tokens = if trial_digest.is_empty() {
            0
        } else {
            estimate_tokens(&render_digest(&trial_digest))
        };

        if pinned_tokens + digest_tokens + tail_tokens + entry_tokens > max_tokens {
            break;
        }

        digest = trial_digest;
        tail_tokens += entry_tokens;
        tail.push(entry);
        taken += 1;
    }

    let _ = taken;
    tail.reverse();

    let digest_tokens = if digest.is_empty() {
        0
    } else {
        estimate_tokens(&render_digest(&digest))
    };

    Some(ContextWindow {
        pinned,
        digest: (!digest.is_empty()).then_some(digest),
        tail,
        tokens: pinned_tokens + digest_tokens + tail_tokens,
        max_tokens,
    })
}

/// Per-entry payload ceiling, so one oversized payload cannot consume the whole
/// window and evict every other turn. A quarter of the budget still lets a
/// large tool result through while leaving room for its neighbours.
fn payload_token_cap(max_tokens: usize) -> usize {
    (max_tokens / 4).max(8)
}

fn build_pinned(
    session_id: &str,
    state: State,
    steps: u32,
    max_steps: u32,
    events: &[Record],
    max_tokens: usize,
) -> Pinned {
    let task_raw = events
        .iter()
        .find(|r| r.event == Event::Start && r.status == Status::Accepted)
        .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
        .unwrap_or_default();

    let (task, task_truncated_bytes) = truncate_to_tokens(&task_raw, max_tokens / 4);

    Pinned {
        session_id: session_id.to_string(),
        state,
        steps,
        max_steps,
        task,
        task_truncated_bytes,
    }
}

fn build_entry(rec: &Record, payload_token_cap: usize) -> Entry {
    let raw = String::from_utf8_lossy(&rec.payload);
    let (payload, dropped_bytes) = truncate_to_tokens(&raw, payload_token_cap);
    Entry {
        seq: rec.seq,
        event: rec.event,
        origin: rec.origin,
        status: rec.status,
        reason: rec.reason,
        to_state: rec.to_state,
        payload,
        dropped_bytes,
    }
}

/// Truncate on a char boundary, returning the bytes dropped.
///
/// Cutting mid-codepoint would produce invalid UTF-8 and, worse, a payload that
/// differs from the ledger's in a way no reader could detect.
fn truncate_to_tokens(text: &str, max_tokens: usize) -> (String, usize) {
    let max_bytes = max_tokens * BYTES_PER_TOKEN;
    if text.len() <= max_bytes {
        return (text.to_string(), 0);
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    (text[..cut].to_string(), text.len() - cut)
}

fn render_pinned(p: &Pinned) -> String {
    let mut out = format!(
        "SESSION {}\nSTATE {} steps {}/{}\nTASK {}",
        p.session_id, p.state, p.steps, p.max_steps, p.task
    );
    if p.task_truncated_bytes > 0 {
        out.push_str(&format!(" …(+{} bytes)", p.task_truncated_bytes));
    }
    out.push('\n');
    out
}

fn render_digest(d: &Digest) -> String {
    let mut out = format!(
        "EVICTED seq {}-{}: {} events, {} accepted, {} rejected\n",
        d.from_seq, d.to_seq, d.events, d.accepted, d.rejected
    );
    if !d.tools.is_empty() {
        out.push_str("  tools:");
        for (name, tally) in &d.tools {
            out.push_str(&format!(
                " {}={}ok/{}rej",
                name, tally.calls, tally.rejected
            ));
        }
        out.push('\n');
    }
    if !d.rejections.is_empty() {
        out.push_str("  rejections:");
        for (reason, count) in &d.rejections {
            out.push_str(&format!(" {reason}={count}"));
        }
        out.push('\n');
    }
    out
}

fn render_entry(e: &Entry) -> String {
    let reason = e.reason.map(|r| r.as_str()).unwrap_or("-");
    let mut out = format!(
        "#{} {} {} {} {} -> {} {}",
        e.seq,
        e.event.as_str(),
        e.origin.as_str(),
        e.status.as_str(),
        reason,
        e.to_state.as_str(),
        e.payload
    );
    if e.dropped_bytes > 0 {
        out.push_str(&format!(" …(+{} bytes)", e.dropped_bytes));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::event::{Draft, Record, GENESIS};

    fn record(seq: u64, event: Event, status: Status, payload: &[u8]) -> Record {
        Record::from_draft(
            Draft {
                session_id: "s".into(),
                mono_ns: seq,
                wall_ms: 0,
                from_state: State::Planning,
                event,
                origin: event.origin(),
                payload: payload.to_vec(),
                status,
                reason: (status == Status::Rejected).then_some(RejectReason::IllegalEdge),
                to_state: State::Planning,
            },
            seq,
            GENESIS,
            b"k",
        )
    }

    fn log(n: u64) -> Vec<Record> {
        let mut events = vec![record(
            1,
            Event::Start,
            Status::Accepted,
            br#"{"task":"do a thing"}"#,
        )];
        for i in 0..n {
            events.push(record(
                i + 2,
                Event::ExecuteTool,
                Status::Accepted,
                br#"{"tool_name":"echo","arguments":{"n":1}}"#,
            ));
        }
        events
    }

    fn window(events: &[Record], max: usize) -> ContextWindow {
        build("s", State::Planning, 3, 50, events, max).unwrap()
    }

    #[test]
    fn a_short_log_is_kept_whole() {
        let events = log(3);
        let w = window(&events, 8192);
        assert_eq!(w.tail.len(), events.len());
        assert!(w.digest.is_none(), "nothing should be evicted");
        assert!(w.fits());
    }

    #[test]
    fn a_long_log_is_bounded_and_digested() {
        let events = log(500);
        let w = window(&events, 1024);
        assert!(w.fits(), "{} > {}", w.tokens, w.max_tokens);
        assert!(w.tail.len() < events.len());
        assert_eq!(
            w.evicted() as usize + w.tail.len(),
            events.len(),
            "every event is either live or counted in the digest"
        );
    }

    #[test]
    fn the_rendered_string_never_exceeds_the_estimate() {
        // The bound is only meaningful if the number the caller sees is an
        // upper bound on the text actually produced.
        let events = log(500);
        for max in [64, 128, 512, 1024, 8192] {
            let w = window(&events, max);
            assert!(estimate_tokens(&w.render()) <= w.tokens);
            assert!(w.tokens <= max, "{} > {max}", w.tokens);
        }
    }

    #[test]
    fn the_task_survives_any_budget() {
        // Working-memory rot: the original goal must not be the thing that
        // falls out to make room for recent noise.
        let events = log(500);
        let w = window(&events, MIN_TOKENS);
        assert!(w.render().contains("do a thing"));
        assert!(w.fits());
    }

    #[test]
    fn the_newest_events_are_the_ones_kept() {
        let events = log(200);
        let w = window(&events, 512);
        let last = events.last().unwrap().seq;
        assert_eq!(w.tail.last().unwrap().seq, last);
        // And the tail is contiguous and oldest-first.
        for pair in w.tail.windows(2) {
            assert_eq!(pair[1].seq, pair[0].seq + 1);
        }
    }

    #[test]
    fn digest_counts_match_what_was_evicted() {
        let mut events = log(100);
        events.push(record(200, Event::Finish, Status::Rejected, b"{}"));
        let w = window(&events, 256);

        let digest = w.digest.as_ref().unwrap();
        let live: std::collections::BTreeSet<u64> = w.tail.iter().map(|e| e.seq).collect();
        let evicted: Vec<&Record> = events.iter().filter(|r| !live.contains(&r.seq)).collect();

        assert_eq!(digest.events, evicted.len() as u64);
        assert_eq!(
            digest.accepted + digest.rejected,
            digest.events,
            "every evicted event is accounted for as one or the other"
        );
        let echo = digest.tools.get("echo").expect("echo calls were evicted");
        assert_eq!(
            echo.calls,
            evicted
                .iter()
                .filter(|r| r.event == Event::ExecuteTool && r.status == Status::Accepted)
                .count() as u64
        );
    }

    #[test]
    fn one_huge_payload_cannot_evict_everything() {
        let big = format!(r#"{{"blob":"{}"}}"#, "x".repeat(100_000));
        let mut events = log(5);
        events.push(record(
            100,
            Event::ToolResult,
            Status::Accepted,
            big.as_bytes(),
        ));
        let w = window(&events, 1024);
        assert!(w.fits());
        assert!(
            w.tail.len() > 1,
            "a single oversized payload must be truncated, not allowed to \
             consume the whole window"
        );
        assert!(w.tail.last().unwrap().dropped_bytes > 0);
    }

    #[test]
    fn building_is_deterministic() {
        let events = log(300);
        assert_eq!(window(&events, 700), window(&events, 700));
        assert_eq!(window(&events, 700).render(), window(&events, 700).render());
    }

    #[test]
    fn an_unusable_budget_is_refused_rather_than_silently_shrunk() {
        assert!(build("s", State::Idle, 0, 50, &log(1), MIN_TOKENS - 1).is_none());
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let text = "héllo wörld, ".repeat(20);
        let (cut, dropped) = truncate_to_tokens(&text, 4);
        assert!(text.starts_with(&cut));
        assert_eq!(cut.len() + dropped, text.len());
    }

    #[test]
    fn an_empty_log_still_produces_a_window() {
        let w = window(&[], 1024);
        assert!(w.tail.is_empty());
        assert!(w.digest.is_none());
        assert!(w.fits());
    }
}
