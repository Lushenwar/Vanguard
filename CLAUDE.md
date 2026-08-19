# CLAUDE.md — Vanguard (Deterministic Agent State Engine, Systems Core)

> **Name: `Vanguard`.** Named for standing at the absolute frontier of execution, shielding systems from unbounded AI drift.
> `Supervisor` was too generic, and `Sentry` implied passive monitoring rather than active control plane enforcement —
> the FSM runtime is the boundary, keeping agent execution deterministic, replayable, and bounded.
> Baked into `crate::config::APP_NAME`, systemd unit files, `/var/lib/vanguard`, and the binaries `vanguardd` / `vgctl`.

## WORKFLOW: BRANCH + PR ONLY

No direct commits to `main`. Every change goes: `git checkout -b <branch>` → commit → `gh pr create`.
A pre-commit hook (`.git/hooks/pre-commit`) enforces this locally by rejecting commits made directly on `main`.

## CURRENT STATUS

```text
╔══════════════════════════════════════════════════════════╗
║  VANGUARD BUILD PROGRESS                       3/8 DONE  ║
║  ███████████░░░░░░░░░░░░░░░░░  PHASES 0-2 SHIPPED        ║
║  Phase specs and exit tests live in this file, below.     ║
║  Phase 0: Runtime Core, Event Log & Signed Ledger    [x]  ║
║  Phase 1: Deterministic FSM Engine & Guardrails      [x]  ║
║  Phase 2: WASM Sandboxed Tool Execution Engine       [x]  ║
║  Phase 3: Context Paging & Memory Eviction Subsystem [ ]  ║
║  Phase 4: gRPC Control Plane & Local Socket API      [ ]  ║
║  Phase 5: Time-Travel Replay & Mock Execution Engine [~]  ║
║  Phase 6: OpenTelemetry Tracing & Audit Log Exporter [ ]  ║
║  Phase 7: eBPF Network Proxy & Tool Rate Limiter     [ ]  ║
╚══════════════════════════════════════════════════════════╝

```

Phase: three of eight phases completed. `[~]` means partially built.

**Phases 0, 1 and 2 are implemented and tested.** The daemon boots, initialises a WAL-mode
SQLite ledger, verifies its HMAC chain, and refuses to serve on a break. The FSM evaluates
proposals against a fixed edge table with origin enforcement and step/rejection budgets,
appending every decision — accepted *and* rejected — to the chain before any state change is
visible. An accepted `EXECUTE_TOOL` runs inside a wasmtime sandbox with a fuel ceiling and no
host bindings whatsoever, and its result comes back as a runtime-origin `TOOL_RESULT`.

**Phase 5 is partially built.** `vgctl replay` folds a ledger back through the engine offline and
reports any divergence in state, status, or head hash. What is missing is the mock *tool* execution
half, which cannot exist before Phase 2 gives tools something to execute in.

**Phases 3, 4, 6, 7 are specified but not built.** Each has a named exit test in the
IMPLEMENTATION CONTRACT below that defines when it is done.

**Checks:** `cargo test --all-targets --all-features && cargo clippy --all-targets -- -D warnings && cargo fmt --check`

---

## WHAT THIS FILE IS

The authoritative specification for building **Vanguard**: a lightweight, high-performance runtime for autonomous AI agents. Vanguard replaces unconstrained LLM execution loops with a **Deterministic Finite State Machine (FSM)** and an **append-only event ledger**.

The product thesis in one line: **LLMs propose state transitions; the system executes them.** An LLM must never hold direct control flow authority over loops, tool invocations, or system state.

---

## THE CENTRAL ARCHITECTURE: TWO PLANES, ONE ENFORCER

The engine decouples **Reasoning** (probabilistic) from **Execution** (deterministic). The LLM is isolated behind a strict FSM interface.

```text
   ┌───────────────────────────┐     ┌───────────────────────────┐
   │     PROPOSER PLANE        │     │     STATE MACHINE (FSM)   │
   │                           │     │                           │
   │   LLM / Model Endpoint    │     │   Strict State Nodes      │
   │   Generates proposed      │     │   Allowed Edge Transitions│
   │   events & tool args      │     │   Valid Invariants        │
   └─────────────┬─────────────┘     └─────────────┬─────────────┘
                 │                                 │
                 └───────────────┬─────────────────┘
                                 ▼
                     ┌──────────────────────┐
                     │  VANGUARD RUNTIME    │
                     │  Validates proposal, │
                     │  appends event log,  │
                     │  executes tool target│
                     └──────────────────────┘

```

### Composition Rules

* **State Authority:** The FSM runtime owns the system state $S_t$. The LLM is a stateless function $P(S_t) \rightarrow E_{\text{proposed}}$.
* **Transition Validation:** A transition from $S_i \rightarrow S_j$ via proposed event $E$ is executed if and only if $E \in \text{AllowedTransitions}(S_i)$. Illegal transitions immediately halt the turn and emit a `StateViolation` event to the ledger.
* **Deterministic Event Sourcing:** State mutates *only* by committing a signed event to the append-only WAL log. The current state is purely a fold over historical events: $S_t = \text{fold}(S_0, [E_1, E_2, \dots, E_t])$.

---

## TECHNICAL REALITIES & CORRECTIONS

1. **LLM Loops cannot own process control flow.** Letting an LLM decide when a loop finishes via freeform text parser results in non-deterministic hangs or infinite tool calling. Execution must be driven by explicit state timeouts and step caps.
2. **Async drop safety in WASM runtimes.** Dropping a Tokio task mid-execution of a WASM tool call can leave WASM linear memory allocated in the host process pool. Tools execute inside an explicit `WasmInstanceGuard` that handles teardown on drop.
3. **Monotonic Event Timestamps.** Wall-clock system time (`SystemTime::now()`) can drift or shift under NTP sync, corrupting time-travel replay sequence order. All ledger entries capture both `Instant` offset (monotonic) and an atomic incrementing sequence ID ($u64$).

---

## THREAT MODEL

| # | Attack / Failure Mode | Defense | Holds? |
| --- | --- | --- | --- |
| 1 | LLM hallucinates an invalid state jump | FSM rejects transition; state remains $S_i$ | Yes |
| 2 | Infinite tool call recursion | Hard step budget ($N \le 50$) per session | Yes |
| 3 | WASM sandbox breakout / resource exhaustion | Explicit `wasmtime` fuel limits & cgroups | Yes |
| 4 | Memory context overflow during long loops | Context Paging Subsystem (evicts cold turns to disk) | Yes |
| 5 | Network exfiltration via tool call | eBPF egress filtering + domain allowlists | Mostly |

---

## NON-NEGOTIABLES

* **No direct unvalidated tool execution.** No tool executes unless wrapped in a typed WASM capability module or isolated subprocess wrapper.
* **Zero unhandled state mutations.** Every state change must be written to disk before side-effects trigger.
* **Deterministic Replayability.** Given an event log file and cached tool outputs, `vgctl replay <log>` must reproduce the exact sequence of FSM states.

---

## TECH STACK

* **Runtime Core:** Rust (`1.80+`), Tokio async runtime.
* **Storage Layer:** SQLite (`rusqlite` with WAL mode and `bundled` static linkage).
* **Tool Sandboxing:** `wasmtime` for WebAssembly execution.
* **IPC / API Interface:** gRPC (`tonic` / `prost`) over Unix Domain Sockets (`/var/run/vanguard.sock`).
* **Observability:** `tracing`, OpenTelemetry, eBPF (`aya-bpf` on Linux).

---

## FILE LAYOUT

```text
vanguard/                          [x] exists  [ ] planned
├── Cargo.toml                     [x]
├── config.dev.toml                [x] dev config; keeps a dev run out of /var
├── src/
│   ├── lib.rs                     [x] crate root
│   ├── main.rs                    [x] vanguardd entry point
│   ├── config.rs                  [x] TOML config + env overrides
│   ├── clock.rs                   [x] monotonic ordering vs advisory wall time
│   ├── error.rs                   [x] crate-wide error type
│   ├── runtime.rs                 [x] the enforcer: evaluate, commit, then act
│   ├── fsm/
│   │   ├── engine.rs              [x] pure proposal evaluator
│   │   ├── state.rs               [x] states, events, origins, reject reasons
│   │   └── transition.rs          [x] the legal edge set
│   ├── ledger/
│   │   ├── db.rs                  [x] SQLite WAL store, single writer
│   │   ├── event.rs               [x] record shape + HMAC chain
│   │   ├── key.rs                 [x] key load/create, permission checks
│   │   └── replay.rs              [x] offline fold back through the engine
│   ├── sandbox/
│   │   ├── mod.rs                 [x] tool registry = the authorization model
│   │   ├── wasm.rs                [x] wasmtime wrapper, fuel & memory ceilings
│   │   └── host_funcs.rs          [ ] deliberately absent; the whitelist is empty
│   ├── memory/                    [ ] Phase 3
│   │   ├── pager.rs               [ ] sliding context window manager
│   │   └── eviction.rs            [ ] LRU token & vector store paging
│   └── api/                       [ ] Phase 4
│       ├── grpc.rs                [ ] tonic service implementation
│       └── proto/                 [ ] protobuf definitions
├── tools/
│   └── echo.wat                   [x] reference tool; the ABI, executable
├── bin/
│   └── vgctl.rs                   [x] audit & administration CLI
└── tests/
    ├── common/mod.rs              [x] shared tool fixtures
    ├── fsm_tests.rs               [x] Phase 1 exit tests
    ├── ledger_tests.rs            [x] Phase 0 exit tests
    ├── sandbox_tests.rs           [x] Phase 2 exit tests
    └── replay_tests.rs            [x] replay fidelity tests

```

---

## FSM & EVENT LEDGER SPECIFICATION

The engine evaluates state changes through a deterministic state transition function:

$$T(S_t, E_{\text{proposed}}) \longrightarrow \begin{cases} (S_{t+1}, A_{\text{exec}}), & \text{if } E_{\text{proposed}} \in \text{ValidEdges}(S_t) \\ (S_t, A_{\text{reject}}), & \text{otherwise} \end{cases}$$

### Ledger Event Schema (JSON Serialization)

```json
{
  "sequence_id": 1042,
  "prev_hash": "a8f5f167f44f4964e6c998dee827110c",
  "timestamp_mono_ns": 8492019402194,
  "current_state": "PLANNING",
  "proposed_event": "EXECUTE_TOOL",
  "payload": {
    "tool_name": "fetch_http",
    "arguments_hash": "e3b0c44298fc1c149afbf4c8996fb924"
  },
  "status": "ACCEPTED",
  "signature": "30450221008f..."
}

```

---

## LOCAL API & gRPC SPECIFICATION

Communication between `vgctl` and `vanguardd` takes place over loopback gRPC (`unix:///var/run/vanguard.sock`).

* `rpc SubmitProposal (ProposalRequest) returns (ProposalResponse)` — Proposes an event from the LLM adapter. Returns immediate state acceptance or rejection.
* `rpc GetState (StateRequest) returns (StateResponse)` — Returns current FSM state, active step count, and context token utilization.
* `rpc StreamLedger (LedgerRequest) returns (stream LedgerEvent)` — Subscribes to live event mutations.
* `rpc TriggerReplay (ReplayRequest) returns (ReplaySummary)` — Pauses live execution and runs an offline replay verification.

---

## IMPLEMENTATION PHASES

### PHASE 0 — RUNTIME CORE & CRYPTOGRAPHICALLY SIGNED LEDGER

**Exit Criteria:** `vanguardd` boots, initializes an encrypted SQLite WAL ledger, and verifies HMAC chain integrity on restart using `vgctl verify`.

### PHASE 1 — DETERMINISTIC FSM ENGINE

**Exit Criteria:** Engine rejects invalid state transition proposals within $<1\text{ ms}$, logging an append-only audit event without mutating state.

### PHASE 2 — WASM TOOL SANDBOXING

**Exit Criteria:** WASM modules execute isolated tool payloads with enforced execution fuel limits. CPU spin-loops hit out-of-fuel panics and terminate cleanly within $50\text{ ms}$.

### PHASE 3 — CONTEXT PAGING & EVICTION

**Exit Criteria:** Agent context stays within a strict $8,192$ token bound across 1,000 conversation turns by paging cold turns to disk and maintaining active state summaries.

### PHASE 4 — gRPC CONTROL PLANE & CLI

**Exit Criteria:** `vgctl` manages daemon sessions over Unix domain sockets, displaying real-time FSM states and step performance metrics.

### PHASE 5 — TIME-TRAVEL REPLAY

**Exit Criteria:** `vgctl replay --log <path>` accurately reconstructs historical execution states offline using cached tool response outputs.

### PHASE 6 — OPENTELEMETRY & AUDIT EXPORTER

**Exit Criteria:** Full trace spans exported to local collector endpoints with zero dropped span events under 1,000 req/sec benchmark load.

### PHASE 7 — eBPF NETWORK PROXY

**Exit Criteria:** Egress traffic from WASM tools restricted strictly to explicit domain/IP allowlists at the socket level.

---

## RUNNING & TESTING

On this workstation every `cargo` invocation below needs
`+stable-x86_64-pc-windows-msvc` — see PLATFORM NOTE.

```bash
# One-time: give the dev state dir a tool to run. The registry is the
# authorization model, so a daemon with no tools directory refuses every
# EXECUTE_TOOL proposal -- which is correct, and looks exactly like a bug.
mkdir -p .vanguard/tools && cp tools/echo.wat .vanguard/tools/

# Terminal 1 — Run runtime daemon in debug mode
cargo run --bin vanguardd -- --config config.dev.toml
cargo run --bin vanguardd -- --config config.dev.toml --check   # verify and exit

# Terminal 2 — Drive the engine directly, no model in the loop
cargo run --bin vgctl -- --config config.dev.toml health
cargo run --bin vgctl -- --config config.dev.toml \
    propose --session-id demo --event START --payload '{"task":"echo-demo"}'
cargo run --bin vgctl -- --config config.dev.toml \
    propose --session-id demo --event EXECUTE_TOOL \
    --payload '{"tool_name":"echo","arguments":{"x":1}}'
cargo run --bin vgctl -- --config config.dev.toml ledger --session-id demo
cargo run --bin vgctl -- --config config.dev.toml replay
cargo run --bin vgctl -- --config config.dev.toml verify

# Execute full suite of unit and integration tests
cargo test --all-targets --all-features

```

One accepted `EXECUTE_TOOL` produces **two** ledger events: the authorization,
then the runtime-origin `TOOL_RESULT` carrying what the sandbox returned. The
session never rests in `TOOL_EXECUTION` — dispatch is synchronous, so there is
no window in which a proposal could arrive while a tool is in flight.

---

## FAILURE MODES & RISK TAXONOMY (WHAT COULD GO WRONG)

**1. Model & Proposer Plane Failures**

* **Prompt Injection & Payload Exploitation:** Direct or indirect prompt injection tricks the model into proposing valid transitions with malicious payloads (e.g., proposing `EXECUTE_TOOL` with destructive flags). The FSM permits the transition because the edge is valid, shifting security vulnerability from control flow to argument validation.
* **Malformed JSON Parsing Latency:** Unstructured or corrupt proposals hit fallback regex parsing, increasing transition evaluation latency from $<200\ \mu\text{s}$ up to $>1.5\text{ ms}$ and breaking real-time execution guarantees.
* **Proposal Lock-in Loops:** The model repeatedly generates identical rejected proposals in a stuck FSM state, consuming step budgets without advancing state.

**2. FSM Runtime & Ledger Corruption**

* **SQLite WAL Lock Contention:** High-concurrency state mutations across worker threads trigger `SQLITE_BUSY` errors, stalling event log commits and degrading turn throughput.
* **Non-Monotonic Timestamp Drift:** CPU clock adjustments or host container migrations skew monotonic timestamps, invalidating step sequencing during time-travel replay verification.
* **Partial Write Chain Breaks:** Crashes or power cuts during active WAL writes truncate the event ledger, breaking cryptographic HMAC chain continuity and preventing daemon startup.

**3. WASM Sandbox & Tool Execution Risks**

* **Async Drop Resource Leaks:** Task cancellations mid-execution leave linear memory or file descriptors allocated in the host process pool, causing progressive memory bloat.
* **Host Binding Panics:** Unhandled exceptions within `wasmtime` host bindings trigger unwinding panics that crash `vanguardd` rather than gracefully terminating the sandbox instance.
* **Fuel Limit Starvation:** High-computation WASM modules exhaust fuel limits prematurely, causing false-positive execution aborts on valid tasks.

**4. Context Paging & Memory Decay**

* **Working-Memory Rot:** Context summarization silently drops critical historical constraints during cold turn eviction, causing downstream turns to execute on invalid domain assumptions.
* **Lossy Compaction Cascades:** Truncated memory summaries inject ambiguous references into the active prompt, causing the model to generate hallucinated parameters during state transitions.

**5. OS, IPC & Networking Hazards**

* **eBPF Kernel Version Incompatibility:** Kernel environments lacking `CAP_BPF` or operating on Linux $<5.15$ fail to attach socket filters, falling back to permissive networking or failing network boundary guarantees.
* **Socket File Descriptor Exhaustion:** Rapid administrative socket reconnects starve available file descriptors at `/var/run/vanguard.sock`, blocking CLI tools from querying runtime status.
* **Stale PID Lockouts:** Abrupt daemon crashes leave behind stale lock files, preventing `vanguardd` from restarting until manual cleanup is performed.

---

# IMPLEMENTATION CONTRACT

Everything above is intent. Everything below is binding: exact states, edges, schema, hashing,
config keys, error codes, and dependencies. When the two disagree, this section wins, and the
disagreement is recorded under **SPEC CORRECTIONS**.

## SPEC CORRECTIONS

| # | Original text | Correction | Reason |
| --- | --- | --- | --- |
| 1 | Ledger schema shows `"signature": "30450221008f..."` (ECDSA DER) | HMAC-SHA256 chain hash only, no asymmetric signature | Phase 0 exit criteria already says HMAC. One local daemon signing its own log gains nothing from a keypair it also holds; asymmetric signing is only worth it when a *third party* must verify without the write key. Deferred to a future phase if external attestation is ever required. |
| 2 | `"prev_hash": "a8f5f167..."` shown as 32 hex chars (128-bit) | 32 **bytes** (64 hex chars), SHA-256 width | The example strings are MD5-width. HMAC-SHA256 output is 32 bytes. |
| 3 | Status block says `See ROADMAP.md` | No `ROADMAP.md` exists; this file is the roadmap | Removed the dangling reference rather than creating a second document to drift out of sync. |
| 4 | `payload.arguments_hash` | Payload is stored **verbatim** as the exact bytes the proposer submitted, and hashed as those bytes | Canonicalizing JSON before hashing invents a second serializer that replay must reproduce exactly. Storing submitted bytes makes byte-identical replay free. A hash *of* the arguments is derivable from the stored bytes whenever it is wanted. |
| 5 | "Every state change written to disk before side-effects trigger" | Unchanged, but made concrete: the ledger `INSERT` must return before the tool dispatcher is handed the call | Stated so it is testable rather than aspirational. |
| 6 | `SessionUnknown` listed as a rejection reason appended to the ledger | Returned as an API error (`Error::UnknownSession`), never as a `REJECTED` row | An event row is a child of a session row; there is no session to attach the rejection to, and inventing a placeholder session so the rejection has a home would let an unauthenticated caller create ledger rows by guessing ids. The variant is kept in `RejectReason` for the wire protocol. |
| 7 | `src/fsm/` "must not gain a dependency" | It uses `serde_json` to decide payload well-formedness | Payload validity has to be decided in the same place, in the same order, as every other rejection, or replay and the live engine can disagree about the same bytes. `serde_json` is already a Phase 0 dependency; the rule still holds against adding anything *new*. |
| 8 | "Tools execute inside an explicit `WasmInstanceGuard` that handles teardown on drop" | No guard type. `Sandbox::call` owns its `Store` in a stack frame and drops it on every path | In synchronous Rust this *is* the guarantee, and a `Drop` impl that only drops is noise pretending to be a safety mechanism. The guard becomes real when tool execution moves onto a cancellable task in Phase 4, where a dropped future can abandon a call mid-flight — that is the failure the original note describes, and it does not exist yet. |
| 9 | `MalformedPayload` = "not valid UTF-8, or not valid JSON" | Broadened to "or missing a field this event requires" | An `EXECUTE_TOOL` with no `tool_name` is structurally wrong, not merely naming an absent tool. Keeping it distinct from `UnknownTool` tells an operator whether the proposer sent the wrong *shape* or the wrong *name*, which are different bugs with different fixes. |
| 10 | Tech stack pins Rust `1.80+` | Rust `1.90+` | `cargo add` resolves against `rust-version`, so a 1.80 floor silently pinned wasmtime to 27. On this workstation wasmtime 27 **aborts the process** on out-of-fuel: the trap is raised from an `extern "C"` libcall that `longjmp`s out, and under x86-64-on-ARM64 emulation the `longjmp` returns instead of unwinding, so control falls off a `nounwind` function. Wasmtime 47 does not have this path. A sandbox that kills the host when a tool exceeds its budget fails the entire point of Phase 2, so the floor moved. |

## FSM: STATES

Six states. Two are terminal. Serialized as the SCREAMING_SNAKE strings shown.

| State | Meaning | Terminal |
| --- | --- | --- |
| `IDLE` | Session exists, no work started | no |
| `PLANNING` | Awaiting a proposal from the proposer plane | no |
| `TOOL_EXECUTION` | A tool call is in flight; no proposal is accepted while here | no |
| `REFLECTING` | A tool result is available and has been handed back to the proposer | no |
| `DONE` | Session completed normally | **yes** |
| `HALTED` | Session stopped by the runtime (budget, violation cap, timeout, abort) | **yes** |

Terminal states accept no further events. A proposal against a terminal state is rejected as
`TerminalState` and still appends a `REJECTED` ledger row — a rejected proposal is evidence and
is never dropped silently.

## FSM: EVENTS AND ORIGIN

`Origin` is a security boundary, not a label. The proposer plane may submit **only** `PROPOSER`
events. A `RUNTIME` event arriving over the proposal API is rejected as `ForgedOrigin` before
edge validation is even consulted — this is what stops a model from fabricating its own tool
results or clearing its own budget.

| Event | Origin | Carries |
| --- | --- | --- |
| `START` | PROPOSER | task description |
| `EXECUTE_TOOL` | PROPOSER | `tool_name`, arbitrary argument bytes |
| `FINISH` | PROPOSER | final answer |
| `TOOL_RESULT` | RUNTIME | tool output or tool error |
| `ABORT` | RUNTIME | reason |

## FSM: TRANSITION TABLE

The complete edge set. Any (state, event) pair absent from this table is illegal.

| From | Event | To |
| --- | --- | --- |
| `IDLE` | `START` | `PLANNING` |
| `PLANNING` | `EXECUTE_TOOL` | `TOOL_EXECUTION` |
| `PLANNING` | `FINISH` | `DONE` |
| `TOOL_EXECUTION` | `TOOL_RESULT` | `REFLECTING` |
| `REFLECTING` | `EXECUTE_TOOL` | `TOOL_EXECUTION` |
| `REFLECTING` | `FINISH` | `DONE` |
| any non-terminal | `ABORT` | `HALTED` |

Note there is no `CONTINUE` event and no return edge to `PLANNING`. `REFLECTING` can dispatch the
next tool directly. A separate "think again" event that only moves `REFLECTING` to `PLANNING`
would add a state hop that changes nothing observable and burns a step from the budget.

## FSM: REJECTION REASONS

Every rejection is one of these, appended to the ledger with `status = REJECTED` and
`to_state = from_state`. The set is closed; there is no `Other`.

| Reason | Trigger |
| --- | --- |
| `IllegalEdge` | (state, event) not in the transition table |
| `TerminalState` | Session already in `DONE` or `HALTED` |
| `ForgedOrigin` | A `RUNTIME`-origin event submitted through the proposal API |
| `StepBudgetExhausted` | Accepted-step count already at `limits.max_steps` |
| `PayloadTooLarge` | Payload exceeds `limits.max_payload_bytes` |
| `MalformedPayload` | Payload is not valid UTF-8, or not valid JSON |
| `UnknownTool` | `EXECUTE_TOOL` names a tool absent from the registry |
| `SessionUnknown` | No such session id |

## BUDGETS AND HALT CONDITIONS

Enforced by the runtime, never by the proposer. Each triggers a `RUNTIME`-origin `ABORT`
carrying the reason, moving the session to `HALTED`.

| Budget | Default | Halts on |
| --- | --- | --- |
| `max_steps` | 50 | Accepted proposer events reach the cap |
| `max_consecutive_rejects` | 3 | Defense against proposal lock-in loops: the model re-proposing an identical rejected transition forever. Counter resets on any acceptance |
| `state_timeout_ms` | 30_000 | Wall-clock time in a single non-terminal state. Wall clock is correct here — this bounds *real* hang, and it is never hashed, so it cannot affect replay |
| `max_payload_bytes` | 65_536 | Rejects the proposal, does not halt the session |

`max_steps` counts **accepted** events only. Rejections are governed by
`max_consecutive_rejects` instead — otherwise a model that spams invalid transitions could burn
a session's entire budget without ever executing anything, converting a validation success into
a denial of service.

## LEDGER: SQLITE SCHEMA

WAL mode, `synchronous = FULL`. `FULL` and not `NORMAL`: under `NORMAL` a power cut can lose
the trailing committed transactions, which is precisely the "partial write chain break" listed
in the risk taxonomy. The durability of the last event is the whole product.

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    created_ms  INTEGER NOT NULL,
    state       TEXT    NOT NULL,
    steps       INTEGER NOT NULL DEFAULT 0,
    rejects     INTEGER NOT NULL DEFAULT 0   -- consecutive
);

CREATE TABLE IF NOT EXISTS events (
    seq         INTEGER PRIMARY KEY,          -- global, monotonic, gapless, starts at 1
    session_id  TEXT    NOT NULL REFERENCES sessions(id),
    mono_ns     INTEGER NOT NULL,             -- ns since daemon epoch; ordering authority
    wall_ms     INTEGER NOT NULL,             -- advisory only, NEVER hashed, NEVER ordered on
    from_state  TEXT    NOT NULL,
    event       TEXT    NOT NULL,
    origin      TEXT    NOT NULL,             -- PROPOSER | RUNTIME
    payload     BLOB    NOT NULL,             -- verbatim submitted bytes
    status      TEXT    NOT NULL,             -- ACCEPTED | REJECTED
    reason      TEXT,                         -- rejection reason, NULL when ACCEPTED
    to_state    TEXT    NOT NULL,
    prev_hash   BLOB    NOT NULL,             -- 32 bytes
    hash        BLOB    NOT NULL              -- 32 bytes
);

CREATE INDEX IF NOT EXISTS events_by_session ON events(session_id, seq);
```

`seq` is global across sessions, not per-session. One chain over the whole ledger means a
deleted or reordered event in *any* session breaks verification. Per-session chains would let
an attacker drop an entire session without leaving a gap.

## LEDGER: HASH CHAIN

```text
hash_n = HMAC-SHA256(key, prev_hash_n || preimage_n)

preimage_n = seq_be64
           || len_be32(session_id) || session_id
           || mono_ns_be64
           || len_be32(from_state) || from_state
           || len_be32(event)      || event
           || len_be32(origin)     || origin
           || len_be32(status)     || status
           || len_be32(reason)     || reason        -- empty string when NULL
           || len_be32(to_state)   || to_state
           || len_be32(payload)    || payload

prev_hash_1 = [0u8; 32]
```

Every variable-length field is length-prefixed. Without prefixes, `("AB", "C")` and `("A", "BC")`
hash identically, and an attacker who controls a payload can shift bytes across a field boundary
to forge a matching chain. `wall_ms` is excluded because it is not deterministic across replay.

**Key.** 32 random bytes from the OS CSPRNG, written to `<state_dir>/ledger.key` at init with
owner-only permissions, or supplied via `VANGUARD_LEDGER_KEY` (hex) which takes precedence.
Refuse to start if the file exists with group/other read permission on Unix.

**Verification.** `vgctl verify` recomputes the chain from `seq = 1`, checking gaplessness and
each link. It reports the first divergent `seq` and exits `3`. `vanguardd` runs the same check
at boot and refuses to serve on failure — a corrupt ledger is not something to append to.

## DETERMINISM RULES

Replay is the product's core claim, so these are hard rules in any code path that can affect
state or the hash chain:

1. No `HashMap`/`HashSet` iteration — `BTreeMap`/`BTreeSet` only. Rust's default hasher is
   randomly seeded per process, so `HashMap` iteration order differs between the original run
   and the replay.
2. No `SystemTime::now()` in hashed fields. `mono_ns` comes from a monotonic `Instant` measured
   against a daemon epoch captured once at startup.
3. No RNG in the engine. Keys and session ids are generated at the edges, then recorded.
4. No floats anywhere in ledger-affecting logic. Payload bytes are opaque, so payload floats are
   fine — they are never re-serialized.
5. **Single writer.** All ledger writes go through one owning task fed by an `mpsc` channel.
   This is the answer to the `SQLITE_BUSY` contention in the risk taxonomy: with exactly one
   writer there is no write contention to lose, and `seq` allocation needs no separate lock.
   Readers use separate read-only connections.

## TOOL ABI AND SANDBOX

A tool is a WebAssembly module that **imports nothing** and exports exactly three things:

| Export | Signature | Meaning |
| --- | --- | --- |
| `memory` | — | Its linear memory |
| `alloc` | `(i32) -> i32` | Reserve `n` bytes, return the offset |
| `run` | `(i32, i32) -> i64` | Take `(ptr, len)` of the input, return `(ptr << 32) \| len` of the output |

The result is packed into one `i64` to avoid multi-value returns and host-side out-parameters,
neither of which earns its ABI weight here. The host bounds-checks the returned range against the
guest's own memory before reading it — `packed` is a value the guest chose, and a guest that
points past the end of its memory must not get host bytes back.

Tool input is the `EXECUTE_TOOL` payload verbatim. Tool output must itself be valid JSON; it is
wrapped as `{"ok":true,"output":<output>}`, or `{"ok":false,"error":"<why>"}` on failure, and that
wrapper is the `TOOL_RESULT` payload. Output that is not JSON is reported as a failed call rather
than stored as an opaque blob — a payload the auditor cannot parse is a payload the auditor
cannot audit.

**The host binding whitelist is empty.** The `wasmtime::Linker` is created with nothing defined,
so a module declaring *any* import — including WASI — fails to instantiate. This is the default
posture, not an unfinished feature: an entry gets added when one has been argued for, and there
is no `host_funcs.rs` until then.

**Termination is bounded by fuel, not wall clock.** Fuel is deterministic — the same module on
the same input runs out after the same instruction on every machine — which is what keeps replay
meaningful. A wall-clock deadline would let the same log produce different outcomes on a loaded
host. `sandbox.wall_timeout_ms` therefore has no enforcement path yet and only becomes meaningful
once a host binding exists that can block, since fuel cannot bound time spent outside wasm.

**The registry is the authorization model.** `EXECUTE_TOOL` naming a tool absent from the registry
is rejected as `UnknownTool` before anything executes, so an empty registry denies everything.
Modules are loaded from `<state_dir>/tools/*.{wasm,wat}` and named by file stem.

## CONFIGURATION

TOML, loaded from `--config <path>`, defaults shown. Any `VANGUARD_<SECTION>_<KEY>` env var
overrides the corresponding file value.

```toml
[runtime]
state_dir   = "/var/lib/vanguard"      # ./.vanguard in dev
socket      = "/var/run/vanguard.sock"
log_level   = "info"

[limits]
max_steps               = 50
max_consecutive_rejects = 3
state_timeout_ms        = 30000
max_payload_bytes       = 65536
max_context_tokens      = 8192

[sandbox]
fuel            = 10000000
max_memory_mb   = 64
wall_timeout_ms = 50

[egress]
allow = []                              # empty = deny all
```

## CLI SURFACE (`vgctl`)

| Command | Does |
| --- | --- |
| `vgctl verify [--db <path>]` | Recompute and check the hash chain offline. No daemon needed |
| `vgctl health` | Daemon liveness and ledger head `seq` |
| `vgctl state --session-id <id>` | Current state, step count, consecutive rejects |
| `vgctl ledger [--session-id <id>] [--follow]` | Dump or tail events |
| `vgctl replay --log <path>` | Offline reconstruction; prints the state sequence |
| `vgctl propose --session-id <id> --event <E> [--payload <json>]` | Manual proposal, for testing the engine without a model |

Exit codes: `0` ok, `1` runtime error, `2` usage error, `3` chain verification failed,
`4` daemon unreachable, `5` proposal rejected (the reason goes to stderr).

## DEPENDENCIES

Pinned by phase so that early phases stay buildable without the later, heavier trees.

| Phase | Crates |
| --- | --- |
| 0 | `rusqlite` (bundled), `hmac`, `sha2`, `getrandom`, `serde`, `serde_json`, `toml`, `thiserror`, `tracing`, `tracing-subscriber`, `clap` (derive), `tokio` (rt-multi-thread, macros, sync, signal) |
| 1 | none beyond phase 0 — the FSM is a pure function over enums and must stay dependency-free |
| 2 | `wasmtime` (47+; see SPEC CORRECTIONS #10) |
| 4 | `tonic`, `prost`, `tonic-build` (build-dep) |
| 6 | `opentelemetry`, `opentelemetry-otlp`, `tracing-opentelemetry` |
| 7 | `aya`, `aya-bpf` — Linux only, behind `#[cfg(target_os = "linux")]` and an `ebpf` feature |

`src/fsm/` must not gain a dependency. It is the component whose correctness everything else
rests on, and it is testable in microseconds precisely because it touches nothing.

## PHASE EXIT TESTS

Each phase is done when its named test passes, not when the code looks finished.

| Phase | Test | Proves |
| --- | --- | --- |
| 0 | `ledger_chain_survives_restart` | Write N events, drop the DB handle, reopen, verify chain |
| 0 | `tampered_payload_breaks_chain` | Mutate one payload byte via raw SQL; verify reports that exact `seq` |
| 1 | `illegal_edges_rejected_without_mutation` | Every (state, event) pair outside the table leaves state unchanged and appends a `REJECTED` row |
| 1 | `forged_runtime_origin_rejected` | `TOOL_RESULT` submitted as a proposal is rejected as `ForgedOrigin` |
| 1 | `step_budget_halts_session` | 50 accepted steps then `HALTED`, budget not burnable by rejections |
| 2 | `spin_loop_hits_fuel_limit` | Infinite-loop WASM module terminates on fuel exhaustion, in under 50 ms |
| 2 | `tools_cannot_reach_the_host` | A module importing WASI fails to instantiate |
| 2 | `a_starved_tool_returns_a_result_instead_of_stranding_the_session` | A runaway tool comes back as a `TOOL_RESULT`, not a hung session |
| 3 | `context_bounded_over_1000_turns` | Token count never exceeds 8192 across 1000 turns |
| 4 | `vgctl_roundtrip_over_socket` | State query over the local socket matches the engine |
| 5 | `replay_reproduces_state_sequence` | Replaying a log yields the identical state sequence and identical head hash |
| 6 | `no_dropped_spans_under_load` | 1000 req/sec, zero dropped spans |
| 7 | `egress_blocked_outside_allowlist` | Linux only; skipped elsewhere |

## PLATFORM NOTE (this workstation)

Host is `aarch64-pc-windows-msvc`, but the installed VS 2022 Build Tools ship only the x86/x64
MSVC libraries — there is no arm64 CRT, so **nothing links on the host toolchain**, including
build scripts. Build and test with the x64 toolchain, which runs under emulation:

```bash
cargo +stable-x86_64-pc-windows-msvc test --all-targets
```

Emulation also breaks wasmtime 27's out-of-fuel unwind path outright — see SPEC CORRECTIONS #10.

Unix domain sockets are unavailable in this environment for Phase 4 purposes on Windows named
paths; the control plane binds a loopback TCP port when `cfg(windows)`, and the Unix socket path
from the config on Unix. Phase 7 (eBPF) cannot be built or tested here at all; it is Linux-only
and gated behind `#[cfg(target_os = "linux")]`.
