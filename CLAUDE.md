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
║  VANGUARD BUILD PROGRESS                  0/8 DONE ║
║  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ALL PHASES PENDING [ ]    ║
║  See ROADMAP.md for the path from prototype to production.║
║  Phase 0: Runtime Core, Event Log & Cryptographic Ledger [ ] ║
║  Phase 1: Deterministic FSM Engine & Guardrails      [ ] ║
║  Phase 2: WASM Sandboxed Tool Execution Engine       [ ] ║
║  Phase 3: Context Paging & Memory Eviction Subsystem  [ ] ║
║  Phase 4: gRPC Control Plane & Local Socket API      [ ] ║
║  Phase 5: Time-Travel Replay & Mock Execution Engine [ ] ║
║  Phase 6: OpenTelemetry Tracing & Audit Log Exporter  [ ] ║
║  Phase 7: eBPF Network Proxy & Tool Rate Limiter     [ ] ║
╚══════════════════════════════════════════════════════════╝

```

Phase: zero of eight phases completed; implementation for all core subsystems is pending.

**Phase 0-7 Planning.** System architecture, data flow schemas, gRPC protobuf contracts, and FSM transition functions have been specified. Development will proceed sequentially from Phase 0 (Cryptographic Ledger & Storage) through Phase 7 (eBPF Egress Filtering).

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
vanguard/
├── Cargo.toml
├── build.rs
├── src/
│   ├── main.rs                 # vanguardd entry point
│   ├── config.rs               # Engine configuration & parameters
│   ├── fsm/
│   │   ├── engine.rs           # FSM state machine validator
│   │   ├── state.rs            # State node & edge definitions
│   │   └── transition.rs       # Legal transition verifiers
│   ├── ledger/
│   │   ├── db.rs               # SQLite WAL store driver
│   │   ├── event.rs            # Cryptographic event schema & hashing
│   │   └── replay.rs           # Replay & time-travel engine
│   ├── sandbox/
│   │   ├── wasm.rs             # Wasmtime runtime wrapper & fuel limits
│   │   └── host_funcs.rs       # Whitelisted host bindings
│   ├── memory/
│   │   ├── pager.rs            # Sliding context window manager
│   │   └── eviction.rs         # LRU token & vector store paging
│   └── api/
│       ├── grpc.rs             # tonic gRPC service implementation
│       └── proto/              # Protobuf definitions
├── bin/
│   └── vgctl.rs                # CLI debugging & administration tool
└── tests/
    ├── fsm_tests.rs
    └── replay_tests.rs

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

```bash
# Terminal 1 — Run runtime daemon in debug mode
cargo run --bin vanguardd -- --config config.dev.toml

# Terminal 2 — Inspect system health and active FSM state
cargo run --bin vgctl -- health
cargo run --bin vgctl -- state --session-id default

# Execute full suite of unit and integration tests
cargo test --all-targets --all-features

```

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
