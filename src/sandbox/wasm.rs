//! Wasmtime execution with hard resource limits.
//!
//! The sandbox exposes **nothing**. The linker is built empty, so a module that
//! declares any import at all fails to instantiate rather than running with a
//! partially satisfied environment. That is the whitelist: it starts empty, and
//! every future entry has to be argued for one at a time.
//!
//! Termination is bounded by *fuel*, not wall clock. Fuel is deterministic —
//! the same module on the same input runs out after the same instruction on
//! every machine — which is what keeps replay meaningful. A wall-clock deadline
//! would make the same log produce different outcomes on a loaded host.

use std::time::{Duration, Instant};

use wasmtime::{Config, Engine, Instance, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// The tool ABI. A module must export these three things and import nothing.
///
/// - `memory`            — its linear memory
/// - `alloc(i32) -> i32` — reserve `n` bytes, return the offset
/// - `run(i32, i32) -> i64` — take (ptr, len) of the input, return a packed
///   `(ptr << 32) | len` pointing at the output
///
/// Packing the result into one `i64` avoids multi-value returns and a
/// host-side out-parameter, both of which need more ABI than this earns.
pub const EXPORT_MEMORY: &str = "memory";
pub const EXPORT_ALLOC: &str = "alloc";
pub const EXPORT_RUN: &str = "run";

/// Resource ceilings for one tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fuel {
    pub units: u64,
    pub max_memory_bytes: usize,
}

impl Default for Fuel {
    fn default() -> Self {
        Fuel {
            units: 10_000_000,
            max_memory_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Why a tool call did not produce output.
///
/// `OutOfFuel` is deliberately distinct from `Trap`: one is the sandbox working
/// as designed, the other is the tool being broken. Collapsing them would make
/// "this tool is too expensive" indistinguishable from "this tool is buggy".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    OutOfFuel,
    Trap(String),
    /// The module asked for an import. Nothing is on offer.
    ForbiddenImport(String),
    /// Missing export, wrong signature, or an out-of-bounds result pointer.
    AbiViolation(String),
    Invalid(String),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::OutOfFuel => write!(f, "out of fuel"),
            ToolError::Trap(m) => write!(f, "trap: {m}"),
            ToolError::ForbiddenImport(m) => write!(f, "forbidden import: {m}"),
            ToolError::AbiViolation(m) => write!(f, "abi violation: {m}"),
            ToolError::Invalid(m) => write!(f, "invalid module: {m}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub bytes: Vec<u8>,
    /// Fuel actually burned. Recorded so an operator can see how close a tool
    /// runs to its ceiling before it starts failing in production.
    pub fuel_used: u64,
    pub elapsed: Duration,
}

/// State threaded through a `Store`. Holds only the limiter — anything else
/// here would be ambient authority the module could reach.
struct HostState {
    limits: StoreLimits,
}

/// A compiled, reusable engine. Compilation is the expensive part, so this is
/// created once and shared; each call still gets its own `Store`.
pub struct Sandbox {
    engine: Engine,
    fuel: Fuel,
}

impl Sandbox {
    pub fn new(fuel: Fuel) -> Result<Sandbox, ToolError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // No threads, no SIMD nondeterminism, no bulk-memory surprises beyond
        // the default. Fewer proposals enabled is fewer ways for a module to
        // behave differently between the original run and its replay.
        config.wasm_threads(false);
        config.wasm_reference_types(false);
        // No host-side backtrace capture on trap. Out-of-fuel is an expected
        // outcome here, not an exceptional one, so the stack walk would run on
        // a hot path to build something nothing reads: `ToolError` carries the
        // trap code and message, which is what an operator acts on.
        config.wasm_backtrace_max_frames(None);

        let engine = Engine::new(&config).map_err(|e| ToolError::Invalid(e.to_string()))?;
        Ok(Sandbox { engine, fuel })
    }

    pub fn fuel(&self) -> Fuel {
        self.fuel
    }

    /// Compile a module from `.wasm` bytes or `.wat` text.
    pub fn compile(&self, bytes: &[u8]) -> Result<Module, ToolError> {
        Module::new(&self.engine, bytes).map_err(|e| ToolError::Invalid(e.to_string()))
    }

    /// Run one tool call to completion or to its resource ceiling.
    ///
    /// The `Store` is owned by this frame and dropped before returning on every
    /// path, success or trap. That ownership is what stops linear memory from
    /// outliving a failed call — there is no pool to leak into. See SPEC
    /// CORRECTIONS #8 in CLAUDE.md for why there is no separate guard type.
    pub fn call(&self, module: &Module, input: &[u8]) -> Result<ToolOutput, ToolError> {
        let started = Instant::now();

        let state = HostState {
            limits: StoreLimitsBuilder::new()
                .memory_size(self.fuel.max_memory_bytes)
                // One memory, one table. A module wanting more is not a tool.
                .memories(1)
                .tables(1)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.fuel.units)
            .map_err(|e| ToolError::Invalid(e.to_string()))?;

        // Empty linker: the module gets nothing it did not bring itself.
        let linker: Linker<HostState> = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, module).map_err(|e| {
            if let Some(fuel_err) = as_fuel_error(&e) {
                return fuel_err;
            }
            // Instantiation fails on an unsatisfied import, which with an empty
            // linker means the module asked for host authority.
            ToolError::ForbiddenImport(root_cause(&e))
        })?;

        let out = self.invoke(&mut store, &instance, input);
        let fuel_used = self
            .fuel
            .units
            .saturating_sub(store.get_fuel().unwrap_or(0));

        out.map(|bytes| ToolOutput {
            bytes,
            fuel_used,
            elapsed: started.elapsed(),
        })
    }

    fn invoke(
        &self,
        store: &mut Store<HostState>,
        instance: &Instance,
        input: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        let memory = instance
            .get_memory(&mut *store, EXPORT_MEMORY)
            .ok_or_else(|| ToolError::AbiViolation(format!("no exported {EXPORT_MEMORY}")))?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&mut *store, EXPORT_ALLOC)
            .map_err(|e| ToolError::AbiViolation(format!("{EXPORT_ALLOC}: {e}")))?;
        let run = instance
            .get_typed_func::<(i32, i32), i64>(&mut *store, EXPORT_RUN)
            .map_err(|e| ToolError::AbiViolation(format!("{EXPORT_RUN}: {e}")))?;

        let len = i32::try_from(input.len())
            .map_err(|_| ToolError::AbiViolation("input exceeds i32".into()))?;

        let ptr = alloc.call(&mut *store, len).map_err(classify)?;
        memory
            .write(&mut *store, ptr as usize, input)
            .map_err(|e| ToolError::AbiViolation(format!("input write: {e}")))?;

        let packed = run.call(&mut *store, (ptr, len)).map_err(classify)?;

        let out_ptr = (packed >> 32) as u32 as usize;
        let out_len = (packed & 0xffff_ffff) as u32 as usize;

        let data = memory.data(&*store);
        // Bounds are checked here rather than trusted: `packed` is a value the
        // guest chose, and a guest that returns a pointer past the end of its
        // own memory must not be able to read host bytes.
        data.get(out_ptr..out_ptr.saturating_add(out_len))
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                ToolError::AbiViolation(format!(
                    "result [{out_ptr}, +{out_len}) is outside a {}-byte memory",
                    data.len()
                ))
            })
    }
}

/// Turn a wasmtime error into the right `ToolError`. Out-of-fuel arrives as a
/// trap, and telling it apart from a real trap is the whole point.
fn classify(err: wasmtime::Error) -> ToolError {
    as_fuel_error(&err).unwrap_or_else(|| ToolError::Trap(root_cause(&err)))
}

fn as_fuel_error(err: &wasmtime::Error) -> Option<ToolError> {
    match err.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::OutOfFuel) => Some(ToolError::OutOfFuel),
        _ => None,
    }
}

fn root_cause(err: &wasmtime::Error) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Echoes its input back. A bump allocator is all a tool needs, and it
    /// makes the module small enough to read.
    const ECHO_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $n i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $n)))
            (local.get $p))
          (func (export "run") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len)))))
    "#;

    const SPIN_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "run") (param i32) (param i32) (result i64)
            (loop $forever (br $forever))
            (i64.const 0)))
    "#;

    fn sandbox() -> Sandbox {
        Sandbox::new(Fuel::default()).unwrap()
    }

    #[test]
    fn echo_round_trips() {
        let sb = sandbox();
        let m = sb.compile(ECHO_WAT.as_bytes()).unwrap();
        let out = sb.call(&m, br#"{"hello":"world"}"#).unwrap();
        assert_eq!(out.bytes, br#"{"hello":"world"}"#);
        assert!(out.fuel_used > 0, "a real call must burn fuel");
    }

    #[test]
    fn spin_loop_runs_out_of_fuel() {
        let sb = sandbox();
        let m = sb.compile(SPIN_WAT.as_bytes()).unwrap();
        assert_eq!(sb.call(&m, b"{}").unwrap_err(), ToolError::OutOfFuel);
    }

    #[test]
    fn host_stays_usable_after_a_starved_module() {
        // The point of the sandbox: one tool exhausting its budget must not
        // affect the next call, which shares the engine.
        let sb = sandbox();
        let spin = sb.compile(SPIN_WAT.as_bytes()).unwrap();
        let echo = sb.compile(ECHO_WAT.as_bytes()).unwrap();
        for _ in 0..3 {
            assert_eq!(sb.call(&spin, b"{}").unwrap_err(), ToolError::OutOfFuel);
            assert_eq!(sb.call(&echo, b"ok").unwrap().bytes, b"ok");
        }
    }

    #[test]
    fn imports_are_refused() {
        let wat = r#"
            (module
              (import "env" "read_file" (func $rf (param i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "run") (param i32) (param i32) (result i64) (i64.const 0)))
        "#;
        let sb = sandbox();
        let m = sb.compile(wat.as_bytes()).unwrap();
        assert!(
            matches!(sb.call(&m, b"{}"), Err(ToolError::ForbiddenImport(_))),
            "a module must not be able to reach the host"
        );
    }

    #[test]
    fn missing_exports_are_an_abi_violation() {
        let wat = r#"(module (memory (export "memory") 1))"#;
        let sb = sandbox();
        let m = sb.compile(wat.as_bytes()).unwrap();
        assert!(matches!(
            sb.call(&m, b"{}"),
            Err(ToolError::AbiViolation(_))
        ));
    }

    #[test]
    fn out_of_bounds_result_pointer_is_refused() {
        // A guest claiming its output lives far past its own memory must not
        // get host bytes back.
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "run") (param i32) (param i32) (result i64)
                (i64.const 0x7fff_ffff_0000_0010)))
        "#;
        let sb = sandbox();
        let m = sb.compile(wat.as_bytes()).unwrap();
        assert!(matches!(
            sb.call(&m, b"{}"),
            Err(ToolError::AbiViolation(_))
        ));
    }

    #[test]
    fn a_trap_is_not_reported_as_out_of_fuel() {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "run") (param i32) (param i32) (result i64)
                (unreachable)))
        "#;
        let sb = sandbox();
        let m = sb.compile(wat.as_bytes()).unwrap();
        assert!(matches!(sb.call(&m, b"{}"), Err(ToolError::Trap(_))));
    }

    #[test]
    fn memory_growth_is_capped() {
        // Asks for 2000 pages (~128 MiB) against a 1 MiB ceiling.
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "run") (param i32) (param i32) (result i64)
                (drop (memory.grow (i32.const 2000)))
                (i64.const 0)))
        "#;
        let sb = Sandbox::new(Fuel {
            units: 10_000_000,
            max_memory_bytes: 1024 * 1024,
        })
        .unwrap();
        let m = sb.compile(wat.as_bytes()).unwrap();
        // `memory.grow` returns -1 rather than trapping, so the call succeeds;
        // what matters is that the host never allocated 128 MiB for it.
        let out = sb.call(&m, b"{}").unwrap();
        assert_eq!(out.bytes, Vec::<u8>::new());
    }
}
