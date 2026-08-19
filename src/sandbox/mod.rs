//! Sandboxed tool execution.
//!
//! There is no `host_funcs.rs`. The whitelist of host bindings is currently
//! empty, which is not an omission but the correct default — see the module doc
//! on [`wasm`]. The file appears when the first binding has been argued for.

pub mod wasm;

use std::collections::BTreeSet;
use std::path::Path;

use wasmtime::Module;

use crate::error::{Error, Result};
pub use wasm::{Fuel, Sandbox, ToolError, ToolOutput};

/// The set of tools that may be named by an `EXECUTE_TOOL` proposal.
///
/// Membership is the whole authorization model: a tool that is not in here
/// cannot be invoked, and the FSM rejects the proposal before anything is
/// executed. An empty registry therefore denies everything, which is the right
/// posture for a runtime that has not been told what it is allowed to run.
pub struct ToolRegistry {
    sandbox: Sandbox,
    // `BTreeMap` rather than `HashMap`: the registry is iterated when reporting
    // and when replaying, and both must be order-stable across processes.
    modules: std::collections::BTreeMap<String, Module>,
}

impl ToolRegistry {
    pub fn new(sandbox: Sandbox) -> ToolRegistry {
        ToolRegistry {
            sandbox,
            modules: std::collections::BTreeMap::new(),
        }
    }

    /// A registry that denies every tool. Useful for a runtime doing pure FSM
    /// work, and it is what `load_dir` starts from.
    pub fn empty() -> Result<ToolRegistry> {
        Ok(ToolRegistry::new(
            Sandbox::new(Fuel::default()).map_err(|e| Error::Config(e.to_string()))?,
        ))
    }

    /// Compile and register one module. The name is what proposals must use.
    pub fn insert(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        let module = self
            .sandbox
            .compile(bytes)
            .map_err(|e| Error::Config(format!("tool {name}: {e}")))?;
        self.modules.insert(name.to_string(), module);
        Ok(())
    }

    /// Load every `*.wasm` and `*.wat` in `dir`, named by file stem.
    ///
    /// A missing directory is not an error: a deployment with no tools is a
    /// valid deployment, and it denies everything. A *malformed* module is an
    /// error, because silently skipping it would leave the operator believing a
    /// tool is available when it is not.
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize> {
        if !dir.is_dir() {
            return Ok(0);
        }
        // Sorted, so two machines loading the same directory register the same
        // tools in the same order.
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("wasm") | Some("wat")
                )
            })
            .collect();
        entries.sort();

        let mut loaded = 0;
        for path in entries {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| {
                    Error::Config(format!("unusable tool filename: {}", path.display()))
                })?
                .to_string();
            self.insert(&name, &std::fs::read(&path)?)?;
            loaded += 1;
        }
        Ok(loaded)
    }

    pub fn names(&self) -> BTreeSet<String> {
        self.modules.keys().cloned().collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.modules.contains_key(name)
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn fuel(&self) -> Fuel {
        self.sandbox.fuel()
    }

    /// Execute `name` against `input`.
    pub fn call(&self, name: &str, input: &[u8]) -> std::result::Result<ToolOutput, ToolError> {
        let module = self
            .modules
            .get(name)
            .ok_or_else(|| ToolError::Invalid(format!("no such tool: {name}")))?;
        self.sandbox.call(module, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn empty_registry_denies_everything() {
        let r = ToolRegistry::empty().unwrap();
        assert!(!r.contains("echo"));
        assert!(r.names().is_empty());
        assert!(r.call("echo", b"{}").is_err());
    }

    #[test]
    fn registered_tool_runs() {
        let mut r = ToolRegistry::empty().unwrap();
        r.insert("echo", ECHO_WAT.as_bytes()).unwrap();
        assert!(r.contains("echo"));
        assert_eq!(r.call("echo", br#"{"a":1}"#).unwrap().bytes, br#"{"a":1}"#);
    }

    #[test]
    fn load_dir_names_tools_by_file_stem() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("echo.wat"), ECHO_WAT).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

        let mut r = ToolRegistry::empty().unwrap();
        assert_eq!(r.load_dir(dir.path()).unwrap(), 1);
        assert_eq!(r.names(), ["echo".to_string()].into_iter().collect());
    }

    #[test]
    fn missing_dir_is_not_an_error_but_a_bad_module_is() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = ToolRegistry::empty().unwrap();
        assert_eq!(r.load_dir(&dir.path().join("nope")).unwrap(), 0);

        std::fs::write(dir.path().join("broken.wat"), "(module (this is not wat").unwrap();
        assert!(r.load_dir(dir.path()).is_err());
    }
}
