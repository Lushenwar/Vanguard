// Each integration test binary compiles this module separately and uses only
// the parts it needs, so anything unused *in that binary* reads as dead code.
// The alternative is a fixtures crate, which is more machinery than four
// constants deserve.
#![allow(dead_code)]

//! Fixtures shared by the integration tests.
//!
//! Lives in `common/` rather than being copied per file so that the tool ABI is
//! written down once — four copies of the same WAT would drift the moment the
//! ABI changes, and the drift would show up as an unrelated test failing.

use vanguard::sandbox::{Fuel, Sandbox, ToolRegistry};

/// Returns its input unchanged, via a bump allocator. Small enough to read,
/// which matters when it is the reference implementation of the ABI.
pub const ECHO_WAT: &str = r#"
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

/// Never terminates. The only thing that stops it is fuel.
pub const SPIN_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "run") (param i32) (param i32) (result i64)
        (loop $forever (br $forever))
        (i64.const 0)))
"#;

pub fn registry_with(tools: &[(&str, &str)], fuel: Fuel) -> ToolRegistry {
    let mut r = ToolRegistry::new(Sandbox::new(fuel).unwrap());
    for (name, wat) in tools {
        r.insert(name, wat.as_bytes()).unwrap();
    }
    r
}

/// The registry most tests want: one working tool called `echo`.
pub fn echo_registry() -> ToolRegistry {
    registry_with(&[("echo", ECHO_WAT)], Fuel::default())
}

pub fn echo_names() -> std::collections::BTreeSet<String> {
    ["echo".to_string()].into_iter().collect()
}
