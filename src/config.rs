//! Engine configuration: TOML on disk, `VANGUARD_<SECTION>_<KEY>` overrides.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fsm::engine::Limits;
use crate::sandbox::Fuel;

pub const APP_NAME: &str = "vanguard";

/// Where the control plane lives on this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp(String),
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Unix(path) => write!(f, "unix://{}", path.display()),
            Endpoint::Tcp(addr) => write!(f, "http://{addr}"),
        }
    }
}
pub const LEDGER_FILE: &str = "vanguard.sqlite";
pub const TOOLS_DIR: &str = "tools";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
// `deny_unknown_fields` turns a mistyped key into a startup failure instead of
// a silently ignored setting. A budget that was never applied because of a typo
// is worse than no budget at all, because it looks enforced.
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub runtime: RuntimeConfig,
    pub limits: LimitsConfig,
    pub sandbox: SandboxConfig,
    pub egress: EgressConfig,
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub state_dir: PathBuf,
    /// Unix domain socket path. Used on Unix; ignored on Windows.
    pub socket: PathBuf,
    /// Loopback address for the control plane. Used on Windows, where Tokio
    /// has no `UnixListener`; ignored on Unix.
    pub control_addr: String,
    pub log_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_steps: u32,
    pub max_consecutive_rejects: u32,
    pub state_timeout_ms: u64,
    pub max_payload_bytes: usize,
    pub max_context_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub fuel: u64,
    pub max_memory_mb: u64,
    pub wall_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub service_name: String,
    /// OTLP/gRPC collector, e.g. `http://127.0.0.1:4317`. Empty disables trace
    /// export entirely rather than falling back to a default endpoint — a
    /// collector address is not something to guess at.
    pub otlp_endpoint: String,
    /// Append-only JSONL audit stream. Empty disables it.
    pub audit_log: PathBuf,
    pub audit_interval_ms: u64,
    pub audit_batch: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        TelemetryConfig {
            service_name: APP_NAME.to_string(),
            otlp_endpoint: String::new(),
            audit_log: PathBuf::new(),
            audit_interval_ms: 1_000,
            audit_batch: 512,
        }
    }
}

impl TelemetryConfig {
    pub fn otlp_enabled(&self) -> bool {
        !self.otlp_endpoint.is_empty()
    }

    pub fn audit_enabled(&self) -> bool {
        !self.audit_log.as_os_str().is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EgressConfig {
    /// Empty means deny all. Absence of a rule is a denial, never a wildcard.
    pub allow: Vec<String>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            state_dir: PathBuf::from("/var/lib/vanguard"),
            socket: PathBuf::from("/var/run/vanguard.sock"),
            control_addr: "127.0.0.1:50505".into(),
            log_level: "info".into(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_steps: 50,
            max_consecutive_rejects: 3,
            state_timeout_ms: 30_000,
            max_payload_bytes: 65_536,
            max_context_tokens: 8_192,
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig {
            fuel: 10_000_000,
            max_memory_mb: 64,
            wall_timeout_ms: 50,
        }
    }
}

impl Config {
    /// Load from `path` (or defaults when `None`), then apply env overrides.
    pub fn load(path: Option<&Path>) -> Result<Config> {
        let text = match path {
            Some(p) => std::fs::read_to_string(p)
                .map_err(|e| Error::Config(format!("{}: {e}", p.display())))?,
            None => String::new(),
        };
        Config::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Config> {
        let mut table: toml::Table =
            toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        apply_env(&mut table, &|name| std::env::var(name).ok());
        table
            .try_into::<Config>()
            .map_err(|e| Error::Config(e.to_string()))
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.runtime.state_dir.join(LEDGER_FILE)
    }

    /// Where compiled tool modules live. Derived from `state_dir` rather than
    /// given its own key: a second path to configure is a second path to get
    /// wrong, and nothing yet wants them apart.
    pub fn tools_dir(&self) -> PathBuf {
        self.runtime.state_dir.join(TOOLS_DIR)
    }

    /// The resource ceiling handed to every tool call.
    pub fn sandbox_fuel(&self) -> Fuel {
        Fuel {
            units: self.sandbox.fuel,
            max_memory_bytes: (self.sandbox.max_memory_mb as usize) * 1024 * 1024,
        }
    }

    /// Where the control plane listens, and where `vgctl` should look for it.
    ///
    /// Two keys rather than one overloaded string: a path and a socket address
    /// are different things, and a single field that is sometimes one and
    /// sometimes the other is a field nobody can validate.
    pub fn control_endpoint(&self) -> Endpoint {
        #[cfg(unix)]
        {
            Endpoint::Unix(self.runtime.socket.clone())
        }
        #[cfg(not(unix))]
        {
            Endpoint::Tcp(self.runtime.control_addr.clone())
        }
    }

    /// The subset of configuration the FSM evaluator is allowed to see.
    pub fn fsm_limits(&self) -> Limits {
        Limits {
            max_steps: self.limits.max_steps,
            max_consecutive_rejects: self.limits.max_consecutive_rejects,
            max_payload_bytes: self.limits.max_payload_bytes,
        }
    }
}

/// Overlay `VANGUARD_<SECTION>_<KEY>` onto a parsed table.
///
/// Walks the defaults rather than accepting arbitrary env names, so an override
/// can only set a key that actually exists, and only to the type that key
/// already has. `lookup` is injected so this is testable without mutating the
/// process environment, which is global and would race across test threads.
fn apply_env(table: &mut toml::Table, lookup: &dyn Fn(&str) -> Option<String>) {
    // The defaults define the full key space; a config file may omit sections.
    let defaults = toml::Table::try_from(Config::default()).expect("defaults serialize");

    for (section, default_val) in &defaults {
        let Some(default_section) = default_val.as_table() else {
            continue;
        };
        for (key, default_field) in default_section {
            let name = format!("VANGUARD_{}_{}", section.to_uppercase(), key.to_uppercase());
            let Some(raw) = lookup(&name) else { continue };
            let Some(value) = coerce(default_field, &raw) else {
                continue;
            };
            table
                .entry(section.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .map(|t| t.insert(key.clone(), value));
        }
    }
}

/// Parse `raw` into whatever type the default for this key has. Returning
/// `None` leaves the file/default value in place rather than substituting a
/// wrong-typed value that would fail deserialization with a confusing message.
fn coerce(default_field: &toml::Value, raw: &str) -> Option<toml::Value> {
    Some(match default_field {
        toml::Value::Integer(_) => toml::Value::Integer(raw.trim().parse().ok()?),
        toml::Value::Boolean(_) => toml::Value::Boolean(raw.trim().parse().ok()?),
        toml::Value::Array(_) => toml::Value::Array(
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| toml::Value::String(s.to_string()))
                .collect(),
        ),
        _ => toml::Value::String(raw.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_toml_yields_defaults() {
        assert_eq!(Config::from_toml("").unwrap(), Config::default());
    }

    #[test]
    fn file_values_override_defaults() {
        let c = Config::from_toml("[limits]\nmax_steps = 7\n").unwrap();
        assert_eq!(c.limits.max_steps, 7);
        // Untouched keys keep their defaults rather than zeroing out.
        assert_eq!(c.limits.max_consecutive_rejects, 3);
    }

    #[test]
    fn unknown_key_is_an_error() {
        let err = Config::from_toml("[limits]\nmax_stpes = 7\n").unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn env_overrides_file() {
        let mut table: toml::Table = toml::from_str("[limits]\nmax_steps = 7\n").unwrap();
        apply_env(&mut table, &|name| match name {
            "VANGUARD_LIMITS_MAX_STEPS" => Some("9".into()),
            "VANGUARD_EGRESS_ALLOW" => Some("a.example, b.example".into()),
            _ => None,
        });
        let c: Config = table.try_into().unwrap();
        assert_eq!(c.limits.max_steps, 9);
        assert_eq!(c.egress.allow, vec!["a.example", "b.example"]);
    }

    #[test]
    fn unparseable_env_value_is_ignored_not_fatal() {
        let mut table: toml::Table = toml::from_str("[limits]\nmax_steps = 7\n").unwrap();
        apply_env(&mut table, &|name| {
            (name == "VANGUARD_LIMITS_MAX_STEPS").then(|| "banana".into())
        });
        let c: Config = table.try_into().unwrap();
        assert_eq!(c.limits.max_steps, 7);
    }

    #[test]
    fn env_cannot_invent_a_key() {
        let mut table: toml::Table = toml::Table::new();
        apply_env(&mut table, &|name| {
            (name == "VANGUARD_LIMITS_MAX_EVERYTHING").then(|| "1".into())
        });
        assert!(Config::default().limits == table.try_into::<Config>().unwrap().limits);
    }
}
