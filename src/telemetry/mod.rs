//! Observability, in two halves that must not be confused with each other.
//!
//! **Traces** are best-effort. Spans describe what the runtime did and are
//! useful for latency and debugging; a batch exporter with a bounded queue can
//! drop them under load, and that is an acceptable trade for observability.
//!
//! **The audit stream is not best-effort.** It is the ledger, exported by
//! cursor, and it cannot drop records: see [`audit`]. Anything not yet
//! acknowledged by a sink is still on disk and will be re-read. A trace pipeline
//! and an audit pipeline look superficially similar and have opposite failure
//! requirements — a dropped span costs you a graph, a dropped audit record costs
//! you the ability to say what happened.
//!
//! CLAUDE.md's Phase 6 exit criterion is "zero dropped span events under 1,000
//! req/sec". What is actually verifiable in-process is that instrumentation
//! emits one span per operation at that rate, which is what
//! `no_dropped_spans_under_load` checks. Whether a *remote* collector receives
//! all of them is a property of that collector's pipeline and its queue depth,
//! not something this crate can assert. The guarantee Vanguard does make about
//! not losing events is the audit stream's, and it is stronger.

pub mod audit;

use std::time::Duration;

use opentelemetry_otlp::WithExportConfig;
use tokio::sync::mpsc;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::api::Handle;
use crate::config::TelemetryConfig;
use crate::error::{Error, Result};
use crate::telemetry::audit::AuditSink;

/// Flushes the tracer provider when dropped.
///
/// Held by `main` for the process lifetime: dropping it early would silently
/// stop trace export while everything still appeared to work.
pub struct Guard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Spans buffered in the batch processor are lost if the process
            // exits without this.
            let _ = provider.shutdown();
        }
    }
}

/// Install the global subscriber: stderr always, OTLP when configured.
pub fn init(level: &str, config: &TelemetryConfig) -> Result<Guard> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if !config.otlp_enabled() {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init();
        return Ok(Guard { provider: None });
    }

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(config.otlp_endpoint.clone())
        .build()
        .map_err(|e| Error::Config(format!("otlp exporter: {e}")))?;

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(config.service_name.clone())
                .build(),
        )
        .build();

    let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "vanguard");
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init();

    Ok(Guard {
        provider: Some(provider),
    })
}

/// Drive an audit sink until `shutdown` fires, then drain what is left.
///
/// The final drain matters: without it, a clean shutdown would leave the last
/// interval's events unexported, and the operator would have no way to tell
/// that from a crash.
pub async fn run_exporter(
    handle: Handle,
    mut sink: Box<dyn AuditSink>,
    interval: Duration,
    batch: usize,
    mut shutdown: mpsc::Receiver<()>,
) {
    loop {
        let stopping = tokio::select! {
            _ = tokio::time::sleep(interval) => false,
            _ = shutdown.recv() => true,
        };

        loop {
            match handle.audit_batch(sink.name(), batch).await {
                Ok(records) if records.is_empty() => break,
                Ok(records) => {
                    let head = records.last().expect("non-empty").seq;
                    let count = records.len();
                    if let Err(e) = sink.write(&records) {
                        // Deliberately no cursor advance: the batch is retried
                        // on the next tick. A sink that stays down backs the
                        // stream up rather than losing it.
                        tracing::error!(error = %e, sink = sink.name(), "audit sink write failed");
                        break;
                    }
                    if let Err(e) = handle.audit_advance(sink.name(), head).await {
                        tracing::error!(error = %e, "advancing audit cursor failed");
                        break;
                    }
                    tracing::debug!(count, head, sink = sink.name(), "audit batch exported");
                    if count < batch {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "reading audit batch failed");
                    break;
                }
            }
        }

        if stopping {
            return;
        }
    }
}
