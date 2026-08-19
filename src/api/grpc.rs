//! The tonic service. Translation only — every decision belongs to the FSM.

use std::pin::Pin;

use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{Request, Response, Status as TonicStatus};

use crate::api::actor::Handle;
use crate::api::pb::{
    self, control_server::Control, HealthRequest, HealthResponse, LedgerEvent, LedgerRequest,
    ProposalRequest, ProposalResponse, ReplayRequest, ReplaySummary, StateRequest, StateResponse,
};
use crate::error::Error;
use crate::fsm::engine::Decision;
use crate::fsm::state::Event;
use crate::ledger::event::{hex, Record};
use crate::runtime::Outcome;

pub struct ControlService {
    handle: Handle,
}

impl ControlService {
    pub fn new(handle: Handle) -> ControlService {
        ControlService { handle }
    }
}

type LedgerStream = Pin<Box<dyn Stream<Item = Result<LedgerEvent, TonicStatus>> + Send>>;

#[tonic::async_trait]
impl Control for ControlService {
    async fn submit_proposal(
        &self,
        request: Request<ProposalRequest>,
    ) -> Result<Response<ProposalResponse>, TonicStatus> {
        let req = request.into_inner();

        // An unparseable event name is a client bug, not a proposal: there is
        // no FSM event to record a rejection against, so it fails at the edge.
        let event = Event::parse(&req.event.to_uppercase()).ok_or_else(|| {
            TonicStatus::invalid_argument(format!("unknown event {:?}", req.event))
        })?;

        // Origin is forced, never read from the request. A caller naming a
        // runtime-only event lands in the ledger as a PROPOSER attempt rejected
        // for ForgedOrigin, which is both the truth and the evidence.
        let outcome = self
            .handle
            .submit(&req.session_id, event, req.payload)
            .await
            .map_err(to_status)?;

        Ok(Response::new(proposal_response(
            &outcome,
            self.handle.limits().max_steps,
        )))
    }

    async fn get_state(
        &self,
        request: Request<StateRequest>,
    ) -> Result<Response<StateResponse>, TonicStatus> {
        let snap = self
            .handle
            .state(&request.into_inner().session_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(StateResponse {
            session_id: snap.session_id,
            state: snap.state.to_string(),
            steps: snap.steps,
            max_steps: snap.max_steps,
            consecutive_rejects: snap.consecutive_rejects,
            max_consecutive_rejects: snap.max_consecutive_rejects,
            events: snap.events,
            last_step_nanos: snap.last_step_nanos,
            mean_step_nanos: snap.mean_step_nanos,
            context_tokens: snap.context_tokens,
            max_context_tokens: snap.max_context_tokens,
        }))
    }

    type StreamLedgerStream = LedgerStream;

    async fn stream_ledger(
        &self,
        request: Request<LedgerRequest>,
    ) -> Result<Response<Self::StreamLedgerStream>, TonicStatus> {
        let req = request.into_inner();
        let filter = (!req.session_id.is_empty()).then_some(req.session_id);

        // Subscribe *before* reading the backlog. The other order leaves a
        // window in which an event commits after the read and before the
        // subscription, and is therefore never delivered at all.
        let mut live = self.handle.subscribe();
        let backlog = if req.from_start {
            self.handle
                .backlog(filter.as_deref())
                .await
                .map_err(to_status)?
        } else {
            Vec::new()
        };

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            let mut sent_through = 0u64;
            for record in backlog {
                sent_through = sent_through.max(record.seq);
                if tx.send(Ok(ledger_event(&record))).await.is_err() {
                    return;
                }
            }

            loop {
                match live.recv().await {
                    // Deduplicated against the backlog: an event committed
                    // between subscribing and reading appears in both.
                    Ok(record) if record.seq <= sent_through => continue,
                    Ok(record) => {
                        if let Some(id) = &filter {
                            if &record.session_id != id {
                                continue;
                            }
                        }
                        sent_through = record.seq;
                        if tx.send(Ok(ledger_event(&record))).await.is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Told explicitly rather than silently skipped: a
                        // subscriber that has missed events needs to know, so
                        // it can re-read the ledger, which is the durable copy.
                        let _ = tx
                            .send(Err(TonicStatus::data_loss(format!(
                                "subscriber fell behind; {n} events were dropped, \
                                 re-request with from_start"
                            ))))
                            .await;
                        return;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn trigger_replay(
        &self,
        request: Request<ReplayRequest>,
    ) -> Result<Response<ReplaySummary>, TonicStatus> {
        let req = request.into_inner();
        let filter = (!req.session_id.is_empty()).then_some(req.session_id);
        let summary = self
            .handle
            .replay(filter.as_deref())
            .await
            .map_err(to_status)?;

        Ok(Response::new(ReplaySummary {
            events: summary.events,
            faithful: summary.is_faithful(),
            head_hash: hex(&summary.head_hash),
            mismatches: summary
                .mismatches
                .into_iter()
                .map(|m| pb::Mismatch {
                    seq: m.seq,
                    session_id: m.session_id,
                    expected: m.expected,
                    recorded: m.recorded,
                })
                .collect(),
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, TonicStatus> {
        let snap = self.handle.health().await.map_err(to_status)?;
        Ok(Response::new(HealthResponse {
            version: snap.version,
            head_seq: snap.head_seq,
            head_hash: snap.head_hash,
            chain_verified: snap.chain_verified,
            tools: snap.tools,
            sessions: snap.sessions,
            uptime_secs: snap.uptime_secs,
        }))
    }
}

fn proposal_response(outcome: &Outcome, max_steps: u32) -> ProposalResponse {
    let (accepted, reject_reason) = match outcome.decision {
        Decision::Accept { .. } => (true, String::new()),
        Decision::Reject { reason } => (false, reason.to_string()),
    };

    ProposalResponse {
        seq: outcome.record.seq,
        accepted,
        reject_reason,
        state: outcome.final_state().to_string(),
        steps: outcome.session.steps,
        max_steps,
        halt_reason: outcome
            .halt
            .as_ref()
            .map(|(reason, _)| reason.as_str().to_string())
            .unwrap_or_default(),
        tool: outcome.tool.as_ref().map(|run| pb::ToolRun {
            tool_name: run.tool_name.clone(),
            ok: run.output.is_ok(),
            error: run
                .output
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default(),
            fuel_used: run.output.as_ref().map(|o| o.fuel_used).unwrap_or(0),
            elapsed_micros: run
                .output
                .as_ref()
                .map(|o| o.elapsed.as_micros() as u64)
                .unwrap_or(0),
            result_seq: run.result.record.seq,
        }),
    }
}

fn ledger_event(record: &Record) -> LedgerEvent {
    LedgerEvent {
        seq: record.seq,
        session_id: record.session_id.clone(),
        mono_ns: record.mono_ns,
        from_state: record.from_state.to_string(),
        event: record.event.to_string(),
        origin: record.origin.to_string(),
        payload: record.payload.clone(),
        status: record.status.as_str().to_string(),
        reject_reason: record.reason.map(|r| r.to_string()).unwrap_or_default(),
        to_state: record.to_state.to_string(),
        hash: hex(&record.hash),
    }
}

/// Map runtime errors onto gRPC codes.
///
/// A broken chain is `data_loss` rather than `internal`: the distinction tells
/// a caller whether to retry or to stop and call an operator, and retrying a
/// corrupt ledger is exactly the wrong move.
fn to_status(err: Error) -> TonicStatus {
    match err {
        Error::UnknownSession(id) => TonicStatus::not_found(format!("unknown session {id}")),
        Error::ChainBroken { .. } | Error::CorruptRow { .. } => {
            TonicStatus::data_loss(err.to_string())
        }
        Error::Config(_) | Error::KeyPermissions { .. } | Error::KeyLength { .. } => {
            TonicStatus::failed_precondition(err.to_string())
        }
        other => TonicStatus::internal(other.to_string()),
    }
}
