use std::{hint::black_box, io::Write as _, num::NonZeroUsize, sync::Arc, time::Instant};

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    CallInspection, CallMethod, CallPath, CallPrepared, CallRef, CallStatus, CallTarget, Digest,
    ExportName, FederationNodeId, FederationOutboundCallStore, FederationSubject,
    MAX_OUTBOUND_RESULT_BYTES, MemoryFederationOutboundCallStore, OutboundCallIntent, RequestId,
};

const ITERATIONS: usize = 500;
const SAMPLES: usize = 5;

#[derive(Clone, Copy)]
enum Query {
    Unsettled,
    Cancellation,
    EmptyAfter,
}

impl Query {
    fn name(self) -> &'static str {
        match self {
            Self::Unsettled => "unsettled",
            Self::Cancellation => "cancellation",
            Self::EmptyAfter => "empty_after",
        }
    }

    fn read(
        self,
        source: &MemoryFederationOutboundCallStore,
        tail: RequestId,
    ) -> Result<Vec<xolotl_federation::OutboundCallRecord>> {
        Ok(match self {
            Self::Unsettled => source.unsettled_outbound(None, 32)?,
            Self::Cancellation => source.pending_outbound_cancellations(None, 32)?,
            Self::EmptyAfter => source.unsettled_outbound(Some(tail), 32)?,
        })
    }
}

fn run(history: usize, output: &mut impl std::io::Write) -> Result<()> {
    let local = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let source = MemoryFederationOutboundCallStore::new(
        local,
        NonZeroUsize::new(MAX_OUTBOUND_RESULT_BYTES).context("source payload budget")?,
    );
    let target = CallTarget {
        export: ExportName::new("tools")?,
        path: CallPath::new("/echo")?,
        method: CallMethod::new("echo")?,
        contract_digest: [3; 32],
    };
    let setup = Instant::now();
    let input: Arc<[u8]> = Arc::from([]);
    let digest = Digest::from_bytes(Sha384::digest(&input).into());
    for index in 0..=history {
        let request_id = RequestId::from_bytes((index as u128 + 1).to_be_bytes());
        source.stage_outbound(
            OutboundCallIntent {
                target_node: peer,
                request: xolotl_federation::PrepareCallRequest {
                    authenticated_origin: local,
                    subject: FederationSubject::Node(local),
                    origin_request_id: request_id,
                    target: target.clone(),
                    input_digest: digest,
                    input_bytes: 0,
                    prepare_deadline_ms: 200,
                    execution_deadline_ms: 800,
                    result_retention_ms: 300,
                },
                input: Arc::clone(&input),
            },
            100,
        )?;
        if index == history {
            continue;
        }
        let mut call_id = [4; 32];
        call_id[..16].copy_from_slice(request_id.as_bytes());
        let prepared = CallPrepared {
            origin_request_id: request_id,
            call: CallRef::new(peer, call_id)?,
            status: CallStatus::Closed,
            reserved_until_ms: 200,
            execution_deadline_ms: 800,
            result_retention_ms: 300,
            authority_revision: 1,
            control_revision: 1,
        };
        source.bind_outbound_prepared(request_id, prepared.clone())?;
        source.settle_outbound(
            request_id,
            CallInspection {
                call: prepared.call,
                status: CallStatus::Closed,
                control_revision: 1,
                authority_revision: 1,
                reserved_until_ms: 200,
                execution_deadline_ms: 800,
                result_retained_until_ms: 0,
                result: None,
                unresolved_effect_ids: Vec::new(),
                cancellation_requested: false,
                kernel_cancel_accepted: false,
                execution_stopped: true,
            },
        )?;
    }
    let tail = RequestId::from_bytes((history as u128 + 1).to_be_bytes());
    let operation = "1/2/3/4/5".parse()?;
    source.bind_outbound_origin(tail, operation, Digest::from_bytes([5; 48]))?;
    ensure!(source.stage_outbound_cancellation(operation)? == Some(tail));
    let setup_us = setup.elapsed().as_micros();
    for query in [Query::Unsettled, Query::Cancellation, Query::EmptyAfter] {
        let observed = query.read(&source, tail)?;
        if matches!(query, Query::EmptyAfter) {
            ensure!(observed.is_empty());
        } else {
            ensure!(observed.len() == 1 && observed[0].intent.request_id() == tail);
        }
        for _ in 0..100 {
            black_box(query.read(&source, tail)?);
        }
        let mut samples = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let started = Instant::now();
            for _ in 0..ITERATIONS {
                black_box(query.read(&source, tail)?);
            }
            samples.push(started.elapsed().as_nanos() / ITERATIONS as u128);
        }
        samples.sort_unstable();
        writeln!(
            output,
            "{history},{setup_us},{},{SAMPLES},{ITERATIONS},{},{},{}",
            query.name(),
            samples[SAMPLES / 2],
            samples[0],
            samples[SAMPLES - 1]
        )?;
    }
    if history > 0 {
        ensure!(
            source
                .outbound_call(RequestId::from_bytes(1_u128.to_be_bytes()))?
                .terminal
                .is_some()
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "history,setup_us,query,samples,iterations,median_ns_per_page,min_ns_per_page,max_ns_per_page"
    )?;
    for history in [0, 1024, 8192, 32768] {
        run(history, &mut output)?;
    }
    Ok(())
}
