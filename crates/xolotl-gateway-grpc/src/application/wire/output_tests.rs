use super::*;
use anyhow::{Context as _, Result, ensure};
use xolotl_types::ExecutionOutput;

fn completion(origin: CompletionOrigin, taint: TaintSet) -> GatewayOutputEvent {
    GatewayOutputEvent::Complete(GatewaySubmitResult {
        accepted: GatewayAccepted {
            submission_id: "submission".into(),
            trace_root: "trace".into(),
            profile_rev: 1,
            surface_id: "generate".into(),
        },
        output: ExecutionOutput::new(Outcome::Done(Value::null()), taint),
        origin,
    })
}

#[test]
fn output_rpc_requires_explicit_stream_before_submission() -> Result<()> {
    for mode in [
        None,
        Some(OutputMode::Unary),
        Some(OutputMode::Collect { limit: 4 }),
        Some(OutputMode::AsyncProcess),
        Some(OutputMode::SinkOnly),
        Some(OutputMode::Stream),
    ] {
        let request = pb::SubmitRequest {
            surface_id: "generate".into(),
            payload: Some(common::Value::default()),
            output: mode.map(xolotl_proto::output_mode_to_pb),
            ..Default::default()
        };
        let decoded = output_submission_from_pb(request);
        if mode == Some(OutputMode::Stream) {
            ensure!(decoded?.requested_output() == OutputMode::Stream);
        } else {
            ensure!(
                matches!(decoded, Err(status) if status.code() == tonic::Code::InvalidArgument)
            );
        }
    }
    Ok(())
}

#[test]
fn unary_and_stream_completion_share_required_lineage_and_cache_origin() -> Result<()> {
    for origin in [
        CompletionOrigin::CurrentAttempt,
        CompletionOrigin::CachedOutcome,
    ] {
        for taint in [TaintSet::pristine(), TaintSet::of(TaintSource::ModelOutput)] {
            let response = output_event_to_pb(&completion(origin, taint.clone()), 1024)?;
            let decoded = pb::SubmitOutputResponse::decode(response.encode_to_vec().as_slice())?;
            let Some(pb::submit_output_response::Event::Completed(done)) = decoded.event else {
                anyhow::bail!("completion event missing");
            };
            let GatewayOutputEvent::Complete(result) = completion(origin, taint.clone()) else {
                anyhow::bail!("missing submission result");
            };
            let unary = submit_response_to_pb(&result, 1024)?;
            ensure!(unary.completion.as_ref() == Some(&done));
            ensure!(
                done.origin
                    == match origin {
                        CompletionOrigin::CurrentAttempt =>
                            pb::CompletionOrigin::CurrentAttempt as i32,
                        CompletionOrigin::CachedOutcome =>
                            pb::CompletionOrigin::CachedOutcome as i32,
                    }
            );
            ensure!(done.taint.context("lineage missing")?.sources.len() == taint.sources().len());
        }
    }
    Ok(())
}

#[test]
fn output_lineage_is_typed_and_all_labels_share_the_frame_budget() -> Result<()> {
    use common::taint_source::Kind;
    let path = Path::parse("state://vault/session/value")?;
    let mut taint = TaintSet::author();
    taint.add(TaintSource::ModelOutput);
    taint.add(TaintSource::Inbound {
        source: "gateway/tasks".into(),
        channel: "submit".into(),
    });
    taint.add(TaintSource::Fetched {
        host: "provider.example".into(),
    });
    taint.add(TaintSource::Protected { path: path.clone() });
    let encoded = output_event_to_pb(&completion(CompletionOrigin::CurrentAttempt, taint), 1024)?;
    let response = pb::SubmitOutputResponse::decode(encoded.encode_to_vec().as_slice())?;
    let Some(pb::submit_output_response::Event::Completed(done)) = response.event else {
        anyhow::bail!("completion event missing");
    };
    let sources = done.taint.context("lineage missing")?.sources;
    ensure!(sources.len() == 5);
    ensure!(matches!(&sources[0].kind, Some(Kind::AuthorConstant(_))));
    ensure!(matches!(&sources[1].kind, Some(Kind::ModelOutput(_))));
    ensure!(
        matches!(&sources[2].kind, Some(Kind::Inbound(source)) if source.source == "gateway/tasks" && source.channel == "submit")
    );
    ensure!(
        matches!(&sources[3].kind, Some(Kind::FetchedHost(host)) if host == "provider.example")
    );
    let Some(Kind::ProtectedPath(encoded_path)) = &sources[4].kind else {
        anyhow::bail!("protected path missing");
    };
    ensure!(xolotl_proto::path_from_pb(encoded_path)? == path);

    let taint = TaintSet::of(TaintSource::Fetched {
        host: "x".repeat(1024).into(),
    });
    ensure!(matches!(
        output_event_to_pb(&completion(CompletionOrigin::CurrentAttempt, taint), 256),
        Err(status) if status.code() == tonic::Code::ResourceExhausted
    ));
    Ok(())
}
