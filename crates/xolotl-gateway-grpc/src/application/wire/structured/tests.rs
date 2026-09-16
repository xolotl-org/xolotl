use super::*;
use anyhow::{Context, ensure};
use std::{convert::Infallible, num::NonZeroUsize, sync::Arc};
use xolotl_gateway::{
    Gateway, GatewayOutputDisclosurePolicy, GatewayOutputDisclosureRequest,
    GatewayOutputObjectOptions, GatewayPrincipalSurfaceBinding, GatewayProfile, GatewayRuntime,
    GatewaySurface, PresentedCredential,
};
use xolotl_kernel::{Bootstrap, EchoDriver, MethodSpec};
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{ExecutionOutput, Failure, Purity};
use xolotl_value_codec::validation::{MemoryKeyOptions, MemoryKeyStore};

struct Permit;
#[tonic::async_trait]
impl GatewayOutputDisclosurePolicy for Permit {
    async fn authorize(
        &self,
        _request: GatewayOutputDisclosureRequest<'_>,
    ) -> Result<(), xolotl_gateway::GatewayError> {
        Ok(())
    }
}

#[tokio::test]
async fn exact_object_frames_preserve_each_gateway_outcome_kind() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let boot = Arc::new(Bootstrap::in_memory());
    let target = boot.register_effect(
        "effect://output/test",
        &[MethodSpec::unary_async("invoke", Purity::Pure)],
        Arc::new(EchoDriver),
    )?;
    let profile = GatewayProfile::new("output")
        .with_bearer_identity(
            "token",
            "alice",
            "structured-wire-test-token",
            "process://alice",
        )?
        .with_surface(GatewaySurface::effect_invoke("test", target))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["test"],
            ["perform://effect/output/test"],
        ));
    let runtime = Arc::new(
        GatewayRuntime::new(boot, profile)?
            .with_object_store(FileObjectStore::open(directory.path())?.into_object_store()),
    );
    let session = runtime
        .authenticate(PresentedCredential::bearer("structured-wire-test-token"))
        .await?;
    let accepted = GatewayAccepted {
        submission_id: "completed".into(),
        trace_root: "trace".into(),
        profile_rev: 1,
        surface_id: "test".into(),
    };
    let encoder = runtime.output_externalizer(
        NonZeroUsize::MIN.saturating_add(96),
        GatewayOutputObjectOptions::default(),
        || {
            std::future::ready(Ok::<_, Infallible>(MemoryKeyStore::new(MemoryKeyOptions {
                page_bytes: NonZeroUsize::MIN.saturating_add(126),
                max_keys: None,
                max_bytes: None,
            })))
        },
        Permit,
    );
    for (outcome, expected) in [
        (
            Outcome::Done(Value::bytes(vec![7; 4096])),
            GatewayOutputKind::Done,
        ),
        (
            Outcome::Short(Value::bytes(vec![7; 4096])),
            GatewayOutputKind::Short,
        ),
        (
            Outcome::Fail(Failure::InvalidInput {
                reason: "diagnostic".repeat(4096),
            }),
            GatewayOutputKind::Fail,
        ),
    ] {
        let result = GatewaySubmitResult {
            accepted: accepted.clone(),
            output: ExecutionOutput::new(outcome, TaintSet::of(TaintSource::ModelOutput)),
            origin: CompletionOrigin::CachedOutcome,
        };
        let output = encoder
            .clone()
            .externalize(
                session.clone(),
                accepted.clone(),
                GatewayOutputEvent::Complete(result),
            )
            .await?;
        let frame = event_to_pb(&output, 4096)?;
        let size = frame.encoded_len();
        ensure!(event_to_pb(&output, size)? == frame);
        ensure!(event_to_pb(&output, size - 1).is_err());
        let decoded = pb::SubmitOutputResponse::decode(frame.encode_to_vec().as_slice())?;
        let Some(pb::submit_output_response::Event::Completed(completed)) = decoded.event else {
            anyhow::bail!("completion missing")
        };
        ensure!(completed.origin == pb::CompletionOrigin::CachedOutcome as i32);
        let (kind, reference) = match completed
            .outcome
            .context("outcome missing")?
            .kind
            .context("kind missing")?
        {
            pb::output_outcome::Kind::Done(value) => (GatewayOutputKind::Done, value.content),
            pb::output_outcome::Kind::Short(value) => (GatewayOutputKind::Short, value.content),
            pb::output_outcome::Kind::Fail(value) => {
                let Some(pb::output_failure::Content::Object(reference)) = value.content else {
                    anyhow::bail!("failure object missing")
                };
                (
                    GatewayOutputKind::Fail,
                    Some(pb::output_value::Content::Object(reference)),
                )
            }
        };
        ensure!(kind == expected);
        let Some(pb::output_value::Content::Object(reference)) = reference else {
            anyhow::bail!("reference missing")
        };
        ensure!(reference.read_grant_id == output.grant().grant_id());
        ensure!(reference.blob.context("blob missing")?.size == output.reference().blob.size);
        ensure!(completed.taint.context("taint missing")?.sources.len() == 1);
        let unary = submit_to_pb(&output, 4096)?;
        let size = unary.encoded_len();
        ensure!(submit_to_pb(&output, size)? == unary);
        ensure!(submit_to_pb(&output, size - 1).is_err());
    }
    Ok(())
}
