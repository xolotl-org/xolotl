//! Structured output is a delivery projection, with explicit source admission.

use super::*;
use crate::{
    GatewayAccepted, GatewayExternalizedOutput, GatewayOutputDisclosurePolicy,
    GatewayOutputDisclosureRequest, GatewayOutputEvent, GatewayOutputKind,
    GatewayOutputObjectOptions, GatewaySubmitResult,
};
use parking_lot::Mutex;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use xolotl_state::object::{ObjectMetadata, ObjectRead, ObjectReadChunk};
use xolotl_state::{StateResult, StateScan};
use xolotl_types::{
    BlobRef, CompletionOrigin, DType, ExecutionOutput, Failure, FloatBits, FrameKind, Path,
    TaintedValue, value::event::MaterializationLimits,
};
use xolotl_value_codec::validation::{MemoryKeyOptions, MemoryKeyStore};
use xolotl_value_object::{encode_value, read_value};

mod adapter;
mod stream;

fn keys() -> MemoryKeyStore {
    MemoryKeyStore::new(MemoryKeyOptions {
        page_bytes: NonZeroUsize::MIN.saturating_add(126),
        max_keys: None,
        max_bytes: None,
    })
}

fn options() -> GatewayOutputObjectOptions {
    GatewayOutputObjectOptions {
        max_frames: None,
        expires_in_ms: Some(60_000),
    }
}

fn accepted() -> GatewayAccepted {
    GatewayAccepted {
        submission_id: "host-completed-result".into(),
        trace_root: "host-completed-trace".into(),
        profile_rev: 1,
        surface_id: "echo".into(),
    }
}

fn completion(outcome: Outcome, taint: TaintSet, origin: CompletionOrigin) -> GatewaySubmitResult {
    GatewaySubmitResult {
        accepted: accepted(),
        output: ExecutionOutput::new(outcome, taint),
        origin,
    }
}

#[derive(Default)]
struct RecordingPolicy {
    observed: Mutex<Vec<(GatewayOutputKind, ObjectMetadata)>>,
    proposed_expiries: Mutex<Vec<i64>>,
    reject_protected: bool,
    gate: Option<Arc<ports::Gate>>,
}

#[async_trait::async_trait]
impl GatewayOutputDisclosurePolicy for RecordingPolicy {
    async fn authorize(
        &self,
        request: GatewayOutputDisclosureRequest<'_>,
    ) -> Result<(), GatewayError> {
        self.observed
            .lock()
            .push((request.kind(), request.metadata.clone()));
        self.proposed_expiries.lock().push(request.expires_at_ms);
        if let Some(gate) = &self.gate {
            gate.enter()
                .await
                .map_err(super::super::object_store_error)?;
        }
        if self.reject_protected && request.metadata.taint.has_protected() {
            return Err(GatewayError::Unauthorized(
                request.session.principal().principal_id().into(),
            ));
        }
        Ok(())
    }
}

async fn grant_count(fixture: &Fixture) -> anyhow::Result<usize> {
    let mut pages = fixture.boot.kernel.state.pages(StateScan::new(Path::parse(
        "state://gateway/object-read-grant",
    )?));
    let mut count = 0;
    while let Some(page) = pages.next().await? {
        count += page.entries.len();
    }
    Ok(count)
}

async fn decode(
    fixture: &Fixture,
    output: &GatewayExternalizedOutput,
) -> anyhow::Result<TaintedValue> {
    let mut input = [0; 131];
    Ok(read_value(
        &fixture.files,
        output.reference(),
        &mut input,
        keys(),
        TaintSet::pristine(),
        MaterializationLimits::default(),
    )
    .await?)
}

fn every_failure() -> anyhow::Result<Vec<Failure>> {
    Ok(vec![
        Failure::PermissionDenied {
            required: vec![
                "perform://effect/private/read".into(),
                "required".repeat(1024),
            ],
            actual: vec!["actual-label".repeat(1024)],
        },
        Failure::NoHandler {
            path: Path::parse("effect://missing/provider")?,
        },
        Failure::BudgetExhausted {
            dim: "tokens_out".into(),
        },
        Failure::RateLimited,
        Failure::ApprovalPending {
            approval_key: "state://approval/pending-key".into(),
            reason: "reviewed later".into(),
        },
        Failure::Timeout,
        Failure::Cancelled,
        Failure::Quarantined {
            op_id: "1/2/3/4/5".into(),
            reason: "uncertain publication".into(),
        },
        Failure::InvalidInput {
            reason: "invalid shape".into(),
        },
        Failure::HandlerError {
            kind: "backend_class".into(),
            message: "backend detail".into(),
        },
        Failure::KernelNamespaceProtected,
        Failure::PolicyViolation {
            policy: "egress".into(),
            detail: "protected source".into(),
        },
        Failure::PathInvalid {
            path: Path::parse("state://")?,
            reason: "empty state path".into(),
        },
        Failure::Custom {
            kind: "custom_extension".into(),
            message: "extension detail".into(),
        },
    ])
}

#[tokio::test]
async fn output_objects_preserve_typed_outcomes_origins_and_nested_descriptors()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let nested = fixture
        .seed(
            b"nested protected bytes",
            "application/octet-stream",
            TaintSet::pristine(),
        )
        .await?
        .blob;
    let value = Value::list(vec![
        Value::bytes(vec![42; 48 * 1024]),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0042))),
        Value::tensor(nested.clone(), DType::I64, vec![u64::MAX, 0]),
        Value::frame(nested.clone(), i64::MIN, FrameKind::Sensor),
    ]);
    let source = TaintSet::of(TaintSource::ModelOutput);
    let policy = RecordingPolicy::default();
    for (outcome, kind, origin) in [
        (
            Outcome::Done(value.clone()),
            GatewayOutputKind::Done,
            CompletionOrigin::CurrentAttempt,
        ),
        (
            Outcome::Short(value.clone()),
            GatewayOutputKind::Short,
            CompletionOrigin::CachedOutcome,
        ),
    ] {
        let original = completion(outcome, source.clone(), origin);
        let mut scratch = [0; 257];
        let object = fixture
            .gateway
            .externalize_output_event(
                &fixture.session,
                &original.accepted,
                GatewayOutputEvent::Complete(original.clone()),
                &mut scratch,
                keys(),
                options(),
                &policy,
            )
            .await?;
        object.validate()?;
        ensure!(object.kind() == kind && object.origin() == Some(origin));
        let GatewayOutputEvent::Complete(retained) = object.original_event() else {
            bail!("completion changed into a chunk")
        };
        ensure!(retained == &original);
        let decoded = decode(&fixture, &object).await?;
        ensure!(decoded.value == value && decoded.taint.contains_all(&source));
        ensure!(object.reference().blob == object.grant().metadata().blob);
        ensure!(
            object.grant().offset() == 0 && object.grant().length() == object.reference().blob.size
        );
        ensure!(
            fixture
                .gateway
                .open_object_read(
                    &fixture.session,
                    crate::OpenObjectReadRequest {
                        grant_id: nested.hash.clone(),
                        offset: 0,
                        length: None,
                    }
                )
                .await
                .is_err()
        );
    }
    ensure!(
        grant_count(&fixture).await? == 2,
        "nested references received an extra grant"
    );

    for failure in every_failure()? {
        let original = completion(
            Outcome::Fail(failure.clone()),
            source.clone(),
            CompletionOrigin::CachedOutcome,
        );
        let mut scratch = [0; 257];
        let object = fixture
            .gateway
            .externalize_output_event(
                &fixture.session,
                &original.accepted,
                GatewayOutputEvent::Complete(original.clone()),
                &mut scratch,
                keys(),
                options(),
                &policy,
            )
            .await?;
        ensure!(
            object.kind() == GatewayOutputKind::Fail
                && object.origin() == Some(CompletionOrigin::CachedOutcome)
        );
        let GatewayOutputEvent::Complete(retained) = object.original_event() else {
            bail!("failure changed into a chunk")
        };
        ensure!(retained == &original);
        let decoded = decode(&fixture, &object).await?;
        let restored: Failure = serde_json::from_value(serde_json::to_value(&decoded.value)?)?;
        ensure!(restored == failure, "external failure lost typed fields");
        ensure!(decoded.taint.contains_all(&source));
    }
    ensure!(grant_count(&fixture).await? == 16);
    ensure!(policy.observed.lock().len() == 16);
    Ok(())
}

type Request<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

struct LateMetadata {
    files: FileObjectStore,
    source: TaintSet,
}

impl ObjectRead for LateMetadata {
    type Metadata<'a> = Request<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = Request<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        Box::pin(async move {
            let mut metadata = self.files.metadata(blob).await?;
            if let Some(metadata) = &mut metadata {
                metadata.taint.union(&self.source);
            }
            Ok(metadata)
        })
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        bytes: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        self.files.read_chunk(blob, offset, bytes)
    }
}

#[tokio::test]
async fn disclosure_considers_deduplicated_and_post_commit_canonical_sources() -> anyhow::Result<()>
{
    for late_metadata in [false, true] {
        let mut fixture = Fixture::new().await?;
        let source = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://private/shared-output")?,
        });
        let value = TaintedValue::new(Value::from("same encoding bytes"), TaintSet::author());
        let mut scratch = [0; 257];
        let prior = encode_value(&fixture.files, &mut scratch, keys(), None, &value).await?;
        if late_metadata {
            fixture.gateway.objects = ObjectStore::new()
                .with_read(Arc::new(LateMetadata {
                    files: fixture.files.clone(),
                    source: source.clone(),
                }))
                .with_write(Arc::new(fixture.files.clone()));
        } else {
            let bytes = std::fs::read(
                fixture
                    .files
                    .root()
                    .join("objects")
                    .join(&prior.reference.blob.hash)
                    .join("data"),
            )?;
            let stored = fixture
                .seed(
                    &bytes,
                    prior
                        .reference
                        .blob
                        .mime
                        .as_deref()
                        .context("encoding media type")?,
                    source.clone(),
                )
                .await?;
            ensure!(stored.blob == prior.reference.blob);
        }
        let original = completion(
            Outcome::Done(value.value),
            value.taint,
            CompletionOrigin::CurrentAttempt,
        );
        let policy = RecordingPolicy {
            reject_protected: true,
            ..RecordingPolicy::default()
        };
        let failure = match fixture
            .gateway
            .externalize_output_event(
                &fixture.session,
                &original.accepted,
                GatewayOutputEvent::Complete(original.clone()),
                &mut scratch,
                keys(),
                options(),
                &policy,
            )
            .await
        {
            Ok(_) => bail!("protected canonical sources were disclosed"),
            Err(failure) => failure,
        };
        ensure!(failure.taint.contains_all(&source));
        {
            let observed = policy.observed.lock();
            ensure!(observed.len() == 1 && observed[0].1.taint.contains_all(&source));
            ensure!(observed[0].1.blob == prior.reference.blob);
        }
        ensure!(grant_count(&fixture).await? == 0);
        ensure!(
            fixture
                .files
                .metadata(&prior.reference.blob)
                .await?
                .is_some(),
            "denied export deleted committed shared content"
        );
    }
    Ok(())
}

#[tokio::test]
async fn authority_changes_during_policy_wait_reject_before_grant_commit() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let gate = ports::Gate::new();
    let policy = RecordingPolicy {
        gate: Some(gate.clone()),
        ..RecordingPolicy::default()
    };
    let original = completion(
        Outcome::Done(Value::integer(7)),
        TaintSet::author(),
        CompletionOrigin::CurrentAttempt,
    );
    let mut scratch = [0; 97];
    let mut pending = Box::pin(fixture.gateway.externalize_output_event(
        &fixture.session,
        &original.accepted,
        GatewayOutputEvent::Complete(original.clone()),
        &mut scratch,
        keys(),
        options(),
        &policy,
    ));
    tokio::select! {
        result = &mut pending => bail!("disclosure unexpectedly completed: {:?}", result.map(|_| ())),
        entered = gate.wait() => entered?,
    }
    fixture.gateway.replace_profile(
        echo_profile(xolotl_types::ResourceName::new(Path::parse(
            "effect://echo/say",
        )?))?
        .with_revision(fixture.session.profile_rev() + 1),
    )?;
    gate.release();
    let failure = match pending.await {
        Ok(_) => bail!("changed audience received a grant"),
        Err(failure) => failure,
    };
    ensure!(failure.taint.contains_all(&original.output.taint));
    ensure!(grant_count(&fixture).await? == 0);
    let blob = policy.observed.lock()[0].1.blob.clone();
    ensure!(fixture.files.metadata(&blob).await?.is_some());
    Ok(())
}
