use super::*;
use crate::{GatewayAuthMethod, GatewayProfile, VerifiedPrincipal};
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use std::future::{Future, pending, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use xolotl_state::{Backend, InMemoryBackend, StateMutation, StateRead, StateResult, StateWrite};
use xolotl_types::{
    BlobRef, CompletionOrigin, DType, Failure, FloatBits, FrameKind, FrameRef, Outcome, TaintSet,
    TaintSource, TaintedValue, TensorRef,
};

struct Submission {
    profile: CompiledGatewayProfile,
    session: GatewaySession,
    submission: GatewaySubmission,
}

impl Submission {
    fn new() -> Result<Self> {
        Ok(Self {
            profile: CompiledGatewayProfile::compile(
                GatewayProfile::new("idempotency").with_revision(1),
            )?,
            session: GatewaySession {
                principal: VerifiedPrincipal {
                    principal_id: "client".into(),
                    credential_id: "client-key".into(),
                    credential_generation: 1,
                    principal_generation: 1,
                    auth_method: GatewayAuthMethod::Bearer,
                },
                identity_path: "process://client".into(),
                profile_name: "idempotency".into(),
                profile_rev: 1,
            },
            submission: GatewaySubmission::direct_input("echo", Value::string("hello".into())),
        })
    }

    async fn reserve(&self, state: &Backend) -> Result<SubmissionIdempotency, GatewayError> {
        reserve_submission_idempotency_if_present(
            state,
            &self.profile,
            &self.session,
            &self.submission,
            Some(("idempotency_key", "same-key".into())),
            42,
        )
        .await?
        .ok_or_else(|| GatewayError::Rejected("missing reservation".into()))
    }
}

fn reserved(result: SubmissionIdempotency) -> Result<Box<GatewayIdempotencyReservation>> {
    match result {
        SubmissionIdempotency::Reserved(reservation) => Ok(reservation),
        SubmissionIdempotency::Replay(_) => bail!("expected a new reservation"),
    }
}

fn accepted() -> GatewayAccepted {
    GatewayAccepted {
        submission_id: "accepted-once".into(),
        trace_root: "trace-once".into(),
        profile_rev: 1,
        surface_id: "echo".into(),
    }
}

#[tokio::test]
async fn released_owner_cannot_replace_reclaimed_or_committed_reservation() -> Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let submission = Submission::new()?;
    let previous = reserved(submission.reserve(&state).await?)?;
    release_submission_idempotency_reservation(&state, Some(&previous)).await?;
    ensure!(state.read(&previous.path).await?.is_none());
    let current = reserved(submission.reserve(&state).await?)?;
    ensure!(previous.path == current.path);
    ensure!(previous.pending_record != current.pending_record);
    ensure!(
        release_submission_idempotency_reservation(&state, Some(&previous))
            .await
            .is_err()
    );
    ensure!(state.read(&current.path).await? == Some(current.pending_record.clone()));

    let accepted = accepted();
    let output = ExecutionOutput::new(
        Outcome::Done(Value::string("hello".into())),
        TaintSet::author(),
    );
    commit_submission_idempotency_output(&state, Some(&current), &accepted, &output).await?;
    let committed = state
        .read(&current.path)
        .await?
        .context("committed record")?;
    ensure!(
        release_submission_idempotency_reservation(&state, Some(&previous))
            .await
            .is_err()
    );
    ensure!(
        release_submission_idempotency_reservation(&state, Some(&current))
            .await
            .is_err()
    );
    ensure!(state.read(&current.path).await? == Some(committed));
    match submission.reserve(&state).await? {
        SubmissionIdempotency::Replay(replayed) => {
            ensure!(replayed.accepted == accepted);
            ensure!(replayed.output == output);
            ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
        }
        SubmissionIdempotency::Reserved(_) => bail!("committed result was not replayed"),
    }
    Ok(())
}

struct PendingCasState {
    inner: InMemoryBackend,
    pause_next: AtomicBool,
}

impl StateRead for PendingCasState {
    type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.inner.read_tainted(path)
    }
}

impl StateWrite for PendingCasState {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let reserves = matches!(
                &mutation,
                StateMutation::CompareSet { value, .. }
                    if value.value.as_map().and_then(|map| map.get("state"))
                        .and_then(Value::as_str) == Some("pending")
            );
            let commit = self.inner.mutate(path, mutation).await?;
            if reserves && self.pause_next.swap(false, Ordering::AcqRel) {
                pending().await
            } else {
                Ok(commit)
            }
        })
    }
}

#[tokio::test]
async fn cancelled_reservation_cas_preserves_pending() -> Result<()> {
    let port = Arc::new(PendingCasState {
        inner: InMemoryBackend::new(),
        pause_next: AtomicBool::new(true),
    });
    let state = Backend::new().with_read(port.clone()).with_write(port);
    let submission = Submission::new()?;
    let mut reserving = Box::pin(submission.reserve(&state));
    ensure!(
        poll_fn(|cx| Poll::Ready(reserving.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(reserving);
    ensure!(matches!(
        submission.reserve(&state).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    Ok(())
}

#[tokio::test]
async fn record_with_wrong_fingerprint_is_not_replayed_or_removed() -> Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let submission = Submission::new()?;
    let reservation = reserved(submission.reserve(&state).await?)?;
    let Some(mut mismatched) = reservation.pending_record.clone().into_map() else {
        bail!("pending record was not a map");
    };
    mismatched.insert("principal_id".into(), Value::string("other-client".into()))?;
    let mismatched = Value::from(mismatched);
    state
        .write_set(&reservation.path, mismatched.clone())
        .await?;
    ensure!(matches!(
        submission.reserve(&state).await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(
        release_submission_idempotency_reservation(&state, Some(&reservation))
            .await
            .is_err()
    );
    ensure!(state.read(&reservation.path).await? == Some(mismatched));
    Ok(())
}

#[tokio::test]
async fn retained_results_preserve_typed_values_failures_and_protected_provenance() -> Result<()> {
    let blob = BlobRef {
        hash: "0123456789abcdef".repeat(4),
        size: 16,
        mime: Some("application/octet-stream".into()),
    };
    let mut items = vec![
        Value::blob(blob.clone()),
        Value::from(TensorRef {
            blob: blob.clone(),
            dtype: DType::F32,
            shape: vec![2, 2],
        }),
        Value::from(FrameRef {
            blob,
            ts_nanos: 123_456,
            kind: FrameKind::Sensor,
        }),
        Value::bytes(vec![0, 1, 255]),
    ];
    items.extend(
        [
            0,
            0x8000_0000_0000_0000,
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            0x7ff8_1234_5678_9abc,
        ]
        .into_iter()
        .map(|bits| Value::float(FloatBits(f64::from_bits(bits)))),
    );
    let value = Value::map(BTreeMap::from([("nested".into(), Value::list(items))]));
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/retained-result")?,
    });
    for outcome in [
        Outcome::Done(value.clone()),
        Outcome::Short(value),
        Outcome::Done(Value::null()),
        Outcome::Fail(Failure::HandlerError {
            kind: "protected-driver".into(),
            message: "retained diagnostic".into(),
        }),
    ] {
        let port = Arc::new(InMemoryBackend::new());
        let state = Backend::new()
            .with_read(port.clone())
            .with_write(port.clone());
        let submission = Submission::new()?;
        let reservation = reserved(submission.reserve(&state).await?)?;
        let accepted = accepted();
        let output = ExecutionOutput::new(outcome, taint.clone());
        commit_submission_idempotency_output(&state, Some(&reservation), &accepted, &output)
            .await?;
        let retained = state
            .read_tainted(&reservation.path)
            .await?
            .context("missing retained result")?;
        ensure!(
            retained.taint == output.taint,
            "State lost result provenance"
        );
        let restored: TaintedValue = serde_json::from_slice(&serde_json::to_vec(&retained)?)?;
        ensure!(restored == retained, "retained result was not lossless");
        state
            .write_set_tainted(&reservation.path, restored.value, restored.taint)
            .await?;
        // The CAS observation supplies both the retained value and its sources;
        // replay must work without a separate read capability or a second view.
        let comparison_only = Backend::new().with_write(port);
        let SubmissionIdempotency::Replay(replayed) = submission.reserve(&comparison_only).await?
        else {
            bail!("retained result was executed again");
        };
        ensure!(replayed.accepted == accepted);
        ensure!(replayed.output == output);
        ensure!(replayed.origin == CompletionOrigin::CachedOutcome);

        let mut missing_taint = serde_json::to_value(&retained)?;
        missing_taint
            .as_object_mut()
            .context("invalid envelope")?
            .remove("taint");
        ensure!(serde_json::from_value::<TaintedValue>(missing_taint).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn old_and_malformed_committed_records_are_rejected_without_release() -> Result<()> {
    for corruption in [
        "unsupported_schema",
        "missing_schema",
        "missing_value",
        "invalid_status",
        "missing_failure",
        "invalid_failure",
        "missing_acceptance",
        "wrong_surface",
        "wrong_revision",
    ] {
        let state = InMemoryBackend::new().into_backend();
        let submission = Submission::new()?;
        let reservation = reserved(submission.reserve(&state).await?)?;
        let output =
            ExecutionOutput::new(Outcome::Done(Value::from("retained")), TaintSet::author());
        commit_submission_idempotency_output(&state, Some(&reservation), &accepted(), &output)
            .await?;
        let retained = state
            .read_tainted(&reservation.path)
            .await?
            .context("missing record")?;
        let Some(mut map) = retained.value.into_map() else {
            bail!("committed record was not a map");
        };
        match corruption {
            "unsupported_schema" => {
                map.insert("schema".into(), Value::from("gateway-idempotency-v99"))?;
            }
            "missing_schema" => {
                map.remove("schema");
            }
            "missing_value" => {
                map.remove("outcome_value");
            }
            "invalid_status" => {
                map.insert("outcome_status".into(), Value::from("unknown"))?;
            }
            "missing_failure" | "invalid_failure" => {
                map.insert("outcome_status".into(), Value::from("fail"))?;
                map.remove("outcome_value");
                if corruption == "invalid_failure" {
                    map.insert("failure_json".into(), Value::from("not a failure"))?;
                }
            }
            "missing_acceptance" => {
                map.remove("accepted_trace_root");
            }
            "wrong_surface" => {
                map.insert(
                    "accepted_surface_id".into(),
                    Value::from("different-surface"),
                )?;
            }
            "wrong_revision" => {
                map.insert("accepted_profile_rev".into(), Value::integer(2))?;
            }
            _ => bail!("unknown corruption case"),
        }
        let corrupted = TaintedValue::new(Value::from(map), retained.taint);
        state
            .write_set_tainted(
                &reservation.path,
                corrupted.value.clone(),
                corrupted.taint.clone(),
            )
            .await?;
        ensure!(
            matches!(
                submission.reserve(&state).await,
                Err(GatewayError::Rejected(_))
            ),
            "{corruption}"
        );
        ensure!(
            state.read_tainted(&reservation.path).await? == Some(corrupted),
            "{corruption}"
        );
        ensure!(
            release_submission_idempotency_reservation(&state, Some(&reservation))
                .await
                .is_err(),
            "{corruption}"
        );
    }
    Ok(())
}

#[test]
fn equal_payloads_ignore_allocation_sharing_in_submission_fingerprints() -> Result<()> {
    let leaf = Value::list(vec![Value::from("same"), Value::integer(42)]);
    let shared = Value::list(vec![leaf.clone(), leaf]);
    let duplicated = Value::list(vec![
        Value::list(vec![Value::from("same"), Value::integer(42)]),
        Value::list(vec![Value::from("same"), Value::integer(42)]),
    ]);
    ensure!(shared == duplicated);
    let first = GatewaySubmission::direct_input("echo", shared);
    let second = GatewaySubmission::direct_input("echo", duplicated);
    let first_hash = submission_hash(&first)?;
    let second_hash = submission_hash(&second)?;
    ensure!(first_hash == second_hash);
    let fixture = Submission::new()?;
    ensure!(
        effective_idempotency_hash(
            &fixture.profile,
            &fixture.session,
            &first,
            &first_hash,
            "idempotency_key",
            "same-key"
        ) == effective_idempotency_hash(
            &fixture.profile,
            &fixture.session,
            &second,
            &second_hash,
            "idempotency_key",
            "same-key"
        )
    );
    Ok(())
}
