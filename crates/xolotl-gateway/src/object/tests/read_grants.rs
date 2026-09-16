use super::ports::{Gate, ProbeStore};
use super::*;
use crate::object::read_grant::{ReadAuthorization, read_grant_path, record};
use crate::{
    ClientCertificateDerSha256, GatewayCredential, GatewayIdentityMapping,
    GatewayPrincipalSurfaceBinding, GatewayProfile, GatewaySurface, OpenObjectReadRequest,
};
use std::future::Future;
use std::pin::Pin;
use xolotl_kernel::{FactSink, Kernel};
use xolotl_state::object::ObjectRead;
use xolotl_state::{Backend, InMemoryBackend, StateMutation, StateRead, StateResult, StateWrite};
use xolotl_types::{BlobRef, DType, FrameKind, Path, ResourceName, TaintedValue};

mod read_audience;

fn request(object: TaintedValue) -> IssueObjectReadGrantRequest {
    IssueObjectReadGrantRequest {
        surface_id: "echo".into(),
        object,
        offset: 0,
        length: None,
        expires_in_ms: Some(60_000),
    }
}

fn open(grant: &GatewayObjectReadGrant) -> OpenObjectReadRequest {
    OpenObjectReadRequest {
        grant_id: grant.grant_id().into(),
        offset: grant.offset(),
        length: Some(grant.length()),
    }
}

async fn stored(fixture: &Fixture, grant: &GatewayObjectReadGrant) -> anyhow::Result<TaintedValue> {
    fixture
        .boot
        .kernel
        .state
        .read_tainted(&read_grant_path(grant.grant_id())?)
        .await?
        .context("missing read grant")
}

#[tokio::test]
async fn direct_object_exports_preserve_typed_identity_and_sources_in_state() -> anyhow::Result<()>
{
    let fixture = Fixture::new().await?;
    let object_taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://private/artifact")?,
    });
    let selected_taint = TaintSet::of(TaintSource::ModelOutput);
    let metadata = fixture
        .seed(
            b"eight123",
            "application/octet-stream",
            object_taint.clone(),
        )
        .await?;
    let expected_taint = object_taint.merged(&selected_taint);
    for item in [
        Value::blob(metadata.blob.clone()),
        Value::tensor(metadata.blob.clone(), DType::U8, vec![8]),
        Value::frame(metadata.blob.clone(), 42, FrameKind::Sensor),
    ] {
        let mut issue = request(TaintedValue::new(item, selected_taint.clone()));
        issue.offset = 2;
        issue.length = Some(4);
        let grant = fixture
            .gateway
            .issue_object_read_grant(&fixture.session, issue)
            .await?;
        ensure!(grant.metadata().blob == metadata.blob);
        ensure!(grant.offset() == 2 && grant.length() == 4);
        ensure!(grant.metadata().taint == expected_taint);
        let envelope = stored(&fixture, &grant).await?;
        ensure!(envelope.taint == grant.metadata().taint);
        let json: serde_json::Value =
            serde_json::from_str(envelope.value.as_str().context("record encoding")?)?;
        ensure!(json.get("taint").is_none());
        let (_, decoded) = record::decode(grant.grant_id(), &envelope)?;
        ensure!(decoded == grant);
        let authorization =
            ReadAuthorization::load(&fixture.gateway, &fixture.session, grant.grant_id()).await?;
        authorization.verify().await?;
    }
    Ok(())
}

#[tokio::test]
async fn read_grants_require_exact_committed_references_and_bounded_ranges() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let metadata = fixture
        .seed(b"data", "text/plain", TaintSet::pristine())
        .await?;
    let mut wrong_size = metadata.blob.clone();
    wrong_size.size += 1;
    let mut wrong_mime = metadata.blob.clone();
    wrong_mime.mime = None;
    for value in [
        Value::blob(wrong_size),
        Value::blob(wrong_mime),
        Value::blob(BlobRef {
            hash: "a".repeat(64),
            ..metadata.blob.clone()
        }),
        Value::blob(BlobRef {
            hash: "../grant".into(),
            ..metadata.blob.clone()
        }),
        Value::list(vec![Value::blob(metadata.blob.clone())]),
        Value::string(metadata.blob.hash.clone()),
    ] {
        ensure!(
            fixture
                .gateway
                .issue_object_read_grant(&fixture.session, request(TaintedValue::pristine(value)))
                .await
                .is_err()
        );
    }
    for (offset, length) in [
        (5, None),
        (u64::MAX, Some(1)),
        (1, Some(u64::MAX)),
        (0, Some(5)),
    ] {
        let mut issue = request(TaintedValue::pristine(Value::blob(metadata.blob.clone())));
        issue.offset = offset;
        issue.length = length;
        ensure!(
            fixture
                .gateway
                .issue_object_read_grant(&fixture.session, issue)
                .await
                .is_err()
        );
    }
    for ttl in [0, u64::MAX, 300_001] {
        let mut issue = request(TaintedValue::pristine(Value::blob(metadata.blob.clone())));
        issue.expires_in_ms = Some(ttl);
        ensure!(
            fixture
                .gateway
                .issue_object_read_grant(&fixture.session, issue)
                .await
                .is_err()
        );
    }
    ensure!(fixture.files.metadata(&metadata.blob).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn grant_audience_and_replica_scope_are_explicit() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let metadata = fixture
        .seed(b"private", "text/plain", TaintSet::pristine())
        .await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            request(TaintedValue::pristine(Value::blob(metadata.blob.clone()))),
        )
        .await?;
    let target = ResourceName::new(Path::parse("effect://echo/say")?);
    let replica = GatewayRuntime::new(fixture.boot.clone(), echo_profile(target.clone())?)?
        .with_object_store(fixture.files.clone().into_object_store());
    let replica_session = replica
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let read = replica
        .open_object_read(&replica_session, open(&grant))
        .await?;
    ensure!(read.metadata().blob == metadata.blob);
    drop(read);

    let bob_token = "read-grant-bob-token-0001";
    let with_bob = echo_profile(target.clone())?
        .with_bearer_identity("cred-bob", "bob", bob_token, "process://bob")?
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "bob",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    let same_profile = GatewayRuntime::new(fixture.boot.clone(), with_bob)?
        .with_object_store(fixture.files.clone().into_object_store());
    let bob = same_profile
        .authenticate(PresentedCredential::bearer(bob_token))
        .await?;
    ensure!(
        same_profile
            .open_object_read(&bob, open(&grant))
            .await
            .is_err()
    );
    ensure!(
        same_profile
            .revoke_object_read_grant(&bob, grant.grant_id())
            .await
            .is_err()
    );

    let other_profile = GatewayProfile::new("other-profile")
        .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")?
        .with_surface(GatewaySurface::effect_invoke("echo", target.clone()))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    let other = GatewayRuntime::new(fixture.boot.clone(), other_profile)?
        .with_object_store(fixture.files.clone().into_object_store());
    let other_session = other
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        other
            .open_object_read(&other_session, open(&grant))
            .await
            .is_err()
    );

    let independent = Fixture::new().await?;
    ensure!(
        independent
            .gateway
            .open_object_read(&independent.session, open(&grant))
            .await
            .is_err()
    );
    let refreshed = echo_profile(target)?.with_revision(fixture.session.profile_rev() + 1);
    fixture.gateway.replace_profile(refreshed)?;
    ensure!(
        fixture
            .gateway
            .open_object_read(&fixture.session, open(&grant))
            .await
            .is_err()
    );
    let current = fixture
        .gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(
        fixture
            .gateway
            .open_object_read(&current, open(&grant))
            .await
            .is_err()
    );
    ensure!(stored(&fixture, &grant).await?.value.as_str().is_some());
    Ok(())
}

#[tokio::test]
async fn same_principal_cannot_reuse_grants_under_changed_authority() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let metadata = fixture
        .seed(b"private", "text/plain", TaintSet::pristine())
        .await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            request(TaintedValue::pristine(Value::blob(metadata.blob))),
        )
        .await?;
    let original_target = ResourceName::new(Path::parse("effect://echo/say")?);
    let other_target = fixture.boot.register_effect(
        "effect://echo/other",
        &[xolotl_kernel::MethodSpec::unary_async(
            "invoke",
            xolotl_types::Purity::Pure,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?;
    for change in [
        "credential",
        "credential_generation",
        "auth_method",
        "identity",
        "identity_generation",
        "surface_missing",
        "surface_target",
    ] {
        let mut credential = GatewayCredential::bearer_token(
            if change == "credential" {
                "other-credential"
            } else {
                "cred-alice"
            },
            "alice",
            TEST_TOKEN,
        )?;
        let presented = if change == "auth_method" {
            credential = GatewayCredential::client_certificate_der_sha256(
                "cred-alice",
                "alice",
                ClientCertificateDerSha256::from_der(b"read-grant-certificate"),
            );
            PresentedCredential::client_certificate_der(b"read-grant-certificate")
        } else {
            PresentedCredential::bearer(TEST_TOKEN)
        };
        if change == "credential_generation" {
            credential = credential.with_generation(2);
        }
        let mut identity = GatewayIdentityMapping::new(
            "alice",
            if change == "identity" {
                "process://other-alice"
            } else {
                "process://alice"
            },
        );
        if change == "identity_generation" {
            identity = identity.with_generation(2);
        }
        let (target, capability) = if change == "surface_target" {
            (other_target.clone(), "perform://effect/echo/other")
        } else {
            (original_target.clone(), "perform://effect/echo/say")
        };
        let mut profile = GatewayProfile::new("gateway-test")
            .with_credential(credential)
            .with_identity_mapping(identity);
        if change != "surface_missing" {
            profile = profile
                .with_surface(GatewaySurface::effect_invoke("echo", target))
                .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                    "alice",
                    ["echo"],
                    [capability],
                ));
        }
        let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
        let other = GatewayRuntime::new(fixture.boot.clone(), profile)?
            .with_object_store(ObjectStore::new().with_read(probe.clone()));
        let session = other.authenticate(presented).await?;
        ensure!(session.principal().principal_id() == "alice");
        ensure!(
            other
                .open_object_read(&session, open(&grant))
                .await
                .is_err(),
            "accepted changed {change}"
        );
        ensure!(
            probe
                .metadata_reads
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
        );
    }
    Ok(())
}

#[tokio::test]
async fn malformed_or_changed_grants_fail_without_deleting_authority() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let metadata = fixture
        .seed(b"private", "text/plain", TaintSet::pristine())
        .await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            request(TaintedValue::pristine(Value::blob(metadata.blob))),
        )
        .await?;
    let saved = stored(&fixture, &grant).await?;
    let path = read_grant_path(grant.grant_id())?;
    for field in [
        "schema",
        "grant_id",
        "profile_name",
        "profile_rev",
        "principal_id",
        "principal_generation",
        "credential_id",
        "credential_generation",
        "auth_method",
        "identity_path",
        "surface_id",
        "target",
        "offset",
        "length",
        "expires_at_ms",
    ] {
        let mut document: serde_json::Value =
            serde_json::from_str(saved.value.as_str().context("grant record")?)?;
        match field {
            "schema" | "grant_id" => document[field] = serde_json::json!("wrong"),
            "offset" | "length" => document[field] = serde_json::json!(u64::MAX),
            "expires_at_ms" => document[field] = serde_json::json!(now_millis().saturating_sub(1)),
            "profile_rev" | "principal_generation" | "credential_generation" => {
                document["scope"][field] = serde_json::json!(99)
            }
            _ => document["scope"][field] = serde_json::json!("wrong"),
        }
        let changed = Value::string(serde_json::to_string(&document)?);
        fixture
            .boot
            .kernel
            .state
            .write_set_tainted(&path, changed.clone(), saved.taint.clone())
            .await?;
        ensure!(
            fixture
                .gateway
                .open_object_read(&fixture.session, open(&grant))
                .await
                .is_err(),
            "accepted changed {field}"
        );
        ensure!(fixture.boot.kernel.state.read(&path).await? == Some(changed));
    }
    fixture
        .boot
        .kernel
        .state
        .write_set_tainted(&path, saved.value.clone(), saved.taint.clone())
        .await?;
    let authorization =
        ReadAuthorization::load(&fixture.gateway, &fixture.session, grant.grant_id()).await?;
    ensure!(
        fixture
            .gateway
            .revoke_object_read_grant(&fixture.session, grant.grant_id())
            .await?
    );
    ensure!(authorization.verify().await.is_err());
    ensure!(
        !fixture
            .gateway
            .revoke_object_read_grant(&fixture.session, grant.grant_id())
            .await?
    );
    ensure!(
        fixture
            .gateway
            .open_object_read(&fixture.session, open(&grant))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn grant_codec_preserves_full_width_object_ranges() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let scope = record::ReadGrantScope::new(
        &fixture.gateway.profile_snapshot(),
        &fixture.session,
        "echo",
    )?;
    let grant = GatewayObjectReadGrant {
        grant_id: format!("org_{}", "1".repeat(32)),
        metadata: xolotl_state::object::ObjectMetadata {
            blob: BlobRef {
                hash: "a".repeat(64),
                size: u64::MAX,
                mime: None,
            },
            taint: TaintSet::of(TaintSource::ModelOutput),
        },
        offset: u64::MAX - 7,
        length: 7,
        expires_at_ms: i64::MAX,
    };
    let envelope = TaintedValue::new(record::encode(scope, &grant)?, grant.metadata.taint.clone());
    let (_, replayed) = record::decode(grant.grant_id(), &envelope)?;
    ensure!(replayed == grant);
    Ok(())
}

struct CommitState {
    inner: InMemoryBackend,
    after_commit: bool,
    grant_path: parking_lot::Mutex<Option<Path>>,
    gate: Option<Arc<Gate>>,
    revoke_gate: Option<Arc<Gate>>,
    fail: bool,
}

impl StateRead for CommitState {
    type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.inner.read_tainted(path)
    }
}

impl StateWrite for CommitState {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if let StateMutation::CompareSet {
                expected: None,
                value,
            } = &mutation
            {
                *self.grant_path.lock() = Some(path.clone());
                let mut commit = xolotl_state::StateCommit {
                    taint: value.taint.clone(),
                };
                if self.after_commit {
                    commit = self.inner.mutate(path, mutation).await?;
                    if let Some(gate) = &self.gate {
                        gate.enter()
                            .await
                            .map_err(|failure| failure.with_taint(&commit.taint))?;
                    }
                } else {
                    if let Some(gate) = &self.gate {
                        gate.enter().await?;
                    }
                    if !self.fail {
                        commit = self.inner.mutate(path, mutation).await?;
                    }
                }
                if self.fail {
                    Err(xolotl_state::StateFailure::new(
                        xolotl_state::StateError::Backend("grant commit failed".into()),
                        commit.taint,
                    ))
                } else {
                    Ok(commit)
                }
            } else {
                if matches!(&mutation, StateMutation::CompareDelete { .. })
                    && let Some(gate) = &self.revoke_gate
                {
                    gate.enter().await?;
                }
                self.inner.mutate(path, mutation).await
            }
        })
    }
}

#[tokio::test]
async fn failed_grant_commit_does_not_publish_a_response_or_delete_shared_content()
-> anyhow::Result<()> {
    for after_commit in [false, true] {
        let state = Arc::new(CommitState {
            inner: InMemoryBackend::new(),
            after_commit,
            grant_path: parking_lot::Mutex::new(None),
            gate: None,
            revoke_gate: None,
            fail: true,
        });
        let boot = Arc::new(Bootstrap::from_kernel(Kernel::with_backends(
            Backend::new()
                .with_read(state.clone())
                .with_write(state.clone()),
            FactSink::in_memory().0,
        )));
        let fixture = Fixture::with_boot(
            boot,
            xolotl_kernel::MethodSpec::unary_async("invoke", xolotl_types::Purity::Pure),
            Arc::new(xolotl_kernel::EchoDriver),
        )
        .await?;
        let metadata = fixture
            .seed(b"shared content", "text/plain", TaintSet::pristine())
            .await?;
        ensure!(
            fixture
                .gateway
                .issue_object_read_grant(
                    &fixture.session,
                    request(TaintedValue::pristine(Value::blob(metadata.blob.clone())))
                )
                .await
                .is_err()
        );
        let path = state
            .grant_path
            .lock()
            .clone()
            .context("grant commit was not attempted")?;
        ensure!(fixture.boot.kernel.state.read(&path).await?.is_some() == after_commit);
        ensure!(fixture.files.metadata(&metadata.blob).await?.is_some());
    }
    Ok(())
}

async fn gated_fixture(state: Arc<CommitState>) -> anyhow::Result<Fixture> {
    let boot = Arc::new(Bootstrap::from_kernel(Kernel::with_backends(
        Backend::new().with_read(state.clone()).with_write(state),
        FactSink::in_memory().0,
    )));
    Fixture::with_boot(
        boot,
        xolotl_kernel::MethodSpec::unary_async("invoke", xolotl_types::Purity::Pure),
        Arc::new(xolotl_kernel::EchoDriver),
    )
    .await
}

#[tokio::test]
async fn cancelled_grant_commit_keeps_its_actual_persistence_state() -> anyhow::Result<()> {
    for after_commit in [false, true] {
        let gate = Gate::new();
        let state = Arc::new(CommitState {
            inner: InMemoryBackend::new(),
            after_commit,
            grant_path: parking_lot::Mutex::new(None),
            gate: Some(gate.clone()),
            revoke_gate: None,
            fail: false,
        });
        let fixture = gated_fixture(state.clone()).await?;
        let metadata = fixture
            .seed(b"shared content", "text/plain", TaintSet::pristine())
            .await?;
        {
            let mut pending = Box::pin(fixture.gateway.issue_object_read_grant(
                &fixture.session,
                request(TaintedValue::pristine(Value::blob(metadata.blob.clone()))),
            ));
            tokio::select! {
                result = &mut pending => bail!("grant commit completed before release: {result:?}"),
                entered = gate.wait() => entered?,
            }
        }
        let path = state
            .grant_path
            .lock()
            .clone()
            .context("grant commit was not attempted")?;
        ensure!(fixture.boot.kernel.state.read(&path).await?.is_some() == after_commit);
        ensure!(fixture.files.metadata(&metadata.blob).await?.is_some());
    }
    Ok(())
}

#[tokio::test]
async fn profile_change_during_grant_commit_does_not_return_live_authority() -> anyhow::Result<()> {
    let gate = Gate::new();
    let state = Arc::new(CommitState {
        inner: InMemoryBackend::new(),
        after_commit: true,
        grant_path: parking_lot::Mutex::new(None),
        gate: Some(gate.clone()),
        revoke_gate: None,
        fail: false,
    });
    let fixture = gated_fixture(state.clone()).await?;
    let metadata = fixture
        .seed(b"shared content", "text/plain", TaintSet::pristine())
        .await?;
    let mut pending = Box::pin(fixture.gateway.issue_object_read_grant(
        &fixture.session,
        request(TaintedValue::pristine(Value::blob(metadata.blob.clone()))),
    ));
    tokio::select! {
        result = &mut pending => bail!("grant commit completed before release: {result:?}"),
        entered = gate.wait() => entered?,
    }
    fixture.gateway.replace_profile(
        echo_profile(ResourceName::new(Path::parse("effect://echo/say")?))?.with_revision(2),
    )?;
    gate.release();
    ensure!(pending.await.is_err());
    let path = state
        .grant_path
        .lock()
        .clone()
        .context("grant commit was not attempted")?;
    ensure!(fixture.boot.kernel.state.read(&path).await?.is_some());
    ensure!(fixture.files.metadata(&metadata.blob).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn delayed_revocation_cannot_delete_a_changed_grant() -> anyhow::Result<()> {
    let gate = Gate::new();
    let state = Arc::new(CommitState {
        inner: InMemoryBackend::new(),
        after_commit: false,
        grant_path: parking_lot::Mutex::new(None),
        gate: None,
        revoke_gate: Some(gate.clone()),
        fail: false,
    });
    let fixture = gated_fixture(state.clone()).await?;
    let metadata = fixture
        .seed(b"shared content", "text/plain", TaintSet::pristine())
        .await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            request(TaintedValue::pristine(Value::blob(metadata.blob))),
        )
        .await?;
    let mut pending = Box::pin(
        fixture
            .gateway
            .revoke_object_read_grant(&fixture.session, grant.grant_id()),
    );
    tokio::select! {
        result = &mut pending => bail!("grant revocation completed before release: {result:?}"),
        entered = gate.wait() => entered?,
    }
    let saved = stored(&fixture, &grant).await?;
    let mut changed: serde_json::Value =
        serde_json::from_str(saved.value.as_str().context("grant record")?)?;
    changed["length"] = serde_json::json!(0);
    let replacement = Value::string(serde_json::to_string(&changed)?);
    let path = read_grant_path(grant.grant_id())?;
    fixture
        .boot
        .kernel
        .state
        .write_set_tainted(&path, replacement.clone(), saved.taint)
        .await?;
    gate.release();
    ensure!(pending.await.is_err());
    ensure!(fixture.boot.kernel.state.read(&path).await? == Some(replacement));
    Ok(())
}
