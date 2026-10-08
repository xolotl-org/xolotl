use super::*;
use crate::credentials::{CredentialOperation, CredentialRequest};
use crate::protocol::{
    ACTION_ACCESS_ROLE_WRITE_CAS, ACTION_ACCESS_SESSION_CURRENT_LOGOUT,
    ACTION_ACCESS_USER_WRITE_CAS, ACTION_EXTERNAL_SOURCE_CLAIM_INSPECT,
    ACTION_EXTERNAL_SOURCE_EVENT_DECISION_INSPECT, ConsoleErrorCode,
};
use crate::{
    BootstrapOutcome, ConsoleConfig, ConsoleService, ConsoleState, LoginRequest, RootProvisioning,
    bootstrap_root_account,
};
use anyhow::{Context, ensure};
use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use xolotl_kernel::{Bootstrap, FactSink, KernelBuilder};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, ExternalInstallationRecord,
    SourceAdmissionError, SourceClaimInspection, SourceCommit, SourceCommitOutcome,
    SourceDeclarationAdmission, SourceEventCommit, SourceFuture, SourceStoreError,
    SourceStreamLifecycle, SourceStreamOpen, SourceStreamOpenOutcome, SourceStreamPosition,
    SourceStreamRetire, SourceStreamRetireOutcome, SourceStreamScope,
};
use xolotl_state::InMemoryBackend;
use xolotl_types::{
    ExternalInstallationDef, TaintSet, ValueMap,
    external::{EventSource, OverflowPolicy, StreamCapacity},
};

const GRANT: &str = "perform://effect/external/source/installation/source/claims/inspect";
const EVENT_GRANT: &str = "perform://effect/external/source/installation/source/events/inspect";

#[derive(Clone, Debug)]
struct ObservedInspection {
    claim_id: SourceClaimId,
}

struct Inspection {
    source: Arc<InMemoryBackend>,
    calls: Mutex<Vec<ObservedInspection>>,
    fail_read: AtomicBool,
    wrong_claim: AtomicBool,
}

impl SourceDeclarationAdmission for Inspection {
    fn validate_source(
        &self,
        installation_id: &str,
        projection_id: &str,
        source: &EventSource,
    ) -> Result<(), SourceAdmissionError> {
        self.source
            .validate_source(installation_id, projection_id, source)
    }
}

impl ExternalInstallationAuthority for Inspection {
    fn load_installation<'a>(
        &'a self,
        id: &'a str,
    ) -> SourceFuture<'a, Option<ExternalInstallationRecord>> {
        self.source.load_installation(id)
    }

    fn list_installations<'a>(
        &'a self,
        after_id: Option<&'a str>,
        limit: NonZeroUsize,
    ) -> SourceFuture<'a, Vec<ExternalInstallationRecord>> {
        self.source.list_installations(after_id, limit)
    }

    fn compare_install<'a>(
        &'a self,
        definition: ExternalInstallationDef,
        expected: Option<xolotl_source::ExternalInstallationRevision>,
    ) -> SourceFuture<'a, ExternalInstallationMutation> {
        self.source.compare_install(definition, expected)
    }

    fn compare_retire<'a>(
        &'a self,
        id: &'a str,
        expected: xolotl_source::ExternalInstallationRevision,
    ) -> SourceFuture<'a, ExternalInstallationMutation> {
        self.source.compare_retire(id, expected)
    }
}

// The injected management object delegates to one storage owner. Console
// cannot call its event commit or maintenance methods.
impl SourceClaimInspection for Inspection {
    fn inspect<'a>(
        &'a self,
        request: SourceEvidenceInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence> {
        Box::pin(async move {
            self.calls
                .lock()
                .map_err(|_error| SourceStoreError::Aborted("test lock".into()))?
                .push(ObservedInspection {
                    claim_id: request.claim.claim_id,
                });
            if self.fail_read.load(Ordering::SeqCst) {
                return Err(SourceStoreError::Indeterminate(
                    "evidence-read-failure-sentinel".into(),
                ));
            }
            let mut evidence = self.source.inspect(request).await?;
            if self.wrong_claim.load(Ordering::SeqCst)
                && let SourceClaimEvidence::Committed(receipt) = &mut evidence
            {
                receipt.projection_id = "another-projection".into();
            }
            Ok(evidence)
        })
    }

    fn inspect_event<'a>(
        &'a self,
        request: SourceEventDecisionInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence> {
        Box::pin(async move {
            if self.fail_read.load(Ordering::SeqCst) {
                return Err(SourceStoreError::Indeterminate(
                    "evidence-read-failure-sentinel".into(),
                ));
            }
            let mut evidence = self.source.inspect_event(request).await?;
            if self.wrong_claim.load(Ordering::SeqCst)
                && let SourceClaimEvidence::Committed(receipt) = &mut evidence
            {
                receipt.projection_id = "another-projection".into();
            }
            Ok(evidence)
        })
    }
}

struct Host {
    state: Arc<ConsoleState>,
    service: ConsoleService,
    source: Arc<InMemoryBackend>,
    inspection: Arc<Inspection>,
    root: String,
    scope_epoch: u64,
}

async fn install_source(
    source: &dyn ExternalInstallationAuthority,
    sink: &Path,
) -> anyhow::Result<u64> {
    let definition = serde_json::from_value(serde_json::json!({
        "id": "installation",
        "platform": "installation",
        "transport": { "grpc": { "endpoint": null } },
        "trust": "full",
        "config_schema": null,
        "config": null,
        "projections": [{
            "id": "source",
            "role": "source",
            "namespace": null,
            "provides": [],
            "emits": {
                "sink": sink.to_string(),
                "purity": "effectful",
                "event_schema": null,
                "max_inline_payload_bytes": 1024,
                "capacity": { "max_events": 8, "on_overflow": "drop_oldest" },
                "rate_limit": null,
                "commands": false,
                "command_schema": null,
                "command_result_schema": null
            },
            "version": 1
        }],
        "version": 0
    }))?;
    let ExternalInstallationMutation::Applied(Some(record)) =
        source.compare_install(definition, None).await?
    else {
        anyhow::bail!("source installation was not accepted");
    };
    record
        .scope_epoch("source")
        .context("active test Source scope")
}

impl Host {
    async fn new(installed: bool) -> anyhow::Result<Self> {
        let (backend, source) = InMemoryBackend::new().into_source_parts();
        let boot = Arc::new(Bootstrap::from_kernel(
            KernelBuilder::new(backend)
                .with_fact_sink(FactSink::in_memory().0)
                .build(),
        ));
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = bootstrap_root_account(
            &boot,
            &xolotl_kernel::host::TokioBlockingSpawner::default(),
            RootProvisioning::default(),
        )
        .await?
        else {
            anyhow::bail!("new root account");
        };
        let inspection = Arc::new(Inspection {
            source: source.clone(),
            calls: Mutex::new(Vec::new()),
            fail_read: AtomicBool::new(false),
            wrong_claim: AtomicBool::new(false),
        });
        let scope_epoch = install_source(
            source.as_ref(),
            &Path::parse("state://business/source-events")?,
        )
        .await?;
        let state = ConsoleState::with_config(
            boot,
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                source_management: installed.then(|| inspection.clone() as Arc<_>),
                ..Default::default()
            },
        )?;
        let service = ConsoleService::new(state.clone());
        let root = service
            .login(
                LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "host-login".into(),
            )
            .await?
            .into_session()
            .ok()
            .context("root login")?
            .token;
        Ok(Self {
            state,
            service,
            source,
            inspection,
            root,
            scope_epoch,
        })
    }

    async fn elevate(&mut self) -> anyhow::Result<()> {
        self.root = self
            .state
            .auth
            .enroll_test_totp(&self.state.boot, &self.root)
            .await?
            .token;
        Ok(())
    }

    fn calls(&self) -> anyhow::Result<Vec<ObservedInspection>> {
        self.inspection
            .calls
            .lock()
            .map(|calls| calls.clone())
            .map_err(|_error| anyhow::anyhow!("inspection lock"))
    }

    async fn seed_receipt(&self) -> anyhow::Result<Path> {
        let sink = Path::parse("state://business/source-events")?;
        let capacity = StreamCapacity {
            max_events: 8,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::string("private-payload-sentinel".into());
        let taint = TaintSet::pristine();
        ensure!(
            self.source
                .commit(SourceCommit {
                    claim: SourceClaim {
                        installation_id: "installation",
                        projection_id: "source",
                        scope_epoch: self.scope_epoch,
                        stream_epoch: None,
                        event_id: "event:1",
                        claim_id: SourceClaimId::from_bytes([1; 16]),
                    },
                    received_at_ms: 123,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 123;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 60_000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1024,
                    payload: &payload,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                })
                .await?
                == SourceCommitOutcome::Accepted
        );
        Ok(sink)
    }

    async fn seed_ordered_event(&self, open_id: &str, claim_byte: u8) -> anyhow::Result<u64> {
        let stream = SourceStreamScope {
            installation_id: "installation",
            projection_id: "source",
            scope_epoch: self.scope_epoch,
            stream_id: "reused-stream",
        };
        let snapshot = self
            .source
            .inspect_stream(stream)
            .await?
            .context("active source scope")?;
        let SourceStreamOpenOutcome::Opened(opened) = self
            .source
            .open_stream(SourceStreamOpen {
                stream,
                open_id,
                expected_revision: snapshot.revision,
            })
            .await?
        else {
            anyhow::bail!("ordered stream was not opened");
        };
        let epoch = opened.active.context("opened stream")?.stream_epoch;
        let sink = Path::parse("state://business/source-events")?;
        let capacity = StreamCapacity {
            max_events: 8,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::integer(i64::from(claim_byte));
        let taint = TaintSet::pristine();
        ensure!(
            self.source
                .commit(SourceCommit {
                    claim: SourceClaim {
                        installation_id: "installation",
                        projection_id: "source",
                        scope_epoch: self.scope_epoch,
                        stream_epoch: Some(epoch),
                        event_id: "event:ordered",
                        claim_id: SourceClaimId::from_bytes([claim_byte; 16]),
                    },
                    received_at_ms: 123,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 123;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 60_000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1024,
                    payload: &payload,
                    taint: &taint,
                    stream: Some(SourceStreamPosition {
                        stream_id: stream.stream_id,
                        stream_epoch: epoch,
                        seq: 1,
                    }),
                    rate_limit: None,
                })
                .await?
                == SourceCommitOutcome::Accepted
        );
        Ok(epoch)
    }

    async fn role(&self, grants: &[&str], version: Option<u64>) -> anyhow::Result<()> {
        self.service
            .call(
                &self.root,
                None,
                ActionCall {
                    action: ACTION_ACCESS_ROLE_WRITE_CAS.into(),
                    input: map_value([
                        ("role", Value::string("source-inspectors".into())),
                        ("value", map_value([("grants", strings(grants))])),
                        (
                            "expected_version",
                            version.map_or(Value::null(), |v| Value::integer(v as i64)),
                        ),
                    ]),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    async fn inspector(&self) -> anyhow::Result<String> {
        self.role(&[GRANT], None).await?;
        self.service
            .call(
                &self.root,
                None,
                ActionCall {
                    action: ACTION_ACCESS_USER_WRITE_CAS.into(),
                    input: map_value([
                        ("username", Value::string("alice".into())),
                        ("expected_version", Value::null()),
                        (
                            "value",
                            map_value([
                                ("status", Value::string("active".into())),
                                ("roles", strings(&["source-inspectors"])),
                                ("grants", strings(&[])),
                                (
                                    "authority_ceiling",
                                    strings(&[GRANT, EVENT_GRANT, "read://state/**"]),
                                ),
                            ]),
                        ),
                    ]),
                    ..Default::default()
                },
            )
            .await?;
        let password = "jS7!Vz3#Ec9$Tu5Xb2Ln";
        self.service
            .credentials(
                &self.root,
                CredentialRequest {
                    username: Some("alice".into()),
                    operation: CredentialOperation::SetPassword {
                        password: password.into(),
                    },
                },
                "admin".into(),
            )
            .await?;
        let login = self
            .service
            .login(
                LoginRequest {
                    username: "alice".into(),
                    password: password.into(),
                    second_factor: None,
                },
                "operator".into(),
            )
            .await?
            .into_session()
            .ok()
            .context("inspector login")?;
        Ok(self
            .state
            .auth
            .enroll_test_totp(&self.state.boot, &login.token)
            .await?
            .token)
    }
}

fn strings(values: &[&str]) -> Value {
    Value::list(
        values
            .iter()
            .map(|value| Value::string((*value).into()))
            .collect(),
    )
}

fn call(scope_epoch: u64) -> ActionCall {
    ActionCall {
        action: ACTION_EXTERNAL_SOURCE_CLAIM_INSPECT.into(),
        input: map_value([
            ("installation_id", Value::string("installation".into())),
            ("projection_id", Value::string("source".into())),
            ("scope_epoch", Value::string(scope_epoch.to_string())),
            ("event_id", Value::string("event:1".into())),
            (
                "claim_id",
                Value::string(SourceClaimId::from_bytes([1; 16]).to_string()),
            ),
        ]),
        justification: Some(" investigate unknown commit ".into()),
        ..Default::default()
    }
}

fn event_call(scope_epoch: u64) -> ActionCall {
    ActionCall {
        action: ACTION_EXTERNAL_SOURCE_EVENT_DECISION_INSPECT.into(),
        input: map_value([
            ("installation_id", Value::string("installation".into())),
            ("projection_id", Value::string("source".into())),
            ("scope_epoch", Value::string(scope_epoch.to_string())),
            ("event_id", Value::string("event:1".into())),
        ]),
        justification: Some("investigate lost host log".into()),
        ..Default::default()
    }
}

fn replace(call: &mut ActionCall, key: &str, value: Value) -> anyhow::Result<()> {
    let mut input = call.input.as_map().context("call map")?.clone();
    input.insert(key.into(), value)?;
    call.input = Value::from(input);
    Ok(())
}

fn map(value: &Value) -> anyhow::Result<&ValueMap> {
    value.as_map().context("response map")
}

#[tokio::test]
async fn event_decision_inspection_recovers_retained_claim_without_log() -> anyhow::Result<()> {
    let mut host = Host::new(true).await?;
    let sink = host.seed_receipt().await?;
    let before = host.state.state.read(&sink).await?;
    let denied = host
        .service
        .call(&host.root, None, event_call(host.scope_epoch))
        .await
        .err()
        .context("MFA rejection")?;
    ensure!(denied.code == ConsoleErrorCode::StepUpRequired);
    host.elevate().await?;
    let output = host
        .service
        .call(&host.root, None, event_call(host.scope_epoch))
        .await?
        .output
        .context("event decision output")?;
    let receipt = map(map(&output)?.get("receipt").context("receipt")?)?;
    ensure!(map(&output)?.get("status").and_then(Value::as_str) == Some("committed"));
    ensure!(
        receipt.get("claim_id").and_then(Value::as_str) == Some("01010101010101010101010101010101")
    );
    ensure!(receipt.get("stream_epoch").is_some_and(Value::is_null));
    ensure!(host.state.state.read(&sink).await? == before);
    let mut unknown = event_call(host.scope_epoch);
    replace(&mut unknown, "event_id", Value::string("missing".into()))?;
    let output = host
        .service
        .call(&host.root, None, unknown)
        .await?
        .output
        .context("missing event output")?;
    ensure!(output == map_value([("status", Value::string("unproven".into()))]));
    let mut extra = event_call(host.scope_epoch);
    replace(&mut extra, "claim_id", Value::string("forged".into()))?;
    let denied = host
        .service
        .call(&host.root, None, extra)
        .await
        .err()
        .context("extra field")?;
    ensure!(denied.code == ConsoleErrorCode::BadRequest);
    let mut wrong_stream = event_call(host.scope_epoch);
    replace(&mut wrong_stream, "stream_epoch", Value::string("1".into()))?;
    let output = host
        .service
        .call(&host.root, None, wrong_stream)
        .await?
        .output
        .context("different ordered event identity")?;
    ensure!(output == map_value([("status", Value::string("unproven".into()))]));
    host.inspection.wrong_claim.store(true, Ordering::SeqCst);
    let denied = host
        .service
        .call(&host.root, None, event_call(host.scope_epoch))
        .await
        .err()
        .context("wrong scoped receipt")?;
    ensure!(denied.code == ConsoleErrorCode::Internal);
    Ok(())
}

#[tokio::test]
async fn ordered_event_inspection_requires_the_exact_stream_incarnation() -> anyhow::Result<()> {
    let mut host = Host::new(true).await?;
    host.elevate().await?;
    let old_epoch = host.seed_ordered_event("open-old", 3).await?;
    let stream = SourceStreamScope {
        installation_id: "installation",
        projection_id: "source",
        scope_epoch: host.scope_epoch,
        stream_id: "reused-stream",
    };
    ensure!(matches!(
        host.source
            .retire_stream(SourceStreamRetire {
                stream,
                stream_epoch: old_epoch,
            })
            .await?,
        SourceStreamRetireOutcome::Retired { .. }
    ));
    let new_epoch = host.seed_ordered_event("open-new", 4).await?;
    ensure!(new_epoch != old_epoch);
    for (epoch, claim_byte) in [(old_epoch, 3), (new_epoch, 4)] {
        let mut request = event_call(host.scope_epoch);
        replace(
            &mut request,
            "event_id",
            Value::string("event:ordered".into()),
        )?;
        replace(
            &mut request,
            "stream_epoch",
            Value::string(epoch.to_string()),
        )?;
        let result = host
            .service
            .call(&host.root, None, request)
            .await?
            .output
            .context("ordered inspection result")?;
        let receipt = map(map(&result)?.get("receipt").context("ordered receipt")?)?;
        ensure!(
            receipt.get("stream_epoch").and_then(Value::as_str) == Some(epoch.to_string().as_str())
        );
        ensure!(
            receipt.get("claim_id").and_then(Value::as_str)
                == Some(
                    SourceClaimId::from_bytes([claim_byte; 16])
                        .to_string()
                        .as_str()
                )
        );
    }
    let mut missing_epoch = event_call(host.scope_epoch);
    replace(
        &mut missing_epoch,
        "event_id",
        Value::string("event:ordered".into()),
    )?;
    let output = host
        .service
        .call(&host.root, None, missing_epoch)
        .await?
        .output
        .context("unordered identity result")?;
    ensure!(output == map_value([("status", Value::string("unproven".into()))]));
    Ok(())
}

#[tokio::test]
async fn event_decision_authority_is_separate_and_rechecked() -> anyhow::Result<()> {
    let mut host = Host::new(true).await?;
    host.elevate().await?;
    host.seed_receipt().await?;
    let token = host.inspector().await?;
    let denied = host
        .service
        .call(&token, None, event_call(host.scope_epoch))
        .await
        .err()
        .context("claim grant does not grant event lookup")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    host.role(&[EVENT_GRANT], Some(1)).await?;
    let denied = host
        .service
        .call(&token, None, event_call(host.scope_epoch))
        .await
        .err()
        .context("an existing session cannot gain a newly granted capability")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    let token = host
        .service
        .login(
            LoginRequest {
                username: "alice".into(),
                password: "jS7!Vz3#Ec9$Tu5Xb2Ln".into(),
                second_factor: Some(
                    host.state
                        .auth
                        .next_test_totp(&host.state.boot, "alice")
                        .await?,
                ),
            },
            "operator".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("inspector login after role grant")?
        .token;
    host.service
        .call(&token, None, event_call(host.scope_epoch))
        .await?;
    host.role(&[GRANT], Some(2)).await?;
    let denied = host
        .service
        .call(&token, None, event_call(host.scope_epoch))
        .await
        .err()
        .context("revoked event authority")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    Ok(())
}

#[tokio::test]
async fn root_inspects_exact_evidence_after_mfa_without_mutating_sink() -> anyhow::Result<()> {
    let mut host = Host::new(true).await?;
    let sink = host.seed_receipt().await?;
    let before = host.state.state.read(&sink).await?;
    let failure = host
        .service
        .call(&host.root, None, call(host.scope_epoch))
        .await
        .err()
        .context("MFA rejection")?;
    ensure!(failure.code == ConsoleErrorCode::StepUpRequired);
    ensure!(host.calls()?.is_empty());
    host.elevate().await?;
    let result = host
        .service
        .call(&host.root, Some("verified-peer"), call(host.scope_epoch))
        .await?;
    ensure!(result.execution.is_none());
    let output = result.output.context("output")?;
    ensure!(map(&output)?.get("status").and_then(Value::as_str) == Some("committed"));
    let receipt = map(map(&output)?.get("receipt").context("receipt")?)?;
    ensure!(
        receipt.get("claim_id").and_then(Value::as_str) == Some("01010101010101010101010101010101")
    );
    ensure!(receipt.get("received_at_ms").and_then(Value::as_int) == Some(123));
    ensure!(receipt.get("sink").and_then(Value::as_str) == Some(sink.to_string().as_str()));
    ensure!(!serde_json::to_string(&output)?.contains("private-payload-sentinel"));
    let observed = host.calls()?;
    ensure!(observed.len() == 1);
    ensure!(observed[0].claim_id == SourceClaimId::from_bytes([1; 16]));
    let facts = host.state.boot.kernel().facts().all_facts()?;
    ensure!(
        !facts
            .iter()
            .filter_map(|fact| fact.outcome.as_ref())
            .any(|value| {
                value
                    .as_map()
                    .and_then(|map| map.get("outcome"))
                    .and_then(Value::as_str)
                    == Some("source_claim_inspect")
            })
    );
    let mut unknown = call(host.scope_epoch);
    replace(
        &mut unknown,
        "claim_id",
        Value::string(SourceClaimId::from_bytes([2; 16]).to_string()),
    )?;
    let output = host
        .service
        .call(&host.root, None, unknown)
        .await?
        .output
        .context("unknown output")?;
    ensure!(output == map_value([("status", Value::string("unproven".into()))]));
    ensure!(host.state.state.read(&sink).await? == before);
    // No installation declaration exists: historical evidence stays inspectable.
    ensure!(
        host.state
            .state
            .read(&Path::parse(
                "state://kernel/external-installations/installation"
            )?)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn account_grants_are_projection_scoped_and_revalidated_for_each_call() -> anyhow::Result<()>
{
    let mut host = Host::new(true).await?;
    host.elevate().await?;
    host.seed_receipt().await?;
    let token = host.inspector().await?;
    host.service
        .call(&token, None, call(host.scope_epoch))
        .await?;
    ensure!(host.calls()?.len() == 1);
    for (key, value) in [("installation_id", "other"), ("projection_id", "other")] {
        let mut outside = call(host.scope_epoch);
        replace(&mut outside, key, Value::string(value.into()))?;
        let denied = host
            .service
            .call(&token, None, outside)
            .await
            .err()
            .context("scope denial")?;
        ensure!(denied.code == ConsoleErrorCode::Forbidden);
    }
    // State visibility alone never authorizes access to private evidence.
    host.role(&["read://state/**"], Some(1)).await?;
    let denied = host
        .service
        .call(&token, None, call(host.scope_epoch))
        .await
        .err()
        .context("revoked role")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    ensure!(host.calls()?.len() == 1);
    host.service
        .call(
            &token,
            None,
            ActionCall {
                action: ACTION_ACCESS_SESSION_CURRENT_LOGOUT.into(),
                ..Default::default()
            },
        )
        .await?;
    let denied = host
        .service
        .call(&token, None, call(host.scope_epoch))
        .await
        .err()
        .context("revoked session")?;
    ensure!(denied.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(host.calls()?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn invalid_input_and_uninstalled_port_do_not_inspect_or_infer_absence() -> anyhow::Result<()>
{
    let mut host = Host::new(true).await?;
    host.elevate().await?;
    for (key, value) in [
        ("claim_id", "00".into()),
        ("claim_id", "AB".repeat(16)),
        ("installation_id", "*".into()),
        ("projection_id", "source/other".into()),
        ("event_id", "x".repeat(257)),
        ("stream_epoch", "0".into()),
        ("stream_epoch", "not-a-number".into()),
        ("operator", "forged-admin".into()),
        ("inspected_at_ms", "0".into()),
    ] {
        let mut invalid = call(host.scope_epoch);
        replace(&mut invalid, key, Value::string(value))?;
        let failure = host
            .service
            .call(&host.root, None, invalid)
            .await
            .err()
            .context("invalid input")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
    }
    for reason in [None, Some("  ".into()), Some("x".repeat(1025))] {
        let invalid = ActionCall {
            justification: reason,
            ..call(host.scope_epoch)
        };
        let failure = host
            .service
            .call(&host.root, None, invalid)
            .await
            .err()
            .context("invalid reason")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
    }
    ensure!(host.calls()?.is_empty());
    let uninstalled = ConsoleService::new(ConsoleState::with_config(
        host.state.boot.clone(),
        ConsoleConfig {
            session_store: Some(host.state.auth.session_store.clone()),
            ..Default::default()
        },
    )?);
    let failure = uninstalled
        .call(&host.root, None, call(host.scope_epoch))
        .await
        .err()
        .context("missing port")?;
    ensure!(
        failure.code == ConsoleErrorCode::BadRequest && failure.message.contains("not installed")
    );
    ensure!(host.calls()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn evidence_read_failure_never_discloses_receipt_or_unproven() -> anyhow::Result<()> {
    let mut host = Host::new(true).await?;
    host.elevate().await?;
    let sink = host.seed_receipt().await?;
    let before = host.state.state.read(&sink).await?;
    host.inspection.fail_read.store(true, Ordering::SeqCst);
    let error = host
        .service
        .call(&host.root, None, call(host.scope_epoch))
        .await
        .err()
        .context("read failure")?;
    ensure!(error.code == ConsoleErrorCode::Internal);
    ensure!(!error.message.contains("sentinel"));
    ensure!(host.calls()?.len() == 1);
    ensure!(host.state.state.read(&sink).await? == before);
    host.inspection.fail_read.store(false, Ordering::SeqCst);
    let output = host
        .service
        .call(&host.root, None, call(host.scope_epoch))
        .await?
        .output
        .context("retry output")?;
    ensure!(map(&output)?.get("status").and_then(Value::as_str) == Some("committed"));
    host.inspection.wrong_claim.store(true, Ordering::SeqCst);
    let error = host
        .service
        .call(&host.root, None, call(host.scope_epoch))
        .await
        .err()
        .context("wrong claim returned by custom adapter")?;
    ensure!(error.code == ConsoleErrorCode::Internal);
    ensure!(!error.message.contains("another-projection"));
    Ok(())
}

#[tokio::test]
async fn redb_console_reads_receipt_without_a_second_audit() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("source.redb");
    {
        let store = xolotl_storage_redb::RedbStore::open(&database)?;
        let (backend, source) = store.state_backend().into_source_parts();
        let boot = Arc::new(Bootstrap::from_kernel(
            KernelBuilder::new(backend)
                .with_fact_sink(FactSink::in_memory().0)
                .build(),
        ));
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = bootstrap_root_account(
            &boot,
            &xolotl_kernel::host::TokioBlockingSpawner::default(),
            RootProvisioning::default(),
        )
        .await?
        else {
            anyhow::bail!("new root account");
        };
        let state = ConsoleState::with_config(
            boot,
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                source_management: Some(source.clone()),
                ..Default::default()
            },
        )?;
        let service = ConsoleService::new(state.clone());
        let token = service
            .login(
                LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                "redb-host".into(),
            )
            .await?
            .into_session()
            .ok()
            .context("root login")?
            .token;
        let token = state
            .auth
            .enroll_test_totp(&state.boot, &token)
            .await?
            .token;
        let sink = Path::parse("state://source/sink")?;
        let scope_epoch = install_source(source.as_ref(), &sink).await?;
        let payload = Value::integer(42);
        let capacity = StreamCapacity {
            max_events: 8,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let taint = TaintSet::pristine();
        ensure!(
            source
                .commit(SourceCommit {
                    claim: SourceClaim {
                        installation_id: "installation",
                        projection_id: "source",
                        scope_epoch,
                        stream_epoch: None,
                        event_id: "event:1",
                        claim_id: SourceClaimId::from_bytes([1; 16]),
                    },
                    received_at_ms: 123,
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 123;
                        move || decision_at_ms
                    }),
                    dedupe_window_ms: 60_000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1024,
                    payload: &payload,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                })
                .await?
                == SourceCommitOutcome::Accepted
        );
        let before = state.state.read(&sink).await?;
        let output = service
            .call(&token, Some("redb-inspector"), call(scope_epoch))
            .await?
            .output
            .context("output")?;
        ensure!(map(&output)?.get("status").and_then(Value::as_str) == Some("committed"));
        ensure!(state.state.read(&sink).await? == before);
    }
    Ok(())
}

#[cfg(feature = "http")]
#[tokio::test]
async fn protobuf_calls_use_the_same_source_inspection_admission_and_result() -> anyhow::Result<()>
{
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use prost::Message;
    use tower::ServiceExt;
    use xolotl_console_protocol::pb;
    let mut host = Host::new(true).await?;
    let state = crate::http::HttpState::new(host.state.clone(), crate::http::HttpConfig::default());
    let router = crate::http::HttpApi::new()
        .with_endpoint(crate::http::HttpEndpoint::Calls)
        .routes(state);
    let native = call(host.scope_epoch);
    let frame = pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
            id: 77,
            action: crate::protocol::ACTION_EXTERNAL_SOURCE_CLAIM_INSPECT.into(),
            input: Some(xolotl_proto::value_to_pb(&native.input)),
            justification: native.justification,
            ..Default::default()
        })),
    }
    .encode_to_vec();
    let request = |token: &str| -> anyhow::Result<Request<Body>> {
        Ok(Request::post("/calls")
            .header("host", "console.local")
            .header("origin", "https://console.local")
            .header("content-type", "application/protobuf")
            .header("authorization", format!("Bearer {token}"))
            .extension(crate::http::HttpPeer::verified_source("local-host")?)
            .body(Body::from(frame.clone()))?)
    };
    let response = router.clone().oneshot(request(&host.root)?).await?;
    ensure!(response.status() == StatusCode::FORBIDDEN);
    ensure!(host.calls()?.is_empty());
    host.elevate().await?;
    host.seed_receipt().await?;
    let expected = host
        .service
        .call(&host.root, None, call(host.scope_epoch))
        .await?
        .output
        .context("native output")?;
    let response = router.clone().oneshot(request(&host.root)?).await?;
    ensure!(response.status() == StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 16 * 1024).await?;
    let response = pb::ConsoleFrame::decode(bytes)?
        .frame
        .context("response frame")?;
    let pb::console_frame::Frame::Reply(reply) = response else {
        anyhow::bail!("expected action reply");
    };
    ensure!(reply.id == 77);
    let result = reply.result.context("action result")?;
    ensure!(xolotl_proto::value_from_pb(&result.output.context("wire output")?)? == expected);
    let native = event_call(host.scope_epoch);
    let expected = host
        .service
        .call(&host.root, None, native.clone())
        .await?
        .output
        .context("native event output")?;
    let frame = pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
            id: 78,
            action: native.action,
            input: Some(xolotl_proto::value_to_pb(&native.input)),
            justification: native.justification,
            ..Default::default()
        })),
    }
    .encode_to_vec();
    let response = router
        .oneshot(
            Request::post("/calls")
                .header("host", "console.local")
                .header("origin", "https://console.local")
                .header("content-type", "application/protobuf")
                .header("authorization", format!("Bearer {}", host.root))
                .extension(crate::http::HttpPeer::verified_source("local-host")?)
                .body(Body::from(frame))?,
        )
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 16 * 1024).await?;
    let response = pb::ConsoleFrame::decode(bytes)?
        .frame
        .context("event response frame")?;
    let pb::console_frame::Frame::Reply(reply) = response else {
        anyhow::bail!("expected event action reply");
    };
    ensure!(reply.id == 78);
    let result = reply.result.context("event action result")?;
    ensure!(xolotl_proto::value_from_pb(&result.output.context("event wire output")?)? == expected);
    Ok(())
}
