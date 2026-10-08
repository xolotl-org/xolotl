use super::*;
use crate::tests::{
    TEST_TOKEN, direct_input_with_provenance, direct_input_with_ticket, echo_profile,
};
use crate::{Gateway, GatewayLimitProfile, GatewaySubmission, PresentedCredential};
use anyhow::{Context, bail, ensure};
use sha2::{Digest as _, Sha384};
use std::sync::Arc;
use xolotl_kernel::Bootstrap;
use xolotl_kernel::host::system_now_millis as now_millis;
use xolotl_state::object::UploadOptions;
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{Outcome, TaintSet, TaintSource};

mod cancellation;
mod incremental;
mod integration;
mod lifecycle;
mod manual_clock;
mod multi;
#[cfg(feature = "structured-output")]
mod output;
mod ports;
mod provenance;
mod read_grants;
mod restart;
mod security;
mod structured;

fn content_digest(bytes: &[u8]) -> String {
    xolotl_types::BlobRef::sha384_hex(&Sha384::digest(bytes).into())
}

struct Fixture {
    _directory: tempfile::TempDir,
    files: FileObjectStore,
    boot: Arc<Bootstrap>,
    gateway: GatewayRuntime,
    session: GatewaySession,
}

impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        Self::with_driver(
            xolotl_kernel::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                xolotl_types::Purity::Pure,
                xolotl_kernel::MethodSpec::UNARY_ASYNC,
            ),
            Arc::new(xolotl_kernel::EchoDriver),
        )
        .await
    }

    async fn with_driver(
        method: xolotl_kernel::MethodSpec,
        driver: Arc<dyn xolotl_kernel::Driver>,
    ) -> anyhow::Result<Self> {
        Self::with_boot(Arc::new(Bootstrap::in_memory()), method, driver).await
    }

    async fn with_boot(
        boot: Arc<Bootstrap>,
        method: xolotl_kernel::MethodSpec,
        driver: Arc<dyn xolotl_kernel::Driver>,
    ) -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let files = FileObjectStore::open(directory.path())?;
        let name = boot.register_effect("effect://echo/say", &[method], driver)?;
        let gateway = GatewayRuntime::new(
            boot.clone(),
            echo_profile(name)?,
            Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
        )?
        .with_object_store(files.clone().into_object_store());
        let session = gateway
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await?;
        Ok(Self {
            _directory: directory,
            files,
            boot,
            gateway,
            session,
        })
    }

    async fn seed(
        &self,
        bytes: &[u8],
        mime: &str,
        taint: TaintSet,
    ) -> anyhow::Result<xolotl_state::object::ObjectMetadata> {
        let store = self.files.clone().into_object_store();
        let upload = store
            .begin_upload(UploadOptions {
                expected_size: Some(bytes.len() as u64),
                mime: Some(mime.into()),
                taint,
            })
            .await?;
        store
            .write_all(&upload, 0, bytes, UPLOAD_CHUNK_BYTES)
            .await?;
        Ok(store.commit_upload(&upload, &TaintSet::pristine()).await?)
    }

    fn install_probe(&mut self, probe: Arc<ports::ProbeStore>) {
        self.gateway.objects = ObjectStore::new()
            .with_read(probe.clone())
            .with_write(probe);
    }

    async fn issue(&self, single_use: bool) -> anyhow::Result<GatewayObjectUploadTicket> {
        Ok(self
            .gateway
            .issue_object_upload_ticket(
                &self.session,
                IssueObjectUploadTicketRequest {
                    surface_id: "echo".into(),
                    submission_token: None,
                    modality: GatewayModality::Bytes,
                    expected_size: None,
                    expected_digest: None,
                    allowed_media_types: Vec::new(),
                    expires_in_ms: Some(60_000),
                    single_use,
                    max_objects: Some(1),
                    max_total_bytes: None,
                    max_record_bytes: None,
                },
            )
            .await?)
    }

    async fn upload(
        &self,
        bytes: &[u8],
        media_type: Option<&str>,
        single_use: bool,
    ) -> anyhow::Result<(GatewayObjectUploadTicket, CommitObjectUploadResponse)> {
        let ticket = self.issue(single_use).await?;
        let mut upload = self.begin(&ticket, media_type).await?;
        upload.write(bytes).await?;
        let response = upload.commit(GatewayObjectKind::Blob).await?;
        Ok((ticket, response))
    }

    async fn begin(
        &self,
        ticket: &GatewayObjectUploadTicket,
        media_type: Option<&str>,
    ) -> Result<GatewayObjectUpload, GatewayError> {
        self.gateway
            .begin_object_upload(
                &self.session,
                BeginObjectUploadRequest {
                    ticket_id: ticket.ticket_id().into(),
                    media_type: media_type.map(str::to_string),
                    submission_token: None,

                    expected_size: None,
                    expected_digest: None,
                },
            )
            .await
    }

    async fn record(&self, ticket_id: &str) -> anyhow::Result<GatewayObjectUploadTicket> {
        let value = self
            .boot
            .kernel()
            .state()
            .read(&upload_ticket_path(ticket_id)?)
            .await?
            .context("missing ticket")?;
        Ok(GatewayObjectUploadTicket::from_value(&value)?)
    }
}

#[test]
fn upload_ticket_records_require_security_state_fields() -> anyhow::Result<()> {
    let ticket = GatewayObjectUploadTicket {
        ticket_id: "ticket_regression".into(),
        profile_name: "test".into(),
        principal_id: "alice".into(),
        surface_id: "echo".into(),
        submission_token: None,
        modality: GatewayModality::Bytes,
        expected_size: None,
        expected_digest: None,
        allowed_media_types: Vec::new(),
        expires_at_ms: now_millis().saturating_add(60_000),
        single_use: true,
        max_objects: 1,
        max_total_bytes: 1024 * 1024,
        max_record_bytes: 256 * 1024,
        committed_items: Vec::new(),
        used_by: None,
    };

    for field in [
        "profile_name",
        "single_use",
        "allowed_media_types",
        "committed_items",
        "max_objects",
        "max_total_bytes",
        "max_record_bytes",
    ] {
        let mut map = ticket.to_value()?.into_map().context("ticket map")?;
        map.remove(field);
        let value = Value::from(map);
        ensure!(
            matches!(GatewayObjectUploadTicket::from_value(&value), Err(GatewayError::Rejected(message)) if message.contains(field)),
            "ticket missing {field} should be rejected"
        );
    }

    let mut map = ticket.to_value()?.into_map().context("ticket map")?;
    map.insert("used_by".into(), Value::integer(7))?;
    let value = Value::from(map);
    ensure!(
        matches!(GatewayObjectUploadTicket::from_value(&value), Err(GatewayError::Rejected(message)) if message.contains("used_by")),
        "ticket with malformed used_by field should be rejected"
    );
    for field in ["submission_token", "expected_digest", "expected_size"] {
        let mut map = ticket.to_value()?.into_map().context("ticket map")?;
        map.insert(field.into(), Value::integer(7))?;
        if field == "expected_size" {
            map.insert(field.into(), Value::string("wrong".into()))?;
        }
        ensure!(
            GatewayObjectUploadTicket::from_value(&Value::from(map)).is_err(),
            "ticket with malformed {field} should be rejected"
        );
        let mut map = ticket.to_value()?.into_map().context("ticket map")?;
        map.insert(field.into(), Value::null())?;
        ensure!(
            GatewayObjectUploadTicket::from_value(&Value::from(map)).is_err(),
            "ticket with null {field} should be rejected"
        );
    }
    let mut map = ticket.to_value()?.into_map().context("ticket map")?;
    map.insert("allowed_media_types".into(), Value::null())?;
    ensure!(GatewayObjectUploadTicket::from_value(&Value::from(map)).is_err());
    let mut used_without_content = ticket;
    used_without_content.used_by = Some("a".repeat(64));
    ensure!(used_without_content.to_value().is_err());
    Ok(())
}

#[test]
fn ticket_paths_and_sizes_are_checked_before_serialization() -> anyhow::Result<()> {
    ensure!(
        upload_ticket_path("ticket_1")?.to_string() == "state://gateway/upload-ticket/ticket_1"
    );
    ensure!(upload_ticket_path("ticket/1").is_err());
    let mut ticket = GatewayObjectUploadTicket {
        ticket_id: "size".into(),
        profile_name: "test".into(),
        principal_id: "alice".into(),
        surface_id: "echo".into(),
        submission_token: None,
        modality: GatewayModality::Bytes,
        expected_size: Some(i64::MAX as u64),
        expected_digest: None,
        allowed_media_types: Vec::new(),
        expires_at_ms: 1,
        single_use: false,
        max_objects: 1,
        max_total_bytes: i64::MAX as u64,
        max_record_bytes: 256 * 1024,
        committed_items: Vec::new(),
        used_by: None,
    };
    ensure!(
        GatewayObjectUploadTicket::from_value(&ticket.to_value()?)?.expected_size
            == ticket.expected_size
    );
    ticket.expected_size = Some(i64::MAX as u64 + 1);
    ensure!(ticket.to_value().is_err());
    let request = IssueObjectUploadTicketRequest {
        surface_id: "echo".into(),
        submission_token: None,
        modality: GatewayModality::Bytes,
        expected_size: None,
        expected_digest: None,
        allowed_media_types: vec!["image/png".into(); 33],
        expires_in_ms: Some(60_000),
        single_use: true,

        max_objects: None,
        max_total_bytes: None,
        max_record_bytes: None,
    };
    ensure!(validate_ticket_issue_request(&request, &GatewayLimitProfile::default()).is_err());
    ticket.expected_size = None;
    ticket.profile_name = "large".repeat(5_000);
    ensure!(ticket.to_value().is_err());
    Ok(())
}

#[tokio::test]
async fn direct_input_large_ref_requires_blob_store_match() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (_, committed) = fixture
        .upload(b"stored image bytes", Some("image/png"), false)
        .await?;
    let out = fixture
        .gateway
        .submit(
            &fixture.session,
            fixture.direct_input_with_provenance(
                "echo",
                committed.item.clone(),
                committed.provenance.clone(),
            )?,
        )
        .await?;
    ensure!(out.output.outcome == Outcome::Done(committed.item.clone()));
    for field in ["size", "mime", "hash"] {
        let mut blob = committed
            .item
            .backing_blob()
            .context("expected blob")?
            .clone();
        match field {
            "size" => blob.size += 1,
            "mime" => blob.mime = Some("text/plain".into()),
            _ => blob.hash = "a".repeat(96),
        }
        let item = Value::blob(blob);
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    fixture.direct_input_with_provenance(
                        "echo",
                        item,
                        committed.provenance.clone(),
                    )?
                )
                .await
                .is_err(),
            "accepted changed {field}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn direct_input_upload_ticket_is_bound_and_single_use() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, committed) = fixture
        .upload(b"ticketed bytes", Some("image/png"), true)
        .await?;
    let mut submission =
        direct_input_with_ticket("echo", committed.item.clone(), ticket.ticket_id());
    submission.options.expected_request_scope = Some(crate::tests::test_request_scope(
        &fixture.gateway,
        &fixture.session,
        "echo",
    )?);
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission.clone())
            .await?
            .output
            .outcome
            == Outcome::Done(committed.item)
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission)
            .await?
            .origin
            == xolotl_types::CompletionOrigin::CachedOutcome
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_upload_ticket_rejects_expired_or_wrong_surface() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, committed) = fixture.upload(b"rejected ticket bytes", None, true).await?;
    let saved = fixture.record(ticket.ticket_id()).await?;
    let mut submission =
        direct_input_with_ticket("echo", committed.item.clone(), ticket.ticket_id());
    submission.options.expected_request_scope = Some(crate::tests::test_request_scope(
        &fixture.gateway,
        &fixture.session,
        "echo",
    )?);
    for field in ["expiry", "surface", "principal", "token"] {
        let mut invalid = saved.clone();
        match field {
            "expiry" => invalid.expires_at_ms = now_millis().saturating_sub(1),
            "surface" => invalid.surface_id = "other".into(),
            "principal" => invalid.principal_id = "other".into(),
            _ => invalid.submission_token = Some("bound".into()),
        }
        fixture
            .boot
            .kernel()
            .state()
            .write_set(
                &upload_ticket_path(ticket.ticket_id())?,
                invalid.to_value()?,
            )
            .await?;
        ensure!(
            fixture
                .gateway
                .submit(&fixture.session, submission.clone())
                .await
                .is_err(),
            "accepted invalid {field}"
        );
        ensure!(
            !fixture.record(ticket.ticket_id()).await?.used_by.is_some(),
            "consumed invalid {field}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn object_upload_issue_commit_returns_bound_single_use_store_proof() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, committed) = fixture
        .upload(b"committed image bytes", Some("image/png"), true)
        .await?;
    ensure!(committed.digest == content_digest(b"committed image bytes"));
    let record = fixture.record(ticket.ticket_id()).await?;
    ensure!(record.is_committed() && !record.used_by.is_some());
    ensure!(record.committed_items.len() == 1);
    ensure!(record.committed_items[0].item == committed.item);
    let submission = GatewaySubmission::direct_input("echo", committed.item.clone())
        .with_provenance(committed.provenance)
        .with_options(crate::SubmitOptions {
            idempotency_key: Some("object-proof-first".into()),
            expected_request_scope: Some(crate::tests::test_request_scope(
                &fixture.gateway,
                &fixture.session,
                "echo",
            )?),
            ..crate::SubmitOptions::default()
        });
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission.clone())
            .await?
            .output
            .outcome
            == Outcome::Done(committed.item)
    );
    let original_scope = submission.options.expected_request_scope.clone();
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                submission.with_options(crate::SubmitOptions {
                    idempotency_key: Some("object-proof-second".into()),
                    expected_request_scope: original_scope,
                    ..crate::SubmitOptions::default()
                })
            )
            .await
            .is_err()
    );
    Ok(())
}
