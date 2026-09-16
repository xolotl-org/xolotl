use super::*;
use crate::tests::{
    TEST_TOKEN, direct_input_with_provenance, direct_input_with_ticket, echo_profile,
};
use crate::{Gateway, GatewaySubmission, PresentedCredential};
use anyhow::{Context, bail, ensure};
use std::sync::Arc;
use xolotl_kernel::Bootstrap;
use xolotl_state::object::UploadOptions;
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{Outcome, TaintSet, TaintSource};

mod cancellation;
mod incremental;
mod integration;
mod lifecycle;
#[cfg(feature = "structured-output")]
mod output;
mod ports;
mod read_grants;
mod restart;
mod security;
mod structured;

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
            xolotl_kernel::MethodSpec::unary_async("invoke", xolotl_types::Purity::Pure),
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
        let gateway = GatewayRuntime::new(boot.clone(), echo_profile(name)?)?
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
                },
            )
            .await
    }

    async fn record(&self, ticket_id: &str) -> anyhow::Result<GatewayObjectUploadTicket> {
        let value = self
            .boot
            .kernel
            .state
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
        committed: false,
        used: false,
    };

    for field in ["profile_name", "single_use", "committed", "used"] {
        let mut map = ticket.to_value()?.into_map().context("ticket map")?;
        map.remove(field);
        let value = Value::from(map);
        ensure!(
            matches!(GatewayObjectUploadTicket::from_value(&value), Err(GatewayError::Rejected(message)) if message.contains(field)),
            "ticket missing {field} should be rejected"
        );
    }

    let mut map = ticket.to_value()?.into_map().context("ticket map")?;
    map.insert("used".into(), Value::string("false".into()))?;
    let value = Value::from(map);
    ensure!(
        matches!(GatewayObjectUploadTicket::from_value(&value), Err(GatewayError::Rejected(message)) if message.contains("used")),
        "ticket with malformed used field should be rejected"
    );
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
        committed: false,
        used: false,
    };
    ensure!(
        GatewayObjectUploadTicket::from_value(&ticket.to_value()?)?.expected_size
            == ticket.expected_size
    );
    ticket.expected_size = Some(i64::MAX as u64 + 1);
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
            direct_input_with_provenance(
                "echo",
                committed.item.clone(),
                committed.provenance.clone(),
            ),
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
            _ => blob.hash = "a".repeat(64),
        }
        let item = Value::blob(blob);
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    direct_input_with_provenance("echo", item, committed.provenance.clone(),)
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
    let submission = direct_input_with_ticket("echo", committed.item.clone(), ticket.ticket_id());
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission.clone())
            .await?
            .output
            .outcome
            == Outcome::Done(committed.item)
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used);
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn direct_input_upload_ticket_rejects_expired_or_wrong_surface() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, committed) = fixture.upload(b"rejected ticket bytes", None, true).await?;
    let saved = fixture.record(ticket.ticket_id()).await?;
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
            .kernel
            .state
            .write_set(
                &upload_ticket_path(ticket.ticket_id())?,
                invalid.to_value()?,
            )
            .await?;
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    direct_input_with_ticket("echo", committed.item.clone(), ticket.ticket_id(),)
                )
                .await
                .is_err(),
            "accepted invalid {field}"
        );
        ensure!(
            !fixture.record(ticket.ticket_id()).await?.used,
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
    ensure!(committed.digest == blake3::hash(b"committed image bytes").to_hex().as_str());
    let record = fixture.record(ticket.ticket_id()).await?;
    ensure!(record.committed && !record.used);
    ensure!(record.expected_size == Some(committed.size));
    ensure!(record.expected_digest.as_deref() == Some(committed.digest.as_str()));
    let submission = GatewaySubmission::direct_input("echo", committed.item.clone())
        .with_provenance(committed.provenance);
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission.clone())
            .await?
            .output
            .outcome
            == Outcome::Done(committed.item)
    );
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission)
            .await
            .is_err()
    );
    Ok(())
}
