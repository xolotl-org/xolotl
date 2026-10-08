//! Installed declarations are stable across public discovery and factor management.

use super::*;
use std::sync::atomic::AtomicUsize;

struct ChangingDescriptor {
    factor: Arc<SignedFactor>,
    initially_enrollable: bool,
    calls: AtomicUsize,
}

impl MfaProvider for ChangingDescriptor {
    fn descriptor(&self) -> MfaProviderDescriptor {
        let mut descriptor = self.factor.descriptor();
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            descriptor.enrollment = self
                .initially_enrollable
                .then_some(MfaEnrollmentDescriptor {
                    begin_schema: None,
                    setup_schema: serde_json::json!(true),
                    pending_schema: None,
                });
        } else {
            descriptor.provider_id = "changed_identity".into();
            descriptor.label = "Changed declaration".into();
            descriptor.enrollment =
                (!self.initially_enrollable).then_some(MfaEnrollmentDescriptor {
                    begin_schema: None,
                    setup_schema: serde_json::json!(true),
                    pending_schema: None,
                });
            // A declaration that never passed installation validation must not
            // become a public response after the installation has succeeded.
            descriptor.authentication.proof_schema = Some(json!({
                "type": "string",
                "description": "x".repeat(32 * 1024),
            }));
        }
        descriptor
    }

    fn begin_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        input: Option<&'a Value>,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        self.factor.begin_enrollment(context, input)
    }

    fn continue_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        private_state: &'a Value,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        self.factor
            .continue_enrollment(context, private_state, input)
    }

    fn verify_proof<'a>(
        &'a self,
        context: MfaContext<'a>,
        verifier: &'a Value,
        proof: &'a Value,
    ) -> MfaFuture<'a, Value> {
        self.factor.verify_proof(context, verifier, proof)
    }
}

struct Fixture {
    boot: Arc<Bootstrap>,
    config: ConsoleConfig,
    service: ConsoleService,
    provider: Arc<ChangingDescriptor>,
    expected: MfaProviderDescriptor,
    key: SigningKey,
}

impl Fixture {
    async fn install(enrollment_supported: bool) -> anyhow::Result<Self> {
        let (boot, mut config, _, factor, key) = fixture().await?;
        let mut expected = factor.descriptor();
        expected.enrollment = enrollment_supported.then_some(MfaEnrollmentDescriptor {
            begin_schema: None,
            setup_schema: serde_json::json!(true),
            pending_schema: None,
        });
        let provider = Arc::new(ChangingDescriptor {
            factor,
            initially_enrollable: enrollment_supported,
            calls: AtomicUsize::new(0),
        });
        config.auth.mfa.install_totp = false;
        config.auth.mfa.providers = vec![provider.clone()];
        let service = ConsoleService::new(ConsoleState::with_config(boot.clone(), config.clone())?);
        ensure!(provider.calls.load(Ordering::SeqCst) == 1);
        Ok(Self {
            boot,
            config,
            service,
            provider,
            expected,
            key,
        })
    }

    fn check_catalog(&self, descriptors: &[MfaProviderSummary]) -> anyhow::Result<()> {
        ensure!(
            descriptors.len() == 1,
            "only the selected custom provider is installed"
        );
        let selected = descriptors
            .iter()
            .find(|provider| provider.descriptor.provider_id == self.expected.provider_id)
            .context("the installed provider remains discoverable")?;
        ensure!(
            serde_json::to_value(&selected.descriptor)? == serde_json::to_value(&self.expected)?
        );
        ensure!(selected.usage == MfaProviderUsage::default());
        ensure!(
            descriptors
                .iter()
                .all(|provider| provider.descriptor.provider_id != "changed_identity")
        );
        ensure!(self.provider.calls.load(Ordering::SeqCst) == 1);
        Ok(())
    }

    async fn check_status(&self, token: &str, factors: usize) -> anyhow::Result<()> {
        let MfaResponse::Status {
            providers,
            factors: enrolled,
            ..
        } = self
            .service
            .mfa(token, MfaRequest::Status {}, "test".into())
            .await?
        else {
            anyhow::bail!("factor status");
        };
        self.check_catalog(&providers)?;
        ensure!(enrolled.len() == factors);
        ensure!(enrolled.iter().all(|factor| {
            factor.provider_id == self.expected.provider_id
                && factor.availability == FactorAvailability::Available
        }));
        Ok(())
    }
}

#[tokio::test]
async fn discovery_and_enrollment_share_the_declaration_validated_at_installation()
-> anyhow::Result<()> {
    let fixture = Fixture::install(true).await?;
    let primary = fixture
        .service
        .login(login(None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let clone = fixture.service.clone();
    for service in [&fixture.service, &clone, &fixture.service] {
        let mut descriptors = service.mfa_providers();
        fixture.check_catalog(&descriptors)?;
        fixture.check_status(&primary.token, 0).await?;
        // Returned discovery is owned client data, not a mutable registration.
        descriptors
            .iter_mut()
            .find(|provider| provider.descriptor.provider_id == fixture.expected.provider_id)
            .context("owned provider descriptor")?
            .descriptor
            .authentication
            .proof_schema = Some(Value::Null);
        descriptors[0].usage.allow_authentication = false;
        fixture.check_catalog(&service.mfa_providers())?;
    }
    let (device, session, _) =
        enroll(&clone, &primary.token, &fixture.key, "Frozen declaration").await?;
    ensure!(session.authentication.mfa_level() == 2);
    fixture.check_status(&session.token, 1).await?;
    let logged_in = fixture
        .service
        .login(
            login(Some(signed_proof(
                &fixture.key,
                &device,
                2,
                MfaPurpose::Login,
            )?)),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(logged_in.authentication.mfa_level() == 2);
    fixture.check_catalog(&fixture.service.mfa_providers())?;

    // Freezing belongs to one installation. A new service still validates its
    // own declaration and must reject this now oversized replacement schema.
    ensure!(ConsoleState::with_config(fixture.boot, fixture.config).is_err());
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn a_later_descriptor_cannot_enable_initially_disabled_enrollment() -> anyhow::Result<()> {
    let fixture = Fixture::install(false).await?;
    let primary = fixture
        .service
        .login(login(None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    for _ in 0..2 {
        fixture.check_catalog(&fixture.service.mfa_providers())?;
        fixture.check_status(&primary.token, 0).await?;
        let error = fixture
            .service
            .mfa(
                &primary.token,
                MfaRequest::Begin {
                    provider_id: fixture.expected.provider_id.clone(),
                    label: "Still disabled".into(),
                    replace_factor_id: None,
                    input: None,
                },
                "test".into(),
            )
            .await
            .err()
            .context("enrollment remains disabled by the installed declaration")?;
        ensure!(error.code == ConsoleErrorCode::AdmissionRejected);
        fixture.check_status(&primary.token, 0).await?;
    }
    ensure!(
        fixture
            .provider
            .factor
            .observations
            .lock()
            .map_err(|_error| anyhow::anyhow!("observations poisoned"))?
            .is_empty(),
        "denied enrollment must not call the provider"
    );
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}
