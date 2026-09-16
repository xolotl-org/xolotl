use super::*;

#[tokio::test]
async fn authority_admission_never_combines_old_hosts_with_a_new_session() -> anyhow::Result<()> {
    let gateway = GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        identity_profile()?.with_registered_host("old.example:9445")?,
    )?;
    let old_session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    gateway.validate_session_authority(&old_session, "old.example:9445")?;
    ensure!(matches!(
        gateway.validate_session_authority(&old_session, "new.example:9445"),
        Err(GatewayError::Unauthorized(_))
    ));

    // Reproduce the split-read ordering: inspect old hosts, reload, then
    // authenticate with a credential that remains valid in the new profile.
    let old_hosts = gateway.registered_gateway_hosts();
    gateway.replace_profile(
        identity_profile()?
            .with_revision(2)
            .with_registered_host("new.example:9445")?,
    )?;
    let current_session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    ensure!(gateway_host_allowed("old.example:9445", &old_hosts));
    ensure!(matches!(
        gateway.validate_session_authority(&current_session, "old.example:9445"),
        Err(GatewayError::Unauthorized(_))
    ));
    ensure!(
        gateway
            .validate_session_authority(&old_session, "old.example:9445")
            .is_err()
    );
    gateway.validate_session_authority(&current_session, "new.example:9445")?;
    Ok(())
}
