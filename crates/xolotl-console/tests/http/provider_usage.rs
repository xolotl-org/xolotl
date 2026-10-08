//! HTTP discovery preserves host permissions and reports dispatch restrictions.

use super::*;
use xolotl_console::{
    AuthenticationStep,
    mfa::{FactorAvailability, MfaProviderSummary, MfaProviderUsage},
};

const PREFIX: &str = "/usage-test";

async fn post(
    app: &Router,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> anyhow::Result<Response> {
    json_request(app, &format!("{PREFIX}{path}"), "POST", body, token).await
}

fn app(boot: &Arc<Bootstrap>, config: ConsoleConfig) -> anyhow::Result<Router> {
    Ok(Router::new().nest(
        PREFIX,
        router(HttpState::new(
            ConsoleState::with_config(boot.clone(), config)?,
            HttpConfig::default(),
        )),
    ))
}

#[tokio::test]
async fn provider_discovery_and_login_distinguish_disabled_and_uninstalled_without_losing_recovery()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            password: Some("Ar7!cVN23#pxQe$Lr9".into()),
            ..Default::default()
        },
    )
    .await?;
    let shared_config = crate::console_config::console_config();
    let allowed = app(&boot, shared_config.clone())?;
    let login = json!({"username":"root","password":"Ar7!cVN23#pxQe$Lr9"});
    let primary = decode::<AuthenticationResponse>(
        post(&allowed, "/auth/password/login", login.clone(), None).await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .ok()
    .context("primary login")?;
    let MfaResponse::Enrollment {
        challenge_id,
        factor_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = decode::<MfaResponse>(
        post(
            &allowed,
            "/credentials/factors",
            json!({"operation":"begin","provider_id":"totp","label":"Retained TOTP"}),
            Some(&primary.token),
        )
        .await?,
        StatusCode::OK,
    )
    .await?
    else {
        anyhow::bail!("enrollment");
    };
    let MfaResponse::Updated { session, recovery_codes } = decode::<MfaResponse>(
        post(
            &allowed,
            "/credentials/factors",
            json!({"operation":"continue","challenge_id":challenge_id,"input":{"kind":"response","response":{"code":totp(&setup)?}}}),
            Some(&primary.token),
        )
        .await?,
        StatusCode::OK,
    )
    .await?
    else {
        anyhow::bail!("confirmed factor");
    };
    let mut recovery = recovery_codes.context("account recovery codes")?;
    let session = decode::<AuthenticationResponse>(
        post(
            &allowed,
            "/session/step-up",
            json!({"proof":{"kind":"recovery_code","code":recovery.pop().context("step-up code")?}}),
            Some(&session.token),
        )
        .await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .ok()
    .context("real second verification")?;

    let mut config = shared_config.clone();
    let usage = MfaProviderUsage {
        allow_enrollment: false,
        allow_authentication: false,
    };
    config.auth.mfa.provider_usage.insert("totp".into(), usage);
    let disabled = app(&boot, config)?;
    let providers: Vec<MfaProviderSummary> = decode(
        json_request(
            &disabled,
            &format!("{PREFIX}/auth/factor-providers"),
            "GET",
            Value::Null,
            None,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    ensure!(providers.len() == 1 && providers[0].descriptor.provider_id == "totp");
    ensure!(providers[0].usage == usage);
    ensure!(providers[0].descriptor.enrollment.is_some());
    ensure!(
        providers[0]
            .descriptor
            .authentication
            .proof_schema
            .is_some()
    );
    let next = decode::<AuthenticationResponse>(
        post(&disabled, "/auth/password/login", login.clone(), None).await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .err()
    .context("disabled provider cannot waive second-factor requirements")?;
    let AuthenticationStep::ChooseFactor { options } = next.step else {
        anyhow::bail!("factor selection");
    };
    ensure!(options.factors[0].availability == FactorAvailability::AuthenticationDisabled);
    ensure!(options.recovery_code_available);

    let credential_path = xolotl_types::Path::parse("state://vault/console/credentials/root")?;
    let lockout_path = xolotl_types::Path::parse("state://vault/console/lockouts/root")?;
    let before_credentials = boot.kernel().state().read(&credential_path).await?;
    let before_lockout = boot.kernel().state().read(&lockout_path).await?;
    let proof = json!({"kind":"factor","factor_id":factor_id,"response":{"code":"000000"}});
    let mut denied_login = login.clone();
    denied_login["second_factor"] = proof.clone();
    // Exceed the credential-failure lockout threshold: policy denials must
    // remain policy denials and leave account recovery immediately usable.
    for _ in 0..6 {
        let failure: ConsoleFailure = decode(
            post(
                &disabled,
                "/auth/password/login",
                denied_login.clone(),
                None,
            )
            .await?,
            StatusCode::FORBIDDEN,
        )
        .await?;
        ensure!(failure.code == ConsoleErrorCode::Forbidden);
    }
    let denied: ConsoleFailure = decode(
        post(
            &disabled,
            "/session/step-up",
            json!({"proof":proof}),
            Some(&session.token),
        )
        .await?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    let denied: ConsoleFailure = decode(
        post(
            &disabled,
            "/credentials/factors",
            json!({"operation":"begin","provider_id":"totp","label":"Disabled registration"}),
            Some(&session.token),
        )
        .await?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    ensure!(boot.kernel().state().read(&credential_path).await? == before_credentials);
    ensure!(boot.kernel().state().read(&lockout_path).await? == before_lockout);

    let mut absent_config = shared_config;
    absent_config.auth.mfa.install_totp = false;
    let absent = app(&boot, absent_config)?;
    let next = decode::<AuthenticationResponse>(
        post(&absent, "/auth/password/login", login.clone(), None).await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .err()
    .context("uninstalled provider retains the second-factor requirement")?;
    let AuthenticationStep::ChooseFactor { options } = next.step else {
        anyhow::bail!("factor selection");
    };
    ensure!(options.factors[0].availability == FactorAvailability::ProviderNotInstalled);
    let failure: ConsoleFailure = decode(
        post(&absent, "/auth/password/login", denied_login, None).await?,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    ensure!(failure.code == ConsoleErrorCode::AdmissionRejected);
    ensure!(boot.kernel().state().read(&credential_path).await? == before_credentials);
    ensure!(boot.kernel().state().read(&lockout_path).await? == before_lockout);

    let mut recovery_login = login;
    recovery_login["second_factor"] =
        json!({"kind":"recovery_code","code":recovery.pop().context("recovery code")?});
    let recovered = decode::<AuthenticationResponse>(
        post(&disabled, "/auth/password/login", recovery_login, None).await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .ok()
    .context("account recovery is independent of provider usage")?;
    ensure!(recovered.authentication.mfa_level() == 2);
    let renamed: MfaResponse = decode(
        post(
            &disabled,
            "/credentials/factors",
            json!({"operation":"rename","factor_id":factor_id,"label":"Still manageable"}),
            Some(&recovered.token),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let MfaResponse::Renamed { factor } = renamed else {
        anyhow::bail!("disabled factor metadata remains manageable");
    };
    ensure!(factor.availability == FactorAvailability::AuthenticationDisabled);
    Ok(())
}
