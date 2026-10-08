//! Public adapters share authentication progress and preserve credential admission.

use super::*;
use xolotl_console::AuthenticationStep;

const PREFIX: &str = "/authentication-test";

async fn request(
    app: &Router,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> anyhow::Result<Response> {
    json_request(app, &format!("{PREFIX}{path}"), "POST", body, token).await
}

async fn choose(app: &Router) -> anyhow::Result<xolotl_console::AuthenticationContinuation> {
    let result: AuthenticationResponse = decode(
        request(
            app,
            "/auth/password/login",
            json!({"username":"root","password":"Ar7!cVN23#pxQe$Lr9"}),
            None,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let next = result.into_session().err().context("factor selection")?;
    let AuthenticationStep::ChooseFactor { options } = &next.step else {
        anyhow::bail!("factor selection");
    };
    ensure!(options.factors.len() == 1 && options.recovery_code_available);
    Ok(*next)
}

async fn enrolled() -> anyhow::Result<(Router, LoginResponse, Vec<String>)> {
    let app = Router::new().nest(PREFIX, router(fixture().await?));
    let session = decode::<AuthenticationResponse>(
        request(
            &app,
            "/auth/password/login",
            json!({"username":"root","password":"Ar7!cVN23#pxQe$Lr9"}),
            None,
        )
        .await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .ok()
    .context("primary session")?;
    let enrollment: MfaResponse = decode(
        request(
            &app,
            "/credentials/factors",
            json!({"operation":"begin","provider_id":"totp","label":"HTTP continuation"}),
            Some(&session.token),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let MfaResponse::Enrollment {
        challenge_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = enrollment
    else {
        anyhow::bail!("enrollment");
    };
    let updated: MfaResponse = decode(
        request(
            &app,
            "/credentials/factors",
            json!({"operation":"continue","challenge_id":challenge_id,"input":{"kind":"response","response":{"code":totp(&setup)?}}}),
            Some(&session.token),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = updated
    else {
        anyhow::bail!("confirmation");
    };
    Ok((app, session, recovery_codes.context("recovery codes")?))
}

#[tokio::test]
async fn login_continuations_validate_origin_and_optional_authorization_without_consuming()
-> anyhow::Result<()> {
    let (app, _, mut recovery) = enrolled().await?;
    let next = choose(&app).await?;
    let body = json!({
        "continuation":next.continuation,
        "input":{"kind":"proof","proof":{"kind":"recovery_code","code":recovery.pop().context("code")?}}
    });
    for (origin, authorization, expected) in [
        (None, vec![], StatusCode::FORBIDDEN),
        (Some("https://other.example"), vec![], StatusCode::FORBIDDEN),
        (
            Some("https://console.local"),
            vec!["Basic token"],
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("https://console.local"),
            vec!["Bearer "],
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("https://console.local"),
            vec!["Bearer one", "Bearer two"],
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("https://console.local"),
            vec!["Bearer one, Bearer two"],
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        for path in ["/auth/continue", "/auth/cancel"] {
            let mut request = Request::builder()
                .method("POST")
                .uri(format!("{PREFIX}{path}"))
                .header(header::HOST, "console.local")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo("127.0.0.1:12345".parse::<SocketAddr>()?));
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            for value in &authorization {
                request = request.header(header::AUTHORIZATION, *value);
            }
            let payload = if path == "/auth/continue" {
                body.clone()
            } else {
                json!({"continuation":next.continuation})
            };
            let response = app
                .clone()
                .oneshot(request.body(Body::from(serde_json::to_vec(&payload)?))?)
                .await?;
            let failure: ConsoleFailure = decode(response, expected).await?;
            ensure!(failure.mfa.is_none());
        }
    }
    let completed = decode::<AuthenticationResponse>(
        request(&app, "/auth/continue", body.clone(), None).await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .ok()
    .context("completed login")?;
    ensure!(completed.authentication.mfa_level() == 2);
    let replay: ConsoleFailure = decode(
        request(&app, "/auth/continue", body, None).await?,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
    Ok(())
}

#[tokio::test]
async fn cancellation_uses_continuation_and_step_up_requires_the_original_bearer()
-> anyhow::Result<()> {
    let (app, owner, mut recovery) = enrolled().await?;
    let next = choose(&app).await?;
    let canceled: Value = decode(
        request(
            &app,
            "/auth/cancel",
            json!({"continuation":next.continuation}),
            None,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    ensure!(canceled.is_null());
    let code = recovery.pop().context("code")?;
    let proof = json!({"kind":"recovery_code","code":code});
    let failure: ConsoleFailure = decode(
        request(
            &app,
            "/auth/continue",
            json!({"continuation":next.continuation,"input":{"kind":"proof","proof":proof}}),
            None,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    ensure!(failure.code == ConsoleErrorCode::NotAuthenticated);
    // The canceled attempt never consumes its account recovery proof.
    let other = decode::<AuthenticationResponse>(
        request(
            &app,
            "/auth/password/login",
            json!({"username":"root","password":"Ar7!cVN23#pxQe$Lr9","second_factor":proof}),
            None,
        )
        .await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .ok()
    .context("direct recovery login")?;
    ensure!(other.authentication.mfa_level() == 2 && other.sid != owner.sid);
    let next = decode::<AuthenticationResponse>(
        request(&app, "/session/step-up", json!({}), Some(&owner.token)).await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .err()
    .context("step-up selection")?;
    ensure!(matches!(next.step, AuthenticationStep::ChooseFactor { .. }));
    let body = json!({"continuation":next.continuation});
    for bearer in [None, Some(other.token.as_str())] {
        let failure: ConsoleFailure = decode(
            request(&app, "/auth/cancel", body.clone(), bearer).await?,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        ensure!(failure.code == ConsoleErrorCode::NotAuthenticated);
    }
    let canceled: Value = decode(
        request(&app, "/auth/cancel", body, Some(&owner.token)).await?,
        StatusCode::OK,
    )
    .await?;
    ensure!(canceled.is_null());
    Ok(())
}
