//! HTTP preserves the difference between an omitted begin input and JSON null.

use super::*;

#[tokio::test]
async fn built_in_totp_rejects_explicit_null_begin_input_but_accepts_omission() -> anyhow::Result<()>
{
    let state = fixture().await?;
    let app = Router::new().nest(http::API_BASE_PATH, router(state));
    let path = |suffix: &str| format!("{}{suffix}", http::API_BASE_PATH);
    let primary = decode::<AuthenticationResponse>(
        json_request(
            &app,
            &path("/auth/password/login"),
            "POST",
            json!({"username":"root","password":"Ar7!cVN23#pxQe$Lr9"}),
            None,
        )
        .await?,
        StatusCode::OK,
    )
    .await?
    .into_session()
    .map_err(|_continuation| anyhow::anyhow!("primary login"))?;
    let denied: ConsoleFailure = decode(
        json_request(
            &app,
            &path("/credentials/factors"),
            "POST",
            json!({"operation":"begin","provider_id":"totp","label":"Authenticator","input":null}),
            Some(&primary.token),
        )
        .await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    ensure!(denied.code == ConsoleErrorCode::BadRequest);
    let MfaResponse::Enrollment { .. } = decode::<MfaResponse>(
        json_request(
            &app,
            &path("/credentials/factors"),
            "POST",
            json!({"operation":"begin","provider_id":"totp","label":"Authenticator"}),
            Some(&primary.token),
        )
        .await?,
        StatusCode::OK,
    )
    .await?
    else {
        anyhow::bail!("TOTP enrollment without begin input");
    };
    Ok(())
}
