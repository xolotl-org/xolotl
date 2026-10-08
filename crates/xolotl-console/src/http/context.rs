//! HTTP admission and audit; credential policy belongs to ConsoleService.

use super::{HttpFailure, HttpState, OriginlessClientPolicy, peer::VerifiedPeer, transport};
use crate::{AuthError, ConsoleFailure};
use axum::http::{HeaderMap, StatusCode, header};
use std::sync::Arc;

pub(super) fn bearer_or_audit<'a>(
    st: &Arc<HttpState>,
    headers: &'a HeaderMap,
    source: &str,
) -> Result<&'a str, HttpFailure> {
    match bearer_from_headers(headers) {
        Ok(bearer) => Ok(bearer),
        Err(e) => {
            record_http_auth_audit(st, "console_credential", Some(source), "missing_bearer")?;
            Err(auth_error(e))
        }
    }
}

fn bearer_from_headers(headers: &HeaderMap) -> Result<&str, AuthError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let header = values.next().ok_or(AuthError::MissingBearer)?;
    if values.next().is_some() {
        return Err(AuthError::MissingBearer);
    }
    let raw = header.to_str().map_err(|_error| AuthError::MissingBearer)?;
    let (scheme, credentials) = raw.split_once(' ').ok_or(AuthError::MissingBearer)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(AuthError::MissingBearer);
    }
    // HTTP authentication schemes are case-insensitive; Bearer permits one or
    // more SP separators, but not tabs or whitespace inside the credential.
    let bearer = credentials.trim_start_matches(' ');
    if bearer.is_empty()
        || bearer
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',')
    {
        return Err(AuthError::MissingBearer);
    }
    Ok(bearer)
}

/// Absence is allowed for login continuations; a supplied credential must still
/// satisfy the same admission contract as mandatory bearer authentication.
pub(super) fn optional_bearer_or_audit<'a>(
    st: &Arc<HttpState>,
    headers: &'a HeaderMap,
    source: &str,
) -> Result<Option<&'a str>, HttpFailure> {
    if headers.contains_key(header::AUTHORIZATION) {
        bearer_or_audit(st, headers, source).map(Some)
    } else {
        Ok(None)
    }
}

fn record_http_auth_audit(
    st: &Arc<HttpState>,
    event: &'static str,
    source_addr: Option<&str>,
    outcome: &'static str,
) -> Result<(), HttpFailure> {
    if !st.console.boot.kernel().facts().is_enabled() {
        return Ok(());
    }
    st.console
        .boot
        .record_gateway_audit(xolotl_kernel::GatewayAudit {
            event,
            username: None,
            source_addr,
            outcome,
            details: None,
        })
        .map_err(|error| {
            tracing::warn!(
                ?error,
                event,
                outcome,
                source_addr = source_addr.unwrap_or("unknown"),
                "console HTTP audit record failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal authentication error".into(),
            )
                .into()
        })
}

pub(super) fn validate_http_auth_origin(
    st: &Arc<HttpState>,
    headers: &HeaderMap,
    peer: &VerifiedPeer,
    source: &str,
) -> Result<(), HttpFailure> {
    let allow_originless = st.originless_clients == OriginlessClientPolicy::AllowVerifiedAutomation
        && peer.is_verified_automation();
    validate_http_origin(st, headers, peer, source, allow_originless)
}

/// Safe GET endpoints use explicit bearer authentication for private data and
/// may receive no browser `Origin`. They still validate Host and any Origin sent.
pub(super) fn validate_http_read_origin(
    st: &Arc<HttpState>,
    headers: &HeaderMap,
    peer: &VerifiedPeer,
    source: &str,
) -> Result<(), HttpFailure> {
    validate_http_origin(st, headers, peer, source, true)
}

fn validate_http_origin(
    st: &Arc<HttpState>,
    headers: &HeaderMap,
    peer: &VerifiedPeer,
    source: &str,
    allow_originless: bool,
) -> Result<(), HttpFailure> {
    match transport::validate_http_request_headers(
        headers,
        peer.socket_addr(),
        &st.transport_security,
        allow_originless,
    ) {
        Ok(()) => Ok(()),
        Err(message) => {
            record_http_auth_audit(st, "console_credential", Some(source), "origin_denied")?;
            Err((StatusCode::FORBIDDEN, message).into())
        }
    }
}

pub(super) fn validate_http_key_origin(
    st: &Arc<HttpState>,
    headers: &HeaderMap,
    peer: &VerifiedPeer,
    source: &str,
) -> Result<String, HttpFailure> {
    // The signed key transcript binds the actual request Origin. A verified
    // automation verdict cannot substitute for that value.
    match transport::validate_http_auth_headers(headers, peer.socket_addr(), &st.transport_security)
    {
        Ok(origin) => Ok(origin),
        Err(message) => {
            record_http_auth_audit(st, "console_credential", Some(source), "origin_denied")?;
            Err((StatusCode::FORBIDDEN, message).into())
        }
    }
}

pub(super) fn validate_key_login_origin(
    st: &Arc<HttpState>,
    source: &str,
    body_origin: &str,
    request_origin: &str,
) -> Result<(), HttpFailure> {
    if body_origin == request_origin {
        Ok(())
    } else {
        record_http_auth_audit(st, "console_credential", Some(source), "origin_mismatch")?;
        Err((
            StatusCode::FORBIDDEN,
            "public-key login origin must match request origin".into(),
        )
            .into())
    }
}

pub(super) fn auth_error(error: AuthError) -> HttpFailure {
    ConsoleFailure::from(error).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_scheme_is_case_insensitive_and_accepts_multiple_spaces() -> anyhow::Result<()> {
        for raw in [
            "Bearer sid.secret",
            "bearer sid.secret",
            "bEaReR   sid.secret",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(raw));
            ensure!(bearer_from_headers(&headers)? == "sid.secret");
        }
        Ok(())
    }

    #[test]
    fn bearer_rejects_ambiguous_headers_and_malformed_credentials() {
        assert!(bearer_from_headers(&HeaderMap::new()).is_err());
        for raw in [
            "Basic sid.secret",
            "Bearer",
            "Bearer   ",
            " Bearer sid.secret",
            "Bearer\tsid.secret",
            "Bearer \tsid.secret",
            "Bearer sid.secret ",
            "Bearer sid. secret",
            "Bearer sid.\tsecret",
            "Bearer one, Bearer two",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(raw));
            assert!(bearer_from_headers(&headers).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert!(bearer_from_headers(&headers).is_err());
    }
}
