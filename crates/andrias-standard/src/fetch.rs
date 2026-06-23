//! Fetch provider: `effect://fetch/get`.
//!
//! Safety: URL admission runs before the request and on every redirect.
//! Literal IPs that are loopback, private, link-local, or unspecified are
//! rejected, as are `.local`/`.internal` names. `fetch` is `Effectful`.
//! Large responses are offloaded to a content-addressed [`BlobRef`] so Facts
//! never inline big payloads.

use andrias_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use andrias_state::Backend;
use andrias_types::{BlobRef, MethodId, Outcome, OutputMode, Purity, Value};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::net::Ipv6Addr;

/// Bodies larger than this are offloaded to a blob ref.
/// 1 MiB keeps Facts small while inlining typical pages.
pub(crate) const INLINE_BODY_LIMIT: usize = 1 << 20;

/// Method names in registration order for `effect://fetch/get`.
pub(crate) const FETCH_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "get",
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// Drives `effect://fetch/get`.
pub(crate) struct FetchDriver {
    client: reqwest::Client,
    state: Backend,
}

impl FetchDriver {
    /// Create a fetch driver that offloads large responses into `state`.
    pub(crate) fn new(state: Backend) -> Result<Self, DriverError> {
        let client = reqwest::Client::builder()
            .redirect(fetch_redirect_policy())
            .build()
            .map_err(|error| DriverError::Other(format!("fetch client init failed: {error}")))?;
        Ok(Self { client, state })
    }
}

fn fetch_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if let Err(error) = validate_redirect_target(attempt.url(), attempt.previous().len()) {
            return attempt.error(error);
        }
        attempt.follow()
    })
}

fn validate_redirect_target(url: &url::Url, previous_len: usize) -> Result<(), String> {
    if previous_len >= 10 {
        return Err("too many redirects".into());
    }
    validate_url(url.as_str()).map_err(|error| format!("redirect target rejected: {error}"))?;
    Ok(())
}

/// SSRF guard: reject non-http(s), loopback, private ranges, and
/// internal TLDs. Returns the validated URL or an error.
pub(crate) fn validate_url(raw: &str) -> Result<url::Url, DriverError> {
    let u = url::Url::parse(raw).map_err(|e| DriverError::Other(format!("bad url: {e}")))?;
    match u.scheme() {
        "http" | "https" => {}
        other => return Err(DriverError::Other(format!("scheme not allowed: {other}"))),
    }
    let host = u
        .host_str()
        .ok_or_else(|| DriverError::Other("url has no host".into()))?;
    if host.ends_with(".local") || host.ends_with(".internal") || host == "localhost" {
        return Err(DriverError::Other(
            "internal host not allowed (SSRF)".into(),
        ));
    }
    // Classify literal IPs via the parsed `Host` so bracketed IPv6 authorities
    // (`http://[::1]/`) are recognized — `host_str` keeps the brackets.
    match u.host() {
        Some(url::Host::Ipv4(ip))
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() =>
        {
            return Err(DriverError::Other(
                "private/loopback IP not allowed (SSRF)".into(),
            ));
        }
        Some(url::Host::Ipv6(ip))
            if ip.is_loopback() || ip.is_unspecified() || is_private_ipv6(&ip) =>
        {
            return Err(DriverError::Other(
                "private/loopback IP not allowed (SSRF)".into(),
            ));
        }
        _ => {}
    }
    Ok(u)
}

/// True for IPv6 ranges that must not be reachable from `fetch`:
/// unique-local `fc00::/7` (covers `fc00::`/`fd00::`) and link-local
/// `fe80::/10`. (Loopback `::1` and unspecified `::` are handled by the
/// stdlib predicates at the call site.) Uses the first segment because the
/// relevant stdlib predicates are still unstable.
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let unique_local = (first & 0xfe00) == 0xfc00; // fc00::/7
    let link_local = (first & 0xffc0) == 0xfe80; // fe80::/10
    unique_local || link_local
}

/// Decide how a fetched response body is surfaced.
/// Small bodies are inlined as a `Str`; bodies at or over [`INLINE_BODY_LIMIT`]
/// are returned as a content-addressed [`Value::Blob`] so the Fact stays small.
/// Callers that produce a BlobRef must also persist the bytes via
/// `body_to_value_persisted`.
pub(crate) fn body_to_value(bytes: Vec<u8>, mime: Option<String>) -> Value {
    if bytes.len() >= INLINE_BODY_LIMIT {
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let size = bytes.len() as u64;
        Value::Blob(BlobRef { hash, size, mime })
    } else {
        match String::from_utf8(bytes) {
            Ok(s) => Value::Str(s),
            Err(e) => Value::Bytes(e.into_bytes()),
        }
    }
}

async fn body_to_value_persisted(
    state: &Backend,
    bytes: Vec<u8>,
    mime: Option<String>,
) -> Result<Value, DriverError> {
    if bytes.len() >= INLINE_BODY_LIMIT {
        Ok(Value::Blob(
            crate::blob::write_blob_bytes(state, bytes, mime).await?,
        ))
    } else {
        Ok(body_to_value(bytes, mime))
    }
}

#[async_trait]
impl Driver for FetchDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let raw = input
            .as_str()
            .or_else(|| {
                input
                    .as_map()
                    .and_then(|m| m.get("url"))
                    .and_then(Value::as_str)
            })
            .ok_or_else(|| DriverError::Other("fetch requires a url".into()))?;
        let url = validate_url(raw)?;
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| DriverError::Transport(e.to_string()))?;
        let status = resp.status().as_u16() as i64;
        let mime = match resp.headers().get(reqwest::header::CONTENT_TYPE) {
            Some(value) => {
                let value = value.to_str().map_err(|error| {
                    DriverError::Transport(format!("bad content-type: {error}"))
                })?;
                Some(value.split(';').next().unwrap_or(value).trim().to_string())
            }
            None => None,
        };
        let body = resp
            .bytes()
            .await
            .map_err(|e| DriverError::Transport(e.to_string()))?;
        let mut m = BTreeMap::new();
        m.insert("status".into(), Value::Int(status));
        // Inline small bodies, offload large ones to a BlobRef.
        m.insert(
            "body".into(),
            body_to_value_persisted(&self.state, body.to_vec(), mime).await?,
        );
        Ok(Outcome::Done(Value::Map(m)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andrias_state::{Backend, InMemoryBackend};
    use andrias_types::{IdentityRef, ProcessId};
    use anyhow::{Context, Result, bail, ensure};
    use std::sync::Arc;

    #[test]
    fn ssrf_guard_blocks_internal_targets() -> Result<()> {
        for url in [
            "http://localhost/x",
            "http://127.0.0.1/x",
            "http://10.0.0.5/x",
            "http://192.168.1.1/x",
            "http://foo.internal/x",
            "file:///etc/passwd",
            "ftp://example.com/x",
        ] {
            ensure!(validate_url(url).is_err(), "url must be blocked: {url}");
        }
        Ok(())
    }

    #[test]
    fn public_https_allowed() -> Result<()> {
        ensure!(
            validate_url("https://example.com/path").is_ok(),
            "public https url must be allowed"
        );
        Ok(())
    }

    #[test]
    fn ssrf_guard_blocks_private_ipv6() -> Result<()> {
        for url in [
            "http://[::1]/x",
            "http://[::]/x",
            "http://[fc00::1]/x",
            "http://[fd12:3456::1]/x",
            "http://[fe80::1]/x",
        ] {
            ensure!(validate_url(url).is_err(), "url must be blocked: {url}");
        }
        Ok(())
    }

    #[test]
    fn ssrf_guard_allows_public_ipv6() -> Result<()> {
        ensure!(
            validate_url("http://[2001:db8::1]/x").is_ok(),
            "public ipv6 url must be allowed"
        );
        Ok(())
    }

    #[test]
    fn redirect_target_uses_same_ssrf_guard() -> Result<()> {
        let private = url::Url::parse("http://127.0.0.1/metadata")
            .context("parse private redirect target")?;
        ensure!(
            validate_redirect_target(&private, 1).is_err(),
            "private redirect target must be blocked"
        );

        let public =
            url::Url::parse("https://example.com/next").context("parse public redirect target")?;
        validate_redirect_target(&public, 1).map_err(anyhow::Error::msg)?;
        ensure!(
            validate_redirect_target(&public, 10).is_err(),
            "redirect loop limit must be enforced"
        );
        Ok(())
    }

    #[test]
    fn body_to_value_inlines_small_text() -> Result<()> {
        let v = body_to_value(b"hello world".to_vec(), Some("text/plain".into()));
        ensure!(
            v == Value::Str("hello world".into()),
            "small text value: {v:?}"
        );
        Ok(())
    }

    #[test]
    fn body_to_value_keeps_small_binary_as_bytes() -> Result<()> {
        let v = body_to_value(vec![0xff, 0xfe, 0x00], None);
        ensure!(
            v == Value::Bytes(vec![0xff, 0xfe, 0x00]),
            "small binary value: {v:?}"
        );
        Ok(())
    }

    #[test]
    fn body_to_value_offloads_large_body_to_blob() -> Result<()> {
        let big = vec![b'a'; INLINE_BODY_LIMIT];
        let expected_hash = blake3::hash(&big).to_hex().to_string();
        match body_to_value(big, Some("application/octet-stream".into())) {
            Value::Blob(b) => {
                ensure!(
                    b.size == INLINE_BODY_LIMIT as u64,
                    "large body size: {}",
                    b.size
                );
                ensure!(
                    b.mime.as_deref() == Some("application/octet-stream"),
                    "large body mime: {:?}",
                    b.mime
                );
                ensure!(b.hash == expected_hash, "large body hash: {}", b.hash);
            }
            other => bail!("expected blob offload, got {other:?}"),
        }
        let small = vec![b'a'; INLINE_BODY_LIMIT - 1];
        ensure!(
            matches!(body_to_value(small, None), Value::Str(_)),
            "small body should stay inline"
        );
        Ok(())
    }

    #[tokio::test]
    async fn persisted_large_body_is_readable_from_blob_store() -> Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let big = vec![b'a'; INLINE_BODY_LIMIT];
        let value =
            body_to_value_persisted(&state, big.clone(), Some("application/octet-stream".into()))
                .await
                .context("persist body to blob store")?;
        let Value::Blob(blob_ref) = value else {
            bail!("expected blob ref");
        };
        let blob = crate::blob::BlobDriver::new(state);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let read = blob
            .call(
                MethodId::new(1),
                Value::Blob(blob_ref),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("read persisted body")?;
        ensure!(
            read == Outcome::Done(Value::Bytes(big)),
            "persisted body read: {read:?}"
        );
        Ok(())
    }
}
