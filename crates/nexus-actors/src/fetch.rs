//! Fetch provider: `effect://fetch/get`.
//!
//! Safety: SSRF guard — only `http`/`https`, and the host must not be
//! loopback, a private network (IPv4 *or* IPv6), or a `.local`/`.internal`
//! name. `fetch` is `Effectful` (a GET can have side effects / be
//! non-replayable). Large responses are offloaded to a content-addressed
//! [`BlobRef`] so Facts never inline big payloads.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{BlobRef, MethodId, Outcome, OutputMode, Purity, Value};
use std::collections::BTreeMap;
use std::net::Ipv6Addr;

/// Bodies larger than this are offloaded to a blob ref.
/// 1 MiB keeps Facts small while inlining typical pages.
pub const INLINE_BODY_LIMIT: usize = 1 << 20;

/// Method names in registration order for `effect://fetch/get`.
pub const FETCH_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "get",
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// Drives `effect://fetch/get`.
pub struct FetchDriver {
    client: reqwest::Client,
    state: Backend,
}

impl FetchDriver {
    /// Create a fetch driver that offloads large responses into `state`.
    pub fn new(state: Backend) -> Self {
        Self {
            client: reqwest::Client::new(),
            state,
        }
    }
}

/// SSRF guard: reject non-http(s), loopback, private ranges, and
/// internal TLDs. Returns the validated URL or an error.
pub fn validate_url(raw: &str) -> Result<url::Url, DriverError> {
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
pub fn body_to_value(bytes: Vec<u8>, mime: Option<String>) -> Value {
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
            .map(str::to_string)
            .or_else(|| {
                input
                    .as_map()
                    .and_then(|m| m.get("url"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .ok_or_else(|| DriverError::Other("fetch requires a url".into()))?;
        let url = validate_url(&raw)?;
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| DriverError::Transport(e.to_string()))?;
        let status = resp.status().as_u16() as i64;
        let mime = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());
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
    use nexus_state::{Backend, InMemoryBackend};
    use nexus_types::{IdentityRef, ProcessId};
    use std::sync::Arc;

    #[test]
    fn ssrf_guard_blocks_internal_targets() {
        assert!(validate_url("http://localhost/x").is_err());
        assert!(validate_url("http://127.0.0.1/x").is_err());
        assert!(validate_url("http://10.0.0.5/x").is_err());
        assert!(validate_url("http://192.168.1.1/x").is_err());
        assert!(validate_url("http://foo.internal/x").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("ftp://example.com/x").is_err());
    }

    #[test]
    fn public_https_allowed() {
        assert!(validate_url("https://example.com/path").is_ok());
    }

    #[test]
    fn ssrf_guard_blocks_private_ipv6() {
        // loopback ::1 and unspecified ::
        assert!(validate_url("http://[::1]/x").is_err());
        assert!(validate_url("http://[::]/x").is_err());
        // unique-local fc00::/7 (both fc00.. and fd00..)
        assert!(validate_url("http://[fc00::1]/x").is_err());
        assert!(validate_url("http://[fd12:3456::1]/x").is_err());
        // link-local fe80::/10
        assert!(validate_url("http://[fe80::1]/x").is_err());
    }

    #[test]
    fn ssrf_guard_allows_public_ipv6() {
        // 2001:db8::/32 documentation range is global-unicast-shaped.
        assert!(validate_url("http://[2001:db8::1]/x").is_ok());
    }

    #[test]
    fn body_to_value_inlines_small_text() {
        let v = body_to_value(b"hello world".to_vec(), Some("text/plain".into()));
        assert_eq!(v, Value::Str("hello world".into()));
    }

    #[test]
    fn body_to_value_keeps_small_binary_as_bytes() {
        // Invalid UTF-8 below the limit falls back to Bytes, not Str.
        let v = body_to_value(vec![0xff, 0xfe, 0x00], None);
        assert_eq!(v, Value::Bytes(vec![0xff, 0xfe, 0x00]));
    }

    #[test]
    fn body_to_value_offloads_large_body_to_blob() {
        let big = vec![b'a'; INLINE_BODY_LIMIT];
        match body_to_value(big.clone(), Some("application/octet-stream".into())) {
            Value::Blob(b) => {
                assert_eq!(b.size, INLINE_BODY_LIMIT as u64);
                assert_eq!(b.mime.as_deref(), Some("application/octet-stream"));
                assert_eq!(b.hash, blake3::hash(&big).to_hex().to_string());
            }
            other => panic!("expected blob offload, got {other:?}"),
        }
        // One byte under the limit still inlines.
        let small = vec![b'a'; INLINE_BODY_LIMIT - 1];
        assert!(matches!(body_to_value(small, None), Value::Str(_)));
    }

    #[tokio::test]
    async fn persisted_large_body_is_readable_from_blob_store() {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let big = vec![b'a'; INLINE_BODY_LIMIT];
        let value =
            body_to_value_persisted(&state, big.clone(), Some("application/octet-stream".into()))
                .await
                .unwrap();
        let Value::Blob(blob_ref) = value else {
            panic!("expected blob ref");
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
            .unwrap();
        assert_eq!(read, Outcome::Done(Value::Bytes(big)));
    }
}
