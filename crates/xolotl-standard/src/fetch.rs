//! Fetch provider: `effect://fetch/get`.
//!
//! Safety: URL admission runs before the request and on every redirect.
//! Literal IPs that are loopback, private, link-local, or unspecified are
//! rejected, as are `.local`/`.internal` names. `fetch` is `Effectful`.
//! Large responses are offloaded to a content-addressed [`xolotl_types::BlobRef`] so Facts
//! never inline big payloads.

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, DriverUsage, MethodSpec, UsageDimension,
};
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{
    MethodId, Outcome, OutputMode, Purity, TaintSet, TaintSource, TaintedValue, Value,
};

/// Bodies larger than this are offloaded to a blob ref.
/// 1 MiB keeps Facts small while inlining typical pages.
pub(crate) const INLINE_BODY_LIMIT: usize = 1 << 20;

/// Method names in registration order for `effect://fetch/get`.
pub(crate) const FETCH_METHODS: &[MethodSpec] =
    &[MethodSpec::new("get", Purity::Effectful, MethodSpec::STREAM_ASYNC).unprotected_input()];

/// Drives `effect://fetch/get`.
pub(crate) struct FetchDriver {
    client: reqwest::Client,
    objects: ObjectStore,
}

impl FetchDriver {
    /// Create a fetch driver with explicit large-object storage capabilities.
    pub(crate) fn new(objects: ObjectStore) -> Result<Self, DriverError> {
        let client = reqwest::Client::builder()
            .redirect(fetch_redirect_policy())
            .build()
            .map_err(|error| DriverError::Other(format!("fetch client init failed: {error}")))?;
        Ok(Self { client, objects })
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

#[async_trait]
impl Driver for FetchDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        if ctx.taint.has_protected() {
            return Err(DriverError::InvalidInput(
                "fetch requires unprotected input".into(),
            ));
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
        let mut resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| DriverError::Transport(e.to_string()))?;
        let status = resp.status().as_u16() as i64;
        let host = resp
            .url()
            .host_str()
            .ok_or_else(|| DriverError::Transport("fetch response URL has no host".into()))?;
        let source = TaintSet::of(TaintSource::Fetched { host: host.into() });
        let mime = match resp.headers().get(reqwest::header::CONTENT_TYPE) {
            Some(value) => {
                let value = value.to_str().map_err(|error| {
                    DriverError::Transport(format!("bad content-type: {error}"))
                })?;
                Some(value.split(';').next().unwrap_or(value).trim().to_string())
            }
            None => None,
        };
        let mut buffer = crate::object::ObjectBuffer::new(
            self.objects.clone(),
            INLINE_BODY_LIMIT - 1,
            mime,
            source.clone().merged(&ctx.taint),
        );
        let mut bytes_read = 0_u64;
        loop {
            let bytes = match resp.chunk().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => break,
                Err(error) => {
                    buffer.abort().await;
                    return buffer
                        .failure(DriverError::Transport(error.to_string()))
                        .into_output("fetch");
                }
            };
            bytes_read = bytes_read
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| DriverError::Other("response byte count exceeds u64".into()))?;
            if output == OutputMode::Stream {
                for chunk in bytes.chunks(crate::object::CHUNK_BYTES) {
                    ctx.emit_tainted(TaintedValue::new(
                        Value::bytes(chunk.to_vec()),
                        source.clone(),
                    ))
                    .await?;
                }
            } else {
                if let Err(error) = buffer.push(&bytes).await {
                    return error.into_output("fetch");
                }
            }
        }
        let mut m = BTreeMap::new();
        m.insert("status".into(), Value::integer(status));
        let body = if output == OutputMode::Stream {
            TaintedValue::pristine(Value::null())
        } else {
            match buffer.finish().await {
                Ok((value, _)) => value,
                Err(error) => return error.into_output("fetch"),
            }
        };
        m.insert("body".into(), body.value);
        Ok(DriverOutput::new(Outcome::Done(Value::map(m)))
            .with_taint(source.merged(&body.taint))
            .with_usage(DriverUsage::from([(
                UsageDimension::BYTES_READ,
                bytes_read,
            )])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

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

    async fn response(
        bytes: Vec<u8>,
        objects: ObjectStore,
    ) -> Result<(FetchDriver, Value, tokio::task::JoinHandle<Result<()>>)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut request = [0_u8; 4096];
            let count = socket.read(&mut request).await?;
            ensure!(count != 0);
            socket.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", bytes.len()).as_bytes()).await?;
            for chunk in bytes.chunks(4096) {
                socket.write_all(chunk).await?;
            }
            Ok(())
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .resolve("public.example", address)
            .build()?;
        Ok((
            FetchDriver { client, objects },
            Value::string(format!("http://public.example:{}/", address.port())),
            server,
        ))
    }

    #[tokio::test]
    async fn response_stream_offloads_at_threshold_and_preserves_source() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let objects =
            xolotl_storage_fs::FileObjectStore::open(directory.path())?.into_object_store();
        for bytes in [
            b"hello".to_vec(),
            vec![0xff, 0xfe],
            vec![b'a'; INLINE_BODY_LIMIT],
        ] {
            let (driver, input, server) = response(bytes.clone(), objects.clone()).await?;
            let output = driver
                .call(
                    MethodId::new(0),
                    input,
                    OutputMode::Unary,
                    &DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)),
                )
                .await?;
            server.await??;
            let source = TaintSet::of(TaintSource::Fetched {
                host: "public.example".into(),
            });
            ensure!(output.taint == source);
            let Outcome::Done(result_value) = output.outcome else {
                bail!("expected response")
            };
            let result = result_value.as_map().context("expected map")?;
            let body = result.get("body").context("expected body")?;
            if bytes.len() >= INLINE_BODY_LIMIT {
                let xolotl_types::ValueView::Blob(reference) = body.view() else {
                    bail!("expected blob")
                };
                ensure!(reference.hash == blake3::hash(&bytes).to_hex().to_string());
                ensure!(reference.size == bytes.len() as u64);
                ensure!(
                    objects
                        .metadata(reference)
                        .await?
                        .context("object was not published")?
                        .taint
                        == source
                );
                let mut chunk = [0_u8; crate::object::CHUNK_BYTES];
                let read = objects.read_chunk(reference, 0, &mut chunk).await?;
                ensure!(chunk[..read.bytes_read] == bytes[..read.bytes_read]);
            } else {
                let expected = match String::from_utf8(bytes) {
                    Ok(text) => Value::string(text),
                    Err(error) => Value::bytes(error.into_bytes()),
                };
                ensure!(body == &expected);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn streamed_fetch_exceeds_window_without_object_storage() -> Result<()> {
        use xolotl_kernel::host::stream::{StreamItem, channel};
        let expected = INLINE_BODY_LIMIT * 2;
        let (driver, input, server) = response(vec![b'a'; expected], ObjectStore::new()).await?;
        let (sink, mut receiver) = channel(xolotl_kernel::stream::StreamWindow::default());
        let context =
            DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
        let read = driver.call(MethodId::new(0), input, OutputMode::Stream, &context);
        let consume = async {
            let mut count = 0;
            while count < expected {
                let StreamItem::Chunk(chunk) = receiver.recv().await.context("expected chunk")?
                else {
                    bail!("unexpected end")
                };
                let value = chunk.into_value();
                ensure!(
                    value.taint
                        == TaintSet::of(TaintSource::Fetched {
                            host: "public.example".into()
                        })
                );
                let Some(bytes) = value.value.as_bytes() else {
                    bail!("expected bytes")
                };
                ensure!(bytes.len() <= crate::object::CHUNK_BYTES);
                count += bytes.len();
            }
            Ok::<_, anyhow::Error>(())
        };
        let (result, consumed) = tokio::join!(read, consume);
        consumed?;
        let output = result?;
        server.await??;
        ensure!(
            output.usage
                == Some(DriverUsage::from([(
                    UsageDimension::BYTES_READ,
                    expected as u64
                )]))
        );
        let Outcome::Done(result_value) = output.outcome else {
            bail!("expected response")
        };
        let result = result_value.as_map().context("expected map")?;
        ensure!(result.get("body") == Some(&Value::null()));
        Ok(())
    }
}
