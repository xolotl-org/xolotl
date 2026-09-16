use super::*;
use anyhow::ensure;
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::sync::Arc;
use std::task::{Context, Poll};
use tonic::Code;
use tonic::codegen::{Service, http};
use xolotl_gateway::{
    GatewayProfile, GatewayRuntime, GatewayTransportSecurityConfig, GatewayTrustedProxyConfig,
};
use xolotl_kernel::Bootstrap;

use super::super::{ApplicationGrpcConfig, ApplicationIngress};

const AUTHORITY: &str = "api.example:7443";
const TOKEN: &str = "application-auth-test-credential";

fn service(mode: GatewayTransportSecurityMode) -> anyhow::Result<ApplicationGrpcService> {
    let profile = GatewayProfile::new("auth-test")
        .with_bearer_identity("alice-credential", "alice", TOKEN, "process://alice")?
        .with_registered_host(AUTHORITY)?;
    let gateway = GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile)?;
    Ok(ApplicationGrpcService::from_arc_with_config(
        Arc::new(gateway),
        ApplicationGrpcConfig {
            transport_security: GatewayTransportSecurityConfig {
                mode,
                trusted_proxy: GatewayTrustedProxyConfig {
                    peers: vec!["127.0.0.1".parse()?],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )?)
}

struct CaptureRequest;

impl Service<http::Request<tonic::body::Body>> for CaptureRequest {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let mut response = http::Response::new(body);
        *response.headers_mut() = parts.headers;
        *response.extensions_mut() = parts.extensions;
        ready(Ok(response))
    }
}

async fn request(uri: &str, peer: Option<&str>) -> anyhow::Result<Request<()>> {
    let mut request = http::Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(tonic::body::Body::empty())?;
    if let Some(peer) = peer {
        request.extensions_mut().insert(TcpConnectInfo {
            local_addr: Some("127.0.0.1:7443".parse()?),
            remote_addr: Some(peer.parse()?),
        });
    }
    let response = ApplicationIngress::new(CaptureRequest)
        .call(request)
        .await?;
    let (parts, _body) = response.into_parts();
    let mut request = Request::new(());
    *request.metadata_mut() = MetadataMap::from_headers(parts.headers);
    *request.extensions_mut() = parts.extensions;
    Ok(request)
}

#[test]
fn credentials_require_one_unambiguous_bearer() -> anyhow::Result<()> {
    let mut metadata = MetadataMap::new();
    ensure!(bearer(&metadata)?.is_none());
    metadata.insert("authorization", "bEaReR secret".parse()?);
    ensure!(bearer(&metadata)? == Some("secret"));
    metadata.append("authorization", "Bearer another".parse()?);
    ensure!(matches!(bearer(&metadata), Err(error) if error.code() == Code::PermissionDenied));
    for invalid in [
        "Basic secret",
        "Bearer",
        "Bearer ",
        "Bearer  secret",
        "Bearer a b",
    ] {
        metadata.clear();
        metadata.insert("authorization", invalid.parse()?);
        ensure!(matches!(bearer(&metadata), Err(error) if error.code() == Code::Unauthenticated));
    }
    Ok(())
}

#[tokio::test]
async fn actual_authority_and_peer_are_required_before_authentication() -> anyhow::Result<()> {
    let service = service(GatewayTransportSecurityMode::LocalTrusted)?;
    let missing_evidence = Request::new(());
    ensure!(
        matches!(service.authenticate(&missing_evidence).await, Err(status) if status.code() == Code::FailedPrecondition)
    );
    for (uri, peer) in [
        ("/application", Some("127.0.0.1:4000")),
        ("http://api.example:7443/application", None),
        (
            "http://api.example:7443/application",
            Some("192.0.2.1:4000"),
        ),
        (
            "http://api.example:7444/application",
            Some("127.0.0.1:4000"),
        ),
    ] {
        let request = request(uri, peer).await?;
        ensure!(
            matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied)
        );
    }
    let request = request(
        "http://api.example:7443/application",
        Some("127.0.0.1:4000"),
    )
    .await?;
    ensure!(
        service
            .authenticate(&request)
            .await?
            .principal()
            .principal_id()
            == "alice"
    );
    Ok(())
}

#[tokio::test]
async fn metadata_host_and_forwarding_cannot_replace_untrusted_authority() -> anyhow::Result<()> {
    let service = service(GatewayTransportSecurityMode::LocalTrusted)?;
    let mut request = request(
        "http://other.example:7443/application",
        Some("127.0.0.1:4000"),
    )
    .await?;
    request.metadata_mut().insert("host", AUTHORITY.parse()?);
    request
        .metadata_mut()
        .insert("x-forwarded-host", AUTHORITY.parse()?);
    request
        .metadata_mut()
        .insert("x-forwarded-proto", "https".parse()?);
    request
        .metadata_mut()
        .insert("forwarded", "host=api.example:7443;proto=https".parse()?);
    ensure!(
        matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied)
    );
    Ok(())
}

#[tokio::test]
async fn tls_modes_reject_plain_connections_despite_secure_headers() -> anyhow::Result<()> {
    for mode in [
        GatewayTransportSecurityMode::ProductionTls,
        GatewayTransportSecurityMode::MutualTls,
    ] {
        let service = service(mode)?;
        let mut request = request(
            "https://api.example:7443/application",
            Some("127.0.0.1:4000"),
        )
        .await?;
        request
            .metadata_mut()
            .insert("x-forwarded-proto", "https".parse()?);
        request
            .metadata_mut()
            .insert("forwarded", "host=api.example:7443;proto=https".parse()?);
        ensure!(
            matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied)
        );
    }
    Ok(())
}

#[tokio::test]
async fn trusted_proxy_requires_known_peer_secure_proto_and_registered_host() -> anyhow::Result<()>
{
    let service = service(GatewayTransportSecurityMode::TrustedReverseProxy)?;
    for (peer, proto, host, accepted) in [
        ("127.0.0.1:4000", Some("https"), AUTHORITY, true),
        ("127.0.0.2:4000", Some("https"), AUTHORITY, false),
        ("127.0.0.1:4000", None, AUTHORITY, false),
        ("127.0.0.1:4000", Some("http"), AUTHORITY, false),
        ("127.0.0.1:4000", Some("https"), "other.example:7443", false),
    ] {
        let mut request = request("http://backend.example/application", Some(peer)).await?;
        request
            .metadata_mut()
            .insert("x-forwarded-host", host.parse()?);
        if let Some(proto) = proto {
            request
                .metadata_mut()
                .insert("x-forwarded-proto", proto.parse()?);
        }
        let result = service.authenticate(&request).await;
        if accepted {
            ensure!(result?.principal().principal_id() == "alice");
        } else {
            ensure!(matches!(result, Err(status) if status.code() == Code::PermissionDenied));
        }
    }
    let mut request = request("http://backend.example/application", Some("127.0.0.1:4000")).await?;
    request.metadata_mut().insert(
        "forwarded",
        "for=192.0.2.1;host=\"api.example:7443\";proto=https".parse()?,
    );
    ensure!(
        service
            .authenticate(&request)
            .await?
            .principal()
            .principal_id()
            == "alice"
    );
    Ok(())
}

#[tokio::test]
async fn duplicate_or_empty_forwarded_authority_is_rejected() -> anyhow::Result<()> {
    let service = service(GatewayTransportSecurityMode::TrustedReverseProxy)?;
    for header in ["x-forwarded-host", "forwarded"] {
        let mut request =
            request("http://backend.example/application", Some("127.0.0.1:4000")).await?;
        request
            .metadata_mut()
            .insert("x-forwarded-proto", "https".parse()?);
        let value = if header == "forwarded" {
            "host=api.example:7443"
        } else {
            AUTHORITY
        };
        request.metadata_mut().append(header, value.parse()?);
        request.metadata_mut().append(header, value.parse()?);
        ensure!(
            matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied)
        );
    }
    let mut request = request(
        "http://api.example:7443/application",
        Some("127.0.0.1:4000"),
    )
    .await?;
    request
        .metadata_mut()
        .insert("x-forwarded-proto", "https".parse()?);
    request
        .metadata_mut()
        .insert("x-forwarded-host", "".parse()?);
    ensure!(
        matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied)
    );
    Ok(())
}

#[tokio::test]
async fn adopted_proxy_proto_must_be_single_and_nonempty() -> anyhow::Result<()> {
    let service = service(GatewayTransportSecurityMode::TrustedReverseProxy)?;
    for (header, first, second) in [
        ("x-forwarded-proto", "https", Some("http")),
        ("x-forwarded-proto", "https", Some("https")),
        ("x-forwarded-proto", "", None),
        ("forwarded", "proto=https", Some("proto=http")),
        ("forwarded", "proto=", None),
    ] {
        let mut request = request(
            "http://api.example:7443/application",
            Some("127.0.0.1:4000"),
        )
        .await?;
        request.metadata_mut().append(header, first.parse()?);
        if let Some(second) = second {
            request.metadata_mut().append(header, second.parse()?);
        }
        ensure!(
            matches!(service.validate_transport(&request), Err(status) if status.code() == Code::PermissionDenied)
        );
        ensure!(
            matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied)
        );
    }
    Ok(())
}

#[tokio::test]
async fn explicit_proxy_headers_take_precedence_over_unused_forwarded() -> anyhow::Result<()> {
    let service = service(GatewayTransportSecurityMode::TrustedReverseProxy)?;
    let mut request = request("http://backend.example/application", Some("127.0.0.1:4000")).await?;
    request
        .metadata_mut()
        .insert("x-forwarded-proto", "https".parse()?);
    request
        .metadata_mut()
        .insert("x-forwarded-host", AUTHORITY.parse()?);
    request
        .metadata_mut()
        .append("forwarded", "proto=http;host=unused.example".parse()?);
    request
        .metadata_mut()
        .append("forwarded", "proto=http;host=another.example".parse()?);
    ensure!(
        service
            .authenticate(&request)
            .await?
            .principal()
            .principal_id()
            == "alice"
    );
    Ok(())
}
