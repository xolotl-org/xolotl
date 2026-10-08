use super::*;
use anyhow::{Context as _, ensure};
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::sync::Arc;
use std::task::{Context, Poll};
use tonic::Code;
use tonic::codegen::{Service, http};
use tonic::transport::server::TcpConnectInfo;
use xolotl_gateway::{
    GatewayProfile, GatewayRuntime, GatewayTransportSecurityConfig, GatewayTrustedProxyConfig,
};
use xolotl_kernel::Bootstrap;

use super::super::{ApplicationGrpcConfig, ApplicationIngress};
use crate::{GrpcConnectionInfo, GrpcTlsConnectionInfo};

const AUTHORITY: &str = "api.example:7443";
const TOKEN: &str = "application-auth-test-credential-32-bytes";

fn service(mode: GatewayTransportSecurityMode) -> anyhow::Result<ApplicationGrpcService> {
    let profile = GatewayProfile::new("auth-test")
        .with_bearer_identity("alice-credential", "alice", TOKEN, "identity://alice")?
        .with_registered_host(AUTHORITY)?;
    let gateway = GatewayRuntime::new(
        Arc::new(Bootstrap::in_memory()),
        profile,
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )?;
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

#[tokio::test]
async fn cached_acceptance_is_authorized_at_service_stream_emission() -> anyhow::Result<()> {
    use super::super::pb::application_gateway_server::ApplicationGateway;
    use tonic::codegen::tokio_stream::StreamExt;
    use xolotl_gateway::{GatewayPrincipalSurfaceBinding, GatewaySurface};
    use xolotl_kernel::{EchoDriver, MethodSpec};
    use xolotl_types::{OutputMode, Purity, Value};

    let boot = Arc::new(Bootstrap::in_memory());
    let target = boot.register_effect(
        "effect://delivery/echo",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::STREAM_ASYNC,
        )],
        Arc::new(EchoDriver),
    )?;
    let profile = GatewayProfile::new("delivery-test")
        .with_bearer_identity("alice-credential", "alice", TOKEN, "identity://alice")?
        .with_registered_host(AUTHORITY)?
        .with_surface(GatewaySurface::effect_invoke("echo", target))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/delivery/echo"],
        ));
    let gateway = Arc::new(GatewayRuntime::new_manual(
        boot,
        profile,
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )?);
    let service = ApplicationGrpcService::from_arc_with_config(
        gateway.clone(),
        ApplicationGrpcConfig {
            transport_security: GatewayTransportSecurityConfig {
                mode: GatewayTransportSecurityMode::LocalTrusted,
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let request = request(&format!("http://{AUTHORITY}/"), Some("127.0.0.1:50000"))
        .await?
        .map(|()| super::super::pb::SubmitRequest {
            surface_id: "echo".into(),
            payload: Some(xolotl_proto::value_to_pb(&Value::null())),
            output: Some(xolotl_proto::output_mode_to_pb(OutputMode::Stream)),
            provenance: None,
            options: None,
        });
    let mut output = service.submit_output(request).await?.into_inner();
    gateway.replace_profile(GatewayProfile::new("delivery-test").with_revision(2))?;
    let error = output
        .next()
        .await
        .context("missing denied delivery")?
        .err()
        .context("cached Accepted bypassed revocation")?;
    ensure!(error.code() == Code::FailedPrecondition);
    ensure!(error.message() == "outcome unknown; reconcile before retrying");
    ensure!(output.next().await.is_none());
    Ok(())
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
async fn authoritative_connection_facts_do_not_fall_back_to_another_peer() -> anyhow::Result<()> {
    let service = service(GatewayTransportSecurityMode::LocalTrusted)?;
    let mut request = request(
        "http://api.example:7443/application",
        Some("127.0.0.1:4000"),
    )
    .await?;
    request.extensions_mut().insert(GrpcConnectionInfo {
        tcp: TcpConnectInfo {
            local_addr: Some("127.0.0.1:7443".parse()?),
            remote_addr: None,
        },
        tls: None,
    });
    ensure!(
        matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied)
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
async fn host_verified_tls_facts_reach_application_authentication() -> anyhow::Result<()> {
    for mode in [
        GatewayTransportSecurityMode::ProductionTls,
        GatewayTransportSecurityMode::MutualTls,
    ] {
        let service = service(mode)?;
        let mut request = request(
            "http://api.example:7443/application",
            Some("127.0.0.1:4000"),
        )
        .await?;
        request.extensions_mut().insert(GrpcConnectionInfo {
            tcp: TcpConnectInfo {
                local_addr: Some("127.0.0.1:7443".parse()?),
                remote_addr: Some("127.0.0.1:4000".parse()?),
            },
            tls: Some(GrpcTlsConnectionInfo::new(
                if mode == GatewayTransportSecurityMode::MutualTls {
                    vec![vec![1]]
                } else {
                    Vec::new()
                },
            )),
        });
        ensure!(
            service
                .authenticate(&request)
                .await?
                .principal()
                .principal_id()
                == "alice"
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
async fn proxy_header_lists_and_repeated_authority_facts_are_rejected() -> anyhow::Result<()> {
    let service = service(GatewayTransportSecurityMode::TrustedReverseProxy)?;
    for (header, value) in [
        ("x-forwarded-proto", "https, http"),
        ("x-forwarded-host", "api.example:7443, other.example:7443"),
        (
            "forwarded",
            "proto=https;host=api.example:7443, proto=http;host=other.example:7443",
        ),
        (
            "forwarded",
            "proto=https;host=api.example:7443;host=other.example:7443",
        ),
        ("forwarded", "proto=https;proto=http;host=api.example:7443"),
    ] {
        let mut request =
            request("http://backend.example/application", Some("127.0.0.1:4000")).await?;
        if header == "x-forwarded-host" {
            request
                .metadata_mut()
                .insert("x-forwarded-proto", "https".parse()?);
        }
        if header == "x-forwarded-proto" {
            request
                .metadata_mut()
                .insert("x-forwarded-host", AUTHORITY.parse()?);
        }
        request.metadata_mut().insert(header, value.parse()?);
        ensure!(
            matches!(service.authenticate(&request).await, Err(status) if status.code() == Code::PermissionDenied),
            "ambiguous {header}: {value} was accepted"
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
