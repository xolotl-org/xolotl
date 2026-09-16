use std::borrow::Cow;
use tonic::metadata::MetadataMap;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::{Request, Status};
use xolotl_gateway::{GatewaySession, GatewayTransportSecurityMode, PresentedCredential};

use super::{ApplicationGrpcService, RequestEvidence};
use crate::transport::{first_forwarded_value, forwarded_header_param, validate_grpc_transport};

impl ApplicationGrpcService {
    pub(super) async fn authenticate<T>(
        &self,
        request: &Request<T>,
    ) -> Result<GatewaySession, Status> {
        let evidence = request
            .extensions()
            .get::<RequestEvidence>()
            .ok_or_else(|| {
                Status::failed_precondition("application ingress evidence is missing")
            })?;
        self.validate_transport(request)?;
        let authority = self
            .authority(request, evidence)?
            .ok_or_else(|| Status::permission_denied("request authority rejected"))?;
        let credential = match bearer(request.metadata())? {
            Some(token) => PresentedCredential::bearer(token),
            None if self.config.transport_security.mode
                == GatewayTransportSecurityMode::MutualTls =>
            {
                let certificates = request
                    .peer_certs()
                    .ok_or_else(|| Status::unauthenticated("authentication failed"))?;
                let leaf = certificates
                    .first()
                    .ok_or_else(|| Status::unauthenticated("authentication failed"))?;
                PresentedCredential::client_certificate_der(leaf.as_ref())
            }
            None => return Err(Status::unauthenticated("authentication failed")),
        };
        let session = self.storage(self.gateway.authenticate(credential)).await?;
        self.gateway
            .validate_session_authority(&session, &authority)
            .map_err(super::gateway_status)?;
        Ok(session)
    }

    fn validate_transport<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let transport = &self.config.transport_security;
        let peer = request.remote_addr().map(|address| address.ip());
        if transport.trusts_peer(peer) && transport.trusted_proxy.honor_x_forwarded_proto {
            let header = if request.metadata().contains_key("x-forwarded-proto") {
                "x-forwarded-proto"
            } else {
                "forwarded"
            };
            let _unambiguous_proto = single_header(request.metadata(), header)?;
        }
        let actual_boundary = match transport.mode {
            GatewayTransportSecurityMode::ProductionTls => request
                .extensions()
                .get::<TlsConnectInfo<TcpConnectInfo>>()
                .is_some(),
            GatewayTransportSecurityMode::MutualTls => request
                .peer_certs()
                .is_some_and(|certificates| !certificates.is_empty()),
            GatewayTransportSecurityMode::TrustedReverseProxy => transport.trusts_peer(peer),
            GatewayTransportSecurityMode::LocalTrusted => peer.is_some_and(|ip| ip.is_loopback()),
            GatewayTransportSecurityMode::UnsafePlaintext
            | GatewayTransportSecurityMode::DisabledForTest => true,
        };
        if !actual_boundary
            || validate_grpc_transport(request.metadata(), peer, transport).is_some()
        {
            return Err(Status::permission_denied("request transport rejected"));
        }
        Ok(())
    }

    fn authority<'a, T>(
        &self,
        request: &Request<T>,
        evidence: &'a RequestEvidence,
    ) -> Result<Option<Cow<'a, str>>, Status> {
        let transport = &self.config.transport_security;
        let peer = request.remote_addr().map(|address| address.ip());
        if transport.trusts_peer(peer) && transport.trusted_proxy.honor_x_forwarded_host {
            let forwarded =
                if let Some(value) = single_header(request.metadata(), "x-forwarded-host")? {
                    Some(first_forwarded_value(value))
                } else {
                    single_header(request.metadata(), "forwarded")?
                        .map(|value| forwarded_header_param(value, "host"))
                };
            if let Some(forwarded) = forwarded {
                return forwarded
                    .map(|authority| Some(Cow::Owned(authority)))
                    .ok_or_else(|| Status::permission_denied("request authority rejected"));
            }
        }
        // Host metadata can be forged independently of HTTP/2 :authority.
        Ok(evidence.authority().map(Cow::Borrowed))
    }
}

fn single_header<'a>(
    metadata: &'a MetadataMap,
    name: &'static str,
) -> Result<Option<&'a str>, Status> {
    if metadata.get_all(name).iter().count() > 1 {
        return Err(Status::permission_denied("ambiguous request metadata"));
    }
    metadata
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map_err(|_error| Status::permission_denied("invalid request metadata"))
        })
        .transpose()
}

fn bearer(metadata: &MetadataMap) -> Result<Option<&str>, Status> {
    let Some(value) = single_header(metadata, "authorization")? else {
        return Ok(None);
    };
    let (_, token) = value
        .split_once(' ')
        .filter(|(scheme, token)| {
            scheme.eq_ignore_ascii_case("bearer")
                && !token.is_empty()
                && !token.bytes().any(|byte| byte.is_ascii_whitespace())
        })
        .ok_or_else(|| Status::unauthenticated("authentication failed"))?;
    Ok(Some(token))
}

#[cfg(test)]
mod tests;
