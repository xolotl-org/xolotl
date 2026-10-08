//! One endpoint catalog drives both HTTP assembly and route discovery.

use super::*;
use axum::routing::{MethodFilter, MethodRouter, get, on};
use serde::Serialize;
use std::collections::BTreeSet;

/// Independently mountable HTTP responsibilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpGroup {
    /// Primary credentials, authentication continuations and public factor discovery.
    Authentication,
    /// Session refresh and second-factor verification.
    Session,
    /// Primary credentials and second-factor enrollment/lifecycle.
    Credentials,
    /// Protobuf request/response calls.
    Calls,
    /// Multiplexed calls and live subscriptions.
    WebSocket,
    /// Listener liveness.
    Health,
}

/// One method/path pair in the unpublished v1 HTTP contract.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpEndpoint {
    /// Password authentication.
    PasswordLogin,
    /// Exchange an externally verified bearer assertion.
    ExternalExchange,
    /// Public-key challenge issuance.
    KeyChallenge,
    /// Signed public-key challenge verification.
    KeyLogin,
    /// Passkey authentication challenge.
    PasskeyChallenge,
    /// Passkey authentication verification.
    PasskeyLogin,
    /// Installed public second-factor providers.
    FactorProviders,
    /// Continue factor verification after primary login or session step-up.
    ContinueAuthentication,
    /// Cancel a pending authentication continuation.
    CancelAuthentication,
    /// Verify fresh second-factor proof.
    StepUp,
    /// Rotate the authenticated session's bearer token.
    Refresh,
    /// Primary credential metadata for the current account.
    CredentialStatus,
    /// Primary credential lifecycle for the current or an authorized account.
    CredentialManagement,
    /// Start passkey registration.
    PasskeyRegistration,
    /// Finish passkey registration.
    PasskeyRegistrationConfirm,
    /// Read the current user's factor status.
    FactorStatus,
    /// Change the current user's factors or recovery codes.
    FactorManagement,
    /// One protobuf ConsoleFrame.call.
    Calls,
    /// Upgrade to the v1 Console WebSocket subprotocol.
    WebSocket,
    /// Listener health check.
    Health,
}

/// An endpoint's mount-relative HTTP contract, with no inferred host URL.
#[derive(Clone, Debug, Serialize)]
pub struct EndpointDescriptor {
    /// Stable discovery identifier.
    pub id: HttpEndpoint,
    /// Independently selectable responsibility.
    pub group: HttpGroup,
    /// HTTP method; Axum also serves HEAD for GET routes.
    pub method: &'static str,
    /// Path relative to the mount point, including its leading slash.
    pub path: &'static str,
    /// Response encoding or upgrade protocol.
    pub encoding: &'static str,
    /// Credential admission: public, primary, bearer, continuation, or
    /// websocket_hello. Step-up continuations also require their original SID's bearer.
    pub authentication: &'static str,
}

impl HttpEndpoint {
    /// All implemented endpoints. Selection controls mounting and discovery together.
    pub const ALL: [Self; 20] = [
        Self::PasswordLogin,
        Self::ExternalExchange,
        Self::KeyChallenge,
        Self::KeyLogin,
        Self::PasskeyChallenge,
        Self::PasskeyLogin,
        Self::FactorProviders,
        Self::ContinueAuthentication,
        Self::CancelAuthentication,
        Self::StepUp,
        Self::Refresh,
        Self::CredentialStatus,
        Self::CredentialManagement,
        Self::PasskeyRegistration,
        Self::PasskeyRegistrationConfirm,
        Self::FactorStatus,
        Self::FactorManagement,
        Self::Calls,
        Self::WebSocket,
        Self::Health,
    ];

    /// Read the canonical method, path, encoding and authentication requirement.
    pub fn descriptor(self) -> EndpointDescriptor {
        use HttpGroup as G;
        let (group, method, path, authentication) = match self {
            Self::PasswordLogin => (G::Authentication, "POST", "/auth/password/login", "primary"),
            Self::ExternalExchange => (G::Authentication, "POST", "/auth/external", "primary"),
            Self::KeyChallenge => (G::Authentication, "POST", "/auth/keys/challenges", "public"),
            Self::KeyLogin => (G::Authentication, "POST", "/auth/keys/login", "primary"),
            Self::PasskeyChallenge => (
                G::Authentication,
                "POST",
                "/auth/passkeys/challenges",
                "public",
            ),
            Self::PasskeyLogin => (G::Authentication, "POST", "/auth/passkeys/login", "primary"),
            Self::FactorProviders => (G::Authentication, "GET", "/auth/factor-providers", "public"),
            Self::ContinueAuthentication => {
                (G::Authentication, "POST", "/auth/continue", "continuation")
            }
            Self::CancelAuthentication => {
                (G::Authentication, "POST", "/auth/cancel", "continuation")
            }
            Self::StepUp => (G::Session, "POST", "/session/step-up", "bearer"),
            Self::Refresh => (G::Session, "POST", "/session/refresh", "bearer"),
            Self::CredentialStatus => (G::Credentials, "GET", "/credentials", "bearer"),
            Self::CredentialManagement => (G::Credentials, "POST", "/credentials", "bearer"),
            Self::PasskeyRegistration => (
                G::Credentials,
                "POST",
                "/credentials/passkeys/registration",
                "bearer",
            ),
            Self::PasskeyRegistrationConfirm => (
                G::Credentials,
                "POST",
                "/credentials/passkeys/registration/confirm",
                "bearer",
            ),
            Self::FactorStatus => (G::Credentials, "GET", "/credentials/factors", "bearer"),
            Self::FactorManagement => (G::Credentials, "POST", "/credentials/factors", "bearer"),
            Self::Calls => (G::Calls, "POST", "/calls", "bearer"),
            Self::WebSocket => (G::WebSocket, "GET", "/ws", "websocket_hello"),
            Self::Health => (G::Health, "GET", "/health", "public"),
        };
        EndpointDescriptor {
            id: self,
            group,
            method,
            path,
            authentication,
            encoding: match self {
                Self::Calls => "application/protobuf",
                Self::WebSocket => crate::protocol::SUBPROTOCOL,
                Self::Health => "text/plain",
                _ => "application/json",
            },
        }
    }

    fn handler(self) -> MethodRouter<Arc<HttpState>> {
        let method = if self.descriptor().method == "GET" {
            MethodFilter::GET
        } else {
            MethodFilter::POST
        };
        match self {
            Self::PasswordLogin => on(method, api_login),
            Self::ExternalExchange => on(method, api_external_exchange),
            Self::KeyChallenge => on(method, api_key_challenge),
            Self::KeyLogin => on(method, api_key_login),
            Self::PasskeyChallenge => on(method, api_passkey_login_begin),
            Self::PasskeyLogin => on(method, api_passkey_login_finish),
            Self::FactorProviders => on(method, api_mfa_providers),
            Self::ContinueAuthentication => on(method, api_continue_authentication),
            Self::CancelAuthentication => on(method, api_cancel_authentication),
            Self::StepUp => on(method, api_step_up),
            Self::Refresh => on(method, api_refresh),
            Self::CredentialStatus => on(method, api_credential_status),
            Self::CredentialManagement => on(method, api_credentials),
            Self::PasskeyRegistration => on(method, api_passkey_register_begin),
            Self::PasskeyRegistrationConfirm => on(method, api_passkey_register_finish),
            Self::FactorStatus => on(method, api_mfa_status),
            Self::FactorManagement => on(method, api_mfa),
            Self::Calls => on(method, calls::call),
            Self::WebSocket => on(method, super::ws::upgrade),
            Self::Health => on(method, || async { "ok" }),
        }
        .layer(DefaultBodyLimit::max(match self {
            Self::Calls => MAX_CALL_BYTES,
            Self::ExternalExchange => MAX_EXTERNAL_ASSERTION_BODY_BYTES,
            _ => MAX_AUTH_BYTES,
        }))
    }
}

/// Manifest for one selected adapter. [`HttpApi::router`] serves it at GET `/`;
/// [`HttpApi::routes`] leaves its publication to the embedding host.
#[derive(Clone, Debug, Serialize)]
pub struct HttpManifest {
    /// Console protocol version, independent of the host's mount prefix.
    pub protocol_version: u16,
    /// Selected endpoint contracts, mounted at these relative paths by either
    /// [`HttpApi::router`] or [`HttpApi::routes`].
    pub endpoints: Vec<EndpointDescriptor>,
    /// Configured adapter security policy; does not attest end-to-end TLS.
    pub transport: crate::protocol::TransportSecuritySummary,
    /// Configured HTTP `Origin` omission policy. A client cannot grant itself
    /// verified automation status through a request header.
    pub originless_clients: OriginlessClientPolicy,
    /// Effective total deadline for receiving an authentication or call body.
    pub request_body_timeout_ms: u64,
    /// Effective WebSocket limits, present only when the upgrade endpoint is mounted.
    /// Duration fields serialize as integer milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket: Option<ConsoleWsConfig>,
}

/// Select HTTP capabilities without depending on any fixed deployment prefix.
///
/// ```no_run
/// # fn mount(state: std::sync::Arc<xolotl_console::http::HttpState>) -> axum::Router {
/// use xolotl_console::http::{HttpApi, HttpEndpoint, HttpGroup};
/// let api = HttpApi::new()
///     .with_group(HttpGroup::Authentication)
///     .with_endpoint(HttpEndpoint::Calls);
/// axum::Router::new().nest("/admin", api.router(state))
/// # }
/// ```
#[derive(Clone, Debug, Default)]
pub struct HttpApi {
    endpoints: BTreeSet<HttpEndpoint>,
}

impl HttpApi {
    /// Start with no operational routes. [`Self::router`] still exposes its manifest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select every implemented HTTP endpoint.
    pub fn all() -> Self {
        Self {
            endpoints: HttpEndpoint::ALL.into(),
        }
    }

    /// Include one endpoint, idempotently.
    pub fn with_endpoint(mut self, endpoint: HttpEndpoint) -> Self {
        self.endpoints.insert(endpoint);
        self
    }

    /// Exclude one endpoint from a previously assembled route set.
    pub fn without_endpoint(mut self, endpoint: HttpEndpoint) -> Self {
        self.endpoints.remove(&endpoint);
        self
    }

    /// Include every endpoint in a responsibility group, idempotently.
    pub fn with_group(mut self, group: HttpGroup) -> Self {
        self.endpoints.extend(
            HttpEndpoint::ALL
                .into_iter()
                .filter(|endpoint| endpoint.descriptor().group == group),
        );
        self
    }

    /// Exclude a responsibility group from a previously assembled route set.
    pub fn without_group(mut self, group: HttpGroup) -> Self {
        self.endpoints
            .retain(|endpoint| endpoint.descriptor().group != group);
        self
    }

    /// Inspect the selected endpoint contracts, relative to this route set's mount.
    /// A host using [`Self::routes`] may publish this at any chosen discovery path
    /// with `Cache-Control: no-store`, as [`Self::router`] does.
    pub fn manifest(&self, state: &HttpState) -> HttpManifest {
        HttpManifest {
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            transport: state.transport_summary(),
            originless_clients: state.originless_clients,
            request_body_timeout_ms: state.request_body_timeout().as_millis() as u64,
            websocket: self
                .endpoints
                .contains(&HttpEndpoint::WebSocket)
                .then(|| state.websocket_config().clone()),
            endpoints: self
                .endpoints
                .iter()
                .map(|endpoint| endpoint.descriptor())
                .collect(),
        }
    }

    /// Build relative routes and their public, non-cacheable GET `/` manifest.
    pub fn router(&self, state: Arc<HttpState>) -> Router {
        let manifest = self.manifest(&state);
        self.routes(state).route(
            "/",
            get(move || {
                let manifest = manifest.clone();
                async move { AuthResponse(manifest) }
            }),
        )
    }

    /// Build only the selected relative routes, without claiming GET `/`.
    ///
    /// Merge this into an existing host router when that router owns its root or
    /// discovery path. If the host publishes [`Self::manifest`] elsewhere, its
    /// endpoint paths remain relative to the mount of these routes; the host
    /// must account for any prefix it adds. The same [`HttpState`] should be
    /// shared by all selected Console routes that share connection admission.
    /// TCP hosts supply Axum `ConnectInfo<SocketAddr>` or
    /// `ConnectInfo<HttpTcpConnection>`; non-TCP hosts attach a verified
    /// [`super::HttpPeer`] extension at their connection boundary.
    pub fn routes(&self, state: Arc<HttpState>) -> Router {
        let mut router = Router::new();
        for endpoint in &self.endpoints {
            router = router.route(endpoint.descriptor().path, endpoint.handler());
        }
        router.with_state(state)
    }
}
