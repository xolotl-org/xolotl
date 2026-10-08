#![forbid(unsafe_code)]

//! `xolotl-console` — the Console Protocol host and management-domain Gateway.
//!
//! Management actions share a Rust service, an HTTP single-call adapter and
//! a WebSocket adapter with subscriptions. Every
//! action runs as a capability-scoped Operation or read-side
//! projection — no privileged backend handle and no raw shell.
//!
//! The default build provides the service and protocol data without an HTTP
//! server. Enable `http` to mount the HTTP/WebSocket adapter or use its listener
//! helper. Independent executions belong to the current host lifecycle.

mod auth;
mod authentication;
pub mod credentials;
mod host_task;
mod host_time;
#[cfg(feature = "http")]
pub mod http;
pub use authentication::{
    AuthenticationContinuation, AuthenticationEvidence, AuthenticationInput,
    AuthenticationResponse, AuthenticationStep, CancelAuthenticationRequest,
    ContinueAuthenticationRequest, ExternalAssertionRequest, PrimaryAuthentication,
    SecondaryAuthentication,
};
pub mod mfa;
mod mgmt;
mod paths;
pub mod protocol;
mod recipes;
mod registry;
pub mod runtime;
pub mod service;
pub mod session_store;
mod state;
pub use runtime::{
    ConsoleExecutionConfig, ConsoleRuntimeConfig, RuntimeCode, RuntimeConfigError, RuntimeRequest,
    RuntimeSubmissionIdentity,
};
pub use service::{
    ConsoleAuthenticationAdmission, ConsoleCallAdmission, ConsoleDelivery,
    ConsoleExecutionShutdown, ConsoleService, ConsoleSubscription, PreparedConsoleResult,
};
pub use session_store::{
    DEFAULT_GLOBAL_SESSION_LIMIT, DEFAULT_MAX_SESSIONS_PER_ACCOUNT, HARD_GLOBAL_SESSION_LIMIT,
    HARD_MAX_SESSIONS_PER_ACCOUNT, MIN_GLOBAL_SESSION_LIMIT, MIN_MAX_SESSIONS_PER_ACCOUNT,
};
mod streams;
pub use streams::ConsoleStreamConfig;
pub mod wire;

pub use auth::{
    AccountAuthority, AccountAuthorityError, AccountFuture, AccountKey, AccountSnapshot, AuthError,
    BootstrapOutcome, ConsoleAuthConfig, ConsoleChallengeConfig, ConsoleWebAuthnConfig,
    CredentialSealer, DEFAULT_IDLE_TTL_MS, DEFAULT_SESSION_TTL_MS, ExternalAssurance,
    ExternalAuthError, ExternalAuthFuture, ExternalPrimaryAuthentication, HARD_ARGON2_CONCURRENCY,
    KeyChallengeRequest, KeyChallengeResponse, KeyLoginRequest, LoginRequest, LoginResponse,
    MAX_IDLE_TTL_MS, MAX_SESSION_TTL_MS, MIN_ARGON2_CONCURRENCY, MIN_IDLE_TTL_MS,
    MIN_SESSION_TTL_MS, PasskeyLoginBeginRequest, PasskeyLoginBeginResponse,
    PasskeyLoginFinishRequest, PasskeyRegisterBeginRequest, PasskeyRegisterBeginResponse,
    PasskeyRegisterFinishRequest, PasskeyRegisterFinishResponse, RootProvisioning, StepUpRequest,
    VerifiedExternalIdentity, bootstrap_root_account, default_argon2_concurrency,
    root_random_password_needed,
};
#[cfg(feature = "http")]
pub use http::{
    ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode, ConsoleTrustedProxyConfig,
    ConsoleUnsafeTransportRelaxation, ConsoleWsConfig, DEFAULT_WS_IDLE_TIMEOUT,
    DEFAULT_WS_MAX_BYTES_PER_SECOND, DEFAULT_WS_MAX_CONNECTIONS_GLOBAL,
    DEFAULT_WS_MAX_CONNECTIONS_PER_ACCOUNT, DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE,
    DEFAULT_WS_MAX_FRAME_BYTES, DEFAULT_WS_MAX_FRAMES_PER_SECOND,
    DEFAULT_WS_MAX_PENDING_EVENT_BYTES, DEFAULT_WS_MAX_SUBSCRIPTIONS, DEFAULT_WS_SEND_TIMEOUT,
    HARD_MAX_WS_BYTES_PER_SECOND, HARD_MAX_WS_CONNECTIONS_GLOBAL,
    HARD_MAX_WS_CONNECTIONS_PER_ACCOUNT, HARD_MAX_WS_CONNECTIONS_PER_SOURCE,
    HARD_MAX_WS_FRAME_BYTES, HARD_MAX_WS_FRAMES_PER_SECOND, HARD_MAX_WS_IDLE_TIMEOUT,
    HARD_MAX_WS_PENDING_EVENT_BYTES, HARD_MAX_WS_SEND_TIMEOUT, HARD_MAX_WS_SUBSCRIPTIONS,
    MIN_WS_CONNECTIONS_GLOBAL, MIN_WS_CONNECTIONS_PER_ACCOUNT, MIN_WS_CONNECTIONS_PER_SOURCE,
    MIN_WS_IDLE_TIMEOUT, MIN_WS_MAX_BYTES_PER_SECOND, MIN_WS_MAX_FRAME_BYTES,
    MIN_WS_MAX_FRAMES_PER_SECOND, MIN_WS_MAX_PENDING_EVENT_BYTES, MIN_WS_MAX_SUBSCRIPTIONS,
    MIN_WS_SEND_TIMEOUT,
};
pub use mgmt::{ConfigAdmissionConfigError, ConfigNamespaceAdmission};
pub use protocol::{
    ActionCall, ActionResult, ClientFrame, ClientHello, ConsoleErrorCode, ConsoleEvent,
    ConsoleFailure, ConsoleFinalizationError, ExecutionReference, OutcomeUnknownDetail,
    PrincipalSummary, ProtocolGreeting, RegistrySnapshot, ServerFrame, StateSourceSummary,
    StreamCall,
};
pub use state::{
    ConsoleConfig, ConsoleConfigError, ConsoleQueryConfig, ConsoleState,
    DEFAULT_QUERY_MAX_FACT_LIMIT, DEFAULT_QUERY_MAX_STATE_LIST_LIMIT,
    DEFAULT_QUERY_MAX_TRACE_LIMIT, HARD_MAX_QUERY_FACT_LIMIT, HARD_MAX_QUERY_STATE_LIST_LIMIT,
    HARD_MAX_QUERY_TRACE_LIMIT, MIN_QUERY_MAX_FACT_LIMIT, MIN_QUERY_MAX_STATE_LIST_LIMIT,
    MIN_QUERY_MAX_TRACE_LIMIT, NoPairingSecretDisplay, PairingSecretDisplay,
};
pub use xolotl_types::UnresolvedOperations;
