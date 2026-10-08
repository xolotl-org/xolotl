//! Authentication entry points shared by embedded hosts and transport adapters.

use super::{ConsoleFailure, ConsoleService, authentication_capacity};
use tokio::sync::OwnedSemaphorePermit;

/// One non-clonable authentication reservation bound to its issuing service.
/// Adapters may hold it while decoding a bounded request, then consume it through
/// an operation below. It holds the existing shared authentication slot through
/// verification or credential mutation, without reacquisition. Dropping the
/// reservation or its operation future releases that slot; it does not undo
/// committed credentials or establish cancellation of an external verifier.
/// Returning a session or continuation releases admission before client think-time.
/// Transport provenance, Origin, body limits and timeouts remain adapter-owned;
/// the reservation grants no account authority and changes no MFA requirements.
#[must_use = "hold the reservation until authentication dispatch or explicitly drop it"]
pub struct ConsoleAuthenticationAdmission {
    service: ConsoleService,
    _capacity: OwnedSemaphorePermit,
}

impl ConsoleService {
    /// Reserve one request before collecting or decoding its credential body.
    /// The returned holder dispatches only through this service. Native methods
    /// acquire the same reservation automatically; custom adapters transfer it.
    pub fn admit_authentication(&self) -> Result<ConsoleAuthenticationAdmission, ConsoleFailure> {
        Ok(ConsoleAuthenticationAdmission {
            _capacity: authentication_capacity(&self.state)?,
            service: self.clone(),
        })
    }

    /// Exchange an opaque assertion using the host-installed trusted verifier
    /// and exact account binding. This is a bearer-assertion flow; it does not
    /// establish possession of an mTLS private key on later connections.
    pub async fn exchange_external(
        &self,
        assertion: &[u8],
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        self.admit_authentication()?
            .exchange_external(assertion, source)
            .await
    }

    /// Discover or change primary credentials. Each mutation uses the same vault
    /// CAS as factor verification, and credential changes invalidate old sessions.
    /// Another account additionally requires recent MFA and user-management
    /// authority covering that account. `source` is the verified peer.
    pub async fn credentials(
        &self,
        bearer: &str,
        request: crate::credentials::CredentialRequest,
        source: String,
    ) -> Result<crate::credentials::CredentialResponse, ConsoleFailure> {
        self.admit_authentication()?
            .credentials(bearer, request, source)
            .await
    }

    /// Discover installed capabilities and host usage permissions without account enrollment.
    pub fn mfa_providers(&self) -> Vec<crate::mfa::MfaProviderSummary> {
        self.state.auth.mfa_providers()
    }

    /// Discover or manage the caller's second factors. Enrollment and credential
    /// changes require a recent login; enrolled accounts also require MFA.
    pub async fn mfa(
        &self,
        bearer: &str,
        request: crate::mfa::MfaRequest,
        source: String,
    ) -> Result<crate::mfa::MfaResponse, ConsoleFailure> {
        self.admit_authentication()?
            .mfa(bearer, request, source)
            .await
    }
    /// Start public-key login. The adapter must validate `request.origin` against
    /// its verified request origin before calling this method, and supply the
    /// verified peer as `source`. The challenge binds the origin into its transcript.
    pub async fn begin_key_login(
        &self,
        request: crate::KeyChallengeRequest,
        source: String,
    ) -> Result<crate::KeyChallengeResponse, ConsoleFailure> {
        self.admit_authentication()?
            .begin_key_login(request, source)
            .await
    }

    /// Verify a signed challenge and complete login or offer factor selection. As with
    /// [`Self::begin_key_login`], the adapter must validate the request origin.
    pub async fn finish_key_login(
        &self,
        request: crate::KeyLoginRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        self.admit_authentication()?
            .finish_key_login(request, source)
            .await
    }

    /// Begin passkey registration after recent authentication. An account with
    /// enrolled independent factors also requires MFA level 2. `source` is
    /// the verified peer; WebAuthn uses the host's configured relying party.
    pub async fn begin_passkey_registration(
        &self,
        bearer: &str,
        request: crate::PasskeyRegisterBeginRequest,
        source: String,
    ) -> Result<crate::PasskeyRegisterBeginResponse, ConsoleFailure> {
        self.admit_authentication()?
            .begin_passkey_registration(bearer, request, source)
            .await
    }

    /// Finish the single-use registration ceremony, save the credential and
    /// return a replacement session. Old tokens, SIDs and challenges are invalidated.
    pub async fn finish_passkey_registration(
        &self,
        bearer: &str,
        request: crate::PasskeyRegisterFinishRequest,
        source: String,
    ) -> Result<crate::PasskeyRegisterFinishResponse, ConsoleFailure> {
        self.admit_authentication()?
            .finish_passkey_registration(bearer, request, source)
            .await
    }

    /// Begin passkey login using the host's WebAuthn configuration. `source`
    /// must identify the verified peer for rate limiting and audit.
    pub async fn begin_passkey_login(
        &self,
        request: crate::PasskeyLoginBeginRequest,
        source: String,
    ) -> Result<crate::PasskeyLoginBeginResponse, ConsoleFailure> {
        self.admit_authentication()?
            .begin_passkey_login(request, source)
            .await
    }

    /// Verify the assertion against the configured relying party and issue a session.
    pub async fn finish_passkey_login(
        &self,
        request: crate::PasskeyLoginFinishRequest,
        source: String,
    ) -> Result<crate::LoginResponse, ConsoleFailure> {
        self.admit_authentication()?
            .finish_passkey_login(request, source)
            .await
    }

    /// Password login for embedded hosts. An enrolled account can continue factor
    /// verification without resubmitting its password. `source` is the verified peer.
    pub async fn login(
        &self,
        request: crate::LoginRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        self.admit_authentication()?.login(request, source).await
    }

    /// Verify a fresh independent factor, or begin factor selection for this session.
    /// Successful verification establishes a new recent-authentication window for credentials.
    pub async fn step_up(
        &self,
        bearer: &str,
        request: crate::StepUpRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        self.admit_authentication()?
            .step_up(bearer, request, source)
            .await
    }

    /// Continue factor verification after primary login or session step-up.
    /// Step-up requires a current bearer for the initiating SID on every request;
    /// login continuations carry only authority to finish that authentication.
    /// `source` is the verified peer for admission and audit, not an owner binding.
    pub async fn continue_authentication(
        &self,
        bearer: Option<&str>,
        request: crate::ContinueAuthenticationRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        self.admit_authentication()?
            .continue_authentication(bearer, request, source)
            .await
    }

    /// Cancel a pending authentication using its continuation and original owner
    /// binding. Step-up also requires the initiating session's current bearer.
    /// Cancellation does not undo a verification whose final consumption already won.
    pub async fn cancel_authentication(
        &self,
        bearer: Option<&str>,
        request: crate::CancelAuthenticationRequest,
        source: String,
    ) -> Result<(), ConsoleFailure> {
        self.admit_authentication()?
            .cancel_authentication(bearer, request, source)
            .await
    }

    /// Rotate a bearer token after revalidating the session and active account.
    /// Preserves the session id, MFA level and hard expiration. `source` identifies
    /// the verified peer for auditing. A lost response may require a new login:
    /// the old secret is invalid once rotation succeeds.
    pub async fn refresh(
        &self,
        bearer: &str,
        source: String,
    ) -> Result<crate::LoginResponse, ConsoleFailure> {
        self.admit_authentication()?.refresh(bearer, source).await
    }
}

impl ConsoleAuthenticationAdmission {
    /// Perform [`ConsoleService::exchange_external`] under this reservation’s issuing service.
    pub async fn exchange_external(
        self,
        assertion: &[u8],
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .exchange_external(&service.state.boot, assertion, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::credentials`] under this reservation’s issuing service.
    pub async fn credentials(
        self,
        bearer: &str,
        request: crate::credentials::CredentialRequest,
        source: String,
    ) -> Result<crate::credentials::CredentialResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .manage_credentials(&service.state.boot, bearer, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::mfa`] under this reservation’s issuing service.
    pub async fn mfa(
        self,
        bearer: &str,
        request: crate::mfa::MfaRequest,
        source: String,
    ) -> Result<crate::mfa::MfaResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .manage_mfa(&service.state.boot, bearer, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::begin_key_login`] under this reservation’s issuing service.
    pub async fn begin_key_login(
        self,
        request: crate::KeyChallengeRequest,
        source: String,
    ) -> Result<crate::KeyChallengeResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .begin_key_login(&service.state.boot, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::finish_key_login`] under this reservation’s issuing service.
    pub async fn finish_key_login(
        self,
        request: crate::KeyLoginRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .finish_key_login(&service.state.boot, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::begin_passkey_registration`] under this reservation’s issuing service.
    pub async fn begin_passkey_registration(
        self,
        bearer: &str,
        request: crate::PasskeyRegisterBeginRequest,
        source: String,
    ) -> Result<crate::PasskeyRegisterBeginResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .begin_passkey_registration(&service.state.boot, bearer, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::finish_passkey_registration`] under this reservation’s issuing service.
    pub async fn finish_passkey_registration(
        self,
        bearer: &str,
        request: crate::PasskeyRegisterFinishRequest,
        source: String,
    ) -> Result<crate::PasskeyRegisterFinishResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .finish_passkey_registration(&service.state.boot, bearer, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::begin_passkey_login`] under this reservation’s issuing service.
    pub async fn begin_passkey_login(
        self,
        request: crate::PasskeyLoginBeginRequest,
        source: String,
    ) -> Result<crate::PasskeyLoginBeginResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .begin_passkey_login(&service.state.boot, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::finish_passkey_login`] under this reservation’s issuing service.
    pub async fn finish_passkey_login(
        self,
        request: crate::PasskeyLoginFinishRequest,
        source: String,
    ) -> Result<crate::LoginResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .finish_passkey_login(&service.state.boot, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::login`] under this reservation’s issuing service.
    pub async fn login(
        self,
        request: crate::LoginRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .login(&service.state.boot, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::step_up`] under this reservation’s issuing service.
    pub async fn step_up(
        self,
        bearer: &str,
        request: crate::StepUpRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .step_up(&service.state.boot, bearer, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::continue_authentication`] under this reservation’s issuing service.
    pub async fn continue_authentication(
        self,
        bearer: Option<&str>,
        request: crate::ContinueAuthenticationRequest,
        source: String,
    ) -> Result<crate::AuthenticationResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .continue_authentication(&service.state.boot, bearer, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::cancel_authentication`] under this reservation’s issuing service.
    pub async fn cancel_authentication(
        self,
        bearer: Option<&str>,
        request: crate::CancelAuthenticationRequest,
        source: String,
    ) -> Result<(), ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .cancel_authentication(&service.state.boot, bearer, request, source)
            .await
            .map_err(Into::into)
    }

    /// Perform [`ConsoleService::refresh`] under this reservation’s issuing service.
    pub async fn refresh(
        self,
        bearer: &str,
        source: String,
    ) -> Result<crate::LoginResponse, ConsoleFailure> {
        let Self { service, _capacity } = self;
        service
            .state
            .auth
            .refresh_session(&service.state.boot, bearer, Some(&source))
            .await
            .map_err(Into::into)
    }
}
