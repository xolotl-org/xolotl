//! Credential-bearing DTOs must be safe to format in adapter diagnostics.

use super::*;
use std::fmt;

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginResponse")
            .field("expires_at", &self.expires_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .field("authentication", &self.authentication)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RootProvisioning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootProvisioning").finish_non_exhaustive()
    }
}

impl fmt::Debug for BootstrapOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPresent => f.write_str("BootstrapOutcome::AlreadyPresent"),
            Self::CreatedFromProvisionedPassword { .. } => f
                .debug_struct("BootstrapOutcome::CreatedFromProvisionedPassword")
                .finish_non_exhaustive(),
            Self::CreatedPreseeded { .. } => f.write_str("BootstrapOutcome::CreatedPreseeded"),
            Self::CreatedRandomPassword { .. } => f
                .debug_struct("BootstrapOutcome::CreatedRandomPassword")
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Debug for KeyLoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyLoginRequest")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PasskeyRegisterFinishRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyRegisterFinishRequest")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PasskeyLoginFinishRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyLoginFinishRequest")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}
