use std::sync::Arc;

use crate::{
    FederationError, FederationNodeId, FederationObjectClock, PeerAdmission,
    VerifiedFederationPeerProof,
};

/// Locally selected admission path, never a claim from a remote frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationAdmission {
    /// A configured, enabled peer with an exact online-key policy.
    Private,
    /// A proven node with no configured peer row, including no disabled row.
    Unconfigured,
}

/// Immutable authority carried across queues and staged work. Binding does
/// not authorize anything: the backend samples the clock and checks current
/// rows inside each actual business decision's lock or transaction.
#[derive(Clone)]
pub struct FederationDecision {
    proof: VerifiedFederationPeerProof,
    admission: FederationAdmission,
    clock: Arc<dyn FederationObjectClock>,
    unconfigured_policy: Option<Arc<PeerAdmission>>,
}

impl FederationDecision {
    /// The host supplies a trusted wall clock, independent of the authority
    /// store's locks. Clock callbacks must not reenter the bound backend.
    pub fn new(
        proof: VerifiedFederationPeerProof,
        admission: FederationAdmission,
        clock: Arc<dyn FederationObjectClock>,
    ) -> Self {
        Self {
            proof,
            admission,
            clock,
            unconfigured_policy: None,
        }
    }

    /// Pin an unconfigured publisher to the host-owned follow policy. The
    /// backend still rejects every configured peer row at each decision.
    pub fn with_unconfigured_policy(
        mut self,
        policy: PeerAdmission,
    ) -> Result<Self, FederationError> {
        policy.validate()?;
        if self.admission != FederationAdmission::Unconfigured {
            return Err(FederationError::Unauthorized);
        }
        self.unconfigured_policy = Some(Arc::new(policy));
        Ok(self)
    }

    /// Exact node proven on the authenticated connection.
    pub const fn peer(&self) -> FederationNodeId {
        self.proof.node_id()
    }

    /// Sample trusted decision time; never reuse a frame's queued timestamp.
    pub fn now_ms(&self) -> Result<u64, FederationError> {
        self.clock.now_ms()
    }

    /// Check rows read under the same authority lock or business transaction.
    pub fn check(
        &self,
        enabled: Option<bool>,
        policy: Option<&PeerAdmission>,
        trusted_floor_ms: u64,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        if now_ms < trusted_floor_ms {
            return Err(FederationError::ClockRollback);
        }
        if now_ms < self.proof.not_before_ms() || now_ms >= self.proof.expires_ms() {
            return Err(FederationError::Unauthorized);
        }
        match self.admission {
            FederationAdmission::Private => {
                let policy = policy.ok_or(FederationError::Unauthorized)?;
                if enabled != Some(true)
                    || self.proof.online_generation() < policy.minimum_online_generation
                    || !policy
                        .allowed_authorization_digests
                        .contains(&self.proof.authorization_digest())
                {
                    return Err(FederationError::Unauthorized);
                }
            }
            FederationAdmission::Unconfigured if enabled.is_some() => {
                return Err(FederationError::Unauthorized);
            }
            FederationAdmission::Unconfigured => {
                if let Some(policy) = &self.unconfigured_policy
                    && (self.proof.online_generation() < policy.minimum_online_generation
                        || !policy
                            .allowed_authorization_digests
                            .contains(&self.proof.authorization_digest()))
                {
                    return Err(FederationError::Unauthorized);
                }
            }
        }
        Ok(())
    }

    /// Reject a confused local adapter rather than authorizing another node.
    pub fn check_peer(&self, peer: FederationNodeId) -> Result<(), FederationError> {
        if self.peer() != peer {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }
}
