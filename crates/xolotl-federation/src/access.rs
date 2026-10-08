use crate::{FederationError, FederationNodeId, HostedSubject, StreamRef};

/// An operator-owned grant to one stable subject, one presenting node, and
/// one immutable export view. A different device needs its own grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectGrant {
    /// Stable issuer-qualified hosted principal.
    pub subject: HostedSubject,
    /// Only this authenticated node may present the subject.
    pub presenter: FederationNodeId,
    /// Exact stream authorized by this grant.
    pub stream: StreamRef,
    /// Inclusive start of the trusted-time validity window.
    pub not_before_ms: u64,
    /// Exclusive end of the trusted-time validity window.
    pub expires_ms: u64,
    /// Historical range available when this grant is issued.
    pub history: GrantHistory,
    /// Local operator switch; false revokes future disclosure.
    pub enabled: bool,
}

/// Management view of one persisted grant. `history_floor` is the record
/// sequence captured when a `FromGrant` decision was committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectGrantEntry {
    /// Current durable grant.
    pub grant: SubjectGrant,
    /// CAS revision for this exact grant key.
    pub revision: u64,
    /// Stream head captured when `FromGrant` was committed.
    pub history_floor: u64,
}

/// Semantic cursor for an exclusive, bounded management scan. It contains no
/// authority; callers must never accept it as a remote access proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectGrantKey {
    /// Subject component of the exact management key.
    pub subject: HostedSubject,
    /// Presenting node component of the exact management key.
    pub presenter: FederationNodeId,
    /// Stream component of the exact management key.
    pub stream: StreamRef,
}

impl SubjectGrantKey {
    /// Derive a scan key from a concrete grant without copying its authority.
    pub fn from_grant(grant: &SubjectGrant) -> Self {
        Self {
            subject: grant.subject.clone(),
            presenter: grant.presenter,
            stream: grant.stream,
        }
    }

    /// Encode the ordered management cursor with lengths for variable fields.
    pub fn encoded(&self) -> Result<Vec<u8>, FederationError> {
        if !valid_name(&self.subject.namespace) || !valid_name(&self.subject.subject) {
            return Err(FederationError::Invalid("invalid subject grant key"));
        }
        let mut key = Vec::with_capacity(
            48 + 2 + self.subject.namespace.len() + 2 + self.subject.subject.len() + 48 + 64,
        );
        key.extend_from_slice(&self.subject.issuer.as_bytes());
        key.extend_from_slice(&(self.subject.namespace.len() as u16).to_be_bytes());
        key.extend_from_slice(self.subject.namespace.as_bytes());
        key.extend_from_slice(&(self.subject.subject.len() as u16).to_be_bytes());
        key.extend_from_slice(self.subject.subject.as_bytes());
        key.extend_from_slice(self.presenter.as_bytes());
        key.extend_from_slice(self.stream.publisher.as_bytes());
        key.extend_from_slice(self.stream.id.as_bytes());
        Ok(key)
    }
}

/// Historical disclosure rule fixed by one subject grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantHistory {
    /// The subject may request the complete retained view history.
    All,
    /// The store captures the current published high water at grant commit.
    FromGrant,
}

impl SubjectGrant {
    /// Validate ownership, time interval, presenter, and literal subject names.
    pub fn validate(&self, local_node: FederationNodeId) -> Result<(), FederationError> {
        if self.stream.publisher != local_node
            || self.presenter == local_node
            || self.not_before_ms >= self.expires_ms
            || !valid_name(&self.subject.namespace)
            || !valid_name(&self.subject.subject)
        {
            return Err(FederationError::Invalid("invalid subject grant"));
        }
        Ok(())
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
