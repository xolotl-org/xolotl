//! Local operator authority. Implementations own the atomic CAS boundary;
//! this port is not reachable through a federation session.

use crate::{ExportAccess, ExportName, FederationError, FederationNodeId, PeerAdmission};

/// Maximum rows returned by one ordered local management scan.
pub const MAX_MANAGEMENT_PAGE: usize = 256;

/// Which local authority may mutate one peer, admission, or export row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityOwner {
    /// An application or Console management transaction owns the row.
    Application,
    /// Declarative host manifest reconciliation owns the row.
    Manifest,
}

/// Local management view of one peer enablement decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerAuthorityEntry {
    /// Exact peer node identity.
    pub peer: FederationNodeId,
    /// CAS revision of this row.
    pub revision: u64,
    /// Whether private peer operations are currently admitted.
    pub enabled: bool,
    /// Local control plane allowed to update the row.
    pub owner: AuthorityOwner,
}

/// Local management view of directional access to one export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportAuthorityEntry {
    /// Exact peer node identity.
    pub peer: FederationNodeId,
    /// Literal export name.
    pub export: ExportName,
    /// CAS revision of this row.
    pub revision: u64,
    /// Independent serve and receive permissions.
    pub access: ExportAccess,
    /// Local control plane allowed to update the row.
    pub owner: AuthorityOwner,
}

/// Local management view of admitted online keys for one peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdmissionEntry {
    /// Exact peer node identity.
    pub peer: FederationNodeId,
    /// CAS revision of this row.
    pub revision: u64,
    /// Minimum generation and exact allowed authorization digests.
    pub admission: PeerAdmission,
    /// Local control plane allowed to update the row.
    pub owner: AuthorityOwner,
}

/// A host-injected management port, separate from remote delivery and calls.
/// `None` in a CAS means create-only; `Some(revision)` requires that exact row.
/// Scans are ordered, exclusive-after, and bounded by `MAX_MANAGEMENT_PAGE`.
/// Backends performing blocking I/O should be called on a bounded host worker.
pub trait FederationManagement: Send + Sync {
    /// Return the node identity to which this local catalog belongs.
    fn local_node(&self) -> FederationNodeId;

    /// Read one peer row, including its owner and revision.
    fn peer(&self, peer: FederationNodeId) -> Result<Option<PeerAuthorityEntry>, FederationError>;
    /// Scan peer rows in node-ID order after the exclusive cursor.
    fn scan_peers(
        &self,
        after: Option<FederationNodeId>,
        max: usize,
    ) -> Result<Vec<PeerAuthorityEntry>, FederationError>;
    /// Create or update an application-owned peer row with exact CAS.
    fn set_peer(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError>;

    /// Read one peer/export directional authority row.
    fn export(
        &self,
        peer: FederationNodeId,
        export: &ExportName,
    ) -> Result<Option<ExportAuthorityEntry>, FederationError>;
    /// Scan one peer's exports in literal name order after the cursor.
    fn scan_exports(
        &self,
        peer: FederationNodeId,
        after: Option<&ExportName>,
        max: usize,
    ) -> Result<Vec<ExportAuthorityEntry>, FederationError>;
    /// Create or update an application-owned export row with exact CAS.
    fn set_export(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError>;

    /// Read the peer's exact online-key admission policy.
    fn online_admission(
        &self,
        peer: FederationNodeId,
    ) -> Result<Option<PeerAdmissionEntry>, FederationError>;
    /// Create or update an application-owned online admission row with exact CAS.
    fn set_online_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError>;
}
