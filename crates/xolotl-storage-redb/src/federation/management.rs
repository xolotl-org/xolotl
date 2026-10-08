use redb::ReadableTable;
use xolotl_federation::{
    AuthorityOwner, ExportAccess, ExportAuthorityEntry, ExportName, FederationError,
    FederationManagement, FederationNodeId, FederationStore, MAX_MANAGEMENT_PAGE, PeerAdmission,
    PeerAdmissionEntry, PeerAuthorityEntry,
};

use super::{
    AdmissionRow, ExportRow, FEDERATION_ADMISSIONS_TABLE, FEDERATION_EXPORTS_TABLE,
    FEDERATION_PEERS_TABLE, NODE_ID_LEN, PeerRow, RedbFederationStore, decode, export_key, storage,
};

fn owner(manifest_owned: bool) -> AuthorityOwner {
    if manifest_owned {
        AuthorityOwner::Manifest
    } else {
        AuthorityOwner::Application
    }
}

fn page_size(max: usize) -> Result<(), FederationError> {
    if max == 0 || max > MAX_MANAGEMENT_PAGE {
        Err(FederationError::Capacity)
    } else {
        Ok(())
    }
}

impl RedbFederationStore {
    /// Manifest-owned peer CAS. It cannot claim an application-owned row.
    pub fn set_manifest_peer_authority(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        self.set_peer_authority_inner(peer, expected_revision, enabled, true)
    }

    /// Manifest-owned export CAS. Both the peer and export must be manifest-owned.
    pub fn set_manifest_export_authority(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError> {
        self.set_export_authority_inner(peer, export, expected_revision, access, true)
    }

    /// List only manifest-owned peer rows for startup reconciliation; these
    /// are management facts, never a remote admission shortcut.
    pub fn list_manifest_peer_authorities(
        &self,
    ) -> Result<Vec<(FederationNodeId, u64, bool)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
        let mut rows = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let row: PeerRow = decode(value.value())?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            if row.manifest_owned {
                let key = <[u8; NODE_ID_LEN]>::try_from(key.value())
                    .map_err(|_error| FederationError::Corrupt)?;
                rows.push((FederationNodeId::from_bytes(key), row.revision, row.enabled));
            }
        }
        Ok(rows)
    }

    /// List only manifest-owned export rows for one peer so omitted entries
    /// can be disabled without changing application-owned rows.
    pub fn list_manifest_export_authorities(
        &self,
        peer: FederationNodeId,
    ) -> Result<Vec<(ExportName, u64, ExportAccess)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_EXPORTS_TABLE).map_err(storage)?;
        let mut rows = Vec::new();
        for entry in table.range(peer.as_bytes().as_slice()..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let key = key.value();
            if !key.starts_with(peer.as_bytes()) {
                break;
            }
            let row: ExportRow = decode(value.value())?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            if row.manifest_owned {
                let name = std::str::from_utf8(&key[NODE_ID_LEN..])
                    .map_err(|_error| FederationError::Corrupt)?;
                rows.push((
                    ExportName::new(name).map_err(|_error| FederationError::Corrupt)?,
                    row.revision,
                    ExportAccess {
                        serve: row.serve,
                        receive: row.receive,
                    },
                ));
            }
        }
        Ok(rows)
    }
}

impl FederationManagement for RedbFederationStore {
    fn local_node(&self) -> FederationNodeId {
        FederationStore::local_node(self)
    }

    fn peer(&self, peer: FederationNodeId) -> Result<Option<PeerAuthorityEntry>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let row = txn
            .open_table(FEDERATION_PEERS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<PeerRow>(value.value()))
            .transpose()?;
        row.map(|row| {
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            Ok(PeerAuthorityEntry {
                peer,
                revision: row.revision,
                enabled: row.enabled,
                owner: owner(row.manifest_owned),
            })
        })
        .transpose()
    }

    fn scan_peers(
        &self,
        after: Option<FederationNodeId>,
        max: usize,
    ) -> Result<Vec<PeerAuthorityEntry>, FederationError> {
        page_size(max)?;
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
        let start = after
            .as_ref()
            .map_or(&[][..], |peer| peer.as_bytes().as_slice());
        let mut rows = Vec::with_capacity(max);
        for entry in table.range(start..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let raw = <[u8; NODE_ID_LEN]>::try_from(key.value())
                .map_err(|_error| FederationError::Corrupt)?;
            let peer = FederationNodeId::from_bytes(raw);
            if after == Some(peer) {
                continue;
            }
            let row: PeerRow = decode(value.value())?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            rows.push(PeerAuthorityEntry {
                peer,
                revision: row.revision,
                enabled: row.enabled,
                owner: owner(row.manifest_owned),
            });
            if rows.len() == max {
                break;
            }
        }
        Ok(rows)
    }

    fn set_peer(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        match FederationStore::set_peer_authority(self, peer, expected_revision, enabled) {
            Err(FederationError::Conflict) => {
                let current = self.peer(peer)?;
                if current
                    .as_ref()
                    .is_some_and(|entry| entry.owner == AuthorityOwner::Manifest)
                {
                    return Err(FederationError::Conflict);
                }
                if current.map(|entry| entry.revision) != expected_revision {
                    return Err(FederationError::RevisionConflict);
                }
                Err(FederationError::Conflict)
            }
            result => result,
        }
    }

    fn export(
        &self,
        peer: FederationNodeId,
        export: &ExportName,
    ) -> Result<Option<ExportAuthorityEntry>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let key = export_key(peer, export);
        let row = txn
            .open_table(FEDERATION_EXPORTS_TABLE)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|value| decode::<ExportRow>(value.value()))
            .transpose()?;
        row.map(|row| {
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            Ok(ExportAuthorityEntry {
                peer,
                export: export.clone(),
                revision: row.revision,
                access: ExportAccess {
                    serve: row.serve,
                    receive: row.receive,
                },
                owner: owner(row.manifest_owned),
            })
        })
        .transpose()
    }

    fn scan_exports(
        &self,
        peer: FederationNodeId,
        after: Option<&ExportName>,
        max: usize,
    ) -> Result<Vec<ExportAuthorityEntry>, FederationError> {
        page_size(max)?;
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_EXPORTS_TABLE).map_err(storage)?;
        let start = after.map_or_else(|| peer.as_bytes().to_vec(), |name| export_key(peer, name));
        let mut rows = Vec::with_capacity(max);
        for entry in table.range(start.as_slice()..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let raw = key.value();
            if !raw.starts_with(peer.as_bytes()) {
                break;
            }
            let name = std::str::from_utf8(&raw[NODE_ID_LEN..])
                .map_err(|_error| FederationError::Corrupt)?;
            let export = ExportName::new(name).map_err(|_error| FederationError::Corrupt)?;
            if after == Some(&export) {
                continue;
            }
            let row: ExportRow = decode(value.value())?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            rows.push(ExportAuthorityEntry {
                peer,
                export,
                revision: row.revision,
                access: ExportAccess {
                    serve: row.serve,
                    receive: row.receive,
                },
                owner: owner(row.manifest_owned),
            });
            if rows.len() == max {
                break;
            }
        }
        Ok(rows)
    }

    fn set_export(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError> {
        match FederationStore::set_export_authority(
            self,
            peer,
            export.clone(),
            expected_revision,
            access,
        ) {
            Err(FederationError::Conflict) => {
                if self
                    .peer(peer)?
                    .is_some_and(|entry| entry.owner == AuthorityOwner::Manifest)
                    || self
                        .export(peer, &export)?
                        .is_some_and(|entry| entry.owner == AuthorityOwner::Manifest)
                {
                    return Err(FederationError::Conflict);
                }
                if self.export(peer, &export)?.map(|entry| entry.revision) != expected_revision {
                    return Err(FederationError::RevisionConflict);
                }
                Err(FederationError::Conflict)
            }
            result => result,
        }
    }

    fn online_admission(
        &self,
        peer: FederationNodeId,
    ) -> Result<Option<PeerAdmissionEntry>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let peer_row = txn
            .open_table(FEDERATION_PEERS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<PeerRow>(value.value()))
            .transpose()?;
        let admission = txn
            .open_table(FEDERATION_ADMISSIONS_TABLE)
            .map_err(storage)?
            .get(peer.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<AdmissionRow>(value.value()))
            .transpose()?;
        match (peer_row, admission) {
            (Some(peer_row), _) if peer_row.revision == 0 => Err(FederationError::Corrupt),
            (_, None) => Ok(None),
            (Some(peer_row), Some(row)) => Ok(Some(PeerAdmissionEntry {
                peer,
                revision: row.revision,
                admission: row.policy()?,
                owner: owner(peer_row.manifest_owned),
            })),
            _ => Err(FederationError::Corrupt),
        }
    }

    fn set_online_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        match self.set_peer_admission(peer, expected_revision, admission) {
            Err(FederationError::Conflict) => {
                if self
                    .peer(peer)?
                    .is_some_and(|entry| entry.owner == AuthorityOwner::Manifest)
                {
                    return Err(FederationError::Conflict);
                }
                if self.online_admission(peer)?.map(|entry| entry.revision) != expected_revision {
                    return Err(FederationError::RevisionConflict);
                }
                Err(FederationError::Conflict)
            }
            result => result,
        }
    }
}
