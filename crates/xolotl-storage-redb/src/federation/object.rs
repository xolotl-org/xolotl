use super::*;
use redb::ReadableTableMetadata;
use xolotl_federation::{
    FederationObjectReadStore, MAX_OBJECT_GRANTS, MAX_OBJECT_TRANSFERS, ObjectGrantId,
    ObjectGrantSpec, ObjectGrantView, ObjectReadAdmission, ObjectReadAuthority, ObjectReadRequest,
};
use xolotl_types::BlobRef;

const NEXT_GRANT_ID_KEY: &str = "object_grant_next_id";
const MAX_RETIRE_BATCH: usize = 256;
const SEND_TRANSFER_KEY_LEN: usize = NODE_ID_LEN + 16;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendTransferRow {
    grant: u64,
    revision: u64,
    expires_at_ms: u64,
}

fn send_transfer_key(request: &ObjectReadRequest) -> [u8; SEND_TRANSFER_KEY_LEN] {
    let mut key = [0; SEND_TRANSFER_KEY_LEN];
    key[..NODE_ID_LEN].copy_from_slice(request.authenticated_presenter.as_bytes());
    key[NODE_ID_LEN..].copy_from_slice(&request.transfer.as_bytes());
    key
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectGrantRow {
    #[serde(with = "fixed_bytes_48")]
    presenter: [u8; NODE_ID_LEN],
    subject: StoredFederationSubject,
    blob: BlobRef,
    range_start: u64,
    range_end: u64,
    expires_at_ms: u64,
    max_total_bytes: u64,
    max_chunk_bytes: u32,
    revision: u64,
    enabled: bool,
    charged_bytes: u64,
}

impl ObjectGrantRow {
    fn new(spec: ObjectGrantSpec) -> Result<Self, FederationError> {
        Ok(Self {
            presenter: *spec.presenter.as_bytes(),
            subject: StoredFederationSubject::from(&spec.subject),
            blob: spec.blob,
            range_start: spec.range_start,
            range_end: spec.range_end,
            expires_at_ms: spec.expires_at_ms,
            max_total_bytes: spec.max_total_bytes,
            max_chunk_bytes: u32::try_from(spec.max_chunk_bytes)
                .map_err(|_error| FederationError::Capacity)?,
            revision: 1,
            enabled: true,
            charged_bytes: 0,
        })
    }

    fn spec(&self) -> Result<ObjectGrantSpec, FederationError> {
        Ok(ObjectGrantSpec {
            presenter: FederationNodeId::from_bytes(self.presenter),
            subject: self.subject.clone().into(),
            blob: self.blob.clone(),
            range_start: self.range_start,
            range_end: self.range_end,
            expires_at_ms: self.expires_at_ms,
            max_total_bytes: self.max_total_bytes,
            max_chunk_bytes: usize::try_from(self.max_chunk_bytes)
                .map_err(|_error| FederationError::Corrupt)?,
        })
    }

    fn validate(&self, local_node: FederationNodeId) -> Result<(), FederationError> {
        if (self.enabled && self.revision != 1)
            || (!self.enabled && self.revision != 2)
            || self.charged_bytes > self.max_total_bytes
        {
            return Err(FederationError::Corrupt);
        }
        self.spec()
            .and_then(|spec| spec.validate(local_node))
            .map_err(|_error| FederationError::Corrupt)
    }

    fn view(
        &self,
        id: ObjectGrantId,
        local_node: FederationNodeId,
    ) -> Result<ObjectGrantView, FederationError> {
        self.validate(local_node)?;
        Ok(ObjectGrantView {
            id,
            spec: self.spec()?,
            revision: self.revision,
            enabled: self.enabled,
            charged_bytes: self.charged_bytes,
        })
    }

    fn check_read(
        &self,
        request: &ObjectReadRequest,
        now_ms: u64,
        local_node: FederationNodeId,
    ) -> Result<(), FederationError> {
        self.validate(local_node)?;
        if !self.enabled
            || now_ms >= self.expires_at_ms
            || self.presenter != *request.authenticated_presenter.as_bytes()
            || self.subject != StoredFederationSubject::from(&request.subject)
            || self.blob != request.blob
        {
            return Err(FederationError::Unauthorized);
        }
        if self.revision != request.expected_revision {
            return Err(FederationError::Conflict);
        }
        let end = request
            .offset
            .checked_add(
                u64::try_from(request.max_bytes).map_err(|_error| FederationError::Capacity)?,
            )
            .ok_or(FederationError::Capacity)?;
        if request.offset < self.range_start || end > self.range_end {
            return Err(FederationError::Unauthorized);
        }
        if request.max_bytes > self.max_chunk_bytes as usize {
            return Err(FederationError::Capacity);
        }
        Ok(())
    }
}

pub(super) fn checked_object_time(
    txn: &WriteTransaction,
    now_ms: u64,
) -> Result<(), FederationError> {
    let mut table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
    let previous = table
        .get(TRUSTED_TIME_KEY)
        .map_err(storage)?
        .map(|value| decode_trusted_time(value.value()))
        .transpose()?;
    if previous.is_some_and(|previous| now_ms < previous) {
        return Err(FederationError::ClockRollback);
    }
    if previous != Some(now_ms) {
        table
            .insert(TRUSTED_TIME_KEY, now_ms.to_be_bytes().as_slice())
            .map_err(storage)?;
    }
    Ok(())
}

fn object_peer_row(
    txn: &WriteTransaction,
    peer: FederationNodeId,
) -> Result<Option<PeerRow>, FederationError> {
    let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
    let row = table
        .get(peer.as_bytes().as_slice())
        .map_err(storage)?
        .map(|saved| decode::<PeerRow>(saved.value()))
        .transpose()?;
    if row.as_ref().is_some_and(|row| row.revision == 0) {
        return Err(FederationError::Corrupt);
    }
    Ok(row)
}

fn check_object_peer(
    txn: &WriteTransaction,
    peer: FederationNodeId,
) -> Result<(), FederationError> {
    if object_peer_row(txn, peer)?.is_some_and(|row| !row.enabled) {
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

fn check_object_read_peer(
    txn: &WriteTransaction,
    request: &ObjectReadRequest,
    authority: ObjectReadAuthority,
    now_ms: u64,
) -> Result<(), FederationError> {
    let peer = request.authenticated_presenter;
    let row = object_peer_row(txn, peer)?;
    let admission_row = txn
        .open_table(FEDERATION_ADMISSIONS_TABLE)
        .map_err(storage)?
        .get(peer.as_bytes().as_slice())
        .map_err(storage)?
        .map(|saved| decode::<AdmissionRow>(saved.value()))
        .transpose()?;
    check_object_read_peer_rows(request, authority, now_ms, row, admission_row)
}

fn check_object_read_peer_rows(
    request: &ObjectReadRequest,
    authority: ObjectReadAuthority,
    now_ms: u64,
    row: Option<PeerRow>,
    admission_row: Option<AdmissionRow>,
) -> Result<(), FederationError> {
    authority.check_request(request, now_ms)?;
    if row.as_ref().is_some_and(|row| row.revision == 0) {
        return Err(FederationError::Corrupt);
    }
    let allowed = match authority.admission() {
        ObjectReadAdmission::Private => {
            if !row.is_some_and(|row| row.enabled) {
                return Err(FederationError::Unauthorized);
            }
            let policy = admission_row
                .ok_or(FederationError::Unauthorized)?
                .policy()?;
            authority.proof().online_generation() >= policy.minimum_online_generation
                && policy
                    .allowed_authorization_digests
                    .contains(&authority.proof().authorization_digest())
        }
        ObjectReadAdmission::Unconfigured => row.is_none() && admission_row.is_none(),
    };
    if !allowed {
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

impl FederationObjectReadStore for RedbFederationStore {
    fn authorize_object_delivery(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(request.authenticated_presenter)?;
        request.validate(self.node)?;
        let (txn, now_ms) = self.begin_delivery_read(now_ms)?;
        let row = txn
            .open_table(FEDERATION_PEERS_TABLE)
            .map_err(storage)?
            .get(request.authenticated_presenter.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<PeerRow>(value.value()))
            .transpose()?;
        let admission = txn
            .open_table(FEDERATION_ADMISSIONS_TABLE)
            .map_err(storage)?
            .get(request.authenticated_presenter.as_bytes().as_slice())
            .map_err(storage)?
            .map(|value| decode::<AdmissionRow>(value.value()))
            .transpose()?;
        check_object_read_peer_rows(request, authority, now_ms, row, admission)?;
        let grant = txn
            .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
            .map_err(storage)?
            .get(request.grant.get())
            .map_err(storage)?
            .map(|value| decode::<ObjectGrantRow>(value.value()))
            .transpose()?
            .ok_or(FederationError::Unauthorized)?;
        grant.check_read(request, now_ms, self.node)?;
        let key = send_transfer_key(request);
        let transfer = txn
            .open_table(FEDERATION_OBJECT_SEND_TRANSFERS_TABLE)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|value| decode::<SendTransferRow>(value.value()))
            .transpose()?
            .ok_or(FederationError::Conflict)?;
        check_send_transfer(&transfer, request, grant.expires_at_ms)
    }

    fn bind_object_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReadStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn issue_object_grant(
        &self,
        spec: ObjectGrantSpec,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        spec.validate(self.node)?;
        if now_ms >= spec.expires_at_ms {
            return Err(FederationError::Unauthorized);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            checked_object_time(txn, now_ms)?;
            check_object_peer(txn, spec.presenter)?;
            let mut grants = txn
                .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
                .map_err(storage)?;
            if grants.len().map_err(storage)? >= MAX_OBJECT_GRANTS as u64 {
                return Err(FederationError::Capacity);
            }
            let id = {
                let mut meta = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
                let previous = meta
                    .get(NEXT_GRANT_ID_KEY)
                    .map_err(storage)?
                    .map(|value| {
                        <[u8; 8]>::try_from(value.value())
                            .map(u64::from_be_bytes)
                            .map_err(|_error| FederationError::Corrupt)
                    })
                    .transpose()?
                    .unwrap_or(0);
                let next = previous.checked_add(1).ok_or(FederationError::Capacity)?;
                meta.insert(NEXT_GRANT_ID_KEY, next.to_be_bytes().as_slice())
                    .map_err(storage)?;
                ObjectGrantId::new(next)?
            };
            let row = ObjectGrantRow::new(spec)?;
            grants
                .insert(id.get(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(grants);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(id, self.node)
        })
    }

    fn object_grant(&self, id: ObjectGrantId) -> Result<Option<ObjectGrantView>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
            .map_err(storage)?;
        table
            .get(id.get())
            .map_err(storage)?
            .map(|saved| decode::<ObjectGrantRow>(saved.value())?.view(id, self.node))
            .transpose()
    }

    fn list_object_grants(&self) -> Result<Vec<ObjectGrantView>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
            .map_err(storage)?;
        if table.len().map_err(storage)? > MAX_OBJECT_GRANTS as u64 {
            return Err(FederationError::Corrupt);
        }
        let mut grants = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let id = ObjectGrantId::new(key.value()).map_err(|_error| FederationError::Corrupt)?;
            grants.push(decode::<ObjectGrantRow>(value.value())?.view(id, self.node)?);
        }
        Ok(grants)
    }

    fn revoke_object_grant(
        &self,
        id: ObjectGrantId,
        expected_revision: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        self.with_decision_write(|txn, _| {
            let mut table = txn
                .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
                .map_err(storage)?;
            let mut row: ObjectGrantRow = table
                .get(id.get())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            row.validate(self.node)?;
            if row.revision != expected_revision || !row.enabled {
                return Err(FederationError::Conflict);
            }
            row.enabled = false;
            row.revision = row
                .revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            table
                .insert(id.get(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(id, self.node)
        })
    }

    fn reserve_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        self.decision_peer(request.authenticated_presenter)?;
        request.validate(self.node)?;
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            checked_object_time(txn, now_ms)?;
            check_object_read_peer(txn, request, authority, now_ms)?;
            let mut table = txn
                .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
                .map_err(storage)?;
            let mut row: ObjectGrantRow = table
                .get(request.grant.get())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::Unauthorized)?;
            row.check_read(request, now_ms, self.node)?;
            row.charged_bytes = row
                .charged_bytes
                .checked_add(
                    u64::try_from(request.max_bytes).map_err(|_error| FederationError::Capacity)?,
                )
                .filter(|charged| *charged <= row.max_total_bytes)
                .ok_or(FederationError::Capacity)?;
            let key = send_transfer_key(request);
            let mut transfers = txn
                .open_table(FEDERATION_OBJECT_SEND_TRANSFERS_TABLE)
                .map_err(storage)?;
            if let Some(saved) = transfers.get(key.as_slice()).map_err(storage)? {
                let previous: SendTransferRow = decode(saved.value())?;
                if previous.grant != request.grant.get()
                    || previous.revision != request.expected_revision
                    || previous.expires_at_ms != row.expires_at_ms
                {
                    return Err(FederationError::Conflict);
                }
            } else {
                if transfers.len().map_err(storage)? >= MAX_OBJECT_TRANSFERS as u64 {
                    return Err(FederationError::Capacity);
                }
                let binding = SendTransferRow {
                    grant: request.grant.get(),
                    revision: request.expected_revision,
                    expires_at_ms: row.expires_at_ms,
                };
                transfers
                    .insert(key.as_slice(), encode(&binding)?.as_slice())
                    .map_err(storage)?;
            }
            drop(transfers);
            table
                .insert(request.grant.get(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(request.grant, self.node)
        })
    }

    fn confirm_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(request.authenticated_presenter)?;
        request.validate(self.node)?;
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            checked_object_time(txn, now_ms)?;
            check_object_read_peer(txn, request, authority, now_ms)?;
            let table = txn
                .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
                .map_err(storage)?;
            let row: ObjectGrantRow = table
                .get(request.grant.get())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::Unauthorized)?;
            row.check_read(request, now_ms, self.node)?;
            drop(table);
            let key = send_transfer_key(request);
            let transfers = txn
                .open_table(FEDERATION_OBJECT_SEND_TRANSFERS_TABLE)
                .map_err(storage)?;
            let binding: SendTransferRow = transfers
                .get(key.as_slice())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::Conflict)?;
            check_send_transfer(&binding, request, row.expires_at_ms)?;
            drop(transfers);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(())
        })
    }

    fn retire_object_grants(&self, now_ms: u64, limit: usize) -> Result<usize, FederationError> {
        if limit == 0 || limit > MAX_RETIRE_BATCH {
            return Err(FederationError::Capacity);
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            checked_object_time(txn, now_ms)?;
            let mut table = txn
                .open_table(FEDERATION_OBJECT_GRANTS_TABLE)
                .map_err(storage)?;
            let mut expired = Vec::new();
            for entry in table.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let row: ObjectGrantRow = decode(value.value())?;
                row.validate(self.node)?;
                if now_ms >= row.expires_at_ms {
                    expired.push(key.value());
                    if expired.len() == limit {
                        break;
                    }
                }
            }
            for id in &expired {
                table.remove(*id).map_err(storage)?;
            }
            drop(table);
            let mut transfers = txn
                .open_table(FEDERATION_OBJECT_SEND_TRANSFERS_TABLE)
                .map_err(storage)?;
            let mut stale = Vec::new();
            for entry in transfers.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let binding: SendTransferRow = decode(value.value())?;
                if binding.expires_at_ms <= now_ms {
                    stale.push(key.value().to_vec());
                }
            }
            for key in &stale {
                transfers.remove(key.as_slice()).map_err(storage)?;
            }
            drop(transfers);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(expired.len())
        })
    }
}

fn check_send_transfer(
    binding: &SendTransferRow,
    request: &ObjectReadRequest,
    expires_at_ms: u64,
) -> Result<(), FederationError> {
    if binding.grant != request.grant.get()
        || binding.revision != request.expected_revision
        || binding.expires_at_ms != expires_at_ms
    {
        return Err(FederationError::Conflict);
    }
    Ok(())
}
