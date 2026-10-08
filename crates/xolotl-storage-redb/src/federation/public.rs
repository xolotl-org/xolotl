use super::*;
use redb::ReadableTableMetadata;
use xolotl_federation::{
    FederationPublicReadStore, MAX_PUBLIC_POLICIES, MAX_PUBLIC_READ_BYTES, MAX_PUBLIC_READ_RECORDS,
    PublicReadPage, PublicReadRequest, PublicStreamPolicy, PublicStreamView,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicPolicyRow {
    revision: u64,
    enabled: bool,
    max_read_records: u32,
    max_read_bytes: u64,
}

impl PublicPolicyRow {
    fn validate(&self) -> Result<(), FederationError> {
        if self.revision == 0
            || self.max_read_records == 0
            || self.max_read_records as usize > MAX_PUBLIC_READ_RECORDS
            || self.max_read_bytes == 0
            || self.max_read_bytes > MAX_PUBLIC_READ_BYTES as u64
        {
            return Err(FederationError::Corrupt);
        }
        Ok(())
    }

    fn policy(&self, stream: StreamRef) -> Result<(PublicStreamPolicy, u64), FederationError> {
        self.validate()?;
        Ok((
            PublicStreamPolicy {
                stream,
                enabled: self.enabled,
                max_read_records: self.max_read_records as usize,
                max_read_bytes: usize::try_from(self.max_read_bytes)
                    .map_err(|_error| FederationError::Corrupt)?,
            },
            self.revision,
        ))
    }

    fn view(
        &self,
        stream: StreamRef,
        spec: &StreamRow,
    ) -> Result<PublicStreamView, FederationError> {
        self.validate()?;
        spec.validate()?;
        Ok(PublicStreamView {
            stream,
            export: ExportName::new(spec.export.clone())
                .map_err(|_error| FederationError::Corrupt)?,
            policy_revision: self.revision,
            head: spec.head.map(TryInto::try_into).transpose()?,
            minimum_available: spec.minimum_available,
            max_read_records: self.max_read_records as usize,
            max_read_bytes: usize::try_from(self.max_read_bytes)
                .map_err(|_error| FederationError::Corrupt)?,
        })
    }
}

impl FederationPublicReadStore for RedbFederationStore {
    fn authorize_public_delivery(
        &self,
        reader: FederationNodeId,
        stream: StreamRef,
        revision: u64,
    ) -> Result<(), FederationError> {
        self.decision_peer(reader)?;
        let (txn, _) = self.begin_delivery_read(0)?;
        check_public_reader(&txn, reader)?;
        let (policy, _) = public_stream(&txn, stream)?;
        if policy.revision != revision {
            return Err(FederationError::Conflict);
        }
        Ok(())
    }

    fn bind_public_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationPublicReadStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn public_stream_policy(
        &self,
        stream: StreamRef,
    ) -> Result<Option<(PublicStreamPolicy, u64)>, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Invalid(
                "public stream has another publisher",
            ));
        }
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_PUBLIC_STREAMS_TABLE)
            .map_err(storage)?;
        let key = stream_key(stream);
        table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode::<PublicPolicyRow>(saved.value())?.policy(stream))
            .transpose()
    }

    fn list_public_stream_policies(
        &self,
    ) -> Result<Vec<(PublicStreamPolicy, u64)>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_PUBLIC_STREAMS_TABLE)
            .map_err(storage)?;
        if table.len().map_err(storage)? > MAX_PUBLIC_POLICIES as u64 {
            return Err(FederationError::Corrupt);
        }
        let mut policies = Vec::new();
        for entry in table.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let key = key.value();
            if key.len() != STREAM_KEY_LEN || key[..NODE_ID_LEN] != *self.node.as_bytes() {
                return Err(FederationError::Corrupt);
            }
            let stream = StreamRef {
                publisher: self.node,
                id: StreamId::from_bytes(
                    <[u8; 16]>::try_from(&key[NODE_ID_LEN..])
                        .map_err(|_error| FederationError::Corrupt)?,
                ),
            };
            policies.push(decode::<PublicPolicyRow>(value.value())?.policy(stream)?);
        }
        Ok(policies)
    }

    fn set_public_stream_policy(
        &self,
        expected_revision: Option<u64>,
        policy: PublicStreamPolicy,
    ) -> Result<PublicStreamView, FederationError> {
        policy.validate(self.node)?;
        self.with_decision_write(|txn, _| {
            let key = stream_key(policy.stream);
            let spec: StreamRow = {
                let table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::NotFound)?;
                decode(saved.value())?
            };
            spec.validate()?;
            let mut table = txn
                .open_table(FEDERATION_PUBLIC_STREAMS_TABLE)
                .map_err(storage)?;
            let current: Option<PublicPolicyRow> = table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?;
            let revision = match &current {
                Some(row) => {
                    row.validate()?;
                    if expected_revision != Some(row.revision) || (!row.enabled && policy.enabled) {
                        return Err(FederationError::Conflict);
                    }
                    row.revision
                        .checked_add(1)
                        .ok_or(FederationError::Capacity)?
                }
                None => {
                    if expected_revision.is_some() {
                        return Err(FederationError::Conflict);
                    }
                    if !policy.enabled || spec.head.is_some() {
                        return Err(FederationError::Invalid(
                            "public policy must begin on an empty stream",
                        ));
                    }
                    if table.len().map_err(storage)? >= MAX_PUBLIC_POLICIES as u64 {
                        return Err(FederationError::Capacity);
                    }
                    1
                }
            };
            let row = PublicPolicyRow {
                revision,
                enabled: policy.enabled,
                max_read_records: u32::try_from(policy.max_read_records)
                    .map_err(|_error| FederationError::Capacity)?,
                max_read_bytes: u64::try_from(policy.max_read_bytes)
                    .map_err(|_error| FederationError::Capacity)?,
            };
            table
                .insert(key.as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(policy.stream, &spec)
        })
    }

    fn inspect_public_stream(
        &self,
        authenticated_reader: FederationNodeId,
        stream: StreamRef,
    ) -> Result<PublicStreamView, FederationError> {
        self.decision_peer(authenticated_reader)?;
        if authenticated_reader == self.node || stream.publisher != self.node {
            return Err(FederationError::Unauthorized);
        }
        let (txn, _) = self.begin_decision_read()?;
        check_public_reader(&txn, authenticated_reader)?;
        let (policy, spec) = public_stream(&txn, stream)?;
        policy.view(stream, &spec)
    }

    fn read_public_stream(
        &self,
        request: PublicReadRequest,
    ) -> Result<PublicReadPage, FederationError> {
        request.validate(self.node)?;
        let (txn, _) = self.begin_decision_read()?;
        check_public_reader(&txn, request.authenticated_reader)?;
        let (policy, spec) = public_stream(&txn, request.stream)?;
        if policy.revision != request.expected_policy_revision {
            return Err(FederationError::Conflict);
        }
        if request.max_records > policy.max_read_records as usize
            || request.max_bytes as u64 > policy.max_read_bytes
        {
            return Err(FederationError::Capacity);
        }
        let head = spec.head.map(TryInto::try_into).transpose()?;
        let first = if let Some(after) = request.after {
            if !spec.verify_retired_cursor(after)? {
                let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
                let key = record_key(request.stream, after.sequence());
                let saved = table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .ok_or(FederationError::Conflict)?;
                let record = decode_record(request.stream, after.sequence(), saved.value())?;
                if record.digest() != after.digest() {
                    return Err(FederationError::Conflict);
                }
            }
            after
                .sequence()
                .checked_add(1)
                .ok_or(FederationError::Capacity)?
        } else {
            spec.minimum_available
        };
        let prefix = stream_key(request.stream);
        let start = record_key(request.stream, first);
        let table = txn.open_table(FEDERATION_RECORDS_TABLE).map_err(storage)?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let mut expected = first;
        for entry in table.range(start.as_slice()..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let key = key.value();
            if !key.starts_with(&prefix) {
                break;
            }
            let raw =
                <[u8; RECORD_KEY_LEN]>::try_from(key).map_err(|_error| FederationError::Corrupt)?;
            let sequence = u64::from_be_bytes(
                raw[STREAM_KEY_LEN..]
                    .try_into()
                    .map_err(|_error| FederationError::Corrupt)?,
            );
            if sequence != expected {
                return Err(FederationError::Corrupt);
            }
            let record = decode_record(request.stream, sequence, value.value())?;
            let next = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Capacity)?;
            if next > request.max_bytes {
                if records.is_empty() {
                    return Err(FederationError::Capacity);
                }
                break;
            }
            bytes = next;
            records.push(record);
            if records.len() >= request.max_records {
                break;
            }
            expected = expected.checked_add(1).ok_or(FederationError::Capacity)?;
        }
        if records.is_empty() && head.is_some_and(|position: Position| position.sequence() >= first)
        {
            return Err(FederationError::Corrupt);
        }
        Ok(PublicReadPage {
            policy_revision: policy.revision,
            records,
            head,
            minimum_available: spec.minimum_available,
        })
    }
}

fn check_public_reader(
    txn: &ReadTransaction,
    reader: FederationNodeId,
) -> Result<(), FederationError> {
    let table = txn.open_table(FEDERATION_PEERS_TABLE).map_err(storage)?;
    if let Some(saved) = table.get(reader.as_bytes().as_slice()).map_err(storage)? {
        let row: PeerRow = decode(saved.value())?;
        if row.revision == 0 {
            return Err(FederationError::Corrupt);
        }
        // Public-only admission belongs exclusively to unconfigured peers.
        // Check this in the same snapshot as the disclosed stream and records.
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

fn public_stream(
    txn: &ReadTransaction,
    stream: StreamRef,
) -> Result<(PublicPolicyRow, StreamRow), FederationError> {
    let key = stream_key(stream);
    let policy: PublicPolicyRow = {
        let table = txn
            .open_table(FEDERATION_PUBLIC_STREAMS_TABLE)
            .map_err(storage)?;
        let saved = table
            .get(key.as_slice())
            .map_err(storage)?
            .ok_or(FederationError::Unauthorized)?;
        decode(saved.value())?
    };
    policy.validate()?;
    if !policy.enabled {
        return Err(FederationError::Unauthorized);
    }
    let spec: StreamRow = {
        let table = txn.open_table(FEDERATION_STREAMS_TABLE).map_err(storage)?;
        let saved = table
            .get(key.as_slice())
            .map_err(storage)?
            .ok_or(FederationError::Corrupt)?;
        decode(saved.value())?
    };
    spec.validate()?;
    Ok((policy, spec))
}
