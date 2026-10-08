use super::*;
use redb::ReadableTableMetadata;
use sha2::{Digest as _, Sha384};
use std::collections::{HashMap, HashSet};
use subtle::ConstantTimeEq as _;
use xolotl_federation::{
    FederationInvitationStore, INVITATION_RECEIPT_RETENTION_MS, InvitationAudience, InvitationId,
    InvitationIssuerAuthority, InvitationIssuerKey, InvitationRedemption, InvitationSpec,
    InvitationView, MAX_INVITATION_ISSUERS, MAX_INVITATIONS, MAX_MANIFEST_PAGE,
    RedeemInvitationRequest,
};

const MAX_RECEIPTS: u64 = 65_536;
const MAX_RETIRE_BATCH: usize = 256;
const INVITATION_HIGH_WATER_KEY: &str = "invitation_id_high_water";
const REQUEST_DOMAIN: &[u8] = b"xolotl.federation.invitation-redemption.v1\0";

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteSubject {
    #[serde(with = "fixed_bytes_48")]
    issuer: [u8; NODE_ID_LEN],
    namespace: String,
    subject: String,
}

impl From<&HostedSubject> for InviteSubject {
    fn from(value: &HostedSubject) -> Self {
        Self {
            issuer: value.issuer.as_bytes(),
            namespace: value.namespace.clone(),
            subject: value.subject.clone(),
        }
    }
}

impl From<InviteSubject> for HostedSubject {
    fn from(value: InviteSubject) -> Self {
        Self {
            issuer: SubjectIssuerId::from_bytes(value.issuer),
            namespace: value.namespace,
            subject: value.subject,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum InviteAudienceRow {
    Named {
        #[serde(with = "fixed_bytes_48")]
        presenter: [u8; NODE_ID_LEN],
        subject: InviteSubject,
    },
    Bearer {
        #[serde(with = "fixed_bytes_48")]
        secret_digest: [u8; DIGEST_LEN],
    },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteSpecRow {
    issuer: InviteSubject,
    #[serde(with = "fixed_bytes_48")]
    publisher: [u8; NODE_ID_LEN],
    stream_id: [u8; 16],
    audience: InviteAudienceRow,
    not_before_ms: u64,
    expires_ms: u64,
    grant_expires_ms: u64,
    max_redemptions: u32,
    from_grant: bool,
}

impl InviteSpecRow {
    fn from_spec(spec: &InvitationSpec) -> Self {
        Self {
            issuer: InviteSubject::from(&spec.issuer),
            publisher: *spec.stream.publisher.as_bytes(),
            stream_id: *spec.stream.id.as_bytes(),
            audience: match &spec.audience {
                InvitationAudience::Named { presenter, subject } => InviteAudienceRow::Named {
                    presenter: *presenter.as_bytes(),
                    subject: InviteSubject::from(subject),
                },
                InvitationAudience::Bearer { secret_digest } => InviteAudienceRow::Bearer {
                    secret_digest: *secret_digest.as_bytes(),
                },
            },
            not_before_ms: spec.not_before_ms,
            expires_ms: spec.expires_ms,
            grant_expires_ms: spec.grant_expires_ms,
            max_redemptions: spec.max_redemptions,
            from_grant: spec.history == GrantHistory::FromGrant,
        }
    }

    fn spec(&self) -> InvitationSpec {
        InvitationSpec {
            issuer: self.issuer.clone().into(),
            stream: StreamRef {
                publisher: FederationNodeId::from_bytes(self.publisher),
                id: StreamId::from_bytes(self.stream_id),
            },
            audience: match &self.audience {
                InviteAudienceRow::Named { presenter, subject } => InvitationAudience::Named {
                    presenter: FederationNodeId::from_bytes(*presenter),
                    subject: subject.clone().into(),
                },
                InviteAudienceRow::Bearer { secret_digest } => InvitationAudience::Bearer {
                    secret_digest: Digest::from_bytes(*secret_digest),
                },
            },
            not_before_ms: self.not_before_ms,
            expires_ms: self.expires_ms,
            grant_expires_ms: self.grant_expires_ms,
            max_redemptions: self.max_redemptions,
            history: if self.from_grant {
                GrantHistory::FromGrant
            } else {
                GrantHistory::All
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationRow {
    spec: InviteSpecRow,
    issuer_authority_revision: u64,
    revision: u64,
    enabled: bool,
    redemptions: u32,
    #[serde(default)]
    manifest_owned: bool,
}

impl InvitationRow {
    fn validate(&self, node: FederationNodeId, id: InvitationId) -> Result<(), FederationError> {
        if self.issuer_authority_revision == 0
            || self.revision == 0
            || self.redemptions > self.spec.max_redemptions
        {
            return Err(FederationError::Corrupt);
        }
        self.spec
            .spec()
            .validate(node, id)
            .map_err(|_error| FederationError::Corrupt)
    }

    fn view(
        &self,
        node: FederationNodeId,
        id: InvitationId,
    ) -> Result<InvitationView, FederationError> {
        self.validate(node, id)?;
        Ok(InvitationView {
            id,
            spec: self.spec.spec(),
            issuer_authority_revision: self.issuer_authority_revision,
            revision: self.revision,
            enabled: self.enabled,
            redemptions: self.redemptions,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerAuthorityRow {
    revision: u64,
    enabled: bool,
    #[serde(default)]
    manifest_owned: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedemptionRow {
    #[serde(with = "fixed_bytes_48")]
    request_digest: [u8; DIGEST_LEN],
    #[serde(with = "fixed_bytes_48")]
    presenter: [u8; NODE_ID_LEN],
    subject: InviteSubject,
    grant_history_floor: u64,
}

fn valid_subject(subject: &HostedSubject) -> bool {
    [&subject.namespace, &subject.subject].iter().all(|value| {
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    })
}

fn issuer_key(issuer: &HostedSubject, stream: StreamRef) -> Result<Vec<u8>, FederationError> {
    if !valid_subject(issuer) {
        return Err(FederationError::Invalid("invalid invitation issuer"));
    }
    let mut key = Vec::with_capacity(
        48 + 2 + issuer.namespace.len() + 2 + issuer.subject.len() + STREAM_KEY_LEN,
    );
    key.extend_from_slice(&issuer.issuer.as_bytes());
    key.extend_from_slice(&(issuer.namespace.len() as u16).to_be_bytes());
    key.extend_from_slice(issuer.namespace.as_bytes());
    key.extend_from_slice(&(issuer.subject.len() as u16).to_be_bytes());
    key.extend_from_slice(issuer.subject.as_bytes());
    key.extend_from_slice(&stream_key(stream));
    Ok(key)
}

fn parse_issuer_key(mut remaining: &[u8]) -> Result<InvitationIssuerKey, FederationError> {
    fn take<'a>(remaining: &mut &'a [u8], len: usize) -> Result<&'a [u8], FederationError> {
        if remaining.len() < len {
            return Err(FederationError::Corrupt);
        }
        let (head, tail) = remaining.split_at(len);
        *remaining = tail;
        Ok(head)
    }
    let original = remaining;
    let issuer = SubjectIssuerId::from_bytes(
        take(&mut remaining, NODE_ID_LEN)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let namespace_len = u16::from_be_bytes(
        take(&mut remaining, 2)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ) as usize;
    let namespace = std::str::from_utf8(take(&mut remaining, namespace_len)?)
        .map_err(|_error| FederationError::Corrupt)?
        .to_owned();
    let subject_len = u16::from_be_bytes(
        take(&mut remaining, 2)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    ) as usize;
    let subject = std::str::from_utf8(take(&mut remaining, subject_len)?)
        .map_err(|_error| FederationError::Corrupt)?
        .to_owned();
    let publisher = FederationNodeId::from_bytes(
        take(&mut remaining, NODE_ID_LEN)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    let id = StreamId::from_bytes(
        take(&mut remaining, 16)?
            .try_into()
            .map_err(|_error| FederationError::Corrupt)?,
    );
    if !remaining.is_empty() {
        return Err(FederationError::Corrupt);
    }
    let key = InvitationIssuerKey {
        issuer: HostedSubject {
            issuer,
            namespace,
            subject,
        },
        stream: StreamRef { publisher, id },
    };
    if issuer_key(&key.issuer, key.stream).map_err(|_error| FederationError::Corrupt)? != original {
        return Err(FederationError::Corrupt);
    }
    Ok(key)
}

fn receipt_key(id: InvitationId, request: RequestId) -> [u8; 32] {
    let mut key = [0; 32];
    key[..16].copy_from_slice(&id.as_bytes());
    key[16..].copy_from_slice(request.as_bytes());
    key
}

fn invitation_high_water_in_write(txn: &WriteTransaction) -> Result<InvitationId, FederationError> {
    let table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
    let bytes = table
        .get(INVITATION_HIGH_WATER_KEY)
        .map_err(storage)?
        .map(|saved| <[u8; 16]>::try_from(saved.value()).map_err(|_error| FederationError::Corrupt))
        .transpose()?
        .unwrap_or([0; 16]);
    Ok(InvitationId::from_bytes(bytes))
}

fn retired_or_unknown(
    txn: &WriteTransaction,
    id: InvitationId,
) -> Result<FederationError, FederationError> {
    let high_water = invitation_high_water_in_write(txn)?;
    Ok(if id.sequence() <= high_water.sequence() {
        FederationError::Indeterminate
    } else {
        FederationError::NotFound
    })
}

fn update_name(hasher: &mut Sha384, name: &str) {
    hasher.update((name.len() as u16).to_be_bytes());
    hasher.update(name.as_bytes());
}

fn request_digest(request: &RedeemInvitationRequest) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(REQUEST_DOMAIN);
    hasher.update(request.invitation.as_bytes());
    hasher.update(request.request_id.as_bytes());
    hasher.update(request.authenticated_presenter.as_bytes());
    hasher.update(request.subject.issuer.as_bytes());
    update_name(&mut hasher, &request.subject.namespace);
    update_name(&mut hasher, &request.subject.subject);
    hasher.update(request.expected_invitation_revision.to_be_bytes());
    match &request.secret {
        Some(secret) => {
            hasher.update([1]);
            hasher.update(secret.digest(request.invitation).as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn issuer_authority(
    txn: &WriteTransaction,
    issuer: &HostedSubject,
    stream: StreamRef,
) -> Result<IssuerAuthorityRow, FederationError> {
    let key = issuer_key(issuer, stream)?;
    let table = txn
        .open_table(FEDERATION_INVITE_ISSUERS_TABLE)
        .map_err(storage)?;
    let row: IssuerAuthorityRow = table
        .get(key.as_slice())
        .map_err(storage)?
        .map(|saved| decode(saved.value()))
        .transpose()?
        .ok_or(FederationError::Unauthorized)?;
    if row.revision == 0 {
        return Err(FederationError::Corrupt);
    }
    Ok(row)
}

fn current_redemption_authority(
    txn: &WriteTransaction,
    invitation_id: InvitationId,
    invitation: &InvitationRow,
    receipt: &RedemptionRow,
    now_ms: u64,
) -> Result<bool, FederationError> {
    let spec = invitation.spec.spec();
    let presenter = FederationNodeId::from_bytes(receipt.presenter);
    let subject: HostedSubject = receipt.subject.clone().into();
    // The caller has already checked this presenter's unconfigured Guest
    // admission in the same write transaction, before reading the receipt.
    let key = subject_grant_key(&subject, presenter, spec.stream);
    let grant = {
        let table = txn
            .open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
            .map_err(storage)?;
        table
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode::<SubjectGrantRow>(saved.value()))
            .transpose()?
    };
    let Some(grant) = grant else {
        return Ok(false);
    };
    grant.validate()?;
    Ok(grant.invitation == Some(invitation_id.as_bytes())
        && grant.enabled
        && grant.revision == 1
        && now_ms >= grant.not_before_ms
        && now_ms < grant.expires_ms)
}

fn check_guest_presenter(
    txn: &WriteTransaction,
    presenter: FederationNodeId,
) -> Result<(), FederationError> {
    let peer = txn
        .open_table(FEDERATION_PEERS_TABLE)
        .map_err(storage)?
        .get(presenter.as_bytes().as_slice())
        .map_err(storage)?
        .map(|saved| decode::<PeerRow>(saved.value()))
        .transpose()?;
    if let Some(peer) = peer {
        if peer.revision == 0 {
            return Err(FederationError::Corrupt);
        }
        return Err(FederationError::Unauthorized);
    }
    Ok(())
}

fn redemption(
    txn: &WriteTransaction,
    invitation_id: InvitationId,
    request_id: RequestId,
    invitation: &InvitationRow,
    receipt: &RedemptionRow,
    now_ms: u64,
) -> Result<InvitationRedemption, FederationError> {
    let spec = invitation.spec.spec();
    let subject: HostedSubject = receipt.subject.clone().into();
    let presenter = FederationNodeId::from_bytes(receipt.presenter);
    let grant = SubjectGrant {
        subject: subject.clone(),
        presenter,
        stream: spec.stream,
        not_before_ms: spec.not_before_ms,
        expires_ms: spec.grant_expires_ms,
        history: spec.history,
        enabled: true,
    };
    Ok(InvitationRedemption {
        invitation: invitation_id,
        request_id,
        presenter,
        subject,
        grant: SubjectGrantEntry {
            grant,
            revision: 1,
            history_floor: receipt.grant_history_floor,
        },
        currently_authorized: current_redemption_authority(
            txn,
            invitation_id,
            invitation,
            receipt,
            now_ms,
        )?,
    })
}

impl RedbFederationStore {
    fn set_issuer_authority_inner(
        &self,
        issuer: &HostedSubject,
        stream: StreamRef,
        expected_revision: Option<u64>,
        enabled: bool,
        manifest_owned: bool,
    ) -> Result<u64, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Invalid("foreign invitation stream"));
        }
        let key = issuer_key(issuer, stream)?;
        self.with_decision_write(|txn, _| {
            let stream_row = txn
                .open_table(FEDERATION_STREAMS_TABLE)
                .map_err(storage)?
                .get(stream_key(stream).as_slice())
                .map_err(storage)?
                .map(|saved| decode::<StreamRow>(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            stream_row.validate()?;
            let mut table = txn
                .open_table(FEDERATION_INVITE_ISSUERS_TABLE)
                .map_err(storage)?;
            let current: Option<IssuerAuthorityRow> = table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?;
            if current.as_ref().is_some_and(|row| row.revision == 0) {
                return Err(FederationError::Corrupt);
            }
            if current
                .as_ref()
                .is_some_and(|row| row.manifest_owned != manifest_owned)
            {
                return Err(FederationError::Conflict);
            }
            if current.is_none() && table.len().map_err(storage)? >= MAX_INVITATION_ISSUERS as u64 {
                return Err(FederationError::Capacity);
            }
            let revision =
                next_revision(current.as_ref().map(|row| row.revision), expected_revision)?;
            table
                .insert(
                    key.as_slice(),
                    encode(&IssuerAuthorityRow {
                        revision,
                        enabled,
                        manifest_owned,
                    })?
                    .as_slice(),
                )
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(revision)
        })
    }

    fn create_invitation_inner(
        &self,
        id: InvitationId,
        spec: InvitationSpec,
        now_ms: u64,
        manifest_owned: bool,
    ) -> Result<InvitationView, FederationError> {
        spec.validate(self.node, id)?;
        if self.decision.is_none() {
            self.checked_time_ms(now_ms)?;
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            super::object::checked_object_time(txn, now_ms)?;
            let high_water = invitation_high_water_in_write(txn)?;
            let mut table = txn
                .open_table(FEDERATION_INVITATIONS_TABLE)
                .map_err(storage)?;
            if let Some(saved) = table.get(id.as_bytes().as_slice()).map_err(storage)? {
                let row: InvitationRow = decode(saved.value())?;
                let view = row.view(self.node, id)?;
                if view.spec != spec || row.manifest_owned != manifest_owned {
                    return Err(FederationError::Conflict);
                }
                return Ok(view);
            }
            if id.sequence() <= high_water.sequence() {
                return Err(FederationError::Indeterminate);
            }
            if now_ms >= spec.expires_ms {
                return Err(FederationError::Unauthorized);
            }
            if table.len().map_err(storage)? >= MAX_INVITATIONS as u64 {
                return Err(FederationError::Capacity);
            }
            let issuer = issuer_authority(txn, &spec.issuer, spec.stream)?;
            if !issuer.enabled || (manifest_owned && !issuer.manifest_owned) {
                return Err(FederationError::Unauthorized);
            }
            let stream = txn
                .open_table(FEDERATION_STREAMS_TABLE)
                .map_err(storage)?
                .get(stream_key(spec.stream).as_slice())
                .map_err(storage)?
                .map(|saved| decode::<StreamRow>(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            stream.validate()?;
            let row = InvitationRow {
                spec: InviteSpecRow::from_spec(&spec),
                issuer_authority_revision: issuer.revision,
                revision: 1,
                enabled: true,
                redemptions: 0,
                manifest_owned,
            };
            table
                .insert(id.as_bytes().as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.open_table(FEDERATION_NODE_TABLE)
                .map_err(storage)?
                .insert(INVITATION_HIGH_WATER_KEY, id.as_bytes().as_slice())
                .map_err(storage)?;
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(self.node, id)
        })
    }
}

impl FederationInvitationStore for RedbFederationStore {
    fn bind_invitation_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationInvitationStore>, FederationError> {
        Ok(std::sync::Arc::new(self.with_decision(decision)?))
    }
    fn local_node(&self) -> FederationNodeId {
        self.node
    }

    fn invitation_high_water(&self) -> Result<InvitationId, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn.open_table(FEDERATION_NODE_TABLE).map_err(storage)?;
        let bytes = table
            .get(INVITATION_HIGH_WATER_KEY)
            .map_err(storage)?
            .map(|saved| {
                <[u8; 16]>::try_from(saved.value()).map_err(|_error| FederationError::Corrupt)
            })
            .transpose()?
            .unwrap_or([0; 16]);
        Ok(InvitationId::from_bytes(bytes))
    }

    fn set_invitation_issuer_authority(
        &self,
        issuer: &HostedSubject,
        stream: StreamRef,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        self.set_issuer_authority_inner(issuer, stream, expected_revision, enabled, false)
    }

    fn invitation_issuer_authority(
        &self,
        issuer: &HostedSubject,
        stream: StreamRef,
    ) -> Result<Option<(u64, bool)>, FederationError> {
        if stream.publisher != self.node {
            return Err(FederationError::Invalid("foreign invitation stream"));
        }
        let key = issuer_key(issuer, stream)?;
        let (txn, _) = self.begin_decision_read()?;
        let row: Option<IssuerAuthorityRow> = txn
            .open_table(FEDERATION_INVITE_ISSUERS_TABLE)
            .map_err(storage)?
            .get(key.as_slice())
            .map_err(storage)?
            .map(|saved| decode(saved.value()))
            .transpose()?;
        row.map(|row| {
            if row.revision == 0 {
                Err(FederationError::Corrupt)
            } else {
                Ok((row.revision, row.enabled))
            }
        })
        .transpose()
    }

    fn set_manifest_invitation_issuer_authority(
        &self,
        issuer: &HostedSubject,
        stream: StreamRef,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        self.set_issuer_authority_inner(issuer, stream, expected_revision, enabled, true)
    }

    fn list_manifest_issuer_authorities(
        &self,
        after: Option<&InvitationIssuerKey>,
        limit: usize,
    ) -> Result<Vec<InvitationIssuerAuthority>, FederationError> {
        if limit == 0 || limit > MAX_MANIFEST_PAGE {
            return Err(FederationError::Capacity);
        }
        let after = after
            .map(|after| issuer_key(&after.issuer, after.stream))
            .transpose()?;
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_INVITE_ISSUERS_TABLE)
            .map_err(storage)?;
        if table.len().map_err(storage)? > MAX_INVITATION_ISSUERS as u64 {
            return Err(FederationError::Corrupt);
        }
        let start = after.as_deref().unwrap_or(&[]);
        let mut entries = Vec::new();
        for entry in table.range(start..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            if after.as_deref() == Some(key.value()) {
                continue;
            }
            let key = parse_issuer_key(key.value())?;
            if key.stream.publisher != self.node {
                return Err(FederationError::Corrupt);
            }
            let row: IssuerAuthorityRow = decode(value.value())?;
            if row.revision == 0 {
                return Err(FederationError::Corrupt);
            }
            if row.manifest_owned {
                entries.push(InvitationIssuerAuthority {
                    key,
                    revision: row.revision,
                    enabled: row.enabled,
                });
                if entries.len() == limit {
                    break;
                }
            }
        }
        Ok(entries)
    }

    fn create_invitation(
        &self,
        id: InvitationId,
        spec: InvitationSpec,
        now_ms: u64,
    ) -> Result<InvitationView, FederationError> {
        self.create_invitation_inner(id, spec, now_ms, false)
    }

    fn create_manifest_invitation(
        &self,
        id: InvitationId,
        spec: InvitationSpec,
        now_ms: u64,
    ) -> Result<InvitationView, FederationError> {
        self.create_invitation_inner(id, spec, now_ms, true)
    }

    fn list_manifest_invitations(
        &self,
        after: Option<InvitationId>,
        limit: usize,
    ) -> Result<Vec<InvitationView>, FederationError> {
        if limit == 0 || limit > MAX_MANIFEST_PAGE {
            return Err(FederationError::Capacity);
        }
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_INVITATIONS_TABLE)
            .map_err(storage)?;
        if table.len().map_err(storage)? > MAX_INVITATIONS as u64 {
            return Err(FederationError::Corrupt);
        }
        let start = after.map_or([0; 16], InvitationId::as_bytes);
        let mut entries = Vec::new();
        for entry in table.range(start.as_slice()..).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            if after.is_some_and(|after| key.value() == after.as_bytes().as_slice()) {
                continue;
            }
            let id = InvitationId::from_bytes(
                <[u8; 16]>::try_from(key.value()).map_err(|_error| FederationError::Corrupt)?,
            );
            let row: InvitationRow = decode(value.value())?;
            let view = row.view(self.node, id)?;
            if row.manifest_owned {
                entries.push(view);
                if entries.len() == limit {
                    break;
                }
            }
        }
        Ok(entries)
    }

    fn invitation(&self, id: InvitationId) -> Result<Option<InvitationView>, FederationError> {
        let (txn, _) = self.begin_decision_read()?;
        let table = txn
            .open_table(FEDERATION_INVITATIONS_TABLE)
            .map_err(storage)?;
        table
            .get(id.as_bytes().as_slice())
            .map_err(storage)?
            .map(|saved| decode::<InvitationRow>(saved.value())?.view(self.node, id))
            .transpose()
    }

    fn revoke_invitation(
        &self,
        id: InvitationId,
        expected_revision: u64,
    ) -> Result<InvitationView, FederationError> {
        self.with_decision_write(|txn, _| {
            let mut table = txn
                .open_table(FEDERATION_INVITATIONS_TABLE)
                .map_err(storage)?;
            let mut row: InvitationRow = table
                .get(id.as_bytes().as_slice())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            row.validate(self.node, id)?;
            if row.revision != expected_revision || !row.enabled {
                return Err(FederationError::Conflict);
            }
            row.enabled = false;
            row.revision = row
                .revision
                .checked_add(1)
                .ok_or(FederationError::Capacity)?;
            table
                .insert(id.as_bytes().as_slice(), encode(&row)?.as_slice())
                .map_err(storage)?;
            drop(table);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            row.view(self.node, id)
        })
    }

    fn redeem_invitation(
        &self,
        request: RedeemInvitationRequest,
    ) -> Result<InvitationRedemption, FederationError> {
        self.decision_peer(request.authenticated_presenter)?;
        if request.invitation.as_bytes() == [0; 16]
            || request.request_id.as_bytes() == &[0; 16]
            || request.authenticated_presenter == self.node
            || request.expected_invitation_revision == 0
            || !valid_subject(&request.subject)
        {
            return Err(FederationError::Invalid("invalid invitation redemption"));
        }
        let digest = request_digest(&request);
        if self.decision.is_none() {
            self.checked_time_ms(request.now_ms)?;
        }
        self.with_decision_write(|txn, decision_time| {
            let mut request = request;
            request.now_ms = decision_time.unwrap_or(request.now_ms);
            super::object::checked_object_time(txn, request.now_ms)?;
            check_guest_presenter(txn, request.authenticated_presenter)?;
            let mut invitations = txn
                .open_table(FEDERATION_INVITATIONS_TABLE)
                .map_err(storage)?;
            let invitation_row: Option<InvitationRow> = invitations
                .get(request.invitation.as_bytes().as_slice())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?;
            let mut invitation = match invitation_row {
                Some(row) => row,
                None => return Err(retired_or_unknown(txn, request.invitation)?),
            };
            invitation.validate(self.node, request.invitation)?;
            let key = receipt_key(request.invitation, request.request_id);
            let mut receipts = txn
                .open_table(FEDERATION_INVITE_RECEIPTS_TABLE)
                .map_err(storage)?;
            let previous: Option<RedemptionRow> = receipts
                .get(key.as_slice())
                .map_err(storage)?
                .map(|saved| decode(saved.value()))
                .transpose()?;
            if let Some(receipt) = previous {
                if bool::from(receipt.request_digest.ct_eq(&digest)) {
                    let answer = redemption(
                        txn,
                        request.invitation,
                        request.request_id,
                        &invitation,
                        &receipt,
                        request.now_ms,
                    )?;
                    drop(receipts);
                    drop(invitations);
                    txn.commit()
                        .map_err(|_error| FederationError::Indeterminate)?;
                    return Ok(answer);
                }
                return Err(FederationError::Conflict);
            }
            if !invitation.enabled
                || invitation.revision != request.expected_invitation_revision
                || request.now_ms < invitation.spec.not_before_ms
                || request.now_ms >= invitation.spec.expires_ms
                || invitation.redemptions >= invitation.spec.max_redemptions
            {
                return Err(FederationError::Unauthorized);
            }
            let spec = invitation.spec.spec();
            let issuer = issuer_authority(txn, &spec.issuer, spec.stream)?;
            if !issuer.enabled || issuer.revision != invitation.issuer_authority_revision {
                return Err(FederationError::Unauthorized);
            }
            match &spec.audience {
                InvitationAudience::Named { presenter, subject } => {
                    if *presenter != request.authenticated_presenter
                        || *subject != request.subject
                        || request.secret.is_some()
                    {
                        return Err(FederationError::Unauthorized);
                    }
                }
                InvitationAudience::Bearer { secret_digest } => {
                    let supplied = request
                        .secret
                        .as_ref()
                        .ok_or(FederationError::Unauthorized)?
                        .digest(request.invitation);
                    if !bool::from(secret_digest.as_bytes().ct_eq(supplied.as_bytes())) {
                        return Err(FederationError::Unauthorized);
                    }
                }
            }
            let stream = txn
                .open_table(FEDERATION_STREAMS_TABLE)
                .map_err(storage)?
                .get(stream_key(spec.stream).as_slice())
                .map_err(storage)?
                .map(|saved| decode::<StreamRow>(saved.value()))
                .transpose()?
                .ok_or(FederationError::NotFound)?;
            stream.validate()?;
            let grant_key = subject_grant_key(
                &request.subject,
                request.authenticated_presenter,
                spec.stream,
            );
            let mut grants = txn
                .open_table(FEDERATION_SUBJECT_GRANTS_TABLE)
                .map_err(storage)?;
            if grants.get(grant_key.as_slice()).map_err(storage)?.is_some() {
                return Err(FederationError::Conflict);
            }
            if receipts.len().map_err(storage)? >= MAX_RECEIPTS {
                return Err(FederationError::Capacity);
            }
            let floor = if spec.history == GrantHistory::FromGrant {
                stream.head.map_or(0, |head| head.sequence)
            } else {
                0
            };
            let grant = SubjectGrantRow {
                revision: 1,
                enabled: true,
                not_before_ms: spec.not_before_ms,
                expires_ms: spec.grant_expires_ms,
                from_grant: spec.history == GrantHistory::FromGrant,
                floor,
                invitation: Some(request.invitation.as_bytes()),
            };
            let receipt = RedemptionRow {
                request_digest: digest,
                presenter: *request.authenticated_presenter.as_bytes(),
                subject: InviteSubject::from(&request.subject),
                grant_history_floor: floor,
            };
            grants
                .insert(grant_key.as_slice(), encode(&grant)?.as_slice())
                .map_err(storage)?;
            receipts
                .insert(key.as_slice(), encode(&receipt)?.as_slice())
                .map_err(storage)?;
            invitation.redemptions += 1;
            invitations
                .insert(
                    request.invitation.as_bytes().as_slice(),
                    encode(&invitation)?.as_slice(),
                )
                .map_err(storage)?;
            drop(grants);
            drop(receipts);
            drop(invitations);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(InvitationRedemption {
                invitation: request.invitation,
                request_id: request.request_id,
                presenter: request.authenticated_presenter,
                subject: request.subject.clone(),
                grant: SubjectGrantEntry {
                    grant: SubjectGrant {
                        subject: request.subject,
                        presenter: request.authenticated_presenter,
                        stream: spec.stream,
                        not_before_ms: spec.not_before_ms,
                        expires_ms: spec.grant_expires_ms,
                        history: spec.history,
                        enabled: true,
                    },
                    revision: 1,
                    history_floor: floor,
                },
                currently_authorized: true,
            })
        })
    }

    fn retire_expired_invitations(
        &self,
        now_ms: u64,
        limit: usize,
    ) -> Result<usize, FederationError> {
        if limit == 0 || limit > MAX_RETIRE_BATCH {
            return Err(FederationError::Capacity);
        }
        if self.decision.is_none() {
            self.checked_time_ms(now_ms)?;
        }
        self.with_decision_write(|txn, decision_time| {
            let now_ms = decision_time.unwrap_or(now_ms);
            super::object::checked_object_time(txn, now_ms)?;
            let mut invitations = txn
                .open_table(FEDERATION_INVITATIONS_TABLE)
                .map_err(storage)?;
            let mut expired = Vec::new();
            let mut receipt_counts = HashMap::new();
            for entry in invitations.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let id = InvitationId::from_bytes(
                    <[u8; 16]>::try_from(key.value()).map_err(|_error| FederationError::Corrupt)?,
                );
                let row: InvitationRow = decode(value.value())?;
                row.validate(self.node, id)?;
                if row
                    .spec
                    .expires_ms
                    .checked_add(INVITATION_RECEIPT_RETENTION_MS)
                    .is_some_and(|end| now_ms >= end)
                {
                    expired.push(id);
                    receipt_counts.insert(id.as_bytes(), row.redemptions);
                    if expired.len() == limit {
                        break;
                    }
                }
            }
            let selected: HashSet<[u8; 16]> = expired.iter().map(|id| id.as_bytes()).collect();
            let mut receipts = txn
                .open_table(FEDERATION_INVITE_RECEIPTS_TABLE)
                .map_err(storage)?;
            let mut receipt_keys = Vec::new();
            for entry in receipts.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                let key = key.value();
                if key.len() != 32 {
                    return Err(FederationError::Corrupt);
                }
                let id =
                    <[u8; 16]>::try_from(&key[..16]).map_err(|_error| FederationError::Corrupt)?;
                if selected.contains(&id) {
                    drop(decode::<RedemptionRow>(value.value())?);
                    receipt_keys.push(key.to_vec());
                    let count = receipt_counts
                        .get_mut(&id)
                        .ok_or(FederationError::Corrupt)?;
                    *count = count.checked_sub(1).ok_or(FederationError::Corrupt)?;
                }
            }
            if receipt_counts.values().any(|remaining| *remaining != 0) {
                return Err(FederationError::Corrupt);
            }
            for key in &receipt_keys {
                receipts.remove(key.as_slice()).map_err(storage)?;
            }
            for id in &expired {
                invitations
                    .remove(id.as_bytes().as_slice())
                    .map_err(storage)?;
            }
            drop(receipts);
            drop(invitations);
            txn.commit()
                .map_err(|_error| FederationError::Indeterminate)?;
            Ok(expired.len())
        })
    }
}
