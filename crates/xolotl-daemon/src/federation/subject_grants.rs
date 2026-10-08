//! Optional manifest ownership of exact hosted-subject stream grants. An
//! embedding host can omit the manifest and manage the same service port.

use std::collections::HashSet;

use anyhow::{Result, ensure};
use xolotl_federation::{
    FederationNodeId, FederationStore, GrantHistory, HostedSubject, StreamId, StreamRef,
    StreamSpec, SubjectGrant, SubjectGrantKey, SubjectIssuerId, SubjectPurpose,
};

use crate::config::{FederationSubjectGrantConfig, FederationSubjectGrantHistoryConfig};
use crate::federation_catalog::SubjectIssuerRule;

use super::decode_hex;

const MAX_MANIFEST_GRANTS: usize = 4096;

pub(super) struct PreparedSubjectGrant {
    grant: SubjectGrant,
    expected_revision: Option<u64>,
}

pub(super) fn parse(
    config: Option<&[FederationSubjectGrantConfig]>,
    local: FederationNodeId,
    enabled_peers: &[FederationNodeId],
    streams: &[StreamSpec],
    issuers: &[SubjectIssuerRule],
) -> Result<Option<Vec<PreparedSubjectGrant>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    ensure!(
        config.len() <= MAX_MANIFEST_GRANTS,
        "too many federation subject grants"
    );
    let mut seen = HashSet::with_capacity(config.len());
    let mut grants = Vec::with_capacity(config.len());
    for item in config {
        let presenter = FederationNodeId::from_bytes(decode_hex::<48>(
            &item.presenter,
            "subject grant presenter",
        )?);
        let issuer =
            SubjectIssuerId::from_bytes(decode_hex::<48>(&item.issuer, "subject grant issuer")?);
        let id = StreamId::from_bytes(decode_hex::<16>(
            &item.stream_id,
            "subject grant stream_id",
        )?);
        let stream = StreamRef {
            publisher: local,
            id,
        };
        ensure!(
            streams.iter().any(|candidate| candidate.stream == stream),
            "subject grant references an undeclared stream"
        );
        let history = match item.history {
            FederationSubjectGrantHistoryConfig::All => GrantHistory::All,
            FederationSubjectGrantHistoryConfig::FromGrant => GrantHistory::FromGrant,
        };
        let grant = SubjectGrant {
            subject: HostedSubject {
                issuer,
                namespace: item.namespace.clone(),
                subject: item.subject.clone(),
            },
            presenter,
            stream,
            not_before_ms: item.not_before_ms,
            expires_ms: item.expires_ms,
            history,
            enabled: item.enabled,
        };
        grant.validate(local)?;
        ensure!(
            enabled_peers.contains(&presenter) || !grant.enabled,
            "enabled subject grant requires an enabled configured peer"
        );
        ensure!(
            !grant.enabled
                || issuers.iter().any(|rule| {
                    rule.issuer == issuer
                        && rule.presenter == presenter
                        && rule.namespace == grant.subject.namespace
                        && rule.purpose == SubjectPurpose::Sync
                }),
            "enabled subject grant requires an explicit Sync issuer rule"
        );
        ensure!(
            item.expected_revision != Some(0),
            "subject grant expected_revision must be positive"
        );
        ensure!(
            seen.insert(SubjectGrantKey::from_grant(&grant).encoded()?),
            "duplicate federation subject grant"
        );
        grants.push(PreparedSubjectGrant {
            grant,
            expected_revision: item.expected_revision,
        });
    }
    Ok(Some(grants))
}

pub(super) fn reconcile(
    store: &dyn FederationStore,
    desired: &[PreparedSubjectGrant],
) -> Result<()> {
    // Reject known CAS conflicts before disabling omitted grants. Startup has
    // no serving session yet, but a malformed manifest should not partially
    // revoke unrelated entries merely because its final row is stale.
    let mut updates = Vec::new();
    for item in desired {
        let current =
            store.subject_grant(&item.grant.subject, item.grant.presenter, item.grant.stream)?;
        if current
            .as_ref()
            .is_some_and(|entry| entry.grant == item.grant)
        {
            continue;
        }
        ensure!(
            current.as_ref().map(|entry| entry.revision) == item.expected_revision,
            "federation subject grant revision conflict"
        );
        if current.is_some() || item.grant.enabled {
            updates.push(item);
        }
    }
    let keys: HashSet<Vec<u8>> = desired
        .iter()
        .map(|item| SubjectGrantKey::from_grant(&item.grant).encoded())
        .collect::<std::result::Result<_, _>>()?;
    let mut after = None;
    loop {
        let page = store.scan_subject_grants(after.as_ref(), 256)?;
        if page.is_empty() {
            break;
        }
        for entry in &page {
            if entry.grant.enabled
                && !keys.contains(&SubjectGrantKey::from_grant(&entry.grant).encoded()?)
            {
                let mut disabled = entry.grant.clone();
                disabled.enabled = false;
                store.set_subject_grant(Some(entry.revision), disabled)?;
            }
        }
        after = page
            .last()
            .map(|entry| SubjectGrantKey::from_grant(&entry.grant));
        if page.len() < 256 {
            break;
        }
    }
    for item in updates {
        store.set_subject_grant(item.expected_revision, item.grant.clone())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, ensure};
    use xolotl_federation::{ExportName, FederationStore, MemoryFederationStore, StreamId};
    use xolotl_storage_redb::RedbStore;

    use super::*;

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn manifest_ownership_disables_removed_grants_and_never_revives_without_cas() -> Result<()> {
        let local = FederationNodeId::from_bytes([71; 48]);
        let presenter = FederationNodeId::from_bytes([72; 48]);
        let issuer = SubjectIssuerId::from_bytes([73; 48]);
        let stream = StreamRef {
            publisher: local,
            id: StreamId::from_bytes([74; 16]),
        };
        let store = MemoryFederationStore::new(local);
        store.set_peer_authority(presenter, None, true)?;
        store.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("notes")?,
        })?;
        let config = FederationSubjectGrantConfig {
            issuer: encode_hex(&issuer.as_bytes()),
            namespace: "people".into(),
            subject: "alice".into(),
            presenter: encode_hex(presenter.as_bytes()),
            stream_id: encode_hex(stream.id.as_bytes()),
            not_before_ms: 1,
            expires_ms: 1000,
            history: FederationSubjectGrantHistoryConfig::FromGrant,
            enabled: true,
            expected_revision: None,
        };
        let streams = [StreamSpec {
            stream,
            export: ExportName::new("notes")?,
        }];
        let issuers = [SubjectIssuerRule {
            issuer,
            presenter,
            purpose: SubjectPurpose::Sync,
            namespace: "people".into(),
        }];
        ensure!(parse(None, local, &[presenter], &streams, &issuers)?.is_none());
        let desired = parse(
            Some(std::slice::from_ref(&config)),
            local,
            &[presenter],
            &streams,
            &issuers,
        )?
        .ok_or_else(|| anyhow::anyhow!("manifest absent"))?;
        reconcile(&store, &desired)?;
        reconcile(&store, &desired)?;
        let key = &desired[0].grant;
        ensure!(
            store
                .subject_grant(&key.subject, presenter, stream)?
                .ok_or_else(|| anyhow::anyhow!("grant missing"))?
                .revision
                == 1
        );
        let mut other = key.clone();
        other.subject.subject = "bob".into();
        store.set_subject_grant(None, other.clone())?;
        let stale_config = FederationSubjectGrantConfig {
            expires_ms: 900,
            expected_revision: Some(2),
            ..config.clone()
        };
        let stale = parse(
            Some(&[stale_config]),
            local,
            &[presenter],
            &streams,
            &issuers,
        )?
        .ok_or_else(|| anyhow::anyhow!("stale manifest absent"))?;
        ensure!(reconcile(&store, &stale).is_err());
        ensure!(
            store
                .subject_grant(&other.subject, presenter, stream)?
                .ok_or_else(|| anyhow::anyhow!("unrelated grant missing"))?
                .grant
                .enabled
        );
        reconcile(&store, &[])?;
        let disabled = store
            .subject_grant(&key.subject, presenter, stream)?
            .ok_or_else(|| anyhow::anyhow!("disabled grant missing"))?;
        ensure!(!disabled.grant.enabled && disabled.revision == 2);
        ensure!(reconcile(&store, &desired).is_err());
        let renewed_config = FederationSubjectGrantConfig {
            expected_revision: Some(2),
            ..config
        };
        let renewed = parse(
            Some(&[renewed_config]),
            local,
            &[presenter],
            &streams,
            &issuers,
        )?
        .ok_or_else(|| anyhow::anyhow!("renewed manifest absent"))?;
        reconcile(&store, &renewed)?;
        ensure!(
            store
                .subject_grant(&key.subject, presenter, stream)?
                .ok_or_else(|| anyhow::anyhow!("renewed grant missing"))?
                .revision
                == 3
        );
        Ok(())
    }

    #[test]
    fn redb_manifest_restart_preserves_revision_and_revocation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("federation.redb");
        let local = FederationNodeId::from_bytes([81; 48]);
        let presenter = FederationNodeId::from_bytes([82; 48]);
        let issuer = SubjectIssuerId::from_bytes([83; 48]);
        let stream = StreamRef {
            publisher: local,
            id: StreamId::from_bytes([84; 16]),
        };
        let spec = StreamSpec {
            stream,
            export: ExportName::new("notes")?,
        };
        let config = FederationSubjectGrantConfig {
            issuer: encode_hex(&issuer.as_bytes()),
            namespace: "people".into(),
            subject: "alice".into(),
            presenter: encode_hex(presenter.as_bytes()),
            stream_id: encode_hex(stream.id.as_bytes()),
            not_before_ms: 1,
            expires_ms: 1_000,
            history: FederationSubjectGrantHistoryConfig::FromGrant,
            enabled: true,
            expected_revision: None,
        };
        let desired = parse(
            Some(&[config]),
            local,
            &[presenter],
            std::slice::from_ref(&spec),
            &[SubjectIssuerRule {
                issuer,
                presenter,
                purpose: SubjectPurpose::Sync,
                namespace: "people".into(),
            }],
        )?
        .ok_or_else(|| anyhow::anyhow!("subject manifest absent"))?;
        let db = RedbStore::open(&path)?;
        let store = db.federation_store(local)?;
        store.set_peer_authority(presenter, None, true)?;
        store.declare_stream(spec)?;
        reconcile(&store, &desired)?;
        drop(store);
        drop(db);

        let db = RedbStore::open(&path)?;
        let store = db.federation_store(local)?;
        reconcile(&store, &desired)?;
        let grant = &desired[0].grant;
        let current = store
            .subject_grant(&grant.subject, presenter, stream)?
            .ok_or_else(|| anyhow::anyhow!("subject grant missing after restart"))?;
        ensure!(current.revision == 1 && current.grant.enabled);
        reconcile(&store, &[])?;
        drop(store);
        drop(db);

        let db = RedbStore::open(&path)?;
        let store = db.federation_store(local)?;
        let revoked = store
            .subject_grant(&grant.subject, presenter, stream)?
            .ok_or_else(|| anyhow::anyhow!("subject revocation missing after restart"))?;
        ensure!(revoked.revision == 2 && !revoked.grant.enabled);
        ensure!(reconcile(&store, &desired).is_err());
        Ok(())
    }
}
