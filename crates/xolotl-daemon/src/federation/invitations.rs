//! Typed stock manifest for exact invitation share authority and invitations.
//! Parsed plans contain no bearer secrets and are reconciled before binding.

use std::collections::HashSet;

use anyhow::{Result, ensure};
use xolotl_federation::{
    Digest, FederationInvitationStore, FederationNodeId, GrantHistory, HostedSubject,
    InvitationAudience, InvitationId, InvitationIssuerKey, InvitationSpec, MAX_INVITATIONS,
    MAX_MANIFEST_PAGE, StreamId, StreamRef, StreamSpec, SubjectIssuerId, SubjectPurpose,
};

use crate::config::{
    FederationInvitationAudienceConfig, FederationInvitationConfig,
    FederationInvitationIssuerAuthorityConfig, FederationSubjectGrantHistoryConfig,
};

use super::{SubjectIssuerRule, decode_hex, validate_revision};

#[derive(Clone)]
pub(super) struct IssuerPlan {
    pub subject: HostedSubject,
    pub stream: StreamRef,
    pub enabled: bool,
    pub expected_revision: Option<u64>,
}

#[derive(Clone)]
pub(super) struct InvitationPlan {
    pub id: InvitationId,
    pub spec: InvitationSpec,
    pub expected_revision: Option<u64>,
}

pub(super) struct ManifestPlan {
    pub issuers: Option<Vec<IssuerPlan>>,
    pub invitations: Option<Vec<InvitationPlan>>,
}

/// Reconcile only rows marked as stock-manifest-owned in redb. Existing
/// embedding-host rows cannot be adopted, even when their values match.
pub(super) fn reconcile(
    store: &dyn FederationInvitationStore,
    plan: &ManifestPlan,
    now_ms: u64,
) -> Result<()> {
    let mut owned_issuers = HashSet::new();
    if plan.issuers.is_some() {
        let mut after: Option<InvitationIssuerKey> = None;
        loop {
            let page = store.list_manifest_issuer_authorities(after.as_ref(), MAX_MANIFEST_PAGE)?;
            if page.is_empty() {
                break;
            }
            for entry in &page {
                owned_issuers.insert((entry.key.issuer.clone(), entry.key.stream));
            }
            after = page.last().map(|entry| entry.key.clone());
            if page.len() < MAX_MANIFEST_PAGE {
                break;
            }
        }
    }
    let mut owned_invitations = HashSet::new();
    let mut invitation_rows = Vec::new();
    if plan.invitations.is_some() {
        let mut after = None;
        loop {
            let page = store.list_manifest_invitations(after, MAX_MANIFEST_PAGE)?;
            if page.is_empty() {
                break;
            }
            for entry in &page {
                owned_invitations.insert(entry.id);
                invitation_rows.push(entry.clone());
            }
            after = page.last().map(|entry| entry.id);
            if page.len() < MAX_MANIFEST_PAGE {
                break;
            }
        }
    }

    // Validate all declared CAS revisions before any omitted row is disabled.
    // This avoids a stale config partially revoking unrelated invitations.
    if let Some(issuers) = &plan.issuers {
        for desired in issuers {
            let current = store.invitation_issuer_authority(&desired.subject, desired.stream)?;
            ensure!(
                current.is_none()
                    || owned_issuers.contains(&(desired.subject.clone(), desired.stream)),
                "invitation issuer authority is application-owned"
            );
            if current.map(|(_, enabled)| enabled) != Some(desired.enabled) {
                ensure!(
                    current.map(|(revision, _)| revision) == desired.expected_revision,
                    "invitation issuer authority revision conflict"
                );
            }
        }
    }
    if let Some(invitations) = &plan.invitations {
        let high_water = store.invitation_high_water()?;
        for desired in invitations {
            let current = store.invitation(desired.id)?;
            ensure!(
                current.is_none() || owned_invitations.contains(&desired.id),
                "invitation is application-owned"
            );
            if let Some(current) = current {
                ensure!(current.enabled, "revoked invitation cannot be revived");
                ensure!(
                    current.spec == desired.spec,
                    "invitation is immutable; use a new ID"
                );
                ensure!(
                    store.invitation_issuer_authority(&desired.spec.issuer, desired.spec.stream)?
                        == Some((current.issuer_authority_revision, true)),
                    "issuer authority revision changed; invitation needs a new ID"
                );
                ensure!(
                    desired.expected_revision.is_none()
                        || desired.expected_revision == Some(current.revision),
                    "invitation revision conflict"
                );
            } else {
                ensure!(
                    desired.expected_revision.is_none(),
                    "new invitation cannot expect a revision"
                );
                ensure!(
                    desired.id > high_water,
                    "invitation ID is below the persisted high-water mark"
                );
                ensure!(
                    now_ms < desired.spec.expires_ms,
                    "new invitation is already expired"
                );
            }
        }
    }

    if let Some(invitations) = &plan.invitations {
        let desired: HashSet<_> = invitations.iter().map(|item| item.id).collect();
        for current in invitation_rows {
            if current.enabled && !desired.contains(&current.id) {
                store.revoke_invitation(current.id, current.revision)?;
            }
        }
    }
    if let Some(issuers) = &plan.issuers {
        let desired: HashSet<_> = issuers
            .iter()
            .map(|item| (item.subject.clone(), item.stream))
            .collect();
        let mut after: Option<InvitationIssuerKey> = None;
        loop {
            let page = store.list_manifest_issuer_authorities(after.as_ref(), MAX_MANIFEST_PAGE)?;
            if page.is_empty() {
                break;
            }
            for current in &page {
                if current.enabled
                    && !desired.contains(&(current.key.issuer.clone(), current.key.stream))
                {
                    store.set_manifest_invitation_issuer_authority(
                        &current.key.issuer,
                        current.key.stream,
                        Some(current.revision),
                        false,
                    )?;
                }
            }
            after = page.last().map(|entry| entry.key.clone());
            if page.len() < MAX_MANIFEST_PAGE {
                break;
            }
        }
        for item in issuers {
            let current = store.invitation_issuer_authority(&item.subject, item.stream)?;
            if current.map(|(_, enabled)| enabled) != Some(item.enabled) {
                store.set_manifest_invitation_issuer_authority(
                    &item.subject,
                    item.stream,
                    item.expected_revision,
                    item.enabled,
                )?;
            }
        }
    }
    if let Some(invitations) = &plan.invitations {
        for item in invitations {
            if store.invitation(item.id)?.is_none() {
                store.create_manifest_invitation(item.id, item.spec.clone(), now_ms)?;
            }
        }
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn subject(issuer: &str, namespace: &str, name: &str) -> Result<HostedSubject> {
    ensure!(
        valid_name(namespace) && valid_name(name),
        "invalid invitation subject"
    );
    Ok(HostedSubject {
        issuer: SubjectIssuerId::from_bytes(decode_hex::<48>(issuer, "invitation issuer")?),
        namespace: namespace.to_owned(),
        subject: name.to_owned(),
    })
}

fn stream(id: &str, local: FederationNodeId, streams: &[StreamSpec]) -> Result<StreamRef> {
    let id = StreamId::from_bytes(decode_hex::<16>(id, "invitation stream_id")?);
    let stream = StreamRef {
        publisher: local,
        id,
    };
    ensure!(
        streams.iter().any(|declared| declared.stream == stream),
        "invitation references undeclared local stream"
    );
    Ok(stream)
}

pub(super) fn parse(
    issuer_config: Option<&[FederationInvitationIssuerAuthorityConfig]>,
    invitation_config: Option<&[FederationInvitationConfig]>,
    local: FederationNodeId,
    streams: &[StreamSpec],
    issuer_rules: &[SubjectIssuerRule],
) -> Result<ManifestPlan> {
    let issuers = issuer_config
        .map(|config| -> Result<Vec<IssuerPlan>> {
            ensure!(
                config.len() <= MAX_INVITATIONS,
                "too many invitation issuer authorities"
            );
            let mut seen = HashSet::new();
            let mut plans = Vec::with_capacity(config.len());
            for item in config {
                validate_revision(
                    item.expected_revision,
                    "invitation issuer expected_revision",
                )?;
                let subject = subject(&item.issuer, &item.namespace, &item.subject)?;
                let stream = stream(&item.stream_id, local, streams)?;
                ensure!(
                    seen.insert((subject.clone(), stream)),
                    "duplicate invitation issuer authority"
                );
                plans.push(IssuerPlan {
                    subject,
                    stream,
                    enabled: item.enabled,
                    expected_revision: item.expected_revision,
                });
            }
            Ok(plans)
        })
        .transpose()?;
    let invitations = invitation_config
        .map(|config| -> Result<Vec<InvitationPlan>> {
            ensure!(config.len() <= MAX_INVITATIONS, "too many invitations");
            let Some(issuer_plans) = issuers.as_ref() else {
                anyhow::bail!(
                    "invitations require an explicit invitation_issuer_authorities manifest"
                );
            };
            let mut seen = HashSet::new();
            let mut plans = Vec::with_capacity(config.len());
            for item in config {
                validate_revision(item.expected_revision, "invitation expected_revision")?;
                let id = InvitationId::from_bytes(decode_hex::<16>(&item.id, "invitation ID")?);
                ensure!(seen.insert(id), "duplicate invitation ID");
                let issuer = subject(&item.issuer, &item.namespace, &item.subject)?;
                let stream = stream(&item.stream_id, local, streams)?;
                ensure!(
                    issuer_plans.iter().any(|authority| authority.enabled
                        && authority.subject == issuer
                        && authority.stream == stream),
                    "invitation has no enabled declared issuer share authority"
                );
                let audience = match &item.audience {
                    FederationInvitationAudienceConfig::Named {
                        presenter,
                        issuer,
                        namespace,
                        subject: name,
                    } => {
                        let presenter = FederationNodeId::from_bytes(decode_hex::<48>(
                            presenter,
                            "invitation audience presenter",
                        )?);
                        let subject = subject(issuer, namespace, name)?;
                        ensure!(
                            issuer_rules.iter().any(|rule| rule.issuer == subject.issuer
                                && rule.namespace == subject.namespace
                                && rule.presenter == presenter
                                && rule.purpose == SubjectPurpose::Sync),
                            "named invitation requires an exact Sync subject issuer rule"
                        );
                        InvitationAudience::Named { presenter, subject }
                    }
                    FederationInvitationAudienceConfig::Bearer { secret_digest } => {
                        InvitationAudience::Bearer {
                            secret_digest: Digest::from_bytes(decode_hex::<48>(
                                secret_digest,
                                "invitation bearer digest",
                            )?),
                        }
                    }
                };
                let history = match item.history {
                    FederationSubjectGrantHistoryConfig::All => GrantHistory::All,
                    FederationSubjectGrantHistoryConfig::FromGrant => GrantHistory::FromGrant,
                };
                let spec = InvitationSpec {
                    issuer,
                    stream,
                    audience,
                    not_before_ms: item.not_before_ms,
                    expires_ms: item.expires_ms,
                    grant_expires_ms: item.grant_expires_ms,
                    max_redemptions: item.max_redemptions,
                    history,
                };
                spec.validate(local, id)?;
                plans.push(InvitationPlan {
                    id,
                    spec,
                    expected_revision: item.expected_revision,
                });
            }
            plans.sort_by_key(|plan| plan.id);
            Ok(plans)
        })
        .transpose()?;
    Ok(ManifestPlan {
        issuers,
        invitations,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, ensure};
    use xolotl_federation::{ExportName, FederationStore, InvitationIssuerKey};
    use xolotl_storage_redb::RedbStore;

    use super::*;

    #[test]
    fn manifest_restarts_without_revision_churn_and_only_revokes_owned_rows() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = RedbStore::open(dir.path().join("invitation-manifest.redb"))?;
        let local = FederationNodeId::from_bytes([91; 48]);
        let presenter = FederationNodeId::from_bytes([92; 48]);
        let stream = StreamRef {
            publisher: local,
            id: StreamId::from_bytes([93; 16]),
        };
        let store = db.federation_store(local)?;
        store.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("shared")?,
        })?;
        let issuer = HostedSubject {
            issuer: SubjectIssuerId::from_bytes([94; 48]),
            namespace: "people".into(),
            subject: "issuer".into(),
        };
        let holder = HostedSubject {
            subject: "holder".into(),
            ..issuer.clone()
        };
        let app_issuer = HostedSubject {
            subject: "application".into(),
            ..issuer.clone()
        };
        store.set_invitation_issuer_authority(&app_issuer, stream, None, true)?;
        let id = InvitationId::from_sequence(1);
        let manifest = ManifestPlan {
            issuers: Some(vec![IssuerPlan {
                subject: issuer.clone(),
                stream,
                enabled: true,
                expected_revision: None,
            }]),
            invitations: Some(vec![InvitationPlan {
                id,
                spec: InvitationSpec {
                    issuer: issuer.clone(),
                    stream,
                    audience: InvitationAudience::Named {
                        presenter,
                        subject: holder,
                    },
                    not_before_ms: 1,
                    expires_ms: 1000,
                    grant_expires_ms: 900,
                    max_redemptions: 1,
                    history: GrantHistory::FromGrant,
                },
                expected_revision: None,
            }]),
        };
        reconcile(&store, &manifest, 100)?;
        reconcile(&store, &manifest, 100)?;
        ensure!(
            store
                .invitation(id)?
                .is_some_and(|view| view.enabled && view.revision == 1)
        );
        ensure!(store.invitation_issuer_authority(&issuer, stream)? == Some((1, true)));
        reconcile(
            &store,
            &ManifestPlan {
                issuers: None,
                invitations: None,
            },
            101,
        )?;
        ensure!(
            store
                .invitation(id)?
                .is_some_and(|view| view.enabled && view.revision == 1)
        );
        let empty = ManifestPlan {
            issuers: Some(vec![]),
            invitations: Some(vec![]),
        };
        reconcile(&store, &empty, 101)?;
        ensure!(
            store
                .invitation(id)?
                .is_some_and(|view| !view.enabled && view.revision == 2)
        );
        ensure!(store.invitation_issuer_authority(&issuer, stream)? == Some((2, false)));
        ensure!(store.invitation_issuer_authority(&app_issuer, stream)? == Some((1, true)));
        ensure!(
            store
                .list_manifest_issuer_authorities(None, 256)?
                .iter()
                .all(|entry| entry.key
                    != InvitationIssuerKey {
                        issuer: app_issuer.clone(),
                        stream
                    })
        );
        ensure!(reconcile(&store, &manifest, 102).is_err());
        ensure!(
            store
                .invitation(id)?
                .is_some_and(|view| !view.enabled && view.revision == 2)
        );
        Ok(())
    }
}
