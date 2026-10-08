//! Volatile root retry evidence shares directory admission and cleanup custody.

use super::*;
use crate::{auth::AccountKey, runtime::RuntimeSubmissionIdentity};
use sha2::{Digest, Sha256};

const ROOT_FIXED_METADATA_BYTES: usize =
    2 * std::mem::size_of::<[u8; 32]>() + 2 * std::mem::size_of::<u64>();

#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct RootKey {
    account: AccountKey,
    epoch: u64,
    nonce_hash: [u8; 32],
}

pub(super) struct RootAlias {
    fingerprint: [u8; 32],
    state: RootState,
}

enum RootState {
    Preparing(u64),
    Accepted {
        sequence: u64,
        reference: ExecutionReference,
    },
}

impl Records {
    pub(super) fn root_accepted(&self, sequence: u64) -> bool {
        self.root_aliases.values().any(|alias| {
            matches!(alias.state, RootState::Accepted { sequence: accepted, .. } if accepted == sequence)
        })
    }

    pub(super) fn root_alias_charges(&self, owner: &ExecutionOwner) -> (usize, usize) {
        let mut total = 0;
        let mut account = 0;
        for (key, alias) in &self.root_aliases {
            let charged = match alias.state {
                RootState::Preparing(_) => true,
                RootState::Accepted { sequence, .. } => !self.entries.contains_key(&sequence),
            };
            if charged {
                total += 1;
                account += usize::from(
                    key.account.authority_id() == owner.authority_id
                        && key.account.instance_id() == owner.account_id,
                );
            }
        }
        (total, account)
    }

    pub(super) fn reclaim_closed_root_aliases(&mut self) {
        self.root_aliases.retain(|key, alias| {
            key.epoch == self.retry_epoch
                || matches!(alias.state, RootState::Accepted { sequence, .. } if self.entries.contains_key(&sequence))
        });
    }
}

impl ExecutionRegistry {
    fn root_key(
        &self,
        owner: &ExecutionOwner,
        identity: &RuntimeSubmissionIdentity,
    ) -> Result<RootKey, ConsoleError> {
        if identity.registry_instance != self.instance
            || identity.nonce.is_empty()
            || identity.nonce.len() > 256
            || !identity.nonce.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(ConsoleError::BadRequest(
                "invalid root submission identity".into(),
            ));
        }
        if owner
            .authority_id
            .len()
            .checked_add(owner.account_id.len())
            .is_none_or(|bytes| bytes > self.config.max_authority_bytes)
        {
            return Err(Self::authority_limit_error());
        }
        Ok(RootKey {
            account: owner.account_key(),
            epoch: identity.retry_epoch,
            nonce_hash: Sha256::digest(identity.nonce.as_bytes()).into(),
        })
    }

    /// Return this live registry's original namespace and currently open epoch.
    pub(crate) fn submission_retry_scope(&self) -> (String, u64) {
        (self.instance.clone(), self.records().retry_epoch)
    }

    /// Trusted host control, not a client RPC. Advance only the expected epoch;
    /// overflow changes nothing. Old active receipts retain their record custody.
    pub(crate) fn close_submission_retry_epoch(&self, expected: u64) -> Result<u64, ConsoleError> {
        let mut records = self.records();
        if records.retry_epoch != expected {
            return Err(ConsoleError::BadRequest(
                "root submission retry epoch changed".into(),
            ));
        }
        let next = expected.checked_add(1).ok_or_else(|| {
            ConsoleError::Operation("root submission retry epoch exhausted".into())
        })?;
        records.retry_epoch = next;
        records.reclaim_closed_root_aliases();
        Ok(next)
    }

    /// Reserve a bounded nonce hash under its complete immutable account key.
    /// Nonces are strict ASCII identifiers without whitespace normalization.
    /// Existing receipts can be read in closed epochs, but cannot be readmitted.
    pub(crate) fn prepare_root_submission(
        self: &Arc<Self>,
        owner: &ExecutionOwner,
        identity: &RuntimeSubmissionIdentity,
        fingerprint: [u8; 32],
    ) -> Result<RootSubmissionProbe, ConsoleError> {
        let key = self.root_key(owner, identity)?;
        self.maintain_volatile();
        let mut records = self.records();
        self.maintain_volatile_in(&mut records);
        if let Some(alias) = records.root_aliases.get(&key) {
            if alias.fingerprint != fingerprint {
                return Err(ConsoleError::BadRequest(
                    "root submission fingerprint changed".into(),
                ));
            }
            return Ok(match &alias.state {
                RootState::Preparing(_) => RootSubmissionProbe::Preparing,
                RootState::Accepted {
                    sequence,
                    reference,
                } => RootSubmissionProbe::Existing {
                    reference: reference.clone(),
                    retired: self.root_reference_retired(&records, *sequence),
                },
            });
        }
        if !self.config.enabled || records.closed || key.epoch != records.retry_epoch {
            return Err(ConsoleError::BadRequest(
                "root submission admission is closed".into(),
            ));
        }
        let (aliases, account_aliases) = records.root_alias_charges(owner);
        let account_records = records
            .entries
            .values()
            .filter(|record| {
                record.owner.authority_id == owner.authority_id
                    && record.owner.account_id == owner.account_id
            })
            .count();
        if records.entries.len() + aliases >= self.config.max_records
            || account_records + account_aliases >= self.config.max_records_per_account
        {
            return Err(ConsoleError::RateLimited);
        }
        let lease = records
            .root_lease
            .checked_add(1)
            .ok_or(ConsoleError::RateLimited)?;
        records.root_lease = lease;
        records.root_aliases.insert(
            key.clone(),
            RootAlias {
                fingerprint,
                state: RootState::Preparing(lease),
            },
        );
        Ok(RootSubmissionProbe::Reserved(RootSubmissionReservation {
            registry: Arc::clone(self),
            key,
            lease,
        }))
    }

    /// Observe evidence without admission, maintenance, or retention renewal.
    /// An expired or forgotten record returns Retired even if cleanup still
    /// retains its internal row. A reclaimed closed-epoch alias is Unproven,
    /// never evidence permitting replay or proving that execution did not occur.
    pub(crate) fn lookup_root_submission(
        &self,
        owner: &ExecutionOwner,
        identity: &RuntimeSubmissionIdentity,
    ) -> Result<RootSubmissionEvidence, ConsoleError> {
        let key = self.root_key(owner, identity)?;
        let records = self.records();
        Ok(
            match records.root_aliases.get(&key).map(|alias| &alias.state) {
                None => RootSubmissionEvidence::Unproven,
                Some(RootState::Preparing(_)) => RootSubmissionEvidence::Preparing,
                Some(RootState::Accepted {
                    sequence,
                    reference,
                }) => {
                    if self.root_reference_retired(&records, *sequence) {
                        RootSubmissionEvidence::Retired(reference.clone())
                    } else {
                        RootSubmissionEvidence::Accepted(reference.clone())
                    }
                }
            },
        )
    }

    fn root_reference_retired(&self, records: &Records, sequence: u64) -> bool {
        records.entries.get(&sequence).is_none_or(|record| {
            !record.visible(self.host_runtime.now_millis(), self.host_runtime.now())
        })
    }
}

impl RootSubmissionReservation {
    /// Atomically transfer the matching kernel cleanup ticket and record into
    /// host custody and publish acceptance. Later worker failure retains this
    /// conclusion through Registration cleanup rather than releasing the nonce.
    pub(crate) fn register(
        self,
        admission: Admission,
        cleanup_ticket: CleanupTicket,
    ) -> Result<
        (
            Registration,
            watch::Receiver<Option<StopReason>>,
            ExecutionReference,
        ),
        ConsoleError,
    > {
        if self.key.account.authority_id() != admission.owner.authority_id
            || self.key.account.instance_id() != admission.owner.account_id
            || admission.origin.is_some()
            || admission.reference.process_id != cleanup_ticket.process().get().to_string()
        {
            return Err(ConsoleError::BadRequest(
                "root submission admission does not match its reservation".into(),
            ));
        }
        let prepared = self.registry.prepare_reservation(
            &admission.owner,
            &admission.authority,
            &admission.authority_candidates,
            admission.origin.as_ref(),
            &admission.budget,
        )?;
        let metadata_bytes = [
            self.key.account.authority_id().len(),
            self.key.account.instance_id().len(),
            admission.reference.process_id.len(),
            admission.reference.program_id.len(),
            prepared.id.len(),
        ]
        .into_iter()
        .try_fold(ROOT_FIXED_METADATA_BYTES, usize::checked_add);
        if metadata_bytes.is_none_or(|bytes| bytes > self.registry.config.max_authority_bytes) {
            return Err(ExecutionRegistry::authority_limit_error());
        }
        self.registry.maintain_volatile();
        let (stop, receive) = watch::channel(None);
        let mut records = self.registry.records();
        if records.retry_epoch != self.key.epoch
            || !matches!(
                records.root_aliases.get(&self.key).map(|alias| &alias.state),
                Some(RootState::Preparing(lease)) if *lease == self.lease
            )
        {
            return Err(ConsoleError::BadRequest(
                "root submission reservation is no longer open".into(),
            ));
        }
        let mut alias = records.root_aliases.remove(&self.key).ok_or_else(|| {
            ConsoleError::Operation("root submission reservation is unavailable".into())
        })?;
        let (sequence, reference) =
            self.registry
                .reserve_in(&mut records, admission, prepared, |_, _| {
                    Ok(Phase::Running {
                        stop,
                        completion: None,
                    })
                })?;
        let record = records.entries.get_mut(&sequence).ok_or_else(|| {
            ConsoleError::Operation("root submission record is unavailable".into())
        })?;
        record.cleanup_ticket = Some(cleanup_ticket);
        alias.state = RootState::Accepted {
            sequence,
            reference: reference.clone(),
        };
        records.root_aliases.insert(self.key.clone(), alias);
        Ok((
            Registration {
                registry: Arc::clone(&self.registry),
                sequence,
                finished: false,
            },
            receive,
            reference,
        ))
    }
}

impl Drop for RootSubmissionReservation {
    fn drop(&mut self) {
        let mut records = self.registry.records();
        if matches!(records.root_aliases.get(&self.key).map(|alias| &alias.state),
            Some(RootState::Preparing(lease)) if *lease == self.lease)
        {
            records.root_aliases.remove(&self.key);
        }
    }
}
