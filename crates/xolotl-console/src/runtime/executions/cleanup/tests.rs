use super::*;
use crate::runtime::RuntimeSubmissionIdentity;
use anyhow::{Context, ensure};
use std::io::Write as _;
use xolotl_kernel::Bootstrap;
use xolotl_types::{CausalPosition, ExecutionId, IdentityRef, InvocationId, ProcessStatus};

fn root_identity(registry: &ExecutionRegistry, nonce: &str) -> RuntimeSubmissionIdentity {
    let (registry_instance, retry_epoch) = registry.submission_retry_scope();
    RuntimeSubmissionIdentity {
        registry_instance,
        retry_epoch,
        nonce: nonce.into(),
    }
}

fn root_reservation(
    registry: &Arc<ExecutionRegistry>,
    owner: &ExecutionOwner,
    identity: &RuntimeSubmissionIdentity,
) -> anyhow::Result<RootSubmissionReservation> {
    match registry.prepare_root_submission(owner, identity, [1; 32])? {
        RootSubmissionProbe::Reserved(reservation) => Ok(reservation),
        _ => anyhow::bail!("expected root reservation"),
    }
}

fn root_admission(owner: &ExecutionOwner, process: u64) -> Admission {
    Admission {
        owner: owner.clone(),
        authority: Vec::new(),
        authority_candidates: Arc::from([]),
        reference: ExecutionReference {
            execution_id: None,
            process_id: process.to_string(),
            program_id: "00".repeat(32),
        },
        budget: Default::default(),
        deadline: xolotl_kernel::host::system_now_millis() + 60_000,
        origin: None,
        stream_output: false,
    }
}

#[test]
fn root_concurrent_nonce_has_one_winner_and_rejects_fingerprint_changes() -> anyhow::Result<()> {
    let (registry, _) = registry(4, 4, 4)?;
    let owner = owner("root-concurrent")?;
    let identity = root_identity(&registry, "same-nonce");
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let attempts = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            let registry = &registry;
            let owner = &owner;
            let identity = &identity;
            threads.push(scope.spawn(move || {
                barrier.wait();
                registry.prepare_root_submission(owner, identity, [1; 32])
            }));
        }
        threads
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .map_err(|_panic| anyhow::anyhow!("submission thread failed"))?
                    .map_err(anyhow::Error::from)
            })
            .collect::<anyhow::Result<Vec<_>>>()
    })?;
    ensure!(
        attempts
            .iter()
            .filter(|attempt| matches!(attempt, RootSubmissionProbe::Reserved(_)))
            .count()
            == 1
    );
    ensure!(
        attempts
            .iter()
            .filter(|attempt| matches!(attempt, RootSubmissionProbe::Preparing))
            .count()
            == 7
    );
    ensure!(
        registry
            .prepare_root_submission(&owner, &identity, [2; 32])
            .is_err()
    );
    ensure!(matches!(
        registry.lookup_root_submission(&owner, &identity)?,
        RootSubmissionEvidence::Preparing
    ));
    drop(attempts);
    ensure!(matches!(
        registry.lookup_root_submission(&owner, &identity)?,
        RootSubmissionEvidence::Unproven
    ));
    Ok(())
}

#[test]
fn root_keys_isolate_accounts_authorities_and_ignore_display_generations() -> anyhow::Result<()> {
    let (registry, _) = registry(4, 4, 4)?;
    let owner = owner("root-key")?;
    let identity = root_identity(&registry, "key");
    let first = root_reservation(&registry, &owner, &identity)?;
    let mut renamed = owner.clone();
    renamed.username = "renamed".into();
    ensure!(matches!(
        registry.prepare_root_submission(&renamed, &identity, [1; 32])?,
        RootSubmissionProbe::Preparing
    ));
    let mut recreated = owner.clone();
    recreated.account_id = "new-account".into();
    let second = root_reservation(&registry, &recreated, &identity)?;
    let mut foreign = owner;
    foreign.authority_id = "foreign".into();
    let third = root_reservation(&registry, &foreign, &identity)?;
    ensure!(registry.records().root_aliases.len() == 3);
    drop((first, second, third));
    Ok(())
}

#[test]
fn root_late_guard_drop_cannot_remove_a_replacement_lease() -> anyhow::Result<()> {
    let (registry, _) = registry(1, 1, 1)?;
    let owner = owner("root-lease")?;
    let identity = root_identity(&registry, "lease");
    let first = root_reservation(&registry, &owner, &identity)?;
    registry.records().root_aliases.clear();
    let replacement = root_reservation(&registry, &owner, &identity)?;
    drop(first);
    ensure!(matches!(
        registry.lookup_root_submission(&owner, &identity)?,
        RootSubmissionEvidence::Preparing
    ));
    drop(replacement);
    ensure!(registry.records().root_aliases.is_empty());
    Ok(())
}

#[tokio::test]
async fn root_cleanup_acceptance_is_atomic_and_worker_drop_retains_evidence() -> anyhow::Result<()>
{
    let (registry, boot) = registry(1, 1, 1)?;
    let owner = owner("root-atomic")?;
    let identity = root_identity(&registry, "atomic");
    let reservation = root_reservation(&registry, &owner, &identity)?;
    ensure!(
        reservation
            .register(
                root_admission(&owner, 7),
                boot.cleanup_ticket(ProcessId::new(8))?
            )
            .is_err()
    );
    ensure!(registry.records().entries.is_empty());
    ensure!(matches!(
        registry.lookup_root_submission(&owner, &identity)?,
        RootSubmissionEvidence::Unproven
    ));
    let reservation = root_reservation(&registry, &owner, &identity)?;
    let (registration, _, reference) = reservation.register(
        root_admission(&owner, 7),
        boot.cleanup_ticket(ProcessId::new(7))?,
    )?;
    {
        let records = registry.records();
        let (_, record) = records
            .record_by_id(id(&reference)?)
            .context("accepted record")?;
        ensure!(record.accepted);
        ensure!(
            record
                .cleanup_ticket
                .as_ref()
                .map(|ticket| ticket.process())
                == Some(ProcessId::new(7))
        );
        ensure!(records.entries.len() == 1 && records.root_aliases.len() == 1);
    }
    ensure!(
        matches!(registry.lookup_root_submission(&owner, &identity)?, RootSubmissionEvidence::Accepted(found) if found == reference)
    );
    ensure!(
        registry
            .prepare_root_submission(&owner, &identity, [2; 32])
            .is_err()
    );
    drop(registration);
    ensure!(
        matches!(registry.prepare_root_submission(&owner, &identity, [1; 32])?, RootSubmissionProbe::Existing { reference: found, retired: false } if found == reference)
    );
    ensure!(registry.pending_volatile_cleanup_count() == 1);
    Ok(())
}

#[tokio::test]
async fn root_forget_and_expiry_leave_open_retired_aliases_and_shared_quotas() -> anyhow::Result<()>
{
    for forgotten in [false, true] {
        let (registry, boot) = registry(2, 2, 2)?;
        let owner = owner("root-retired")?;
        let identity = root_identity(&registry, "retired");
        let reservation = root_reservation(&registry, &owner, &identity)?;
        let (registration, _, reference) = reservation.register(
            root_admission(&owner, 7),
            boot.cleanup_ticket(ProcessId::new(7))?,
        )?;
        boot.finalize_process(ProcessId::new(7)).await?;
        registration.finish(true);
        if forgotten {
            registry.forget(&owner, id(&reference)?).await?;
        } else {
            expire(&registry, id(&reference)?)?;
            ensure!(registry.records().entries.len() == 1);
            ensure!(
                matches!(registry.lookup_root_submission(&owner, &identity)?, RootSubmissionEvidence::Retired(found) if found == reference)
            );
            ensure!(registry.records().entries.len() == 1);
            registry.maintain_volatile();
        }
        ensure!(registry.records().entries.is_empty());
        ensure!(
            matches!(registry.lookup_root_submission(&owner, &identity)?, RootSubmissionEvidence::Retired(found) if found == reference)
        );
        ensure!(
            matches!(registry.prepare_root_submission(&owner, &identity, [1; 32])?, RootSubmissionProbe::Existing { reference: found, retired: true } if found == reference)
        );
        let (parent, _, parent_ref) = register(&registry, &boot, &owner, 8)?;
        ensure!(matches!(
            register(&registry, &boot, &owner, 9),
            Err(ConsoleError::RateLimited)
        ));
        let origin = ExecutionOrigin {
            execution_id: id(&parent_ref)?.into(),
            operation: OperationId::new(
                ProcessId::new(8),
                ExecutionId::FIRST,
                InvocationId::new(1),
                CausalPosition::new(1),
                0,
            ),
        };
        ensure!(matches!(
            registry.register_child(
                owner.clone(),
                Vec::new(),
                root_admission(&owner, 9).reference,
                root_admission(&owner, 9).deadline,
                origin
            ),
            Err(ConsoleError::RateLimited)
        ));
        ensure!(
            registry.close_submission_retry_epoch(identity.retry_epoch)?
                == identity.retry_epoch + 1
        );
        ensure!(matches!(
            registry.lookup_root_submission(&owner, &identity)?,
            RootSubmissionEvidence::Unproven
        ));
        ensure!(
            registry
                .prepare_root_submission(&owner, &identity, [1; 32])
                .is_err()
        );
        let replacement =
            root_reservation(&registry, &owner, &root_identity(&registry, "retired"))?;
        drop((parent, replacement));
    }
    Ok(())
}

#[tokio::test]
async fn root_register_rejection_releases_only_preparing_and_accepted_reject_keeps_custody()
-> anyhow::Result<()> {
    let (registry, boot) = registry(1, 1, 3)?;
    let owner = owner("root-capacity")?;
    let identity = root_identity(&registry, "rejected");
    let reservation = root_reservation(&registry, &owner, &identity)?;
    let (running, _, _) = register(&registry, &boot, &owner, 8)?;
    ensure!(matches!(
        reservation.register(
            root_admission(&owner, 7),
            boot.cleanup_ticket(ProcessId::new(7))?
        ),
        Err(ConsoleError::RateLimited)
    ));
    ensure!(registry.records().root_aliases.is_empty());
    ensure!(registry.records().entries.len() == 1);
    boot.finalize_process(ProcessId::new(8)).await?;
    running.finish(true);
    let reservation = root_reservation(&registry, &owner, &identity)?;
    let (mut accepted, _, reference) = reservation.register(
        root_admission(&owner, 7),
        boot.cleanup_ticket(ProcessId::new(7))?,
    )?;
    accepted.reject();
    ensure!(registry.pending_volatile_cleanup_count() == 1);
    ensure!(
        matches!(registry.lookup_root_submission(&owner, &identity)?, RootSubmissionEvidence::Accepted(found) if found == reference)
    );
    ensure!(registry.records().record_by_id(id(&reference)?).is_some());
    drop(accepted);
    Ok(())
}

#[test]
fn root_aliases_charge_the_full_account_quota_without_charging_other_accounts() -> anyhow::Result<()>
{
    let registry = ExecutionRegistry::new(ConsoleExecutionConfig {
        enabled: true,
        max_records: 3,
        max_records_per_account: 1,
        ..Default::default()
    })?;
    let first_owner = owner("root-account-limit")?;
    let mut second_owner = first_owner.clone();
    second_owner.authority_id = "other-authority".into();
    let identity = root_identity(&registry, "quota");
    let first = root_reservation(&registry, &first_owner, &identity)?;
    let second = root_reservation(&registry, &second_owner, &identity)?;
    ensure!(matches!(
        registry.prepare_root_submission(&first_owner, &root_identity(&registry, "next"), [1; 32]),
        Err(ConsoleError::RateLimited)
    ));
    ensure!(matches!(
        registry.register_authorized(root_admission(&first_owner, 7)),
        Err(ConsoleError::RateLimited)
    ));
    drop(first);
    let (accepted, _, _) = registry.register_authorized(root_admission(&first_owner, 7))?;
    drop((second, accepted));
    Ok(())
}

#[tokio::test]
async fn root_epoch_closure_preserves_active_acceptance_and_reclaims_only_eligible_aliases()
-> anyhow::Result<()> {
    let (registry, boot) = registry(2, 2, 2)?;
    let owner = owner("root-epoch")?;
    let identity = root_identity(&registry, "active");
    let reservation = root_reservation(&registry, &owner, &identity)?;
    let (registration, _, reference) = reservation.register(
        root_admission(&owner, 7),
        boot.cleanup_ticket(ProcessId::new(7))?,
    )?;
    let preparing_identity = root_identity(&registry, "preparing");
    let preparing = root_reservation(&registry, &owner, &preparing_identity)?;
    ensure!(
        registry
            .close_submission_retry_epoch(identity.retry_epoch + 1)
            .is_err()
    );
    ensure!(
        registry.close_submission_retry_epoch(identity.retry_epoch)? == identity.retry_epoch + 1
    );
    ensure!(matches!(
        registry.lookup_root_submission(&owner, &preparing_identity)?,
        RootSubmissionEvidence::Unproven
    ));
    ensure!(
        preparing
            .register(
                root_admission(&owner, 8),
                boot.cleanup_ticket(ProcessId::new(8))?
            )
            .is_err()
    );
    ensure!(
        matches!(registry.lookup_root_submission(&owner, &identity)?, RootSubmissionEvidence::Accepted(found) if found == reference)
    );
    ensure!(
        matches!(registry.prepare_root_submission(&owner, &identity, [1; 32])?, RootSubmissionProbe::Existing { reference: found, retired: false } if found == reference)
    );
    let current = root_reservation(&registry, &owner, &root_identity(&registry, "preparing"))?;
    boot.finalize_process(ProcessId::new(7)).await?;
    registration.finish(true);
    registry.forget(&owner, id(&reference)?).await?;
    ensure!(matches!(
        registry.lookup_root_submission(&owner, &identity)?,
        RootSubmissionEvidence::Unproven
    ));
    ensure!(registry.records().root_aliases.len() == 1);
    drop(current);
    Ok(())
}

#[test]
fn root_epoch_overflow_and_readonly_queries_do_not_mutate_directory() -> anyhow::Result<()> {
    let (registry, _) = registry(1, 1, 1)?;
    let owner = owner("root-readonly")?;
    registry.records().retry_epoch = u64::MAX;
    let identity = root_identity(&registry, "read");
    let reservation = root_reservation(&registry, &owner, &identity)?;
    let sequence = registry.records().sequence;
    ensure!(registry.close_submission_retry_epoch(u64::MAX).is_err());
    ensure!(registry.submission_retry_scope().1 == u64::MAX);
    for _ in 0..10 {
        ensure!(matches!(
            registry.lookup_root_submission(&owner, &identity)?,
            RootSubmissionEvidence::Preparing
        ));
        ensure!(matches!(
            registry.lookup_root_submission(&owner, &root_identity(&registry, "missing"))?,
            RootSubmissionEvidence::Unproven
        ));
    }
    ensure!(registry.records().sequence == sequence);
    ensure!(registry.records().root_aliases.len() == 1);
    drop(reservation);
    Ok(())
}

#[test]
fn root_nonce_namespace_owner_bytes_and_preparing_capacity_are_bounded() -> anyhow::Result<()> {
    let (registry, boot) = registry(2, 2, 2)?;
    let owner = owner("root-bounds")?;
    for nonce in [
        "",
        " leading",
        "trailing ",
        "line\n",
        "非ASCII",
        &"a".repeat(257),
    ] {
        let identity = root_identity(&registry, nonce);
        ensure!(
            registry
                .prepare_root_submission(&owner, &identity, [1; 32])
                .is_err()
        );
        ensure!(registry.lookup_root_submission(&owner, &identity).is_err());
    }
    let mut foreign = root_identity(&registry, "foreign");
    foreign.registry_instance = "another-registry".into();
    ensure!(
        registry
            .prepare_root_submission(&owner, &foreign, [1; 32])
            .is_err()
    );
    ensure!(registry.lookup_root_submission(&owner, &foreign).is_err());
    let first = root_reservation(&registry, &owner, &root_identity(&registry, "-_.:AZaz09"))?;
    let second = root_reservation(
        &registry,
        &owner,
        &root_identity(&registry, &"a".repeat(256)),
    )?;
    ensure!(matches!(
        register(&registry, &boot, &owner, 7),
        Err(ConsoleError::RateLimited)
    ));
    ensure!(matches!(
        registry.prepare_root_submission(&owner, &root_identity(&registry, "full"), [1; 32]),
        Err(ConsoleError::RateLimited)
    ));
    drop((first, second));
    let oversized = ExecutionRegistry::new(ConsoleExecutionConfig {
        enabled: true,
        max_authority_bytes: 3,
        ..Default::default()
    })?;
    let identity = root_identity(&oversized, "key");
    ensure!(
        oversized
            .prepare_root_submission(&owner, &identity, [1; 32])
            .is_err()
    );
    ensure!(oversized.lookup_root_submission(&owner, &identity).is_err());
    ensure!(oversized.records().root_aliases.is_empty());
    Ok(())
}

#[test]
fn root_accepted_reference_metadata_is_bounded_before_cloning() -> anyhow::Result<()> {
    let (registry, boot) = registry(1, 1, 1)?;
    let owner = owner("root-reference-bytes")?;
    let identity = root_identity(&registry, "reference");
    let reservation = root_reservation(&registry, &owner, &identity)?;
    let mut admission = root_admission(&owner, 7);
    admission.reference.program_id = "a".repeat(registry.config.max_authority_bytes);
    ensure!(
        reservation
            .register(admission, boot.cleanup_ticket(ProcessId::new(7))?)
            .is_err()
    );
    ensure!(registry.records().entries.is_empty());
    ensure!(registry.records().root_aliases.is_empty());
    let reservation = root_reservation(&registry, &owner, &identity)?;
    let (registration, _, reference) = reservation.register(
        root_admission(&owner, 7),
        boot.cleanup_ticket(ProcessId::new(7))?,
    )?;
    ensure!(
        matches!(registry.lookup_root_submission(&owner, &identity)?, RootSubmissionEvidence::Accepted(found) if found == reference)
    );
    drop(registration);
    Ok(())
}

#[tokio::test]
async fn root_sustained_epoch_reclamation_stays_bounded_and_preserves_cleanup() -> anyhow::Result<()>
{
    const CYCLES: usize = 128;
    let started = std::time::Instant::now();
    let (registry, boot) = registry(2, 2, 2)?;
    let owner = owner("root-sustained")?;
    let held_identity = root_identity(&registry, "held-cleanup");
    let held = root_reservation(&registry, &owner, &held_identity)?;
    let (held_registration, _, held_reference) = held.register(
        root_admission(&owner, 9),
        boot.cleanup_ticket(ProcessId::new(9))?,
    )?;
    drop(held_registration);
    for _ in 0..CYCLES {
        let identity = root_identity(&registry, "cycle");
        let reservation = root_reservation(&registry, &owner, &identity)?;
        let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
        let process = request.id();
        request.detach();
        let (registration, _, reference) = reservation.register(
            root_admission(&owner, process.get()),
            boot.cleanup_ticket(process)?,
        )?;
        {
            let records = registry.records();
            ensure!(records.entries.len() == 2 && records.root_aliases.len() == 2);
        }
        boot.finalize_process(process).await?;
        registration.finish(true);
        registry.forget(&owner, id(&reference)?).await?;
        ensure!(
            matches!(registry.lookup_root_submission(&owner, &identity)?, RootSubmissionEvidence::Retired(found) if found == reference)
        );
        ensure!(
            matches!(registry.prepare_root_submission(&owner, &identity, [1; 32])?, RootSubmissionProbe::Existing { reference: found, retired: true } if found == reference)
        );
        ensure!(
            registry.close_submission_retry_epoch(identity.retry_epoch)?
                == identity.retry_epoch + 1
        );
        ensure!(matches!(
            registry.lookup_root_submission(&owner, &identity)?,
            RootSubmissionEvidence::Unproven
        ));
        ensure!(
            registry
                .prepare_root_submission(&owner, &identity, [1; 32])
                .is_err()
        );
        ensure!(
            matches!(registry.lookup_root_submission(&owner, &held_identity)?, RootSubmissionEvidence::Accepted(found) if found == held_reference)
        );
        ensure!(registry.pending_volatile_cleanup_count() == 1);
        let records = registry.records();
        ensure!(records.entries.len() == 1 && records.root_aliases.len() == 1);
        let (_, held_record) = records
            .record_by_id(id(&held_reference)?)
            .context("held cleanup")?;
        ensure!(held_record.custody_pending() && held_record.cleanup_ticket.is_some());
    }
    let current = root_reservation(&registry, &owner, &root_identity(&registry, "cycle"))?;
    drop(current);
    boot.finalize_process(ProcessId::new(9)).await?;
    registry.maintain_volatile();
    registry.forget(&owner, id(&held_reference)?).await?;
    ensure!(registry.records().entries.is_empty());
    ensure!(registry.records().root_aliases.is_empty());
    writeln!(
        std::io::stderr().lock(),
        "guarded root reclamation: {CYCLES} cycles, fixture-inclusive elapsed {:?}; no latency threshold or speedup claim",
        started.elapsed()
    )?;
    Ok(())
}

fn owner(account: &str) -> anyhow::Result<ExecutionOwner> {
    Ok(serde_json::from_value(serde_json::json!({
        "username": "root", "account_id": account, "authority_id": "local", "revocation_epoch": "1", "authority_ceiling": [],
        "credential_epoch": "credentials", "identity_path": format!("identity://console/accounts/{account}"),
    }))?)
}

fn registry(
    concurrent: usize,
    per_account: usize,
    records: usize,
) -> anyhow::Result<(Arc<ExecutionRegistry>, Bootstrap)> {
    let boot = Bootstrap::in_memory();
    for _ in 2..=9 {
        boot.request_under(boot.root(), IdentityRef::ROOT, &[])?
            .detach();
    }
    Ok((
        ExecutionRegistry::new(ConsoleExecutionConfig {
            enabled: true,
            max_concurrent: concurrent,
            max_concurrent_per_account: per_account,
            max_records: records,
            max_records_per_account: records,
            ..Default::default()
        })?,
        boot,
    ))
}

fn register(
    registry: &Arc<ExecutionRegistry>,
    boot: &Bootstrap,
    owner: &ExecutionOwner,
    process: u64,
) -> Result<
    (
        Registration,
        watch::Receiver<Option<StopReason>>,
        ExecutionReference,
    ),
    ConsoleError,
> {
    let admitted = registry.register(
        owner.clone(),
        Vec::new(),
        ExecutionReference {
            execution_id: None,
            process_id: process.to_string(),
            program_id: "00".repeat(32),
        },
        xolotl_kernel::host::system_now_millis() + 60_000,
        xolotl_types::BudgetSpec::default(),
    )?;
    admitted.0.bind_cleanup(
        boot.cleanup_ticket(ProcessId::new(process))
            .map_err(|error| ConsoleError::Operation(error.to_string()))?,
    )?;
    Ok(admitted)
}

fn body() -> Completion {
    Completion {
        outcome: "done".into(),
        stop_cause: None,
        result: RetainedResult::encode(&Value::integer(37), 1024),
        unresolved_operations: Default::default(),
        cleanup_complete: false,
        finalization: Default::default(),
    }
}

#[tokio::test]
async fn retained_body_and_finalization_survive_automatic_kernel_retirement() -> anyhow::Result<()>
{
    let capacity = std::num::NonZeroUsize::new(2).context("capacity")?;
    let boot = Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
            .with_process_capacity(capacity)
            .build(),
    );
    let registry = ExecutionRegistry::new(ConsoleExecutionConfig {
        enabled: true,
        ..Default::default()
    })?;
    let owner = owner("retained")?;
    let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
    let process = request.id();
    let (registration, _, reference) = register(&registry, &boot, &owner, process.get())?;
    registration.record_body(body());
    let output = xolotl_types::ExecutionOutput::new(
        xolotl_types::Outcome::Done(Value::integer(37)),
        xolotl_types::TaintSet::author(),
    );
    request.finish(&output).await?;
    registration.finish(true);
    let before = registry.result(&owner, id(&reference)?, |_| true)?;
    ensure!(field(&before, "output")? == &Value::integer(37));
    ensure!(field(field(&before, "finalization")?, "status")?.as_str() == Some("available"));
    let replacement = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
    ensure!(boot.kernel().processes().status(process).is_none());
    let after = registry.result(&owner, id(&reference)?, |_| true)?;
    ensure!(after == before);
    replacement.finish(&output).await?;
    Ok(())
}

fn id(reference: &ExecutionReference) -> anyhow::Result<&str> {
    reference.execution_id.as_deref().context("execution ID")
}

fn field<'a>(value: &'a Value, name: &str) -> anyhow::Result<&'a Value> {
    value
        .as_map()
        .and_then(|fields| fields.get(name))
        .context(name.to_owned())
}

fn expire(registry: &ExecutionRegistry, id: &str) -> anyhow::Result<()> {
    let mut records = registry.records();
    let record = records
        .entries
        .values_mut()
        .find(|record| record.id == id)
        .context("record")?;
    let Phase::Finished { expires, .. } = &mut record.phase else {
        anyhow::bail!("attempt is still running");
    };
    *expires = registry.host_runtime.now();
    Ok(())
}

fn grant_observation(registry: &ExecutionRegistry, id: &str) -> anyhow::Result<()> {
    let mut records = registry.records();
    let record = records
        .entries
        .values_mut()
        .find(|record| record.id == id)
        .context("record")?;
    record.authority = Arc::from(vec![("read".into(), Path::parse("state://visible")?)]);
    Ok(())
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = panic.downcast_ref::<String>() {
        message
    } else if let Some(message) = panic.downcast_ref::<&str>() {
        message
    } else {
        "non-string panic payload"
    }
}

#[tokio::test]
async fn execution_id_index_tracks_admission_forget_expiry_and_rejection() -> anyhow::Result<()> {
    let (registry, boot) = registry(2, 2, 4)?;
    let first_owner = owner("first")?;
    let second_owner = owner("second")?;
    let (first, _, first_ref) = register(&registry, &boot, &first_owner, 7)?;
    let first_id = id(&first_ref)?.to_owned();
    boot.finalize_process(ProcessId::new(7)).await?;
    first.finish(true);
    let (second, _, second_ref) = register(&registry, &boot, &second_owner, 8)?;
    let second_id = id(&second_ref)?.to_owned();
    boot.finalize_process(ProcessId::new(8)).await?;
    second.finish(true);
    ensure!(registry.records().index_is_complete());
    ensure!(registry.get(&first_owner, &first_id).is_ok());
    ensure!(registry.get(&second_owner, &second_id).is_ok());
    ensure!(registry.get(&first_owner, &second_id).is_err());

    registry.forget(&first_owner, &first_id).await?;
    ensure!(registry.get(&first_owner, &first_id).is_err());
    ensure!(registry.records().sequence_for(&first_id).is_none());
    ensure!(registry.records().index_is_complete());

    expire(&registry, &second_id)?;
    registry.maintain_volatile();
    ensure!(registry.records().sequence_for(&second_id).is_none());
    ensure!(registry.records().index_is_complete());

    let (mut rejected, _, reference) = register(&registry, &boot, &first_owner, 9)?;
    let rejected_id = id(&reference)?.to_owned();
    ensure!(registry.records().sequence_for(&rejected_id).is_some());
    rejected.reject();
    ensure!(registry.records().sequence_for(&rejected_id).is_none());
    ensure!(registry.records().index_is_complete());
    Ok(())
}

#[test]
fn execution_timestamps_follow_the_console_host_clock() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicI64, Ordering};
    use xolotl_kernel::host::{AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner};

    struct Clock(AtomicI64);

    impl HostClock for Clock {
        fn monotonic_now(&self) -> std::time::Instant {
            std::time::Instant::now()
        }

        fn unix_millis(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }

        fn sleep_until(
            &self,
            _deadline: std::time::Instant,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    let clock = Arc::new(Clock(AtomicI64::new(1_000)));
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(NoTasks),
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            ))
            .build(),
    ));
    let state = crate::ConsoleState::with_config(
        boot,
        crate::ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: crate::ConsoleRuntimeConfig {
                enabled: true,
                executions: ConsoleExecutionConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let (registration, _, reference) = state.executions.register(
        owner("clock")?,
        Vec::new(),
        ExecutionReference {
            execution_id: None,
            process_id: "7".into(),
            program_id: "00".repeat(32),
        },
        20_000,
        xolotl_types::BudgetSpec::default(),
    )?;
    let execution_id = id(&reference)?;
    let created_at = state
        .executions
        .records()
        .record_by_id(execution_id)
        .map(|(_, record)| record.created_at)
        .context("created execution")?;
    ensure!(created_at == 1_000);

    clock.0.store(1_500, Ordering::SeqCst);
    registration.finish(false);
    let finished_at = state
        .executions
        .records()
        .record_by_id(execution_id)
        .and_then(|(_, record)| match &record.phase {
            Phase::Finished { finished_at, .. } => Some(*finished_at),
            _ => None,
        })
        .context("finished execution")?;
    ensure!(finished_at == 1_500);

    let (registration, _, reference) = state.executions.register(
        owner("clock")?,
        Vec::new(),
        ExecutionReference {
            execution_id: None,
            process_id: "8".into(),
            program_id: "00".repeat(32),
        },
        20_000,
        xolotl_types::BudgetSpec::default(),
    )?;
    clock.0.store(1_200, Ordering::SeqCst);
    registration.finish(false);
    let finished_at = state
        .executions
        .records()
        .record_by_id(id(&reference)?)
        .and_then(|(_, record)| match &record.phase {
            Phase::Finished { finished_at, .. } => Some(*finished_at),
            _ => None,
        })
        .context("finished execution after clock rollback")?;
    ensure!(finished_at == 1_500);
    Ok(())
}

#[tokio::test]
async fn result_authorization_can_reenter_the_directory() -> anyhow::Result<()> {
    let (registry, boot) = registry(1, 1, 2)?;
    let owner = owner("first")?;
    let (registration, _, reference) = register(&registry, &boot, &owner, 7)?;
    let id = id(&reference)?.to_owned();
    boot.finalize_process(ProcessId::new(7)).await?;
    registration.finish(true);
    grant_observation(&registry, &id)?;

    let worker_registry = Arc::clone(&registry);
    let worker_owner = owner.clone();
    let worker_id = id.clone();
    let (done, received) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = worker_registry.result(&worker_owner, &worker_id, |_| {
            worker_registry.get(&worker_owner, &worker_id).is_ok()
        });
        done.send(result.is_ok())
    });
    ensure!(received.recv_timeout(Duration::from_secs(2))?);
    worker
        .join()
        .map_err(|panic| anyhow::anyhow!("reader panicked: {}", panic_message(&*panic)))??;

    let expiration = std::cell::RefCell::new(None);
    let result = registry.result(&owner, &id, |_| {
        *expiration.borrow_mut() = Some(expire(&registry, &id));
        true
    });
    expiration
        .into_inner()
        .context("expiry callback was not invoked")??;
    ensure!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn slow_result_authorization_does_not_block_other_directory_reads() -> anyhow::Result<()> {
    let (registry, boot) = registry(1, 1, 2)?;
    let owner = owner("first")?;
    let (registration, _, reference) = register(&registry, &boot, &owner, 7)?;
    let id = id(&reference)?.to_owned();
    boot.finalize_process(ProcessId::new(7)).await?;
    registration.finish(true);
    grant_observation(&registry, &id)?;

    let result_registry = Arc::clone(&registry);
    let result_owner = owner.clone();
    let result_id = id.clone();
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let result_worker = std::thread::spawn(move || {
        result_registry
            .result(&result_owner, &result_id, |_| {
                entered.send(()).is_ok() && release_rx.recv().is_ok()
            })
            .is_ok()
    });
    entered_rx.recv_timeout(Duration::from_secs(2))?;

    let read_registry = Arc::clone(&registry);
    let (read_done, read_rx) = std::sync::mpsc::channel();
    let read_worker =
        std::thread::spawn(move || read_done.send(read_registry.get(&owner, &id).is_ok()));
    let read_completed = read_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or(false);
    release.send(())?;
    ensure!(
        result_worker
            .join()
            .map_err(|panic| anyhow::anyhow!("reader panicked: {}", panic_message(&*panic)))?
    );
    read_worker
        .join()
        .map_err(|panic| anyhow::anyhow!("reader panicked: {}", panic_message(&*panic)))??;
    ensure!(
        read_completed,
        "unrelated read waited for authorization callback"
    );
    Ok(())
}

#[tokio::test]
async fn cleanup_custody_survives_expiry_and_blocks_forget_and_admission() -> anyhow::Result<()> {
    let (registry, boot) = registry(1, 1, 2)?;
    let owner = owner("first")?;
    let (mut registration, _, reference) = register(&registry, &boot, &owner, 7)?;
    registration.record_body(body());
    registration.settle(false);
    ensure!(registry.forget(&owner, id(&reference)?).await.is_err());
    ensure!(matches!(
        register(&registry, &boot, &owner, 8),
        Err(ConsoleError::RateLimited)
    ));
    expire(&registry, id(&reference)?)?;
    ensure!(registry.get(&owner, id(&reference)?).is_err());
    ensure!(registry.result(&owner, id(&reference)?, |_| true).is_err());
    ensure!(
        field(&registry.list(&owner, None, 10, usize::MAX)?, "entries")?
            .as_list()
            .context("list")?
            .is_empty()
    );
    let pending = registry.pending_cleanup();
    ensure!(pending.len() == 1 && pending[0].process == ProcessId::new(7));
    ensure!(registry.records().entries.len() == 1);
    ensure!(matches!(
        register(&registry, &boot, &owner, 8),
        Err(ConsoleError::RateLimited)
    ));
    boot.finish_process_as(pending[0].process, ProcessStatus::Completed)
        .await?;
    ensure!(registry.acknowledge_cleanup(&pending[0]));
    ensure!(!registry.acknowledge_cleanup(&pending[0]));
    ensure!(registry.records().entries.len() == 1);
    registry.maintain_volatile();
    ensure!(registry.records().entries.is_empty());
    let (mut next, _, _) = register(&registry, &boot, &owner, 8)?;
    next.reject();
    Ok(())
}

#[tokio::test]
async fn cleanup_confirmation_preserves_result_and_deadline_and_notifies_waiters()
-> anyhow::Result<()> {
    let (registry, boot) = registry(1, 1, 2)?;
    let owner = owner("first")?;
    let (mut registration, _, reference) = register(&registry, &boot, &owner, 7)?;
    registration.record_body(body());
    registration.settle(false);
    let before = registry.result(&owner, id(&reference)?, |_| true)?;
    let pending = registry
        .pending_cleanup()
        .pop()
        .context("pending cleanup")?;
    let changed = registry.changed.notified();
    tokio::pin!(changed);
    changed.as_mut().enable();
    let mut wrong = pending.clone();
    wrong.process = ProcessId::new(8);
    ensure!(!registry.acknowledge_cleanup(&wrong));
    boot.finish_process_as(pending.process, ProcessStatus::Completed)
        .await?;
    ensure!(registry.acknowledge_cleanup(&pending));
    ensure!(futures_util::FutureExt::now_or_never(changed).is_some());
    let after = registry.result(&owner, id(&reference)?, |_| true)?;
    ensure!(field(&before, "output")? == field(&after, "output")?);
    for name in ["finished_at", "expires_at"] {
        ensure!(field(field(&before, "record")?, name)? == field(field(&after, "record")?, name)?);
    }
    ensure!(field(field(&after, "record")?, "outcome")?.as_str() == Some("done"));
    ensure!(field(field(&after, "record")?, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(field(field(&after, "finalization")?, "status")?.as_str() == Some("available"));
    ensure!(
        !field(&after, "record")?
            .as_map()
            .context("record map")?
            .contains_key("audit_recorded")
    );
    ensure!(!registry.acknowledge_cleanup(&pending));
    ensure!(registry.result(&owner, id(&reference)?, |_| true)? == after);
    registry.forget(&owner, id(&reference)?).await?;
    ensure!(!registry.acknowledge_cleanup(&pending));
    Ok(())
}

#[tokio::test]
async fn observing_external_cleanup_releases_custody_without_changing_result_retention()
-> anyhow::Result<()> {
    let (registry, boot) = registry(2, 2, 3)?;
    let owner = owner("first")?;
    let (mut registration, _, reference) = register(&registry, &boot, &owner, 7)?;
    registration.record_body(body());
    registration.settle(false);
    let before = registry.result(&owner, id(&reference)?, |_| true)?;
    ensure!(registry.pending_volatile_cleanup_count() == 1);
    boot.finish_process_as(ProcessId::new(7), ProcessStatus::Completed)
        .await?;
    let after = registry.result(&owner, id(&reference)?, |_| true)?;
    ensure!(field(&before, "output")? == field(&after, "output")?);
    for name in ["outcome", "finished_at", "expires_at"] {
        ensure!(field(field(&before, "record")?, name)? == field(field(&after, "record")?, name)?);
    }
    ensure!(field(field(&after, "record")?, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(registry.pending_cleanup().is_empty());
    ensure!(registry.pending_volatile_cleanup_count() == 0);
    ensure!(
        registry
            .records()
            .entries
            .values()
            .all(|record| record.cleanup_ticket.is_none())
    );
    registry.maintain_volatile();
    ensure!(
        registry
            .records()
            .entries
            .values()
            .all(|record| record.cleanup_ticket.is_none())
    );

    let (second, _, expired) = register(&registry, &boot, &owner, 8)?;
    second.finish(false);
    expire(&registry, id(&expired)?)?;
    ensure!(registry.pending_volatile_cleanup_count() == 1);
    ensure!(registry.records().entries.len() == 2);
    boot.finish_process_as(ProcessId::new(8), ProcessStatus::Completed)
        .await?;
    ensure!(registry.pending_volatile_cleanup_count() == 1);
    registry.maintain_volatile();
    ensure!(registry.pending_volatile_cleanup_count() == 0);
    ensure!(registry.records().entries.len() == 1);
    ensure!(registry.result(&owner, id(&reference)?, |_| true)? == after);
    Ok(())
}

#[test]
fn ticket_binding_rejects_another_process_and_missing_tickets_remain_visible_to_shutdown()
-> anyhow::Result<()> {
    let (registry, boot) = registry(1, 1, 2)?;
    let owner = owner("first")?;
    let (mut registration, _, _) = registry.register(
        owner,
        Vec::new(),
        ExecutionReference {
            execution_id: None,
            process_id: "7".into(),
            program_id: "00".repeat(32),
        },
        xolotl_kernel::host::system_now_millis() + 60_000,
        xolotl_types::BudgetSpec::default(),
    )?;
    ensure!(
        registration
            .bind_cleanup(boot.cleanup_ticket(ProcessId::new(8))?)
            .is_err()
    );
    registration.settle(false);
    ensure!(registry.pending_cleanup().is_empty());
    ensure!(registry.pending_volatile_cleanup_count() == 1);
    registration.bind_cleanup(boot.cleanup_ticket(ProcessId::new(7))?)?;
    ensure!(registry.pending_cleanup().len() == 1);
    ensure!(registry.pending_volatile_cleanup_count() == 1);
    Ok(())
}

#[tokio::test]
async fn released_cleanup_uses_both_account_and_global_concurrency_capacity() -> anyhow::Result<()>
{
    let (registry, boot) = registry(2, 1, 4)?;
    let first = owner("first")?;
    let second = owner("second")?;
    let third = owner("third")?;
    let (first_registration, _, _) = register(&registry, &boot, &first, 7)?;
    first_registration.finish(false);
    ensure!(matches!(
        register(&registry, &boot, &first, 8),
        Err(ConsoleError::RateLimited)
    ));
    let (second_registration, _, _) = register(&registry, &boot, &second, 8)?;
    second_registration.finish(false);
    ensure!(matches!(
        register(&registry, &boot, &third, 9),
        Err(ConsoleError::RateLimited)
    ));
    let pending = registry
        .pending_cleanup()
        .into_iter()
        .find(|candidate| candidate.process == ProcessId::new(7))
        .context("first")?;
    boot.finish_process_as(pending.process, ProcessStatus::Completed)
        .await?;
    ensure!(registry.acknowledge_cleanup(&pending));
    let (mut replacement, _, _) = register(&registry, &boot, &first, 9)?;
    replacement.reject();
    Ok(())
}

#[tokio::test]
async fn a_released_source_does_not_pin_receipts_or_admit_children_while_cleanup_is_pending()
-> anyhow::Result<()> {
    let (registry, boot) = registry(2, 2, 3)?;
    let owner = owner("first")?;
    let (mut parent, _, reference) = register(&registry, &boot, &owner, 7)?;
    let origin = ExecutionOrigin {
        execution_id: id(&reference)?.into(),
        operation: OperationId::new(
            ProcessId::new(7),
            ExecutionId::FIRST,
            InvocationId::new(1),
            CausalPosition::new(1),
            0,
        ),
    };
    let child_reference = ExecutionReference {
        execution_id: None,
        process_id: "8".into(),
        program_id: reference.program_id,
    };
    let register_child = || {
        registry.register_child(
            owner.clone(),
            Vec::new(),
            child_reference.clone(),
            xolotl_kernel::host::system_now_millis() + 60_000,
            origin.clone(),
        )
    };
    let ChildRegistration::Reserved(mut child, _, accepted) = register_child()? else {
        anyhow::bail!("child reservation");
    };
    child.bind_cleanup(boot.cleanup_ticket(ProcessId::new(8))?)?;
    child.record_body(body());
    boot.finish_process_as(ProcessId::new(8), ProcessStatus::Completed)
        .await?;
    child.settle(true);
    expire(&registry, id(&accepted)?)?;
    ensure!(
        registry.records().entries.len() == 2,
        "a running source pins its receipt"
    );
    ensure!(matches!(register_child()?, ChildRegistration::Existing(_)));
    parent.settle(false);
    registry.maintain_volatile();
    ensure!(
        registry.records().entries.len() == 1,
        "pending cleanup cannot extend source execution"
    );
    ensure!(register_child().is_err());
    ensure!(registry.pending_cleanup().len() == 1);
    Ok(())
}

#[test]
fn root_authority_limit_charges_retained_candidates_before_reserving() -> anyhow::Result<()> {
    let owner = owner("candidate-root")?;
    let authority = vec![("read".into(), Path::parse("state://visible")?)];
    let base = test_candidates(&authority)?;
    let candidates: Arc<[Capability]> = (0..16)
        .flat_map(|_| base.iter().cloned())
        .collect::<Vec<_>>()
        .into();
    for budget in [
        xolotl_types::BudgetSpec::default(),
        xolotl_types::BudgetSpec {
            max_micro_usd: Some(u64::MAX),
            max_inflight_ops: Some(u32::MAX),
            max_inference_tokens: Some(u64::MAX),
        },
    ] {
        let origin: Option<ExecutionOrigin> = None;
        let complete =
            serde_json::to_vec(&(&owner, &authority, &origin, candidates.as_ref(), &budget))?.len();
        let omitted = serde_json::to_vec(&(&owner, &authority, &origin, &budget))?.len();
        ensure!(omitted < complete - 1);
        for limit in [complete - 1, complete] {
            let registry = ExecutionRegistry::new(ConsoleExecutionConfig {
                enabled: true,
                max_authority_bytes: limit,
                max_concurrent: 1,
                max_concurrent_per_account: 1,
                max_records: 1,
                max_records_per_account: 1,
                ..Default::default()
            })?;
            let admission = |candidates: Arc<[Capability]>| Admission {
                owner: owner.clone(),
                authority: authority.clone(),
                authority_candidates: candidates,
                reference: ExecutionReference {
                    execution_id: None,
                    process_id: "7".into(),
                    program_id: "00".repeat(32),
                },
                budget: budget.clone(),
                deadline: xolotl_kernel::host::system_now_millis() + 60_000,
                origin: None,
                stream_output: true,
            };
            let result = registry.register_authorized(admission(Arc::clone(&candidates)));
            if limit < complete {
                ensure!(matches!(
                    result,
                    Err(ConsoleError::BadRequest(message))
                        if message == "execution authority exceeds the host retention limit"
                ));
                let records = registry.records();
                ensure!(records.entries.is_empty());
                ensure!(records.id_to_sequence.is_empty());
                ensure!(records.sequence == 0);
                drop(records);
                let (mut replacement, _, _) = registry
                    .register_authorized(admission(Arc::from(test_candidates(&authority)?)))?;
                replacement.reject();
                ensure!(registry.records().entries.is_empty());
            } else {
                let (mut registration, _, reference) = result?;
                let records = registry.records();
                let record = records
                    .entries
                    .get(&registration.sequence)
                    .context("root")?;
                ensure!(record.budget == budget);
                ensure!(Arc::ptr_eq(&record.authority_candidates, &candidates));
                drop(records);
                ensure!(
                    registry
                        .result(&owner, id(&reference)?, |retained| retained
                            == candidates.as_ref())
                        .is_ok()
                );
                ensure!(matches!(
                    registry.result(&owner, id(&reference)?, |_| false),
                    Err(ConsoleError::Auth(crate::auth::AuthError::PermissionDenied))
                ));
                ensure!(matches!(
                    registry.register_authorized(admission(Arc::clone(&candidates))),
                    Err(ConsoleError::RateLimited)
                ));
                registration.reject();
            }
        }
    }
    Ok(())
}

#[test]
fn child_authority_limit_charges_source_candidates_and_actual_budget() -> anyhow::Result<()> {
    let owner = owner("candidate-child")?;
    let authority = vec![("read".into(), Path::parse("state://visible")?)];
    let base = test_candidates(&authority)?;
    let candidates: Arc<[Capability]> = (0..16)
        .flat_map(|_| base.iter().cloned())
        .collect::<Vec<_>>()
        .into();
    for budget in [
        xolotl_types::BudgetSpec::default(),
        xolotl_types::BudgetSpec {
            max_micro_usd: Some(u64::MAX),
            max_inflight_ops: Some(u32::MAX),
            max_inference_tokens: Some(u64::MAX),
        },
    ] {
        let mut origin = ExecutionOrigin {
            execution_id: "a".repeat(32),
            operation: OperationId::new(
                ProcessId::new(7),
                ExecutionId::FIRST,
                InvocationId::new(1),
                CausalPosition::new(1),
                0,
            ),
        };
        let complete = serde_json::to_vec(&(
            &owner,
            &authority,
            Some(&origin),
            candidates.as_ref(),
            &budget,
        ))?
        .len();
        let omitted = serde_json::to_vec(&(&owner, &authority, Some(&origin), &budget))?.len();
        ensure!(omitted < complete - 1);
        for limit in [complete - 1, complete] {
            let registry = ExecutionRegistry::new(ConsoleExecutionConfig {
                enabled: true,
                max_authority_bytes: limit,
                max_concurrent: 2,
                max_concurrent_per_account: 2,
                max_records: 2,
                max_records_per_account: 2,
                ..Default::default()
            })?;
            let (mut parent, _, parent_reference) = registry.register_authorized(Admission {
                owner: owner.clone(),
                authority: authority.clone(),
                authority_candidates: Arc::clone(&candidates),
                reference: ExecutionReference {
                    execution_id: None,
                    process_id: "7".into(),
                    program_id: "00".repeat(32),
                },
                budget: budget.clone(),
                deadline: xolotl_kernel::host::system_now_millis() + 60_000,
                origin: None,
                stream_output: false,
            })?;
            origin.execution_id = id(&parent_reference)?.into();
            let child = || {
                registry.register_child(
                    owner.clone(),
                    authority.clone(),
                    ExecutionReference {
                        execution_id: None,
                        process_id: "8".into(),
                        program_id: parent_reference.program_id.clone(),
                    },
                    xolotl_kernel::host::system_now_millis() + 60_000,
                    origin.clone(),
                )
            };
            if limit < complete {
                for _ in 0..2 {
                    ensure!(matches!(
                        child(),
                        Err(ConsoleError::BadRequest(message))
                            if message == "execution authority exceeds the host retention limit"
                    ));
                    let records = registry.records();
                    ensure!(records.entries.len() == 1);
                    ensure!(records.id_to_sequence.len() == 1);
                    ensure!(records.sequence == parent.sequence);
                    ensure!(
                        records
                            .entries
                            .values()
                            .all(|record| record.origin.is_none())
                    );
                }
                let (mut replacement, _, _) = registry.register(
                    owner.clone(),
                    Vec::new(),
                    ExecutionReference {
                        execution_id: None,
                        process_id: "9".into(),
                        program_id: parent_reference.program_id.clone(),
                    },
                    xolotl_kernel::host::system_now_millis() + 60_000,
                    budget.clone(),
                )?;
                replacement.reject();
            } else {
                let ChildRegistration::Reserved(mut registration, _, reference) = child()? else {
                    anyhow::bail!("expected child reservation");
                };
                let records = registry.records();
                let record = records
                    .entries
                    .get(&registration.sequence)
                    .context("child")?;
                ensure!(record.budget == budget);
                ensure!(record.origin.as_ref() == Some(&origin));
                ensure!(Arc::ptr_eq(&record.authority_candidates, &candidates));
                ensure!(!record.accepted);
                drop(records);
                ensure!(
                    registry
                        .result(&owner, id(&reference)?, |retained| retained
                            == candidates.as_ref())
                        .is_ok()
                );
                ensure!(matches!(
                    registry.result(&owner, id(&reference)?, |_| false),
                    Err(ConsoleError::Auth(crate::auth::AuthError::PermissionDenied))
                ));
                ensure!(matches!(child(), Err(ConsoleError::RateLimited)));
                registration.accepted();
                let ChildRegistration::Existing(existing) = child()? else {
                    anyhow::bail!("expected accepted receipt");
                };
                ensure!(existing == reference);
                registration.reject();
                let ChildRegistration::Reserved(mut retry, _, _) = child()? else {
                    anyhow::bail!("expected released reservation");
                };
                retry.reject();
            }
            ensure!(
                registry
                    .result(&owner, id(&parent_reference)?, |retained| retained
                        == candidates.as_ref())
                    .is_ok()
            );
            ensure!(matches!(
                registry.result(&owner, id(&parent_reference)?, |_| false),
                Err(ConsoleError::Auth(crate::auth::AuthError::PermissionDenied))
            ));
            parent.reject();
            ensure!(registry.records().entries.is_empty());
        }
    }
    Ok(())
}

#[test]
fn child_authority_limit_counts_the_source_budget_exactly() -> anyhow::Result<()> {
    let owner = owner("first")?;
    let authority = vec![("read".into(), Path::parse("state://visible")?)];
    let candidates = test_candidates(&authority)?;
    let origin = ExecutionOrigin {
        execution_id: "a".repeat(32),
        operation: OperationId::new(
            ProcessId::new(7),
            ExecutionId::FIRST,
            InvocationId::new(1),
            CausalPosition::new(1),
            0,
        ),
    };
    for budget in [
        xolotl_types::BudgetSpec::default(),
        xolotl_types::BudgetSpec {
            max_micro_usd: Some(u64::MAX),
            max_inflight_ops: Some(u32::MAX),
            max_inference_tokens: Some(u64::MAX),
        },
    ] {
        let encoded =
            serde_json::to_vec(&(&owner, &authority, Some(&origin), &candidates, &budget))?;
        let candidates_len = serde_json::to_vec(&candidates)?.len();
        let budget_len = serde_json::to_vec(&budget)?.len();
        let registry = |limit| {
            ExecutionRegistry::new(ConsoleExecutionConfig {
                max_authority_bytes: limit,
                ..Default::default()
            })
        };
        let at_limit = registry(encoded.len())?;
        let prepared = at_limit.prepare_child_reservation(&owner, &authority, &origin)?;
        ensure!(prepared.authority_bytes_available == Some(candidates_len + budget_len));
        ExecutionRegistry::check_retained_authority_bytes(
            prepared
                .authority_bytes_available
                .context("authority limit")?,
            &candidates,
            &budget,
        )?;

        let below_limit = registry(encoded.len() - 1)?;
        let prepared = below_limit.prepare_child_reservation(&owner, &authority, &origin)?;
        ensure!(
            ExecutionRegistry::check_retained_authority_bytes(
                prepared
                    .authority_bytes_available
                    .context("authority limit")?,
                &candidates,
                &budget,
            )
            .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn shutdown_waits_for_attempt_exit_without_discarding_pending_cleanup() -> anyhow::Result<()>
{
    let (registry, boot) = registry(1, 1, 2)?;
    let owner = owner("first")?;
    let (registration, stop, _) = register(&registry, &boot, &owner, 7)?;
    let shutdown = registry.shutdown();
    tokio::pin!(shutdown);
    ensure!(futures_util::FutureExt::now_or_never(shutdown.as_mut()).is_none());
    ensure!(matches!(*stop.borrow(), Some(StopReason::Shutdown)));
    ensure!(registry.pending_cleanup().is_empty());
    registration.finish(false);
    tokio::time::timeout(Duration::from_millis(100), shutdown).await?;
    ensure!(registry.pending_cleanup().len() == 1);
    ensure!(
        registry
            .records()
            .entries
            .values()
            .all(Record::custody_pending)
    );
    ensure!(!registry.accepting());
    Ok(())
}
