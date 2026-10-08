use super::*;
use crate::policy::{CheckCtx, ConstraintCheck, PolicyDecision, PolicySource};
use std::sync::{
    Weak,
    atomic::{AtomicUsize, Ordering},
};

fn request(process: ProcessId, resource: ResourceId) -> OpenRequest {
    OpenRequest {
        process,
        resource,
        verb: "perform".into(),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        acting: IdentityRef::ROOT,
        requested_path: None,
        now_millis: 10,
    }
}

fn grant(registry: &Registry, holder: ProcessId) -> Grant {
    Grant {
        id: registry.next_grant_id(),
        holder,
        selector: ResourceSelector::all(),
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    }
}

#[test]
fn propagation_only_open_preserves_category_and_cannot_gain_callable_rights() -> anyhow::Result<()>
{
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/delegation")?;
    let owner = ProcessId::new(7);
    let mut req = request(owner, resource);
    req.rights = Rights::new(MethodBitmap::empty(), RightFlags::DELEGATE);
    let prepared = prepare_open(&registry, req, &[grant(&registry, owner)])?;
    ensure!(prepared.open_verb() == "perform");
    let handles = HandleTable::new();
    let root = prepared.install(&handles)?;
    let child = handles.derive(
        root,
        prepared.rights(),
        xolotl_types::DeriveKind::Delegate,
        owner,
    )?;
    let snapshot = handles.get(child).context("derived handle")?;
    ensure!(snapshot.open_verb == "perform" && !snapshot.allows_method(0));
    ensure!(
        handles
            .derive(
                child,
                request(owner, resource).rights,
                xolotl_types::DeriveKind::Delegate,
                owner
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn preparation_is_inspectable_and_discarding_it_allocates_no_handle() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/inspect")?;
    let process = ProcessId::new(7);
    let grant = grant(&registry, process);
    let handles = HandleTable::new();
    let prepared = prepare_open(
        &registry,
        request(process, resource),
        std::slice::from_ref(&grant),
    )?;
    ensure!(prepared.process() == process && prepared.acting() == IdentityRef::ROOT);
    ensure!(prepared.resource() == resource);
    ensure!(prepared.path() == &Path::parse("effect://prepared/inspect")?);
    ensure!(prepared.rights() == request(process, resource).rights);
    ensure!(prepared.policy().is_none());
    ensure!(
        prepared
            .driver_plan()
            .supports(xolotl_types::MethodId::new(100))
    );
    ensure!(handles.is_empty());
    drop(prepared);
    ensure!(handles.is_empty());

    let prepared = prepare_open(&registry, request(process, resource), &[grant])?;
    let handle = prepared.install(&handles)?;
    ensure!(handle.index == 0 && handle.generation == 1);
    ensure!(handles.get(handle).context("installed")?.process == process);
    Ok(())
}

#[test]
fn both_new_and_cached_preparations_reject_control_changes_before_installation()
-> anyhow::Result<()> {
    for cached in [false, true] {
        let registry = Registry::new();
        let resource = setup_resource(&registry, "effect://prepared/stale")?;
        let process = ProcessId::new(7);
        let mut grant = grant(&registry, process);
        registry.register_grant(grant.clone());
        let handles = HandleTable::new();
        if cached {
            drop(prepare_open(&registry, request(process, resource), &[])?);
        }
        let prepared = prepare_open(&registry, request(process, resource), &[])?;
        ensure!(registry.open_cache_stats().0 == u64::from(cached));
        grant.rights.methods = xolotl_types::GrantMethods::none();
        registry.register_grant(grant);
        ensure!(matches!(
            prepared.install(&handles),
            Err(OpenError::RegistryChanged)
        ));
        ensure!(handles.is_empty());
        ensure!(matches!(
            prepare_open(&registry, request(process, resource), &[]),
            Err(OpenError::RightsNotSubset)
        ));
    }
    Ok(())
}

#[test]
fn unrelated_endpoint_changes_preserve_local_open_and_its_cache() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/local_endpoint_independence")?;
    let owner = ProcessId::new(7);
    registry.register_grant(grant(&registry, owner));
    let prepared = prepare_open(&registry, request(owner, resource), &[])?;
    ensure!(registry.open_cache_stats().2 == 1);
    let revision = registry.revision();
    let endpoint = registry.next_endpoint_id();
    registry.register_endpoint(
        endpoint,
        Arc::new(TestEndpoint {
            seen: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }),
    );
    ensure!(registry.revision() == revision && registry.open_cache_stats().2 == 1);
    let handles = HandleTable::new();
    prepared.install(&handles)?;
    drop(prepare_open(&registry, request(owner, resource), &[])?);
    ensure!(registry.open_cache_stats().0 == 1);
    ensure!(registry.unregister_endpoint(endpoint));
    ensure!(registry.revision() == revision && registry.open_cache_stats().2 == 1);
    Ok(())
}

#[test]
fn endpoint_replacement_retires_only_dependent_plans() -> anyhow::Result<()> {
    let registry = Registry::new();
    let first_endpoint = registry.next_endpoint_id();
    let second_endpoint = registry.next_endpoint_id();
    let endpoint = || {
        Arc::new(TestEndpoint {
            seen: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }) as crate::driver::DynRemoteEndpoint
    };
    registry.register_endpoint(first_endpoint, endpoint());
    registry.register_endpoint(second_endpoint, endpoint());
    let first = setup_remote_resource(
        &registry,
        "effect://external-provider/prepared/first",
        first_endpoint,
    )?;
    let second = setup_remote_resource(
        &registry,
        "effect://external-provider/prepared/second",
        second_endpoint,
    )?;
    let local = setup_resource(&registry, "effect://prepared/local_alongside_remote")?;
    let owner = ProcessId::new(7);
    registry.register_grant(grant(&registry, owner));
    let prepared_first = prepare_open(&registry, request(owner, first), &[])?;
    let prepared_second = prepare_open(&registry, request(owner, second), &[])?;
    let prepared_local = prepare_open(&registry, request(owner, local), &[])?;
    ensure!(registry.open_cache_stats().2 == 3);
    let revision = registry.revision();

    registry.register_endpoint(first_endpoint, endpoint());
    ensure!(registry.revision() == revision && registry.open_cache_stats().2 == 2);
    let handles = HandleTable::new();
    ensure!(matches!(
        prepared_first.install(&handles),
        Err(OpenError::RegistryChanged)
    ));
    prepared_second.install(&handles)?;
    prepared_local.install(&handles)?;
    let replacement = prepare_open(&registry, request(owner, first), &[])?;
    ensure!(registry.open_cache_stats().2 == 3);
    replacement.install(&handles)?;

    ensure!(registry.unregister_endpoint(first_endpoint));
    ensure!(registry.open_cache_stats().2 == 2);
    ensure!(matches!(
        replacement.install(&handles),
        Err(OpenError::RegistryChanged)
    ));
    ensure!(matches!(
        prepare_open(&registry, request(owner, first), &[]),
        Err(OpenError::NoSuchEndpoint(id)) if id == first_endpoint
    ));
    Ok(())
}

#[tokio::test]
async fn expiring_grant_is_checked_at_open_and_at_each_operation() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/expires")?;
    let owner = ProcessId::new(7);
    let mut limited = grant(&registry, owner);
    limited.expires = Expiry::At(20);
    registry.register_grant(limited);

    for now in [10, 20] {
        let mut req = request(owner, resource);
        req.now_millis = now;
        let prepared = prepare_open(&registry, req, &[])?;
        let policy = prepared.policy().context("expiry is residual")?;
        let decision = policy
            .check(&CheckCtx {
                input: &Value::null(),
                acting: IdentityRef::ROOT,
                now_millis: now,
                target: resource,
            })
            .await;
        ensure!(decision.is_allow());
        let expired = policy
            .check(&CheckCtx {
                input: &Value::null(),
                acting: IdentityRef::ROOT,
                now_millis: 21,
                target: resource,
            })
            .await;
        ensure!(matches!(expired, PolicyDecision::Deny { .. }));
    }
    ensure!(registry.open_cache_stats() == (0, 0, 0));

    let mut expired = request(owner, resource);
    expired.now_millis = 21;
    ensure!(matches!(
        prepare_open(&registry, expired, &[]),
        Err(OpenError::NoMatchingGrant { .. })
    ));
    ensure!(registry.open_cache_stats() == (0, 0, 0));
    Ok(())
}

#[tokio::test]
async fn matching_grants_are_alternatives_across_registered_and_attached_sources()
-> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/tenants")?;
    let owner = ProcessId::new(7);
    let mut alice = grant(&registry, owner);
    alice.selector = ResourceSelector::parse("perform://effect/prepared/tenants@tenant=alice")?;
    registry.register_grant(alice);
    let mut bob = grant(&registry, owner);
    bob.selector = ResourceSelector::parse("perform://effect/prepared/tenants@tenant=bob")?;
    let mut wrong_rights = grant(&registry, owner);
    wrong_rights.selector =
        ResourceSelector::parse("perform://effect/prepared/tenants@tenant=mallory")?;
    wrong_rights.rights.methods = xolotl_types::GrantMethods::none();
    let prepared = prepare_open(&registry, request(owner, resource), &[bob, wrong_rights])?;
    let policy = prepared.policy().context("grant alternatives")?;
    for (tenant, allowed) in [("alice", true), ("bob", true), ("mallory", false)] {
        let input = Value::map(
            [("tenant".into(), Value::string(tenant.into()))]
                .into_iter()
                .collect(),
        );
        let decision = policy
            .check(&CheckCtx {
                input: &input,
                acting: IdentityRef::ROOT,
                now_millis: 10,
                target: resource,
            })
            .await;
        ensure!(decision.is_allow() == allowed, "{tenant}: {decision:?}");
    }
    ensure!(registry.open_cache_stats() == (0, 0, 0));
    Ok(())
}

#[test]
fn cache_eviction_keeps_prepared_and_installed_plans_alive() -> anyhow::Result<()> {
    for capacity in [0, 2] {
        let registry = Registry::with_open_cache_capacity(capacity);
        let resource = setup_state_subtree_resource(&registry)?;
        let owner = ProcessId::new(7);
        registry.register_grant(grant(&registry, owner));
        let request_at = |index: u64| -> anyhow::Result<OpenRequest> {
            let mut req = request(owner, resource);
            req.verb = "read".into();
            req.requested_path = Some(Path::parse(&format!("state://prepared/bounded/{index}"))?);
            Ok(req)
        };
        let retained = prepare_open(&registry, request_at(0)?, &[])?;
        let handles = HandleTable::new();
        let installed = prepare_open(&registry, request_at(0)?, &[])?.install(&handles)?;
        for index in 1..80 {
            drop(prepare_open(&registry, request_at(index)?, &[])?);
            ensure!(registry.open_cache_stats().2 <= capacity);
        }
        ensure!(registry.open_cache_capacity() == capacity);
        ensure!(registry.open_cache_stats().2 == capacity);
        ensure!(handles.get(installed).is_some());
        let admitted_after_eviction = retained.install(&handles)?;
        ensure!(handles.get(admitted_after_eviction).is_some() && handles.len() == 2);
    }
    Ok(())
}

#[test]
fn oversized_open_keys_still_prepare_and_install_without_cache_retention() -> anyhow::Result<()> {
    for clustered in [false, true] {
        let registry = Registry::new();
        let owner = ProcessId::new(7);
        let prefix = if clustered {
            "path://edge/effect/cache/"
        } else {
            "state://application/"
        };
        let at_limit = Path::parse(&format!("{prefix}{}", "a".repeat(1024 - prefix.len())))?;
        let over_limit = Path::parse(&format!("{prefix}{}", "b".repeat(1025 - prefix.len())))?;
        ensure!(at_limit.canonical_len() == Some(1024));
        ensure!(over_limit.canonical_len() == Some(1025));
        let resource = if clustered {
            setup_resource(&registry, &over_limit.to_string())?
        } else {
            setup_state_subtree_resource(&registry)?
        };
        registry.register_grant(grant(&registry, owner));
        let handles = HandleTable::new();
        let request_for = |path: &Path| OpenRequest {
            process: owner,
            resource,
            verb: if clustered { "perform" } else { "read" }.into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: Some(path.clone()),
            now_millis: 10,
        };
        for _ in 0..2 {
            let opened = prepare_open(&registry, request_for(&over_limit), &[])?;
            let id = opened.install(&handles)?;
            ensure!(
                handles.get(id).context("opened handle")?.bound_path == Some(over_limit.clone())
            );
        }
        ensure!(registry.open_cache_stats() == (0, 0, 0));
        if !clustered {
            for _ in 0..2 {
                drop(prepare_open(&registry, request_for(&at_limit), &[])?);
            }
            ensure!(registry.open_cache_stats() == (1, 1, 1));
        }
    }
    Ok(())
}

#[test]
fn large_registered_grant_constraints_do_not_multiply_in_the_cache() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/large_grant")?;
    let owner = ProcessId::new(7);
    let mut source = grant(&registry, owner);
    source
        .constraints
        .predicates
        .push(xolotl_types::cap::Predicate::parse(&format!(
            "account={}",
            "x".repeat(8192)
        ))?);
    registry.register_grant(source);
    let handles = HandleTable::new();
    for now in 10..20 {
        let mut req = request(owner, resource);
        req.now_millis = now;
        let prepared = prepare_open(&registry, req, &[])?;
        ensure!(prepared.policy().context("large residual")?.len() == 1);
        ensure!(handles.get(prepared.install(&handles)?).is_some());
    }
    ensure!(registry.open_cache_stats() == (0, 0, 0));
    Ok(())
}

struct LargeResidualSource(AtomicUsize);

impl PolicySource for LargeResidualSource {
    fn applies_to(&self, _: &OpenContext) -> bool {
        true
    }

    fn compile(&self, _: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let predicate =
            xolotl_types::cap::Predicate::parse(&format!("account={}", "x".repeat(8192)))
                .map_err(|error| PolicyCompileError::DeniedAtOpen(error.to_string()))?;
        Ok(PolicySnapshot::new(vec![Arc::new(ConstraintCheck {
            constraints: ConstraintSet {
                predicates: vec![predicate],
            },
        })]))
    }
}

#[test]
fn source_policies_do_not_leave_native_residuals_in_the_open_cache() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/native_residual")?;
    let owner = ProcessId::new(7);
    registry.register_grant(grant(&registry, owner));
    let source = Arc::new(LargeResidualSource(AtomicUsize::new(0)));
    registry.register_policy(source.clone());
    for now in 10..20 {
        let mut req = request(owner, resource);
        req.now_millis = now;
        let prepared = prepare_open(&registry, req, &[])?;
        ensure!(prepared.policy().context("source residual")?.len() == 1);
    }
    ensure!(source.0.load(Ordering::SeqCst) == 10);
    ensure!(registry.open_cache_stats() == (0, 0, 0));
    Ok(())
}

#[test]
fn long_propagation_only_verb_remains_valid_without_cache_retention() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/long_verb")?;
    let owner = ProcessId::new(7);
    registry.register_grant(grant(&registry, owner));
    let handles = HandleTable::new();
    for _ in 0..2 {
        let mut req = request(owner, resource);
        req.verb = "x".repeat(257);
        req.rights.methods = MethodBitmap::empty();
        let prepared = prepare_open(&registry, req, &[])?;
        ensure!(handles.get(prepared.install(&handles)?).is_some());
    }
    ensure!(registry.open_cache_stats() == (0, 0, 0));
    Ok(())
}

struct ChangeRegistryDuringCompile {
    registry: Weak<Registry>,
    grant: Grant,
}

impl PolicySource for ChangeRegistryDuringCompile {
    fn applies_to(&self, _: &OpenContext) -> bool {
        true
    }

    fn compile(&self, _: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
        if let Some(registry) = self.registry.upgrade() {
            registry.register_grant(self.grant.clone());
        }
        Ok(PolicySnapshot::empty())
    }
}

#[test]
fn uncached_preparation_still_rejects_concurrent_registry_changes() -> anyhow::Result<()> {
    for attached in [false, true] {
        let registry = Arc::new(Registry::new());
        let path = if attached {
            Path::parse("effect://prepared/attached_revision")?
        } else {
            Path::parse(&format!("effect://{}", "x".repeat(1016)))?
        };
        let resource = setup_resource(&registry, &path.to_string())?;
        let owner = ProcessId::new(7);
        let selected = grant(&registry, owner);
        if !attached {
            registry.register_grant(selected.clone());
        }
        registry.register_policy(Arc::new(ChangeRegistryDuringCompile {
            registry: Arc::downgrade(&registry),
            grant: grant(&registry, ProcessId::new(8)),
        }));
        let supplied = attached.then_some(selected).into_iter().collect::<Vec<_>>();
        ensure!(matches!(
            prepare_open(&registry, request(owner, resource), &supplied),
            Err(OpenError::RegistryChanged)
        ));
        ensure!(registry.open_cache_stats() == (0, 0, 0));
    }
    Ok(())
}

#[tokio::test]
async fn attached_grant_id_reuse_cannot_reuse_another_grants_residual() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://prepared/constraints")?;
    let process = ProcessId::new(7);
    let mut grant = grant(&registry, process);
    let plain = prepare_open(
        &registry,
        request(process, resource),
        std::slice::from_ref(&grant),
    )?;
    ensure!(plain.policy().is_none());
    drop(plain);
    let revision = registry.revision();
    grant.constraints = ConstraintSet {
        predicates: vec![xolotl_types::cap::Predicate::parse("account=alice")?],
    };
    let constrained = prepare_open(
        &registry,
        request(process, resource),
        std::slice::from_ref(&grant),
    )?;
    let input = Value::map(std::collections::BTreeMap::from([(
        "account".into(),
        Value::from("bob"),
    )]));
    let context = CheckCtx {
        input: &input,
        acting: IdentityRef::ROOT,
        now_millis: 10,
        target: resource,
    };
    ensure!(matches!(
        constrained
            .policy()
            .context("new residual")?
            .check(&context)
            .await,
        PolicyDecision::Deny { .. }
    ));
    ensure!(registry.revision() == revision && registry.open_cache_stats() == (0, 0, 0));
    let repeated = prepare_open(
        &registry,
        request(process, resource),
        std::slice::from_ref(&grant),
    )?;
    ensure!(repeated.policy().context("recompiled residual")?.len() == 1);
    ensure!(registry.open_cache_stats() == (0, 0, 0));

    // The same ID in a different host-supplied holder domain is not the same grant.
    grant.holder = ProcessId::new(8);
    let foreign = prepare_open(
        &registry,
        request(grant.holder, resource),
        std::slice::from_ref(&grant),
    )?;
    ensure!(foreign.process() == grant.holder && registry.open_cache_stats() == (0, 0, 0));
    grant.constraints = ConstraintSet::empty();
    let unconstrained = prepare_open(&registry, request(grant.holder, resource), &[grant])?;
    ensure!(unconstrained.policy().is_none());
    ensure!(registry.open_cache_stats() == (0, 0, 0));
    Ok(())
}

#[test]
fn wildcard_targets_are_rejected_before_policy_callbacks_or_cache_entries() -> anyhow::Result<()> {
    struct CountPolicy(AtomicUsize);
    impl PolicySource for CountPolicy {
        fn applies_to(&self, _: &OpenContext) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
        fn compile(&self, _: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
            Ok(PolicySnapshot::empty())
        }
    }
    let boot = crate::Bootstrap::in_memory();
    boot.register_subtree_resource_at(
        "state://application",
        "*://state/application/**",
        InterfaceFamily::Value,
        &[crate::MethodSpec::new(
            "read",
            xolotl_types::MethodAuthority::Read,
            Purity::Pure,
            crate::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(EchoDriver),
    )?;
    let policy = Arc::new(CountPolicy(AtomicUsize::new(0)));
    boot.kernel().registry().register_policy(policy.clone());
    let handles = boot.kernel().handles().len();
    for path in ["state://application/*", "state://application/**"] {
        let name = ResourceName::new(Path::parse(path)?);
        ensure!(
            matches!(boot.open_for(boot.root(), &name, "read"), Err(OpenError::NonConcretePath(target)) if target == *name.path())
        );
    }
    ensure!(policy.0.load(Ordering::SeqCst) == 0);
    ensure!(
        boot.kernel().handles().len() == handles
            && boot.kernel().registry().open_cache_stats().2 == 0
    );
    // A wildcard Grant selector still authorizes an ordinary concrete open.
    boot.open_for(
        boot.root(),
        &ResourceName::new(Path::parse("state://application/item")?),
        "read",
    )?;
    ensure!(policy.0.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[test]
fn a_concrete_path_cannot_select_a_different_resource_driver() -> anyhow::Result<()> {
    let registry = Registry::new();
    let expected = setup_resource(&registry, "effect://prepared/expected")?;
    setup_resource(&registry, "effect://prepared/other")?;
    let process = ProcessId::new(7);
    let mut req = request(process, expected);
    req.requested_path = Some(Path::parse("effect://prepared/other")?);
    ensure!(matches!(
        prepare_open(&registry, req, &[grant(&registry, process)]),
        Err(OpenError::ResourcePathMismatch(id)) if id == expected
    ));
    ensure!(registry.open_cache_stats() == (0, 0, 0));
    Ok(())
}

struct ReenterAtCompile {
    boot: Weak<crate::Bootstrap>,
    outer: Path,
    nested: ResourceName,
    calls: AtomicUsize,
}

impl PolicySource for ReenterAtCompile {
    fn applies_to(&self, context: &OpenContext) -> bool {
        context.resource_path == &self.outer
    }

    fn compile(&self, _: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
        let deny = |reason: &str| PolicyCompileError::DeniedAtOpen(reason.into());
        let boot = self.boot.upgrade().ok_or_else(|| deny("host stopped"))?;
        // A failed regression reports an error immediately instead of hanging
        // the test by trying a nested open under a non-reentrant write lock.
        let handles = boot
            .kernel()
            .handles()
            .try_write()
            .ok_or_else(|| deny("handle table is locked during policy compilation"))?;
        drop(handles);
        boot.open_for(boot.root(), &self.nested, "perform")
            .map_err(|error| PolicyCompileError::DeniedAtOpen(error.to_string()))?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PolicySnapshot::empty())
    }
}

#[tokio::test]
async fn bootstrap_and_executor_allow_policy_compilation_to_reenter_open() -> anyhow::Result<()> {
    for via_executor in [false, true] {
        let boot = Arc::new(crate::Bootstrap::in_memory());
        setup_resource(boot.kernel().registry(), "effect://prepared/outer")?;
        setup_resource(boot.kernel().registry(), "effect://prepared/nested")?;
        let outer = ResourceName::new(Path::parse("effect://prepared/outer")?);
        let policy = Arc::new(ReenterAtCompile {
            boot: Arc::downgrade(&boot),
            outer: outer.path().clone(),
            nested: ResourceName::new(Path::parse("effect://prepared/nested")?),
            calls: AtomicUsize::new(0),
        });
        boot.kernel().registry().register_policy(policy.clone());
        if via_executor {
            let executor = crate::Executor::from_process_table(
                boot.root(),
                boot.kernel().processes().clone(),
                boot.kernel().data_plane(),
                boot.kernel().registry().clone(),
            )?;
            let operation = xolotl_graph::DoNode::op(xolotl_graph::OperationTemplate {
                target: outer,
                method: "invoke".into(),
                method_id: None,
                output: xolotl_types::OutputMode::Unary,
                literal_input: Some(Value::integer(42)),
            });
            let result = executor
                .eval_tainted(&operation, xolotl_types::TaintSet::pristine())
                .await;
            ensure!(
                result.outcome == xolotl_types::Outcome::Done(Value::integer(42)),
                "{:?}",
                result.outcome
            );
        } else {
            boot.open_for(boot.root(), &outer, "perform")?;
        }
        ensure!(policy.calls.load(Ordering::SeqCst) == 1);
        ensure!(boot.kernel().handles().read().len() == 2);
    }
    Ok(())
}

struct CancelAtCompile {
    boot: Weak<crate::Bootstrap>,
    owner: ProcessId,
}

impl PolicySource for CancelAtCompile {
    fn applies_to(&self, _: &OpenContext) -> bool {
        true
    }

    fn compile(&self, _: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
        let boot = self
            .boot
            .upgrade()
            .ok_or_else(|| PolicyCompileError::DeniedAtOpen("host stopped".into()))?;
        boot.cancel_process(self.owner)
            .map_err(|error| PolicyCompileError::DeniedAtOpen(error.to_string()))?;
        Ok(PolicySnapshot::empty())
    }
}

#[tokio::test]
async fn cancellation_during_compilation_cannot_install_a_late_handle() -> anyhow::Result<()> {
    for via_executor in [false, true] {
        let boot = Arc::new(crate::Bootstrap::in_memory());
        setup_resource(boot.kernel().registry(), "effect://prepared/cancel")?;
        let owner = boot.request_under(
            boot.root(),
            IdentityRef::ROOT,
            &[crate::CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse("perform://effect/prepared/**")?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::all(),
                    RightFlags::empty(),
                ),
            }],
        )?;
        boot.kernel()
            .registry()
            .register_policy(Arc::new(CancelAtCompile {
                boot: Arc::downgrade(&boot),
                owner: owner.id(),
            }));
        let target = ResourceName::new(Path::parse("effect://prepared/cancel")?);
        if via_executor {
            let result = owner
                .executor()
                .prepare_operation(&xolotl_graph::OperationTemplate {
                    target,
                    method: "invoke".into(),
                    method_id: None,
                    output: xolotl_types::OutputMode::Unary,
                    literal_input: None,
                });
            ensure!(result.is_err());
        } else {
            ensure!(
                matches!(boot.open_for(owner.id(), &target, "perform"), Err(OpenError::ProcessUnavailable(id)) if id == owner.id())
            );
        }
        ensure!(boot.kernel().handles().read().is_empty());
        owner
            .finish(&xolotl_types::ExecutionOutput {
                outcome: xolotl_types::Outcome::Fail(xolotl_types::Failure::Cancelled),
                taint: xolotl_types::TaintSet::pristine(),
                unresolved_operations: Default::default(),
            })
            .await?;
    }
    Ok(())
}
