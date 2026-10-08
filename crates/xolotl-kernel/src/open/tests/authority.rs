use super::*;
use xolotl_types::{MethodAuthority, MethodId, Outcome, OutputMode, TaintSet};

#[tokio::test]
async fn method_and_propagation_grants_form_two_independent_or_domains() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_resource(&registry, "effect://authority/composed")?;
    let owner = ProcessId::new(17);
    let candidate =
        |predicate: &str, rights: xolotl_types::GrantRights, expires| -> anyhow::Result<Grant> {
            Ok(Grant {
                id: registry.next_grant_id(),
                holder: owner,
                selector: ResourceSelector::parse(&format!(
                    "perform://effect/authority/composed@{predicate}"
                ))?,
                rights,
                constraints: ConstraintSet::empty(),
                expires,
            })
        };
    let method = xolotl_types::GrantRights::new(
        xolotl_types::GrantMethods::name("invoke"),
        RightFlags::empty(),
    );
    let propagation =
        xolotl_types::GrantRights::new(xolotl_types::GrantMethods::none(), RightFlags::SPAWN_WITH);
    let grants = [
        candidate("tenant=alice", method.clone(), Expiry::Never)?,
        candidate("tenant=bob", method.clone(), Expiry::Never)?,
        candidate("lane=east", propagation.clone(), Expiry::At(15))?,
        candidate("lane=west", propagation, Expiry::Never)?,
    ];
    let request = || OpenRequest {
        process: owner,
        resource,
        verb: "perform".into(),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::SPAWN_WITH),
        acting: IdentityRef::ROOT,
        requested_path: None,
        now_millis: 10,
    };
    ensure!(matches!(
        prepare_open(&registry, request(), &grants[..2]),
        Err(OpenError::RightsNotSubset)
    ));
    ensure!(matches!(
        prepare_open(&registry, request(), &grants[2..]),
        Err(OpenError::RightsNotSubset)
    ));
    let prepared = prepare_open(&registry, request(), &grants)?;
    let snapshot = prepared.policy().context("two conditional grant domains")?;
    ensure!(
        snapshot.len() == 2,
        "one residual per domain, not four pairs"
    );
    let check = |tenant: &str, lane: &str, now_millis| {
        let input = Value::map(std::collections::BTreeMap::from([
            ("tenant".into(), Value::string(tenant.into())),
            ("lane".into(), Value::string(lane.into())),
        ]));
        (input, now_millis)
    };
    for (tenant, lane, now, allowed) in [
        ("alice", "east", 10, true),
        ("bob", "west", 10, true),
        ("alice", "west", 10, true),
        ("mallory", "west", 10, false),
        ("bob", "north", 10, false),
        ("bob", "east", 16, false),
        ("bob", "west", 16, true),
    ] {
        let (input, now_millis) = check(tenant, lane, now);
        let ctx = crate::policy::CheckCtx {
            input: &input,
            acting: IdentityRef::ROOT,
            now_millis,
            target: resource,
        };
        ensure!(snapshot.check(&ctx).await.is_allow() == allowed);
        ensure!(snapshot.check_derivation(&ctx).await.is_allow() == allowed);
    }
    let handles = HandleTable::new();
    let parent = prepared.install(&handles)?;
    let child = handles.derive(
        parent,
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        xolotl_types::DeriveKind::SpawnWith,
        ProcessId::new(18),
    )?;
    let child = handles.get(child).context("derived child")?;
    ensure!(child.rights.methods == MethodBitmap::method(0) && child.rights.flags.is_empty());
    Ok(())
}

fn extend_resource(
    reg: &Registry,
    resource: ResourceId,
    method: Method,
) -> Result<(), crate::registry::AdmissionError> {
    relink_methods(reg, resource, vec![method], true)
}

fn relink_methods(
    reg: &Registry,
    resource: ResourceId,
    methods: Vec<Method>,
    append: bool,
) -> Result<(), crate::registry::AdmissionError> {
    let current = reg
        .resource(resource)
        .ok_or_else(|| crate::registry::AdmissionError::Rejected("resource missing".into()))?;
    let iface_id = reg.next_interface_id();
    reg.register_interface(Interface {
        id: iface_id,
        family: InterfaceFamily::Value,
        methods,
        laws: Vec::new(),
    })?;
    let mut interfaces = if append {
        current.interfaces
    } else {
        InterfaceSet::default()
    };
    interfaces.interfaces.push(iface_id);
    let driver_id = reg.next_driver_id();
    reg.register_driver(DriverDescriptor {
        id: driver_id,
        name: "composed".into(),
        implements: interfaces.clone(),
        transport: xolotl_types::Transport::InProcess,
        driver: Arc::new(FnDriver(|method: MethodId, _| {
            Ok(Value::integer(method.get() as i64))
        })),
    })?;
    let binding_id = reg.next_binding_id();
    reg.admit_binding(Binding {
        id: binding_id,
        selector: ResourceSelector::all(),
        interfaces: interfaces.clone(),
        driver: xolotl_types::DriverRef {
            id: driver_id,
            name: "composed".into(),
        },
        endpoint: None,
        generation: 2,
    })?;
    reg.relink_resource(&current.descriptor.name, interfaces, binding_id)?;
    Ok(())
}

#[test]
fn relink_cannot_turn_an_existing_grant_bit_into_a_different_method() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_state_subtree_resource(&registry)?;
    let holder = ProcessId::new(93);
    registry.register_grant(Grant {
        id: registry.next_grant_id(),
        holder,
        selector: ResourceSelector::parse("read://state/application/**")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("read"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let target = Path::parse("state://application/item")?;
    let request = || OpenRequest {
        process: holder,
        resource,
        verb: "read".into(),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        acting: IdentityRef::ROOT,
        requested_path: Some(target.clone()),
        now_millis: 0,
    };
    ensure!(prepare_open(&registry, request(), &[]).is_ok());

    let original = registry
        .resource_method(resource, "read")
        .context("original read method")?
        .1;
    let mut secret = original.clone();
    secret.id = MethodId::new(93);
    secret.name = "read_secret".into();
    relink_methods(&registry, resource, vec![secret, original], false)?;
    ensure!(
        registry
            .resource_method(resource, "read_secret")
            .map(|(index, _)| index)
            == Some(0)
    );
    ensure!(
        registry
            .resource_method(resource, "read")
            .map(|(index, _)| index)
            == Some(1)
    );
    ensure!(
        matches!(
            prepare_open(&registry, request(), &[]),
            Err(OpenError::RightsNotSubset)
        ),
        "a grant issued for read must not authorize a new read_secret method after relink"
    );
    let mut reordered_read = request();
    reordered_read.rights = Rights::new(MethodBitmap::method(1), RightFlags::empty());
    ensure!(prepare_open(&registry, reordered_read, &[]).is_ok());
    Ok(())
}

#[tokio::test]
async fn composed_interfaces_keep_distinct_authority_bits_and_dispatch_ids() -> anyhow::Result<()> {
    let boot = crate::Bootstrap::in_memory();
    let registry = boot.kernel().registry();
    let resource = setup_state_subtree_resource(registry)?;
    let prior = registry.resource(resource).context("original resource")?;
    let mut write = registry
        .resource_method(resource, "read")
        .context("read method")?
        .1;
    write.id = MethodId::new(71);
    write.name = "replace".into();
    write.authority = MethodAuthority::Write;
    write.purity = Purity::Effectful;
    write.replay = ReplayClass::NonIdempotentEffect;
    extend_resource(registry, resource, write)?;
    let prior_methods = registry
        .interface_methods(&prior.interfaces)
        .context("prior contract")?;
    ensure!(prior_methods.len() == 1 && prior_methods[0].name == "read");
    ensure!(registry.method_bitmap_for_verb(resource, "read") == MethodBitmap::method(0));
    ensure!(registry.method_bitmap_for_verb(resource, "write") == MethodBitmap::method(1));
    ensure!(
        registry
            .method_bitmap_for_verb(resource, "perform")
            .is_empty()
    );

    let request = boot.request_under(
        boot.root(),
        IdentityRef::ROOT,
        &[crate::CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("read://state/application/**")?,
            // Broad bitmaps never turn a read selector into write authority.
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
        }],
    )?;
    let target = ResourceName::new(Path::parse("state://application/item")?);
    let error = open_resource_with_attached(
        registry,
        boot.kernel().handles(),
        OpenRequest {
            process: request.id(),
            resource,
            verb: "read".into(),
            rights: Rights::new(MethodBitmap::method(1), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: Some(target.path().clone()),
            now_millis: 0,
        },
        &boot.kernel().processes().attached_grants(request.id()),
    )
    .err()
    .context("forged method rejected")?;
    ensure!(matches!(error, OpenError::MethodAuthorityMismatch(_)));
    let executor = request.executor();
    let operation = |method: &str| {
        xolotl_graph::DoNode::op(xolotl_graph::OperationTemplate {
            target: target.clone(),
            method: method.into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        })
    };
    let read = executor
        .eval_tainted(&operation("read"), TaintSet::author())
        .await;
    ensure!(read.outcome == Outcome::Done(Value::integer(0)));
    let denied = executor
        .eval_tainted(&operation("replace"), TaintSet::author())
        .await;
    ensure!(matches!(denied.outcome, Outcome::Fail(_)));
    request.finish(&read).await?;

    let writer = boot.request_under(
        boot.root(),
        IdentityRef::ROOT,
        &[crate::CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("write://state/application/**")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("replace"),
                RightFlags::empty(),
            ),
        }],
    )?;
    let written = writer
        .executor()
        .eval_tainted(&operation("replace"), TaintSet::author())
        .await;
    ensure!(written.outcome == Outcome::Done(Value::integer(71)));
    writer.finish(&written).await?;
    Ok(())
}

#[test]
fn admission_rejects_ambiguous_methods_and_incompatible_authority() -> anyhow::Result<()> {
    for fault in ["name", "id", "spawn"] {
        let registry = Registry::new();
        let resource = setup_state_subtree_resource(&registry)?;
        let mut method = registry
            .resource_method(resource, "read")
            .context("method")?
            .1;
        if fault != "name" {
            method.name = "another".into();
        }
        if fault != "id" {
            method.id = MethodId::new(99);
        }
        if fault == "spawn" {
            method.authority = MethodAuthority::Spawn;
        }
        ensure!(
            extend_resource(&registry, resource, method).is_err(),
            "accepted {fault}"
        );
        ensure!(
            registry
                .resource_methods(resource)
                .context("methods")?
                .len()
                == 1
        );
    }
    let registry = Registry::new();
    let resource = setup_state_subtree_resource(&registry)?;
    let mut method = registry
        .resource_method(resource, "read")
        .context("method")?
        .1;
    method.name = "perform".into();
    method.id = MethodId::new(99);
    method.authority = MethodAuthority::Perform;
    extend_resource(&registry, resource, method)?;
    ensure!(registry.resource_method(resource, "perform").is_some());
    Ok(())
}

#[test]
fn interface_contracts_are_immutable_and_resource_width_is_bounded() -> anyhow::Result<()> {
    let registry = Registry::new();
    let resource = setup_state_subtree_resource(&registry)?;
    let id = registry
        .resource(resource)
        .context("resource")?
        .interfaces
        .interfaces[0];
    let original = registry.interface(id).context("interface")?;
    let mut altered = original.clone();
    altered.methods[0].authority = MethodAuthority::Write;
    ensure!(matches!(
        registry.register_interface(altered),
        Err(crate::registry::AdmissionError::DuplicateInterfaceId(_))
    ));
    ensure!(registry.interface(id).context("unchanged interface")? == original);
    for index in 1..64 {
        let mut method = original.methods[0].clone();
        method.id = MethodId::new(index);
        method.name = format!("method_{index}");
        extend_resource(&registry, resource, method)?;
    }
    let mut overflow = original.methods[0].clone();
    overflow.id = MethodId::new(64);
    overflow.name = "overflow".into();
    ensure!(extend_resource(&registry, resource, overflow).is_err());
    ensure!(registry.method_bitmap_for_verb(resource, "read") == MethodBitmap::ALL);
    Ok(())
}

#[tokio::test]
async fn a_prepared_executor_cannot_reinterpret_method_ids_after_relink() -> anyhow::Result<()> {
    let boot = crate::Bootstrap::in_memory();
    let registry = boot.kernel().registry();
    let resource = setup_state_subtree_resource(registry)?;
    let request = boot.request_under(
        boot.root(),
        IdentityRef::ROOT,
        &[crate::CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("read://state/application/**")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
        }],
    )?;
    let operation = xolotl_graph::OperationTemplate {
        target: ResourceName::new(Path::parse("state://application/item")?),
        method: "read".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    };
    let executor = request.executor();
    executor.prepare_operation(&operation)?;
    let mut read = registry
        .resource_method(resource, "read")
        .context("method")?
        .1;
    let mut other = read.clone();
    read.id = MethodId::new(99);
    other.name = "another".into();
    // The old read id now means a different method, with the same capability category.
    relink_methods(registry, resource, vec![read, other], false)?;
    boot.kernel()
        .handles()
        .write()
        .revoke_owned_by(request.id());
    let program = xolotl_graph::DoNode::op(operation);
    let stale = executor.eval_tainted(&program, TaintSet::author()).await;
    ensure!(
        matches!(stale.outcome, Outcome::Fail(ref error) if error.to_string().contains("contract changed"))
    );
    ensure!(boot.kernel().handles().read().is_empty());
    let fresh = request
        .executor()
        .eval_tainted(&program, TaintSet::author())
        .await;
    ensure!(fresh.outcome == Outcome::Done(Value::integer(99)));
    request.finish(&fresh).await?;
    Ok(())
}

#[tokio::test]
async fn a_prepared_executor_keeps_its_prefix_binding_after_a_more_specific_registration()
-> anyhow::Result<()> {
    let boot = crate::Bootstrap::in_memory();
    let registry = boot.kernel().registry();
    let original_resource = setup_state_subtree_resource(registry)?;
    let request = boot.request_under(
        boot.root(),
        IdentityRef::ROOT,
        &[crate::CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("read://state/application/**")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
        }],
    )?;
    let operation = xolotl_graph::OperationTemplate {
        target: ResourceName::new(Path::parse("state://application/item")?),
        method: "read".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::integer(1)),
    };
    let program = xolotl_graph::DoNode::op(operation.clone());
    let executor = request.executor();
    executor.prepare_operation(&operation)?;

    let mut method = registry
        .resource_method(original_resource, "read")
        .context("original method")?
        .1;
    method.id = MethodId::new(99);
    let interface = registry.next_interface_id();
    registry.register_interface(Interface {
        id: interface,
        family: InterfaceFamily::Value,
        methods: vec![method],
        laws: Vec::new(),
    })?;
    let interfaces = InterfaceSet::new(vec![interface]);
    let driver = registry.next_driver_id();
    registry.register_driver(DriverDescriptor {
        id: driver,
        name: "specific-state".into(),
        implements: interfaces.clone(),
        transport: xolotl_types::Transport::InProcess,
        driver: Arc::new(FnDriver(|_, _| Ok(Value::integer(2)))),
    })?;
    let binding = registry.next_binding_id();
    registry.admit_binding(Binding {
        id: binding,
        selector: ResourceSelector::all(),
        interfaces: interfaces.clone(),
        driver: xolotl_types::DriverRef {
            id: driver,
            name: "specific-state".into(),
        },
        endpoint: None,
        generation: 1,
    })?;
    let specific_resource = registry.next_resource_id();
    registry.admit_resource(
        Resource {
            id: specific_resource,
            descriptor: ResourceDescriptor {
                name: ResourceName::new(Path::parse("state://application")?),
                kind: ResourceKind::State,
                addressing: xolotl_types::ResourceAddressing::Prefix,
                metadata: Metadata::default(),
            },
            interfaces,
            binding,
        },
        false,
    )?;
    ensure!(registry.resolve_resource(&operation.target)? == specific_resource);

    let retained = executor.eval_tainted(&program, TaintSet::author()).await;
    ensure!(retained.outcome == Outcome::Done(Value::integer(1)));

    boot.kernel()
        .handles()
        .write()
        .revoke_owned_by(request.id());
    let stale = executor.eval_tainted(&program, TaintSet::author()).await;
    ensure!(
        matches!(stale.outcome, Outcome::Fail(ref error) if error.to_string().contains("does not resolve to resource")),
        "old executor switched to the new prefix resource: {stale:?}"
    );
    ensure!(boot.kernel().handles().read().is_empty());

    let fresh = request
        .executor()
        .eval_tainted(&program, TaintSet::author())
        .await;
    ensure!(fresh.outcome == Outcome::Done(Value::integer(2)));
    request.finish(&fresh).await?;
    Ok(())
}

struct ChangeGrantDuringCompile {
    boot: std::sync::Weak<crate::Bootstrap>,
    grant: Grant,
}

impl crate::policy::PolicySource for ChangeGrantDuringCompile {
    fn applies_to(&self, _: &OpenContext) -> bool {
        true
    }

    fn compile(&self, _: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
        let boot = self
            .boot
            .upgrade()
            .ok_or_else(|| PolicyCompileError::DeniedAtOpen("host stopped".into()))?;
        boot.kernel().registry().register_grant(self.grant.clone());
        Ok(PolicySnapshot::empty())
    }
}

#[test]
fn concurrent_control_change_cannot_publish_or_cache_an_old_handle_plan() -> anyhow::Result<()> {
    let boot = Arc::new(crate::Bootstrap::in_memory());
    let registry = boot.kernel().registry();
    setup_state_subtree_resource(registry)?;
    let mut grant = registry
        .grants_of(boot.root())
        .into_iter()
        .next()
        .context("root grant")?;
    grant.rights =
        xolotl_types::GrantRights::new(xolotl_types::GrantMethods::none(), RightFlags::empty());
    registry.register_policy(Arc::new(ChangeGrantDuringCompile {
        boot: Arc::downgrade(&boot),
        grant,
    }));
    let target = ResourceName::new(Path::parse("state://application/item")?);
    let error = boot
        .open_for(boot.root(), &target, "read")
        .err()
        .context("stale open rejected")?;
    ensure!(error == OpenError::RegistryChanged);
    ensure!(boot.kernel().handles().read().is_empty());
    ensure!(registry.open_cache_stats().2 == 0);
    let error = boot
        .open_for(boot.root(), &target, "read")
        .err()
        .context("new authority denies")?;
    ensure!(error == OpenError::RightsNotSubset);
    Ok(())
}
