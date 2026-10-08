mod authority;
mod prepared;

use super::*;
use crate::driver::{
    DriverDescriptor, DriverError, EchoDriver, FnDriver, RemoteEndpoint, RemoteInvokeDispatch,
};
use crate::handle::HandleTable;
use crate::policy::PolicySnapshot;
use anyhow::{Context, bail, ensure};
use async_trait::async_trait;
use parking_lot::Mutex;
use xolotl_types::{
    Binding, ConstraintSet, EndpointId, Expiry, Grant, Interface, InterfaceFamily, InterfaceSet,
    Invoke, InvokeResult, Metadata, Method, MethodBitmap, ModalitySet, OutputModeSet, Path, Purity,
    ReplayClass, Resource, ResourceAddressing, ResourceDescriptor, ResourceKind, ResourceName,
    ResourceSelector, RightFlags, Rights, SchemaId, Value,
};

fn setup_resource(reg: &Registry, path: &str) -> anyhow::Result<ResourceId> {
    let target = Path::parse(path)?;
    let binding_selector = match target.cluster() {
        Some(cluster) => format!("perform://path://{cluster}/effect/**"),
        None => "perform://effect/**".into(),
    };
    let iface_id = reg.next_interface_id();
    reg.register_interface(Interface {
        id: iface_id,
        family: InterfaceFamily::Callable,
        methods: vec![Method {
            id: xolotl_types::MethodId::new(100),
            name: "invoke".into(),
            authority: xolotl_types::MethodAuthority::Perform,
            input: SchemaId::new(0),
            output: SchemaId::new(0),
            modality: ModalitySet::TEXT,
            purity: Purity::Pure,
            replay: ReplayClass::Deterministic,
            supports: OutputModeSet::UNARY,
            cost: Default::default(),
            batchable: false,
            finalize_allowed: false,
            requires_unprotected_input: false,
        }],
        laws: Vec::new(),
    })?;
    let driver_id = reg.next_driver_id();
    reg.register_driver(DriverDescriptor {
        id: driver_id,
        name: "echo".into(),
        implements: InterfaceSet::new(vec![iface_id]),
        transport: xolotl_types::Transport::InProcess,
        driver: Arc::new(EchoDriver),
    })?;
    let binding_id = reg.next_binding_id();
    reg.register_binding(Binding {
        id: binding_id,
        selector: ResourceSelector::parse(&binding_selector)?,
        interfaces: InterfaceSet::new(vec![iface_id]),
        driver: xolotl_types::DriverRef {
            id: driver_id,
            name: "echo".into(),
        },
        endpoint: None,
        generation: 1,
    });
    let rid = reg.next_resource_id();
    reg.admit_resource(
        Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: ResourceName::new(target),
                kind: ResourceKind::Effect,
                addressing: Default::default(),
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::new(vec![iface_id]),
            binding: binding_id,
        },
        path.starts_with("effect://kernel/"),
    )
    .context("resource admission failed")?;
    Ok(rid)
}

fn setup_remote_resource(
    reg: &Registry,
    path: &str,
    endpoint: EndpointId,
) -> anyhow::Result<ResourceId> {
    setup_remote_resource_with_addressing(reg, path, endpoint, ResourceAddressing::Exact)
}

fn setup_remote_resource_with_addressing(
    reg: &Registry,
    path: &str,
    endpoint: EndpointId,
    addressing: ResourceAddressing,
) -> anyhow::Result<ResourceId> {
    let iface_id = reg.next_interface_id();
    reg.register_interface(Interface {
        id: iface_id,
        family: InterfaceFamily::Callable,
        methods: vec![Method {
            id: xolotl_types::MethodId::new(0),
            name: "invoke".into(),
            authority: xolotl_types::MethodAuthority::Perform,
            input: SchemaId::new(0),
            output: SchemaId::new(0),
            modality: ModalitySet::TEXT,
            purity: Purity::Effectful,
            replay: ReplayClass::NonIdempotentEffect,
            supports: OutputModeSet::UNARY | OutputModeSet::STREAM,
            cost: Default::default(),
            batchable: false,
            finalize_allowed: false,
            requires_unprotected_input: false,
        }],
        laws: Vec::new(),
    })?;
    let driver_id = reg.next_driver_id();
    reg.register_driver(DriverDescriptor {
        id: driver_id,
        name: "remote-provider".into(),
        implements: InterfaceSet::new(vec![iface_id]),
        transport: xolotl_types::Transport::Grpc {
            endpoint: Some("test-endpoint".into()),
        },
        // This local driver must not be called for endpoint bindings. The
        // compiled plan uses RemoteDriver stubs instead.
        driver: Arc::new(EchoDriver),
    })?;
    let binding_id = reg.next_binding_id();
    reg.admit_binding(Binding {
        id: binding_id,
        selector: ResourceSelector::parse("perform://effect/external-provider/**")?,
        interfaces: InterfaceSet::new(vec![iface_id]),
        driver: xolotl_types::DriverRef {
            id: driver_id,
            name: "remote-provider".into(),
        },
        endpoint: Some(endpoint),
        generation: 1,
    })
    .context("remote binding admission failed")?;
    let rid = reg.next_resource_id();
    reg.admit_resource(
        Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: ResourceName::new(Path::parse(path)?),
                kind: ResourceKind::Effect,
                addressing,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::new(vec![iface_id]),
            binding: binding_id,
        },
        false,
    )
    .context("remote resource admission failed")?;
    Ok(rid)
}

fn setup_state_subtree_resource(reg: &Registry) -> anyhow::Result<ResourceId> {
    let iface_id = reg.next_interface_id();
    reg.register_interface(Interface {
        id: iface_id,
        family: InterfaceFamily::Value,
        methods: vec![Method {
            id: xolotl_types::MethodId::new(0),
            name: "read".into(),
            authority: xolotl_types::MethodAuthority::Read,
            input: SchemaId::new(0),
            output: SchemaId::new(0),
            modality: ModalitySet::TEXT,
            purity: Purity::Pure,
            replay: ReplayClass::Observation,
            supports: OutputModeSet::UNARY,
            cost: Default::default(),
            batchable: false,
            finalize_allowed: false,
            requires_unprotected_input: false,
        }],
        laws: Vec::new(),
    })?;
    let driver_id = reg.next_driver_id();
    reg.register_driver(DriverDescriptor {
        id: driver_id,
        name: "state".into(),
        implements: InterfaceSet::new(vec![iface_id]),
        transport: xolotl_types::Transport::InProcess,
        driver: Arc::new(FnDriver(|_, input| Ok(input))),
    })?;
    let binding_id = reg.next_binding_id();
    reg.register_binding(Binding {
        id: binding_id,
        selector: ResourceSelector::parse("*://state/**")?,
        interfaces: InterfaceSet::new(vec![iface_id]),
        driver: xolotl_types::DriverRef {
            id: driver_id,
            name: "state".into(),
        },
        endpoint: None,
        generation: 1,
    });
    let rid = reg.next_resource_id();
    reg.admit_resource(
        Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: ResourceName::new(Path::parse("state://")?),
                kind: ResourceKind::State,
                addressing: xolotl_types::ResourceAddressing::Prefix,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::new(vec![iface_id]),
            binding: binding_id,
        },
        true,
    )
    .context("state resource admission failed")?;
    Ok(rid)
}

struct TestEndpoint {
    seen: Arc<Mutex<Vec<Invoke>>>,
}

#[async_trait]
impl RemoteEndpoint for TestEndpoint {
    async fn invoke(
        &self,
        _dispatch: RemoteInvokeDispatch,
        invoke: Invoke,
    ) -> Result<InvokeResult, DriverError> {
        self.seen.lock().push(invoke.clone());
        Ok(InvokeResult {
            invocation_id: invoke.invocation_id,
            outcome: Ok(xolotl_types::Value::string("remote".into())),
        })
    }
}

fn expect_open_error(result: Result<HandleId, OpenError>) -> anyhow::Result<OpenError> {
    match result {
        Ok(handle) => bail!("expected open error, got handle {handle:?}"),
        Err(err) => Ok(err),
    }
}

#[test]
fn open_unconditional_when_no_constraints() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let id = open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    )
    .context("open_resource failed")?;
    let h = handles.get(id).context("opened handle did not resolve")?;
    ensure!(
        h.is_unconditional(),
        "no constraints should use the unconditional fast path"
    );
    ensure!(
        h.driver_plan.supports(xolotl_types::MethodId::new(100)),
        "driver plan should support method 100"
    );
    Ok(())
}

#[tokio::test]
async fn selector_predicate_becomes_residual_constraint() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post@tenant=acme")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let id = open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    )
    .context("open_resource failed")?;
    let h = handles.get(id).context("opened handle did not resolve")?;
    let FastPath::Conditional(snapshot) = &h.fast_path else {
        bail!("selector predicate should produce a conditional handle");
    };

    let deny = snapshot
        .check(&crate::policy::CheckCtx {
            input: &Value::null(),
            acting: IdentityRef::ROOT,
            now_millis: 0,
            target: rid,
        })
        .await;
    ensure!(
        matches!(deny, crate::policy::PolicyDecision::Deny { .. }),
        "missing predicate input should be denied: {deny:?}"
    );

    let input = Value::map(
        [("tenant".into(), Value::string("acme".into()))]
            .into_iter()
            .collect(),
    );
    let allow = snapshot
        .check(&crate::policy::CheckCtx {
            input: &input,
            acting: IdentityRef::ROOT,
            now_millis: 0,
            target: rid,
        })
        .await;
    ensure!(
        allow == crate::policy::PolicyDecision::Allow,
        "matching predicate input should be allowed: {allow:?}"
    );
    Ok(())
}

#[test]
fn endpoint_binding_requires_registered_endpoint() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_remote_resource(
        &reg,
        "effect://external-provider/acme/search",
        EndpointId::new(99),
    )?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/external-provider/acme/search")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let err = expect_open_error(open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    ))?;
    ensure!(
        matches!(err, OpenError::NoSuchEndpoint(id) if id == EndpointId::new(99)),
        "unexpected open error: {err:?}"
    );
    Ok(())
}

#[test]
fn ordinary_effect_grant_cannot_open_kernel_effect() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://kernel/process/inspect")?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/**")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let err = expect_open_error(open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    ))?;
    ensure!(
        matches!(err, OpenError::ReservedPath(ref p) if p == "effect://kernel/process/inspect"),
        "unexpected open error: {err:?}"
    );
    ensure!(
        handles.is_empty(),
        "reserved open should not allocate handles"
    );
    Ok(())
}

#[tokio::test]
async fn endpoint_binding_compiles_to_remote_driver_plan() -> anyhow::Result<()> {
    let reg = Registry::new();
    let endpoint = reg.next_endpoint_id();
    let seen = Arc::new(Mutex::new(Vec::new()));
    reg.register_endpoint(endpoint, Arc::new(TestEndpoint { seen: seen.clone() }));
    let rid = setup_remote_resource(&reg, "effect://external-provider/acme/search", endpoint)?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/external-provider/acme/search")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let id = open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    )
    .context("open_resource failed")?;
    let h = handles.get(id).context("opened handle did not resolve")?;
    ensure!(h.driver_plan.is_remote(), "driver plan should be remote");
    ensure!(
        h.driver_plan.supports(xolotl_types::MethodId::new(0)),
        "driver plan should support method 0"
    );

    let ctx = crate::DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_operation_id(
        xolotl_types::OperationId::new(
            ProcessId::new(1),
            xolotl_types::ExecutionId::FIRST,
            xolotl_types::InvocationId::new(5),
            xolotl_types::NodeId::new(4),
            0,
        ),
    );
    let out = h
        .driver_plan
        .call(
            xolotl_types::MethodId::new(0),
            xolotl_types::Value::string("q".into()),
            xolotl_types::OutputMode::Unary,
            &ctx,
        )
        .await
        .context("remote driver call failed")?;
    ensure!(
        out.outcome == xolotl_types::Outcome::Done(xolotl_types::Value::string("remote".into())),
        "unexpected remote outcome: {out:?}"
    );
    let seen = seen.lock();
    ensure!(
        seen.len() == 1,
        "unexpected remote invoke count: {}",
        seen.len()
    );
    let invoke = seen.first().context("missing remote invoke")?;
    ensure!(
        invoke.invocation_id == "1/1/5/4/0",
        "invocation id mismatch"
    );
    ensure!(
        invoke.effect_path.to_string() == "effect://external-provider/acme/search",
        "remote effect path mismatch"
    );
    Ok(())
}

#[tokio::test]
async fn remote_prefix_dispatch_preserves_each_authorized_concrete_path() -> anyhow::Result<()> {
    use crate::{Bootstrap, RequestGrantTemplate};
    use xolotl_graph::{DoNode, OperationTemplate};

    let boot = Bootstrap::in_memory();
    let registry = boot.kernel().registry();
    let endpoint = registry.next_endpoint_id();
    let seen = Arc::new(Mutex::new(Vec::new()));
    registry.register_endpoint(endpoint, Arc::new(TestEndpoint { seen: seen.clone() }));
    setup_remote_resource_with_addressing(
        registry,
        "path://peer/effect/catalog",
        endpoint,
        ResourceAddressing::Prefix,
    )?;

    let rights = xolotl_types::GrantRights::new(
        xolotl_types::GrantMethods::name("invoke"),
        RightFlags::empty(),
    );
    let process = boot.spawn_request_process_under_with_request_grants(
        boot.root(),
        IdentityRef::ROOT,
        &[
            RequestGrantTemplate {
                literal: "perform://path://peer/effect/catalog/search",
                rights: rights.clone(),
            },
            RequestGrantTemplate {
                literal: "perform://path://peer/effect/catalog/summary",
                rights,
            },
        ],
    )?;
    let executor = boot.kernel().executor_for(process);
    for path in [
        "path://peer/effect/catalog/search",
        "path://peer/effect/catalog/summary",
    ] {
        let result = executor
            .eval(&DoNode::op(OperationTemplate {
                target: ResourceName::new(Path::parse(path)?),
                method: "invoke".into(),
                method_id: None,
                output: xolotl_types::OutputMode::Unary,
                literal_input: Some(Value::string("q".into())),
            }))
            .await;
        ensure!(
            result.outcome == xolotl_types::Outcome::Done(Value::string("remote".into())),
            "authorized remote operation failed at {path}: {result:?}"
        );
        ensure!(
            result.taint.sources().iter().any(|source| matches!(
                source,
                xolotl_types::TaintSource::Inbound { channel, .. } if channel.as_str() == path
            )),
            "remote provenance lost the concrete target {path}"
        );
    }
    let denied = executor
        .eval(&DoNode::op(OperationTemplate {
            target: ResourceName::new(Path::parse("path://peer/effect/catalog/other")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::string("q".into())),
        }))
        .await;
    ensure!(
        matches!(denied.outcome, xolotl_types::Outcome::Fail(_)),
        "unauthorized sibling was accepted: {denied:?}"
    );
    let invoked: Vec<_> = seen
        .lock()
        .iter()
        .map(|invoke| invoke.effect_path.to_string())
        .collect();
    ensure!(
        invoked
            == [
                "path://peer/effect/catalog/search",
                "path://peer/effect/catalog/summary",
            ],
        "remote endpoint saw the wrong concrete targets: {invoked:?}"
    );
    Ok(())
}

#[test]
fn open_freezes_cleanup_ownership_in_cached_and_delegated_plans() -> anyhow::Result<()> {
    let reg = Registry::new();
    let resource = setup_state_subtree_resource(&reg)?;
    let owner = ProcessId::new(7);
    let other = ProcessId::new(9);
    let rights = Rights::new(MethodBitmap::method(0), RightFlags::DELEGATE);
    for holder in [owner, other] {
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder,
            selector: ResourceSelector::parse("read://state/**")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("read"),
                RightFlags::DELEGATE,
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
    }
    let requested_path = Path::parse("state://process/7/result")?;
    let request = |process| OpenRequest {
        process,
        resource,
        verb: "read".into(),
        rights,
        acting: IdentityRef::ROOT,
        requested_path: Some(requested_path.clone()),
        now_millis: 1,
    };
    let handles = HandleTable::new();
    let first = open_resource(&reg, &handles, request(owner))?;
    let cached = open_resource(&reg, &handles, request(owner))?;
    ensure!(reg.open_cache_stats() == (1, 1, 1));
    let foreign = open_resource(&reg, &handles, request(other))?;
    let delegated = handles.derive(first, rights, xolotl_types::DeriveKind::Delegate, other)?;
    for handle in [first, cached, foreign, delegated] {
        let opened = handles.get(handle).context("missing opened handle")?;
        let contract = opened
            .driver_plan
            .contract(xolotl_types::MethodId::new(0))
            .context("missing contract")?;
        ensure!(!contract.finalize_allowed && contract.cleanup_owner == Some(owner));
        ensure!(contract.permits_cleanup(owner));
        ensure!(!contract.permits_cleanup(other));
        ensure!(contract.permits_cleanup(opened.process) == (opened.process == owner));
    }
    ensure!(handles.release(first));
    let derived = handles
        .get(delegated)
        .context("derived handle lost released parent")?;
    ensure!(
        !derived
            .driver_plan
            .contract(xolotl_types::MethodId::new(0))
            .context("missing derived contract")?
            .permits_cleanup(other)
    );
    Ok(())
}

#[test]
fn repeated_open_reuses_compiled_open_plan_not_handle_slot() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let req = || OpenRequest {
        process: ProcessId::new(1),
        resource: rid,
        verb: "perform".into(),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        acting: IdentityRef::ROOT,
        requested_path: None,
        now_millis: 123,
    };

    let first = open_resource(&reg, &handles, req()).context("first open failed")?;
    ensure!(
        reg.open_cache_stats() == (0, 1, 1),
        "first open cache stats mismatch: {:?}",
        reg.open_cache_stats()
    );
    let second = open_resource(&reg, &handles, req()).context("second open failed")?;
    ensure!(
        reg.open_cache_stats() == (1, 1, 1),
        "second open cache stats mismatch: {:?}",
        reg.open_cache_stats()
    );

    ensure!(first != second, "each open should allocate its own handle");
    ensure!(
        handles.len() == 2,
        "unexpected handle count: {}",
        handles.len()
    );
    ensure!(
        handles
            .get(first)
            .context("first handle did not resolve")?
            .is_unconditional(),
        "first handle should be unconditional"
    );
    ensure!(
        handles
            .get(second)
            .context("second handle did not resolve")?
            .is_unconditional(),
        "second handle should be unconditional"
    );
    Ok(())
}

#[test]
fn open_fails_without_matching_grant() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    let handles = HandleTable::new();
    let err = expect_open_error(open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    ))?;
    ensure!(
        matches!(err, OpenError::NoMatchingGrant { .. }),
        "unexpected open error: {err:?}"
    );
    Ok(())
}

#[test]
fn local_grant_cannot_open_clustered_resource() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "path://phone/effect/x/post")?;
    let holder = ProcessId::new(1);
    let rights = Rights::new(MethodBitmap::method(0), RightFlags::empty());
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder,
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let request = || OpenRequest {
        process: holder,
        resource: rid,
        verb: "perform".into(),
        rights,
        acting: IdentityRef::ROOT,
        requested_path: None,
        now_millis: 0,
    };
    let denied = expect_open_error(open_resource(&reg, &handles, request()))?;
    ensure!(matches!(denied, OpenError::NoMatchingGrant { .. }));

    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder,
        selector: ResourceSelector::parse("perform://path://phone/effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let opened = open_resource(&reg, &handles, request())?;
    ensure!(
        handles
            .get(opened)
            .context("opened handle missing")?
            .bound_path
            .as_ref()
            == Some(&Path::parse("path://phone/effect/x/post")?)
    );
    Ok(())
}

#[test]
fn ordinary_state_grant_cannot_open_vault_or_fact_projection() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_state_subtree_resource(&reg)?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("*://state/**")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    for path in [
        "state://vault/alice/token",
        "state://fact/1",
        "state://kernel/bootstrap/phase",
        "state://kernel",
    ] {
        let err = expect_open_error(open_resource(
            &reg,
            &handles,
            OpenRequest {
                process: ProcessId::new(1),
                resource: rid,
                verb: "read".into(),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                acting: IdentityRef::ROOT,
                requested_path: Some(Path::parse(path)?),
                now_millis: 0,
            },
        ))?;
        ensure!(
            matches!(err, OpenError::ReservedPath(ref p) if p == path),
            "unexpected reserved-path error for {path}: {err:?}"
        );
    }
    ensure!(
        handles.is_empty(),
        "reserved opens should not allocate handles"
    );
    Ok(())
}

#[test]
fn open_picks_grant_covering_rights_not_first_selector_match() -> anyhow::Result<()> {
    // A process holds TWO grants hitting the same resource: the first (by
    // registration order) covers only derive flags but NO methods; the
    // second covers method 0. Requesting method 0 must succeed by selecting
    // the *covering* grant, not spuriously fail on the first match.
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    // Grant A: matches selector, but rights cover no methods.
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::none(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    // Grant B: matches selector AND covers method 0.
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let id = open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    )
    .context("open_resource should select the grant covering method 0")?;
    let handle = handles.get(id).context("opened handle did not resolve")?;
    ensure!(
        handle.rights.methods.allows(0),
        "selected handle should allow method 0"
    );
    Ok(())
}

#[test]
fn open_rights_not_subset_when_selector_matched_but_rights_uncovered() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    // Only grant: matches selector but covers no methods.
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::none(),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let err = expect_open_error(open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    ))?;
    ensure!(
        matches!(err, OpenError::RightsNotSubset),
        "unexpected open error: {err:?}"
    );
    Ok(())
}

#[test]
fn open_conditional_when_constraints_present() -> anyhow::Result<()> {
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet {
            predicates: vec![xolotl_types::cap::Predicate::parse("account=alice")?],
        },
        expires: Expiry::Never,
    });
    let handles = HandleTable::new();
    let id = open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    )
    .context("open_resource failed")?;
    let handle = handles.get(id).context("opened handle did not resolve")?;
    ensure!(
        !handle.is_unconditional(),
        "constraint-bearing grant should produce a conditional handle"
    );
    Ok(())
}

#[test]
fn registered_policy_adds_residual_check() -> anyhow::Result<()> {
    use crate::policy::CapabilityPolicy;
    let reg = Registry::new();
    let rid = setup_resource(&reg, "effect://x/post")?;
    // Grant has no constraints (would be Unconditional)…
    reg.register_grant(Grant {
        id: reg.next_grant_id(),
        holder: ProcessId::new(1),
        selector: ResourceSelector::parse("perform://effect/x/post")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::all(),
            RightFlags::all(),
        ),
        constraints: ConstraintSet::empty(),
        expires: Expiry::Never,
    });
    // …but a registered source policy attaches an input predicate, so the
    // handle must become Conditional (a residual check exists).
    reg.register_policy(Arc::new(CapabilityPolicy {
        pattern: xolotl_types::Capability::parse("perform://effect/x/**")?,
        constraints: ConstraintSet {
            predicates: vec![xolotl_types::cap::Predicate::parse("account=alice")?],
        },
    }));
    let handles = HandleTable::new();
    let id = open_resource(
        &reg,
        &handles,
        OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 0,
        },
    )
    .context("open_resource failed")?;
    let handle = handles.get(id).context("opened handle did not resolve")?;
    ensure!(
        !handle.is_unconditional(),
        "matching source policy with a predicate should produce a conditional handle"
    );
    Ok(())
}
