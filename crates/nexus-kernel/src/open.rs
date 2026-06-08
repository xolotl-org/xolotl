//! `open()` = compile: turn a Grant + Resource + Policy + Binding into a
//! closed, executable [`Handle`]. This is the only way a Handle is created.
//!
//! The seven compile steps:
//!
//! ```text
//! 1. find holder==process grant whose selector hits the resource
//! 2. requested rights ⊆ grant.rights (bitmap subset)
//! 3. check static (open-time) constraints
//! 4. compile applicable Policy → PolicySnapshot, partially evaluating
//! 5. read Binding → build DriverPlan (local inline / remote stub)
//! 6. residual empty? → mark Unconditional
//! 7. allocate (index, generation) slot in HandleTable, return Handle
//! ```

use crate::driver::{DriverPlan, RemoteDriver};
use crate::handle::{FastPath, Handle, HandleState, HandleTable};
use crate::policy::{ConstraintCheck, OpenContext, PolicyCompileError, PolicySnapshot};
use crate::registry::{CompiledOpenPlan, OpenCacheKey, Registry};
use nexus_types::{ConstraintSet, HandleId, IdentityRef, ProcessId, ResourceId, Rights};
use std::sync::Arc;
use thiserror::Error;

/// Errors returned while compiling an open request into a handle.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum OpenError {
    /// The process holds no grant whose selector matches the resource/path.
    #[error("no grant held by {process} matches resource {resource}")]
    NoMatchingGrant {
        /// Process that attempted the open.
        process: ProcessId,
        /// Resource requested by the open.
        resource: ResourceId,
    },
    /// A grant selector matched, but the requested rights exceeded it.
    #[error("requested rights exceed the granting rights (not a subset)")]
    RightsNotSubset,
    /// Registry has no resource with this id.
    #[error("resource {0} not found")]
    NoSuchResource(ResourceId),
    /// Resource points at a binding that is not registered.
    #[error("binding {0} not found")]
    NoSuchBinding(nexus_types::BindingId),
    /// Binding points at a driver that is not registered.
    #[error("driver {0} not found")]
    NoSuchDriver(nexus_types::DriverId),
    /// Binding points at a remote endpoint that is not registered.
    #[error("endpoint {0} not found")]
    NoSuchEndpoint(nexus_types::EndpointId),
    /// Grant expiry or static constraints failed at open time.
    #[error("grant expired or static constraint failed")]
    StaticConstraintFailed,
    /// A source policy denied the open before a handle was created.
    #[error("a source policy denied the open: {0}")]
    PolicyDenied(String),
    /// Reserved state paths cannot be opened through non-kernel grants.
    #[error("reserved path cannot be opened through non-kernel state grants: {0}")]
    ReservedPath(String),
}

/// What the caller asks to open: a resource, the rights it wants, and the verb
/// (selector match key).
pub struct OpenRequest {
    /// Process that will own the resulting handle.
    pub process: ProcessId,
    /// Resource id selected by control-plane name resolution.
    pub resource: ResourceId,
    /// Capability verb used when matching grant selectors.
    pub verb: String,
    /// Rights requested for the resulting handle.
    pub rights: Rights,
    /// The identity the opening Process acts as. Carried
    /// into the [`OpenContext`] so identity-scoped policy checks can be
    /// partially evaluated and eliminated at open time. Defaults to
    /// [`IdentityRef::ROOT`] only for the kernel's own internal opens.
    pub acting: IdentityRef,
    /// The concrete path the caller asked to open. For prefix-resolved
    /// Resources (`state://**`) this is the specific path beneath the registered
    /// root, and becomes the handle's `bound_path` so the driver reaches the
    /// real path. `None` falls back to the resolved Resource's own name.
    pub requested_path: Option<nexus_types::Path>,
    /// Wall clock at open, for expiry / static constraint evaluation.
    pub now_millis: i64,
}

/// Compile and install a Handle. On success the Handle is in the table
/// and its [`HandleId`] is returned.
pub fn open_resource(
    registry: &Registry,
    handles: &mut HandleTable,
    req: OpenRequest,
) -> Result<HandleId, OpenError> {
    // Step 0: resolve the resource descriptor.
    let resource = registry
        .resource(req.resource)
        .ok_or(OpenError::NoSuchResource(req.resource))?;
    // The path used for grant/selector matching and as the handle's bound path
    // is the *requested* concrete path when given; otherwise it is the resolved
    // Resource's own name.
    let match_path = req
        .requested_path
        .clone()
        .unwrap_or_else(|| resource.descriptor.name.path().clone());
    let resource_name = match_path;
    let resource_root = resource.descriptor.name.path();
    let is_fact_projection_resource = resource_root.scheme() == "state"
        && resource_root.segments().first().map(|s| s.as_str()) == Some("fact");
    if nexus_types::is_vault_reserved(&resource_name)
        || (nexus_types::is_fact_reserved(&resource_name) && !is_fact_projection_resource)
    {
        return Err(OpenError::ReservedPath(resource_name.to_string()));
    }

    // Step 1+2 fused: find a grant held by the process that both hits
    // the resource via its selector AND covers the requested rights. Fusing the
    // two checks is required: a process may hold several grants matching the
    // same resource (e.g. one for method X, one for method Y). Picking the first
    // selector match and only then checking rights would spuriously reject a
    // request that a *different* held grant authorizes. We therefore require
    // `req.rights ⊆ g.rights` as part of selection, and only surface
    // `RightsNotSubset` when a selector matched but no grant covered the rights.
    let matching: Vec<_> = registry
        .candidate_grants(req.process, &req.verb, &resource_name)
        .into_iter()
        .filter(|g| {
            !g.expires.is_expired(req.now_millis) && g.selector.matches(&req.verb, &resource_name)
        })
        .collect();
    let selector_matched = !matching.is_empty();
    let grant = match matching
        .into_iter()
        .find(|g| req.rights.is_subset_of(&g.rights))
    {
        Some(g) => g,
        // A selector matched but none covered the rights → RightsNotSubset;
        // nothing matched the resource at all → NoMatchingGrant.
        None if selector_matched => return Err(OpenError::RightsNotSubset),
        None => {
            return Err(OpenError::NoMatchingGrant {
                process: req.process,
                resource: req.resource,
            });
        }
    };

    // Step 3: static constraints. Constraints that reference no per-op input
    // (only `until`, evaluated against the wall clock) are decided now; if they
    // fail with no input, the grant doesn't apply at open time.
    // The full residual is carried forward to step 4.
    let constraints = grant.constraints.clone();
    let cache_key = OpenCacheKey::new(
        grant.id,
        req.resource,
        resource_name.clone(),
        req.verb.clone(),
        req.rights,
        req.acting,
        req.now_millis,
    );
    if let Some(plan) = registry.cached_open_plan(&cache_key) {
        return Ok(handles.insert(handle_from_plan(req.process, Some(resource_name), plan)));
    }

    // Step 4: compile policy → snapshot with partial evaluation. The residual
    // is the input-dependent part of (a) the grant's own constraints and (b)
    // every registered source policy that applies to this open. The
    // open-time decidable parts are evaluated and eliminated.
    let mut snapshot = compile_policy_snapshot(&constraints);
    let open_ctx = OpenContext {
        resource: req.resource,
        resource_path: &resource_name,
        verb: &req.verb,
        rights: req.rights,
        acting: req.acting,
        now_millis: req.now_millis,
    };
    for policy in registry.policies() {
        if policy.applies_to(&open_ctx) {
            match policy.compile(&open_ctx) {
                Ok(residual) => snapshot = snapshot.merge(residual),
                Err(PolicyCompileError::DeniedAtOpen(reason)) => {
                    return Err(OpenError::PolicyDenied(reason));
                }
            }
        }
    }

    // Step 5: read binding → build the driver plan (local inline / remote stub).
    let binding = registry
        .binding(resource.binding)
        .ok_or(OpenError::NoSuchBinding(resource.binding))?;
    let remote_endpoint = match binding.endpoint {
        Some(endpoint_id) => Some(
            registry
                .remote_endpoint(endpoint_id)
                .ok_or(OpenError::NoSuchEndpoint(endpoint_id))?,
        ),
        None => None,
    };
    let driver_impl = match binding.endpoint {
        Some(_) => None,
        None => Some(
            registry
                .driver_impl(binding.driver.id)
                .ok_or(OpenError::NoSuchDriver(binding.driver.id))?,
        ),
    };

    // Build a dispatch table over the resource's interface methods.
    let dispatch_driver: crate::driver::DynDriver =
        match (binding.endpoint, remote_endpoint, driver_impl) {
            (Some(endpoint_id), Some(endpoint), _) => Arc::new(RemoteDriver::new(
                endpoint_id,
                resource_name.clone(),
                endpoint,
            )) as crate::driver::DynDriver,
            (None, _, Some(local)) => local,
            (Some(endpoint_id), None, _) => return Err(OpenError::NoSuchEndpoint(endpoint_id)),
            (None, _, None) => return Err(OpenError::NoSuchDriver(binding.driver.id)),
        };
    let mut plan = DriverPlan::new(binding.driver.id, binding.endpoint, binding.generation);
    for iface_id in &resource.interfaces.interfaces {
        if let Some(iface) = registry.interface(*iface_id) {
            for method in &iface.methods {
                plan.insert(method.id, dispatch_driver.clone());
            }
        }
    }

    // Step 6: residual empty → Unconditional.
    let fast_path = if snapshot.is_empty() {
        FastPath::Unconditional
    } else {
        FastPath::Conditional(snapshot)
    };
    let compiled = CompiledOpenPlan {
        resource: req.resource,
        rights: req.rights,
        driver_plan: plan,
        fast_path,
    };
    registry.store_open_plan(cache_key, compiled.clone());

    // Step 7: allocate slot, install, return id.
    Ok(handles.insert(handle_from_plan(req.process, Some(resource_name), compiled)))
}

fn handle_from_plan(
    process: ProcessId,
    bound_path: Option<nexus_types::Path>,
    plan: CompiledOpenPlan,
) -> Handle {
    Handle {
        id: HandleId::new(0, 0), // patched by insert()
        process,
        resource: plan.resource,
        rights: plan.rights,
        driver_plan: plan.driver_plan,
        fast_path: plan.fast_path,
        state: HandleState::Active,
        // The concrete path this handle addresses, so prefix-resolved
        // Resources (state://**) reach the driver with the real path.
        bound_path,
    }
}

/// Compile a constraint set into a residual [`PolicySnapshot`]. An empty
/// constraint set produces an empty (Unconditional) snapshot.
fn compile_policy_snapshot(constraints: &ConstraintSet) -> PolicySnapshot {
    if constraints.is_empty() {
        PolicySnapshot::empty()
    } else {
        PolicySnapshot::new(vec![Arc::new(ConstraintCheck {
            constraints: constraints.clone(),
        })])
    }
}

/// Derive a child handle by attenuation: rights must be a subset and the
/// requested derivation kind must be permitted by the parent's flags.
pub fn derive_handle(
    handles: &mut HandleTable,
    parent_id: HandleId,
    new_rights: Rights,
    kind: nexus_types::DeriveKind,
    new_owner: ProcessId,
) -> Result<HandleId, OpenError> {
    let parent = handles.get(parent_id).ok_or(OpenError::RightsNotSubset)?;
    if parent.state != HandleState::Active {
        return Err(OpenError::StaticConstraintFailed);
    }
    if !new_rights.is_subset_of(&parent.rights) {
        return Err(OpenError::RightsNotSubset);
    }
    if !parent.rights.allows_derive(kind) {
        return Err(OpenError::RightsNotSubset);
    }
    let child = Handle {
        id: HandleId::new(0, 0),
        process: new_owner,
        resource: parent.resource,
        rights: new_rights,
        driver_plan: parent.driver_plan.clone(),
        fast_path: parent.fast_path.clone(),
        state: HandleState::Active,
        bound_path: parent.bound_path.clone(),
    };
    Ok(handles.insert(child))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{DriverDescriptor, DriverError, EchoDriver, FnDriver, RemoteEndpoint};
    use crate::handle::HandleTable;
    use async_trait::async_trait;
    use nexus_types::{
        Binding, EndpointId, Expiry, Grant, Interface, InterfaceFamily, InterfaceSet, Invoke,
        InvokeResult, Metadata, Method, MethodBitmap, ModalitySet, OutputModeSet, Path, Purity,
        ReplayClass, Resource, ResourceDescriptor, ResourceKind, ResourceName, ResourceSelector,
        RightFlags, Rights, SchemaId,
    };
    use parking_lot::Mutex;

    fn setup_resource(reg: &Registry, path: &str) -> ResourceId {
        let iface_id = reg.next_interface_id();
        reg.register_interface(Interface {
            id: iface_id,
            family: InterfaceFamily::Callable,
            methods: vec![Method {
                id: nexus_types::MethodId::new(100),
                name: "invoke".into(),
                input: SchemaId::new(0),
                output: SchemaId::new(0),
                modality: ModalitySet::TEXT,
                purity: Purity::Pure,
                replay: ReplayClass::Deterministic,
                supports: OutputModeSet::UNARY,
                cost: Default::default(),
                batchable: false,
            }],
            laws: Vec::new(),
        });
        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: "echo".into(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: nexus_types::Transport::InProcess,
            driver: Arc::new(EchoDriver),
        });
        let binding_id = reg.next_binding_id();
        reg.register_binding(Binding {
            id: binding_id,
            selector: ResourceSelector::parse("perform://effect/**").unwrap(),
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: nexus_types::DriverRef {
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
                    name: ResourceName::new(Path::parse(path).unwrap()),
                    kind: ResourceKind::Effect,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            false,
        )
        .unwrap();
        rid
    }

    fn setup_remote_resource(reg: &Registry, path: &str, endpoint: EndpointId) -> ResourceId {
        let iface_id = reg.next_interface_id();
        reg.register_interface(Interface {
            id: iface_id,
            family: InterfaceFamily::Callable,
            methods: vec![Method {
                id: nexus_types::MethodId::new(0),
                name: "invoke".into(),
                input: SchemaId::new(0),
                output: SchemaId::new(0),
                modality: ModalitySet::TEXT,
                purity: Purity::Effectful,
                replay: ReplayClass::NonIdempotentEffect,
                supports: OutputModeSet::UNARY | OutputModeSet::STREAM,
                cost: Default::default(),
                batchable: false,
            }],
            laws: Vec::new(),
        });
        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: "remote-provider".into(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: nexus_types::Transport::Grpc {
                endpoint: Some("test-endpoint".into()),
            },
            // This local driver must not be called for endpoint bindings. The
            // compiled plan uses RemoteDriver stubs instead.
            driver: Arc::new(EchoDriver),
        });
        let binding_id = reg.next_binding_id();
        reg.admit_binding(Binding {
            id: binding_id,
            selector: ResourceSelector::parse("perform://effect/plugin/**").unwrap(),
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: nexus_types::DriverRef {
                id: driver_id,
                name: "remote-provider".into(),
            },
            endpoint: Some(endpoint),
            generation: 1,
        })
        .unwrap();
        let rid = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: ResourceName::new(Path::parse(path).unwrap()),
                    kind: ResourceKind::Effect,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            false,
        )
        .unwrap();
        rid
    }

    fn setup_state_subtree_resource(reg: &Registry) -> ResourceId {
        let iface_id = reg.next_interface_id();
        reg.register_interface(Interface {
            id: iface_id,
            family: InterfaceFamily::Value,
            methods: vec![Method {
                id: nexus_types::MethodId::new(0),
                name: "read".into(),
                input: SchemaId::new(0),
                output: SchemaId::new(0),
                modality: ModalitySet::TEXT,
                purity: Purity::Pure,
                replay: ReplayClass::Observation,
                supports: OutputModeSet::UNARY,
                cost: Default::default(),
                batchable: false,
            }],
            laws: Vec::new(),
        });
        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: "state".into(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: nexus_types::Transport::InProcess,
            driver: Arc::new(FnDriver(|_, input| Ok(input))),
        });
        let binding_id = reg.next_binding_id();
        reg.register_binding(Binding {
            id: binding_id,
            selector: ResourceSelector::parse("*://state/**").unwrap(),
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: nexus_types::DriverRef {
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
                    name: ResourceName::new(Path::parse("state://").unwrap()),
                    kind: ResourceKind::State,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            true,
        )
        .unwrap();
        rid
    }

    struct TestEndpoint {
        seen: Arc<Mutex<Vec<Invoke>>>,
    }

    #[async_trait]
    impl RemoteEndpoint for TestEndpoint {
        async fn invoke(&self, invoke: Invoke) -> Result<InvokeResult, DriverError> {
            self.seen.lock().push(invoke.clone());
            Ok(InvokeResult {
                invocation_id: invoke.invocation_id,
                outcome: Ok(nexus_types::Value::Str("remote".into())),
            })
        }
    }

    #[test]
    fn open_unconditional_when_no_constraints() {
        let reg = Registry::new();
        let rid = setup_resource(&reg, "effect://x/post");
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/x/post").unwrap(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        let id = open_resource(
            &reg,
            &mut handles,
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
        .unwrap();
        let h = handles.get(id).unwrap();
        assert!(
            h.is_unconditional(),
            "no constraints ⇒ Unconditional fast path"
        );
        assert!(h.driver_plan.supports(nexus_types::MethodId::new(100)));
    }

    #[test]
    fn endpoint_binding_requires_registered_endpoint() {
        let reg = Registry::new();
        let rid = setup_remote_resource(&reg, "effect://plugin/acme/search", EndpointId::new(99));
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/plugin/acme/search").unwrap(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        let err = open_resource(
            &reg,
            &mut handles,
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
        .unwrap_err();
        assert!(matches!(err, OpenError::NoSuchEndpoint(id) if id == EndpointId::new(99)));
    }

    #[tokio::test]
    async fn endpoint_binding_compiles_to_remote_driver_plan() {
        let reg = Registry::new();
        let endpoint = reg.next_endpoint_id();
        let seen = Arc::new(Mutex::new(Vec::new()));
        reg.register_endpoint(endpoint, Arc::new(TestEndpoint { seen: seen.clone() }));
        let rid = setup_remote_resource(&reg, "effect://plugin/acme/search", endpoint);
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/plugin/acme/search").unwrap(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        let id = open_resource(
            &reg,
            &mut handles,
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
        .unwrap();
        let h = handles.get(id).unwrap();
        assert!(h.driver_plan.is_remote());
        assert!(h.driver_plan.supports(nexus_types::MethodId::new(0)));

        let ctx =
            crate::DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_operation_id(
                nexus_types::OperationId::new(ProcessId::new(1), nexus_types::NodeId::new(4), 0),
            );
        let out = h
            .driver_plan
            .call(
                nexus_types::MethodId::new(0),
                nexus_types::Value::Str("q".into()),
                nexus_types::OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            out,
            nexus_types::Outcome::Done(nexus_types::Value::Str("remote".into()))
        );
        let seen = seen.lock();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].invocation_id, "1/4/0");
        assert_eq!(
            seen[0].effect_path.to_string(),
            "effect://plugin/acme/search"
        );
    }

    #[test]
    fn repeated_open_reuses_compiled_open_plan_not_handle_slot() {
        let reg = Registry::new();
        let rid = setup_resource(&reg, "effect://x/post");
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/x/post").unwrap(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        let req = || OpenRequest {
            process: ProcessId::new(1),
            resource: rid,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: None,
            now_millis: 123,
        };

        let first = open_resource(&reg, &mut handles, req()).unwrap();
        assert_eq!(reg.open_cache_stats(), (0, 1, 1));
        let second = open_resource(&reg, &mut handles, req()).unwrap();
        assert_eq!(reg.open_cache_stats(), (1, 1, 1));

        assert_ne!(first, second, "each open still allocates its own Handle");
        assert_eq!(handles.len(), 2);
        assert!(handles.get(first).unwrap().is_unconditional());
        assert!(handles.get(second).unwrap().is_unconditional());
    }

    #[test]
    fn open_fails_without_matching_grant() {
        let reg = Registry::new();
        let rid = setup_resource(&reg, "effect://x/post");
        let mut handles = HandleTable::new();
        let err = open_resource(
            &reg,
            &mut handles,
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
        .unwrap_err();
        assert!(matches!(err, OpenError::NoMatchingGrant { .. }));
    }

    #[test]
    fn ordinary_state_grant_cannot_open_vault_or_fact_projection() {
        let reg = Registry::new();
        let rid = setup_state_subtree_resource(&reg);
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("*://state/**").unwrap(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        for path in ["state://vault/alice/token", "state://fact/1"] {
            let err = open_resource(
                &reg,
                &mut handles,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource: rid,
                    verb: "read".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: Some(Path::parse(path).unwrap()),
                    now_millis: 0,
                },
            )
            .unwrap_err();
            assert!(matches!(err, OpenError::ReservedPath(p) if p == path));
        }
        assert_eq!(handles.len(), 0);
    }

    #[test]
    fn open_picks_grant_covering_rights_not_first_selector_match() {
        // A process holds TWO grants hitting the same resource: the first (by
        // registration order) covers only derive flags but NO methods; the
        // second covers method 0. Requesting method 0 must succeed by selecting
        // the *covering* grant, not spuriously fail on the first match.
        let reg = Registry::new();
        let rid = setup_resource(&reg, "effect://x/post");
        // Grant A: matches selector, but rights cover no methods.
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/x/post").unwrap(),
            rights: Rights::new(MethodBitmap::empty(), RightFlags::all()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        // Grant B: matches selector AND covers method 0.
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/x/post").unwrap(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        let id = open_resource(
            &reg,
            &mut handles,
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
        .expect("a held grant covers method 0; open must select it");
        assert!(handles.get(id).unwrap().rights.methods.allows(0));
    }

    #[test]
    fn open_rights_not_subset_when_selector_matched_but_rights_uncovered() {
        let reg = Registry::new();
        let rid = setup_resource(&reg, "effect://x/post");
        // Only grant: matches selector but covers no methods.
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/x/post").unwrap(),
            rights: Rights::new(MethodBitmap::empty(), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        let err = open_resource(
            &reg,
            &mut handles,
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
        .unwrap_err();
        assert!(matches!(err, OpenError::RightsNotSubset));
    }

    #[test]
    fn open_conditional_when_constraints_present() {
        let reg = Registry::new();
        let rid = setup_resource(&reg, "effect://x/post");
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/x/post").unwrap(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
            constraints: ConstraintSet {
                predicates: vec![nexus_types::cap::Predicate::parse("account=alice").unwrap()],
            },
            expires: Expiry::Never,
        });
        let mut handles = HandleTable::new();
        let id = open_resource(
            &reg,
            &mut handles,
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
        .unwrap();
        assert!(!handles.get(id).unwrap().is_unconditional());
    }

    #[test]
    fn registered_policy_adds_residual_check() {
        use crate::policy::CapabilityPolicy;
        let reg = Registry::new();
        let rid = setup_resource(&reg, "effect://x/post");
        // Grant has no constraints (would be Unconditional)…
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/x/post").unwrap(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        // …but a registered source policy attaches an input predicate, so the
        // handle must become Conditional (a residual check exists).
        reg.register_policy(Arc::new(CapabilityPolicy {
            pattern: nexus_types::Capability::parse("perform://effect/x/**").unwrap(),
            constraints: ConstraintSet {
                predicates: vec![nexus_types::cap::Predicate::parse("account=alice").unwrap()],
            },
        }));
        let mut handles = HandleTable::new();
        let id = open_resource(
            &reg,
            &mut handles,
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
        .unwrap();
        assert!(
            !handles.get(id).unwrap().is_unconditional(),
            "a matching source policy with a predicate ⇒ Conditional"
        );
    }
}
