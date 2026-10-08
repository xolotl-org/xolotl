//! Compile open requests into executable [`Handle`] values.
//!
//! Preparation resolves authority and builds an immutable plan without borrowing
//! the handle table. Installation checks that the control plane is unchanged and
//! allocates a slot. Host policy callbacks run only during preparation.

use crate::driver::{DriverPlan, RemoteDriver};
use crate::handle::{FastPath, Handle, HandleTable};
use crate::policy::{OpenContext, PolicyCompileError};
use crate::process::state_cleanup_owner;
use crate::registry::{CompiledOpenPlan, OpenCacheKey, Registry, ResolveError};
use std::sync::Arc;
use thiserror::Error;
use xolotl_types::{Expiry, Grant, HandleId, IdentityRef, ProcessId, ResourceId, Rights};

mod authority;
mod prepared;
use authority::compile_grant_snapshot;
pub use prepared::PreparedOpen;

/// Errors returned while compiling an open request into a handle.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum OpenError {
    /// The acting identity is not registered in this Kernel's directory.
    #[error("identity admission failed: {0}")]
    Identity(#[from] crate::identity::IdentityError),
    /// The handle table cannot admit a new slot or its parent was revoked.
    #[error("handle admission failed: {0}")]
    HandleAdmission(#[from] xolotl_core::AuthorityError),
    /// The caller tried to open a resource for a process not present in the
    /// process table.
    #[error("process {0} not found")]
    NoSuchProcess(ProcessId),
    /// The owning process no longer accepts handles in the current execution scope.
    #[error("process {0} no longer accepts handles")]
    ProcessUnavailable(ProcessId),
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
    /// Requested method bits do not belong to the requested capability category.
    #[error("requested methods do not match capability verb {0}")]
    MethodAuthorityMismatch(String),
    /// The prepared method layout differs from the resource's current contract.
    #[error("resource method contract changed; prepare a new execution")]
    MethodContractChanged,
    /// A live cached handle cannot be used for the requested operation.
    #[error("bound handle {0} does not match the requested target, identity, method, or rights")]
    BoundHandleMismatch(HandleId),
    /// Control-plane state changed between preparation and handle installation.
    #[error("registry changed before handle installation; prepare the open again")]
    RegistryChanged,
    /// The requested path resolves to another resource.
    #[error("requested path does not resolve to resource {0}")]
    ResourcePathMismatch(ResourceId),
    /// A handle must bind one concrete target, never a selector pattern.
    #[error("handle target must be a concrete path: {0}")]
    NonConcretePath(xolotl_types::Path),
    /// Registry has no resource with this id.
    #[error("resource {0} not found")]
    NoSuchResource(ResourceId),
    /// Registry has no resource matching the requested name.
    #[error("{0}")]
    ResolveResource(#[from] ResolveError),
    /// Resource points at a binding that is not registered.
    #[error("binding {0} not found")]
    NoSuchBinding(xolotl_types::BindingId),
    /// Binding points at a driver that is not registered.
    #[error("driver {0} not found")]
    NoSuchDriver(xolotl_types::DriverId),
    /// Binding points at a remote endpoint that is not registered.
    #[error("endpoint {0} not found")]
    NoSuchEndpoint(xolotl_types::EndpointId),
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
    pub requested_path: Option<xolotl_types::Path>,
    /// Wall clock at open, for expiry / static constraint evaluation.
    pub now_millis: i64,
}

/// Compile and install a Handle. On success the Handle is in the table
/// and its [`HandleId`] is returned.
/// Policy compilation runs outside the table lock. Use [`prepare_open`] and
/// [`PreparedOpen::install`] separately to inspect the contract before installation.
pub fn open_resource(
    registry: &Registry,
    handles: &HandleTable,
    req: OpenRequest,
) -> Result<HandleId, OpenError> {
    open_resource_with_attached(registry, handles, req, &[])
}

/// Compile and install a Handle using process-attached grants.
pub fn open_resource_with_attached(
    registry: &Registry,
    handles: &HandleTable,
    req: OpenRequest,
    attached_grants: &[Grant],
) -> Result<HandleId, OpenError> {
    prepare_open(registry, req, attached_grants)?.install(handles)
}

/// Resolve authority and compile an immutable plan without installing a handle.
/// Pass an empty slice when all grants live in the registry. Attached grants are
/// supplied by the trusted host; callers manage their process lifecycle separately.
/// Static policy observes `req.now_millis`; installation does not rerun callbacks
/// or advance that authorization time. Prepare close to installation.
///
/// ```
/// use xolotl_kernel::{HandleTable, OpenError, OpenRequest, Registry, prepare_open};
/// use xolotl_types::{Grant, HandleId};
///
/// fn open_shared(
///     registry: &Registry,
///     handles: &HandleTable,
///     request: OpenRequest,
///     grants: &[Grant],
/// ) -> Result<HandleId, OpenError> {
///     let prepared = prepare_open(registry, request, grants)?;
///     // Inspect prepared.policy() or method contracts before allocating a slot.
///     prepared.install(handles)
/// }
/// ```
pub fn prepare_open(
    registry: &Registry,
    req: OpenRequest,
    attached_grants: &[Grant],
) -> Result<PreparedOpen, OpenError> {
    prepare_open_with_contract(registry, req, attached_grants, None)
}

pub(crate) fn prepare_open_with_contract(
    registry: &Registry,
    req: OpenRequest,
    attached_grants: &[Grant],
    expected: Option<&crate::registry::ResourceContract>,
) -> Result<PreparedOpen, OpenError> {
    let revision = registry.revision();
    // Resolve the resource descriptor before evaluating grants and policies.
    let resource = registry
        .resource(req.resource)
        .ok_or(OpenError::NoSuchResource(req.resource))?;
    if expected.is_some_and(|contract| !contract.matches(&resource)) {
        return Err(OpenError::MethodContractChanged);
    }
    // The path used for grant/selector matching and as the handle's bound path
    // is the *requested* concrete path when given; otherwise it is the resolved
    // Resource's own name.
    let match_path = req
        .requested_path
        .clone()
        .unwrap_or_else(|| resource.descriptor.name.path().clone());
    let resource_name = match_path;
    if !resource_name.is_concrete() {
        return Err(OpenError::NonConcretePath(resource_name));
    }
    if registry.resolve_resource(&xolotl_types::ResourceName::new(resource_name.clone()))?
        != req.resource
    {
        return Err(OpenError::ResourcePathMismatch(req.resource));
    }
    let resource_root = resource.descriptor.name.path();
    let is_fact_projection_resource = resource_root.scheme() == "state"
        && resource_root.segments().first().map(|s| s.as_str()) == Some("fact");
    if xolotl_types::is_kernel_reserved(&resource_name)
        || xolotl_types::is_vault_reserved(&resource_name)
        || (xolotl_types::is_fact_reserved(&resource_name) && !is_fact_projection_resource)
    {
        return Err(OpenError::ReservedPath(resource_name.to_string()));
    }

    let methods = registry
        .interface_methods(&resource.interfaces)
        .ok_or(OpenError::NoSuchResource(req.resource))?;
    let eligible = methods
        .iter()
        .enumerate()
        .filter(|(_, method)| method.authority.verb() == req.verb)
        .fold(xolotl_types::MethodBitmap::empty(), |bitmap, (index, _)| {
            bitmap | xolotl_types::MethodBitmap::method(index as u32)
        });
    // A propagation-only handle still has an explicit admission category. Its
    // zero method bitmap never authorizes a later derivation to add methods.
    if req.verb.is_empty() || req.verb == "*" || !req.rights.methods.is_subset_of(eligible) {
        return Err(OpenError::MethodAuthorityMismatch(req.verb));
    }

    // A method grant and a propagation grant may be different candidates.
    // Select either contributor once, then compile each right domain as its own
    // OR of grants. The two domains are conjunctive at the actual operation.
    let (mut grants, mut selector_matched, cache_allowed) = registry.select_open_grants(
        req.process,
        &req.verb,
        &resource_name,
        req.rights,
        &methods,
        req.now_millis,
    );
    let registered_count = grants.len();
    for grant in attached_grants {
        if grant.holder != req.process
            || grant.expires.is_expired(req.now_millis)
            || !grant.selector.matches(&req.verb, &resource_name)
        {
            continue;
        }
        selector_matched = true;
        let covers_methods = !req.rights.methods.is_empty()
            && grant
                .rights
                .methods
                .covers_bitmap(req.rights.methods, &methods);
        let covers_flags =
            !req.rights.flags.is_empty() && grant.rights.flags.contains(req.rights.flags);
        if covers_methods || covers_flags || req.rights == Rights::default() {
            grants.push(grant.clone());
        }
    }
    let method_grants: Vec<_> = if req.rights.methods.is_empty() {
        Vec::new()
    } else {
        grants
            .iter()
            .filter(|grant| {
                grant
                    .rights
                    .methods
                    .covers_bitmap(req.rights.methods, &methods)
            })
            .collect()
    };
    let propagation_grants: Vec<_> = if req.rights.flags.is_empty() {
        Vec::new()
    } else {
        grants
            .iter()
            .filter(|grant| grant.rights.flags.contains(req.rights.flags))
            .collect()
    };
    if grants.is_empty()
        || !req.rights.methods.is_empty() && method_grants.is_empty()
        || !req.rights.flags.is_empty() && propagation_grants.is_empty()
    {
        // A selector matched but none covered the rights; without any selector
        // match, report that no grant covered the resource.
        if selector_matched {
            return Err(OpenError::RightsNotSubset);
        } else {
            return Err(OpenError::NoMatchingGrant {
                process: req.process,
                resource: req.resource,
            });
        }
    }

    // Evaluate constraints that do not require per-operation input at open time.
    // The remaining residual policy is carried into the handle plan.
    let grant_policy = if req.rights.methods.is_empty() {
        crate::policy::PolicySnapshot::empty()
    } else {
        compile_grant_snapshot(&method_grants)
    }
    .merge(if req.rights.flags.is_empty() {
        crate::policy::PolicySnapshot::empty()
    } else {
        compile_grant_snapshot(&propagation_grants)
    });
    // Registered grants change only with the registry revision. Attached
    // grants are host-owned snapshots with no revision; caching them would
    // retain arbitrarily large external authority and require deep equality.
    let cache_key = if registered_count == 1
        && grants.len() == 1
        && grants[0].expires == Expiry::Never
        && cache_allowed
        && grants[0]
            .rights
            .methods
            .covers_bitmap(req.rights.methods, &methods)
        && grants[0].rights.flags.contains(req.rights.flags)
    {
        OpenCacheKey::for_cache(
            &grants[0],
            req.resource,
            &resource_name,
            &req.verb,
            req.rights,
            req.acting,
        )
    } else {
        None
    };
    if let Some((plan, revision)) = cache_key
        .as_ref()
        .and_then(|key| registry.cached_open_plan(key, revision))
    {
        return Ok(PreparedOpen::new(
            registry.clone(),
            revision,
            req.process,
            req.acting,
            req.verb,
            resource_name,
            plan,
        ));
    }

    // Compile policy into a snapshot with partial evaluation. The residual is
    // the input-dependent part of the grant constraints and registered source
    // policies that apply to this open. Open-time decidable parts are evaluated
    // and eliminated.
    let mut snapshot = grant_policy;
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

    // Read the binding and build the driver plan.
    let binding = registry
        .binding(resource.binding)
        .ok_or(OpenError::NoSuchBinding(resource.binding))?;
    let (remote_endpoint, revision) = match binding.endpoint {
        Some(endpoint_id) => {
            let (endpoint, revision) = registry
                .remote_endpoint_with_revision(endpoint_id, revision)
                .ok_or(OpenError::NoSuchEndpoint(endpoint_id))?;
            (Some(endpoint), revision)
        }
        None => (None, revision),
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
                resource.id,
                binding.generation,
                resource_name.clone(),
                endpoint,
            )) as crate::driver::DynDriver,
            (None, _, Some(local)) => local,
            (Some(endpoint_id), None, _) => return Err(OpenError::NoSuchEndpoint(endpoint_id)),
            (None, _, None) => return Err(OpenError::NoSuchDriver(binding.driver.id)),
        };
    let mut plan = DriverPlan::new(binding.driver.id, binding.endpoint, binding.generation);
    let cleanup_owner = state_cleanup_owner(&resource_name);
    for (index, method) in methods.into_iter().enumerate() {
        let index = u32::try_from(index).map_err(|_error| OpenError::RightsNotSubset)?;
        plan.insert_declared(index, method, cleanup_owner, dispatch_driver.clone());
    }

    // Empty residual policy permits the unconditional fast path.
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
    if !registry.publish_open_plan(cache_key, &compiled, revision) {
        return Err(OpenError::RegistryChanged);
    }

    Ok(PreparedOpen::new(
        registry.clone(),
        revision,
        req.process,
        req.acting,
        req.verb,
        resource_name,
        compiled,
    ))
}

fn handle_from_plan(
    process: ProcessId,
    acting: IdentityRef,
    open_verb: String,
    bound_path: Option<xolotl_types::Path>,
    plan: CompiledOpenPlan,
) -> Handle {
    Handle {
        id: HandleId::new(0, 0), // patched by insert()
        process,
        acting,
        open_verb,
        resource: plan.resource,
        rights: plan.rights,
        driver_plan: plan.driver_plan,
        fast_path: plan.fast_path,
        // The concrete path this handle addresses, so prefix-resolved
        // Resources (state://**) reach the driver with the real path.
        bound_path,
    }
}

#[cfg(test)]
mod tests;
