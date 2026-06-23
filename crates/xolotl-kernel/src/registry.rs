//! Control-plane registries, name resolution, and admission.
//!
//! The [`Registry`] holds the six control-plane descriptions
//! (Resource/Interface/Driver/Binding/Policy/Grant). It is consulted only on
//! the slow path (`open()`, admission) — **never** by the data plane.

use crate::driver::{DriverDescriptor, DriverPlan, DynDriver, DynRemoteEndpoint};
use crate::handle::FastPath;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use xolotl_types::{
    Binding, BindingId, DriverId, EndpointId, Grant, GrantId, Interface, InterfaceId, InterfaceSet,
    MethodId, Path, ProcessId, Resource, ResourceId, ResourceName, Rights,
};

const SMALL_HOLDER_GRANT_SCAN_LIMIT: usize = 8;

/// Errors returned by control-plane resource name resolution.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ResolveError {
    /// No registered resource matched the requested name.
    #[error("no resource named {0}")]
    NoSuchResource(String),
}

/// Errors returned by registry admission checks.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// Binding id was already registered.
    #[error("binding id {0:?} is already registered")]
    DuplicateBindingId(BindingId),
    /// Resource id was already registered.
    #[error("resource id {0:?} is already registered")]
    DuplicateResourceId(ResourceId),
    /// Resource name was already registered.
    #[error("resource name {0} is already registered")]
    DuplicateResourceName(String),
    /// Binding's driver does not implement a declared interface.
    #[error("interface {0} not implemented by driver {1}")]
    InterfaceNotImplemented(InterfaceId, DriverId),
    /// Binding points at a driver that is not registered.
    #[error("driver {0:?} is not registered")]
    DriverNotRegistered(DriverId),
    /// Resource points at a binding that is not registered.
    #[error("binding {0:?} is not registered")]
    BindingNotRegistered(BindingId),
    /// Resource requires interfaces not covered by its binding.
    #[error("binding {0} does not cover resource {1}'s interfaces")]
    InterfacesNotCovered(BindingId, ResourceId),
    /// Resource name was not registered.
    #[error("resource name {0} is not registered")]
    ResourceNotRegistered(String),
    /// A relink tried to move a resource to an older binding generation.
    #[error("resource {resource} binding generation regressed from {current} to {attempted}")]
    BindingGenerationRegressed {
        /// Resource name being relinked.
        resource: String,
        /// Current binding generation.
        current: u64,
        /// Attempted binding generation.
        attempted: u64,
    },
    /// Non-kernel caller attempted to register a reserved path.
    #[error("resource name {0} is under a reserved kernel prefix")]
    ReservedPrefix(String),
    /// Admission failed for a domain-specific reason.
    #[error("admission rejected: {0}")]
    Rejected(String),
}

/// Exact-match grant selector index key.
///
/// Exact selectors use this key; wildcard selectors stay in the per-holder
/// wildcard fallback list.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GrantSelectorKey {
    /// Process that holds the grant.
    pub holder: ProcessId,
    /// Capability verb, such as `read` or `perform`.
    pub verb: String,
    /// Concrete path matched by an exact selector.
    pub path: Path,
}

/// The six control-plane registries. Behind a single lock for
/// simplicity; the data plane never touches this, so contention is confined to
/// the slow path.
#[derive(Default)]
pub struct RegistryInner {
    /// Registered resources keyed by compact id.
    pub resources: HashMap<ResourceId, Resource>,
    /// Registered interfaces keyed by compact id.
    pub interfaces: HashMap<InterfaceId, Interface>,
    /// Registered driver descriptors keyed by compact id.
    pub drivers: HashMap<DriverId, DriverDescriptor>,
    /// Registered remote endpoint transports keyed by compact id.
    pub endpoints: HashMap<EndpointId, DynRemoteEndpoint>,
    /// Registered bindings keyed by compact id.
    pub bindings: HashMap<BindingId, Binding>,
    /// Registered grants keyed by grant id.
    pub grants: HashMap<GrantId, Grant>,
    /// Grant ids grouped by holder for slow-path grant scans.
    pub grants_by_holder: HashMap<ProcessId, Vec<GrantId>>,
    /// Exact, non-wildcard selector index for large grant sets.
    pub exact_grants: HashMap<GrantSelectorKey, Vec<GrantId>>,
    /// Wildcard selector fallback grant ids grouped by holder.
    pub wildcard_grants_by_holder: HashMap<ProcessId, Vec<GrantId>>,
    /// Source policies, consulted at `open()`. Held as trait
    /// objects so any `PolicySource` can register.
    pub policies: Vec<Arc<dyn crate::policy::PolicySource>>,
    /// Name → id index for resolution.
    pub names: HashMap<ResourceName, ResourceId>,
    /// Compiled open-plan cache. Cleared whenever control-plane
    /// descriptions change, so cached plans never survive a re-link/policy
    /// update/admission mutation.
    pub open_cache: HashMap<OpenCacheKey, CompiledOpenPlan>,
    /// Number of compiled-open-plan cache hits.
    pub open_cache_hits: u64,
    /// Number of compiled-open-plan cache misses.
    pub open_cache_misses: u64,
    next_id: u64,
}

impl RegistryInner {
    fn fresh_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn invalidate_open_cache(&mut self) {
        self.open_cache.clear();
    }

    fn index_grant(&mut self, id: GrantId, grant: &Grant) {
        self.grants_by_holder
            .entry(grant.holder)
            .or_default()
            .push(id);
        if let Some(key) = exact_selector_key(grant) {
            self.exact_grants.entry(key).or_default().push(id);
        } else {
            self.wildcard_grants_by_holder
                .entry(grant.holder)
                .or_default()
                .push(id);
        }
    }

    fn unindex_grant(&mut self, id: GrantId, grant: &Grant) {
        remove_indexed_id(&mut self.grants_by_holder, &grant.holder, id);
        if let Some(key) = exact_selector_key(grant) {
            remove_indexed_id(&mut self.exact_grants, &key, id);
        } else {
            remove_indexed_id(&mut self.wildcard_grants_by_holder, &grant.holder, id);
        }
    }
}

fn remove_indexed_id<K>(index: &mut HashMap<K, Vec<GrantId>>, key: &K, id: GrantId)
where
    K: Eq + std::hash::Hash,
{
    if let Some(ids) = index.get_mut(key) {
        ids.retain(|candidate| *candidate != id);
        if ids.is_empty() {
            index.remove(key);
        }
    }
}

fn exact_selector_key(grant: &Grant) -> Option<GrantSelectorKey> {
    let pattern = &grant.selector.pattern;
    if pattern.verb == "*"
        || pattern.scheme == "*"
        || pattern.scheme == "**"
        || pattern
            .segments
            .iter()
            .any(|segment| segment.as_str() == "*" || segment.as_str() == "**")
    {
        return None;
    }

    let mut path = Path::new(pattern.scheme.as_str());
    for segment in &pattern.segments {
        path = path.push(segment.clone());
    }
    Some(GrantSelectorKey {
        holder: grant.holder,
        verb: pattern.verb.clone(),
        path,
    })
}

fn target_selector_key(process: ProcessId, verb: &str, target: &Path) -> GrantSelectorKey {
    let mut path = Path::new(target.scheme());
    for segment in target.segments() {
        path = path.push(segment.clone());
    }
    GrantSelectorKey {
        holder: process,
        verb: verb.to_string(),
        path,
    }
}

/// Cache key for `open()` compilation. It includes every current
/// `OpenContext` field that can affect policy compilation, plus concrete
/// rights. Registry mutations clear the cache, so binding/policy/driver
/// generations cannot leak through stale plans.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OpenCacheKey {
    /// Grant selected by open.
    pub grant: GrantId,
    /// Resource being opened.
    pub resource: ResourceId,
    /// Concrete resource path used for selector and policy matching.
    pub resource_path: xolotl_types::Path,
    /// Capability verb requested by open.
    pub verb: String,
    /// Requested method bitmap bits.
    pub methods: u64,
    /// Requested right flag bits.
    pub flags: u32,
    /// Acting identity captured in the open context.
    pub acting: xolotl_types::IdentityRef,
    /// Open-time wall clock used for expiry and static policy checks.
    pub now_millis: i64,
}

impl OpenCacheKey {
    /// Build a key from the open context and requested rights.
    pub fn new(
        grant: GrantId,
        resource: ResourceId,
        resource_path: xolotl_types::Path,
        verb: impl Into<String>,
        rights: Rights,
        acting: xolotl_types::IdentityRef,
        now_millis: i64,
    ) -> Self {
        Self {
            grant,
            resource,
            resource_path,
            verb: verb.into(),
            methods: rights.methods.bits(),
            flags: rights.flags.bits(),
            acting,
            now_millis,
        }
    }
}

/// Cached `open()` compile product before assigning a process-owned Handle
/// slot. The Handle itself is never cached because ownership and generation are
/// per open.
#[derive(Clone)]
pub struct CompiledOpenPlan {
    /// Resource id captured by the compiled plan.
    pub resource: ResourceId,
    /// Rights that will be copied into the handle.
    pub rights: Rights,
    /// Frozen driver dispatch plan.
    pub driver_plan: DriverPlan,
    /// Fast-path policy marker captured by open.
    pub fast_path: FastPath,
}

/// Snapshot of registry object counts and open-plan cache metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryCounts {
    /// Number of registered resources.
    pub resources: usize,
    /// Number of registered interfaces.
    pub interfaces: usize,
    /// Number of registered drivers.
    pub drivers: usize,
    /// Number of registered remote endpoints.
    pub endpoints: usize,
    /// Number of registered bindings.
    pub bindings: usize,
    /// Number of registered grants.
    pub grants: usize,
    /// Number of registered source policies.
    pub policies: usize,
    /// Number of resource-name index entries.
    pub names: usize,
    /// Number of compiled open plans in the cache.
    pub open_cache_entries: usize,
    /// Number of open-plan cache hits.
    pub open_cache_hits: u64,
    /// Number of open-plan cache misses.
    pub open_cache_misses: u64,
}

/// Shared, lockable registry handle.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<RegistryInner>>,
}

impl Registry {
    /// Create an empty shared registry.
    pub fn new() -> Self {
        Self::default()
    }

    // ID allocation.

    /// Allocate the next resource id.
    pub fn next_resource_id(&self) -> ResourceId {
        ResourceId::new(self.inner.write().fresh_id())
    }
    /// Allocate the next interface id.
    pub fn next_interface_id(&self) -> InterfaceId {
        InterfaceId::new(self.inner.write().fresh_id())
    }
    /// Allocate the next driver id.
    pub fn next_driver_id(&self) -> DriverId {
        DriverId::new(self.inner.write().fresh_id())
    }
    /// Allocate the next remote endpoint id.
    pub fn next_endpoint_id(&self) -> EndpointId {
        EndpointId::new(self.inner.write().fresh_id())
    }
    /// Allocate the next binding id.
    pub fn next_binding_id(&self) -> BindingId {
        BindingId::new(self.inner.write().fresh_id())
    }
    /// Allocate the next grant id.
    pub fn next_grant_id(&self) -> GrantId {
        GrantId::new(self.inner.write().fresh_id())
    }

    // Registration. Admission lives in `admit_*`.

    /// Register an interface descriptor and invalidate cached open plans.
    pub fn register_interface(&self, iface: Interface) {
        let mut inner = self.inner.write();
        inner.interfaces.insert(iface.id, iface);
        inner.invalidate_open_cache();
    }

    /// Register a driver descriptor and invalidate cached open plans.
    pub fn register_driver(&self, desc: DriverDescriptor) {
        let mut inner = self.inner.write();
        inner.drivers.insert(desc.id, desc);
        inner.invalidate_open_cache();
    }

    /// Register or replace a remote endpoint transport. Bindings with
    /// `endpoint = Some(id)` compile to RPC stubs backed by this entry.
    pub fn register_endpoint(&self, id: EndpointId, endpoint: DynRemoteEndpoint) {
        let mut inner = self.inner.write();
        inner.endpoints.insert(id, endpoint);
        inner.invalidate_open_cache();
    }

    /// Remove a live remote endpoint transport and invalidate cached open
    /// plans that may reference it.
    pub fn unregister_endpoint(&self, id: EndpointId) -> bool {
        let mut inner = self.inner.write();
        let removed = inner.endpoints.remove(&id).is_some();
        if removed {
            inner.invalidate_open_cache();
        }
        removed
    }

    /// Admit and register a Resource. Rejects reserved-prefix names
    /// for non-kernel callers and verifies the binding covers the resource's
    /// interfaces.
    pub fn admit_resource(
        &self,
        resource: Resource,
        kernel_caller: bool,
    ) -> Result<ResourceId, AdmissionError> {
        let name = resource.descriptor.name.clone();
        if !kernel_caller && xolotl_types::is_kernel_reserved(name.path()) {
            return Err(AdmissionError::ReservedPrefix(name.path().to_string()));
        }
        let mut inner = self.inner.write();
        if inner.resources.contains_key(&resource.id) {
            return Err(AdmissionError::DuplicateResourceId(resource.id));
        }
        if inner.names.contains_key(&name) {
            return Err(AdmissionError::DuplicateResourceName(
                name.path().to_string(),
            ));
        }
        let binding = inner
            .bindings
            .get(&resource.binding)
            .ok_or(AdmissionError::BindingNotRegistered(resource.binding))?;
        // Binding must cover the resource's interfaces.
        if !binding.interfaces.covers(&resource.interfaces) {
            return Err(AdmissionError::InterfacesNotCovered(
                resource.binding,
                resource.id,
            ));
        }
        let id = resource.id;
        inner.names.insert(name, id);
        inner.resources.insert(id, resource);
        inner.invalidate_open_cache();
        Ok(id)
    }

    /// Relink an existing Resource to a new admitted Binding.
    ///
    /// The Resource id and name stay stable; newly opened Handles compile
    /// against the new binding, while already opened Handles keep their frozen
    /// driver plan. The new binding generation must not move backwards.
    pub fn relink_resource(
        &self,
        name: &ResourceName,
        interfaces: InterfaceSet,
        binding: BindingId,
    ) -> Result<ResourceId, AdmissionError> {
        let mut inner = self.inner.write();
        let id = inner
            .names
            .get(name)
            .copied()
            .ok_or_else(|| AdmissionError::ResourceNotRegistered(name.path().to_string()))?;
        let old_binding_id = inner
            .resources
            .get(&id)
            .ok_or_else(|| AdmissionError::ResourceNotRegistered(name.path().to_string()))?
            .binding;
        let old_generation = inner
            .bindings
            .get(&old_binding_id)
            .ok_or(AdmissionError::BindingNotRegistered(old_binding_id))?
            .generation;
        let new_binding = inner
            .bindings
            .get(&binding)
            .ok_or(AdmissionError::BindingNotRegistered(binding))?;
        if !new_binding.interfaces.covers(&interfaces) {
            return Err(AdmissionError::InterfacesNotCovered(binding, id));
        }
        if new_binding.generation < old_generation {
            return Err(AdmissionError::BindingGenerationRegressed {
                resource: name.path().to_string(),
                current: old_generation,
                attempted: new_binding.generation,
            });
        }
        let resource = inner
            .resources
            .get_mut(&id)
            .ok_or_else(|| AdmissionError::ResourceNotRegistered(name.path().to_string()))?;
        resource.interfaces = interfaces;
        resource.binding = binding;
        inner.invalidate_open_cache();
        Ok(id)
    }

    /// Return the current binding generation for a registered Resource.
    pub fn resource_binding_generation(&self, name: &ResourceName) -> Result<u64, AdmissionError> {
        let inner = self.inner.read();
        let id = inner
            .names
            .get(name)
            .copied()
            .ok_or_else(|| AdmissionError::ResourceNotRegistered(name.path().to_string()))?;
        let resource = inner
            .resources
            .get(&id)
            .ok_or_else(|| AdmissionError::ResourceNotRegistered(name.path().to_string()))?;
        let binding = inner
            .bindings
            .get(&resource.binding)
            .ok_or(AdmissionError::BindingNotRegistered(resource.binding))?;
        Ok(binding.generation)
    }

    /// Admit and register a Binding. The bound Driver must
    /// implement every Interface the Binding declares — checked here so a
    /// Binding can never reference interfaces its Driver doesn't provide.
    pub fn admit_binding(&self, binding: Binding) -> Result<BindingId, AdmissionError> {
        let inner = self.inner.read();
        if inner.bindings.contains_key(&binding.id) {
            return Err(AdmissionError::DuplicateBindingId(binding.id));
        }
        let driver = inner
            .drivers
            .get(&binding.driver.id)
            .ok_or(AdmissionError::DriverNotRegistered(binding.driver.id))?;
        for iface in &binding.interfaces.interfaces {
            if !driver.implements.interfaces.contains(iface) {
                return Err(AdmissionError::InterfaceNotImplemented(
                    *iface,
                    binding.driver.id,
                ));
            }
        }
        drop(inner);
        let id = binding.id;
        let mut inner = self.inner.write();
        inner.bindings.insert(id, binding);
        inner.invalidate_open_cache();
        Ok(id)
    }

    /// Register a binding without admission checks for crate-local fixtures.
    #[cfg(test)]
    pub(crate) fn register_binding(&self, binding: Binding) {
        let mut inner = self.inner.write();
        inner.bindings.insert(binding.id, binding);
        inner.invalidate_open_cache();
    }

    /// Admission sandbox check: every effect path a sandboxed
    /// provider declares must fall under its namespace prefix. Returns the first
    /// offending path, or `Ok(())` if all are within bounds.
    pub fn check_namespace_sandbox(
        namespace: &xolotl_types::Path,
        effect_paths: &[xolotl_types::Path],
    ) -> Result<(), AdmissionError> {
        for p in effect_paths {
            if !namespace.is_prefix_of(p) {
                return Err(AdmissionError::Rejected(format!(
                    "effect '{p}' escapes provider namespace '{namespace}'"
                )));
            }
        }
        Ok(())
    }

    /// Register or replace a grant and update grant selector indexes.
    pub fn register_grant(&self, grant: Grant) -> GrantId {
        let id = grant.id;
        let mut inner = self.inner.write();
        let old = inner.grants.get(&id).cloned();
        if let Some(old) = old {
            inner.unindex_grant(id, &old);
        }
        inner.index_grant(id, &grant);
        inner.grants.insert(id, grant);
        inner.invalidate_open_cache();
        id
    }

    /// Register a source policy. Consulted at every `open()` whose
    /// resource the policy applies to.
    pub fn register_policy(&self, policy: Arc<dyn crate::policy::PolicySource>) {
        let mut inner = self.inner.write();
        inner.policies.push(policy);
        inner.invalidate_open_cache();
    }

    /// Snapshot of the registered source policies (slow-path, called by
    /// `open()` to compile the residual).
    pub fn policies(&self) -> Vec<Arc<dyn crate::policy::PolicySource>> {
        self.inner.read().policies.clone()
    }

    // Name resolution.

    /// Resolve a control-plane resource name to a resource id.
    ///
    /// Callable `effect://` resources require exact matches; collection-style
    /// resources such as `state://` may resolve by longest path prefix.
    pub fn resolve_resource(&self, name: &ResourceName) -> Result<ResourceId, ResolveError> {
        let inner = self.inner.read();
        // Exact match first (the common case: every effect:// resource).
        if let Some(id) = inner.names.get(name).copied() {
            return Ok(id);
        }
        // Prefix resolution is only for collection-style resources such
        // as `state://**`. Callable `effect://...` resources must resolve by
        // exact path so an aggregate effect prefix can never serve sibling
        // actions like `effect://approval/check`.
        let target = name.path();
        if target.scheme() == "effect" {
            return Err(ResolveError::NoSuchResource(name.path().to_string()));
        }

        // Pick the longest-prefix match so a more specific collection root wins
        // over a broader one. The handle records the concrete `bound_path`.
        let mut best: Option<(usize, ResourceId)> = None;
        for (rname, rid) in inner.names.iter() {
            let root = rname.path();
            if root.scheme() == target.scheme() && root.is_prefix_of(target) {
                let depth = root.segments().len();
                if best.map(|(d, _)| depth >= d).unwrap_or(true) {
                    best = Some((depth, *rid));
                }
            }
        }
        best.map(|(_, id)| id)
            .ok_or_else(|| ResolveError::NoSuchResource(name.path().to_string()))
    }

    // Slow-path reads for open().

    /// Fetch a registered resource descriptor.
    pub fn resource(&self, id: ResourceId) -> Option<Resource> {
        self.inner.read().resources.get(&id).cloned()
    }

    /// Fetch a registered binding descriptor.
    pub fn binding(&self, id: BindingId) -> Option<Binding> {
        self.inner.read().bindings.get(&id).cloned()
    }

    /// Fetch a registered interface descriptor.
    pub fn interface(&self, id: InterfaceId) -> Option<Interface> {
        self.inner.read().interfaces.get(&id).cloned()
    }

    /// Fetch a registered driver descriptor.
    pub fn driver(&self, id: DriverId) -> Option<DriverDescriptor> {
        self.inner.read().drivers.get(&id).cloned()
    }

    /// The live driver implementation for a driver id.
    pub fn driver_impl(&self, id: DriverId) -> Option<DynDriver> {
        self.inner.read().drivers.get(&id).map(|d| d.driver.clone())
    }

    /// The live transport implementation for a remote endpoint id.
    pub fn remote_endpoint(&self, id: EndpointId) -> Option<DynRemoteEndpoint> {
        self.inner.read().endpoints.get(&id).cloned()
    }

    /// Fetch a registered grant.
    pub fn grant(&self, id: GrantId) -> Option<Grant> {
        self.inner.read().grants.get(&id).cloned()
    }

    /// All grants held by `process`, used by the `open()` slow path.
    pub fn grants_of(&self, process: ProcessId) -> Vec<Grant> {
        let inner = self.inner.read();
        inner
            .grants_by_holder
            .get(&process)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| inner.grants.get(id).cloned())
            .collect()
    }

    /// Candidate grants for `open()` selector matching. Exact, non-wildcard
    /// selectors are addressed directly by `(holder, verb, path)`; wildcard
    /// selectors stay in a small per-holder fallback set and are still matched
    /// structurally by `open()`.
    pub fn candidate_grants(&self, process: ProcessId, verb: &str, target: &Path) -> Vec<Grant> {
        let inner = self.inner.read();
        let Some(holder_ids) = inner.grants_by_holder.get(&process) else {
            return Vec::new();
        };
        if holder_ids.len() <= SMALL_HOLDER_GRANT_SCAN_LIMIT {
            return holder_ids
                .iter()
                .filter_map(|id| inner.grants.get(id).cloned())
                .collect();
        }
        // Capability selectors do not carry Path::cluster and ResourceSelector
        // matching is defined over verb + scheme + segments. Keep the exact
        // index key on the same structural surface so clustered targets do not
        // miss grants that would match through ResourceSelector::matches.
        let key = target_selector_key(process, verb, target);
        inner
            .exact_grants
            .get(&key)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .chain(
                inner
                    .wildcard_grants_by_holder
                    .get(&process)
                    .into_iter()
                    .flat_map(|ids| ids.iter()),
            )
            .filter_map(|id| inner.grants.get(id).cloned())
            .collect()
    }

    /// Resolve the first method named `name` on `interface`, returning its
    /// index (bit position) and id.
    pub fn method_index(&self, interface: InterfaceId, name: &str) -> Option<(u32, MethodId)> {
        let inner = self.inner.read();
        let iface = inner.interfaces.get(&interface)?;
        iface.method_index(name).map(|(i, m)| (i, m.id))
    }

    /// Number of registered resources.
    pub fn resource_count(&self) -> usize {
        self.inner.read().resources.len()
    }

    /// Snapshot counts for registry observability.
    pub fn counts(&self) -> RegistryCounts {
        let inner = self.inner.read();
        RegistryCounts {
            resources: inner.resources.len(),
            interfaces: inner.interfaces.len(),
            drivers: inner.drivers.len(),
            endpoints: inner.endpoints.len(),
            bindings: inner.bindings.len(),
            grants: inner.grants.len(),
            policies: inner.policies.len(),
            names: inner.names.len(),
            open_cache_entries: inner.open_cache.len(),
            open_cache_hits: inner.open_cache_hits,
            open_cache_misses: inner.open_cache_misses,
        }
    }

    /// Look up a compiled open plan and update hit/miss counters.
    pub fn cached_open_plan(&self, key: &OpenCacheKey) -> Option<CompiledOpenPlan> {
        let mut inner = self.inner.write();
        let plan = inner.open_cache.get(key).cloned();
        if plan.is_some() {
            inner.open_cache_hits += 1;
        } else {
            inner.open_cache_misses += 1;
        }
        plan
    }

    /// Store a compiled open plan in the cache.
    pub fn store_open_plan(&self, key: OpenCacheKey, plan: CompiledOpenPlan) {
        self.inner.write().open_cache.insert(key, plan);
    }

    /// Return `(hits, misses, entries)` for the compiled open-plan cache.
    pub fn open_cache_stats(&self) -> (u64, u64, usize) {
        let inner = self.inner.read();
        (
            inner.open_cache_hits,
            inner.open_cache_misses,
            inner.open_cache.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use xolotl_types::{
        ConstraintSet, Expiry, InterfaceSet, Metadata, MethodBitmap, Path, ResourceDescriptor,
        ResourceKind, ResourceSelector, RightFlags,
    };

    fn name(s: &str) -> anyhow::Result<ResourceName> {
        Ok(ResourceName::new(Path::parse(s)?))
    }

    fn empty_binding(reg: &Registry, generation: u64) -> anyhow::Result<BindingId> {
        let id = reg.next_binding_id();
        reg.register_binding(Binding {
            id,
            selector: ResourceSelector::parse("perform://effect/**")?,
            interfaces: InterfaceSet::default(),
            driver: xolotl_types::DriverRef {
                id: DriverId::new(0),
                name: "test".into(),
            },
            endpoint: None,
            generation,
        });
        Ok(id)
    }

    #[test]
    fn namespace_sandbox_rejects_escape() -> anyhow::Result<()> {
        // A sandboxed provider's effects must stay under its namespace.
        let ns = xolotl_types::Path::parse("effect://external-provider/acme")?;
        let allowed = [
            xolotl_types::Path::parse("effect://external-provider/acme/fetch")?,
            xolotl_types::Path::parse("effect://external-provider/acme/post")?,
        ];
        ensure!(
            Registry::check_namespace_sandbox(&ns, &allowed).is_ok(),
            "provider namespace should allow paths below the namespace"
        );
        let escaped = [
            xolotl_types::Path::parse("effect://external-provider/acme/ok")?,
            xolotl_types::Path::parse("effect://x/post")?,
        ];
        ensure!(
            Registry::check_namespace_sandbox(&ns, &escaped).is_err(),
            "provider namespace should reject paths outside the namespace"
        );
        let sibling = [xolotl_types::Path::parse(
            "effect://external-provider/acmeevil/tool",
        )?];
        ensure!(
            Registry::check_namespace_sandbox(&ns, &sibling).is_err(),
            "provider namespace should reject string-prefix siblings"
        );
        Ok(())
    }

    #[test]
    fn resolve_after_admit() -> anyhow::Result<()> {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let binding = empty_binding(&reg, 1)?;
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("effect://inference/infer")?,
                kind: ResourceKind::Effect,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding,
        };
        reg.admit_resource(res, false)?;
        let resolved = reg.resolve_resource(&name("effect://inference/infer")?)?;
        ensure!(resolved == rid, "resolved resource id mismatch");
        Ok(())
    }

    #[test]
    fn duplicate_resource_name_is_rejected() -> anyhow::Result<()> {
        let reg = Registry::new();
        let binding = empty_binding(&reg, 1)?;
        let first = Resource {
            id: reg.next_resource_id(),
            descriptor: ResourceDescriptor {
                name: name("effect://inference/infer")?,
                kind: ResourceKind::Effect,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding,
        };
        reg.admit_resource(first, false)?;

        let second = Resource {
            id: reg.next_resource_id(),
            descriptor: ResourceDescriptor {
                name: name("effect://inference/infer")?,
                kind: ResourceKind::Effect,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding,
        };
        let err = reg.admit_resource(second, false);
        ensure!(
            matches!(err, Err(AdmissionError::DuplicateResourceName(_))),
            "duplicate resource name was not rejected: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn relink_resource_keeps_resource_id_and_updates_binding() -> anyhow::Result<()> {
        let reg = Registry::new();
        let first_binding = empty_binding(&reg, 1)?;
        let rid = reg.next_resource_id();
        let resource_name = name("effect://external-provider/chat/search")?;
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::default(),
                binding: first_binding,
            },
            false,
        )?;

        let next_binding = empty_binding(&reg, 2)?;
        let relinked =
            reg.relink_resource(&resource_name, InterfaceSet::default(), next_binding)?;
        ensure!(relinked == rid, "relink changed resource id");
        let generation = reg.resource_binding_generation(&resource_name)?;
        ensure!(generation == 2, "resource generation was not updated");
        let stored = reg.resource(rid).context("resource should remain stored")?;
        ensure!(
            stored.binding == next_binding,
            "resource binding was not updated"
        );
        Ok(())
    }

    #[test]
    fn relink_resource_rejects_generation_regression() -> anyhow::Result<()> {
        let reg = Registry::new();
        let first_binding = empty_binding(&reg, 3)?;
        let rid = reg.next_resource_id();
        let resource_name = name("effect://external-provider/chat/search")?;
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::default(),
                binding: first_binding,
            },
            false,
        )?;

        let stale_binding = empty_binding(&reg, 2)?;
        let err = reg.relink_resource(&resource_name, InterfaceSet::default(), stale_binding);
        ensure!(
            matches!(err, Err(AdmissionError::BindingGenerationRegressed { .. })),
            "stale binding generation was not rejected: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn effect_resources_do_not_prefix_resolve_sibling_actions() -> anyhow::Result<()> {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let binding = empty_binding(&reg, 1)?;
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("effect://approval")?,
                kind: ResourceKind::Effect,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding,
        };
        reg.admit_resource(res, false)?;

        let resolved = reg.resolve_resource(&name("effect://approval")?)?;
        ensure!(resolved == rid, "resolved effect id mismatch");
        let err = reg.resolve_resource(&name("effect://approval/check")?);
        ensure!(
            matches!(
                err,
            Err(ResolveError::NoSuchResource(ref path)) if path == "effect://approval/check"
            ),
            "effect sibling action should not prefix-resolve: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn state_resources_can_prefix_resolve_concrete_paths() -> anyhow::Result<()> {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let binding = empty_binding(&reg, 1)?;
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("state://memory")?,
                kind: ResourceKind::State,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding,
        };
        reg.admit_resource(res, false)?;

        let resolved = reg.resolve_resource(&name("state://memory/alice/fact")?)?;
        ensure!(resolved == rid, "state prefix resource id mismatch");
        Ok(())
    }

    #[test]
    fn reserved_prefix_rejected_for_non_kernel() -> anyhow::Result<()> {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let binding = empty_binding(&reg, 1)?;
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("state://kernel/secret")?,
                kind: ResourceKind::Kernel,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding,
        };
        let non_kernel = reg.admit_resource(res.clone(), false);
        ensure!(
            matches!(non_kernel, Err(AdmissionError::ReservedPrefix(_))),
            "non-kernel caller should not admit reserved prefix: {non_kernel:?}"
        );
        // Kernel caller may register it.
        reg.admit_resource(res, true)?;
        Ok(())
    }

    #[test]
    fn grants_of_filters_by_holder() -> anyhow::Result<()> {
        let reg = Registry::new();
        let g = |holder: u64, id: u64| -> anyhow::Result<Grant> {
            Ok(Grant {
                id: GrantId::new(id),
                holder: ProcessId::new(holder),
                selector: xolotl_types::ResourceSelector::parse("perform://effect/x")?,
                rights: xolotl_types::Rights::default(),
                constraints: xolotl_types::ConstraintSet::empty(),
                expires: xolotl_types::Expiry::Never,
            })
        };
        reg.register_grant(g(1, 10)?);
        reg.register_grant(g(1, 11)?);
        reg.register_grant(g(2, 12)?);
        ensure!(
            reg.grants_of(ProcessId::new(1)).len() == 2,
            "holder 1 grant count mismatch"
        );
        ensure!(
            reg.grants_of(ProcessId::new(2)).len() == 1,
            "holder 2 grant count mismatch"
        );
        Ok(())
    }

    #[test]
    fn candidate_grants_use_exact_selector_index() -> anyhow::Result<()> {
        let reg = Registry::new();
        let holder = ProcessId::new(7);
        for i in 0..128 {
            reg.register_grant(Grant {
                id: reg.next_grant_id(),
                holder,
                selector: ResourceSelector::parse(&format!("perform://effect/irrelevant/g{i}"))
                    .with_context(|| format!("irrelevant selector {i} did not parse"))?,
                rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder,
            selector: ResourceSelector::parse("perform://effect/target")?,
            rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let target = Path::parse("effect://target")?;
        let candidates = reg.candidate_grants(holder, "perform", &target);
        ensure!(candidates.len() == 1, "candidate count mismatch");
        let candidate = candidates.first().context("missing candidate grant")?;
        ensure!(
            candidate.selector.matches("perform", &target),
            "candidate selector did not match target"
        );
        Ok(())
    }

    #[test]
    fn candidate_grants_exact_index_matches_clustered_targets_structurally() -> anyhow::Result<()> {
        let reg = Registry::new();
        let holder = ProcessId::new(7);
        for i in 0..SMALL_HOLDER_GRANT_SCAN_LIMIT {
            reg.register_grant(Grant {
                id: reg.next_grant_id(),
                holder,
                selector: ResourceSelector::parse(&format!("perform://effect/irrelevant/g{i}"))
                    .with_context(|| format!("irrelevant selector {i} did not parse"))?,
                rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder,
            selector: ResourceSelector::parse("perform://effect/target")?,
            rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let target = Path::parse("path://phone/effect/target")?;
        let candidates = reg.candidate_grants(holder, "perform", &target);
        ensure!(candidates.len() == 1, "candidate count mismatch");
        let candidate = candidates.first().context("missing candidate grant")?;
        ensure!(
            candidate.selector.matches("perform", &target),
            "candidate selector did not match clustered target"
        );
        Ok(())
    }

    #[test]
    fn replacing_grant_updates_selector_indexes() -> anyhow::Result<()> {
        let reg = Registry::new();
        let holder = ProcessId::new(7);
        for i in 0..SMALL_HOLDER_GRANT_SCAN_LIMIT {
            reg.register_grant(Grant {
                id: reg.next_grant_id(),
                holder,
                selector: ResourceSelector::parse(&format!("perform://effect/irrelevant/g{i}"))
                    .with_context(|| format!("irrelevant selector {i} did not parse"))?,
                rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        let id = reg.next_grant_id();
        let grant = |selector: &str| -> anyhow::Result<Grant> {
            Ok(Grant {
                id,
                holder,
                selector: ResourceSelector::parse(selector)?,
                rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            })
        };

        reg.register_grant(grant("perform://effect/old")?);
        reg.register_grant(grant("perform://effect/new")?);

        let old = Path::parse("effect://old")?;
        ensure!(
            reg.candidate_grants(holder, "perform", &old).is_empty(),
            "old selector index should be empty after replacement"
        );
        let new = Path::parse("effect://new")?;
        let candidates = reg.candidate_grants(holder, "perform", &new);
        ensure!(
            candidates.len() == 1,
            "new selector candidate count mismatch"
        );
        Ok(())
    }
}
