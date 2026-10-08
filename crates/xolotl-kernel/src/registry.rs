//! Control-plane registries, name resolution, and admission.
//!
//! The [`Registry`] holds the six control-plane descriptions
//! (Resource/Interface/Driver/Binding/Policy/Grant). It is consulted only on
//! the slow path (`open()`, admission) — **never** by the data plane.

use crate::driver::{DriverDescriptor, DriverPlan, DynDriver, DynRemoteEndpoint};
use crate::handle::FastPath;
use crate::runtime_domain::RuntimeDomain;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use xolotl_types::{
    Binding, BindingId, DriverId, EndpointId, Grant, GrantId, Interface, InterfaceId, InterfaceSet,
    Metadata, Method, MethodBitmap, Path, ProcessId, Resource, ResourceDescriptor, ResourceId,
    ResourceName, Rights,
};

const SMALL_HOLDER_GRANT_SCAN_LIMIT: usize = 8;

mod open_cache;
use open_cache::{OpenPlanCache, RetiredOpenPlans};

fn validate_resource_name(name: &ResourceName) -> Result<(), AdmissionError> {
    if name.path().is_concrete() {
        Ok(())
    } else {
        Err(AdmissionError::Rejected(format!(
            "resource {} must have a concrete registered path",
            name.path()
        )))
    }
}

fn validate_methods<'a>(
    methods: impl IntoIterator<Item = &'a Method>,
    target: Option<&Path>,
) -> Result<(), AdmissionError> {
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    for method in methods {
        if method.name.is_empty() || !names.insert(&method.name) || !ids.insert(method.id) {
            return Err(AdmissionError::Rejected(
                "resource methods require nonempty, unique names and unique ids".into(),
            ));
        }
        if names.len() > 64 {
            return Err(AdmissionError::Rejected(
                "a resource supports at most 64 methods across its interfaces".into(),
            ));
        }
        if let Some(target) = target {
            xolotl_types::Capability::try_new(
                method.authority.verb(),
                target.scheme(),
                core::iter::empty::<&str>(),
                None,
            )
            .map_err(|error| {
                AdmissionError::Rejected(format!(
                    "method {} on {target} has invalid authority: {error}",
                    method.name
                ))
            })?;
        }
    }
    Ok(())
}

fn validate_resource_methods(
    inner: &RegistryInner,
    interfaces: &InterfaceSet,
    target: &Path,
) -> Result<(), AdmissionError> {
    let mut methods = Vec::new();
    for id in &interfaces.interfaces {
        let interface = inner
            .interfaces
            .get(id)
            .ok_or_else(|| AdmissionError::Rejected(format!("interface {id} is not registered")))?;
        methods.extend(&interface.methods);
    }
    validate_methods(methods, Some(target))
}

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
    /// Interface descriptors are immutable once registered.
    #[error("interface id {0} is already registered")]
    DuplicateInterfaceId(InterfaceId),
    /// Driver id is already registered.
    #[error("driver id {0} is already registered")]
    DuplicateDriverId(DriverId),
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
struct GrantSelectorKey {
    /// Process that holds the grant.
    holder: ProcessId,
    /// Capability verb, such as `read` or `perform`.
    verb: String,
    /// Concrete path matched by an exact selector.
    path: Path,
}

/// The six control-plane registries. Behind a single lock for
/// simplicity; the data plane never touches this, so contention is confined to
/// the slow path.
#[derive(Default)]
struct RegistryInner {
    /// Present only for registries assembled into a Kernel.
    runtime_domain: Option<RuntimeDomain>,
    /// Registered resources keyed by compact id.
    resources: HashMap<ResourceId, Resource>,
    /// Registered interfaces keyed by compact id.
    interfaces: HashMap<InterfaceId, Interface>,
    /// Registered driver descriptors keyed by compact id.
    drivers: HashMap<DriverId, DriverDescriptor>,
    /// Registered remote endpoint transports keyed by compact id.
    endpoints: HashMap<EndpointId, DynRemoteEndpoint>,
    /// Generation of each live transport. Endpoint replacement does not change
    /// unrelated resources or grants, but must invalidate its own open plans.
    endpoint_epochs: HashMap<EndpointId, u64>,
    next_endpoint_epoch: u64,
    /// Registered bindings keyed by compact id.
    bindings: HashMap<BindingId, Binding>,
    /// Binding bundles whose creator permits automatic retirement on relink.
    reclaimable_bindings: HashSet<BindingId>,
    /// Registered grants keyed by grant id.
    grants: HashMap<GrantId, Grant>,
    /// Grant ids grouped by holder for slow-path grant scans.
    grants_by_holder: HashMap<ProcessId, Vec<GrantId>>,
    /// Exact, non-wildcard selector index for large grant sets.
    exact_grants: HashMap<GrantSelectorKey, Vec<GrantId>>,
    /// Wildcard selector fallback grant ids grouped by holder.
    wildcard_grants_by_holder: HashMap<ProcessId, Vec<GrantId>>,
    /// Source policies, consulted at `open()`. Held as trait
    /// objects so any `PolicySource` can register.
    policies: Vec<Arc<dyn crate::policy::PolicySource>>,
    /// Name → id index for resolution.
    names: HashMap<ResourceName, ResourceId>,
    /// Compiled open-plan cache. Cleared whenever control-plane
    /// descriptions change, so cached plans never survive a re-link/policy
    /// update/admission mutation.
    open_cache: OpenPlanCache,
    revision: u64,
    next_id: u64,
}

type RetiredBinding = (Binding, Option<DriverDescriptor>, Vec<Interface>);

#[derive(Clone)]
pub(crate) struct ResourceContract {
    binding: BindingId,
    interfaces: InterfaceSet,
}

impl ResourceContract {
    pub(crate) fn interface_count(&self) -> usize {
        self.interfaces.interfaces.len()
    }

    pub(crate) fn matches(&self, resource: &Resource) -> bool {
        self.binding == resource.binding && self.interfaces == resource.interfaces
    }
}

pub(crate) struct ResolvedMethod {
    pub contract: ResourceContract,
    pub index: u32,
    pub descriptor: Method,
}

impl RegistryInner {
    fn methods_in<'a>(
        &'a self,
        interfaces: &'a InterfaceSet,
    ) -> Option<impl Iterator<Item = &'a Method> + 'a> {
        // Admission keeps these references valid. Preserve the snapshot API's
        // `None` result if a caller supplies an interface set with a missing id.
        if interfaces
            .interfaces
            .iter()
            .any(|id| !self.interfaces.contains_key(id))
        {
            return None;
        }
        Some(interfaces.interfaces.iter().flat_map(|id| {
            self.interfaces
                .get(id)
                .into_iter()
                .flat_map(|interface| interface.methods.iter())
        }))
    }

    fn interface_methods(&self, interfaces: &InterfaceSet) -> Option<Vec<Method>> {
        Some(self.methods_in(interfaces)?.cloned().collect())
    }

    fn fresh_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn invalidate_open_cache(&mut self) -> RetiredOpenPlans {
        self.revision = self.revision.wrapping_add(1);
        self.open_cache.clear()
    }

    fn replace_endpoint_epoch(&mut self, id: EndpointId) {
        self.next_endpoint_epoch = self.next_endpoint_epoch.wrapping_add(1);
        self.endpoint_epochs.insert(id, self.next_endpoint_epoch);
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

    fn retire_unreferenced_binding(&mut self, id: BindingId) -> Option<RetiredBinding> {
        if self
            .resources
            .values()
            .any(|resource| resource.binding == id)
        {
            return None;
        }
        let binding = self.bindings.remove(&id)?;
        self.reclaimable_bindings.remove(&id);
        let driver_referenced = self
            .bindings
            .values()
            .any(|other| other.driver.id == binding.driver.id);
        let retired_driver = (!driver_referenced)
            .then(|| self.drivers.remove(&binding.driver.id))
            .flatten();
        let mut retired_interfaces = Vec::new();
        for interface_id in &binding.interfaces.interfaces {
            let referenced_by_resource = self
                .resources
                .values()
                .any(|resource| resource.interfaces.interfaces.contains(interface_id));
            let referenced_by_binding = self
                .bindings
                .values()
                .any(|other| other.interfaces.interfaces.contains(interface_id));
            let referenced_by_driver = self
                .drivers
                .values()
                .any(|driver| driver.implements.interfaces.contains(interface_id));
            if !referenced_by_resource
                && !referenced_by_binding
                && !referenced_by_driver
                && let Some(interface) = self.interfaces.remove(interface_id)
            {
                retired_interfaces.push(interface);
            }
        }
        Some((binding, retired_driver, retired_interfaces))
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

fn validate_resource_binding(
    inner: &RegistryInner,
    id: ResourceId,
    name: &ResourceName,
    interfaces: &InterfaceSet,
    binding_id: BindingId,
) -> Result<u64, AdmissionError> {
    validate_resource_name(name)?;
    let binding = inner
        .bindings
        .get(&binding_id)
        .ok_or(AdmissionError::BindingNotRegistered(binding_id))?;
    if !binding.interfaces.covers(interfaces) {
        return Err(AdmissionError::InterfacesNotCovered(binding_id, id));
    }
    validate_resource_methods(inner, interfaces, name.path())?;
    Ok(binding.generation)
}

/// Check a self-contained interface/driver/binding bundle before any of its
/// descriptions become visible. The caller holds the registry write lock.
fn validate_new_bundle(
    inner: &RegistryInner,
    interfaces: &[Interface],
    driver: &DriverDescriptor,
    binding: &Binding,
) -> Result<HashSet<InterfaceId>, AdmissionError> {
    let mut ids = HashSet::with_capacity(interfaces.len());
    for interface in interfaces {
        if !ids.insert(interface.id) || inner.interfaces.contains_key(&interface.id) {
            return Err(AdmissionError::DuplicateInterfaceId(interface.id));
        }
        validate_methods(interface.methods.iter(), None)?;
    }
    if inner.drivers.contains_key(&driver.id) {
        return Err(AdmissionError::DuplicateDriverId(driver.id));
    }
    if inner.bindings.contains_key(&binding.id) {
        return Err(AdmissionError::DuplicateBindingId(binding.id));
    }
    if binding.driver.id != driver.id
        || ids.len() != driver.implements.interfaces.len()
        || ids.len() != binding.interfaces.interfaces.len()
        || !driver
            .implements
            .interfaces
            .iter()
            .all(|id| ids.contains(id))
        || !binding
            .interfaces
            .interfaces
            .iter()
            .all(|id| ids.contains(id))
    {
        return Err(AdmissionError::Rejected(
            "reclaimable bundle interfaces or driver do not match".into(),
        ));
    }
    Ok(ids)
}

fn exact_selector_key(grant: &Grant) -> Option<GrantSelectorKey> {
    let pattern = &grant.selector.pattern;
    if pattern.verb == "*"
        || pattern.cluster.as_deref() == Some("*")
        || pattern.scheme == "*"
        || pattern.scheme == "**"
        || pattern
            .segments
            .iter()
            .any(|segment| segment.as_str() == "*" || segment.as_str() == "**")
    {
        return None;
    }

    let mut path = Path::try_new(pattern.scheme.as_str()).ok()?;
    if let Some(cluster) = &pattern.cluster {
        path = path.try_with_cluster(cluster.as_str()).ok()?;
    }
    for segment in &pattern.segments {
        path = path.try_push(segment.as_str()).ok()?;
    }
    Some(GrantSelectorKey {
        holder: grant.holder,
        verb: pattern.verb.clone(),
        path,
    })
}

fn target_selector_key(process: ProcessId, verb: &str, target: &Path) -> GrantSelectorKey {
    GrantSelectorKey {
        holder: process,
        verb: verb.to_string(),
        path: target.clone(),
    }
}

/// Visit candidate grants in the same order as the public discovery query.
/// The callback runs under the registry read lock; callers must keep it pure.
fn visit_candidate_grants<T>(
    inner: &RegistryInner,
    process: ProcessId,
    verb: &str,
    target: &Path,
    mut visit: impl FnMut(&Grant) -> Option<T>,
) -> Option<T> {
    let holder_ids = inner.grants_by_holder.get(&process)?;
    if holder_ids.len() <= SMALL_HOLDER_GRANT_SCAN_LIMIT {
        return holder_ids
            .iter()
            .filter_map(|id| inner.grants.get(id))
            .find_map(&mut visit);
    }
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
        .filter_map(|id| inner.grants.get(id))
        .find_map(visit)
}

/// Cache key for simple `open()` compilation. Grant expiry is checked before
/// lookup on every open; grants with constraints and any installed policy
/// source bypass this cache, so the compiled plan cannot depend on the clock.
/// Lookups and publication also check the registry revision.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OpenCacheKey {
    /// Grant selected by open.
    grant: GrantId,
    /// Resource being opened.
    resource: ResourceId,
    /// Concrete resource path used for selector and policy matching.
    resource_path: xolotl_types::Path,
    /// Capability verb requested by open.
    verb: String,
    /// Requested method bitmap bits.
    methods: u64,
    /// Requested right flag bits.
    flags: u32,
    /// Acting identity captured in the open context.
    acting: xolotl_types::IdentityRef,
}

impl OpenCacheKey {
    // Cache admission is an optimization only: large inputs still open, but
    // cannot turn a fixed entry count into unbounded duplicated key storage.
    const MAX_PATH_BYTES: usize = 1024;
    const MAX_VERB_BYTES: usize = 256;
    pub(crate) fn for_cache(
        grant: &Grant,
        resource: ResourceId,
        resource_path: &Path,
        verb: &str,
        rights: Rights,
        acting: xolotl_types::IdentityRef,
    ) -> Option<Self> {
        if resource_path.canonical_len()? > Self::MAX_PATH_BYTES
            || verb.len() > Self::MAX_VERB_BYTES
            || !grant.constraints.is_empty()
            || grant.selector.pattern.predicate.is_some()
        {
            return None;
        }
        Some(Self::new(
            grant.id,
            resource,
            resource_path.clone(),
            verb,
            rights,
            acting,
        ))
    }

    /// Build a key from the open context and requested rights.
    pub fn new(
        grant: GrantId,
        resource: ResourceId,
        resource_path: xolotl_types::Path,
        verb: impl Into<String>,
        rights: Rights,
        acting: xolotl_types::IdentityRef,
    ) -> Self {
        Self {
            grant,
            resource,
            resource_path,
            verb: verb.into(),
            methods: rights.methods.bits(),
            flags: rights.flags.bits(),
            acting,
        }
    }
}

/// Cached `open()` compile product before assigning a process-owned Handle
/// slot. The Handle itself is never cached because ownership and generation are
/// per open.
#[derive(Clone)]
pub(crate) struct CompiledOpenPlan {
    /// Resource id captured by the compiled plan.
    pub resource: ResourceId,
    /// Rights that will be copied into the handle.
    pub rights: Rights,
    /// Frozen driver dispatch plan.
    pub driver_plan: DriverPlan,
    /// Fast-path policy marker captured by open.
    pub fast_path: FastPath,
}

/// Dependencies that must still match when a compiled plan is published or
/// installed. The global revision covers descriptors, grants and policies;
/// endpoint replacements have a narrower generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpenRevision {
    global: u64,
    endpoint: Option<(EndpointId, u64)>,
}

impl OpenRevision {
    fn with_endpoint(mut self, id: EndpointId, epoch: u64) -> Self {
        self.endpoint = Some((id, epoch));
        self
    }
}

impl RegistryInner {
    fn matches_open_revision(&self, revision: OpenRevision) -> bool {
        self.revision == revision.global
            && revision
                .endpoint
                .is_none_or(|(id, epoch)| self.endpoint_epochs.get(&id).copied() == Some(epoch))
    }
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
    /// Opens that bypass cache admission are not counted.
    pub open_cache_misses: u64,
}

/// One resource declaration in an atomic batch of owned binding updates.
/// `new_id` is used only when the resource name is not registered yet.
pub struct ResourceUpsert {
    /// Id to assign if this name is new.
    pub new_id: ResourceId,
    /// The current descriptor to publish, including metadata.
    pub descriptor: ResourceDescriptor,
    /// Interfaces exposed by the new binding.
    pub interfaces: InterfaceSet,
    /// A previously admitted, reclaimable binding owned by the caller.
    pub binding: BindingId,
}

/// Shared, lockable registry handle.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<RegistryInner>>,
}

impl Registry {
    /// Create an empty shared registry with a cache of at most 1,024 open plans.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with a bounded FIFO cache of compiled opens. Zero
    /// disables this cache; already installed handles keep their frozen plans.
    /// Only registry-owned grants and bounded path/verb keys enter this cache.
    /// This does not limit memory retained by native driver or policy objects.
    pub fn with_open_cache_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RegistryInner {
                open_cache: OpenPlanCache::new(capacity),
                ..RegistryInner::default()
            })),
        }
    }

    pub(crate) fn with_runtime_domain(self, domain: RuntimeDomain) -> Self {
        self.inner.write().runtime_domain = Some(domain);
        self
    }

    pub(crate) fn runtime_domain(&self) -> Option<RuntimeDomain> {
        self.inner.read().runtime_domain.clone()
    }

    /// Maximum retained compiled opens. Eviction never revokes live handles.
    pub fn open_cache_capacity(&self) -> usize {
        self.inner.read().open_cache.capacity
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

    /// Register an immutable interface descriptor.
    ///
    /// Changing a contract requires a new interface id and a resource relink.
    pub fn register_interface(&self, iface: Interface) -> Result<(), AdmissionError> {
        let mut inner = self.inner.write();
        if inner.interfaces.contains_key(&iface.id) {
            return Err(AdmissionError::DuplicateInterfaceId(iface.id));
        }
        validate_methods(iface.methods.iter(), None)?;
        inner.interfaces.insert(iface.id, iface);
        let retired = inner.invalidate_open_cache();
        drop(inner);
        drop(retired);
        Ok(())
    }

    /// Register a new driver descriptor and invalidate cached open plans.
    /// An existing driver id cannot be replaced in place: bindings that use it
    /// must retain their admitted interface contract. Relink a resource through
    /// a new driver and binding to change its implementation.
    pub fn register_driver(&self, desc: DriverDescriptor) -> Result<(), AdmissionError> {
        let mut inner = self.inner.write();
        if inner.drivers.contains_key(&desc.id) {
            let id = desc.id;
            drop(inner);
            return Err(AdmissionError::DuplicateDriverId(id));
        }
        inner.drivers.insert(desc.id, desc);
        let retired = inner.invalidate_open_cache();
        drop(inner);
        drop(retired);
        Ok(())
    }

    /// Admit one caller-owned interface/driver/binding bundle atomically.
    /// Every interface in the bundle must be used by the driver and binding;
    /// this makes later retirement of the binding reclaim the whole bundle.
    pub fn admit_reclaimable_bundle(
        &self,
        interfaces: Vec<Interface>,
        driver: DriverDescriptor,
        binding: Binding,
    ) -> Result<BindingId, AdmissionError> {
        let mut inner = self.inner.write();
        if let Err(error) = validate_new_bundle(&inner, &interfaces, &driver, &binding) {
            // Native driver captures may run host code on Drop.
            drop(inner);
            return Err(error);
        }
        let binding_id = binding.id;
        for interface in interfaces {
            inner.interfaces.insert(interface.id, interface);
        }
        inner.drivers.insert(driver.id, driver);
        inner.bindings.insert(binding_id, binding);
        inner.reclaimable_bindings.insert(binding_id);
        Ok(binding_id)
    }

    /// Admit one complete Resource and its caller-owned descriptions atomically.
    /// No Interface, Driver or Binding is published when Resource admission
    /// fails. The bundle is reclaimable when the Resource is later relinked.
    pub fn admit_resource_bundle(
        &self,
        interfaces: Vec<Interface>,
        driver: DriverDescriptor,
        binding: Binding,
        resource: Resource,
        kernel_caller: bool,
    ) -> Result<ResourceId, AdmissionError> {
        self.publish_resource_bundle(interfaces, driver, binding, resource, kernel_caller, false)
    }

    /// Admit a complete Resource bundle, or atomically relink the named
    /// Resource to it. An existing Resource keeps its id and kind, and its
    /// binding generation cannot move backwards. Descriptions owned by the
    /// previous reclaimable binding are retired after publication.
    pub fn upsert_resource_bundle(
        &self,
        interfaces: Vec<Interface>,
        driver: DriverDescriptor,
        binding: Binding,
        resource: Resource,
        kernel_caller: bool,
    ) -> Result<ResourceId, AdmissionError> {
        self.publish_resource_bundle(interfaces, driver, binding, resource, kernel_caller, true)
    }

    fn publish_resource_bundle(
        &self,
        interfaces: Vec<Interface>,
        driver: DriverDescriptor,
        binding: Binding,
        mut resource: Resource,
        kernel_caller: bool,
        relink_existing: bool,
    ) -> Result<ResourceId, AdmissionError> {
        let mut inner = self.inner.write();
        let validation = (|| {
            let ids = validate_new_bundle(&inner, &interfaces, &driver, &binding)?;
            let name = &resource.descriptor.name;
            validate_resource_name(name)?;
            if !kernel_caller && xolotl_types::is_kernel_reserved(name.path()) {
                return Err(AdmissionError::ReservedPrefix(name.path().to_string()));
            }
            let existing_id = inner.names.get(name).copied();
            if inner.resources.contains_key(&resource.id) && existing_id != Some(resource.id) {
                return Err(AdmissionError::DuplicateResourceId(resource.id));
            }
            if existing_id.is_some() && !relink_existing {
                return Err(AdmissionError::DuplicateResourceName(
                    name.path().to_string(),
                ));
            }
            let old_binding = if let Some(id) = existing_id {
                let existing = inner.resources.get(&id).ok_or_else(|| {
                    AdmissionError::ResourceNotRegistered(name.path().to_string())
                })?;
                if existing.descriptor.kind != resource.descriptor.kind {
                    return Err(AdmissionError::Rejected(format!(
                        "resource {} kind cannot change on relink",
                        name.path()
                    )));
                }
                if existing.descriptor.addressing != resource.descriptor.addressing {
                    return Err(AdmissionError::Rejected(format!(
                        "resource {} addressing cannot change on relink",
                        name.path()
                    )));
                }
                let current = inner
                    .bindings
                    .get(&existing.binding)
                    .ok_or(AdmissionError::BindingNotRegistered(existing.binding))?
                    .generation;
                if binding.generation < current {
                    return Err(AdmissionError::BindingGenerationRegressed {
                        resource: name.path().to_string(),
                        current,
                        attempted: binding.generation,
                    });
                }
                Some(existing.binding)
            } else {
                None
            };
            if resource.binding != binding.id {
                return Err(AdmissionError::BindingNotRegistered(resource.binding));
            }
            if !binding.interfaces.covers(&resource.interfaces) {
                return Err(AdmissionError::InterfacesNotCovered(
                    binding.id,
                    resource.id,
                ));
            }
            if resource
                .interfaces
                .interfaces
                .iter()
                .any(|id| !ids.contains(id))
            {
                return Err(AdmissionError::Rejected(
                    "resource interface is not in its bundle".into(),
                ));
            }
            let methods = resource.interfaces.interfaces.iter().flat_map(|id| {
                interfaces
                    .iter()
                    .filter(move |interface| interface.id == *id)
                    .flat_map(|interface| interface.methods.iter())
            });
            validate_methods(methods, Some(name.path()))?;
            Ok((existing_id.unwrap_or(resource.id), old_binding))
        })();
        let (id, old_binding) = match validation {
            Ok(validated) => validated,
            Err(error) => {
                // The failed bundle, including its native driver, drops after the lock.
                drop(inner);
                return Err(error);
            }
        };

        resource.id = id;
        if old_binding.is_none() {
            inner.names.insert(resource.descriptor.name.clone(), id);
        }
        for interface in interfaces {
            inner.interfaces.insert(interface.id, interface);
        }
        inner.drivers.insert(driver.id, driver);
        inner.reclaimable_bindings.insert(binding.id);
        inner.bindings.insert(binding.id, binding);
        inner.resources.insert(id, resource);
        let retired_plans = inner.invalidate_open_cache();
        let retired_binding = old_binding
            .filter(|old| inner.reclaimable_bindings.contains(old))
            .and_then(|old| inner.retire_unreferenced_binding(old));
        drop(inner);
        drop((retired_plans, retired_binding));
        Ok(id)
    }

    /// Register or replace a remote endpoint transport. Bindings with
    /// `endpoint = Some(id)` compile to RPC stubs backed by this entry.
    pub fn register_endpoint(&self, id: EndpointId, endpoint: DynRemoteEndpoint) {
        let mut inner = self.inner.write();
        let previous = inner.endpoints.insert(id, endpoint);
        inner.replace_endpoint_epoch(id);
        let retired = inner.open_cache.remove_endpoint(id);
        drop(inner);
        drop((previous, retired));
    }

    /// Remove a live remote endpoint transport and invalidate cached open
    /// plans that may reference it.
    pub fn unregister_endpoint(&self, id: EndpointId) -> bool {
        let mut inner = self.inner.write();
        let removed = inner.endpoints.remove(&id);
        let changed = removed.is_some();
        let retired = changed.then(|| {
            inner.endpoint_epochs.remove(&id);
            inner.open_cache.remove_endpoint(id)
        });
        drop(inner);
        drop((removed, retired));
        changed
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
        validate_resource_binding(
            &inner,
            resource.id,
            &name,
            &resource.interfaces,
            resource.binding,
        )?;
        let id = resource.id;
        inner.names.insert(name, id);
        inner.resources.insert(id, resource);
        let retired = inner.invalidate_open_cache();
        drop(inner);
        drop(retired);
        Ok(id)
    }

    /// Publish several owned binding changes as one registry transaction.
    /// New names are admitted; existing names keep their Resource id and kind
    /// while their interfaces, binding, and metadata are replaced. Validation
    /// of the entire batch precedes any Resource change. Previous bindings
    /// admitted as reclaimable are retired once no current Resource uses them.
    ///
    /// The caller must retire the staged bindings if this method fails. Already
    /// opened Handles keep their frozen plans; retired drivers drop outside
    /// the registry lock.
    pub fn upsert_reclaimable_resources(
        &self,
        upserts: Vec<ResourceUpsert>,
        kernel_caller: bool,
    ) -> Result<Vec<ResourceId>, AdmissionError> {
        if upserts.is_empty() {
            return Ok(Vec::new());
        }
        let mut inner = self.inner.write();
        let mut names = HashSet::with_capacity(upserts.len());
        let mut new_ids = HashSet::with_capacity(upserts.len());
        for upsert in &upserts {
            let name = &upsert.descriptor.name;
            if !names.insert(name) {
                return Err(AdmissionError::DuplicateResourceName(
                    name.path().to_string(),
                ));
            }
            if !kernel_caller && xolotl_types::is_kernel_reserved(name.path()) {
                return Err(AdmissionError::ReservedPrefix(name.path().to_string()));
            }
            if !inner.reclaimable_bindings.contains(&upsert.binding) {
                return Err(AdmissionError::Rejected(format!(
                    "binding {} is not reclaimable",
                    upsert.binding
                )));
            }
            let id = inner.names.get(name).copied().unwrap_or(upsert.new_id);
            let generation =
                validate_resource_binding(&inner, id, name, &upsert.interfaces, upsert.binding)?;
            if let Some(existing) = inner.resources.get(&id) {
                if existing.descriptor.name != *name {
                    return Err(AdmissionError::DuplicateResourceId(id));
                }
                if existing.descriptor.kind != upsert.descriptor.kind {
                    return Err(AdmissionError::Rejected(format!(
                        "resource {} kind cannot change on relink",
                        name.path()
                    )));
                }
                if existing.descriptor.addressing != upsert.descriptor.addressing {
                    return Err(AdmissionError::Rejected(format!(
                        "resource {} addressing cannot change on relink",
                        name.path()
                    )));
                }
                let current = inner
                    .bindings
                    .get(&existing.binding)
                    .ok_or(AdmissionError::BindingNotRegistered(existing.binding))?
                    .generation;
                if generation < current {
                    return Err(AdmissionError::BindingGenerationRegressed {
                        resource: name.path().to_string(),
                        current,
                        attempted: generation,
                    });
                }
            } else if !new_ids.insert(id) {
                return Err(AdmissionError::DuplicateResourceId(id));
            }
        }

        let mut ids = Vec::with_capacity(upserts.len());
        let mut old_bindings = HashSet::with_capacity(upserts.len());
        for upsert in upserts {
            let name = upsert.descriptor.name.clone();
            let id = inner.names.get(&name).copied().unwrap_or(upsert.new_id);
            if let Some(previous) = inner.resources.insert(
                id,
                Resource {
                    id,
                    descriptor: upsert.descriptor,
                    interfaces: upsert.interfaces,
                    binding: upsert.binding,
                },
            ) {
                old_bindings.insert(previous.binding);
            }
            inner.names.entry(name).or_insert(id);
            ids.push(id);
        }
        let retired_plans = inner.invalidate_open_cache();
        let mut retired_bindings = Vec::new();
        for id in old_bindings {
            if inner.reclaimable_bindings.contains(&id)
                && let Some(retired) = inner.retire_unreferenced_binding(id)
            {
                retired_bindings.push(retired);
            }
        }
        drop(inner);
        drop((retired_plans, retired_bindings));
        Ok(ids)
    }

    /// Withdraw a host-owned resource only if its current registration still
    /// matches the caller's publication. Previously opened Handles retain
    /// their frozen plans; this prevents new opens and retires descriptions
    /// that no remaining resource uses.
    pub fn remove_reclaimable_resource_if(
        &self,
        name: &ResourceName,
        expected_resource: ResourceId,
        expected_binding: BindingId,
    ) -> Result<bool, AdmissionError> {
        let mut inner = self.inner.write();
        let Some(id) = inner.names.get(name).copied() else {
            return Ok(false);
        };
        let resource = inner.resources.get(&id).ok_or_else(|| {
            AdmissionError::Rejected(format!("resource {} has no registration", name.path()))
        })?;
        if id != expected_resource
            || resource.binding != expected_binding
            || !inner.reclaimable_bindings.contains(&expected_binding)
        {
            return Err(AdmissionError::Rejected(format!(
                "resource {} publication ownership changed",
                name.path()
            )));
        }
        inner.names.remove(name);
        let removed = inner.resources.remove(&id);
        let retired_plans = inner.invalidate_open_cache();
        let retired_binding = inner.retire_unreferenced_binding(expected_binding);
        drop(inner);
        drop((removed, retired_plans, retired_binding));
        Ok(true)
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
        self.relink_resource_inner(name, interfaces, binding, None, false, None)
    }

    /// Relink a Resource, replace its metadata, and retire its actual previous
    /// binding generation in the same registry transaction when it was admitted
    /// as reclaimable.
    /// Ordinary manually admitted bindings remain independently reusable.
    /// Descriptions still referenced by another current registration remain.
    /// Native driver captures are destroyed after releasing the registry lock.
    pub fn relink_resource_retiring_previous(
        &self,
        name: &ResourceName,
        interfaces: InterfaceSet,
        binding: BindingId,
        metadata: Metadata,
    ) -> Result<ResourceId, AdmissionError> {
        self.relink_resource_inner(name, interfaces, binding, Some(metadata), true, None)
    }

    /// Relink a host publication only while the resource still has the exact
    /// id and binding previously published by that host. The ownership check,
    /// link change, and old-binding retirement share one registry transaction.
    pub fn relink_reclaimable_resource_if(
        &self,
        name: &ResourceName,
        expected_resource: ResourceId,
        expected_binding: BindingId,
        interfaces: InterfaceSet,
        binding: BindingId,
        metadata: Metadata,
    ) -> Result<ResourceId, AdmissionError> {
        self.relink_resource_inner(
            name,
            interfaces,
            binding,
            Some(metadata),
            true,
            Some((expected_resource, expected_binding)),
        )
    }

    fn relink_resource_inner(
        &self,
        name: &ResourceName,
        interfaces: InterfaceSet,
        binding: BindingId,
        metadata: Option<Metadata>,
        retire_previous: bool,
        expected_publication: Option<(ResourceId, BindingId)>,
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
        if let Some(expected) = expected_publication
            && (expected != (id, old_binding_id)
                || !inner.reclaimable_bindings.contains(&old_binding_id)
                || !inner.reclaimable_bindings.contains(&binding))
        {
            return Err(AdmissionError::Rejected(format!(
                "resource {} publication ownership changed",
                name.path()
            )));
        }
        let old_generation = inner
            .bindings
            .get(&old_binding_id)
            .ok_or(AdmissionError::BindingNotRegistered(old_binding_id))?
            .generation;
        let new_generation = validate_resource_binding(&inner, id, name, &interfaces, binding)?;
        if new_generation < old_generation {
            return Err(AdmissionError::BindingGenerationRegressed {
                resource: name.path().to_string(),
                current: old_generation,
                attempted: new_generation,
            });
        }
        let resource = inner
            .resources
            .get_mut(&id)
            .ok_or_else(|| AdmissionError::ResourceNotRegistered(name.path().to_string()))?;
        resource.interfaces = interfaces;
        resource.binding = binding;
        if let Some(metadata) = metadata {
            resource.descriptor.metadata = metadata;
        }
        let retired_plans = inner.invalidate_open_cache();
        let retired_binding = (retire_previous
            && inner.reclaimable_bindings.contains(&old_binding_id))
        .then(|| inner.retire_unreferenced_binding(old_binding_id))
        .flatten();
        drop(inner);
        drop((retired_plans, retired_binding));
        Ok(id)
    }

    /// Retire a binding generation that the caller owns after replacing its
    /// resource link. A binding still used by any resource is never removed.
    /// Its driver and interfaces are removed only when no other registered
    /// binding or resource uses them. Already opened handles retain their
    /// frozen dispatch plans independently of these descriptions.
    ///
    /// Call this only when no future registration will reuse the retired ids.
    /// Ordinary [`Self::relink_resource`] leaves independently registered
    /// descriptions available for deliberate reuse.
    /// Returns `false` when the binding is missing or still in use.
    pub fn retire_unreferenced_binding(&self, id: BindingId) -> bool {
        let retired = {
            let mut inner = self.inner.write();
            inner.retire_unreferenced_binding(id)
        };
        let removed = retired.is_some();
        // A native driver may run host code from Drop, so release every retired
        // descriptor only after the registry lock is gone.
        drop(retired);
        removed
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
        self.admit_binding_inner(binding, false)
    }

    /// Admit a fresh binding bundle that may be retired automatically when its
    /// Resource is relinked through [`Self::relink_resource_retiring_previous`].
    /// The caller owns this binding's driver and interface ids and will not
    /// reuse them after retirement. Shared live references prevent collection.
    pub fn admit_reclaimable_binding(&self, binding: Binding) -> Result<BindingId, AdmissionError> {
        self.admit_binding_inner(binding, true)
    }

    fn admit_binding_inner(
        &self,
        binding: Binding,
        reclaimable: bool,
    ) -> Result<BindingId, AdmissionError> {
        let mut inner = self.inner.write();
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
        let id = binding.id;
        inner.bindings.insert(id, binding);
        if reclaimable {
            inner.reclaimable_bindings.insert(id);
        }
        let retired = inner.invalidate_open_cache();
        drop(inner);
        drop(retired);
        Ok(id)
    }

    /// Register a binding without admission checks for crate-local fixtures.
    #[cfg(test)]
    pub(crate) fn register_binding(&self, binding: Binding) {
        let mut inner = self.inner.write();
        inner.bindings.insert(binding.id, binding);
        let retired = inner.invalidate_open_cache();
        drop(inner);
        drop(retired);
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
        let old = inner.grants.remove(&id);
        if let Some(old) = &old {
            inner.unindex_grant(id, old);
        }
        inner.index_grant(id, &grant);
        inner.grants.insert(id, grant);
        let retired = inner.invalidate_open_cache();
        drop(inner);
        drop((old, retired));
        id
    }

    /// Register a source policy. Consulted at every `open()` whose
    /// resource the policy applies to.
    pub fn register_policy(&self, policy: Arc<dyn crate::policy::PolicySource>) {
        let mut inner = self.inner.write();
        inner.policies.push(policy);
        let retired = inner.invalidate_open_cache();
        drop(inner);
        drop(retired);
    }

    /// Snapshot of the registered source policies (slow-path, called by
    /// `open()` to compile the residual).
    pub fn policies(&self) -> Vec<Arc<dyn crate::policy::PolicySource>> {
        self.inner.read().policies.clone()
    }

    // Name resolution.

    /// Resolve a control-plane resource name to a resource id.
    ///
    /// Exact registrations match only their own name. Prefix registrations
    /// also resolve descendants; the nearest registered prefix wins within
    /// the same scheme and cluster. Path semantics do not depend on scheme.
    pub fn resolve_resource(&self, name: &ResourceName) -> Result<ResourceId, ResolveError> {
        let inner = self.inner.read();
        // An explicit registration always outranks an ancestor prefix.
        if let Some(id) = inner.names.get(name).copied() {
            return Ok(id);
        }
        let target = name.path();
        // Path::pop_segment preserves scheme and cluster. Only an ancestor
        // explicitly installed as a collection may handle this concrete path.
        let mut ancestor = target.clone();
        while ancestor.pop_segment() {
            if let Some(id) = inner.names.get(&ancestor).copied()
                && inner.resources.get(&id).is_some_and(|resource| {
                    resource.descriptor.addressing == xolotl_types::ResourceAddressing::Prefix
                })
            {
                return Ok(id);
            }
        }
        Err(ResolveError::NoSuchResource(name.path().to_string()))
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

    /// Owned candidate-grant snapshot for discovery. Opening selects inside
    /// the registry and copies only its chosen grant. Exact selectors use
    /// `(holder, verb, path)`; wildcard selectors stay in a per-holder fallback.
    pub fn candidate_grants(&self, process: ProcessId, verb: &str, target: &Path) -> Vec<Grant> {
        let inner = self.inner.read();
        let mut candidates = Vec::new();
        visit_candidate_grants(&inner, process, verb, target, |grant| {
            candidates.push(grant.clone());
            None::<()>
        });
        candidates
    }

    /// Select registered grants that can contribute either requested right domain.
    /// Method and propagation candidates are compiled independently at open;
    /// a flag-only grant must never contribute callable method authority.
    pub(crate) fn select_open_grants(
        &self,
        process: ProcessId,
        verb: &str,
        target: &Path,
        rights: Rights,
        methods: &[Method],
        now_millis: i64,
    ) -> (Vec<Grant>, bool, bool) {
        let inner = self.inner.read();
        let cache_allowed = inner.policies.is_empty() && inner.open_cache.capacity > 0;
        let mut selector_matched = false;
        let mut selected = Vec::new();
        visit_candidate_grants(&inner, process, verb, target, |grant| {
            if grant.holder != process
                || grant.expires.is_expired(now_millis)
                || !grant.selector.matches(verb, target)
            {
                return None;
            }
            selector_matched = true;
            let methods = !rights.methods.is_empty()
                && grant.rights.methods.covers_bitmap(rights.methods, methods);
            let flags = !rights.flags.is_empty() && grant.rights.flags.contains(rights.flags);
            if methods || flags || rights == Rights::default() {
                selected.push(grant.clone());
            }
            None::<()>
        });
        (selected, selector_matched, cache_allowed)
    }

    /// Snapshot methods in resource-wide bitmap order.
    ///
    /// Interfaces are concatenated in the resource's declared order. Admission
    /// rejects duplicate names/ids and more than 64 methods across that set.
    pub fn resource_methods(&self, resource: ResourceId) -> Option<Vec<Method>> {
        let inner = self.inner.read();
        let resource = inner.resources.get(&resource)?;
        inner.interface_methods(&resource.interfaces)
    }

    /// Resolve the immutable interfaces of an already captured resource.
    /// Opening must not combine an old binding with a concurrently relinked
    /// resource's new method table.
    pub(crate) fn interface_methods(&self, interfaces: &InterfaceSet) -> Option<Vec<Method>> {
        self.inner.read().interface_methods(interfaces)
    }

    /// Resolve a method by name with its resource-wide rights bit.
    pub fn resource_method(&self, resource: ResourceId, name: &str) -> Option<(u32, Method)> {
        self.resolve_method_contract(resource, name)
            .map(|resolved| (resolved.index, resolved.descriptor))
    }

    pub(crate) fn resolve_method_contract(
        &self,
        resource: ResourceId,
        name: &str,
    ) -> Option<ResolvedMethod> {
        let inner = self.inner.read();
        let resource = inner.resources.get(&resource)?;
        let (index, descriptor) = inner
            .methods_in(&resource.interfaces)?
            .enumerate()
            .find(|(_, method)| method.name == name)?;
        Some(ResolvedMethod {
            contract: ResourceContract {
                binding: resource.binding,
                interfaces: resource.interfaces.clone(),
            },
            index: index as u32,
            descriptor: descriptor.clone(),
        })
    }

    /// Methods whose declared capability category exactly matches `verb`.
    ///
    /// A wildcard grant can cover any concrete verb, but opening a handle
    /// always names one concrete category. `perform` does not include others.
    pub fn method_bitmap_for_verb(&self, resource: ResourceId, verb: &str) -> MethodBitmap {
        let inner = self.inner.read();
        let Some(resource) = inner.resources.get(&resource) else {
            return MethodBitmap::empty();
        };
        let Some(methods) = inner.methods_in(&resource.interfaces) else {
            return MethodBitmap::empty();
        };
        methods
            .enumerate()
            .filter(|(_, method)| method.authority.verb() == verb)
            .fold(MethodBitmap::empty(), |bitmap, (index, _)| {
                bitmap | MethodBitmap::method(index as u32)
            })
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
            open_cache_hits: inner.open_cache.hits,
            open_cache_misses: inner.open_cache.misses,
        }
    }

    /// Current control-plane revision for an open compilation attempt.
    pub(crate) fn revision(&self) -> OpenRevision {
        OpenRevision {
            global: self.inner.read().revision,
            endpoint: None,
        }
    }

    /// Capture the endpoint and its generation in the same registry read.
    pub(crate) fn remote_endpoint_with_revision(
        &self,
        id: EndpointId,
        revision: OpenRevision,
    ) -> Option<(DynRemoteEndpoint, OpenRevision)> {
        let inner = self.inner.read();
        let endpoint = inner.endpoints.get(&id)?.clone();
        let epoch = *inner.endpoint_epochs.get(&id)?;
        Some((endpoint, revision.with_endpoint(id, epoch)))
    }

    /// Run only kernel slot installation under this guard; never host callbacks.
    pub(crate) fn with_open_revision<T>(
        &self,
        revision: OpenRevision,
        install: impl FnOnce() -> T,
    ) -> Option<T> {
        let inner = self.inner.read();
        if !inner.matches_open_revision(revision) {
            drop(inner);
            return None;
        }
        Some(install())
    }

    /// Look up a compiled open plan from the same control-plane revision.
    pub(crate) fn cached_open_plan(
        &self,
        key: &OpenCacheKey,
        revision: OpenRevision,
    ) -> Option<(CompiledOpenPlan, OpenRevision)> {
        let mut inner = self.inner.write();
        if !inner.matches_open_revision(revision) || !inner.policies.is_empty() {
            return None;
        }
        let plan = inner.open_cache.get(key)?;
        let revision = if let Some(id) = plan.driver_plan.endpoint {
            revision.with_endpoint(id, *inner.endpoint_epochs.get(&id)?)
        } else {
            revision
        };
        Some((plan, revision))
    }

    /// Validate the revision, then publish a cacheable plan if a key is given.
    /// Attached grants and oversized keys omit it; those opens still need the
    /// same revision check before returning a prepared plan.
    pub(crate) fn publish_open_plan(
        &self,
        key: Option<OpenCacheKey>,
        plan: &CompiledOpenPlan,
        revision: OpenRevision,
    ) -> bool {
        let mut inner = self.inner.write();
        if !inner.matches_open_revision(revision) {
            return false;
        }
        let retired = if let Some(key) =
            key.filter(|_| inner.open_cache.capacity > 0 && inner.policies.is_empty())
        {
            inner.open_cache.insert(key, plan.clone())
        } else {
            None
        };
        drop(inner);
        drop(retired);
        true
    }

    /// Return `(hits, misses, entries)` for eligible cache lookups. Opens that
    /// bypass cache admission do not increment either counter.
    pub fn open_cache_stats(&self) -> (u64, u64, usize) {
        let inner = self.inner.read();
        (
            inner.open_cache.hits,
            inner.open_cache.misses,
            inner.open_cache.len(),
        )
    }
}

#[cfg(test)]
mod cache_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use std::sync::{
        Weak,
        atomic::{AtomicBool, Ordering},
    };
    use xolotl_types::{
        ConstraintSet, Expiry, InterfaceSet, Metadata, Path, ResourceAddressing,
        ResourceDescriptor, ResourceKind, ResourceSelector, RightFlags,
    };

    #[test]
    fn concurrent_binding_admission_cannot_overwrite_an_admitted_contract() -> anyhow::Result<()> {
        let registry = Registry::new();
        let driver = registry.next_driver_id();
        registry.register_driver(DriverDescriptor {
            id: driver,
            name: "binding-admission".into(),
            implements: InterfaceSet::default(),
            transport: xolotl_types::Transport::InProcess,
            driver: Arc::new(crate::driver::EchoDriver),
        })?;
        let binding = Binding {
            id: registry.next_binding_id(),
            selector: ResourceSelector::all(),
            interfaces: InterfaceSet::default(),
            driver: xolotl_types::DriverRef {
                id: driver,
                name: "binding-admission".into(),
            },
            endpoint: None,
            generation: 1,
        };
        let start = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        registry.admit_binding(binding.clone())
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker.join().map_err(|payload| {
                        anyhow::Error::msg(crate::bootstrap::panic_payload_message(
                            "binding admission",
                            payload,
                        ))
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })?;
        ensure!(results.iter().filter(|result| result.is_ok()).count() == 1);
        for result in results {
            ensure!(
                matches!(result, Ok(id) | Err(AdmissionError::DuplicateBindingId(id)) if id == binding.id)
            );
        }
        ensure!(registry.counts().bindings == 1);
        Ok(())
    }

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

    fn register_owned_binding(
        reg: &Registry,
        generation: u64,
        implementation: DynDriver,
    ) -> anyhow::Result<(InterfaceId, DriverId, BindingId)> {
        let interface = reg.next_interface_id();
        reg.register_interface(Interface {
            id: interface,
            family: xolotl_types::InterfaceFamily::Callable,
            methods: Vec::new(),
            laws: Vec::new(),
        })?;
        let interfaces = InterfaceSet::new(vec![interface]);
        let driver = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver,
            name: "owned-generation".into(),
            implements: interfaces.clone(),
            transport: xolotl_types::Transport::InProcess,
            driver: implementation,
        })?;
        let binding = reg.next_binding_id();
        reg.admit_reclaimable_binding(Binding {
            id: binding,
            selector: ResourceSelector::parse("perform://effect/**")?,
            interfaces,
            driver: xolotl_types::DriverRef {
                id: driver,
                name: "owned-generation".into(),
            },
            endpoint: None,
            generation,
        })?;
        Ok((interface, driver, binding))
    }

    fn owned_binding(
        reg: &Registry,
        generation: u64,
    ) -> anyhow::Result<(
        InterfaceId,
        DriverId,
        BindingId,
        Weak<crate::driver::EchoDriver>,
    )> {
        let implementation = Arc::new(crate::driver::EchoDriver);
        let weak = Arc::downgrade(&implementation);
        let (interface, driver, binding) = register_owned_binding(reg, generation, implementation)?;
        Ok((interface, driver, binding, weak))
    }

    #[test]
    fn duplicate_driver_id_cannot_replace_a_live_resource_binding() -> anyhow::Result<()> {
        let registry = Registry::new();
        let (interface, driver, binding, original) = owned_binding(&registry, 1)?;
        let resource_name = name("effect://owned/driver-replacement")?;
        let resource = registry.next_resource_id();
        registry.admit_resource(
            Resource {
                id: resource,
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![interface]),
                binding,
            },
            false,
        )?;

        let result = registry.register_driver(DriverDescriptor {
            id: driver,
            name: "replacement".into(),
            implements: InterfaceSet::default(),
            transport: xolotl_types::Transport::InProcess,
            driver: Arc::new(crate::driver::EchoDriver),
        });
        ensure!(matches!(
            result,
            Err(AdmissionError::DuplicateDriverId(id)) if id == driver
        ));
        let retained = registry.driver(driver).context("original driver")?;
        ensure!(retained.name == "owned-generation");
        ensure!(retained.implements == InterfaceSet::new(vec![interface]));
        ensure!(original.upgrade().is_some());
        ensure!(registry.resource(resource).context("resource")?.binding == binding);
        ensure!(registry.resource_binding_generation(&resource_name)? == 1);
        Ok(())
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
                addressing: Default::default(),
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
                addressing: Default::default(),
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
                addressing: Default::default(),
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
                    addressing: Default::default(),
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
    fn explicit_retirement_bounds_repeated_owned_relinks() -> anyhow::Result<()> {
        let reg = Registry::new();
        let resource_name = name("effect://owned/relink")?;
        let (mut old_interface, mut old_driver, mut old_binding, mut old_implementation) =
            owned_binding(&reg, 1)?;
        let resource = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: resource,
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![old_interface]),
                binding: old_binding,
            },
            false,
        )?;
        ensure!(!reg.retire_unreferenced_binding(old_binding));

        for generation in 2..=64 {
            let (interface, driver, binding, implementation) = owned_binding(&reg, generation)?;
            ensure!(
                reg.relink_resource_retiring_previous(
                    &resource_name,
                    InterfaceSet::new(vec![interface]),
                    binding,
                    Metadata::default(),
                )? == resource
            );
            ensure!(!reg.retire_unreferenced_binding(old_binding));
            ensure!(reg.binding(old_binding).is_none());
            ensure!(reg.driver(old_driver).is_none());
            ensure!(reg.interface(old_interface).is_none());
            ensure!(old_implementation.upgrade().is_none());
            let counts = reg.counts();
            ensure!(
                (
                    counts.resources,
                    counts.interfaces,
                    counts.drivers,
                    counts.bindings
                ) == (1, 1, 1, 1),
                "relink {generation} retained old descriptions: {counts:?}"
            );
            (old_interface, old_driver, old_binding, old_implementation) =
                (interface, driver, binding, implementation);
        }
        Ok(())
    }

    #[test]
    fn owned_relink_does_not_retire_an_independently_registered_old_binding() -> anyhow::Result<()>
    {
        let reg = Registry::new();
        let old = empty_binding(&reg, 1)?;
        let resource_name = name("effect://manual/then-owned")?;
        reg.admit_resource(
            Resource {
                id: reg.next_resource_id(),
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::default(),
                binding: old,
            },
            false,
        )?;

        let (next_interface, _, next, _) = owned_binding(&reg, 2)?;
        reg.relink_resource_retiring_previous(
            &resource_name,
            InterfaceSet::new(vec![next_interface]),
            next,
            Metadata::default(),
        )?;
        ensure!(reg.binding(old).is_some());
        Ok(())
    }

    #[test]
    fn retiring_one_binding_keeps_descriptions_shared_by_another() -> anyhow::Result<()> {
        let reg = Registry::new();
        let resource_name = name("effect://owned/shared")?;
        let (interface, driver, first, implementation) = owned_binding(&reg, 1)?;
        reg.admit_resource(
            Resource {
                id: reg.next_resource_id(),
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![interface]),
                binding: first,
            },
            false,
        )?;
        let second = reg.next_binding_id();
        reg.admit_binding(Binding {
            id: second,
            selector: ResourceSelector::parse("perform://effect/**")?,
            interfaces: InterfaceSet::new(vec![interface]),
            driver: xolotl_types::DriverRef {
                id: driver,
                name: "shared".into(),
            },
            endpoint: None,
            generation: 2,
        })?;
        reg.relink_resource(&resource_name, InterfaceSet::new(vec![interface]), second)?;
        ensure!(reg.retire_unreferenced_binding(first));
        ensure!(reg.interface(interface).is_some());
        ensure!(reg.driver(driver).is_some());
        ensure!(implementation.upgrade().is_some());

        let (third_interface, _, third, _) = owned_binding(&reg, 3)?;
        reg.relink_resource(
            &resource_name,
            InterfaceSet::new(vec![third_interface]),
            third,
        )?;
        ensure!(reg.retire_unreferenced_binding(second));
        ensure!(reg.interface(interface).is_none());
        ensure!(reg.driver(driver).is_none());
        ensure!(implementation.upgrade().is_none());
        Ok(())
    }

    #[test]
    fn withdrawal_requires_current_publication_and_releases_owned_descriptions()
    -> anyhow::Result<()> {
        let reg = Registry::new();
        let resource_name = name("effect://external-source/chat/inbox/command")?;
        let (interface, driver, binding, implementation) = owned_binding(&reg, 1)?;
        let resource_id = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: resource_id,
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![interface]),
                binding,
            },
            false,
        )?;
        ensure!(
            reg.remove_reclaimable_resource_if(&resource_name, ResourceId::new(0), binding)
                .is_err()
        );
        ensure!(
            reg.remove_reclaimable_resource_if(&resource_name, resource_id, BindingId::new(0))
                .is_err()
        );
        ensure!(reg.resolve_resource(&resource_name)? == resource_id);
        ensure!(reg.remove_reclaimable_resource_if(&resource_name, resource_id, binding)?);
        ensure!(reg.resolve_resource(&resource_name).is_err());
        ensure!(reg.resource(resource_id).is_none());
        ensure!(reg.binding(binding).is_none());
        ensure!(reg.interface(interface).is_none());
        ensure!(reg.driver(driver).is_none());
        ensure!(implementation.upgrade().is_none());
        ensure!(!reg.remove_reclaimable_resource_if(&resource_name, resource_id, binding)?);
        Ok(())
    }

    #[test]
    fn conditional_relink_cannot_replace_another_publication() -> anyhow::Result<()> {
        let reg = Registry::new();
        let resource_name = name("effect://external-source/chat/inbox/command")?;
        let (interface, _, first, _) = owned_binding(&reg, 1)?;
        let resource_id = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: resource_id,
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![interface]),
                binding: first,
            },
            false,
        )?;
        let (next_interface, _, next, _) = owned_binding(&reg, 2)?;
        let next_interfaces = InterfaceSet::new(vec![next_interface]);
        ensure!(
            reg.relink_reclaimable_resource_if(
                &resource_name,
                ResourceId::new(0),
                first,
                next_interfaces.clone(),
                next,
                Metadata::default(),
            )
            .is_err()
        );
        ensure!(reg.resource(resource_id).context("resource")?.binding == first);
        ensure!(
            reg.relink_reclaimable_resource_if(
                &resource_name,
                resource_id,
                first,
                next_interfaces,
                next,
                Metadata::default(),
            )? == resource_id
        );
        ensure!(
            reg.resource(resource_id)
                .context("relinked resource")?
                .binding
                == next
        );
        ensure!(reg.binding(first).is_none());
        ensure!(
            reg.relink_reclaimable_resource_if(
                &resource_name,
                resource_id,
                first,
                InterfaceSet::default(),
                first,
                Metadata::default(),
            )
            .is_err()
        );
        Ok(())
    }

    struct LockCheckingDriver {
        registry: Weak<RwLock<RegistryInner>>,
        released: Arc<AtomicBool>,
        unlocked: Arc<AtomicBool>,
    }

    impl Drop for LockCheckingDriver {
        fn drop(&mut self) {
            self.unlocked.store(
                self.registry
                    .upgrade()
                    .is_some_and(|registry| registry.try_write().is_some()),
                Ordering::SeqCst,
            );
            self.released.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl crate::driver::Driver for LockCheckingDriver {
        async fn call(
            &self,
            _method: xolotl_types::MethodId,
            input: xolotl_types::Value,
            _output: xolotl_types::OutputMode,
            _ctx: &crate::driver::DriverContext,
        ) -> Result<crate::driver::DriverOutput, crate::driver::DriverError> {
            Ok(crate::driver::DriverOutput::new(
                xolotl_types::Outcome::Done(input),
            ))
        }
    }

    #[test]
    fn retired_driver_drops_outside_registry_lock() -> anyhow::Result<()> {
        let reg = Registry::new();
        let released = Arc::new(AtomicBool::new(false));
        let unlocked = Arc::new(AtomicBool::new(false));
        let (interface, _, old) = register_owned_binding(
            &reg,
            1,
            Arc::new(LockCheckingDriver {
                registry: Arc::downgrade(&reg.inner),
                released: released.clone(),
                unlocked: unlocked.clone(),
            }),
        )?;
        let resource_name = name("effect://owned/drop")?;
        reg.admit_resource(
            Resource {
                id: reg.next_resource_id(),
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![interface]),
                binding: old,
            },
            false,
        )?;
        let (next_interface, _, next, _) = owned_binding(&reg, 2)?;
        reg.relink_resource_retiring_previous(
            &resource_name,
            InterfaceSet::new(vec![next_interface]),
            next,
            Metadata::default(),
        )?;
        ensure!(!reg.retire_unreferenced_binding(old));
        ensure!(released.load(Ordering::SeqCst));
        ensure!(unlocked.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn batch_relink_retires_old_driver_outside_registry_lock() -> anyhow::Result<()> {
        let reg = Registry::new();
        let released = Arc::new(AtomicBool::new(false));
        let unlocked = Arc::new(AtomicBool::new(false));
        let (interface, _, old) = register_owned_binding(
            &reg,
            1,
            Arc::new(LockCheckingDriver {
                registry: Arc::downgrade(&reg.inner),
                released: released.clone(),
                unlocked: unlocked.clone(),
            }),
        )?;
        let resource_name = name("effect://owned/batch-drop")?;
        let resource_id = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: resource_id,
                descriptor: ResourceDescriptor {
                    name: resource_name.clone(),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![interface]),
                binding: old,
            },
            false,
        )?;
        let (next_interface, _, next, _) = owned_binding(&reg, 2)?;
        let result = reg.upsert_reclaimable_resources(
            vec![ResourceUpsert {
                new_id: reg.next_resource_id(),
                descriptor: ResourceDescriptor {
                    name: resource_name,
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![next_interface]),
                binding: next,
            }],
            false,
        )?;
        ensure!(result == vec![resource_id]);
        ensure!(released.load(Ordering::SeqCst));
        ensure!(unlocked.load(Ordering::SeqCst));
        ensure!(reg.binding(old).is_none());
        Ok(())
    }

    #[test]
    fn rejected_reclaimable_bundle_publishes_no_descriptors() -> anyhow::Result<()> {
        let reg = Registry::new();
        let baseline = reg.counts();
        let interface = reg.next_interface_id();
        let driver = reg.next_driver_id();
        let binding = reg.next_binding_id();
        let result = reg.admit_reclaimable_bundle(
            vec![Interface {
                id: interface,
                family: xolotl_types::InterfaceFamily::Callable,
                methods: Vec::new(),
                laws: Vec::new(),
            }],
            DriverDescriptor {
                id: driver,
                name: "invalid".into(),
                implements: InterfaceSet::default(),
                transport: xolotl_types::Transport::InProcess,
                driver: Arc::new(crate::driver::EchoDriver),
            },
            Binding {
                id: binding,
                selector: ResourceSelector::parse("perform://effect/**")?,
                interfaces: InterfaceSet::new(vec![interface]),
                driver: xolotl_types::DriverRef {
                    id: driver,
                    name: "invalid".into(),
                },
                endpoint: None,
                generation: 1,
            },
        );
        ensure!(result.is_err());
        ensure!(reg.counts() == baseline);
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
                    addressing: Default::default(),
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
    fn exact_resources_do_not_prefix_resolve_sibling_actions() -> anyhow::Result<()> {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let binding = empty_binding(&reg, 1)?;
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("effect://approval")?,
                kind: ResourceKind::Effect,
                addressing: ResourceAddressing::Exact,
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
            "exact action should not prefix-resolve: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn prefix_resources_can_resolve_concrete_paths() -> anyhow::Result<()> {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let binding = empty_binding(&reg, 1)?;
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("state://memory")?,
                kind: ResourceKind::State,
                addressing: ResourceAddressing::Prefix,
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
    fn addressing_is_explicit_for_custom_and_effect_schemes() -> anyhow::Result<()> {
        let reg = Registry::new();
        let binding = empty_binding(&reg, 1)?;
        let register = |path: &str, kind, addressing| -> anyhow::Result<ResourceId> {
            let id = reg.next_resource_id();
            reg.admit_resource(
                Resource {
                    id,
                    descriptor: ResourceDescriptor {
                        name: name(path)?,
                        kind,
                        addressing,
                        metadata: Metadata::default(),
                    },
                    interfaces: InterfaceSet::default(),
                    binding,
                },
                false,
            )?;
            Ok(id)
        };
        let exact = register(
            "device://lab/thermostat",
            ResourceKind::Device,
            ResourceAddressing::Exact,
        )?;
        ensure!(reg.resolve_resource(&name("device://lab/thermostat")?)? == exact);
        ensure!(
            reg.resolve_resource(&name("device://lab/thermostat/secret")?)
                .is_err()
        );

        let collection = register(
            "device://lab/sensors",
            ResourceKind::Device,
            ResourceAddressing::Prefix,
        )?;
        let closer = register(
            "device://lab/sensors/room",
            ResourceKind::Device,
            ResourceAddressing::Prefix,
        )?;
        ensure!(reg.resolve_resource(&name("device://lab/sensors/hall")?)? == collection);
        ensure!(reg.resolve_resource(&name("device://lab/sensors/room/sample")?)? == closer);
        ensure!(
            reg.resolve_resource(&name("path://remote/device/lab/sensors/room")?)
                .is_err()
        );

        let effect_collection = register(
            "effect://batch",
            ResourceKind::Effect,
            ResourceAddressing::Prefix,
        )?;
        ensure!(reg.resolve_resource(&name("effect://batch/item")?)? == effect_collection);
        ensure!(
            register(
                "device://lab/*",
                ResourceKind::Device,
                ResourceAddressing::Prefix,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn prefix_resolution_uses_nearest_ancestor_within_its_cluster() -> anyhow::Result<()> {
        let reg = Registry::new();
        let binding = empty_binding(&reg, 1)?;
        let register = |path: &str| -> anyhow::Result<ResourceId> {
            let id = reg.next_resource_id();
            reg.admit_resource(
                Resource {
                    id,
                    descriptor: ResourceDescriptor {
                        name: name(path)?,
                        kind: ResourceKind::State,
                        addressing: ResourceAddressing::Prefix,
                        metadata: Metadata::default(),
                    },
                    interfaces: InterfaceSet::default(),
                    binding,
                },
                false,
            )?;
            Ok(id)
        };
        let local_root = register("state://")?;
        let local_memory = register("state://memory")?;
        let local_alice = register("state://memory/alice")?;
        let phone_root = register("path://phone/state")?;
        let phone_memory = register("path://phone/state/memory")?;

        ensure!(reg.resolve_resource(&name("state://memory/alice/fact")?)? == local_alice);
        ensure!(reg.resolve_resource(&name("state://memory/bob")?)? == local_memory);
        ensure!(reg.resolve_resource(&name("state://other")?)? == local_root);
        ensure!(
            reg.resolve_resource(&name("path://phone/state/memory/alice/fact")?)? == phone_memory
        );
        ensure!(reg.resolve_resource(&name("path://phone/state/other")?)? == phone_root);
        ensure!(
            reg.resolve_resource(&name("path://tablet/state/other")?)
                .is_err()
        );
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
                addressing: Default::default(),
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
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::none(),
                    xolotl_types::RightFlags::empty(),
                ),
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
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::all(),
                    RightFlags::empty(),
                ),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder,
            selector: ResourceSelector::parse("perform://effect/target")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
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
    fn candidate_grants_index_preserves_cluster_scope() -> anyhow::Result<()> {
        let reg = Registry::new();
        let holder = ProcessId::new(7);
        for i in 0..SMALL_HOLDER_GRANT_SCAN_LIMIT {
            reg.register_grant(Grant {
                id: reg.next_grant_id(),
                holder,
                selector: ResourceSelector::parse(&format!("perform://effect/irrelevant/g{i}"))
                    .with_context(|| format!("irrelevant selector {i} did not parse"))?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::all(),
                    RightFlags::empty(),
                ),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder,
            selector: ResourceSelector::parse("perform://effect/target")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder,
            selector: ResourceSelector::parse("perform://path://phone/effect/target")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder,
            selector: ResourceSelector::parse("perform://path://*/effect/target")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let target = Path::parse("path://phone/effect/target")?;
        let candidates = reg.candidate_grants(holder, "perform", &target);
        ensure!(candidates.len() == 2, "clustered candidate count mismatch");
        let matched = candidates
            .iter()
            .filter(|grant| grant.selector.matches("perform", &target))
            .count();
        ensure!(matched == 2, "clustered grants did not match target");
        let local = Path::parse("effect://target")?;
        let local_candidates = reg.candidate_grants(holder, "perform", &local);
        ensure!(
            local_candidates
                .iter()
                .filter(|grant| grant.selector.matches("perform", &local))
                .count()
                == 1,
            "local grant index crossed cluster boundary"
        );
        let tablet = Path::parse("path://tablet/effect/target")?;
        let tablet_candidates = reg.candidate_grants(holder, "perform", &tablet);
        ensure!(
            tablet_candidates.len() == 1,
            "tablet candidate count mismatch"
        );
        ensure!(
            tablet_candidates[0].selector.matches("perform", &tablet),
            "wildcard cluster selector missed tablet"
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
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::all(),
                    RightFlags::empty(),
                ),
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
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::all(),
                    RightFlags::empty(),
                ),
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
