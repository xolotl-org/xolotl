//! Control-plane registries, name resolution, and admission (§10).
//!
//! The [`Registry`] holds the six control-plane descriptions
//! (Resource/Interface/Driver/Binding/Policy/Grant). It is consulted only on
//! the slow path (`open()`, admission) — **never** by the data plane (§10.1).

use crate::driver::{DriverDescriptor, DriverPlan, DynDriver, DynRemoteEndpoint};
use crate::handle::FastPath;
use nexus_types::{
    Binding, BindingId, DriverId, EndpointId, Grant, GrantId, Interface, InterfaceId, MethodId,
    ProcessId, Resource, ResourceId, ResourceName, Rights,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ResolveError {
    #[error("no resource named {0}")]
    NoSuchResource(String),
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("interface {0} not implemented by driver {1}")]
    InterfaceNotImplemented(InterfaceId, DriverId),
    #[error("binding {0} does not cover resource {1}'s interfaces")]
    InterfacesNotCovered(BindingId, ResourceId),
    #[error("resource name {0} is under a reserved kernel prefix")]
    ReservedPrefix(String),
    #[error("admission rejected: {0}")]
    Rejected(String),
}

/// The six control-plane registries (§10.1). Behind a single lock for
/// simplicity; the data plane never touches this, so contention is confined to
/// the slow path.
#[derive(Default)]
pub struct RegistryInner {
    pub resources: HashMap<ResourceId, Resource>,
    pub interfaces: HashMap<InterfaceId, Interface>,
    pub drivers: HashMap<DriverId, DriverDescriptor>,
    pub endpoints: HashMap<EndpointId, DynRemoteEndpoint>,
    pub bindings: HashMap<BindingId, Binding>,
    pub grants: HashMap<GrantId, Grant>,
    /// Source policies (§8 / §10.1), consulted at `open()`. Held as trait
    /// objects so any `PolicySource` can register.
    pub policies: Vec<Arc<dyn crate::policy::PolicySource>>,
    /// Name → id index for resolution (§10.2).
    pub names: HashMap<ResourceName, ResourceId>,
    /// Compiled open-plan cache (§5.6). Cleared whenever control-plane
    /// descriptions change, so cached plans never survive a re-link/policy
    /// update/admission mutation.
    pub open_cache: HashMap<OpenCacheKey, CompiledOpenPlan>,
    pub open_cache_hits: u64,
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
}

/// Cache key for `open()` compilation (§5.6). It includes every current
/// `OpenContext` field that can affect policy compilation, plus concrete
/// rights. Registry mutations clear the cache, so binding/policy/driver
/// generations cannot leak through stale plans.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OpenCacheKey {
    pub grant: GrantId,
    pub resource: ResourceId,
    pub resource_path: nexus_types::Path,
    pub verb: String,
    pub methods: u64,
    pub flags: u32,
    pub acting: nexus_types::IdentityRef,
    pub now_millis: i64,
}

impl OpenCacheKey {
    pub fn new(
        grant: GrantId,
        resource: ResourceId,
        resource_path: nexus_types::Path,
        verb: impl Into<String>,
        rights: Rights,
        acting: nexus_types::IdentityRef,
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
    pub resource: ResourceId,
    pub rights: Rights,
    pub driver_plan: DriverPlan,
    pub fast_path: FastPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryCounts {
    pub resources: usize,
    pub interfaces: usize,
    pub drivers: usize,
    pub endpoints: usize,
    pub bindings: usize,
    pub grants: usize,
    pub policies: usize,
    pub names: usize,
    pub open_cache_entries: usize,
    pub open_cache_hits: u64,
    pub open_cache_misses: u64,
}

/// Shared, lockable registry handle.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<RegistryInner>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    // ── id allocation ──────────────────────────────────────────────

    pub fn next_resource_id(&self) -> ResourceId {
        ResourceId::new(self.inner.write().fresh_id())
    }
    pub fn next_interface_id(&self) -> InterfaceId {
        InterfaceId::new(self.inner.write().fresh_id())
    }
    pub fn next_driver_id(&self) -> DriverId {
        DriverId::new(self.inner.write().fresh_id())
    }
    pub fn next_endpoint_id(&self) -> EndpointId {
        EndpointId::new(self.inner.write().fresh_id())
    }
    pub fn next_binding_id(&self) -> BindingId {
        BindingId::new(self.inner.write().fresh_id())
    }
    pub fn next_grant_id(&self) -> GrantId {
        GrantId::new(self.inner.write().fresh_id())
    }

    // ── registration (admission lives in `admit_*`) ─────────────────

    pub fn register_interface(&self, iface: Interface) {
        let mut inner = self.inner.write();
        inner.interfaces.insert(iface.id, iface);
        inner.invalidate_open_cache();
    }

    pub fn register_driver(&self, desc: DriverDescriptor) {
        let mut inner = self.inner.write();
        inner.drivers.insert(desc.id, desc);
        inner.invalidate_open_cache();
    }

    /// Register or replace a remote endpoint transport (§7.4). Bindings with
    /// `endpoint = Some(id)` compile to RPC stubs backed by this entry.
    pub fn register_endpoint(&self, id: EndpointId, endpoint: DynRemoteEndpoint) {
        let mut inner = self.inner.write();
        inner.endpoints.insert(id, endpoint);
        inner.invalidate_open_cache();
    }

    /// Admit and register a Resource (§10.3). Rejects reserved-prefix names
    /// for non-kernel callers and verifies the binding covers the resource's
    /// interfaces (§7.2).
    pub fn admit_resource(
        &self,
        resource: Resource,
        kernel_caller: bool,
    ) -> Result<ResourceId, AdmissionError> {
        let name = resource.descriptor.name.clone();
        if !kernel_caller && nexus_types::is_kernel_reserved(name.path()) {
            return Err(AdmissionError::ReservedPrefix(name.path().to_string()));
        }
        let mut inner = self.inner.write();
        // Binding must cover the resource's interfaces.
        if let Some(binding) = inner.bindings.get(&resource.binding)
            && !binding.interfaces.covers(&resource.interfaces)
        {
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

    /// Admit and register a Binding (§7.2 / §10.3). The bound Driver must
    /// implement every Interface the Binding declares — checked here so a
    /// Binding can never reference interfaces its Driver doesn't provide.
    pub fn admit_binding(&self, binding: Binding) -> Result<BindingId, AdmissionError> {
        let inner = self.inner.read();
        if let Some(driver) = inner.drivers.get(&binding.driver.id) {
            for iface in &binding.interfaces.interfaces {
                if !driver.implements.interfaces.contains(iface) {
                    return Err(AdmissionError::InterfaceNotImplemented(
                        *iface,
                        binding.driver.id,
                    ));
                }
            }
        }
        drop(inner);
        let id = binding.id;
        let mut inner = self.inner.write();
        inner.bindings.insert(id, binding);
        inner.invalidate_open_cache();
        Ok(id)
    }

    pub fn register_binding(&self, binding: Binding) {
        let mut inner = self.inner.write();
        inner.bindings.insert(binding.id, binding);
        inner.invalidate_open_cache();
    }

    /// Admission sandbox check (§16.3.2 / §10.3): every effect path a sandboxed
    /// provider declares must fall under its namespace prefix. Returns the first
    /// offending path, or `Ok(())` if all are within bounds.
    pub fn check_namespace_sandbox(
        namespace: &nexus_types::Path,
        effect_paths: &[nexus_types::Path],
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

    pub fn register_grant(&self, grant: Grant) -> GrantId {
        let id = grant.id;
        let mut inner = self.inner.write();
        inner.grants.insert(id, grant);
        inner.invalidate_open_cache();
        id
    }

    /// Register a source policy (§8 / §10.1). Consulted at every `open()` whose
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

    // ── name resolution (§10.2) ─────────────────────────────────────

    pub fn resolve_resource(&self, name: &ResourceName) -> Result<ResourceId, ResolveError> {
        let inner = self.inner.read();
        // Exact match first (the common case: every effect:// resource).
        if let Some(id) = inner.names.get(name).copied() {
            return Ok(id);
        }
        // Prefix resolution (§12) is only for collection-style resources such
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

    // ── slow-path reads for open() ──────────────────────────────────

    pub fn resource(&self, id: ResourceId) -> Option<Resource> {
        self.inner.read().resources.get(&id).cloned()
    }

    pub fn binding(&self, id: BindingId) -> Option<Binding> {
        self.inner.read().bindings.get(&id).cloned()
    }

    pub fn interface(&self, id: InterfaceId) -> Option<Interface> {
        self.inner.read().interfaces.get(&id).cloned()
    }

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

    pub fn grant(&self, id: GrantId) -> Option<Grant> {
        self.inner.read().grants.get(&id).cloned()
    }

    /// All grants held by `process` (slow path; `open()` step 1, §5.2).
    pub fn grants_of(&self, process: ProcessId) -> Vec<Grant> {
        self.inner
            .read()
            .grants
            .values()
            .filter(|g| g.holder == process)
            .cloned()
            .collect()
    }

    /// Resolve the first method named `name` on `interface`, returning its
    /// index (bit position) and id.
    pub fn method_index(&self, interface: InterfaceId, name: &str) -> Option<(u32, MethodId)> {
        let inner = self.inner.read();
        let iface = inner.interfaces.get(&interface)?;
        iface.method_index(name).map(|(i, m)| (i, m.id))
    }

    pub fn resource_count(&self) -> usize {
        self.inner.read().resources.len()
    }

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

    pub fn store_open_plan(&self, key: OpenCacheKey, plan: CompiledOpenPlan) {
        self.inner.write().open_cache.insert(key, plan);
    }

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
    use nexus_types::{InterfaceSet, Metadata, Path, ResourceDescriptor, ResourceKind};

    fn name(s: &str) -> ResourceName {
        ResourceName::new(Path::parse(s).unwrap())
    }

    #[test]
    fn namespace_sandbox_rejects_escape() {
        // §16.3.2: a sandboxed provider's effects must stay under its namespace.
        let ns = nexus_types::Path::parse("effect://plugin/acme").unwrap();
        assert!(
            Registry::check_namespace_sandbox(
                &ns,
                &[
                    nexus_types::Path::parse("effect://plugin/acme/fetch").unwrap(),
                    nexus_types::Path::parse("effect://plugin/acme/post").unwrap()
                ],
            )
            .is_ok()
        );
        assert!(
            Registry::check_namespace_sandbox(
                &ns,
                &[
                    nexus_types::Path::parse("effect://plugin/acme/ok").unwrap(),
                    nexus_types::Path::parse("effect://x/post").unwrap()
                ],
            )
            .is_err()
        );
        assert!(
            Registry::check_namespace_sandbox(
                &ns,
                &[nexus_types::Path::parse("effect://plugin/acmeevil/tool").unwrap()],
            )
            .is_err(),
            "segment-aware sandboxing must reject string-prefix siblings"
        );
    }

    #[test]
    fn resolve_after_admit() {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("effect://inference/infer"),
                kind: ResourceKind::Effect,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding: BindingId::new(0),
        };
        reg.admit_resource(res, false).unwrap();
        assert_eq!(
            reg.resolve_resource(&name("effect://inference/infer"))
                .unwrap(),
            rid
        );
    }

    #[test]
    fn effect_resources_do_not_prefix_resolve_sibling_actions() {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("effect://approval"),
                kind: ResourceKind::Effect,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding: BindingId::new(0),
        };
        reg.admit_resource(res, false).unwrap();

        assert_eq!(
            reg.resolve_resource(&name("effect://approval")).unwrap(),
            rid
        );
        assert!(matches!(
            reg.resolve_resource(&name("effect://approval/check")),
            Err(ResolveError::NoSuchResource(path)) if path == "effect://approval/check"
        ));
    }

    #[test]
    fn state_resources_can_prefix_resolve_concrete_paths() {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("state://memory"),
                kind: ResourceKind::State,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding: BindingId::new(0),
        };
        reg.admit_resource(res, false).unwrap();

        assert_eq!(
            reg.resolve_resource(&name("state://memory/alice/fact"))
                .unwrap(),
            rid
        );
    }

    #[test]
    fn reserved_prefix_rejected_for_non_kernel() {
        let reg = Registry::new();
        let rid = reg.next_resource_id();
        let res = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name("state://kernel/secret"),
                kind: ResourceKind::Kernel,
                metadata: Metadata::default(),
            },
            interfaces: InterfaceSet::default(),
            binding: BindingId::new(0),
        };
        assert!(matches!(
            reg.admit_resource(res.clone(), false),
            Err(AdmissionError::ReservedPrefix(_))
        ));
        // Kernel caller may register it.
        assert!(reg.admit_resource(res, true).is_ok());
    }

    #[test]
    fn grants_of_filters_by_holder() {
        let reg = Registry::new();
        let g = |holder: u64, id: u64| Grant {
            id: GrantId::new(id),
            holder: ProcessId::new(holder),
            selector: nexus_types::ResourceSelector::parse("perform://effect/x").unwrap(),
            rights: nexus_types::Rights::default(),
            constraints: nexus_types::ConstraintSet::empty(),
            expires: nexus_types::Expiry::Never,
        };
        reg.register_grant(g(1, 10));
        reg.register_grant(g(1, 11));
        reg.register_grant(g(2, 12));
        assert_eq!(reg.grants_of(ProcessId::new(1)).len(), 2);
        assert_eq!(reg.grants_of(ProcessId::new(2)).len(), 1);
    }
}
