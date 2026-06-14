//! Bootstrap: assemble a ready-to-use kernel through an ordered startup
//! sequence.
//!
//! Bootstrap sequence: parse config, open the state backend, mount the
//! FactSink, build registries, create the root/system Process, install
//! in-process Drivers, recover unfinished Processes, start Gateways, and mark
//! the daemon ready.
//!
//! This module provides the assembly primitives; the daemon drives the full
//! startup sequence. The [`Bootstrap`] helper wires a kernel with a root Process
//! holding an omnipotent kernel grant, plus a fluent way to register the
//! standard Resource/Interface/Driver/Binding/Grant tuples. The kernel has no
//! special loading path; built-ins and external providers use the same
//! registration interface.

use crate::driver::{DriverDescriptor, DynDriver};
use crate::kernel::Kernel;
use crate::open::{OpenError, OpenRequest, open_resource_with_attached};
use crate::process::ProcessEntry;
use crate::registry::AdmissionError;
use nexus_types::{
    Binding, CapError, ConstraintSet, DriverRef, Expiry, Fact, Grant, HandleId, IdentityRef,
    Interface, InterfaceFamily, InterfaceSet, Metadata, Method, MethodBitmap, ModalitySet,
    OutputModeSet, Path, PathError, ProcessId, ProcessStatus, Purity, Resource, ResourceDescriptor,
    ResourceKind, ResourceName, ResourceSelector, RightFlags, Rights, SchemaId, Transport,
};
use thiserror::Error;

/// A ready kernel plus the root Process id. The root holds an
/// omnipotent grant; everything else is attenuated from it.
pub struct Bootstrap {
    /// Assembled kernel instance.
    pub kernel: Kernel,
    /// Root/system process seeded during bootstrap.
    pub root: ProcessId,
}

/// Redacted gateway-layer audit metadata. These events happen before a request
/// Process exists, and credentials remain outside Operation input.
pub struct GatewayAudit<'a> {
    /// Audit event name, such as `console_login`.
    pub event: &'a str,
    /// Username involved in the event, when known.
    pub username: Option<&'a str>,
    /// Redacted source address or peer label.
    pub source_addr: Option<&'a str>,
    /// Stable outcome tag for the event.
    pub outcome: &'a str,
    /// MFA assurance level associated with the event.
    pub mfa_level: Option<u8>,
    /// Additional redacted metadata.
    pub details: Option<nexus_types::Value>,
}

/// Request grant template attached to a spawned request Process.
pub struct RequestGrantTemplate<'a> {
    /// Capability selector literal for the request grant.
    pub literal: &'a str,
    /// Method bits the request grant may exercise.
    pub methods: MethodBitmap,
}

/// Parsed request grant template attached to a spawned request Process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRequestGrantTemplate {
    /// Capability selector for the request grant.
    pub selector: ResourceSelector,
    /// Method bits the request grant may exercise.
    pub methods: MethodBitmap,
}

struct ParsedRequestGrantTemplate {
    selector: ResourceSelector,
    methods: Option<MethodBitmap>,
}

/// Errors raised while assembling built-in resources, drivers, and bootstrap
/// facts/state.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// A method list is invalid for the resource being registered.
    #[error("invalid method spec for {resource}: {reason}")]
    InvalidMethodSpec {
        /// Resource path being registered.
        resource: String,
        /// Validation failure reason.
        reason: String,
    },
    /// A capability selector literal could not be parsed.
    #[error("invalid selector {literal:?}: {source}")]
    Selector {
        /// Literal selector that failed parsing.
        literal: String,
        #[source]
        /// Parser error.
        source: CapError,
    },
    /// A resource path literal could not be parsed.
    #[error("invalid path {literal:?}: {source}")]
    Path {
        /// Literal path that failed parsing.
        literal: String,
        #[source]
        /// Parser error.
        source: PathError,
    },
    /// Registry admission rejected a bootstrap object.
    #[error("admission failed: {0}")]
    Admission(#[from] AdmissionError),
    /// A request grant selector is not covered by any grant the authority
    /// anchor holds. No Process is created.
    #[error("request grant {literal:?} exceeds authority anchor ceiling")]
    CapabilityCeiling {
        /// Request grant literal that exceeded the anchor.
        literal: String,
    },
    /// Writing a bootstrap fact failed.
    #[error("fact write failed: {0}")]
    Fact(#[from] crate::FactError),
    /// Writing bootstrap state failed.
    #[error("state write failed: {0}")]
    State(#[from] nexus_state::StateError),
}

/// Assembly-time method descriptor. Output support is explicit: no
/// bootstrap path may silently advertise streaming for a unary-only driver.
#[derive(Clone, Copy, Debug)]
pub struct MethodSpec {
    /// Public method name inside the interface.
    pub name: &'static str,
    /// Method purity used to derive replay class.
    pub purity: Purity,
    /// Output modes supported by this method.
    pub supports: OutputModeSet,
    /// Whether the method accepts explicit list-shaped batches.
    pub batchable: bool,
    /// Whether the method observes external state and must record observations
    /// that affect recovery.
    pub observes_external: bool,
}

impl MethodSpec {
    /// Convenience output set for unary plus async-process methods.
    pub const UNARY_ASYNC: OutputModeSet = OutputModeSet::from_bits_retain(0b0101);
    /// Convenience output set for unary, stream, and async-process methods.
    pub const STREAM_ASYNC: OutputModeSet = OutputModeSet::from_bits_retain(0b0111);
    /// Convenience output set for sink-only plus async-process methods.
    pub const SINK_ASYNC: OutputModeSet = OutputModeSet::from_bits_retain(0b1100);

    /// Create a method specification with explicit output support.
    pub const fn new(name: &'static str, purity: Purity, supports: OutputModeSet) -> Self {
        Self {
            name,
            purity,
            supports,
            batchable: false,
            observes_external: false,
        }
    }

    /// Mark this method as observing external state.
    pub const fn observes_external(mut self) -> Self {
        self.observes_external = true;
        self
    }

    /// Mark this method as explicitly batchable.
    pub const fn batchable(mut self) -> Self {
        self.batchable = true;
        self
    }

    /// Create a unary/async-process method spec.
    pub fn unary_async(name: &'static str, purity: Purity) -> Self {
        Self::new(
            name,
            purity,
            OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
        )
    }

    /// Create a stream-capable method spec.
    pub fn stream_async(name: &'static str, purity: Purity) -> Self {
        Self::new(
            name,
            purity,
            OutputModeSet::UNARY | OutputModeSet::STREAM | OutputModeSet::ASYNC_PROCESS,
        )
    }

    /// Create a sink-only/async-process method spec.
    pub fn sink_async(name: &'static str, purity: Purity) -> Self {
        Self::new(
            name,
            purity,
            OutputModeSet::SINK_ONLY | OutputModeSet::ASYNC_PROCESS,
        )
    }
}

impl Bootstrap {
    /// Build an in-memory kernel, create the root Process, and grant it the
    /// omnipotent capability (`*://**`).
    pub fn in_memory() -> Self {
        let kernel = Kernel::in_memory();
        Self::seed(kernel)
    }

    /// Create the root Process and seed its omnipotent grant over an
    /// already-built [`Kernel`] such as one backed by redb.
    pub fn from_kernel(kernel: Kernel) -> Self {
        Self::seed(kernel)
    }

    fn seed(kernel: Kernel) -> Self {
        // Create the root/system Process.
        let root = kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(root, None, IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        kernel.processes.insert(entry);

        // Root holds the omnipotent grant.
        let grant = Grant {
            id: kernel.registry.next_grant_id(),
            holder: root,
            selector: ResourceSelector::all(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        };
        kernel.registry.register_grant(grant);

        Bootstrap { kernel, root }
    }

    /// Register a Callable effect Resource backed by an in-process driver, and
    /// return its [`ResourceName`]. Callable effects are one authorized action
    /// per path and expose exactly one public method: `invoke`. Drivers
    /// that implement several actions must register several effect paths.
    pub fn register_effect(
        &self,
        path: &str,
        methods: &[MethodSpec],
        driver: DynDriver,
    ) -> Result<ResourceName, BootstrapError> {
        self.register_effect_with_cost(path, methods, driver, nexus_types::CostModel::default())
    }

    /// Like [`register_effect`](Self::register_effect) but every method carries
    /// `cost`. Cost-bearing providers (inference, fetch) use this so the
    /// budget check (reserve/settle) has a real estimate to work from.
    pub fn register_effect_with_cost(
        &self,
        path: &str,
        methods: &[MethodSpec],
        driver: DynDriver,
        cost: nexus_types::CostModel,
    ) -> Result<ResourceName, BootstrapError> {
        if methods.len() != 1 || methods[0].name != "invoke" {
            return Err(BootstrapError::InvalidMethodSpec {
                resource: path.to_string(),
                reason: "Callable effect resources expose exactly one public `invoke` method"
                    .into(),
            });
        }
        let reg = &self.kernel.registry;
        let iface_id = reg.next_interface_id();
        let method_descs = build_methods(methods, cost, false);
        reg.register_interface(Interface {
            id: iface_id,
            family: InterfaceFamily::Callable,
            methods: method_descs,
            laws: Vec::new(),
        });

        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: path.to_string(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: Transport::InProcess,
            driver,
        });

        let binding_id = reg.next_binding_id();
        // The binding selector mirrors the effect path under the `perform` verb.
        // A parse failure here is an assembly-time programmer error (the path is
        // a static literal), so fail fast — never silently broaden the selector
        // to a wildcard, which would over-grant authority.
        let selector_literal = format!("perform://{}", strip_scheme(path));
        let selector = ResourceSelector::parse(&selector_literal).map_err(|source| {
            BootstrapError::Selector {
                literal: selector_literal,
                source,
            }
        })?;
        // Admit (not bare-register) so the invariant is enforced even for
        // built-ins: the bound Driver implements every Interface the Binding
        // declares. The driver registered just above implements `iface_id`, so a
        // failure here is an assembly-time programmer error.
        reg.admit_binding(Binding {
            id: binding_id,
            selector,
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: DriverRef {
                id: driver_id,
                name: path.to_string(),
            },
            endpoint: None,
            generation: 1,
        })?;

        let rid = reg.next_resource_id();
        let name = ResourceName::new(Path::parse(path).map_err(|source| BootstrapError::Path {
            literal: path.to_string(),
            source,
        })?);
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: name.clone(),
                    kind: ResourceKind::Effect,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            true,
        )?;
        Ok(name)
    }

    /// Register a single Resource serving an entire `<scheme>://` subtree,
    /// backed by `driver`. Used for the StateDriver: one Resource at the
    /// `state://` root that `resolve_resource` prefix-matches for every
    /// concrete state path, so state reads and writes become state-driver
    /// Operations. `methods` are the Value/Sequence methods
    /// (`read`/`write`/`append`/`delete`/`list`); the binding selector
    /// authorizes those verbs over the whole `<scheme>/**` subtree.
    pub fn register_subtree_resource(
        &self,
        scheme: &str,
        family: InterfaceFamily,
        methods: &[MethodSpec],
        driver: DynDriver,
    ) -> Result<ResourceName, BootstrapError> {
        self.register_subtree_resource_at(
            &format!("{scheme}://"),
            &format!("*://{scheme}/**"),
            family,
            methods,
            driver,
        )
    }

    /// Register a concrete subtree root, e.g. `state://fact`, with an explicit
    /// grant selector pattern, e.g. `read://state/fact/**`. More-specific roots
    /// win during name resolution, so read-only projections can live under
    /// `state://` without falling through to the generic StateDriver.
    pub fn register_subtree_resource_at(
        &self,
        root_path: &str,
        selector_pattern: &str,
        family: InterfaceFamily,
        methods: &[MethodSpec],
        driver: DynDriver,
    ) -> Result<ResourceName, BootstrapError> {
        let reg = &self.kernel.registry;
        let iface_id = reg.next_interface_id();
        let method_descs = build_methods(methods, Default::default(), true);
        reg.register_interface(Interface {
            id: iface_id,
            family,
            methods: method_descs,
            laws: Vec::new(),
        });

        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: root_path.to_string(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: Transport::InProcess,
            driver,
        });

        let binding_id = reg.next_binding_id();
        let selector = ResourceSelector::parse(selector_pattern).map_err(|source| {
            BootstrapError::Selector {
                literal: selector_pattern.to_string(),
                source,
            }
        })?;
        reg.admit_binding(Binding {
            id: binding_id,
            selector,
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: DriverRef {
                id: driver_id,
                name: root_path.to_string(),
            },
            endpoint: None,
            generation: 1,
        })?;

        let rid = reg.next_resource_id();
        let name =
            ResourceName::new(
                Path::parse(root_path).map_err(|source| BootstrapError::Path {
                    literal: root_path.to_string(),
                    source,
                })?,
            );
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: name.clone(),
                    kind: ResourceKind::State,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            true,
        )?;
        Ok(name)
    }

    /// Open a handle for `process` against a registered resource and bind it on
    /// the executor that will run that process's program. Returns the handle.
    pub fn open_for(
        &self,
        process: ProcessId,
        name: &ResourceName,
        verb: &str,
    ) -> Result<HandleId, OpenError> {
        let resource_id = self
            .kernel
            .registry
            .resolve_resource(name)
            .map_err(|_| OpenError::NoSuchResource(nexus_types::ResourceId::new(0)))?;
        let mut handles = self.kernel.handles.write();
        // The acting identity is the opening Process's own identity;
        // root's internal opens fall back to ROOT.
        let acting = self
            .kernel
            .processes
            .identity(process)
            .unwrap_or(IdentityRef::ROOT);
        let attached_grants = self.kernel.processes.attached_grants(process);
        open_resource_with_attached(
            &self.kernel.registry,
            &mut handles,
            OpenRequest {
                process,
                resource: resource_id,
                verb: verb.to_string(),
                // Ordinary effect/state opens request only the method authority
                // implied by the selector verb. Do not request derivation flags:
                // attenuated request Processes intentionally receive no derive
                // flags, and asking for them would make safe child opens fail.
                rights: Rights::new(
                    method_bitmap_for_verb(&self.kernel.registry, resource_id, verb),
                    RightFlags::empty(),
                ),
                acting,
                // Carry the concrete requested path so prefix-resolved Resources
                // (state://**) bind the real path on the handle.
                requested_path: Some(name.path().clone()),
                now_millis: crate::executor::now_millis(),
            },
            &attached_grants,
        )
    }

    /// Return the method bitmap selected by a capability verb for a resource.
    pub fn request_method_bitmap(
        &self,
        name: &ResourceName,
        verb: &str,
    ) -> Result<MethodBitmap, OpenError> {
        let resource_id = self
            .kernel
            .registry
            .resolve_resource(name)
            .map_err(|_| OpenError::NoSuchResource(nexus_types::ResourceId::new(0)))?;
        Ok(method_bitmap_for_verb(
            &self.kernel.registry,
            resource_id,
            verb,
        ))
    }

    /// Spawn a request Process under `anchor` with explicit request grant
    /// templates. The grant registry is not written on the request path.
    pub fn spawn_request_process_under_with_request_grants(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[RequestGrantTemplate<'_>],
    ) -> Result<ProcessId, BootstrapError> {
        let compiled = grants
            .iter()
            .map(|grant| {
                ResourceSelector::parse(grant.literal)
                    .map(|selector| ParsedRequestGrantTemplate {
                        selector,
                        methods: Some(grant.methods),
                    })
                    .map_err(|source| BootstrapError::Selector {
                        literal: grant.literal.to_string(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.spawn_request_process_under_inner(anchor, identity, &compiled)
    }

    /// Spawn a request Process under `anchor` with pre-parsed request grants.
    pub fn spawn_request_process_under_with_compiled_request_grants(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[CompiledRequestGrantTemplate],
    ) -> Result<ProcessId, BootstrapError> {
        let parsed: Vec<_> = grants
            .iter()
            .map(|grant| ParsedRequestGrantTemplate {
                selector: grant.selector.clone(),
                methods: Some(grant.methods),
            })
            .collect();
        self.spawn_request_process_under_inner(anchor, identity, &parsed)
    }

    fn spawn_request_process_under_inner(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[ParsedRequestGrantTemplate],
    ) -> Result<ProcessId, BootstrapError> {
        // Resolve every covering grant before allocating the child so a
        // rejection leaves no Process or grant behind.
        let anchor_grants = self.kernel.registry.grants_of(anchor);
        let mut planned: Vec<(ResourceSelector, Rights)> = Vec::with_capacity(anchor_grants.len());
        for grant in grants {
            let selector = &grant.selector;
            // covers_cap matches on verb + scheme + segments; the anchor pattern
            // must be at least as broad as the declared one.
            let covering = anchor_grants.iter().find(|g| {
                let requested = grant.methods.unwrap_or(g.rights.methods);
                !requested.is_empty()
                    && requested.is_subset_of(g.rights.methods)
                    && g.selector.pattern.covers_cap(&selector.pattern)
            });
            match covering {
                Some(g) => {
                    let rights = Rights::new(
                        grant.methods.unwrap_or(g.rights.methods),
                        RightFlags::empty(),
                    );
                    planned.push((selector.clone(), rights));
                }
                None => {
                    return Err(BootstrapError::CapabilityCeiling {
                        literal: selector.pattern.to_string(),
                    });
                }
            }
        }

        let child = self.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(child, Some(anchor), identity);
        entry.status = ProcessStatus::Running;

        for (selector, rights) in planned {
            entry.attached_grants.push(Grant {
                id: self.kernel.processes.fresh_attached_grant_id(),
                holder: child,
                selector,
                rights,
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        self.kernel.processes.insert(entry);
        Ok(child)
    }

    /// Recover every unfinished Process from its Fact stream, persisting any
    /// quarantine entries to `state://quarantine/*`.
    /// Returns the aggregate recovery report. Called by the daemon on boot.
    pub async fn recover_all(&self) -> Result<crate::recovery::RecoveryReport, crate::FactError> {
        let mut agg = crate::recovery::RecoveryReport::default();
        for pid in self.kernel.processes.all_ids() {
            let report = crate::recovery::recover_process_persisting(
                &self.kernel.facts,
                &self.kernel.state,
                pid,
            )
            .await?;
            agg.skipped += report.skipped;
            agg.retried += report.retried;
            agg.quarantined += report.quarantined;
            agg.schema_mismatched += report.schema_mismatched;
        }
        Ok(agg)
    }

    /// Record a Gateway-layer audit Fact for pre-Operation events such as
    /// console login/logout/root bootstrap. Credential material is
    /// intentionally absent: only redacted event metadata reaches the Fact log.
    pub fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), crate::FactError> {
        let process = self.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(process, None, IdentityRef::ROOT);
        entry.status = ProcessStatus::Completed;

        let mut outcome = std::collections::BTreeMap::new();
        outcome.insert("event".into(), nexus_types::Value::Str(audit.event.into()));
        outcome.insert(
            "outcome".into(),
            nexus_types::Value::Str(audit.outcome.into()),
        );
        if let Some(username) = audit.username {
            outcome.insert("username".into(), nexus_types::Value::Str(username.into()));
        }
        if let Some(source_addr) = audit.source_addr {
            outcome.insert(
                "source_addr".into(),
                nexus_types::Value::Str(source_addr.into()),
            );
        }
        if let Some(mfa_level) = audit.mfa_level {
            outcome.insert(
                "mfa_level".into(),
                nexus_types::Value::Int(i64::from(mfa_level)),
            );
        }
        if let Some(details) = audit.details {
            outcome.insert("details".into(), details);
        }

        self.kernel.facts.complete(Fact {
            id: nexus_types::OperationId::new(process, GATEWAY_AUDIT_NODE, 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: IdentityRef::ROOT,
            handle: nexus_types::HandleId::new(0, 0),
            resource: nexus_types::ResourceId::new(0),
            method: nexus_types::MethodId::new(0),
            input_ref: nexus_types::ValueRef::Inline(nexus_types::Value::Null),
            taint: nexus_types::TaintSet::author(),
            decision: nexus_types::DecisionTag::Ok,
            outcome_ref: nexus_types::OutcomeRef::Inline(nexus_types::Value::Map(outcome)),
            batch: None,
            replay: nexus_types::ReplayClass::Observation,
            timestamp: nexus_types::Timestamp::millis(crate::executor::now_millis()),
        })?;
        self.kernel.processes.insert(entry);
        Ok(())
    }

    /// Finalize a Process: the ordered teardown sequence. Mutating the
    /// process tree + handle table directly (this is the kernel's own
    /// bookkeeping, not a runtime Operation):
    ///
    /// 1. mark `Finalizing`
    /// 2. cancel descendants deepest-first
    /// 3. run the process's finalizers in reverse order
    /// 4. revoke all handles owned by the process (ABA-safe generation bump)
    /// 5. mark `Done` and record a `ProcessFinalized` Fact-like state marker
    pub async fn finalize_process(&self, process: ProcessId) -> Result<(), BootstrapError> {
        let procs = &self.kernel.processes;
        // 1. mark Finalizing.
        procs.set_status(process, ProcessStatus::Finalizing);

        // 2. cancel descendants deepest-first (excluding self, handled last).
        for descendant in procs.subtree_post_order(process) {
            if descendant != process {
                procs.set_status(descendant, ProcessStatus::Cancelled);
                self.kernel.handles.write().revoke_owned_by(descendant);
            }
        }

        // 3. run finalizers in reverse.
        for body in procs.take_finalizers(process) {
            let ex = self.kernel.executor_for(process);
            let _ = ex.eval(&body).await;
        }

        // 4. revoke handles owned by the process.
        let revoked = self.kernel.handles.write().revoke_owned_by(process);

        // 5. Write a ProcessFinalized Fact to the Fact stream as the
        // authoritative lifecycle record, mark Completed, and write a state
        // marker for quick lookup. The Fact uses a reserved high CausalPosition
        // so it never collides with a program node's id. If the Fact cannot be
        // recorded, leave the Process in Finalizing for operator inspection.
        let finalized = Fact {
            id: nexus_types::OperationId::new(process, FINALIZED_NODE, 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: procs.identity(process).unwrap_or(IdentityRef::ROOT),
            handle: nexus_types::HandleId::new(0, 0),
            resource: nexus_types::ResourceId::new(0),
            method: nexus_types::MethodId::new(0),
            input_ref: nexus_types::ValueRef::Inline(nexus_types::Value::Null),
            taint: nexus_types::TaintSet::pristine(),
            decision: nexus_types::DecisionTag::Ok,
            outcome_ref: nexus_types::OutcomeRef::Inline(nexus_types::Value::Map({
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    "event".into(),
                    nexus_types::Value::Str("ProcessFinalized".into()),
                );
                m.insert(
                    "revoked_handles".into(),
                    nexus_types::Value::Int(revoked as i64),
                );
                m
            })),
            batch: None,
            replay: nexus_types::ReplayClass::Observation,
            timestamp: nexus_types::Timestamp::millis(crate::executor::now_millis()),
        };
        self.kernel.facts.complete(finalized)?;
        procs.set_status(process, ProcessStatus::Completed);
        let path = finalized_marker_path(process).map_err(|source| BootstrapError::Path {
            literal: format!("state://kernel/process/{}/finalized", process.get()),
            source,
        })?;
        self.kernel
            .state
            .write_set(&path, nexus_types::Value::Int(revoked as i64))
            .await?;
        Ok(())
    }
}

/// Reserved CausalPosition for the per-process `ProcessFinalized` lifecycle Fact
/// Far above any compiled program's node ids so it never collides.
const FINALIZED_NODE: nexus_types::NodeId = nexus_types::NodeId::new(u32::MAX);
const GATEWAY_AUDIT_NODE: nexus_types::NodeId = nexus_types::NodeId::new(u32::MAX - 1);

fn finalized_marker_path(process: ProcessId) -> Result<Path, PathError> {
    Path::try_new("state")?
        .try_push("kernel")?
        .try_push("process")?
        .try_push(process.get().to_string())?
        .try_push("finalized")
}

fn method_bitmap_for_verb(
    registry: &crate::registry::Registry,
    resource_id: nexus_types::ResourceId,
    verb: &str,
) -> MethodBitmap {
    let Some(resource) = registry.resource(resource_id) else {
        return MethodBitmap::empty();
    };
    let mut methods = MethodBitmap::empty();
    for iface_id in &resource.interfaces.interfaces {
        let Some(iface) = registry.interface(*iface_id) else {
            continue;
        };
        if verb == "perform" {
            for (index, _) in iface.methods.iter().enumerate() {
                methods |= MethodBitmap::method(index as u32);
            }
        } else {
            for (index, method) in iface.methods.iter().enumerate() {
                let matches_verb = match verb {
                    "read" => method.name == "read" || method.name == "list",
                    "write" => {
                        method.name == "write" || method.name == "append" || method.name == "delete"
                    }
                    "append" => method.name == "append",
                    "subscribe" => method.name == "subscribe",
                    "spawn" | "act-as" => false,
                    _ => false,
                };
                if matches_verb {
                    methods |= MethodBitmap::method(index as u32);
                }
            }
        }
    }
    methods
}

fn build_methods(
    specs: &[MethodSpec],
    cost: nexus_types::CostModel,
    state_backed: bool,
) -> Vec<Method> {
    specs
        .iter()
        .enumerate()
        .map(|(i, spec)| Method {
            // MethodId == the method's index within this interface, so the
            // rights bitmap bit, the driver's dispatch key, and the id all
            // agree. Ids are interface-scoped (the handle identifies the
            // resource), so cross-resource reuse of small ids is fine.
            id: nexus_types::MethodId::new(i as u64),
            name: spec.name.to_string(),
            input: SchemaId::new(0),
            output: SchemaId::new(0),
            modality: ModalitySet::TEXT,
            purity: spec.purity,
            replay: spec
                .purity
                .replay_class(state_backed || spec.observes_external),
            supports: spec.supports,
            cost,
            batchable: spec.batchable,
        })
        .collect()
}

/// Strip the `scheme://` prefix, yielding `scheme/segments` for selector use.
fn strip_scheme(path: &str) -> String {
    path.replacen("://", "/", 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::EchoDriver;
    use nexus_graph::{DoNode, OperationTemplate};
    use nexus_types::{OutputMode, Value};
    use std::sync::Arc;

    #[tokio::test]
    async fn end_to_end_operation_flows_through_resolved_handle() {
        let boot = Bootstrap::in_memory();
        // Register an echo effect and open a handle for the root process.
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[MethodSpec::new(
                    "invoke",
                    Purity::Pure,
                    MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(EchoDriver),
            )
            .unwrap();
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();

        // Build an executor, bind the handle, run a one-Operation program.
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("hello".into())),
        });
        let out = ex.eval(&prog).await;
        assert_eq!(out, nexus_types::Outcome::Done(Value::Str("hello".into())));

        // A single unconsumed pure-Deterministic read need not record a Fact
        // because recovery can recompute it. The EchoDriver method is Pure, and
        // the op's output flows nowhere, so no Fact is written.
        assert_eq!(boot.kernel.facts.facts_of(boot.root).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn unary_only_method_rejects_stream_request() {
        let boot = Bootstrap::in_memory();
        let name = boot
            .register_effect(
                "effect://echo/unary",
                &[MethodSpec::new(
                    "invoke",
                    Purity::Pure,
                    MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(EchoDriver),
            )
            .unwrap();
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Stream,
            literal_input: Some(Value::Str("hello".into())),
        });
        match ex.eval(&prog).await {
            nexus_types::Outcome::Fail(nexus_types::Failure::InvalidInput { reason }) => {
                assert!(
                    reason.contains("does not support output mode"),
                    "unexpected failure reason: {reason}"
                );
            }
            other => panic!("expected unsupported stream request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn budget_exhaustion_denies_costly_op_before_effect() {
        // A process with a tiny daily budget running a costed effect is denied
        // with BudgetExhausted because the reservation fires before dispatch.
        let boot = Bootstrap::in_memory();
        let name = boot
            .register_effect_with_cost(
                "effect://pricey/call",
                &[MethodSpec::new(
                    "invoke",
                    Purity::Effectful,
                    MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(EchoDriver),
                // 1 USD flat per call = 1_000_000 micro-USD.
                nexus_types::CostModel {
                    flat_micro_usd: 1_000_000,
                    ..Default::default()
                },
            )
            .unwrap();
        // Root's daily budget is only 500_000 micro-USD — below one call.
        boot.kernel.processes.set_budget_spec(
            boot.root,
            nexus_types::BudgetSpec {
                daily_micro_usd: Some(500_000),
                ..Default::default()
            },
        );
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("hi".into())),
        });
        match ex.eval(&prog).await {
            nexus_types::Outcome::Fail(nexus_types::Failure::BudgetExhausted { dim }) => {
                assert_eq!(dim, "daily_micro_usd");
            }
            other => panic!("expected BudgetExhausted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn batchable_budget_charges_flat_cost_per_element() {
        // Batchable methods apply CostModel per element. A 3-element batch with
        // flat=100 reserves 300 before dispatch, so a 250 budget denies.
        let boot = Bootstrap::in_memory();
        let name = boot
            .register_effect_with_cost(
                "effect://batch/embed",
                &[
                    MethodSpec::new("invoke", Purity::Idempotent, MethodSpec::UNARY_ASYNC)
                        .batchable(),
                ],
                Arc::new(EchoDriver),
                nexus_types::CostModel {
                    flat_micro_usd: 100,
                    ..Default::default()
                },
            )
            .unwrap();
        boot.kernel.processes.set_budget_spec(
            boot.root,
            nexus_types::BudgetSpec {
                daily_micro_usd: Some(250),
                ..Default::default()
            },
        );
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::List(vec![
                Value::Str("a".into()),
                Value::Str("b".into()),
                Value::Str("c".into()),
            ])),
        });
        match ex.eval(&prog).await {
            nexus_types::Outcome::Fail(nexus_types::Failure::BudgetExhausted { dim }) => {
                assert_eq!(dim, "daily_micro_usd");
            }
            other => panic!("expected batch BudgetExhausted, got {other:?}"),
        }
    }

    #[test]
    fn effect_registration_rejects_sibling_methods() {
        let boot = Bootstrap::in_memory();
        assert!(matches!(
            boot.register_effect(
                "effect://approval/ask",
                &[
                    MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC),
                    MethodSpec::new("check", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
                ],
                Arc::new(EchoDriver),
            ),
            Err(BootstrapError::InvalidMethodSpec { .. })
        ));
    }

    #[tokio::test]
    async fn budget_settles_and_allows_within_limit() {
        // A costed op within budget runs, and settlement leaves inflight at 0.
        let boot = Bootstrap::in_memory();
        let name = boot
            .register_effect_with_cost(
                "effect://cheap/call",
                &[MethodSpec::new(
                    "invoke",
                    Purity::Pure,
                    MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(EchoDriver),
                nexus_types::CostModel {
                    flat_micro_usd: 100,
                    ..Default::default()
                },
            )
            .unwrap();
        boot.kernel.processes.set_budget_spec(
            boot.root,
            nexus_types::BudgetSpec {
                daily_micro_usd: Some(1_000_000),
                ..Default::default()
            },
        );
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("ok".into())),
        });
        assert_eq!(
            ex.eval(&prog).await,
            nexus_types::Outcome::Done(Value::Str("ok".into()))
        );
        // Settled: inflight released, spend reflects the flat charge.
        let inflight = boot
            .kernel
            .processes
            .budget_mut(boot.root, |b| b.inflight_ops)
            .unwrap();
        assert_eq!(inflight, 0, "inflight slot released after settle");
        let spent = boot
            .kernel
            .processes
            .budget_mut(boot.root, |b| b.spent_micro_usd)
            .unwrap();
        assert_eq!(spent, 100, "flat cost settled");
    }

    #[tokio::test]
    async fn consumed_operation_records_a_fact() {
        // When the operation's output is consumed downstream, a Fact is
        // recorded so recovery can reuse it.
        let boot = Bootstrap::in_memory();
        let name = boot
            .register_effect(
                "effect://echo2/say",
                &[MethodSpec::new(
                    "invoke",
                    Purity::Pure,
                    MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(EchoDriver),
            )
            .unwrap();
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        ex.steps
            .install(boot.root, "echo_back", |v, _| DoNode::pure(v));
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("hi".into())),
        })
        .and_then(nexus_graph::StepRef::new(boot.root, "echo_back"));
        let out = ex.eval(&prog).await;
        assert_eq!(out, nexus_types::Outcome::Done(Value::Str("hi".into())));
        assert_eq!(boot.kernel.facts.facts_of(boot.root).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn recover_all_runs_clean_on_fresh_boot() {
        // A freshly-booted kernel has no pending Facts → nothing to recover.
        let boot = Bootstrap::in_memory();
        let report = boot.recover_all().await.unwrap();
        assert_eq!(report.skipped + report.retried + report.quarantined, 0);
    }

    #[tokio::test]
    async fn finalize_marks_completed_and_writes_marker() {
        let boot = Bootstrap::in_memory();
        // Spawn a child request Process, then finalize it.
        let child = boot
            .spawn_request_process_under_with_request_grants(
                boot.root,
                nexus_types::IdentityRef::ROOT,
                &[],
            )
            .unwrap();
        boot.finalize_process(child).await.unwrap();
        assert_eq!(
            boot.kernel.processes.status(child),
            Some(nexus_types::ProcessStatus::Completed)
        );
        // The finalize marker is written to state.
        let path = finalized_marker_path(child).unwrap();
        let marker = boot.kernel.state.read(&path).await.unwrap();
        assert!(marker.is_some());
        // Finalization appends a ProcessFinalized Fact to the Fact stream.
        let facts = boot.kernel.facts.facts_of(child).unwrap();
        assert!(
            facts.iter().any(|f| {
                f.id.position == nexus_types::NodeId::new(u32::MAX)
                    && matches!(&f.outcome_ref, nexus_types::OutcomeRef::Inline(nexus_types::Value::Map(m))
                        if m.get("event").and_then(|v| v.as_str()) == Some("ProcessFinalized"))
            }),
            "finalize records a ProcessFinalized Fact"
        );
    }

    struct FailingFinalizeFactStore;

    impl crate::fact::FactStore for FailingFinalizeFactStore {
        fn append(&self, _fact: Fact) -> Result<u64, crate::fact::FactError> {
            Err(crate::fact::FactError("simulated append failure".into()))
        }

        fn complete(&self, _fact: Fact) -> Result<(), crate::fact::FactError> {
            Err(crate::fact::FactError("simulated complete failure".into()))
        }

        fn sync(&self) -> Result<(), crate::fact::FactError> {
            Ok(())
        }

        fn facts_of(
            &self,
            _process: nexus_types::ProcessId,
        ) -> Result<Vec<Fact>, crate::fact::FactError> {
            Ok(Vec::new())
        }

        fn all_facts(&self) -> Result<Vec<Fact>, crate::fact::FactError> {
            Ok(Vec::new())
        }

        fn cursor(&self) -> u64 {
            0
        }
    }

    #[tokio::test]
    async fn finalize_fact_failure_keeps_process_finalizing() {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore));
        let state: nexus_state::Backend = Arc::new(nexus_state::InMemoryBackend::new());
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let child = boot
            .spawn_request_process_under_with_request_grants(
                boot.root,
                nexus_types::IdentityRef::ROOT,
                &[],
            )
            .unwrap();

        let err = boot.finalize_process(child).await.unwrap_err();
        assert!(matches!(err, BootstrapError::Fact(_)));
        assert_eq!(
            boot.kernel.processes.status(child),
            Some(nexus_types::ProcessStatus::Finalizing),
            "a terminal status requires the authoritative finalization Fact"
        );
    }

    #[test]
    fn gateway_audit_fact_failure_does_not_insert_audit_process() {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore));
        let state: nexus_state::Backend = Arc::new(nexus_state::InMemoryBackend::new());
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let before = boot.kernel.processes.all_ids().len();

        let err = boot
            .record_gateway_audit(GatewayAudit {
                event: "login",
                username: Some("alice"),
                source_addr: Some("127.0.0.1"),
                outcome: "denied",
                mfa_level: None,
                details: None,
            })
            .unwrap_err();

        assert!(err.to_string().contains("simulated complete failure"));
        assert_eq!(
            boot.kernel.processes.all_ids().len(),
            before,
            "pre-operation audit events must not create process rows without audit Facts"
        );
    }

    #[test]
    fn request_process_rejects_malformed_request_grant_before_insert() {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel.processes.all_ids().len();
        let err = boot
            .spawn_request_process_under_with_request_grants(
                boot.root,
                nexus_types::IdentityRef::ROOT,
                &[RequestGrantTemplate {
                    literal: "effect://x/post",
                    methods: MethodBitmap::method(0),
                }],
            )
            .unwrap_err();
        assert!(matches!(err, BootstrapError::Selector { .. }));
        assert_eq!(
            boot.kernel.processes.all_ids().len(),
            before,
            "malformed request grants must not leave a child process behind"
        );
    }

    /// Register a Process holding exactly `selectors` as grants, to act as a
    /// restricted authority anchor in tests.
    fn restricted_anchor(boot: &Bootstrap, selectors: &[&str]) -> nexus_types::ProcessId {
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), nexus_types::IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        for sel in selectors {
            let grant = Grant {
                id: boot.kernel.registry.next_grant_id(),
                holder: anchor,
                selector: ResourceSelector::parse(sel).expect("anchor selector parses"),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            };
            boot.kernel.registry.register_grant(grant);
        }
        anchor
    }

    #[test]
    fn root_anchor_covers_every_request_grant_template() {
        let boot = Bootstrap::in_memory();
        let child = boot
            .spawn_request_process_under_with_request_grants(
                boot.root,
                nexus_types::IdentityRef::ROOT,
                &[
                    RequestGrantTemplate {
                        literal: "perform://effect/x/post",
                        methods: MethodBitmap::method(0),
                    },
                    RequestGrantTemplate {
                        literal: "read://state/memory/alice/x",
                        methods: MethodBitmap::method(0),
                    },
                ],
            )
            .expect("root anchor covers all request grant templates");
        assert!(
            boot.kernel.registry.grants_of(child).is_empty(),
            "request Process grants must not be registered in the global grant table"
        );
        let grants = boot.kernel.processes.attached_grants(child);
        assert_eq!(grants.len(), 2, "one grant per request grant template");
    }

    #[test]
    fn restricted_anchor_rejects_capability_outside_ceiling_fail_closed() {
        // An anchor holding only inference authority must reject a request
        // grant outside that ceiling.
        let boot = Bootstrap::in_memory();
        let anchor = restricted_anchor(&boot, &["perform://effect/inference/**"]);
        let before = boot.kernel.processes.all_ids().len();

        // Covered capability is fine.
        boot.spawn_request_process_under_with_request_grants(
            anchor,
            nexus_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/inference/infer",
                methods: MethodBitmap::method(0),
            }],
        )
        .expect("request grant within anchor ceiling is accepted");

        // Rejected declarations must not allocate a child Process.
        let mid = boot.kernel.processes.all_ids().len();
        let err = boot
            .spawn_request_process_under_with_request_grants(
                anchor,
                nexus_types::IdentityRef::ROOT,
                &[RequestGrantTemplate {
                    literal: "perform://effect/proc/spawn",
                    methods: MethodBitmap::method(0),
                }],
            )
            .unwrap_err();
        assert!(
            matches!(err, BootstrapError::CapabilityCeiling { .. }),
            "request grant outside anchor ceiling must be rejected"
        );
        assert_eq!(
            boot.kernel.processes.all_ids().len(),
            mid,
            "a rejected over-broad request grant must not leave a child process behind"
        );
        assert!(mid > before, "the covered spawn did create a child");
    }

    #[test]
    fn restricted_anchor_rejects_when_one_of_several_caps_exceeds_ceiling() {
        // The whole spawn fails if any request grant exceeds the anchor; the
        // covered ones must not be partially granted.
        let boot = Bootstrap::in_memory();
        let anchor = restricted_anchor(&boot, &["perform://effect/inference/**"]);
        let before = boot.kernel.processes.all_ids().len();
        let err = boot
            .spawn_request_process_under_with_request_grants(
                anchor,
                nexus_types::IdentityRef::ROOT,
                &[
                    RequestGrantTemplate {
                        literal: "perform://effect/inference/infer",
                        methods: MethodBitmap::method(0),
                    },
                    RequestGrantTemplate {
                        literal: "write://state/vault/alice/x",
                        methods: MethodBitmap::method(0),
                    },
                ],
            )
            .unwrap_err();
        assert!(matches!(err, BootstrapError::CapabilityCeiling { .. }));
        assert_eq!(
            boot.kernel.processes.all_ids().len(),
            before,
            "a partially-uncovered declared set must spawn nothing"
        );
    }

    #[test]
    fn request_grant_template_narrows_anchor_method_rights() {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), nexus_types::IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        boot.kernel.registry.register_grant(Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**").unwrap(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let child = boot
            .spawn_request_process_under_with_request_grants(
                anchor,
                nexus_types::IdentityRef::ROOT,
                &[RequestGrantTemplate {
                    literal: "perform://effect/echo/say",
                    methods: MethodBitmap::method(0),
                }],
            )
            .unwrap();
        let grants = boot.kernel.processes.attached_grants(child);
        assert_eq!(grants.len(), 1);
        assert!(grants[0].rights.methods.allows(0));
        assert!(!grants[0].rights.methods.allows(1));
    }

    #[test]
    fn compiled_request_grant_template_uses_anchor_backstop() {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), nexus_types::IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        boot.kernel.registry.register_grant(Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**").unwrap(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let compiled = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/echo/say").unwrap(),
            methods: MethodBitmap::method(0),
        };
        let child = boot
            .spawn_request_process_under_with_compiled_request_grants(
                anchor,
                nexus_types::IdentityRef::ROOT,
                &[compiled],
            )
            .unwrap();
        assert_eq!(boot.kernel.processes.attached_grants(child).len(), 1);

        let overbroad = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/echo/say").unwrap(),
            methods: MethodBitmap::method(1),
        };
        assert!(matches!(
            boot.spawn_request_process_under_with_compiled_request_grants(
                anchor,
                nexus_types::IdentityRef::ROOT,
                &[overbroad],
            ),
            Err(BootstrapError::CapabilityCeiling { .. })
        ));
    }

    #[tokio::test]
    async fn recovery_replays_completed_effect_without_reissuing() {
        // Re-running a recovered program must not repeat an effect that already
        // happened. We run a consumed Operation once, build a ReplayMap from the
        // fact stream, then re-run the same program with the map; the effect
        // driver must not be called the second time.
        use crate::driver::FnDriver;
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicU32, Ordering};

        static CALLS: AtomicU32 = AtomicU32::new(0);
        CALLS.store(0, Ordering::SeqCst);

        let boot = Bootstrap::in_memory();
        let name = boot
            .register_effect(
                "effect://counter/tick",
                &[MethodSpec::new(
                    "invoke",
                    Purity::Effectful,
                    MethodSpec::UNARY_ASYNC,
                )],
                StdArc::new(FnDriver(|_m: nexus_types::MethodId, _in: Value| {
                    CALLS.fetch_add(1, Ordering::SeqCst);
                    Ok(Value::Int(7))
                })),
            )
            .unwrap();
        let handle = boot.open_for(boot.root, &name, "perform").unwrap();

        // A program whose Operation output is consumed (so a Fact is recorded).
        let prog = DoNode::Op(OperationTemplate {
            target: name.clone(),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        })
        .and_then(nexus_graph::StepRef::new(boot.root, "use_it"));

        // First run: the effect fires once and records a Fact.
        let ex1 = boot.kernel.executor_for(boot.root);
        ex1.bind_handle(name.clone(), handle);
        ex1.steps
            .install(boot.root, "use_it", |v, _| DoNode::pure(v));
        let _ = ex1.eval(&prog).await;
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "effect fires on the first run"
        );

        // Build a replay map from the recorded facts and re-run.
        let replay = StdArc::new(crate::recovery::ReplayMap::from_facts(
            &boot.kernel.facts.facts_of(boot.root).unwrap(),
        ));
        assert!(!replay.is_empty(), "the completed effect was recorded");
        let handle2 = boot.open_for(boot.root, &name, "perform").unwrap();
        let ex2 = boot.kernel.executor_for(boot.root).with_replay(replay);
        ex2.bind_handle(name.clone(), handle2);
        ex2.steps
            .install(boot.root, "use_it", |v, _| DoNode::pure(v));
        let out = ex2.eval(&prog).await;

        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "recovery must NOT re-issue the already-recorded effect"
        );
        assert_eq!(
            out,
            nexus_types::Outcome::Done(Value::Int(7)),
            "recorded outcome is replayed"
        );
    }
}
