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
use crate::process::{FinalizeStart, ProcessEntry, TaskAttachment};
use crate::registry::{AdmissionError, ResolveError};
use crate::step::{StepFn, StepInstallError};
use futures_util::FutureExt;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use thiserror::Error;
use xolotl_graph::{ActorSpec, DoNode, LintSeverity, lint_actor};
use xolotl_types::{
    Binding, CapError, ConstraintSet, DriverRef, Expiry, Fact, Grant, HandleId, IdentityRef,
    Interface, InterfaceFamily, InterfaceSet, Metadata, Method, MethodBitmap, ModalitySet,
    OutputModeSet, Path, PathError, ProcessId, ProcessStatus, Purity, Resource, ResourceDescriptor,
    ResourceKind, ResourceName, ResourceSelector, RightFlags, Rights, SchemaId, Transport,
};

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
    pub details: Option<xolotl_types::Value>,
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

/// A spawned actor process.
pub struct SpawnedActor {
    /// Process created for the actor body.
    pub process: ProcessId,
    /// Directory entry written under `state://agents/<identity>/<name>`.
    pub directory: Path,
}

/// Process-local step installed before a spawned actor body starts.
#[derive(Clone)]
pub struct ProcessStepBinding {
    /// Name referenced by `StepRef`.
    pub name: String,
    /// Step function registered under `name`.
    pub step: StepFn,
}

impl ProcessStepBinding {
    /// Create a process-local step binding.
    pub fn new(name: impl Into<String>, step: StepFn) -> Self {
        Self {
            name: name.into(),
            step,
        }
    }
}

struct EffectRegistration<'a> {
    path: &'a str,
    methods: &'a [MethodSpec],
    driver: DynDriver,
    cost: xolotl_types::CostModel,
    metadata: Metadata,
    generation: u64,
    relink_existing: bool,
}

struct ParsedRequestGrantTemplate {
    selector: ResourceSelector,
    methods: Option<MethodBitmap>,
}

struct PlannedRequestGrant {
    selector: ResourceSelector,
    rights: Rights,
    constraints: ConstraintSet,
    expires: Expiry,
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
    /// The requested Process does not exist.
    #[error("process {process} not found")]
    NoSuchProcess {
        /// Process id supplied by the caller.
        process: ProcessId,
    },
    /// Writing a bootstrap fact failed.
    #[error("fact write failed: {0}")]
    Fact(#[from] crate::FactError),
    /// Writing bootstrap state failed.
    #[error("state write failed: {0}")]
    State(#[source] Box<xolotl_state::StateError>),
    /// Actor admission rejected a declaration before execution.
    #[error("actor {actor:?} rejected: {message}")]
    ActorAdmission {
        /// Actor name.
        actor: String,
        /// Admission failure.
        message: String,
    },
    /// Actor body uses capabilities outside its declared ceiling.
    #[error("actor {actor:?} failed capability lint: {message}")]
    ActorLint {
        /// Actor name.
        actor: String,
        /// Lint failure.
        message: String,
    },
    /// Actor step bindings contain the same name more than once.
    #[error("actor {actor:?} has duplicate step binding {name:?}")]
    DuplicateStepBinding {
        /// Actor name.
        actor: String,
        /// Step name.
        name: String,
    },
    /// Installing a process-local step failed.
    #[error("actor {actor:?} step {name:?} install failed: {source}")]
    StepInstall {
        /// Actor name.
        actor: String,
        /// Step name.
        name: String,
        /// Step table error.
        #[source]
        source: StepInstallError,
    },
    /// Actor body or finalizer references a step that was not supplied.
    #[error("actor {actor:?} references missing step binding {name:?}")]
    MissingStepBinding {
        /// Actor name.
        actor: String,
        /// Missing step name.
        name: String,
    },
}

impl From<xolotl_state::StateError> for BootstrapError {
    fn from(source: xolotl_state::StateError) -> Self {
        Self::State(Box::new(source))
    }
}

/// Assembly-time method descriptor. Output support must match the driver.
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
    /// Whether the method may run while the owning Process is finalizing.
    pub finalize_allowed: bool,
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
            finalize_allowed: false,
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

    /// Allow this method to be called from a Process finalizer.
    pub const fn finalize_allowed(mut self) -> Self {
        self.finalize_allowed = true;
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
        self.register_effect_with_cost(path, methods, driver, xolotl_types::CostModel::default())
    }

    /// Like [`register_effect`](Self::register_effect) but every method carries
    /// `cost`. Cost-bearing providers (inference, fetch) use this so the
    /// budget check (reserve/settle) has a real estimate to work from.
    pub fn register_effect_with_cost(
        &self,
        path: &str,
        methods: &[MethodSpec],
        driver: DynDriver,
        cost: xolotl_types::CostModel,
    ) -> Result<ResourceName, BootstrapError> {
        self.register_effect_inner(EffectRegistration {
            path,
            methods,
            driver,
            cost,
            metadata: Metadata::default(),
            generation: 1,
            relink_existing: false,
        })
    }

    /// Register or relink a Callable effect Resource backed by an in-process
    /// driver.
    pub fn register_or_relink_effect_with_cost(
        &self,
        path: &str,
        methods: &[MethodSpec],
        driver: DynDriver,
        cost: xolotl_types::CostModel,
        metadata: Metadata,
        generation: u64,
    ) -> Result<ResourceName, BootstrapError> {
        self.register_effect_inner(EffectRegistration {
            path,
            methods,
            driver,
            cost,
            metadata,
            generation,
            relink_existing: true,
        })
    }

    fn register_effect_inner(
        &self,
        registration: EffectRegistration<'_>,
    ) -> Result<ResourceName, BootstrapError> {
        let EffectRegistration {
            path,
            methods,
            driver,
            cost,
            metadata,
            generation,
            relink_existing,
        } = registration;
        if methods.len() != 1 || methods[0].name != "invoke" {
            return Err(BootstrapError::InvalidMethodSpec {
                resource: path.to_string(),
                reason: "Callable effect resources expose exactly one public `invoke` method"
                    .into(),
            });
        }
        if generation == 0 {
            return Err(BootstrapError::InvalidMethodSpec {
                resource: path.to_string(),
                reason: "binding generation must be positive".into(),
            });
        }
        let name = ResourceName::new(Path::parse(path).map_err(|source| BootstrapError::Path {
            literal: path.to_string(),
            source,
        })?);
        let reg = &self.kernel.registry;
        if relink_existing {
            match reg.resource_binding_generation(&name) {
                Ok(current) if generation < current => {
                    return Err(
                        crate::registry::AdmissionError::BindingGenerationRegressed {
                            resource: name.path().to_string(),
                            current,
                            attempted: generation,
                        }
                        .into(),
                    );
                }
                Ok(_) | Err(crate::registry::AdmissionError::ResourceNotRegistered(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let selector_literal = format!("perform://{}", strip_scheme(path));
        let selector = ResourceSelector::parse(&selector_literal).map_err(|source| {
            BootstrapError::Selector {
                literal: selector_literal,
                source,
            }
        })?;
        let iface_id = reg.next_interface_id();
        let method_descs = build_methods(methods, cost, false);
        let interfaces = InterfaceSet::new(vec![iface_id]);
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
            implements: interfaces.clone(),
            transport: Transport::InProcess,
            driver,
        });

        let binding_id = reg.next_binding_id();
        // Admit (not bare-register) so the invariant is enforced even for
        // built-ins: the bound Driver implements every Interface the Binding
        // declares. The driver registered just above implements `iface_id`, so a
        // failure here is an assembly-time programmer error.
        reg.admit_binding(Binding {
            id: binding_id,
            selector,
            interfaces: interfaces.clone(),
            driver: DriverRef {
                id: driver_id,
                name: path.to_string(),
            },
            endpoint: None,
            generation,
        })?;

        if relink_existing {
            match reg.resolve_resource(&name) {
                Ok(_) => {
                    reg.relink_resource(&name, interfaces, binding_id)?;
                    return Ok(name);
                }
                Err(ResolveError::NoSuchResource(_)) => {}
            }
        }

        let rid = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: name.clone(),
                    kind: ResourceKind::Effect,
                    metadata,
                },
                interfaces,
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

    /// Open a handle for `process` against a registered resource.
    pub fn open_for(
        &self,
        process: ProcessId,
        name: &ResourceName,
        verb: &str,
    ) -> Result<HandleId, OpenError> {
        let resource_id = self.kernel.registry.resolve_resource(name)?;
        let mut handles = self.kernel.handles.write();
        let acting = self
            .kernel
            .processes
            .identity(process)
            .ok_or(OpenError::NoSuchProcess(process))?;
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
        let resource_id = self.kernel.registry.resolve_resource(name)?;
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
        let planned = self.plan_request_grants(anchor, grants)?;
        let child = self.kernel.processes.fresh_id();
        let entry = self.request_process_entry(child, anchor, identity, planned);
        self.kernel.processes.insert(entry);
        Ok(child)
    }

    fn plan_request_grants(
        &self,
        anchor: ProcessId,
        grants: &[ParsedRequestGrantTemplate],
    ) -> Result<Vec<PlannedRequestGrant>, BootstrapError> {
        if !self.kernel.processes.exists(anchor) {
            return Err(BootstrapError::NoSuchProcess { process: anchor });
        }
        let now_millis = crate::executor::now_millis();
        let mut anchor_grants = self.kernel.registry.grants_of(anchor);
        anchor_grants.extend(self.kernel.processes.attached_grants(anchor));
        let mut planned: Vec<PlannedRequestGrant> = Vec::with_capacity(grants.len());
        for grant in grants {
            let (selector, requested_predicate) =
                Self::normalize_selector_constraints(&grant.selector);
            // covers_cap matches on verb + scheme + segments; the anchor pattern
            // must be at least as broad as the declared one.
            let covering = anchor_grants.iter().find(|g| {
                let requested = grant.methods.unwrap_or(g.rights.methods);
                !requested.is_empty()
                    && !g.expires.is_expired(now_millis)
                    && requested.is_subset_of(g.rights.methods)
                    && g.selector.pattern.covers_cap(&selector.pattern)
            });
            match covering {
                Some(g) => {
                    let rights = Rights::new(
                        grant.methods.unwrap_or(g.rights.methods),
                        RightFlags::empty(),
                    );
                    planned.push(PlannedRequestGrant {
                        selector,
                        rights,
                        constraints: Self::derived_grant_constraints(g, requested_predicate),
                        expires: g.expires,
                    });
                }
                None => {
                    return Err(BootstrapError::CapabilityCeiling {
                        literal: grant.selector.pattern.to_string(),
                    });
                }
            }
        }
        Ok(planned)
    }

    fn request_process_entry(
        &self,
        child: ProcessId,
        anchor: ProcessId,
        identity: IdentityRef,
        planned: Vec<PlannedRequestGrant>,
    ) -> ProcessEntry {
        let mut entry = ProcessEntry::new(child, Some(anchor), identity);
        entry.status = ProcessStatus::Running;

        for grant in planned {
            entry.attached_grants.push(Grant {
                id: self.kernel.processes.fresh_attached_grant_id(),
                holder: child,
                selector: grant.selector,
                rights: grant.rights,
                constraints: grant.constraints,
                expires: grant.expires,
            });
        }
        entry
    }

    fn normalize_selector_constraints(
        selector: &ResourceSelector,
    ) -> (ResourceSelector, Option<xolotl_types::Predicate>) {
        let mut selector = selector.clone();
        let predicate = selector.pattern.predicate.take();
        (selector, predicate)
    }

    fn derived_grant_constraints(
        parent: &Grant,
        requested_predicate: Option<xolotl_types::Predicate>,
    ) -> ConstraintSet {
        let mut predicates = Vec::with_capacity(
            usize::from(parent.selector.pattern.predicate.is_some())
                + parent.constraints.predicates.len()
                + usize::from(requested_predicate.is_some()),
        );
        if let Some(predicate) = parent.selector.pattern.predicate.clone() {
            predicates.push(predicate);
        }
        predicates.extend(parent.constraints.predicates.iter().cloned());
        if let Some(predicate) = requested_predicate {
            predicates.push(predicate);
        }
        ConstraintSet { predicates }
    }

    /// Spawn a named long-lived actor Process under `anchor`.
    ///
    /// The actor receives only the capabilities declared by
    /// `spec.declared_capabilities`, intersected with the anchor's grants. Its
    /// body still runs through the ordinary Executor and every effect goes
    /// through `open()`, Handle checks, Policy, Driver dispatch, and Facts.
    pub async fn spawn_actor_under(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
    ) -> Result<SpawnedActor, BootstrapError> {
        self.spawn_actor_under_with_steps(
            anchor,
            identity,
            identity_segment,
            spec,
            std::iter::empty::<ProcessStepBinding>(),
        )
        .await
    }

    /// Spawn a named long-lived actor Process with process-local steps already
    /// installed before the body starts.
    pub async fn spawn_actor_under_with_steps<I>(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
        step_bindings: I,
    ) -> Result<SpawnedActor, BootstrapError>
    where
        I: IntoIterator<Item = ProcessStepBinding>,
    {
        let step_bindings: Vec<ProcessStepBinding> = step_bindings.into_iter().collect();
        validate_actor_segment("actor name", &spec.name)?;
        validate_actor_segment("actor identity segment", identity_segment)?;
        validate_actor_step_bindings(spec, &step_bindings)?;
        let child = self.kernel.processes.fresh_id();
        let spec = spec.bind_process_local_refs(child).map_err(|source| {
            BootstrapError::ActorAdmission {
                actor: spec.name.clone(),
                message: source.to_string(),
            }
        })?;
        xolotl_graph::compile_do(&spec.body).map_err(|source| BootstrapError::ActorAdmission {
            actor: spec.name.clone(),
            message: source.to_string(),
        })?;
        for (index, finalizer) in spec.finalizers.iter().enumerate() {
            xolotl_graph::compile_do(finalizer).map_err(|source| {
                BootstrapError::ActorAdmission {
                    actor: spec.name.clone(),
                    message: format!("finalizer[{index}] compile failed: {source}"),
                }
            })?;
        }

        let lint_message = actor_lint_message(&spec);
        if let Some(message) = lint_message {
            return Err(BootstrapError::ActorLint {
                actor: spec.name.clone(),
                message,
            });
        }

        let parsed = spec
            .declared_capabilities
            .iter()
            .map(|literal| {
                ResourceSelector::parse(literal)
                    .map(|selector| ParsedRequestGrantTemplate {
                        selector,
                        methods: None,
                    })
                    .map_err(|source| BootstrapError::Selector {
                        literal: literal.clone(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let directory = actor_directory_path(identity_segment, &spec.name)?;
        let inbox = actor_inbox_path(identity_segment, &spec.name)?;
        let planned = self.plan_request_grants(anchor, &parsed)?;
        let mut entry = self.request_process_entry(child, anchor, identity, planned);
        entry.budget_spec = spec.budget.clone();
        let body = spec.body.clone();
        let finalizers: Vec<DoNode> = spec.finalizers.clone();
        entry.on_finalize.extend(finalizers.iter().cloned());
        entry.directory = Some(directory.clone());

        let initial = actor_directory_value(&spec, child, ProcessStatus::Running, &inbox);
        install_process_step_bindings(&self.kernel.steps, child, &spec.name, &step_bindings)?;
        if let Err(source) = self.kernel.state.write_cas(&directory, None, initial).await {
            self.kernel.handles.write().revoke_owned_by(child);
            cleanup_process_steps(&self.kernel.steps, child);
            return Err(BootstrapError::State(Box::new(source)));
        }

        self.kernel.processes.insert(entry);

        let kernel = self.kernel.clone();
        let actor_name = spec.name.clone();
        let task = tokio::spawn(async move {
            let outcome = match AssertUnwindSafe(kernel.executor_for(child).eval(&body))
                .catch_unwind()
                .await
            {
                Ok(outcome) => outcome,
                Err(payload) => xolotl_types::Outcome::Fail(xolotl_types::Failure::HandlerError {
                    kind: "panic".into(),
                    message: panic_payload_message("actor process", payload),
                }),
            };
            let status = match &outcome {
                xolotl_types::Outcome::Fail(_) => ProcessStatus::Failed,
                _ => ProcessStatus::Completed,
            };
            match kernel.processes.begin_finalizing(child) {
                FinalizeStart::Started => {
                    if let Err(error) =
                        finish_process_terminal_attempt(&kernel, child, status).await
                    {
                        tracing::error!(
                            actor = %actor_name,
                            process = child.get(),
                            error = %error,
                            "actor process terminal finalization failed"
                        );
                    }
                }
                FinalizeStart::AlreadyFinalizing | FinalizeStart::AlreadyTerminal => {}
                FinalizeStart::NoSuchProcess => {
                    tracing::error!(
                        actor = %actor_name,
                        process = child.get(),
                        "actor process disappeared before terminal finalization"
                    );
                }
            }
            kernel.processes.remove_task(child);
            outcome
        });
        match self
            .kernel
            .processes
            .attach_task(child, task.abort_handle())
        {
            TaskAttachment::Attached | TaskAttachment::AlreadyTerminal => {}
            TaskAttachment::NoSuchProcess => {
                task.abort();
                cleanup_process_steps(&self.kernel.steps, child);
                return Err(BootstrapError::NoSuchProcess { process: child });
            }
            TaskAttachment::AlreadyAttached => {
                task.abort();
                cleanup_process_steps(&self.kernel.steps, child);
                return Err(BootstrapError::ActorAdmission {
                    actor: spec.name.clone(),
                    message: "process already has an attached task".into(),
                });
            }
        }

        Ok(SpawnedActor {
            process: child,
            directory,
        })
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
        outcome.insert("event".into(), xolotl_types::Value::Str(audit.event.into()));
        outcome.insert(
            "outcome".into(),
            xolotl_types::Value::Str(audit.outcome.into()),
        );
        if let Some(username) = audit.username {
            outcome.insert("username".into(), xolotl_types::Value::Str(username.into()));
        }
        if let Some(source_addr) = audit.source_addr {
            outcome.insert(
                "source_addr".into(),
                xolotl_types::Value::Str(source_addr.into()),
            );
        }
        if let Some(mfa_level) = audit.mfa_level {
            outcome.insert(
                "mfa_level".into(),
                xolotl_types::Value::Int(i64::from(mfa_level)),
            );
        }
        if let Some(details) = audit.details {
            outcome.insert("details".into(), details);
        }

        self.kernel.facts.complete(Fact {
            id: xolotl_types::OperationId::new(process, GATEWAY_AUDIT_NODE, 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: IdentityRef::ROOT,
            handle: xolotl_types::HandleId::new(0, 0),
            resource: xolotl_types::ResourceId::new(0),
            method: xolotl_types::MethodId::new(0),
            input_ref: xolotl_types::ValueRef::Inline(xolotl_types::Value::Null),
            taint: xolotl_types::TaintSet::author(),
            decision: xolotl_types::DecisionTag::Ok,
            outcome_ref: xolotl_types::OutcomeRef::Inline(xolotl_types::Value::Map(outcome)),
            batch: None,
            replay: xolotl_types::ReplayClass::Observation,
            timestamp: xolotl_types::Timestamp::millis(crate::executor::now_millis()),
        })?;
        self.kernel.processes.insert(entry);
        Ok(())
    }

    /// Finalize a Process by marking teardown state, cancelling descendants,
    /// running finalizers, revoking owned handles, and recording the
    /// `ProcessFinalized` lifecycle marker.
    pub async fn finalize_process(&self, process: ProcessId) -> Result<(), BootstrapError> {
        let procs = &self.kernel.processes;
        let terminal_status = procs
            .status(process)
            .filter(|current| current.is_terminal())
            .unwrap_or(ProcessStatus::Completed);
        match procs.begin_finalizing(process) {
            FinalizeStart::Started => {}
            FinalizeStart::AlreadyFinalizing | FinalizeStart::AlreadyTerminal => return Ok(()),
            FinalizeStart::NoSuchProcess => return Err(BootstrapError::NoSuchProcess { process }),
        }

        // Cancel descendants deepest-first while this process remains in
        // Finalizing until its own cleanup completes.
        for descendant in procs.subtree_post_order(process) {
            if descendant != process {
                let cancelled = procs.cancel_if_non_terminal(descendant).ok_or(
                    BootstrapError::NoSuchProcess {
                        process: descendant,
                    },
                )?;
                procs.abort_task(descendant);
                self.kernel.handles.write().revoke_owned_by(descendant);
                cleanup_process_steps(&self.kernel.steps, descendant);
                if cancelled && let Some(directory) = procs.directory(descendant) {
                    update_actor_directory_status(
                        &self.kernel.state,
                        &directory,
                        ProcessStatus::Cancelled,
                    )
                    .await?;
                }
            }
        }
        procs.abort_task(process);

        finish_process_terminal_attempt(&self.kernel, process, terminal_status).await
    }

    /// Mark a Process cancelled so its next execution boundary stops work.
    pub fn cancel_process(&self, process: ProcessId) -> Result<bool, BootstrapError> {
        self.kernel
            .processes
            .cancel_if_non_terminal(process)
            .ok_or(BootstrapError::NoSuchProcess { process })
    }

    /// Finish a request Process after its program returned an outcome.
    pub async fn finish_request_process(
        &self,
        process: ProcessId,
        outcome: &xolotl_types::Outcome,
    ) -> Result<(), BootstrapError> {
        let status = match outcome {
            xolotl_types::Outcome::Fail(
                xolotl_types::Failure::Cancelled | xolotl_types::Failure::Timeout,
            ) => ProcessStatus::Cancelled,
            xolotl_types::Outcome::Fail(_) => ProcessStatus::Failed,
            xolotl_types::Outcome::Done(_) | xolotl_types::Outcome::Short(_) => {
                ProcessStatus::Completed
            }
        };
        self.finish_process_as(process, status).await
    }

    /// Run finalizers, revoke handles, and record lifecycle state with an
    /// explicit terminal status.
    pub async fn finish_process_as(
        &self,
        process: ProcessId,
        status: ProcessStatus,
    ) -> Result<(), BootstrapError> {
        let terminal_status = self
            .kernel
            .processes
            .status(process)
            .filter(|current| current.is_terminal())
            .unwrap_or(status);
        match self.kernel.processes.begin_finalizing(process) {
            FinalizeStart::Started => {
                finish_process_terminal_attempt(&self.kernel, process, terminal_status).await
            }
            FinalizeStart::AlreadyFinalizing | FinalizeStart::AlreadyTerminal => Ok(()),
            FinalizeStart::NoSuchProcess => Err(BootstrapError::NoSuchProcess { process }),
        }
    }
}

/// Reserved CausalPosition for the per-process `ProcessFinalized` lifecycle Fact
/// Far above any compiled program's node ids so it never collides.
const FINALIZED_NODE: xolotl_types::NodeId = xolotl_types::NodeId::new(u32::MAX);
const GATEWAY_AUDIT_NODE: xolotl_types::NodeId = xolotl_types::NodeId::new(u32::MAX - 1);

fn finalized_marker_path(process: ProcessId) -> Result<Path, PathError> {
    Path::try_new("state")?
        .try_push("kernel")?
        .try_push("process")?
        .try_push_literal(process.get().to_string())?
        .try_push("finalized")
}

async fn finish_process_terminal_attempt(
    kernel: &Kernel,
    process: ProcessId,
    terminal_status: ProcessStatus,
) -> Result<(), BootstrapError> {
    let result = finish_process_terminal(kernel, process, terminal_status).await;
    if result.is_err() && kernel.processes.release_finalizing(process).is_none() {
        tracing::error!(
            process = process.get(),
            "process disappeared while releasing failed finalization attempt"
        );
    }
    result
}

async fn finish_process_terminal(
    kernel: &Kernel,
    process: ProcessId,
    terminal_status: ProcessStatus,
) -> Result<(), BootstrapError> {
    let mut finalizer_failures = kernel
        .processes
        .finalizer_failures(process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;
    let base_failure_index = finalizer_failures.len();
    for (index, body) in kernel
        .processes
        .take_finalizers(process)
        .into_iter()
        .enumerate()
    {
        let ex = kernel.executor_for(process).with_finalizer_mode();
        if let xolotl_types::Outcome::Fail(failure) = ex.eval(&body).await {
            let failure = failure.to_string();
            tracing::warn!(
                process = process.get(),
                %failure,
                "process finalizer failed"
            );
            let mut item = BTreeMap::new();
            item.insert(
                "index".into(),
                xolotl_types::Value::Int((base_failure_index + index) as i64),
            );
            item.insert("failure".into(), xolotl_types::Value::Str(failure));
            finalizer_failures.push(xolotl_types::Value::Map(item));
        }
    }
    kernel
        .processes
        .set_finalizer_failures(process, finalizer_failures.clone())
        .ok_or(BootstrapError::NoSuchProcess { process })?;

    let revoked = kernel.handles.write().revoke_owned_by(process);
    let finalizer_failure_count = finalizer_failures.len();
    let finalized = Fact {
        id: xolotl_types::OperationId::new(process, FINALIZED_NODE, 0),
        schema_version: Fact::SCHEMA_VERSION,
        caller: process,
        acting: kernel
            .processes
            .identity(process)
            .ok_or(BootstrapError::NoSuchProcess { process })?,
        handle: xolotl_types::HandleId::new(0, 0),
        resource: xolotl_types::ResourceId::new(0),
        method: xolotl_types::MethodId::new(0),
        input_ref: xolotl_types::ValueRef::Inline(xolotl_types::Value::Null),
        taint: xolotl_types::TaintSet::pristine(),
        decision: xolotl_types::DecisionTag::Ok,
        outcome_ref: xolotl_types::OutcomeRef::Inline(xolotl_types::Value::Map({
            let mut m = BTreeMap::new();
            m.insert(
                "event".into(),
                xolotl_types::Value::Str("ProcessFinalized".into()),
            );
            m.insert(
                "status".into(),
                xolotl_types::Value::Str(process_status_label(terminal_status).into()),
            );
            m.insert(
                "revoked_handles".into(),
                xolotl_types::Value::Int(revoked as i64),
            );
            m.insert(
                "finalizer_failure_count".into(),
                xolotl_types::Value::Int(finalizer_failure_count as i64),
            );
            if !finalizer_failures.is_empty() {
                m.insert(
                    "finalizer_failures".into(),
                    xolotl_types::Value::List(finalizer_failures),
                );
            }
            m
        })),
        batch: None,
        replay: xolotl_types::ReplayClass::Observation,
        timestamp: xolotl_types::Timestamp::millis(crate::executor::now_millis()),
    };
    kernel.facts.complete(finalized)?;
    let actual_status = kernel
        .processes
        .mark_terminal_status(process, terminal_status)
        .ok_or(BootstrapError::NoSuchProcess { process })?;

    let marker_path = finalized_marker_path(process).map_err(|source| BootstrapError::Path {
        literal: format!("state://kernel/process/{}/finalized", process.get()),
        source,
    })?;
    let marker_result = kernel
        .state
        .write_set(&marker_path, xolotl_types::Value::Int(revoked as i64))
        .await
        .map_err(BootstrapError::from);
    let directory_result = match kernel.processes.directory(process) {
        Some(directory) => {
            update_actor_directory_status(&kernel.state, &directory, actual_status).await
        }
        None => Ok(()),
    };

    match (marker_result, directory_result) {
        (Ok(()), Ok(())) => {
            cleanup_process_steps(&kernel.steps, process);
            kernel
                .processes
                .complete_finalization(process)
                .ok_or(BootstrapError::NoSuchProcess { process })
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => {
            tracing::error!(
                process = process.get(),
                error = %secondary,
                "process directory update failed after finalize marker failure"
            );
            Err(primary)
        }
    }
}

fn actor_lint_message(spec: &ActorSpec) -> Option<String> {
    let mut messages = Vec::new();
    for finding in lint_actor(spec) {
        if finding.severity == LintSeverity::Error {
            messages.push(finding.message);
        }
    }
    if messages.is_empty() {
        None
    } else {
        Some(messages.join("; "))
    }
}

pub(crate) fn panic_payload_message(
    context: &str,
    payload: Box<dyn std::any::Any + Send>,
) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return format!("{context} panicked: {message}");
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return format!("{context} panicked: {message}");
    }
    format!("{context} panicked")
}

fn validate_actor_segment(label: &'static str, value: &str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() {
        return Err(BootstrapError::ActorAdmission {
            actor: value.to_string(),
            message: format!("{label} must not be empty"),
        });
    }
    let mut chars = value.chars();
    let valid = matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if valid {
        Ok(())
    } else {
        Err(BootstrapError::ActorAdmission {
            actor: value.to_string(),
            message: format!(
                "{label} must start with an ASCII letter or digit and contain only ASCII letters, digits, '_' or '-'"
            ),
        })
    }
}

fn validate_process_step_bindings(
    actor: &str,
    bindings: &[ProcessStepBinding],
) -> Result<BTreeSet<String>, BootstrapError> {
    let mut seen = BTreeSet::new();
    for binding in bindings {
        if binding.name.trim().is_empty() {
            return Err(BootstrapError::ActorAdmission {
                actor: actor.to_string(),
                message: "step name must not be empty".into(),
            });
        }
        if !seen.insert(binding.name.clone()) {
            return Err(BootstrapError::DuplicateStepBinding {
                actor: actor.to_string(),
                name: binding.name.clone(),
            });
        }
    }
    Ok(seen)
}

fn validate_actor_step_bindings(
    spec: &ActorSpec,
    bindings: &[ProcessStepBinding],
) -> Result<(), BootstrapError> {
    let provided = validate_process_step_bindings(&spec.name, bindings)?;
    let mut required = BTreeSet::new();
    collect_step_names(&spec.name, &spec.body, &mut required)?;
    for finalizer in &spec.finalizers {
        collect_step_names(&spec.name, finalizer, &mut required)?;
    }
    for name in required {
        if !provided.contains(name.as_str()) {
            return Err(BootstrapError::MissingStepBinding {
                actor: spec.name.clone(),
                name,
            });
        }
    }
    Ok(())
}

fn collect_step_names(
    actor: &str,
    node: &DoNode,
    out: &mut BTreeSet<String>,
) -> Result<(), BootstrapError> {
    match node {
        DoNode::AndThen { d, then } => {
            collect_step_names(actor, d, out)?;
            insert_step_name(actor, &then.name, out)
        }
        DoNode::OrElse { d, or } => {
            collect_step_names(actor, d, out)?;
            insert_step_name(actor, &or.name, out)
        }
        DoNode::Both(left, right) | DoNode::Race(left, right) => {
            collect_step_names(actor, left, out)?;
            collect_step_names(actor, right, out)
        }
        DoNode::Let { value, body, .. } => {
            collect_step_names(actor, value, out)?;
            collect_step_names(actor, body, out)
        }
        DoNode::Acting { body, .. } => collect_step_names(actor, body, out),
        DoNode::Pure(_) | DoNode::Use(_) | DoNode::Fail(_) | DoNode::Wait(_) | DoNode::Op(_) => {
            Ok(())
        }
    }
}

fn insert_step_name(
    actor: &str,
    name: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), BootstrapError> {
    if name.trim().is_empty() {
        return Err(BootstrapError::ActorAdmission {
            actor: actor.to_string(),
            message: "step reference name must not be empty".into(),
        });
    }
    out.insert(name.to_string());
    Ok(())
}

fn install_process_step_bindings(
    steps: &crate::step::StepTable,
    process: ProcessId,
    actor: &str,
    bindings: &[ProcessStepBinding],
) -> Result<(), BootstrapError> {
    for binding in bindings {
        if let Err(source) =
            steps.install_step_fn(process, binding.name.clone(), binding.step.clone())
        {
            cleanup_process_steps(steps, process);
            return Err(BootstrapError::StepInstall {
                actor: actor.to_string(),
                name: binding.name.clone(),
                source,
            });
        }
    }
    Ok(())
}

fn cleanup_process_steps(steps: &crate::step::StepTable, process: ProcessId) {
    let removed_steps = steps.remove_process(process);
    if removed_steps > 0 {
        tracing::debug!(
            process = process.get(),
            removed_steps,
            "removed process-local steps"
        );
    }
}

fn actor_directory_path(identity_segment: &str, name: &str) -> Result<Path, BootstrapError> {
    Path::try_new("state")
        .and_then(|path| path.try_push("agents"))
        .and_then(|path| path.try_push_literal(identity_segment))
        .and_then(|path| path.try_push_literal(name))
        .map_err(|source| BootstrapError::Path {
            literal: format!("state://agents/{identity_segment}/{name}"),
            source,
        })
}

fn actor_inbox_path(identity_segment: &str, name: &str) -> Result<Path, BootstrapError> {
    actor_directory_path(identity_segment, name)?
        .try_push("inbox")
        .map_err(|source| BootstrapError::Path {
            literal: format!("state://agents/{identity_segment}/{name}/inbox"),
            source,
        })
}

fn actor_directory_value(
    spec: &ActorSpec,
    process: ProcessId,
    status: ProcessStatus,
    inbox: &Path,
) -> xolotl_types::Value {
    let mut m = BTreeMap::new();
    m.insert("name".into(), xolotl_types::Value::Str(spec.name.clone()));
    m.insert(
        "path".into(),
        xolotl_types::Value::Str(format!("process://{}", process.get())),
    );
    m.insert(
        "process".into(),
        xolotl_types::Value::Str(process.get().to_string()),
    );
    m.insert(
        "status".into(),
        xolotl_types::Value::Str(process_status_label(status).into()),
    );
    m.insert("inbox".into(), xolotl_types::Value::Str(inbox.to_string()));
    m.insert(
        "declared_capabilities".into(),
        xolotl_types::Value::List(
            spec.declared_capabilities
                .iter()
                .cloned()
                .map(xolotl_types::Value::Str)
                .collect(),
        ),
    );
    xolotl_types::Value::Map(m)
}

async fn update_actor_directory_status(
    state: &xolotl_state::Backend,
    directory: &Path,
    status: ProcessStatus,
) -> Result<(), BootstrapError> {
    let Some(mut value) = state.read(directory).await? else {
        return Err(BootstrapError::ActorAdmission {
            actor: directory.to_string(),
            message: "actor directory entry is missing".into(),
        });
    };
    match &mut value {
        xolotl_types::Value::Map(map) => {
            map.insert(
                "status".into(),
                xolotl_types::Value::Str(process_status_label(status).into()),
            );
            state.write_set(directory, value).await?;
            Ok(())
        }
        _ => Err(BootstrapError::ActorAdmission {
            actor: directory.to_string(),
            message: "actor directory entry must be a map".into(),
        }),
    }
}

fn process_status_label(status: ProcessStatus) -> &'static str {
    match status {
        ProcessStatus::Created => "created",
        ProcessStatus::Running => "running",
        ProcessStatus::Waiting => "waiting",
        ProcessStatus::Suspended => "suspended",
        ProcessStatus::Finalizing => "finalizing",
        ProcessStatus::Completed => "completed",
        ProcessStatus::Failed => "failed",
        ProcessStatus::Cancelled => "cancelled",
    }
}

fn method_bitmap_for_verb(
    registry: &crate::registry::Registry,
    resource_id: xolotl_types::ResourceId,
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
    cost: xolotl_types::CostModel,
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
            id: xolotl_types::MethodId::new(i as u64),
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
            finalize_allowed: spec.finalize_allowed,
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
    use anyhow::{Context, bail, ensure};
    use std::sync::Arc;
    use xolotl_graph::{ActorSpec, DoNode, OperationTemplate, StepRef};
    use xolotl_types::{OutputMode, Value};

    fn expect_bootstrap_error<T>(
        result: Result<T, BootstrapError>,
    ) -> anyhow::Result<BootstrapError> {
        match result {
            Ok(_) => bail!("expected bootstrap error"),
            Err(err) => Ok(err),
        }
    }

    async fn wait_actor_status(
        boot: &Bootstrap,
        directory: &Path,
        status: &str,
    ) -> anyhow::Result<Value> {
        for _ in 0..100 {
            if let Some(value) = boot.kernel.state.read(directory).await?
                && value
                    .as_map()
                    .and_then(|map| map.get("status"))
                    .and_then(Value::as_str)
                    == Some(status)
            {
                return Ok(value);
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        bail!("actor directory did not reach status {status}");
    }

    #[tokio::test]
    async fn actor_spawn_runs_body_and_writes_directory() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let spec = ActorSpec {
            name: "housekeeper".into(),
            body: DoNode::pure(Value::Str("done".into())),
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        let value = wait_actor_status(&boot, &actor.directory, "completed").await?;
        let Value::Map(map) = value else {
            bail!("actor directory entry must be a map");
        };
        ensure!(
            map.get("status").and_then(Value::as_str) == Some("completed"),
            "actor status was not completed: {map:?}"
        );
        ensure!(
            map.get("path").and_then(Value::as_str)
                == Some(format!("process://{}", actor.process.get()).as_str()),
            "actor process path mismatch: {map:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_body_operation_opens_through_declared_capability() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/actor-body",
            &[
                MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC)
                    .finalize_allowed(),
            ],
            Arc::new(EchoDriver),
        )?;
        let spec = ActorSpec {
            name: "body_op".into(),
            body: DoNode::op(OperationTemplate {
                target: name.clone(),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Str("hello".into())),
            }),
            declared_capabilities: vec!["perform://effect/echo/actor-body".into()],
            ..ActorSpec::default()
        };

        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            facts.iter().any(|fact| fact.caller == actor.process),
            "actor operation should record a fact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_rejects_missing_step_binding() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel.processes.count();
        let spec = ActorSpec {
            name: "missing_step".into(),
            body: DoNode::pure(Value::Null).and_then(StepRef::new(boot.root, "send")),
            ..ActorSpec::default()
        };
        let err = expect_bootstrap_error(
            boot.spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::MissingStepBinding { .. }),
            "unexpected missing step error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.count() == before,
            "missing step binding should not create a process"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_with_step_binding_runs_immediately() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/actor-bound-step",
            &[
                MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC)
                    .finalize_allowed(),
            ],
            Arc::new(EchoDriver),
        )?;
        let spec = ActorSpec {
            name: "bound_step".into(),
            body: DoNode::pure(Value::Null).and_then(StepRef::new(boot.root, "send")),
            declared_capabilities: vec!["perform://effect/echo/actor-bound-step".into()],
            ..ActorSpec::default()
        };
        let step_target = name.clone();
        let actor = boot
            .spawn_actor_under_with_steps(
                boot.root,
                xolotl_types::IdentityRef::ROOT,
                "root",
                &spec,
                [ProcessStepBinding::new(
                    "send",
                    Arc::new(move |_, _| {
                        DoNode::op(OperationTemplate {
                            target: step_target.clone(),
                            method: "invoke".into(),
                            method_id: None,
                            output: OutputMode::Unary,
                            literal_input: Some(Value::Str("from-bound-step".into())),
                        })
                    }),
                )],
            )
            .await?;
        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            facts.iter().any(|fact| fact.caller == actor.process),
            "bound step operation should record a fact"
        );
        ensure!(
            boot.kernel.steps.get(actor.process, "send").is_none(),
            "process-local step should be removed after actor completion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_completion_runs_finalizers_before_step_cleanup() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/actor-completion-finalizer",
            &[
                MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC)
                    .finalize_allowed(),
            ],
            Arc::new(EchoDriver),
        )?;
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .context("registered completion finalizer effect did not resolve")?;
        let spec = ActorSpec {
            name: "completion_finalizer".into(),
            body: DoNode::pure(Value::Null),
            declared_capabilities: vec!["perform://effect/echo/actor-completion-finalizer".into()],
            finalizers: vec![
                DoNode::pure(Value::Null).and_then(StepRef::new(boot.root, "cleanup")),
            ],
            ..ActorSpec::default()
        };
        let step_target = name.clone();
        let actor = boot
            .spawn_actor_under_with_steps(
                boot.root,
                xolotl_types::IdentityRef::ROOT,
                "root",
                &spec,
                [ProcessStepBinding::new(
                    "cleanup",
                    Arc::new(move |_, _| {
                        DoNode::op(OperationTemplate {
                            target: step_target.clone(),
                            method: "invoke".into(),
                            method_id: None,
                            output: OutputMode::Unary,
                            literal_input: Some(Value::Str("cleanup".into())),
                        })
                    }),
                )],
            )
            .await?;

        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            facts.iter().any(|fact| fact.resource == resource_id),
            "completion finalizer operation should record a fact"
        );
        ensure!(
            boot.kernel.steps.get(actor.process, "cleanup").is_none(),
            "finalizer step should be removed after actor completion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalizer_failure_is_recorded_in_lifecycle_fact() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let spec = ActorSpec {
            name: "failing_finalizer".into(),
            body: DoNode::pure(Value::Null),
            finalizers: vec![DoNode::Fail(xolotl_types::Failure::InvalidInput {
                reason: "cleanup failed".into(),
            })],
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        let finalized = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("missing ProcessFinalized fact")?;
        let xolotl_types::OutcomeRef::Inline(Value::Map(map)) = &finalized.outcome_ref else {
            bail!("ProcessFinalized outcome must be a map");
        };
        ensure!(
            map.get("finalizer_failure_count").and_then(Value::as_int) == Some(1),
            "finalizer failure count was not recorded: {map:?}"
        );
        let Some(Value::List(failures)) = map.get("finalizer_failures") else {
            bail!("finalizer failures list missing");
        };
        ensure!(failures.len() == 1, "unexpected failures: {failures:?}");
        ensure!(
            failures
                .first()
                .and_then(Value::as_map)
                .and_then(|item| item.get("failure"))
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains("cleanup failed")),
            "finalizer failure detail was not recorded: {failures:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_does_not_overwrite_terminal_actor_status() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let spec = ActorSpec {
            name: "failed_actor".into(),
            body: DoNode::Fail(xolotl_types::Failure::InvalidInput {
                reason: "body failed".into(),
            }),
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        wait_actor_status(&boot, &actor.directory, "failed").await?;
        boot.finalize_process(actor.process).await?;
        let value = boot
            .kernel
            .state
            .read(&actor.directory)
            .await?
            .context("missing actor directory entry")?;
        ensure!(
            value
                .as_map()
                .and_then(|map| map.get("status"))
                .and_then(Value::as_str)
                == Some("failed"),
            "terminal actor status was overwritten: {value:?}"
        );
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        let finalized = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("missing ProcessFinalized fact")?;
        let xolotl_types::OutcomeRef::Inline(Value::Map(map)) = &finalized.outcome_ref else {
            bail!("ProcessFinalized outcome must be a map");
        };
        ensure!(
            map.get("status").and_then(Value::as_str) == Some("failed"),
            "ProcessFinalized status was overwritten: {map:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_rejects_duplicate_step_bindings() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel.processes.count();
        let spec = ActorSpec {
            name: "duplicate_steps".into(),
            body: DoNode::pure(Value::Null),
            ..ActorSpec::default()
        };
        let step: StepFn = Arc::new(|v, _| DoNode::pure(v));
        let err = expect_bootstrap_error(
            boot.spawn_actor_under_with_steps(
                boot.root,
                xolotl_types::IdentityRef::ROOT,
                "root",
                &spec,
                [
                    ProcessStepBinding::new("same", step.clone()),
                    ProcessStepBinding::new("same", step),
                ],
            )
            .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::DuplicateStepBinding { .. }),
            "unexpected duplicate binding error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.count() == before,
            "duplicate step bindings should not create a process"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_rejects_undeclared_capability() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel.processes.count();
        let spec = ActorSpec {
            name: "bad_actor".into(),
            body: DoNode::op(OperationTemplate {
                target: xolotl_types::ResourceName::new(xolotl_types::Path::parse(
                    "effect://fetch/get",
                )?),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Null),
            }),
            ..ActorSpec::default()
        };
        let err = expect_bootstrap_error(
            boot.spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::ActorLint { .. }),
            "unexpected error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.count() == before,
            "rejected actor should not create a process"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_directory_conflict_does_not_insert_process() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let spec = ActorSpec {
            name: "singleton".into(),
            body: DoNode::pure(Value::Null),
            ..ActorSpec::default()
        };
        let first = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        let before_second = boot.kernel.processes.count();
        let err = expect_bootstrap_error(
            boot.spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::State(_)),
            "unexpected error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.count() == before_second,
            "conflicting actor should not create a process"
        );
        wait_actor_status(&boot, &first.directory, "completed").await?;
        Ok(())
    }

    #[tokio::test]
    async fn finalize_actor_aborts_task_and_updates_directory() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let signal = Path::parse("state://signals/never")?;
        let spec = ActorSpec {
            name: "waiter".into(),
            body: DoNode::wait_signal(signal),
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        boot.finalize_process(actor.process).await?;
        let value = boot
            .kernel
            .state
            .read(&actor.directory)
            .await?
            .context("missing actor directory entry")?;
        ensure!(
            value
                .as_map()
                .and_then(|map| map.get("status"))
                .and_then(Value::as_str)
                == Some("completed"),
            "actor directory status was not completed: {value:?}"
        );
        ensure!(
            !boot.kernel.processes.abort_task(actor.process),
            "actor task should have been removed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_finalizer_operation_opens_while_finalizing() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/actor-finalizer",
            &[
                MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC)
                    .finalize_allowed(),
            ],
            Arc::new(EchoDriver),
        )?;
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .context("registered finalizer effect did not resolve")?;
        let spec = ActorSpec {
            name: "finalizer_op".into(),
            body: DoNode::wait_signal(Path::parse("state://signals/finalizer-never")?),
            declared_capabilities: vec!["perform://effect/echo/actor-finalizer".into()],
            finalizers: vec![DoNode::op(OperationTemplate {
                target: name,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Str("cleanup".into())),
            })],
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        boot.finalize_process(actor.process).await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            facts.iter().any(|fact| fact.resource == resource_id),
            "finalizer operation should record a fact for the effect resource"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_finalizer_rejects_method_without_finalize_allowance() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/not-finalize-allowed",
            &[MethodSpec::new(
                "invoke",
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .context("registered finalizer denial effect did not resolve")?;
        let spec = ActorSpec {
            name: "finalizer_denied".into(),
            body: DoNode::pure(Value::Null),
            declared_capabilities: vec!["perform://effect/echo/not-finalize-allowed".into()],
            finalizers: vec![DoNode::op(OperationTemplate {
                target: name,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Str("cleanup".into())),
            })],
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            !facts.iter().any(|fact| fact.resource == resource_id),
            "finalizer-only denied operation should not dispatch"
        );
        let finalized = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("missing ProcessFinalized fact")?;
        let xolotl_types::OutcomeRef::Inline(Value::Map(map)) = &finalized.outcome_ref else {
            bail!("ProcessFinalized outcome must be a map");
        };
        ensure!(
            map.get("finalizer_failure_count").and_then(Value::as_int) == Some(1),
            "denied finalizer failure was not recorded: {map:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalizer_mode_allows_only_current_process_state_subtree() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        boot.register_subtree_resource(
            "state",
            InterfaceFamily::Value,
            &[MethodSpec::new(
                "write",
                Purity::Idempotent,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let ex = boot.kernel.executor_for(boot.root).with_finalizer_mode();
        let local_target = ResourceName::new(Path::parse(&format!(
            "state://process/{}/cleanup",
            boot.root.get()
        ))?);
        let local = ex
            .eval(&DoNode::op(OperationTemplate {
                target: local_target,
                method: "write".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Str("cleanup".into())),
            }))
            .await;
        ensure!(
            matches!(local, xolotl_types::Outcome::Done(_)),
            "current process state write should be allowed in finalizer mode: {local:?}"
        );

        let sibling_target = ResourceName::new(Path::parse("state://process/999999/cleanup")?);
        let sibling = ex
            .eval(&DoNode::op(OperationTemplate {
                target: sibling_target,
                method: "write".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Str("cleanup".into())),
            }))
            .await;
        ensure!(
            matches!(
                sibling,
                xolotl_types::Outcome::Fail(xolotl_types::Failure::PolicyViolation { .. })
            ),
            "other process state write should be denied in finalizer mode: {sibling:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_rejects_undeclared_finalizer_capability() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel.processes.count();
        let spec = ActorSpec {
            name: "bad_finalizer".into(),
            finalizers: vec![DoNode::op(OperationTemplate {
                target: xolotl_types::ResourceName::new(xolotl_types::Path::parse(
                    "effect://fetch/get",
                )?),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::Null),
            })],
            ..ActorSpec::default()
        };
        let err = expect_bootstrap_error(
            boot.spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::ActorLint { .. }),
            "unexpected error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.count() == before,
            "rejected actor should not create a process"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_rejects_missing_process() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let err = expect_bootstrap_error(boot.finalize_process(ProcessId::new(99_999)).await)?;
        ensure!(
            matches!(err, BootstrapError::NoSuchProcess { .. }),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn open_for_rejects_missing_process() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/missing-process",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let err = boot.open_for(ProcessId::new(99_999), &name, "perform");
        ensure!(
            matches!(err, Err(OpenError::NoSuchProcess(_))),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn end_to_end_operation_flows_through_resolved_handle() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        // Register an echo effect and open a handle for the root process.
        let name = boot.register_effect(
            "effect://echo/say",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let handle = boot.open_for(boot.root, &name, "perform")?;

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
        ensure!(
            out == xolotl_types::Outcome::Done(Value::Str("hello".into())),
            "unexpected operation outcome: {out:?}"
        );

        // A single unconsumed pure-Deterministic read need not record a Fact
        // because recovery can recompute it. The EchoDriver method is Pure, and
        // the op's output flows nowhere, so no Fact is written.
        let facts = boot.kernel.facts.facts_of(boot.root)?;
        ensure!(
            facts.is_empty(),
            "pure unconsumed op should not record facts"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unary_only_method_rejects_stream_request() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/unary",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let handle = boot.open_for(boot.root, &name, "perform")?;
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
            xolotl_types::Outcome::Fail(xolotl_types::Failure::InvalidInput { reason }) => {
                ensure!(
                    reason.contains("does not support output mode"),
                    "unexpected failure reason: {reason}"
                );
            }
            other => bail!("expected unsupported stream request, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn invalid_output_mode_does_not_open_handle() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo/unary-lazy",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let before = boot.kernel.handles.read().len();
        let ex = boot.kernel.executor_for(boot.root);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Stream,
            literal_input: Some(Value::Str("hello".into())),
        });
        match ex.eval(&prog).await {
            xolotl_types::Outcome::Fail(xolotl_types::Failure::InvalidInput { reason }) => {
                ensure!(
                    reason.contains("does not support output mode"),
                    "unexpected failure reason: {reason}"
                );
            }
            other => bail!("expected unsupported stream request, got {other:?}"),
        }
        ensure!(
            boot.kernel.handles.read().len() == before,
            "invalid output mode should not open a handle"
        );
        Ok(())
    }

    #[tokio::test]
    async fn budget_exhaustion_denies_costly_op_before_effect() -> anyhow::Result<()> {
        // A process with a tiny daily budget running a costed effect is denied
        // with BudgetExhausted because the reservation fires before dispatch.
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect_with_cost(
            "effect://pricey/call",
            &[MethodSpec::new(
                "invoke",
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
            // 1 USD flat per call = 1_000_000 micro-USD.
            xolotl_types::CostModel {
                flat_micro_usd: 1_000_000,
                ..Default::default()
            },
        )?;
        // Root's daily budget is only 500_000 micro-USD — below one call.
        ensure!(
            boot.kernel.processes.set_budget_spec(
                boot.root,
                xolotl_types::BudgetSpec {
                    daily_micro_usd: Some(500_000),
                    ..Default::default()
                },
            ),
            "root process missing while setting test budget"
        );
        let handle = boot.open_for(boot.root, &name, "perform")?;
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
            xolotl_types::Outcome::Fail(xolotl_types::Failure::BudgetExhausted { dim }) => {
                ensure!(
                    dim == "daily_micro_usd",
                    "unexpected budget dimension: {dim}"
                );
            }
            other => bail!("expected BudgetExhausted, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn batchable_budget_charges_flat_cost_per_element() -> anyhow::Result<()> {
        // Batchable methods apply CostModel per element. A 3-element batch with
        // flat=100 reserves 300 before dispatch, so a 250 budget denies.
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect_with_cost(
            "effect://batch/embed",
            &[MethodSpec::new("invoke", Purity::Idempotent, MethodSpec::UNARY_ASYNC).batchable()],
            Arc::new(EchoDriver),
            xolotl_types::CostModel {
                flat_micro_usd: 100,
                ..Default::default()
            },
        )?;
        ensure!(
            boot.kernel.processes.set_budget_spec(
                boot.root,
                xolotl_types::BudgetSpec {
                    daily_micro_usd: Some(250),
                    ..Default::default()
                },
            ),
            "root process missing while setting test budget"
        );
        let handle = boot.open_for(boot.root, &name, "perform")?;
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
            xolotl_types::Outcome::Fail(xolotl_types::Failure::BudgetExhausted { dim }) => {
                ensure!(
                    dim == "daily_micro_usd",
                    "unexpected budget dimension: {dim}"
                );
            }
            other => bail!("expected batch BudgetExhausted, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn effect_registration_rejects_sibling_methods() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        ensure!(
            matches!(
                boot.register_effect(
                    "effect://approval/ask",
                    &[
                        MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC),
                        MethodSpec::new("check", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
                    ],
                    Arc::new(EchoDriver),
                ),
                Err(BootstrapError::InvalidMethodSpec { .. })
            ),
            "sibling methods should be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn budget_settles_and_allows_within_limit() -> anyhow::Result<()> {
        // A costed op within budget runs, and settlement leaves inflight at 0.
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect_with_cost(
            "effect://cheap/call",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
            xolotl_types::CostModel {
                flat_micro_usd: 100,
                ..Default::default()
            },
        )?;
        ensure!(
            boot.kernel.processes.set_budget_spec(
                boot.root,
                xolotl_types::BudgetSpec {
                    daily_micro_usd: Some(1_000_000),
                    ..Default::default()
                },
            ),
            "root process missing while setting test budget"
        );
        let handle = boot.open_for(boot.root, &name, "perform")?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("ok".into())),
        });
        let out = ex.eval(&prog).await;
        ensure!(
            out == xolotl_types::Outcome::Done(Value::Str("ok".into())),
            "unexpected budgeted operation outcome: {out:?}"
        );
        // Settled: inflight released, spend reflects the flat charge.
        let inflight = boot
            .kernel
            .processes
            .budget_mut(boot.root, |b| b.inflight_ops)
            .context("missing root budget state")?;
        ensure!(inflight == 0, "inflight slot released after settle");
        let spent = boot
            .kernel
            .processes
            .budget_mut(boot.root, |b| b.spent_micro_usd)
            .context("missing root budget state")?;
        ensure!(spent == 100, "flat cost settled");
        Ok(())
    }

    #[tokio::test]
    async fn consumed_operation_records_a_fact() -> anyhow::Result<()> {
        // When the operation's output is consumed downstream, a Fact is
        // recorded so recovery can reuse it.
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect(
            "effect://echo2/say",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let handle = boot.open_for(boot.root, &name, "perform")?;
        let ex = boot.kernel.executor_for(boot.root);
        ex.bind_handle(name.clone(), handle);
        ex.steps
            .install(boot.root, "echo_back", |v, _| DoNode::pure(v))?;
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Str("hi".into())),
        })
        .and_then(xolotl_graph::StepRef::new(boot.root, "echo_back"));
        let out = ex.eval(&prog).await;
        ensure!(
            out == xolotl_types::Outcome::Done(Value::Str("hi".into())),
            "unexpected consumed operation outcome: {out:?}"
        );
        let facts = boot.kernel.facts.facts_of(boot.root)?;
        ensure!(facts.len() == 1, "consumed op should record one fact");
        Ok(())
    }

    #[tokio::test]
    async fn recover_all_runs_clean_on_fresh_boot() -> anyhow::Result<()> {
        // A freshly-booted kernel has no pending Facts → nothing to recover.
        let boot = Bootstrap::in_memory();
        let report = boot.recover_all().await?;
        ensure!(
            report.skipped + report.retried + report.quarantined == 0,
            "fresh boot should have nothing to recover"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_marks_completed_and_writes_marker() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        // Spawn a child request Process, then finalize it.
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;
        boot.finalize_process(child).await?;
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Completed),
            "child process should be completed"
        );
        // The finalize marker is written to state.
        let path = finalized_marker_path(child)?;
        let marker = boot.kernel.state.read(&path).await?;
        ensure!(marker.is_some(), "finalize marker should be written");
        // Finalization appends a ProcessFinalized Fact to the Fact stream.
        let facts = boot.kernel.facts.facts_of(child)?;
        ensure!(
            facts.iter().any(|f| {
                f.id.position == xolotl_types::NodeId::new(u32::MAX)
                    && matches!(&f.outcome_ref, xolotl_types::OutcomeRef::Inline(xolotl_types::Value::Map(m))
                        if m.get("event").and_then(|v| v.as_str()) == Some("ProcessFinalized"))
            }),
            "finalize records a ProcessFinalized Fact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_preserves_cancelled_request_status() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;
        ensure!(
            boot.cancel_process(child)?,
            "request process should be newly cancelled"
        );

        boot.finalize_process(child).await?;
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Cancelled),
            "finalize should preserve cancelled status"
        );
        let facts = boot.kernel.facts.facts_of(child)?;
        let finalized = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("missing ProcessFinalized fact")?;
        let xolotl_types::OutcomeRef::Inline(Value::Map(map)) = &finalized.outcome_ref else {
            bail!("ProcessFinalized outcome must be a map");
        };
        ensure!(
            map.get("status").and_then(Value::as_str) == Some("cancelled"),
            "ProcessFinalized status should remain cancelled: {map:?}"
        );
        Ok(())
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
            _process: xolotl_types::ProcessId,
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

    struct FailOnceCompleteFactStore {
        inner: crate::fact::InMemoryFactStore,
        fail_next_complete: std::sync::atomic::AtomicBool,
    }

    impl FailOnceCompleteFactStore {
        fn new() -> Self {
            Self {
                inner: crate::fact::InMemoryFactStore::new(),
                fail_next_complete: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    impl crate::fact::FactStore for FailOnceCompleteFactStore {
        fn append(&self, fact: Fact) -> Result<u64, crate::fact::FactError> {
            self.inner.append(fact)
        }

        fn complete(&self, fact: Fact) -> Result<(), crate::fact::FactError> {
            if self
                .fail_next_complete
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(crate::fact::FactError("simulated complete failure".into()));
            }
            self.inner.complete(fact)
        }

        fn sync(&self) -> Result<(), crate::fact::FactError> {
            self.inner.sync()
        }

        fn facts_of(
            &self,
            process: xolotl_types::ProcessId,
        ) -> Result<Vec<Fact>, crate::fact::FactError> {
            self.inner.facts_of(process)
        }

        fn all_facts(&self) -> Result<Vec<Fact>, crate::fact::FactError> {
            self.inner.all_facts()
        }

        fn cursor(&self) -> u64 {
            self.inner.cursor()
        }
    }

    #[tokio::test]
    async fn finalize_fact_failure_keeps_process_finalizing() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore));
        let state: xolotl_state::Backend = Arc::new(xolotl_state::InMemoryBackend::new());
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;

        let err = expect_bootstrap_error(boot.finalize_process(child).await)?;
        ensure!(
            matches!(err, BootstrapError::Fact(_)),
            "unexpected finalize error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Finalizing),
            "a terminal status requires the authoritative finalization Fact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_can_retry_after_fact_failure() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailOnceCompleteFactStore::new()));
        let state: xolotl_state::Backend = Arc::new(xolotl_state::InMemoryBackend::new());
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;

        let err = expect_bootstrap_error(boot.finalize_process(child).await)?;
        ensure!(
            matches!(err, BootstrapError::Fact(_)),
            "unexpected first finalize error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Finalizing),
            "failed finalize should leave process retryable"
        );

        boot.finalize_process(child).await?;
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Completed),
            "retry should complete process finalization"
        );
        ensure!(
            boot.kernel
                .state
                .read(&finalized_marker_path(child)?)
                .await?
                .is_some(),
            "retry should write the finalized marker"
        );
        let facts = boot.kernel.facts.facts_of(child)?;
        ensure!(
            facts.iter().any(|fact| fact.id.position == FINALIZED_NODE),
            "retry should record the ProcessFinalized fact"
        );
        Ok(())
    }

    #[test]
    fn gateway_audit_fact_failure_does_not_insert_audit_process() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore));
        let state: xolotl_state::Backend = Arc::new(xolotl_state::InMemoryBackend::new());
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let before = boot.kernel.processes.all_ids().len();

        let err = match boot.record_gateway_audit(GatewayAudit {
            event: "login",
            username: Some("alice"),
            source_addr: Some("127.0.0.1"),
            outcome: "denied",
            mfa_level: None,
            details: None,
        }) {
            Ok(()) => bail!("expected gateway audit fact error"),
            Err(err) => err,
        };

        ensure!(
            err.to_string().contains("simulated complete failure"),
            "unexpected audit error: {err}"
        );
        ensure!(
            boot.kernel.processes.all_ids().len() == before,
            "pre-operation audit events must not create process rows without audit Facts"
        );
        Ok(())
    }

    #[test]
    fn request_process_rejects_malformed_request_grant_before_insert() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel.processes.all_ids().len();
        let err = expect_bootstrap_error(boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "effect://x/post",
                methods: MethodBitmap::method(0),
            }],
        ))?;
        ensure!(
            matches!(err, BootstrapError::Selector { .. }),
            "unexpected malformed request grant error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.all_ids().len() == before,
            "malformed request grants must not leave a child process behind"
        );
        Ok(())
    }

    /// Register a Process holding exactly `selectors` as grants, to act as a
    /// restricted authority anchor in tests.
    fn restricted_anchor(
        boot: &Bootstrap,
        selectors: &[&str],
    ) -> anyhow::Result<xolotl_types::ProcessId> {
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        for sel in selectors {
            let grant = Grant {
                id: boot.kernel.registry.next_grant_id(),
                holder: anchor,
                selector: ResourceSelector::parse(sel)?,
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            };
            boot.kernel.registry.register_grant(grant);
        }
        Ok(anchor)
    }

    #[test]
    fn root_anchor_covers_every_request_grant_template() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
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
        )?;
        ensure!(
            boot.kernel.registry.grants_of(child).is_empty(),
            "request Process grants must not be registered in the global grant table"
        );
        let grants = boot.kernel.processes.attached_grants(child);
        ensure!(grants.len() == 2, "one grant per request grant template");
        Ok(())
    }

    #[test]
    fn restricted_anchor_rejects_capability_outside_ceiling_fail_closed() -> anyhow::Result<()> {
        // An anchor holding only inference authority must reject a request
        // grant outside that ceiling.
        let boot = Bootstrap::in_memory();
        let anchor = restricted_anchor(&boot, &["perform://effect/inference/**"])?;
        let before = boot.kernel.processes.all_ids().len();

        // Covered capability is fine.
        boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/inference/infer",
                methods: MethodBitmap::method(0),
            }],
        )?;

        // Rejected declarations must not allocate a child Process.
        let mid = boot.kernel.processes.all_ids().len();
        let err = expect_bootstrap_error(boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/proc/spawn",
                methods: MethodBitmap::method(0),
            }],
        ))?;
        ensure!(
            matches!(err, BootstrapError::CapabilityCeiling { .. }),
            "request grant outside anchor ceiling must be rejected"
        );
        ensure!(
            boot.kernel.processes.all_ids().len() == mid,
            "a rejected over-broad request grant must not leave a child process behind"
        );
        ensure!(mid > before, "the covered spawn did create a child");
        Ok(())
    }

    #[test]
    fn restricted_anchor_rejects_when_one_of_several_caps_exceeds_ceiling() -> anyhow::Result<()> {
        // The whole spawn fails if any request grant exceeds the anchor; the
        // covered ones must not be partially granted.
        let boot = Bootstrap::in_memory();
        let anchor = restricted_anchor(&boot, &["perform://effect/inference/**"])?;
        let before = boot.kernel.processes.all_ids().len();
        let err = expect_bootstrap_error(boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
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
        ))?;
        ensure!(
            matches!(err, BootstrapError::CapabilityCeiling { .. }),
            "unexpected capability ceiling error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.all_ids().len() == before,
            "a partially-uncovered declared set must spawn nothing"
        );
        Ok(())
    }

    #[test]
    fn request_grant_template_narrows_anchor_method_rights() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        boot.kernel.registry.register_grant(Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**")?,
            rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let child = boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/say",
                methods: MethodBitmap::method(0),
            }],
        )?;
        let grants = boot.kernel.processes.attached_grants(child);
        ensure!(
            grants.len() == 1,
            "unexpected grant count: {}",
            grants.len()
        );
        ensure!(
            grants[0].rights.methods.allows(0),
            "method 0 should be allowed"
        );
        ensure!(
            !grants[0].rights.methods.allows(1),
            "method 1 should not be allowed"
        );
        Ok(())
    }

    #[test]
    fn request_grant_derivation_preserves_parent_limits() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        let expires = Expiry::At(crate::executor::now_millis() + 60_000);
        boot.kernel.registry.register_grant(Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**@tenant=acme")?,
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet {
                predicates: vec![xolotl_types::Predicate::parse("account=alice")?],
            },
            expires,
        });

        let child = boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/say@purpose=test",
                methods: MethodBitmap::method(0),
            }],
        )?;
        let grants = boot.kernel.processes.attached_grants(child);
        let grant = grants.first().context("missing derived grant")?;
        ensure!(grant.expires == expires, "grant expiry was not preserved");
        ensure!(
            grant.selector.pattern.predicate.is_none(),
            "selector predicate should be normalized into constraints"
        );
        ensure!(
            grant.constraints.predicates.len() == 3,
            "parent/request predicates were not all retained: {:?}",
            grant.constraints.predicates
        );
        Ok(())
    }

    #[test]
    fn request_grant_derivation_uses_attached_anchor_grants() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/**",
                methods: MethodBitmap::method(0),
            }],
        )?;

        let child = boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/say",
                methods: MethodBitmap::method(0),
            }],
        )?;
        ensure!(
            boot.kernel.processes.attached_grants(child).len() == 1,
            "child should derive from anchor's attached grant"
        );
        Ok(())
    }

    #[test]
    fn request_process_rejects_missing_anchor() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel.processes.all_ids().len();
        let err = expect_bootstrap_error(boot.spawn_request_process_under_with_request_grants(
            ProcessId::new(99_999),
            xolotl_types::IdentityRef::ROOT,
            &[],
        ))?;
        ensure!(
            matches!(err, BootstrapError::NoSuchProcess { .. }),
            "unexpected missing-anchor error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.all_ids().len() == before,
            "missing anchor should not create a child process"
        );
        Ok(())
    }

    #[test]
    fn compiled_request_grant_template_uses_anchor_backstop() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        boot.kernel.registry.register_grant(Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**")?,
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let compiled = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/echo/say")?,
            methods: MethodBitmap::method(0),
        };
        let child = boot.spawn_request_process_under_with_compiled_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[compiled],
        )?;
        ensure!(
            boot.kernel.processes.attached_grants(child).len() == 1,
            "compiled grant should attach one grant"
        );

        let overbroad = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/echo/say")?,
            methods: MethodBitmap::method(1),
        };
        ensure!(
            matches!(
                boot.spawn_request_process_under_with_compiled_request_grants(
                    anchor,
                    xolotl_types::IdentityRef::ROOT,
                    &[overbroad],
                ),
                Err(BootstrapError::CapabilityCeiling { .. })
            ),
            "overbroad compiled grant should be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_replays_completed_effect_without_reissuing() -> anyhow::Result<()> {
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
        let name = boot.register_effect(
            "effect://counter/tick",
            &[MethodSpec::new(
                "invoke",
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            StdArc::new(FnDriver(|_m: xolotl_types::MethodId, _in: Value| {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(Value::Int(7))
            })),
        )?;
        let handle = boot.open_for(boot.root, &name, "perform")?;

        // A program whose Operation output is consumed (so a Fact is recorded).
        let prog = DoNode::Op(OperationTemplate {
            target: name.clone(),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::Null),
        })
        .and_then(xolotl_graph::StepRef::new(boot.root, "use_it"));

        let ex1 = boot.kernel.executor_for(boot.root);
        ex1.bind_handle(name.clone(), handle);
        ex1.steps
            .install(boot.root, "use_it", |v, _| DoNode::pure(v))?;
        let first = ex1.eval(&prog).await;
        ensure!(
            first == xolotl_types::Outcome::Done(Value::Int(7)),
            "unexpected first run outcome: {first:?}"
        );
        ensure!(
            CALLS.load(Ordering::SeqCst) == 1,
            "effect fires on the first run"
        );

        // Build a replay map from the recorded facts and re-run.
        let facts = boot.kernel.facts.facts_of(boot.root)?;
        let replay = StdArc::new(crate::recovery::ReplayMap::from_facts(&facts));
        ensure!(!replay.is_empty(), "the completed effect was recorded");
        let handle2 = boot.open_for(boot.root, &name, "perform")?;
        let ex2 = boot.kernel.executor_for(boot.root).with_replay(replay);
        ex2.bind_handle(name.clone(), handle2);
        let out = ex2.eval(&prog).await;

        ensure!(
            CALLS.load(Ordering::SeqCst) == 1,
            "recovery must NOT re-issue the already-recorded effect"
        );
        ensure!(
            out == xolotl_types::Outcome::Done(Value::Int(7)),
            "recorded outcome is replayed"
        );
        Ok(())
    }
}
