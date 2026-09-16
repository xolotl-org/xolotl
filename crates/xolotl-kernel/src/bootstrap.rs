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
use crate::process::{ProcessEntry, TaskAttachment};
use crate::registry::{AdmissionError, ResolveError};
use crate::step::StepModule;
use std::collections::BTreeMap;
use thiserror::Error;
use xolotl_types::{
    Binding, CapError, ConstraintSet, DriverRef, Expiry, Fact, Grant, HandleId, IdentityRef,
    Interface, InterfaceFamily, InterfaceSet, Metadata, Method, MethodBitmap, ModalitySet,
    OutputModeSet, Path, PathError, ProcessId, ProcessStatus, Purity, Resource, ResourceDescriptor,
    ResourceKind, ResourceName, ResourceSelector, RightFlags, Rights, SchemaId, Transport,
};

#[cfg(feature = "durable")]
pub(crate) mod durable;
#[cfg(feature = "durable")]
pub use durable::{DurableRecovery, DurableRecoveryConfig, DurableRecoveryReport};
mod request;
pub use request::{ProcessCleanupFailure, ProcessCleanupReport, RequestProcess};
mod actor;
pub(crate) mod finalize;

/// A ready kernel plus the root Process id. The root holds an
/// omnipotent grant; everything else is attenuated from it.
#[derive(Clone)]
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
    /// A terminal or finalizing process cannot admit children or start work.
    #[error("process {process} is closing and cannot start work")]
    ProcessUnavailable {
        /// Authority anchor whose lifecycle no longer permits request admission.
        process: ProcessId,
    },
    /// Process storage or identity admission was rejected before execution.
    #[error("process admission failed: {0}")]
    ProcessAdmission(#[source] crate::process::ProcessAdmissionError),
    /// Completion would wait on the caller or let finalizers wait on each other.
    #[error("process {process} cannot be joined from this execution context")]
    ProcessBusy {
        /// Process whose owner must first return or request cancellation.
        process: ProcessId,
    },
    /// Background process creation requires an active Tokio runtime.
    #[error("process {process} requires an active Tokio runtime")]
    ProcessRuntimeUnavailable {
        /// Process whose task could not be started.
        process: ProcessId,
    },
    /// A lifecycle completion was given a nonterminal status.
    #[error("cannot finish process {process} with nonterminal status {status:?}")]
    NonterminalStatus {
        /// Process whose lifecycle would have been changed.
        process: ProcessId,
        /// Rejected status.
        status: ProcessStatus,
    },
    /// Writing a bootstrap fact failed.
    #[error("fact write failed: {0}")]
    Fact(#[from] crate::FactError),
    /// An execution identity could not be reserved before dispatch or cleanup.
    #[error("execution identity allocation failed: {0}")]
    ExecutionId(#[from] crate::ExecutionIdError),
    /// Persisting the terminal checkpoint retirement failed; cleanup is retryable.
    #[cfg(feature = "durable")]
    #[error("checkpoint lifecycle failed: {0}")]
    Checkpoint(#[source] Box<xolotl_types::Failure>),
    /// Writing bootstrap state failed.
    #[error("state write failed: {0}")]
    State(#[source] Box<xolotl_state::StateFailure>),
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
    /// Actor body or finalizer references a step that was not supplied.
    #[error("actor {actor:?} references missing step binding {name:?}")]
    MissingStepBinding {
        /// Actor name.
        actor: String,
        /// Missing step name.
        name: String,
    },
}

impl From<xolotl_state::StateFailure> for BootstrapError {
    fn from(source: xolotl_state::StateFailure) -> Self {
        Self::State(Box::new(source))
    }
}

impl From<crate::process::ProcessAdmissionError> for BootstrapError {
    fn from(source: crate::process::ProcessAdmissionError) -> Self {
        match source {
            crate::process::ProcessAdmissionError::Unavailable { process } => {
                Self::ProcessUnavailable { process }
            }
            other => Self::ProcessAdmission(other),
        }
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
    /// Whether protected input must be rejected before this method runs.
    pub requires_unprotected_input: bool,
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
            requires_unprotected_input: false,
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

    /// Require unprotected input, independently of a resource's name or scheme.
    pub const fn unprotected_input(mut self) -> Self {
        self.requires_unprotected_input = true;
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
        let root = kernel.processes.initialize_root(|root| {
            kernel.registry.register_grant(Grant {
                id: kernel.registry.next_grant_id(),
                holder: root,
                selector: ResourceSelector::all(),
                rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        });

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
        self.spawn_request_process_under_inner(anchor, identity, compiled, StepModule::default())
    }

    /// Spawn a request Process under `anchor` with pre-parsed request grants.
    pub fn spawn_request_process_under_with_compiled_request_grants(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[CompiledRequestGrantTemplate],
    ) -> Result<ProcessId, BootstrapError> {
        self.spawn_request_process_under_with_steps(anchor, identity, grants, StepModule::default())
    }

    /// Spawn a request with attenuated grants and a shared native module.
    /// The module is attached before any executor can observe the new process.
    pub fn spawn_request_process_under_with_steps(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[CompiledRequestGrantTemplate],
        steps: StepModule,
    ) -> Result<ProcessId, BootstrapError> {
        let parsed: Vec<_> = grants
            .iter()
            .map(|grant| ParsedRequestGrantTemplate {
                selector: grant.selector.clone(),
                methods: Some(grant.methods),
            })
            .collect();
        self.spawn_request_process_under_inner(anchor, identity, parsed, steps)
    }

    fn spawn_request_process_under_inner(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        mut grants: Vec<ParsedRequestGrantTemplate>,
        steps: StepModule,
    ) -> Result<ProcessId, BootstrapError> {
        let child = self.kernel.processes.fresh_id()?;
        for grant in &mut grants {
            xolotl_graph::bind_process_self_capability(&mut grant.selector.pattern, child);
        }
        let planned = self.plan_request_grants(anchor, &grants)?;
        let mut entry = self.request_process_entry(child, anchor, identity, planned);
        entry.steps = steps;
        entry.scope.start();
        self.kernel.processes.admit_child(entry)?;
        Ok(child)
    }

    fn plan_request_grants(
        &self,
        anchor: ProcessId,
        grants: &[ParsedRequestGrantTemplate],
    ) -> Result<Vec<PlannedRequestGrant>, BootstrapError> {
        match self.kernel.processes.status(anchor) {
            None => return Err(BootstrapError::NoSuchProcess { process: anchor }),
            Some(status) if status.is_terminal() || status == ProcessStatus::Finalizing => {
                return Err(BootstrapError::ProcessUnavailable { process: anchor });
            }
            Some(_) => {}
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

    /// Classify every retained Fact, including records of processes already reaped
    /// or not yet restored, and persist quarantine entries to `state://quarantine/*`.
    /// Uses default per-page read budgets. Returns the aggregate recovery report
    /// without scheduling execution; quiesce Fact writers for stable results.
    pub async fn recover_all(&self) -> Result<crate::recovery::RecoveryReport, crate::FactError> {
        crate::recovery::recover_all_persisting(&self.kernel.facts, &self.kernel.state).await
    }

    /// Classify retained Facts with explicit record and encoded-byte page budgets.
    /// See [`crate::recovery::recover_all_persisting_with_limits`] for consistency
    /// and partial-failure semantics.
    pub async fn recover_all_with_limits(
        &self,
        limits: crate::RecoveryLimits,
    ) -> Result<crate::RecoveryReport, crate::FactError> {
        crate::recovery::recover_all_persisting_with_limits(
            &self.kernel.facts,
            &self.kernel.state,
            limits,
        )
        .await
    }

    /// Record a Gateway-layer audit Fact for pre-Operation events such as
    /// console login/logout/root bootstrap. Credential material is
    /// intentionally absent: only redacted event metadata reaches the Fact log.
    pub fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), crate::FactError> {
        let execution = self
            .kernel
            .execution_ids()
            .allocate()
            .map_err(|error| crate::FactError(error.to_string()))?;
        let process = self.root;

        let mut outcome = std::collections::BTreeMap::new();
        outcome.insert(
            "event".into(),
            xolotl_types::Value::string(audit.event.into()),
        );
        outcome.insert(
            "outcome".into(),
            xolotl_types::Value::string(audit.outcome.into()),
        );
        if let Some(username) = audit.username {
            outcome.insert(
                "username".into(),
                xolotl_types::Value::string(username.into()),
            );
        }
        if let Some(source_addr) = audit.source_addr {
            outcome.insert(
                "source_addr".into(),
                xolotl_types::Value::string(source_addr.into()),
            );
        }
        if let Some(mfa_level) = audit.mfa_level {
            outcome.insert(
                "mfa_level".into(),
                xolotl_types::Value::integer(i64::from(mfa_level)),
            );
        }
        if let Some(details) = audit.details {
            outcome.insert("details".into(), details);
        }

        self.kernel.facts.complete(Fact {
            id: xolotl_types::OperationId::new(
                process,
                execution,
                xolotl_types::InvocationId::new(0),
                GATEWAY_AUDIT_NODE,
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: IdentityRef::ROOT,
            handle: xolotl_types::HandleId::new(0, 0),
            resource: xolotl_types::ResourceId::new(0),
            method: xolotl_types::MethodId::new(0),
            input: xolotl_types::Value::null(),
            taint: xolotl_types::TaintSet::author(),
            decision: xolotl_types::DecisionTag::Ok,
            outcome: Some(xolotl_types::Value::map(outcome)),
            batch: None,
            replay: xolotl_types::ReplayClass::Observation,
            timestamp: xolotl_types::Timestamp::millis(crate::executor::now_millis()),
        })?;
        Ok(())
    }
}

/// Reserved CausalPosition for the per-process `ProcessFinalized` lifecycle Fact
/// Far above any compiled program's node ids so it never collides.
const FINALIZED_NODE: xolotl_types::NodeId = xolotl_types::NodeId::new(u32::MAX);
const GATEWAY_AUDIT_NODE: xolotl_types::NodeId = xolotl_types::NodeId::new(u32::MAX - 1);

fn finalized_marker_path(
    process: ProcessId,
    execution: xolotl_types::ExecutionId,
) -> Result<Path, PathError> {
    Path::try_new("state")?
        .try_push("kernel")?
        .try_push("process")?
        .try_push_literal(process.get().to_string())?
        .try_push_literal(execution.get().to_string())?
        .try_push("finalized")
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

fn task_attachment_error(process: ProcessId, attachment: TaskAttachment) -> BootstrapError {
    match attachment {
        TaskAttachment::NoSuchProcess => BootstrapError::NoSuchProcess { process },
        TaskAttachment::AlreadyTerminal => BootstrapError::ProcessUnavailable { process },
        TaskAttachment::NoRuntime => BootstrapError::ProcessRuntimeUnavailable { process },
        TaskAttachment::Attached | TaskAttachment::AlreadyAttached => {
            BootstrapError::ProcessBusy { process }
        }
    }
}

pub(crate) fn process_status_label(status: ProcessStatus) -> &'static str {
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
            requires_unprotected_input: spec.requires_unprotected_input,
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
    use crate::step::{StepBinding, StepFn};
    use anyhow::{Context, bail, ensure};
    use std::collections::BTreeSet;
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
            body: DoNode::pure(Value::string("done".into())),
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        let value = wait_actor_status(&boot, &actor.directory, "completed").await?;
        let map = value
            .as_map()
            .context("actor directory entry must be a map")?;
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
                literal_input: Some(Value::string("hello".into())),
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
            body: DoNode::pure(Value::null()).and_then(StepRef::new("send")),
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
            body: DoNode::pure(Value::null()).and_then(StepRef::new("send")),
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
                StepModule::new([StepBinding::new(
                    "send",
                    Arc::new(move |_, _| {
                        DoNode::op(OperationTemplate {
                            target: step_target.clone(),
                            method: "invoke".into(),
                            method_id: None,
                            output: OutputMode::Unary,
                            literal_input: Some(Value::string("from-bound-step".into())),
                        })
                    }),
                )])?,
            )
            .await?;
        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            facts.iter().any(|fact| fact.caller == actor.process),
            "bound step operation should record a fact"
        );
        ensure!(
            boot.kernel.processes.steps(actor.process).is_empty(),
            "process-local step should be removed after actor completion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actors_share_nested_steps_with_local_paths_and_finalizers() -> anyhow::Result<()> {
        use crate::{Driver, DriverContext, DriverError};
        use xolotl_types::{Failure, MethodId, Outcome};

        #[derive(Default)]
        struct Writes(parking_lot::Mutex<Vec<(ProcessId, Option<Path>, Value)>>);

        #[async_trait::async_trait]
        impl Driver for Writes {
            async fn call(
                &self,
                _method: MethodId,
                input: Value,
                _output: OutputMode,
                ctx: &DriverContext,
            ) -> Result<crate::DriverOutput, DriverError> {
                self.0
                    .lock()
                    .push((ctx.caller, ctx.target_path.clone(), input.clone()));
                Ok(crate::DriverOutput::new(Outcome::Done(input)))
            }
        }

        let boot = Bootstrap::in_memory();
        let writes = Arc::new(Writes::default());
        boot.register_subtree_resource(
            "state",
            InterfaceFamily::Value,
            &[MethodSpec::new(
                "write",
                Purity::Idempotent,
                MethodSpec::UNARY_ASYNC,
            )],
            writes.clone(),
        )?;
        let signal = Path::parse("state://process/self/start")?;
        let target = ResourceName::new(Path::parse("state://process/self/scratch")?);
        let steps = StepModule::new([
            StepBinding::new(
                "entry",
                Arc::new(move |_, _| {
                    DoNode::wait_signal(signal.clone())
                        .and_then(StepRef::new("store"))
                        .and_then(StepRef::new("recoverable"))
                }),
            ),
            StepBinding::new(
                "store",
                Arc::new(move |input, arg| {
                    DoNode::op(OperationTemplate {
                        target: target.clone(),
                        method: "write".into(),
                        method_id: None,
                        output: OutputMode::Unary,
                        literal_input: Some(arg.unwrap_or(input)),
                    })
                }),
            ),
            StepBinding::new(
                "recoverable",
                Arc::new(|_, _| {
                    DoNode::fail(Failure::Cancelled)
                        .or_else(StepRef::new("store").with_arg(Value::integer(7)))
                }),
            ),
            StepBinding::new(
                "cleanup",
                Arc::new(|_, _| DoNode::pure(99).and_then(StepRef::new("store"))),
            ),
        ])?;
        let spec = ActorSpec {
            name: "shared_steps".into(),
            body: DoNode::pure(Value::null()).and_then(StepRef::new("entry")),
            declared_capabilities: vec!["write://state/process/self/**".into()],
            finalizers: vec![DoNode::pure(Value::null()).and_then(StepRef::new("cleanup"))],
            ..ActorSpec::default()
        };
        let mut actors = Vec::new();
        for identity in ["first", "second"] {
            actors.push(
                boot.spawn_actor_under_with_steps(
                    boot.root,
                    xolotl_types::IdentityRef::ROOT,
                    identity,
                    &spec,
                    steps.clone(),
                )
                .await?,
            );
        }
        for (index, actor) in actors.iter().enumerate() {
            let signal = Path::parse(&format!("state://process/{}/start", actor.process.get()))?;
            boot.kernel
                .state
                .write_cas(&signal, None, Value::integer(index as i64))
                .await?;
            wait_actor_status(&boot, &actor.directory, "completed").await?;
            let expected_path =
                Path::parse(&format!("state://process/{}/scratch", actor.process.get()))?;
            let observed = writes.0.lock();
            let local: Vec<_> = observed
                .iter()
                .filter(|(caller, _, _)| *caller == actor.process)
                .collect();
            ensure!(
                local.len() == 3,
                "missing body, recovery or finalizer operation: {local:?}"
            );
            for ((_, path, value), expected) in local.into_iter().zip([index as i64, 7, 99]) {
                ensure!(path.as_ref() == Some(&expected_path));
                ensure!(*value == Value::integer(expected));
            }
            ensure!(boot.kernel.processes.steps(actor.process).is_empty());
        }
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
            body: DoNode::pure(Value::null()),
            declared_capabilities: vec!["perform://effect/echo/actor-completion-finalizer".into()],
            finalizers: vec![DoNode::pure(Value::null()).and_then(StepRef::new("cleanup"))],
            ..ActorSpec::default()
        };
        let step_target = name.clone();
        let actor = boot
            .spawn_actor_under_with_steps(
                boot.root,
                xolotl_types::IdentityRef::ROOT,
                "root",
                &spec,
                StepModule::new([StepBinding::new(
                    "cleanup",
                    Arc::new(move |_, _| {
                        DoNode::op(OperationTemplate {
                            target: step_target.clone(),
                            method: "invoke".into(),
                            method_id: None,
                            output: OutputMode::Unary,
                            literal_input: Some(Value::string("cleanup".into())),
                        })
                    }),
                )])?,
            )
            .await?;

        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            facts.iter().any(|fact| fact.resource == resource_id),
            "completion finalizer operation should record a fact"
        );
        ensure!(
            boot.kernel.processes.steps(actor.process).is_empty(),
            "finalizer step should be removed after actor completion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalizer_failure_is_recorded_in_lifecycle_fact() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let spec = ActorSpec {
            name: "failing_finalizer".into(),
            body: DoNode::pure(Value::null()),
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
        let map = finalized
            .outcome
            .as_ref()
            .and_then(Value::as_map)
            .context("ProcessFinalized outcome must be a map")?;
        ensure!(
            map.get("finalizer_failure_count").and_then(Value::as_int) == Some(1),
            "finalizer failure count was not recorded: {map:?}"
        );
        let failures = map
            .get("finalizer_failures")
            .and_then(Value::as_list)
            .context("finalizer failures list missing")?;
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
        let map = finalized
            .outcome
            .as_ref()
            .and_then(Value::as_map)
            .context("ProcessFinalized outcome must be a map")?;
        ensure!(
            map.get("status").and_then(Value::as_str) == Some("failed"),
            "ProcessFinalized status was overwritten: {map:?}"
        );
        Ok(())
    }

    #[test]
    fn request_local_templates_bind_before_attenuation() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let template = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("write://state/process/self/scratch@account=alice")?,
            methods: MethodBitmap::method(0),
        };
        let process = boot.spawn_request_process_under_with_steps(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            std::slice::from_ref(&template),
            StepModule::default(),
        )?;
        let grants = boot.kernel.processes.attached_grants(process);
        let grant = grants.first().context("request has no attached grant")?;
        ensure!(
            grant.selector.pattern.to_string()
                == format!("write://state/process/{}/scratch", process.get())
        );
        ensure!(
            grant.constraints.predicates
                == [template
                    .selector
                    .pattern
                    .predicate
                    .clone()
                    .context("missing predicate")?]
        );
        ensure!(template.selector.pattern.segments[1].as_str() == "self");

        let before = boot.kernel.processes.count();
        let rejected = boot.spawn_request_process_under_with_steps(
            process,
            xolotl_types::IdentityRef::ROOT,
            &[template],
            StepModule::default(),
        );
        ensure!(matches!(
            rejected,
            Err(BootstrapError::CapabilityCeiling { .. })
        ));
        ensure!(boot.kernel.processes.count() == before);
        Ok(())
    }

    #[tokio::test]
    async fn request_modules_are_isolated_and_released_after_finalization() -> anyhow::Result<()> {
        use xolotl_types::{Failure, Outcome};
        let boot = Bootstrap::in_memory();
        let step: StepFn = Arc::new(|v, _| DoNode::pure(v));
        let weak = Arc::downgrade(&step);
        let process = boot.spawn_request_process_under_with_steps(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[],
            StepModule::new([StepBinding::new("identity", step)])?,
        )?;
        let program = DoNode::pure(42).and_then(StepRef::new("identity"));
        let executor = boot.kernel.executor_for(process);
        let outcome = executor.eval(&program).await;
        ensure!(outcome.outcome == Outcome::Done(Value::integer(42)));
        ensure!(
            matches!(
                boot.kernel
                    .executor_for(boot.root)
                    .eval(&program)
                    .await
                    .outcome,
                Outcome::Fail(_)
            ),
            "request functions must not leak to the parent"
        );
        let overridden = boot
            .kernel
            .executor_for(process)
            .with_steps(StepModule::single("identity", |_, _| DoNode::pure(99))?);
        ensure!(overridden.eval(&program).await.outcome == Outcome::Done(Value::integer(99)));
        ensure!(executor.eval(&program).await == outcome);
        boot.finish_request_process(process, &outcome).await?;
        ensure!(boot.kernel.processes.steps(process).is_empty());
        ensure!(
            executor.eval(&program).await.outcome == Outcome::Fail(Failure::Cancelled),
            "a retained executor must not invoke code after its process terminates"
        );
        ensure!(weak.upgrade().is_some());
        drop(executor);
        ensure!(weak.upgrade().is_none());
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
                literal_input: Some(Value::null()),
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
    async fn actor_spawn_directory_conflict_leaves_only_terminal_admission_state()
    -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let spec = ActorSpec {
            name: "singleton".into(),
            body: DoNode::pure(Value::null()),
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
        ensure!(boot.drain_cleanup().await.failures.is_empty());
        ensure!(boot.kernel.processes.count() == before_second + 1);
        let rejected = boot
            .kernel
            .processes
            .children_of(boot.root)
            .into_iter()
            .find(|process| *process != first.process)
            .context("missing rejected admission")?;
        ensure!(
            boot.kernel
                .processes
                .status(rejected)
                .is_some_and(ProcessStatus::is_terminal)
        );
        ensure!(!boot.kernel.processes.has_task(rejected));
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
                == Some("cancelled"),
            "actor directory status was not cancelled: {value:?}"
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
                literal_input: Some(Value::string("cleanup".into())),
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
        use std::sync::atomic::{AtomicUsize, Ordering};
        let boot = Bootstrap::in_memory();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let name = boot.register_effect(
            "effect://echo/not-finalize-allowed",
            &[MethodSpec::new(
                "invoke",
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(crate::FnDriver(move |_method, input| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(input)
            })),
        )?;
        let resource_id = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .context("registered finalizer denial effect did not resolve")?;
        let spec = ActorSpec {
            name: "finalizer_denied".into(),
            body: DoNode::pure(Value::null()),
            declared_capabilities: vec!["perform://effect/echo/not-finalize-allowed".into()],
            finalizers: vec![DoNode::op(OperationTemplate {
                target: name,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::string("cleanup".into())),
            })],
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root, xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        ensure!(
            calls.load(Ordering::SeqCst) == 0,
            "denied finalizer reached its driver"
        );
        ensure!(
            facts.iter().any(|fact| fact.resource == resource_id
                && fact.decision == xolotl_types::DecisionTag::Denied),
            "denied finalizer should retain its admission record"
        );
        let finalized = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("missing ProcessFinalized fact")?;
        let map = finalized
            .outcome
            .as_ref()
            .and_then(Value::as_map)
            .context("ProcessFinalized outcome must be a map")?;
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
        ensure!(
            boot.kernel
                .processes
                .begin_finalizing(boot.root, ProcessStatus::Completed)
                == crate::process::FinalizeStart::Started
        );
        let local_target = ResourceName::new(Path::parse(&format!(
            "state://process/{}/cleanup",
            boot.root.get()
        ))?);
        let local_program = DoNode::op(OperationTemplate {
            target: local_target,
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::string("cleanup".into())),
        });
        let local = crate::process::scope_finalizer(
            &boot.kernel.processes,
            boot.root,
            ex.eval(&local_program),
        )
        .await;
        ensure!(
            matches!(local.outcome, xolotl_types::Outcome::Done(_)),
            "current process state write should be allowed in finalizer mode: {local:?}"
        );

        let sibling_target = ResourceName::new(Path::parse("state://process/999999/cleanup")?);
        let sibling_program = DoNode::op(OperationTemplate {
            target: sibling_target,
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::string("cleanup".into())),
        });
        let sibling = crate::process::scope_finalizer(
            &boot.kernel.processes,
            boot.root,
            ex.eval(&sibling_program),
        )
        .await;
        ensure!(
            matches!(
                sibling.outcome,
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
                literal_input: Some(Value::null()),
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
            literal_input: Some(Value::string("hello".into())),
        });
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == xolotl_types::Outcome::Done(Value::string("hello".into())),
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
            literal_input: Some(Value::string("hello".into())),
        });
        match ex.eval(&prog).await.outcome {
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
            literal_input: Some(Value::string("hello".into())),
        });
        match ex.eval(&prog).await.outcome {
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
            literal_input: Some(Value::string("hi".into())),
        });
        match ex.eval(&prog).await.outcome {
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
            literal_input: Some(Value::list(vec![
                Value::string("a".into()),
                Value::string("b".into()),
                Value::string("c".into()),
            ])),
        });
        match ex.eval(&prog).await.outcome {
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
            literal_input: Some(Value::string("ok".into())),
        });
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == xolotl_types::Outcome::Done(Value::string("ok".into())),
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
        let ex = ex.with_steps(StepModule::single("echo_back", |v, _| DoNode::pure(v))?);
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::string("hi".into())),
        })
        .and_then(xolotl_graph::StepRef::new("echo_back"));
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == xolotl_types::Outcome::Done(Value::string("hi".into())),
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
    async fn finalize_marks_cancelled_and_writes_marker() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        // Spawn a child request Process, then finalize it.
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;
        boot.finalize_process(child).await?;
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Cancelled),
            "unfinished child process should be cancelled"
        );
        // The finalize marker is written to state.
        let path = finalized_marker_path(
            child,
            boot.kernel
                .processes
                .lifecycle_execution(child)
                .context("missing lifecycle scope")?,
        )?;
        let marker = boot.kernel.state.read(&path).await?;
        ensure!(marker.is_some(), "finalize marker should be written");
        // Finalization appends a ProcessFinalized Fact to the Fact stream.
        let facts = boot.kernel.facts.facts_of(child)?;
        ensure!(
            facts.iter().any(|f| {
                f.id.position == xolotl_types::NodeId::new(u32::MAX)
                    && f.outcome.as_ref().and_then(Value::as_map).is_some_and(|m| {
                        m.get("event").and_then(Value::as_str) == Some("ProcessFinalized")
                    })
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
        let map = finalized
            .outcome
            .as_ref()
            .and_then(Value::as_map)
            .context("ProcessFinalized outcome must be a map")?;
        ensure!(
            map.get("status").and_then(Value::as_str) == Some("cancelled"),
            "ProcessFinalized status should remain cancelled: {map:?}"
        );
        Ok(())
    }

    #[derive(Default)]
    struct FailingFinalizeFactStore(crate::InMemoryExecutionIdSource);

    impl crate::ExecutionIdSource for FailingFinalizeFactStore {
        fn reserve(
            &self,
            count: std::num::NonZeroU64,
        ) -> Result<crate::ExecutionIdRange, crate::ExecutionIdError> {
            self.0.reserve(count)
        }
    }

    impl crate::fact::FactStore for FailingFinalizeFactStore {
        fn scan(&self, query: crate::FactQuery) -> Result<crate::FactPage, crate::FactError> {
            crate::InMemoryFactStore::new().scan(query)
        }

        fn lookup(
            &self,
            _query: crate::FactLookup,
        ) -> Result<crate::FactLookupResult, crate::FactError> {
            Ok(crate::FactLookupResult::Missing)
        }

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

    impl crate::ExecutionIdSource for FailOnceCompleteFactStore {
        fn reserve(
            &self,
            count: std::num::NonZeroU64,
        ) -> Result<crate::ExecutionIdRange, crate::ExecutionIdError> {
            self.inner.reserve(count)
        }
    }

    impl crate::fact::FactStore for FailOnceCompleteFactStore {
        fn scan(&self, query: crate::FactQuery) -> Result<crate::FactPage, crate::FactError> {
            self.inner.scan(query)
        }

        fn lookup(
            &self,
            query: crate::FactLookup,
        ) -> Result<crate::FactLookupResult, crate::FactError> {
            self.inner.lookup(query)
        }

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
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore::default()));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
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
    async fn retrying_owned_completion_preserves_independent_actor_lifetime() -> anyhow::Result<()>
    {
        let facts = crate::fact::FactSink::new(Arc::new(FailOnceCompleteFactStore::new()));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let parent = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
        let parent_id = parent.id();
        let spec = ActorSpec {
            name: "independent_completion".into(),
            body: DoNode::wait_signal(Path::parse("state://signal/never")?),
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(parent_id, IdentityRef::ROOT, "root", &spec)
            .await?;
        ensure!(
            parent
                .finish(&xolotl_types::ExecutionOutput::new(
                    xolotl_types::Outcome::Done(Value::null()),
                    xolotl_types::TaintSet::pristine()
                ))
                .await
                .is_err()
        );
        let report = boot.drain_cleanup().await;
        ensure!(report.failures.is_empty());
        ensure!(boot.kernel.processes.status(parent_id) == Some(ProcessStatus::Completed));
        ensure!(boot.kernel.processes.status(actor.process) == Some(ProcessStatus::Running));
        boot.finalize_process(parent_id).await?;
        ensure!(boot.kernel.processes.status(actor.process) == Some(ProcessStatus::Cancelled));
        Ok(())
    }

    #[tokio::test]
    async fn finalize_can_retry_after_fact_failure() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailOnceCompleteFactStore::new()));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let effect = boot.register_effect(
            "effect://finalize-retry",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(crate::EchoDriver),
        )?;
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/finalize-retry",
                methods: MethodBitmap::method(0),
            }],
        )?;
        boot.open_for(child, &effect, "perform")?;

        let err = expect_bootstrap_error(boot.finalize_process(child).await)?;
        ensure!(
            matches!(err, BootstrapError::Fact(_)),
            "unexpected first finalize error: {err:?}"
        );
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Finalizing),
            "failed finalize should leave process retryable"
        );

        let (record, revoked) = boot
            .kernel
            .processes
            .finalization_record(child)
            .context("missing retry record")?;
        ensure!(revoked == 1);
        boot.finalize_process(child).await?;
        ensure!(
            boot.kernel.processes.status(child) == Some(xolotl_types::ProcessStatus::Cancelled),
            "retry should preserve the forced cancellation intent"
        );
        ensure!(
            boot.kernel
                .state
                .read(&finalized_marker_path(
                    child,
                    boot.kernel
                        .processes
                        .lifecycle_execution(child)
                        .context("missing lifecycle scope")?
                )?)
                .await?
                .is_some(),
            "retry should write the finalized marker"
        );
        let facts = boot.kernel.facts.facts_of(child)?;
        let committed = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("missing committed record")?;
        ensure!(committed.timestamp == record.timestamp);
        ensure!(committed.outcome == record.outcome);
        ensure!(
            boot.kernel
                .state
                .read(&finalized_marker_path(
                    child,
                    boot.kernel
                        .processes
                        .lifecycle_execution(child)
                        .context("missing lifecycle scope")?
                )?)
                .await?
                == Some(Value::integer(1))
        );
        ensure!(boot.kernel.processes.attached_grants(child).is_empty());
        ensure!(
            facts.iter().any(|fact| fact.id.position == FINALIZED_NODE),
            "retry should record the ProcessFinalized fact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_finalization_preserves_remaining_work_and_wakes_another_owner()
    -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Poll;
        let boot = Bootstrap::in_memory();
        let process = boot.kernel.processes.fresh_id()?;
        let calls = Arc::new([
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ]);
        let modules = (0..3)
            .map(|index| {
                let calls = Arc::clone(&calls);
                let wait = Path::parse("state://signals/interrupted-finalizer")?;
                StepModule::single(format!("step{index}"), move |_, _| {
                    calls[index].fetch_add(1, Ordering::SeqCst);
                    if index == 1 {
                        DoNode::wait_signal(wait.clone())
                    } else {
                        DoNode::pure(Value::null())
                    }
                })
                .map_err(anyhow::Error::from)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut entry = ProcessEntry::new(process, Some(boot.root), IdentityRef::ROOT);
        entry.scope.start();
        entry.steps = StepModule::compose(modules)?;
        entry.on_finalize = (0..3)
            .rev()
            .map(|index| {
                DoNode::pure(Value::null())
                    .and_then(xolotl_graph::StepRef::new(format!("step{index}")))
            })
            .collect();
        boot.kernel.processes.insert(entry);

        let mut first = Box::pin(boot.finish_process_as(process, ProcessStatus::Failed));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        ensure!(calls[0].load(Ordering::SeqCst) == 1 && calls[1].load(Ordering::SeqCst) == 1);
        ensure!(!boot.cancel_process(process)?);
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Finalizing));
        let mut second = Box::pin(boot.finalize_process(process));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(1), second).await??;
        ensure!(calls.iter().all(|calls| calls.load(Ordering::SeqCst) == 1));
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Failed));
        let facts = boot.kernel.facts.facts_of(process)?;
        let fact = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("missing finalization fact")?;
        let record = fact
            .outcome
            .as_ref()
            .and_then(Value::as_map)
            .context("invalid lifecycle record")?;
        ensure!(
            record
                .get("finalizer_failure_count")
                .and_then(Value::as_int)
                == Some(1)
        );
        let failures = record
            .get("finalizer_failures")
            .and_then(Value::as_list)
            .context("missing failures")?;
        let failure = failures
            .first()
            .and_then(Value::as_map)
            .context("invalid failure")?;
        ensure!(failure.get("index").and_then(Value::as_int) == Some(1));
        ensure!(
            failure
                .get("failure")
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains("interrupted"))
        );
        boot.finalize_process(process).await?;
        ensure!(calls.iter().all(|calls| calls.load(Ordering::SeqCst) == 1));
        Ok(())
    }

    #[test]
    fn gateway_audit_fact_failure_does_not_insert_audit_process() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore::default()));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
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
        let anchor = boot.kernel.processes.fresh_id()?;
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
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
        let anchor = boot.kernel.processes.fresh_id()?;
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
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
        let anchor = boot.kernel.processes.fresh_id()?;
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
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
        let anchor = boot.kernel.processes.fresh_id()?;
        let mut entry = ProcessEntry::new(anchor, Some(boot.root), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
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
    async fn separate_evaluations_record_distinct_effects() -> anyhow::Result<()> {
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
                Ok(Value::integer(7))
            })),
        )?;
        let handle = boot.open_for(boot.root, &name, "perform")?;

        // A program whose Operation output is consumed (so a Fact is recorded).
        let prog = DoNode::Op(OperationTemplate {
            target: name.clone(),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::null()),
        })
        .and_then(xolotl_graph::StepRef::new("use_it"));

        let steps = StepModule::single("use_it", |v, _| DoNode::pure(v))?;
        let ex1 = boot
            .kernel
            .executor_for(boot.root)
            .with_steps(steps.clone());
        ex1.bind_handle(name.clone(), handle);
        let first = ex1.eval(&prog).await;
        ensure!(
            first.outcome == xolotl_types::Outcome::Done(Value::integer(7)),
            "unexpected first run outcome: {first:?}"
        );
        ensure!(
            CALLS.load(Ordering::SeqCst) == 1,
            "effect fires on the first run"
        );

        let repeated = ex1.eval(&prog).await;
        ensure!(repeated == first);
        let handle2 = boot.open_for(boot.root, &name, "perform")?;
        let ex2 = boot.kernel.executor_for(boot.root).with_steps(steps);
        ex2.bind_handle(name.clone(), handle2);
        let out = ex2.eval(&prog).await;

        ensure!(
            CALLS.load(Ordering::SeqCst) == 3,
            "each independent evaluation must execute its effect"
        );
        ensure!(
            out.outcome == xolotl_types::Outcome::Done(Value::integer(7)),
            "unexpected independent evaluation result"
        );
        let facts = boot.kernel.facts.facts_of(boot.root)?;
        ensure!(facts.len() == 3);
        ensure!(
            facts
                .iter()
                .map(|fact| fact.id)
                .collect::<BTreeSet<_>>()
                .len()
                == 3
        );
        ensure!(
            facts
                .iter()
                .all(|fact| fact.id.position == facts[0].id.position)
        );
        ensure!(
            facts
                .iter()
                .all(|fact| fact.id.invocation == facts[0].id.invocation)
        );
        ensure!(
            facts
                .iter()
                .map(|fact| fact.id.execution)
                .collect::<BTreeSet<_>>()
                .len()
                == 3
        );
        Ok(())
    }
}
