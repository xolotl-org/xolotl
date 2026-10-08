//! Bootstrap: assemble a ready-to-use kernel through an ordered startup
//! sequence.
//!
//! Bootstrap sequence: parse config, open the state backend, mount the
//! FactSink, build registries, create the root/system Process, install
//! in-process Drivers, start Gateways, and mark
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
use crate::open::{OpenError, OpenRequest, prepare_open};
use crate::process::{ProcessEntry, TaskAttachment};
use crate::registry::AdmissionError;
use crate::step::StepModule;
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use xolotl_types::audit::{GATEWAY_AUDIT_NODE, gateway_audit_event};
use xolotl_types::{
    Binding, CapError, Capability, ConstraintSet, DriverRef, Expiry, Fact, Grant, GrantMethods,
    GrantRights, HandleId, IdentityRef, Interface, InterfaceFamily, InterfaceSet, Metadata, Method,
    MethodBitmap, ModalitySet, OutputModeSet, Path, PathError, ProcessId, ProcessStatus, Purity,
    Resource, ResourceDescriptor, ResourceKind, ResourceName, ResourceSelector, RightFlags, Rights,
    SchemaId, Transport,
};

mod request;
pub use request::{
    ProcessCleanupFailure, ProcessCleanupReport, RequestFinishError, RequestProcess,
};
mod actor;
pub(crate) mod finalize;

/// A ready kernel plus the root Process id. The root holds an
/// omnipotent grant; everything else is attenuated from it.
#[derive(Clone)]
pub struct Bootstrap {
    /// Assembled kernel instance.
    kernel: Kernel,
    /// Root/system process seeded during bootstrap.
    root: ProcessId,
    /// Detached request cleanup must release its Kernel captures before a
    /// graceful host can reopen storage in the same process.
    cleanup_tasks: std::sync::Arc<request::DetachedCleanupTasks>,
}

/// Redacted gateway-layer audit metadata, separate from Operation input.
/// The application owns its meaning and redaction; the kernel records it
/// without interpreting authentication or authorization claims.
pub struct GatewayAudit<'a> {
    /// Nonempty application event name, such as `console_login`.
    pub event: &'a str,
    /// Caller-supplied account or principal label, when known.
    pub username: Option<&'a str>,
    /// Redacted source address or peer label.
    pub source_addr: Option<&'a str>,
    /// Nonempty, stable outcome tag for the event.
    pub outcome: &'a str,
    /// Additional redacted, application-owned metadata, retained without
    /// interpretation or promotion into the common event fields.
    pub details: Option<xolotl_types::Value>,
}

/// Request grant template attached to a spawned request Process.
pub struct RequestGrantTemplate<'a> {
    /// Capability selector literal for the request grant.
    pub literal: &'a str,
    /// Explicit method and propagation rights, attenuated against the anchor.
    pub rights: GrantRights,
}

/// Parsed request grant template attached to a spawned request Process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRequestGrantTemplate {
    /// Capability selector for the request grant.
    pub selector: ResourceSelector,
    /// Explicit method and propagation rights, attenuated against the anchor.
    pub rights: GrantRights,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRequestGrantTemplate {
    selector: ResourceSelector,
    rights: Option<GrantRights>,
}

#[derive(Clone, Copy)]
struct RequestGrantView<'a> {
    selector: &'a ResourceSelector,
    rights: Option<&'a GrantRights>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PlannedRequestGrant {
    selector: ResourceSelector,
    rights: GrantRights,
    constraints: ConstraintSet,
    expires: Expiry,
}

// A Console may admit 16,384 distinct request templates. The Kernel also
// bounds any additional alternatives produced by overlapping parent grants.
const MAX_REQUEST_GRANT_ALTERNATIVES: usize = 16_384;

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
    /// The caller identity is not registered in this Kernel's directory.
    #[error("identity admission failed: {0}")]
    Identity(#[from] crate::identity::IdentityError),
    /// A request grant selector is not covered by any grant the authority
    /// anchor holds. No Process is created.
    #[error("request grant {literal:?} exceeds authority anchor ceiling")]
    CapabilityCeiling {
        /// Request grant literal that exceeded the anchor.
        literal: String,
    },
    /// Attenuation would attach more distinct grants than one Process may hold.
    #[error("request grant alternatives exceed limit {limit}")]
    RequestGrantLimit {
        /// Maximum number of distinct attached grants.
        limit: usize,
    },
    /// The requested Process does not exist.
    #[error("process {process} not found")]
    NoSuchProcess {
        /// Process id supplied by the caller.
        process: ProcessId,
    },
    /// The cleanup ticket belongs to a different kernel process table.
    #[error("cleanup ticket for process {process} belongs to a different process table")]
    CleanupTicketMismatch {
        /// Process named by the mismatched ticket.
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
    /// The caller stopped waiting; cleanup and already accepted effects remain owned.
    #[error("cleanup observation deadline expired for process {process}")]
    CleanupWaitExpired {
        /// Original process whose cleanup may still complete.
        process: ProcessId,
    },
    /// Background process creation requires an available host task spawner.
    #[error("process {process} requires an available host task spawner")]
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
    /// No host blocking worker accepted the terminal record before it changed state.
    #[error("terminal record scheduling failed: {0}")]
    TerminalRecordScheduling(#[source] crate::host::BlockingSpawnError),
    /// The accepted worker ended without confirming its terminal record result.
    #[error("terminal record result unknown; retry after reconciling its fact: {0}")]
    TerminalRecordUnknown(#[source] crate::host::BlockingTaskError),
    /// A host-owned process result could not be published; cleanup remains retryable.
    #[error("process result publication failed: {0}")]
    Publication(#[source] Box<xolotl_types::Failure>),
    /// An execution identity could not be reserved before dispatch or cleanup.
    #[error("execution identity allocation failed: {0}")]
    ExecutionId(#[from] crate::ExecutionIdError),
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
    /// Capability category required to open this method.
    pub authority: xolotl_types::MethodAuthority,
    /// Method purity used to derive replay class.
    pub purity: Purity,
    /// Output modes supported by this method.
    pub supports: OutputModeSet,
    /// Whether the method accepts explicit list-shaped batches.
    pub batchable: bool,
    /// Whether the method observes external state.
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

    /// Create a method with explicit authority and output support.
    pub const fn new(
        name: &'static str,
        authority: xolotl_types::MethodAuthority,
        purity: Purity,
        supports: OutputModeSet,
    ) -> Self {
        Self {
            name,
            authority,
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
}

impl Bootstrap {
    /// The assembled kernel whose process table owns this bootstrap's root.
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    /// The root/system process initialized once in this kernel's process table.
    pub fn root(&self) -> ProcessId {
        self.root
    }

    /// Build an in-memory kernel, create the root Process, and grant it the
    /// omnipotent capability (`*://**`).
    #[cfg(any(test, feature = "memory"))]
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
        let root = kernel.processes().initialize_root(|root| {
            kernel.registry().register_grant(Grant {
                id: kernel.registry().next_grant_id(),
                holder: root,
                selector: ResourceSelector::all(),
                rights: GrantRights::new(GrantMethods::all(), RightFlags::all()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        });

        Bootstrap {
            kernel,
            root,
            cleanup_tasks: std::sync::Arc::default(),
        }
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
        if methods.len() != 1
            || methods[0].name != "invoke"
            || methods[0].authority != xolotl_types::MethodAuthority::Perform
        {
            return Err(BootstrapError::InvalidMethodSpec {
                resource: path.to_string(),
                reason: "Callable effect resources expose one public `invoke` method with perform authority"
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
        let reg = self.kernel().registry();
        let target = name.path();
        let capability = Capability::try_new(
            "perform",
            target.scheme(),
            target.segments().iter().map(|segment| segment.as_str()),
            None,
        )
        .and_then(|capability| match target.cluster() {
            Some(cluster) => capability.try_with_cluster(cluster),
            None => Ok(capability),
        })
        .map_err(|source| BootstrapError::Selector {
            literal: path.to_string(),
            source,
        })?;
        let selector = ResourceSelector {
            pattern: capability,
        };
        let iface_id = reg.next_interface_id();
        let method_descs = build_methods(methods, cost, false);
        let interfaces = InterfaceSet::new(vec![iface_id]);
        let interface = Interface {
            id: iface_id,
            family: InterfaceFamily::Callable,
            methods: method_descs,
            laws: Vec::new(),
        };

        let driver_id = reg.next_driver_id();
        let driver = DriverDescriptor {
            id: driver_id,
            name: path.to_string(),
            implements: interfaces.clone(),
            transport: Transport::InProcess,
            driver,
        };

        let binding_id = reg.next_binding_id();
        let binding = Binding {
            id: binding_id,
            selector,
            interfaces: interfaces.clone(),
            driver: DriverRef {
                id: driver_id,
                name: path.to_string(),
            },
            endpoint: None,
            generation,
        };

        let rid = reg.next_resource_id();
        let resource = Resource {
            id: rid,
            descriptor: ResourceDescriptor {
                name: name.clone(),
                kind: ResourceKind::Effect,
                addressing: xolotl_types::ResourceAddressing::Exact,
                metadata,
            },
            interfaces,
            binding: binding_id,
        };
        if relink_existing {
            reg.upsert_resource_bundle(vec![interface], driver, binding, resource, true)?;
        } else {
            reg.admit_resource_bundle(vec![interface], driver, binding, resource, true)?;
        }
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

    /// Register a State collection at a concrete subtree root, e.g.
    /// `state://fact`, with an explicit grant selector pattern such as
    /// `read://state/fact/**`. This convenience method declares Prefix
    /// addressing; use [`Self::register_resource`] to choose another kind or
    /// addressing mode. The bundle publishes atomically.
    pub fn register_subtree_resource_at(
        &self,
        root_path: &str,
        selector_pattern: &str,
        family: InterfaceFamily,
        methods: &[MethodSpec],
        driver: DynDriver,
    ) -> Result<ResourceName, BootstrapError> {
        let name =
            ResourceName::new(
                Path::parse(root_path).map_err(|source| BootstrapError::Path {
                    literal: root_path.to_string(),
                    source,
                })?,
            );
        self.register_resource_inner(
            ResourceDescriptor {
                name,
                kind: ResourceKind::State,
                addressing: xolotl_types::ResourceAddressing::Prefix,
                metadata: Metadata::default(),
            },
            selector_pattern,
            family,
            methods,
            driver,
            true,
        )
    }

    /// Register one host-defined Resource with explicit classification and
    /// addressing. A Prefix resource handles descendants only when no closer
    /// explicit registration exists. Authorization uses the requested path,
    /// not merely this descriptor's root. All descriptions publish atomically.
    pub fn register_resource(
        &self,
        descriptor: ResourceDescriptor,
        selector_pattern: &str,
        family: InterfaceFamily,
        methods: &[MethodSpec],
        driver: DynDriver,
    ) -> Result<ResourceName, BootstrapError> {
        self.register_resource_inner(descriptor, selector_pattern, family, methods, driver, false)
    }

    fn register_resource_inner(
        &self,
        descriptor: ResourceDescriptor,
        selector_pattern: &str,
        family: InterfaceFamily,
        methods: &[MethodSpec],
        driver: DynDriver,
        state_backed: bool,
    ) -> Result<ResourceName, BootstrapError> {
        let name = descriptor.name.clone();
        let root_path = name.path().to_string();
        let selector = ResourceSelector::parse(selector_pattern).map_err(|source| {
            BootstrapError::Selector {
                literal: selector_pattern.to_string(),
                source,
            }
        })?;
        let reg = self.kernel().registry();
        let iface_id = reg.next_interface_id();
        let method_descs = build_methods(methods, Default::default(), state_backed);
        let interfaces = InterfaceSet::new(vec![iface_id]);
        let interface = Interface {
            id: iface_id,
            family,
            methods: method_descs,
            laws: Vec::new(),
        };

        let driver_id = reg.next_driver_id();
        let driver = DriverDescriptor {
            id: driver_id,
            name: root_path.clone(),
            implements: interfaces.clone(),
            transport: Transport::InProcess,
            driver,
        };

        let binding_id = reg.next_binding_id();
        let binding = Binding {
            id: binding_id,
            selector,
            interfaces: interfaces.clone(),
            driver: DriverRef {
                id: driver_id,
                name: root_path,
            },
            endpoint: None,
            generation: 1,
        };

        let rid = reg.next_resource_id();
        reg.admit_resource_bundle(
            vec![interface],
            driver,
            binding,
            Resource {
                id: rid,
                descriptor,
                interfaces,
                binding: binding_id,
            },
            true,
        )?;
        Ok(name)
    }

    /// Open a handle for `process` against a registered resource, requesting
    /// every method declared under `verb`.
    pub fn open_for(
        &self,
        process: ProcessId,
        name: &ResourceName,
        verb: &str,
    ) -> Result<HandleId, OpenError> {
        let acting = self
            .kernel()
            .processes()
            .identity(process)
            .ok_or(OpenError::NoSuchProcess(process))?;
        self.open_for_as(process, acting, name, verb)
    }

    /// Open only one named method for a process. This preserves a narrow
    /// request grant when other methods share the same authority category.
    pub fn open_for_method(
        &self,
        process: ProcessId,
        name: &ResourceName,
        verb: &str,
        method: &str,
    ) -> Result<HandleId, OpenError> {
        let acting = self
            .kernel()
            .processes()
            .identity(process)
            .ok_or(OpenError::NoSuchProcess(process))?;
        self.open_for_as_method(process, acting, name, verb, method)
    }

    /// Open one named method while retaining an explicit acting identity.
    pub fn open_for_as_method(
        &self,
        process: ProcessId,
        acting: IdentityRef,
        name: &ResourceName,
        verb: &str,
        method: &str,
    ) -> Result<HandleId, OpenError> {
        self.open_for_as_selected(process, acting, name, verb, Some(method))
    }

    /// Open a process-owned handle for a particular acting identity, requesting
    /// every method declared under `verb`.
    ///
    /// The handle retains this identity in its frozen open-time policy. The
    /// executing `Acting` scope must still pass its own `act-as` check against
    /// the value entering that scope; opening a handle cannot authorize entry.
    /// Use this Kernel's identity directory to resolve an `Acting` path.
    pub fn open_for_as(
        &self,
        process: ProcessId,
        acting: IdentityRef,
        name: &ResourceName,
        verb: &str,
    ) -> Result<HandleId, OpenError> {
        self.open_for_as_selected(process, acting, name, verb, None)
    }

    fn open_for_as_selected(
        &self,
        process: ProcessId,
        acting: IdentityRef,
        name: &ResourceName,
        verb: &str,
        method: Option<&str>,
    ) -> Result<HandleId, OpenError> {
        if self.kernel().processes().identity(process).is_none() {
            return Err(OpenError::NoSuchProcess(process));
        }
        self.kernel().identities().verify(acting)?;
        let resource_id = self.kernel().registry().resolve_resource(name)?;
        let (methods, selected) = if let Some(method) = method {
            let (index, installed) = self
                .kernel()
                .registry()
                .resource_method(resource_id, method)
                .ok_or(OpenError::MethodContractChanged)?;
            if installed.authority.verb() != verb {
                return Err(OpenError::MethodAuthorityMismatch(verb.into()));
            }
            (MethodBitmap::method(index), Some((index, method)))
        } else {
            (
                self.kernel()
                    .registry()
                    .method_bitmap_for_verb(resource_id, verb),
                None,
            )
        };
        let attached_grants = self.kernel().processes().attached_grants(process);
        let prepared = prepare_open(
            self.kernel().registry(),
            OpenRequest {
                process,
                resource: resource_id,
                verb: verb.to_string(),
                // Ordinary effect/state opens request only method authority.
                // Propagation rights require an explicit host request.
                rights: Rights::new(methods, RightFlags::empty()),
                acting,
                // Carry the concrete requested path so prefix-resolved Resources
                // (state://**) bind the real path on the handle.
                requested_path: Some(name.path().clone()),
                now_millis: self.kernel().host_runtime().now_millis(),
            },
            &attached_grants,
        )?;
        // A resource may be relinked between the name lookup and open
        // preparation. Verify the frozen dispatch contract before installing
        // the handle; installation itself rejects any later registry change.
        if let Some((index, method)) = selected
            && !prepared.driver_plan().methods().any(|(_, entry)| {
                entry.contract.method_index == index
                    && entry.declaration().is_some_and(|frozen| {
                        frozen.name == method && frozen.authority.verb() == verb
                    })
            })
        {
            return Err(OpenError::MethodContractChanged);
        }
        prepared.install_for(
            &mut self.kernel().handles().write(),
            self.kernel().processes(),
        )
    }

    /// Return the method bitmap selected by a capability verb for a resource.
    pub fn request_method_bitmap(
        &self,
        name: &ResourceName,
        verb: &str,
    ) -> Result<MethodBitmap, OpenError> {
        let resource_id = self.kernel().registry().resolve_resource(name)?;
        Ok(self
            .kernel()
            .registry()
            .method_bitmap_for_verb(resource_id, verb))
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
                        rights: Some(grant.rights.clone()),
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
                rights: Some(grant.rights.clone()),
            })
            .collect();
        self.spawn_request_process_under_inner(anchor, identity, parsed, steps)
    }

    fn spawn_request_process_under_inner(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: Vec<ParsedRequestGrantTemplate>,
        steps: StepModule,
    ) -> Result<ProcessId, BootstrapError> {
        let entry = self.prepare_request_process_entry(anchor, identity, grants, steps)?;
        let child = entry.scope.process();
        self.kernel().processes().admit_child(entry)?;
        Ok(child)
    }

    fn prepare_request_process_entry(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        mut grants: Vec<ParsedRequestGrantTemplate>,
        steps: StepModule,
    ) -> Result<ProcessEntry, BootstrapError> {
        self.kernel().identities().verify(identity)?;
        let child = self.kernel().processes().fresh_id()?;
        for grant in &mut grants {
            xolotl_graph::bind_process_self_capability(&mut grant.selector.pattern, child);
        }
        let planned = self.plan_request_grants(anchor, &grants)?;
        let mut entry = self.request_process_entry(child, anchor, identity, planned);
        entry.steps = steps;
        entry.scope.start();
        Ok(entry)
    }

    fn plan_request_grants(
        &self,
        anchor: ProcessId,
        grants: &[ParsedRequestGrantTemplate],
    ) -> Result<Vec<PlannedRequestGrant>, BootstrapError> {
        self.plan_request_grant_views(
            anchor,
            grants.iter().map(|grant| RequestGrantView {
                selector: &grant.selector,
                rights: grant.rights.as_ref(),
            }),
        )
    }

    fn plan_request_grant_views<'a>(
        &self,
        anchor: ProcessId,
        grants: impl IntoIterator<Item = RequestGrantView<'a>>,
    ) -> Result<Vec<PlannedRequestGrant>, BootstrapError> {
        match self.kernel().processes().status(anchor) {
            None => return Err(BootstrapError::NoSuchProcess { process: anchor }),
            Some(status) if status.is_terminal() || status == ProcessStatus::Finalizing => {
                return Err(BootstrapError::ProcessUnavailable { process: anchor });
            }
            Some(_) => {}
        }
        let now_millis = self.kernel().host_runtime().now_millis();
        let mut anchor_grants = self.kernel().registry().grants_of(anchor);
        anchor_grants.extend(self.kernel().processes().attached_grants(anchor));
        Self::plan_grants_from_views(
            &anchor_grants,
            grants,
            now_millis,
            MAX_REQUEST_GRANT_ALTERNATIVES,
        )
    }

    #[cfg(test)]
    fn plan_grants_from(
        anchor_grants: &[Grant],
        grants: &[ParsedRequestGrantTemplate],
        now_millis: i64,
    ) -> Result<Vec<PlannedRequestGrant>, BootstrapError> {
        Self::plan_grants_from_with_limit(
            anchor_grants,
            grants,
            now_millis,
            MAX_REQUEST_GRANT_ALTERNATIVES,
        )
    }

    #[cfg(test)]
    fn plan_grants_from_with_limit(
        anchor_grants: &[Grant],
        grants: &[ParsedRequestGrantTemplate],
        now_millis: i64,
        limit: usize,
    ) -> Result<Vec<PlannedRequestGrant>, BootstrapError> {
        Self::plan_grants_from_views(
            anchor_grants,
            grants.iter().map(|grant| RequestGrantView {
                selector: &grant.selector,
                rights: grant.rights.as_ref(),
            }),
            now_millis,
            limit,
        )
    }

    fn plan_grants_from_views<'a>(
        anchor_grants: &[Grant],
        grants: impl IntoIterator<Item = RequestGrantView<'a>>,
        now_millis: i64,
        limit: usize,
    ) -> Result<Vec<PlannedRequestGrant>, BootstrapError> {
        let mut unique = HashSet::new();
        for grant in grants {
            // Every covering parent is a separate OR candidate; choosing the
            // first one would make the result depend on grant insertion order.
            let mut covered = false;
            for parent in anchor_grants {
                if parent.expires.is_expired(now_millis)
                    || !parent
                        .selector
                        .pattern
                        .covers_cap_pattern(&grant.selector.pattern)
                {
                    continue;
                }
                let inherited;
                let requested = if let Some(rights) = grant.rights {
                    rights
                } else {
                    inherited =
                        GrantRights::new(parent.rights.methods.clone(), RightFlags::empty());
                    &inherited
                };
                if requested.is_empty() || !requested.is_subset_of(&parent.rights) {
                    continue;
                }
                covered = true;
                unique.insert(PlannedRequestGrant {
                    selector: grant.selector.clone(),
                    rights: requested.clone(),
                    constraints: Self::derived_grant_constraints(
                        parent,
                        grant.selector.pattern.predicate.as_ref(),
                    ),
                    expires: parent.expires,
                });
                if unique.len() > limit {
                    return Err(BootstrapError::RequestGrantLimit { limit });
                }
            }
            if !covered {
                return Err(BootstrapError::CapabilityCeiling {
                    literal: grant.selector.pattern.to_string(),
                });
            }
        }
        let mut planned: Vec<_> = unique.into_iter().collect();
        planned.sort_unstable_by(Self::compare_planned_grants);
        Ok(planned)
    }

    fn compare_request_selectors(
        left: &ResourceSelector,
        right: &ResourceSelector,
    ) -> std::cmp::Ordering {
        let left = &left.pattern;
        let right = &right.pattern;
        left.verb
            .cmp(&right.verb)
            .then_with(|| left.cluster.cmp(&right.cluster))
            .then_with(|| left.scheme.cmp(&right.scheme))
            .then_with(|| left.segments.cmp(&right.segments))
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| left.predicate.cmp(&right.predicate))
    }

    fn compare_planned_grants(
        left: &PlannedRequestGrant,
        right: &PlannedRequestGrant,
    ) -> std::cmp::Ordering {
        Self::compare_request_selectors(&left.selector, &right.selector)
            .then_with(|| left.rights.methods.cmp(&right.rights.methods))
            .then_with(|| left.rights.flags.bits().cmp(&right.rights.flags.bits()))
            .then_with(|| left.constraints.cmp(&right.constraints))
            .then_with(|| left.expires.cmp(&right.expires))
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
                id: self.kernel().processes().fresh_attached_grant_id(),
                holder: child,
                selector: grant.selector,
                rights: grant.rights,
                constraints: grant.constraints,
                expires: grant.expires,
            });
        }
        entry
    }

    fn derived_grant_constraints(
        parent: &Grant,
        child_predicate: Option<&xolotl_types::Predicate>,
    ) -> ConstraintSet {
        let mut predicates = Vec::with_capacity(
            usize::from(parent.selector.pattern.predicate.is_some())
                + parent.constraints.predicates.len(),
        );
        if let Some(predicate) = parent.selector.pattern.predicate.clone()
            && Some(&predicate) != child_predicate
        {
            predicates.push(predicate);
        }
        predicates.extend(
            parent
                .constraints
                .predicates
                .iter()
                .filter(|predicate| Some(*predicate) != child_predicate)
                .cloned(),
        );
        predicates.sort_unstable();
        predicates.dedup();
        ConstraintSet { predicates }
    }

    /// Record a gateway-layer application audit Fact under the root process.
    /// The caller must redact credentials and other secrets before submission.
    /// Identity labels and details remain application metadata; this method
    /// neither verifies them nor derives authentication or authorization from them.
    /// Empty event or outcome labels are rejected before Fact delivery.
    pub fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), crate::FactError> {
        if !self.kernel().facts().is_enabled() {
            return Err(crate::FactError::new(
                "observation storage is not installed".into(),
            ));
        }
        let execution = self
            .kernel()
            .execution_ids()
            .allocate()
            .map_err(|error| crate::FactError::new(error.to_string()))?;
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
        if let Some(details) = audit.details {
            outcome.insert("details".into(), details);
        }

        let fact = Fact {
            id: xolotl_types::OperationId::new(
                process,
                execution,
                xolotl_types::InvocationId::new(0),
                GATEWAY_AUDIT_NODE,
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            caller_identity: Some(IdentityRef::ROOT),
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
            timestamp: xolotl_types::Timestamp::millis(self.kernel().host_runtime().now_millis()),
        };
        if gateway_audit_event(&fact).is_none() {
            return Err(crate::FactError::new(
                "invalid gateway audit event envelope".into(),
            ));
        }
        self.kernel().facts().complete(fact)
    }

    /// Record a service observation only when the host installed observation
    /// storage. Once selected, recording failures remain visible to the service.
    /// This is not appropriate for an unconditionally required recording barrier.
    pub fn record_optional_gateway_audit(
        &self,
        audit: GatewayAudit<'_>,
    ) -> Result<(), crate::FactError> {
        if !self.kernel().facts().is_enabled() {
            return Ok(());
        }
        self.record_gateway_audit(audit)
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
            // agree for this single-interface resource. Multi-interface hosts
            // must assign ids unique across each resource's interface set.
            id: xolotl_types::MethodId::new(i as u64),
            name: spec.name.to_string(),
            authority: spec.authority,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::EchoDriver;
    use crate::registry::ResolveError;
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

    #[test]
    fn effect_relink_updates_metadata_without_retaining_old_registrations() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let registry = boot.kernel().registry();
        let methods = [MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )];
        let name = boot.register_or_relink_effect_with_cost(
            "effect://relink/example",
            &methods,
            Arc::new(EchoDriver),
            xolotl_types::CostModel::default(),
            Metadata {
                provider_id: Some("provider-v1".into()),
                ..Metadata::default()
            },
            1,
        )?;
        let resource_id = registry.resolve_resource(&name)?;
        let counts = registry.counts();

        for generation in 2..=16 {
            let metadata = Metadata {
                provider_id: Some(format!("provider-v{generation}")),
                tags: vec![format!("revision-{generation}")],
                ..Metadata::default()
            };
            boot.register_or_relink_effect_with_cost(
                "effect://relink/example",
                &methods,
                Arc::new(EchoDriver),
                xolotl_types::CostModel::default(),
                metadata.clone(),
                generation,
            )?;
            ensure!(registry.resolve_resource(&name)? == resource_id);
            ensure!(
                registry
                    .resource(resource_id)
                    .context("relinked resource missing")?
                    .descriptor
                    .metadata
                    == metadata
            );
            let after = registry.counts();
            ensure!(after.resources == counts.resources);
            ensure!(after.interfaces == counts.interfaces);
            ensure!(after.drivers == counts.drivers);
            ensure!(after.bindings == counts.bindings);
        }

        ensure!(
            boot.register_or_relink_effect_with_cost(
                "effect://relink/example",
                &methods,
                Arc::new(EchoDriver),
                xolotl_types::CostModel::default(),
                Metadata::default(),
                1,
            )
            .is_err()
        );
        ensure!(registry.counts() == counts);
        Ok(())
    }

    #[test]
    fn duplicate_effect_registration_publishes_no_partial_bundle() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let registry = boot.kernel().registry();
        let method = MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        );
        let name = boot.register_effect(
            "effect://assembly/duplicate",
            &[method],
            Arc::new(EchoDriver),
        )?;
        let resource_id = registry.resolve_resource(&name)?;
        let counts = registry.counts();

        let result = boot.register_effect(
            "effect://assembly/duplicate",
            &[method],
            Arc::new(EchoDriver),
        );
        ensure!(matches!(
            result,
            Err(BootstrapError::Admission(
                AdmissionError::DuplicateResourceName(_)
            ))
        ));
        ensure!(registry.resolve_resource(&name)? == resource_id);
        ensure!(registry.counts() == counts);
        Ok(())
    }

    #[test]
    fn effect_relink_reclaims_a_plain_registration_bundle() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let registry = boot.kernel().registry();
        let method = MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        );
        let name = boot.register_effect(
            "effect://assembly/plain-relink",
            &[method],
            Arc::new(EchoDriver),
        )?;
        let id = registry.resolve_resource(&name)?;
        let counts = registry.counts();

        boot.register_or_relink_effect_with_cost(
            "effect://assembly/plain-relink",
            &[method],
            Arc::new(EchoDriver),
            xolotl_types::CostModel::default(),
            Metadata::default(),
            2,
        )?;
        ensure!(registry.resolve_resource(&name)? == id);
        ensure!(registry.resource_binding_generation(&name)? == 2);
        ensure!(registry.counts() == counts);
        Ok(())
    }

    #[test]
    fn concurrent_effect_registration_and_relink_publish_complete_bundles() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let registry = boot.kernel().registry();
        let baseline = registry.counts();
        let method = MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        );
        let start = std::sync::Barrier::new(8);
        let registrations = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    let boot = boot.clone();
                    let start = &start;
                    scope.spawn(move || {
                        start.wait();
                        boot.register_effect(
                            "effect://assembly/concurrent",
                            &[method],
                            Arc::new(EchoDriver),
                        )
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker.join().map_err(|payload| {
                        anyhow::Error::msg(panic_payload_message("effect registration", payload))
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })?;
        ensure!(registrations.iter().filter(|result| result.is_ok()).count() == 1);
        ensure!(registrations.iter().all(|result| {
            result.is_ok()
                || matches!(
                    result,
                    Err(BootstrapError::Admission(
                        AdmissionError::DuplicateResourceName(_)
                    ))
                )
        }));
        let name = ResourceName::new(Path::parse("effect://assembly/concurrent")?);
        let id = registry.resolve_resource(&name)?;
        let installed = registry.counts();
        ensure!(installed.resources == baseline.resources + 1);
        ensure!(installed.interfaces == baseline.interfaces + 1);
        ensure!(installed.drivers == baseline.drivers + 1);
        ensure!(installed.bindings == baseline.bindings + 1);

        let start = std::sync::Barrier::new(8);
        let relinks = std::thread::scope(|scope| {
            let workers: Vec<_> = (2..=9)
                .map(|generation| {
                    let boot = boot.clone();
                    let start = &start;
                    scope.spawn(move || {
                        start.wait();
                        boot.register_or_relink_effect_with_cost(
                            "effect://assembly/concurrent",
                            &[method],
                            Arc::new(EchoDriver),
                            xolotl_types::CostModel::default(),
                            Metadata::default(),
                            generation,
                        )
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker.join().map_err(|payload| {
                        anyhow::Error::msg(panic_payload_message("effect relink", payload))
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })?;
        ensure!(relinks.iter().any(Result::is_ok));
        ensure!(relinks.iter().all(|result| {
            result.is_ok()
                || matches!(
                    result,
                    Err(BootstrapError::Admission(
                        AdmissionError::BindingGenerationRegressed { .. }
                    ))
                )
        }));
        ensure!(registry.resolve_resource(&name)? == id);
        ensure!(registry.resource_binding_generation(&name)? == 9);
        ensure!(registry.counts() == installed);
        Ok(())
    }

    #[test]
    fn subtree_registration_failure_publishes_no_partial_bundle() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let registry = boot.kernel().registry();
        let baseline = registry.counts();
        let root = "state://subtree/atomic";
        let selector = "read://state/subtree/atomic/**";
        let method = MethodSpec::new(
            "read",
            xolotl_types::MethodAuthority::Read,
            Purity::Pure,
            OutputModeSet::UNARY,
        );

        let invalid_path = boot.register_subtree_resource_at(
            "not a path",
            selector,
            InterfaceFamily::Value,
            &[method],
            Arc::new(EchoDriver),
        );
        ensure!(matches!(invalid_path, Err(BootstrapError::Path { .. })));
        ensure!(registry.counts() == baseline);

        let invalid_selector = boot.register_subtree_resource_at(
            root,
            "not a selector",
            InterfaceFamily::Value,
            &[method],
            Arc::new(EchoDriver),
        );
        ensure!(matches!(
            invalid_selector,
            Err(BootstrapError::Selector { .. })
        ));
        ensure!(registry.counts() == baseline);

        let invalid_methods = boot.register_subtree_resource_at(
            root,
            selector,
            InterfaceFamily::Value,
            &[method, method],
            Arc::new(EchoDriver),
        );
        ensure!(matches!(invalid_methods, Err(BootstrapError::Admission(_))));
        ensure!(registry.counts() == baseline);

        let name = ResourceName::new(Path::parse(root)?);
        ensure!(matches!(
            registry.resolve_resource(&name),
            Err(ResolveError::NoSuchResource(_))
        ));
        ensure!(
            boot.register_subtree_resource_at(
                root,
                selector,
                InterfaceFamily::Value,
                &[method],
                Arc::new(EchoDriver),
            )? == name
        );
        let registered = registry.counts();
        ensure!(registered.resources == baseline.resources + 1);
        ensure!(registered.interfaces == baseline.interfaces + 1);
        ensure!(registered.drivers == baseline.drivers + 1);
        ensure!(registered.bindings == baseline.bindings + 1);

        let duplicate = boot.register_subtree_resource_at(
            root,
            selector,
            InterfaceFamily::Value,
            &[method],
            Arc::new(EchoDriver),
        );
        ensure!(matches!(duplicate, Err(BootstrapError::Admission(_))));
        ensure!(registry.counts() == registered);
        Ok(())
    }

    async fn wait_actor_status(
        boot: &Bootstrap,
        directory: &Path,
        status: &str,
    ) -> anyhow::Result<Value> {
        for _ in 0..100 {
            if let Some(value) = boot.kernel().state().read(directory).await?
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
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
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
        let boot = crate::fact::testing::observing_bootstrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let name = boot.register_effect(
            "effect://echo/actor-body",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )
            .finalize_allowed()],
            Arc::new(crate::driver::FnDriver(move |_, value| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(value)
            })),
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
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        wait_actor_status(&boot, &actor.directory, "completed").await?;
        ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 1);
        ensure!(boot.kernel().facts().facts_of(actor.process)?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_rejects_missing_step_binding() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel().processes().count();
        let spec = ActorSpec {
            name: "missing_step".into(),
            body: DoNode::pure(Value::null()).and_then(StepRef::new("send")),
            ..ActorSpec::default()
        };
        let err = expect_bootstrap_error(
            boot.spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::MissingStepBinding { .. }),
            "unexpected missing step error: {err:?}"
        );
        ensure!(
            boot.kernel().processes().count() == before,
            "missing step binding should not create a process"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_spawn_with_step_binding_runs_immediately() -> anyhow::Result<()> {
        let boot = crate::fact::testing::observing_bootstrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let name = boot.register_effect(
            "effect://echo/actor-bound-step",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )
            .finalize_allowed()],
            Arc::new(crate::driver::FnDriver(move |_, value| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(value)
            })),
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
                boot.root(),
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
        ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 1);
        ensure!(boot.kernel().facts().facts_of(actor.process)?.is_empty());
        ensure!(
            boot.kernel().processes().steps(actor.process).is_empty(),
            "process-local step should be removed after actor completion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actors_share_nested_steps_with_local_paths_and_finalizers() -> anyhow::Result<()> {
        use crate::{Driver, DriverContext, DriverError};
        use xolotl_types::{Failure, MethodId, Outcome};

        struct Writes(
            parking_lot::Mutex<Vec<(ProcessId, Option<Path>, Value)>>,
            crate::DynDriver,
        );

        #[async_trait::async_trait]
        impl Driver for Writes {
            async fn call(
                &self,
                method: MethodId,
                input: Value,
                output: OutputMode,
                ctx: &DriverContext,
            ) -> Result<crate::DriverOutput, DriverError> {
                if method.get() == 1 {
                    return self.1.call(MethodId::new(0), input, output, ctx).await;
                }
                self.0
                    .lock()
                    .push((ctx.caller, ctx.target_path.clone(), input.clone()));
                Ok(crate::DriverOutput::new(Outcome::Done(input)))
            }
        }

        let boot = Bootstrap::in_memory();
        let writes = Arc::new(Writes(
            parking_lot::Mutex::new(Vec::new()),
            crate::executor::signal_tests::signal_driver(boot.kernel().state().clone()),
        ));
        boot.register_subtree_resource(
            "state",
            InterfaceFamily::Value,
            &[
                MethodSpec::new(
                    "write",
                    xolotl_types::MethodAuthority::Write,
                    Purity::Idempotent,
                    MethodSpec::UNARY_ASYNC,
                ),
                MethodSpec::new(
                    "subscribe",
                    xolotl_types::MethodAuthority::Subscribe,
                    Purity::Pure,
                    MethodSpec::UNARY_ASYNC,
                )
                .observes_external()
                .finalize_allowed(),
            ],
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
            declared_capabilities: vec![
                "write://state/process/self/**".into(),
                "subscribe://state/process/self/start".into(),
            ],
            finalizers: vec![DoNode::pure(Value::null()).and_then(StepRef::new("cleanup"))],
            ..ActorSpec::default()
        };
        let mut actors = Vec::new();
        for identity in ["first", "second"] {
            actors.push(
                boot.spawn_actor_under_with_steps(
                    boot.root(),
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
            boot.kernel()
                .state()
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
            ensure!(boot.kernel().processes().steps(actor.process).is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn actor_completion_runs_finalizers_before_step_cleanup() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let name = boot.register_effect(
            "effect://echo/actor-completion-finalizer",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )
            .finalize_allowed()],
            Arc::new(crate::driver::FnDriver(move |_, value| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(value)
            })),
        )?;
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
                boot.root(),
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
        ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 1);
        ensure!(
            boot.kernel().processes().steps(actor.process).is_empty(),
            "finalizer step should be removed after actor completion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalizer_failure_retains_cleanup_result() -> anyhow::Result<()> {
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
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        wait_actor_status(&boot, &actor.directory, "completed").await?;
        let failures = boot
            .kernel()
            .processes()
            .finalizer_failures(actor.process)
            .context("missing finalizer failures")?;
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
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        wait_actor_status(&boot, &actor.directory, "failed").await?;
        boot.finalize_process(actor.process).await?;
        let value = boot
            .kernel()
            .state()
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
        ensure!(boot.kernel().processes().status(actor.process) == Some(ProcessStatus::Failed));
        Ok(())
    }

    #[test]
    fn request_local_templates_bind_before_attenuation() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let template = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("write://state/process/self/scratch@account=alice")?,
            rights: GrantRights::new(GrantMethods::name("write"), RightFlags::empty()),
        };
        let process = boot.spawn_request_process_under_with_steps(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            std::slice::from_ref(&template),
            StepModule::default(),
        )?;
        let grants = boot.kernel().processes().attached_grants(process);
        let grant = grants.first().context("request has no attached grant")?;
        ensure!(
            grant.selector.pattern.to_string()
                == format!(
                    "write://state/process/{}/scratch@account=alice",
                    process.get()
                )
        );
        ensure!(grant.selector.pattern.predicate == template.selector.pattern.predicate);
        ensure!(grant.constraints.is_empty());
        ensure!(template.selector.pattern.segments[1].as_str() == "self");

        let before = boot.kernel().processes().count();
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
        ensure!(boot.kernel().processes().count() == before);
        Ok(())
    }

    #[tokio::test]
    async fn request_modules_are_isolated_and_released_after_finalization() -> anyhow::Result<()> {
        use xolotl_types::{Failure, Outcome};
        let boot = Bootstrap::in_memory();
        let step: StepFn = Arc::new(|v, _| DoNode::pure(v));
        let weak = Arc::downgrade(&step);
        let process = boot.spawn_request_process_under_with_steps(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            &[],
            StepModule::new([StepBinding::new("identity", step)])?,
        )?;
        let program = DoNode::pure(42).and_then(StepRef::new("identity"));
        let executor = boot.kernel().executor_for(process);
        let outcome = executor.eval(&program).await;
        ensure!(outcome.outcome == Outcome::Done(Value::integer(42)));
        ensure!(
            matches!(
                boot.kernel()
                    .executor_for(boot.root())
                    .eval(&program)
                    .await
                    .outcome,
                Outcome::Fail(_)
            ),
            "request functions must not leak to the parent"
        );
        let overridden = boot
            .kernel()
            .executor_for(process)
            .with_steps(StepModule::single("identity", |_, _| DoNode::pure(99))?);
        ensure!(overridden.eval(&program).await.outcome == Outcome::Done(Value::integer(99)));
        ensure!(executor.eval(&program).await == outcome);
        boot.finish_request_process(process, &outcome).await?;
        ensure!(boot.kernel().processes().steps(process).is_empty());
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
        let before = boot.kernel().processes().count();
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
            boot.spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::ActorLint { .. }),
            "unexpected error: {err:?}"
        );
        ensure!(
            boot.kernel().processes().count() == before,
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
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        let before_second = boot.kernel().processes().count();
        let err = expect_bootstrap_error(
            boot.spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::State(_)),
            "unexpected error: {err:?}"
        );
        ensure!(boot.drain_cleanup().await.failures.is_empty());
        ensure!(boot.kernel().processes().count() == before_second + 1);
        let rejected = boot
            .kernel()
            .processes()
            .children_of(boot.root())
            .into_iter()
            .find(|process| *process != first.process)
            .context("missing rejected admission")?;
        ensure!(
            boot.kernel()
                .processes()
                .status(rejected)
                .is_some_and(ProcessStatus::is_terminal)
        );
        ensure!(!boot.kernel().processes().has_task(rejected));
        wait_actor_status(&boot, &first.directory, "completed").await?;
        Ok(())
    }

    #[tokio::test]
    async fn finalize_actor_aborts_task_and_updates_directory() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        crate::executor::signal_tests::install_signal_resource(
            &boot,
            boot.kernel().state().clone(),
        )?;
        let signal = Path::parse("state://signals/never")?;
        let spec = ActorSpec {
            name: "waiter".into(),
            body: DoNode::wait_signal(signal),
            declared_capabilities: vec!["subscribe://state/signals/never".into()],
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;
        boot.finalize_process(actor.process).await?;
        let value = boot
            .kernel()
            .state()
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
            !boot.kernel().processes().abort_task(actor.process),
            "actor task should have been removed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn actor_finalizer_operation_opens_while_finalizing() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        crate::executor::signal_tests::install_signal_resource(
            &boot,
            boot.kernel().state().clone(),
        )?;
        let name = boot.register_effect(
            "effect://echo/actor-finalizer",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )
            .finalize_allowed()],
            Arc::new(crate::driver::FnDriver(move |_, value| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(value)
            })),
        )?;
        let spec = ActorSpec {
            name: "finalizer_op".into(),
            body: DoNode::wait_signal(Path::parse("state://signals/finalizer-never")?),
            declared_capabilities: vec![
                "perform://effect/echo/actor-finalizer".into(),
                "subscribe://state/signals/finalizer-never".into(),
            ],
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
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        boot.finalize_process(actor.process).await?;
        ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 1);
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
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(crate::FnDriver(move |_method, input| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(input)
            })),
        )?;
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
            .spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
            .await?;

        wait_actor_status(&boot, &actor.directory, "completed").await?;
        ensure!(
            calls.load(Ordering::SeqCst) == 0,
            "denied finalizer reached its driver"
        );
        ensure!(
            boot.kernel()
                .processes()
                .finalizer_failures(actor.process)
                .context("missing finalizer failures")?
                .len()
                == 1
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
                xolotl_types::MethodAuthority::Write,
                Purity::Idempotent,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let ex = boot
            .kernel()
            .executor_for(boot.root())
            .with_finalizer_mode();
        ensure!(
            boot.kernel()
                .processes()
                .begin_finalizing(boot.root(), ProcessStatus::Completed)
                == crate::process::FinalizeStart::Started
        );
        let local_target = ResourceName::new(Path::parse(&format!(
            "state://process/{}/cleanup",
            boot.root().get()
        ))?);
        let local_program = DoNode::op(OperationTemplate {
            target: local_target,
            method: "write".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::string("cleanup".into())),
        });
        let local = crate::process::scope_finalizer(
            boot.kernel().processes(),
            boot.root(),
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
            boot.kernel().processes(),
            boot.root(),
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
        let before = boot.kernel().processes().count();
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
            boot.spawn_actor_under(boot.root(), xolotl_types::IdentityRef::ROOT, "root", &spec)
                .await,
        )?;
        ensure!(
            matches!(err, BootstrapError::ActorLint { .. }),
            "unexpected error: {err:?}"
        );
        ensure!(
            boot.kernel().processes().count() == before,
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
                xolotl_types::MethodAuthority::Perform,
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
        let boot = crate::fact::testing::observing_bootstrap();
        // Register an echo effect and open a handle for the root process.
        let name = boot.register_effect(
            "effect://echo/say",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let handle = boot.open_for(boot.root(), &name, "perform")?;

        // Build an executor, bind the handle, run a one-Operation program.
        let ex = boot.kernel().executor_for(boot.root());
        ex.bind_handle(name.clone(), handle)?;
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

        // Observation recording is disabled. The EchoDriver method is Pure, and
        // the op's output flows nowhere, so no Fact is written.
        let facts = boot.kernel().facts().facts_of(boot.root())?;
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
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let handle = boot.open_for(boot.root(), &name, "perform")?;
        let ex = boot.kernel().executor_for(boot.root());
        ex.bind_handle(name.clone(), handle)?;
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
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let before = boot.kernel().handles().read().len();
        let ex = boot.kernel().executor_for(boot.root());
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
            boot.kernel().handles().read().len() == before,
            "invalid output mode should not open a handle"
        );
        Ok(())
    }

    #[tokio::test]
    async fn budget_exhaustion_denies_costly_op_before_effect() -> anyhow::Result<()> {
        // A process with a tiny lifetime budget running a costed effect is denied
        // with BudgetExhausted because the reservation fires before dispatch.
        let boot = Bootstrap::in_memory();
        let name = boot.register_effect_with_cost(
            "effect://pricey/call",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
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
        // Root's budget is only 500_000 micro-USD — below one call.
        ensure!(
            boot.kernel()
                .processes()
                .set_budget_spec(
                    boot.root(),
                    xolotl_types::BudgetSpec {
                        max_micro_usd: Some(500_000),
                        ..Default::default()
                    },
                )
                .is_ok(),
            "root process missing while setting test budget"
        );
        let handle = boot.open_for(boot.root(), &name, "perform")?;
        let ex = boot.kernel().executor_for(boot.root());
        ex.bind_handle(name.clone(), handle)?;
        let prog = DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::string("hi".into())),
        });
        match ex.eval(&prog).await.outcome {
            xolotl_types::Outcome::Fail(xolotl_types::Failure::BudgetExhausted { dim }) => {
                ensure!(dim == "micro_usd", "unexpected budget dimension: {dim}");
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
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Idempotent,
                MethodSpec::UNARY_ASYNC,
            )
            .batchable()],
            Arc::new(EchoDriver),
            xolotl_types::CostModel {
                flat_micro_usd: 100,
                ..Default::default()
            },
        )?;
        ensure!(
            boot.kernel()
                .processes()
                .set_budget_spec(
                    boot.root(),
                    xolotl_types::BudgetSpec {
                        max_micro_usd: Some(250),
                        ..Default::default()
                    },
                )
                .is_ok(),
            "root process missing while setting test budget"
        );
        let handle = boot.open_for(boot.root(), &name, "perform")?;
        let ex = boot.kernel().executor_for(boot.root());
        ex.bind_handle(name.clone(), handle)?;
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
                ensure!(dim == "micro_usd", "unexpected budget dimension: {dim}");
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
                        MethodSpec::new(
                            "invoke",
                            xolotl_types::MethodAuthority::Perform,
                            Purity::Effectful,
                            MethodSpec::UNARY_ASYNC
                        ),
                        MethodSpec::new(
                            "check",
                            xolotl_types::MethodAuthority::Perform,
                            Purity::Idempotent,
                            MethodSpec::UNARY_ASYNC
                        ),
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
                xolotl_types::MethodAuthority::Perform,
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
            boot.kernel()
                .processes()
                .set_budget_spec(
                    boot.root(),
                    xolotl_types::BudgetSpec {
                        max_micro_usd: Some(1_000_000),
                        ..Default::default()
                    },
                )
                .is_ok(),
            "root process missing while setting test budget"
        );
        let handle = boot.open_for(boot.root(), &name, "perform")?;
        let ex = boot.kernel().executor_for(boot.root());
        ex.bind_handle(name.clone(), handle)?;
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
            .kernel()
            .processes()
            .budget_mut(boot.root(), |b| b.inflight_ops)
            .context("missing root budget state")?;
        ensure!(inflight == 0, "inflight slot released after settle");
        let spent = boot
            .kernel()
            .processes()
            .budget_mut(boot.root(), |b| b.spent_micro_usd)
            .context("missing root budget state")?;
        ensure!(spent == 100, "flat cost settled");
        Ok(())
    }

    #[tokio::test]
    async fn explicit_observation_records_a_fact() -> anyhow::Result<()> {
        let boot = crate::fact::testing::observing_bootstrap();
        let name = boot.register_effect(
            "effect://echo2/say",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let handle = boot.open_for(boot.root(), &name, "perform")?;
        let ex = boot
            .kernel()
            .executor_for(boot.root())
            .with_fact_recording(true);
        ex.bind_handle(name.clone(), handle)?;
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
        let facts = boot.kernel().facts().facts_of(boot.root())?;
        ensure!(facts.len() == 1, "consumed op should record one fact");
        Ok(())
    }

    #[tokio::test]
    async fn finalize_marks_cancelled_without_observation_records() -> anyhow::Result<()> {
        let boot = crate::fact::testing::observing_bootstrap();
        // Spawn a child request Process, then finalize it.
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;
        boot.finalize_process(child).await?;
        ensure!(
            boot.kernel().processes().status(child) == Some(xolotl_types::ProcessStatus::Cancelled),
            "unfinished child process should be cancelled"
        );
        ensure!(boot.cleanup_ticket(child)?.is_complete());
        ensure!(
            boot.kernel()
                .processes()
                .finalization_report(child)
                .is_some()
        );
        ensure!(boot.kernel().facts().facts_of(child)?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn finalize_preserves_cancelled_request_status() -> anyhow::Result<()> {
        let boot = crate::fact::testing::observing_bootstrap();
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;
        ensure!(
            boot.cancel_process(child)?,
            "request process should be newly cancelled"
        );

        boot.finalize_process(child).await?;
        ensure!(
            boot.kernel().processes().status(child) == Some(xolotl_types::ProcessStatus::Cancelled),
            "finalize should preserve cancelled status"
        );
        ensure!(boot.kernel().facts().facts_of(child)?.is_empty());
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
            Err(crate::fact::FactError::new(
                "simulated append failure".into(),
            ))
        }

        fn complete(&self, _fact: Fact) -> Result<(), crate::fact::FactError> {
            Err(crate::fact::FactError::new(
                "simulated complete failure".into(),
            ))
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

    #[tokio::test]
    async fn finalize_is_independent_of_fact_delivery() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore::default()));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(state)
                .with_fact_sink(facts)
                .build(),
        );
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            &[],
        )?;

        boot.finalize_process(child).await?;
        ensure!(boot.kernel().processes().status(child) == Some(ProcessStatus::Cancelled));
        ensure!(boot.cleanup_ticket(child)?.is_complete());
        Ok(())
    }

    #[tokio::test]
    async fn owned_completion_preserves_independent_actor_lifetime() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore::default()));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(state)
                .with_fact_sink(facts)
                .build(),
        );
        crate::executor::signal_tests::install_signal_resource(
            &boot,
            boot.kernel().state().clone(),
        )?;
        let parent = boot.request_under(
            boot.root(),
            IdentityRef::ROOT,
            &[CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse("subscribe://state/signal/never")?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::name("subscribe"),
                    RightFlags::empty(),
                ),
            }],
        )?;
        let parent_id = parent.id();
        let spec = ActorSpec {
            name: "independent_completion".into(),
            body: DoNode::wait_signal(Path::parse("state://signal/never")?),
            declared_capabilities: vec!["subscribe://state/signal/never".into()],
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
                .is_ok()
        );
        let report = boot.drain_cleanup().await;
        ensure!(report.failures.is_empty());
        ensure!(boot.kernel().processes().status(parent_id) == Some(ProcessStatus::Completed));
        ensure!(boot.kernel().processes().status(actor.process) == Some(ProcessStatus::Running));
        boot.finalize_process(parent_id).await?;
        ensure!(boot.kernel().processes().status(actor.process) == Some(ProcessStatus::Cancelled));
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_finalization_preserves_remaining_work_and_wakes_another_owner()
    -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Poll;
        let boot = Bootstrap::in_memory();
        crate::executor::signal_tests::install_signal_resource(
            &boot,
            boot.kernel().state().clone(),
        )?;
        let process = boot.kernel().processes().fresh_id()?;
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
        let mut entry = ProcessEntry::new(process, Some(boot.root()), IdentityRef::ROOT);
        entry.scope.start();
        entry.attached_grants.push(Grant {
            id: boot.kernel().processes().fresh_attached_grant_id(),
            holder: process,
            selector: ResourceSelector::parse("subscribe://state/signals/interrupted-finalizer")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("subscribe"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        entry.steps = StepModule::compose(modules)?;
        entry.on_finalize = (0..3)
            .rev()
            .map(|index| {
                DoNode::pure(Value::null())
                    .and_then(xolotl_graph::StepRef::new(format!("step{index}")))
            })
            .collect();
        boot.kernel().processes().insert(entry);

        let mut first = Box::pin(boot.finish_process_as(process, ProcessStatus::Failed));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        ensure!(calls[0].load(Ordering::SeqCst) == 1 && calls[1].load(Ordering::SeqCst) == 1);
        ensure!(!boot.cancel_process(process)?);
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Finalizing));
        let mut second = Box::pin(boot.finalize_process(process));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(1), second).await??;
        ensure!(calls.iter().all(|calls| calls.load(Ordering::SeqCst) == 1));
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Failed));
        let failures = boot
            .kernel()
            .processes()
            .finalizer_failures(process)
            .context("missing failures")?;
        ensure!(failures.len() == 1);
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
    fn gateway_audit_preserves_application_metadata_without_interpreting_authentication()
    -> anyhow::Result<()> {
        let boot = crate::fact::testing::observing_bootstrap();
        let details = Value::map(BTreeMap::from([
            ("event".into(), Value::from("application_detail")),
            (
                "authentication".into(),
                Value::map(BTreeMap::from([
                    ("method".into(), Value::from("host_defined")),
                    ("assurance".into(), Value::from("verified_by_host")),
                ])),
            ),
        ]));
        for (event, details) in [
            ("console_login", Some(details)),
            ("gateway_mcp", Some(Value::integer(7))),
            ("host.work_completed", None),
        ] {
            boot.record_gateway_audit(GatewayAudit {
                event,
                username: Some("service-account"),
                source_addr: Some("local-adapter"),
                outcome: "accepted",
                details: details.clone(),
            })?;
            let facts = boot.kernel().facts().facts_of(boot.root())?;
            let fact = facts.last().context("missing gateway audit")?;
            ensure!(fact.schema_version == 1 && Fact::SCHEMA_VERSION == 1);
            ensure!(fact.id.position == GATEWAY_AUDIT_NODE);
            ensure!(fact.replay == xolotl_types::ReplayClass::Observation);
            let outcome = fact
                .outcome
                .as_ref()
                .and_then(Value::as_map)
                .context("missing gateway audit envelope")?;
            ensure!(outcome.get("event").and_then(Value::as_str) == Some(event));
            ensure!(outcome.get("outcome").and_then(Value::as_str) == Some("accepted"));
            ensure!(outcome.get("details") == details.as_ref());
            ensure!(!outcome.contains_key("authentication") && !outcome.contains_key("mfa_level"));
            ensure!(
                xolotl_types::AuditRules::default().tags_for(fact, 0)
                    == vec![xolotl_types::AuditTag::Custom {
                        label: event.into()
                    }]
            );
        }
        Ok(())
    }

    #[test]
    fn gateway_audit_rejects_invalid_envelopes_before_fact_delivery() {
        let boot = crate::fact::testing::observing_bootstrap();
        for (event, outcome) in [("", "accepted"), ("gateway_mcp", "")] {
            assert!(
                boot.record_gateway_audit(GatewayAudit {
                    event,
                    username: None,
                    source_addr: None,
                    outcome,
                    details: None,
                })
                .is_err()
            );
        }
        assert!(
            boot.kernel()
                .facts()
                .facts_of(boot.root())
                .is_ok_and(|facts| facts.is_empty())
        );
    }

    #[test]
    fn gateway_audit_fact_failure_does_not_insert_audit_process() -> anyhow::Result<()> {
        let facts = crate::fact::FactSink::new(Arc::new(FailingFinalizeFactStore::default()));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(state)
                .with_fact_sink(facts)
                .build(),
        );
        let before = boot.kernel().processes().all_ids().len();

        let err = match boot.record_gateway_audit(GatewayAudit {
            event: "login",
            username: Some("alice"),
            source_addr: Some("127.0.0.1"),
            outcome: "denied",
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
            boot.kernel().processes().all_ids().len() == before,
            "pre-operation audit events must not create process rows without audit Facts"
        );
        Ok(())
    }

    #[test]
    fn request_process_rejects_malformed_request_grant_before_insert() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel().processes().all_ids().len();
        let err = expect_bootstrap_error(boot.spawn_request_process_under_with_request_grants(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "effect://x/post",
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
            }],
        ))?;
        ensure!(
            matches!(err, BootstrapError::Selector { .. }),
            "unexpected malformed request grant error: {err:?}"
        );
        ensure!(
            boot.kernel().processes().all_ids().len() == before,
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
        let anchor = boot.kernel().processes().fresh_id()?;
        let mut entry =
            ProcessEntry::new(anchor, Some(boot.root()), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
        boot.kernel().processes().insert(entry);
        for sel in selectors {
            let grant = Grant {
                id: boot.kernel().registry().next_grant_id(),
                holder: anchor,
                selector: ResourceSelector::parse(sel)?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::name("invoke"),
                    RightFlags::empty(),
                ),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            };
            boot.kernel().registry().register_grant(grant);
        }
        Ok(anchor)
    }

    #[test]
    fn request_attenuation_keeps_parent_alternatives_across_generations() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let literal = "perform://effect/inference/infer";
        let requested = RequestGrantTemplate {
            literal,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                RightFlags::empty(),
            ),
        };
        let parents = [
            "perform://effect/inference/**@tenant=alice",
            "perform://effect/inference/**@tenant=bob",
        ];
        let anchor = restricted_anchor(&boot, &parents)?;
        let child = boot.spawn_request_process_under_with_request_grants(
            anchor,
            IdentityRef::ROOT,
            std::slice::from_ref(&requested),
        )?;
        let first = boot.kernel().processes().attached_grants(child);
        ensure!(first.len() == 2, "both parent alternatives must survive");
        let target = Path::parse("effect://inference/infer")?;
        let input = |tenant: &str, region: &str| {
            Value::map(std::collections::BTreeMap::from([
                ("tenant".into(), Value::string(tenant.into())),
                ("region".into(), Value::string(region.into())),
            ]))
        };
        for tenant in ["alice", "bob"] {
            ensure!(
                first
                    .iter()
                    .any(|grant| { grant.covers("perform", &target, &input(tenant, "east"), 0) })
            );
        }
        ensure!(
            !first
                .iter()
                .any(|grant| { grant.covers("perform", &target, &input("mallory", "east"), 0) })
        );
        ensure!(
            first
                .iter()
                .all(|grant| grant.selector.pattern.predicate.is_none())
        );

        let narrower = RequestGrantTemplate {
            literal: "perform://effect/inference/infer@region=east",
            rights: requested.rights.clone(),
        };
        let grandchild = boot.spawn_request_process_under_with_request_grants(
            child,
            IdentityRef::ROOT,
            std::slice::from_ref(&narrower),
        )?;
        let second = boot.kernel().processes().attached_grants(grandchild);
        ensure!(second.len() == 2);
        let region_east = xolotl_types::Predicate::parse("region=east")?;
        ensure!(second.iter().all(|grant| {
            grant.selector.pattern.predicate.as_ref() == Some(&region_east)
                && grant.constraints.predicates.len() == 1
        }));
        for tenant in ["alice", "bob"] {
            ensure!(
                second
                    .iter()
                    .any(|grant| { grant.covers("perform", &target, &input(tenant, "east"), 0) })
            );
            ensure!(
                !second
                    .iter()
                    .any(|grant| { grant.covers("perform", &target, &input(tenant, "west"), 0) })
            );
        }
        let great_grandchild = boot.spawn_request_process_under_with_request_grants(
            grandchild,
            IdentityRef::ROOT,
            &[narrower],
        )?;
        let third = boot.kernel().processes().attached_grants(great_grandchild);
        ensure!(third.len() == 2);
        ensure!(
            third
                .iter()
                .all(|grant| grant.constraints.predicates.len() == 1)
        );

        let reversed = restricted_anchor(&boot, &[parents[1], parents[0]])?;
        let reordered = boot.spawn_request_process_under_with_request_grants(
            reversed,
            IdentityRef::ROOT,
            &[requested],
        )?;
        let reordered = boot.kernel().processes().attached_grants(reordered);
        ensure!(
            first.iter().zip(&reordered).all(|(left, right)| {
                left.selector == right.selector
                    && left.rights == right.rights
                    && left.constraints == right.constraints
                    && left.expires == right.expires
            }),
            "attached alternatives must have canonical order"
        );
        Ok(())
    }

    #[test]
    fn request_attenuation_deduplicates_and_bounds_parent_alternatives() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = restricted_anchor(
            &boot,
            &[
                "perform://effect/inference/**@tenant=alice",
                "perform://effect/inference/**@tenant=alice",
            ],
        )?;
        let template = ParsedRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/inference/infer")?,
            rights: Some(GrantRights::new(
                GrantMethods::name("invoke"),
                RightFlags::empty(),
            )),
        };
        let mut parents = boot.kernel().registry().grants_of(anchor);
        ensure!(
            Bootstrap::plan_grants_from(&parents, std::slice::from_ref(&template), 0)?.len() == 1
        );
        for index in 0..2 {
            parents.push(Grant {
                id: boot.kernel().registry().next_grant_id(),
                holder: anchor,
                selector: ResourceSelector::parse(&format!(
                    "perform://effect/inference/**@tenant=tenant{index}"
                ))?,
                rights: template.rights.clone().context("explicit rights")?,
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        ensure!(matches!(
            Bootstrap::plan_grants_from_with_limit(&parents, &[template], 0, 2),
            Err(BootstrapError::RequestGrantLimit { limit: 2 })
        ));
        Ok(())
    }

    #[test]
    fn implicit_actor_request_inherits_each_parent_method_without_propagation() -> anyhow::Result<()>
    {
        let boot = Bootstrap::in_memory();
        let selector = ResourceSelector::parse("perform://effect/echo/**")?;
        let parents = [
            Grant {
                id: boot.kernel().registry().next_grant_id(),
                holder: boot.root(),
                selector: selector.clone(),
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::CLONE),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            },
            Grant {
                id: boot.kernel().registry().next_grant_id(),
                holder: boot.root(),
                selector,
                rights: GrantRights::new(GrantMethods::name("observe"), RightFlags::TRANSFER),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            },
        ];
        let template = ParsedRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/echo/say")?,
            rights: None,
        };
        let planned = Bootstrap::plan_grants_from(&parents, &[template], 0)?;
        ensure!(planned.len() == 2);
        ensure!(planned.iter().all(|grant| grant.rights.flags.is_empty()));
        let methods: Vec<_> = planned
            .iter()
            .map(|grant| grant.rights.methods.clone())
            .collect();
        ensure!(
            methods.contains(&GrantMethods::name("invoke"))
                && methods.contains(&GrantMethods::name("observe"))
        );
        Ok(())
    }

    #[test]
    fn root_anchor_covers_every_request_grant_template() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let child = boot.spawn_request_process_under_with_request_grants(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            &[
                RequestGrantTemplate {
                    literal: "perform://effect/x/post",
                    rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
                },
                RequestGrantTemplate {
                    literal: "read://state/memory/alice/x",
                    rights: GrantRights::new(GrantMethods::name("read"), RightFlags::empty()),
                },
            ],
        )?;
        ensure!(
            boot.kernel().registry().grants_of(child).is_empty(),
            "request Process grants must not be registered in the global grant table"
        );
        let grants = boot.kernel().processes().attached_grants(child);
        ensure!(grants.len() == 2, "one grant per request grant template");
        Ok(())
    }

    #[test]
    fn restricted_anchor_rejects_capability_outside_ceiling_fail_closed() -> anyhow::Result<()> {
        // An anchor holding only inference authority must reject a request
        // grant outside that ceiling.
        let boot = Bootstrap::in_memory();
        let anchor = restricted_anchor(&boot, &["perform://effect/inference/**"])?;
        let before = boot.kernel().processes().all_ids().len();

        // Covered capability is fine.
        boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/inference/infer",
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
            }],
        )?;

        // Rejected declarations must not allocate a child Process.
        let mid = boot.kernel().processes().all_ids().len();
        let err = expect_bootstrap_error(boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/proc/spawn",
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
            }],
        ))?;
        ensure!(
            matches!(err, BootstrapError::CapabilityCeiling { .. }),
            "request grant outside anchor ceiling must be rejected"
        );
        ensure!(
            boot.kernel().processes().all_ids().len() == mid,
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
        let before = boot.kernel().processes().all_ids().len();
        let err = expect_bootstrap_error(boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[
                RequestGrantTemplate {
                    literal: "perform://effect/inference/infer",
                    rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
                },
                RequestGrantTemplate {
                    literal: "write://state/vault/alice/x",
                    rights: GrantRights::new(GrantMethods::name("write"), RightFlags::empty()),
                },
            ],
        ))?;
        ensure!(
            matches!(err, BootstrapError::CapabilityCeiling { .. }),
            "unexpected capability ceiling error: {err:?}"
        );
        ensure!(
            boot.kernel().processes().all_ids().len() == before,
            "a partially-uncovered declared set must spawn nothing"
        );
        Ok(())
    }

    #[test]
    fn request_grant_template_narrows_anchor_method_rights() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel().processes().fresh_id()?;
        let mut entry =
            ProcessEntry::new(anchor, Some(boot.root()), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
        boot.kernel().processes().insert(entry);
        boot.kernel().registry().register_grant(Grant {
            id: boot.kernel().registry().next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let child = boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/say",
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
            }],
        )?;
        let grants = boot.kernel().processes().attached_grants(child);
        ensure!(
            grants.len() == 1,
            "unexpected grant count: {}",
            grants.len()
        );
        ensure!(
            grants[0].rights.methods.allows("invoke"),
            "method 0 should be allowed"
        );
        ensure!(
            !grants[0].rights.methods.allows("other"),
            "method 1 should not be allowed"
        );
        Ok(())
    }

    #[test]
    fn request_grant_derivation_preserves_parent_limits() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel().processes().fresh_id()?;
        let mut entry =
            ProcessEntry::new(anchor, Some(boot.root()), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
        boot.kernel().processes().insert(entry);
        let expires = Expiry::At(boot.kernel().host_runtime().now_millis() + 60_000);
        boot.kernel().registry().register_grant(Grant {
            id: boot.kernel().registry().next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**@tenant=acme")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                RightFlags::empty(),
            ),
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
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
            }],
        )?;
        let grants = boot.kernel().processes().attached_grants(child);
        let grant = grants.first().context("missing derived grant")?;
        ensure!(grant.expires == expires, "grant expiry was not preserved");
        ensure!(
            grant.selector.pattern.predicate
                == Some(xolotl_types::Predicate::parse("purpose=test")?),
            "request predicate must remain on the selector"
        );
        ensure!(
            grant.constraints.predicates.len() == 2,
            "parent predicates were not all retained: {:?}",
            grant.constraints.predicates
        );
        Ok(())
    }

    #[test]
    fn request_grant_multigeneration_retains_each_ancestor_condition() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = restricted_anchor(&boot, &["perform://effect/echo/**@tenant=acme"])?;
        let rights = GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty());
        let child = boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/say@purpose=test",
                rights: rights.clone(),
            }],
        )?;
        let grandchild = boot.spawn_request_process_under_with_request_grants(
            child,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/say@lane=east",
                rights: rights.clone(),
            }],
        )?;
        let grants = boot.kernel().processes().attached_grants(grandchild);
        let grant = grants.first().context("missing grandchild grant")?;
        ensure!(grants.len() == 1);
        ensure!(grant.rights == rights);
        ensure!(
            grant.selector.pattern.predicate == Some(xolotl_types::Predicate::parse("lane=east")?)
        );
        ensure!(
            grant.constraints.predicates
                == [
                    xolotl_types::Predicate::parse("purpose=test")?,
                    xolotl_types::Predicate::parse("tenant=acme")?,
                ]
        );
        let mut predicates = grant.constraints.predicates.clone();
        predicates.push(
            grant
                .selector
                .pattern
                .predicate
                .clone()
                .context("missing request predicate")?,
        );
        let conditions = ConstraintSet { predicates };
        for (tenant, purpose, lane, allowed) in [
            ("acme", "test", "east", true),
            ("other", "test", "east", false),
            ("acme", "other", "east", false),
            ("acme", "test", "west", false),
        ] {
            let input = Value::map(std::collections::BTreeMap::from([
                ("tenant".into(), Value::string(tenant.into())),
                ("purpose".into(), Value::string(purpose.into())),
                ("lane".into(), Value::string(lane.into())),
            ]));
            ensure!(conditions.eval(&input, 0) == allowed);
        }
        Ok(())
    }

    #[test]
    fn request_grant_derivation_uses_attached_anchor_grants() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.spawn_request_process_under_with_request_grants(
            boot.root(),
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/**",
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
            }],
        )?;

        let child = boot.spawn_request_process_under_with_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[RequestGrantTemplate {
                literal: "perform://effect/echo/say",
                rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
            }],
        )?;
        ensure!(
            boot.kernel().processes().attached_grants(child).len() == 1,
            "child should derive from anchor's attached grant"
        );
        Ok(())
    }

    #[test]
    fn request_process_rejects_missing_anchor() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let before = boot.kernel().processes().all_ids().len();
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
            boot.kernel().processes().all_ids().len() == before,
            "missing anchor should not create a child process"
        );
        Ok(())
    }

    #[test]
    fn compiled_request_grant_template_uses_anchor_backstop() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let anchor = boot.kernel().processes().fresh_id()?;
        let mut entry =
            ProcessEntry::new(anchor, Some(boot.root()), xolotl_types::IdentityRef::ROOT);
        entry.scope.start();
        boot.kernel().processes().insert(entry);
        boot.kernel().registry().register_grant(Grant {
            id: boot.kernel().registry().next_grant_id(),
            holder: anchor,
            selector: ResourceSelector::parse("perform://effect/echo/**")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });

        let compiled = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/echo/say")?,
            rights: GrantRights::new(GrantMethods::name("invoke"), RightFlags::empty()),
        };
        let child = boot.spawn_request_process_under_with_compiled_request_grants(
            anchor,
            xolotl_types::IdentityRef::ROOT,
            &[compiled],
        )?;
        ensure!(
            boot.kernel().processes().attached_grants(child).len() == 1,
            "compiled grant should attach one grant"
        );

        let overbroad = CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/echo/say")?,
            rights: GrantRights::new(GrantMethods::name("other"), RightFlags::empty()),
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

        let boot = crate::fact::testing::observing_bootstrap();
        let name = boot.register_effect(
            "effect://counter/tick",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            StdArc::new(FnDriver(|_m: xolotl_types::MethodId, _in: Value| {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(Value::integer(7))
            })),
        )?;
        let handle = boot.open_for(boot.root(), &name, "perform")?;

        // Each evaluation has a distinct identity when observation is requested.
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
            .kernel()
            .executor_for(boot.root())
            .with_steps(steps.clone())
            .with_fact_recording(true);
        ex1.bind_handle(name.clone(), handle)?;
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
        let handle2 = boot.open_for(boot.root(), &name, "perform")?;
        let ex2 = boot
            .kernel()
            .executor_for(boot.root())
            .with_steps(steps)
            .with_fact_recording(true);
        ex2.bind_handle(name.clone(), handle2)?;
        let out = ex2.eval(&prog).await;

        ensure!(
            CALLS.load(Ordering::SeqCst) == 3,
            "each independent evaluation must execute its effect"
        );
        ensure!(
            out.outcome == xolotl_types::Outcome::Done(Value::integer(7)),
            "unexpected independent evaluation result"
        );
        let facts = boot.kernel().facts().facts_of(boot.root())?;
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
