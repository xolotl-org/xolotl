//! Control-plane descriptors: `Resource`, `Interface`, `Method`, `Binding`.
//!
//! These are **wasm-safe data**: they describe what a Resource is, what
//! methods it exposes, and which Driver it binds to — but they hold no live
//! dispatch table. The runtime `Handle` / `DriverPlan` (which carry
//! `Arc<dyn Driver>`) live in `nexus-kernel`. The console and wire protocols
//! reference these descriptors directly.

use crate::ids::{BindingId, DriverId, EndpointId, InterfaceId, MethodId, ResourceId, SchemaId};
use crate::path::Path;
use crate::replay::{Purity, ReplayClass};
use serde::{Deserialize, Serialize};

/// Implements serde for a `bitflags` type via its raw integer bits.
macro_rules! bitflags_serde_bits {
    ($name:ident, $int:ty) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                self.bits().serialize(s)
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok(<$name>::from_bits_retain(<$int>::deserialize(d)?))
            }
        }
    };
}

bitflags::bitflags! {
    /// Output modes a method supports / a caller requests. A method
    /// declares its supported set; an [`Operation`](crate::operation::Operation)
    /// requests exactly one mode, which must be in that set.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct OutputModeSet: u8 {
        /// Unary request/response support.
        const UNARY         = 0b0001;
        /// Streaming response support.
        const STREAM        = 0b0010;
        /// Async process response support.
        const ASYNC_PROCESS = 0b0100;
        /// Sink-only request support.
        const SINK_ONLY     = 0b1000;
    }
}
bitflags_serde_bits!(OutputModeSet, u8);

/// The single output mode a caller requests on one operation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    /// One request → one response value.
    #[default]
    Unary,
    /// One request → a stream of values (written to a stream channel).
    Stream,
    /// Caller-side adapter that aggregates the method's supported underlying
    /// output (`Unary` or `Stream`) into a bounded list of at most `limit`
    /// elements.
    Collect {
        /// Maximum number of produced values buffered into the collected list.
        limit: usize,
    },
    /// One request → an async process handle (poll/await separately).
    AsyncProcess,
    /// Write-only; no response body expected.
    SinkOnly,
}

impl OutputMode {
    /// The single-bit set this mode belongs to (for the "is supported" check).
    /// `Collect` has no bit of its own — it is a caller-side adapter, so
    /// it maps to no set here and is handled specially by `is_supported_by`.
    pub fn as_set(self) -> OutputModeSet {
        match self {
            OutputMode::Unary => OutputModeSet::UNARY,
            OutputMode::Stream => OutputModeSet::STREAM,
            // Collect aggregates an underlying Unary/Stream result; it has
            // no dedicated support bit (see `is_supported_by`).
            OutputMode::Collect { .. } => OutputModeSet::empty(),
            OutputMode::AsyncProcess => OutputModeSet::ASYNC_PROCESS,
            OutputMode::SinkOnly => OutputModeSet::SINK_ONLY,
        }
    }

    /// Whether `supported` permits this requested mode. `Collect` is a
    /// caller-side aggregation adapter: it is satisfiable by any method that
    /// supports `Unary` or `Stream` (the adapter buffers up to `limit`).
    pub fn is_supported_by(self, supported: OutputModeSet) -> bool {
        match self {
            OutputMode::Collect { .. } => {
                supported.intersects(OutputModeSet::UNARY | OutputModeSet::STREAM)
            }
            other => supported.contains(other.as_set()),
        }
    }
}

bitflags::bitflags! {
    /// Modalities a method accepts / produces. Drives routing (pick a
    /// model that supports the modality), budgeting (bill per modality), and
    /// redaction (scan per modality) without inspecting content.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct ModalitySet: u16 {
        /// Text content.
        const TEXT      = 0b0000_0001;
        /// Image content.
        const IMAGE     = 0b0000_0010;
        /// Audio content.
        const AUDIO     = 0b0000_0100;
        /// Video content.
        const VIDEO     = 0b0000_1000;
        /// Embedding vector content.
        const EMBEDDING = 0b0001_0000;
        /// Pose or action-trajectory content.
        const POSE      = 0b0010_0000;
        /// Sensor telemetry content.
        const SENSOR    = 0b0100_0000;
    }
}
bitflags_serde_bits!(ModalitySet, u16);

/// The seven interface families every Resource's interface belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceFamily {
    /// read/write a current value.
    Value,
    /// read_at/append/subscribe: ordered data, logs, media frames, streams.
    Sequence,
    /// invoke: commands, models, remote APIs.
    Callable,
    /// spawn/kill/status: process or task execution.
    Executor,
    /// list/open_child: child enumeration.
    Directory,
    /// write: write-only, no response body required.
    Sink,
    /// watch/snapshot: state observation.
    Observable,
}

/// Cost model for a method, used by routing / budgeting. Kept simple and
/// wasm-safe — the kernel feeds these into the budget check (CompiledCheck).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CostModel {
    /// Flat micro-USD charged per invocation (e.g. a fixed API fee).
    pub flat_micro_usd: u64,
    /// Micro-USD per 1000 input tokens (modeled cost for LLM-like methods).
    pub per_1k_in_micro_usd: u64,
    /// Micro-USD per 1000 output tokens.
    pub per_1k_out_micro_usd: u64,
}

impl CostModel {
    /// Estimate the micro-USD cost of one call, given
    /// input and (projected) output token counts. Used for budget reservation
    /// *before* the effect, so it is deliberately a conservative upper bound:
    /// callers pass a high output estimate. Settlement later corrects to actual.
    pub fn estimate_micro_usd(&self, in_tokens: u64, out_tokens: u64) -> u64 {
        self.flat_micro_usd
            .saturating_add(self.per_1k_in_micro_usd.saturating_mul(in_tokens) / 1000)
            .saturating_add(self.per_1k_out_micro_usd.saturating_mul(out_tokens) / 1000)
    }

    /// Whether this method has any modeled cost (drives whether the budget check
    /// even runs — a zero-cost method needs no reservation).
    pub fn is_free(&self) -> bool {
        self.flat_micro_usd == 0 && self.per_1k_in_micro_usd == 0 && self.per_1k_out_micro_usd == 0
    }
}

/// One method of an interface. Describes how the method executes,
/// outputs, replays, and bills.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Method {
    /// Method id within the interface.
    pub id: MethodId,
    /// Stable name within the interface (e.g. `read`, `invoke`, `append`).
    pub name: String,
    /// Input schema descriptor id.
    pub input: SchemaId,
    /// Output schema descriptor id.
    pub output: SchemaId,
    /// Modalities accepted or produced by this method.
    pub modality: ModalitySet,
    /// Declared side-effect class; the kernel derives [`ReplayClass`].
    pub purity: Purity,
    /// Replay semantics; defaults to the class derived from `purity` but may
    /// be explicitly overridden at admission.
    pub replay: ReplayClass,
    /// Output modes this method can satisfy.
    pub supports: OutputModeSet,
    /// Cost model used for budget reservation.
    pub cost: CostModel,
    /// Whether this method is batchable: a call may take `List<elem>`
    /// and produce `List<result>`, applying per-element cost/redaction but
    /// recording a single summarizing Fact. `embed`/`rerank`/`index.upsert`
    /// declare this true. Defaults to false (one call, one Fact).
    #[serde(default)]
    pub batchable: bool,
    /// Whether this method may run from a Process finalizer after the Process
    /// has entered `Finalizing`.
    #[serde(default)]
    pub finalize_allowed: bool,
}

/// An algebraic law an [`Interface`] declares, used by validation,
/// optimization, and the simulator to reason about method behavior without
/// executing it. Laws are advisory metadata: the kernel does not synthesize
/// behavior from them, but tooling (Sim, the planner, equivalence checks) may.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "law")]
pub enum InterfaceLaw {
    /// `method(x)` then `method(x)` ≡ `method(x)` (e.g. idempotent writes).
    Idempotent {
        /// Method name governed by the law.
        method: String,
    },
    /// Reading back what was written returns it: `get(write(k,v)) == v`.
    ReadYourWrites {
        /// Write method name.
        write: String,
        /// Read method name.
        read: String,
    },
    /// Two methods commute: order does not affect the result.
    Commutes {
        /// First method name.
        a: String,
        /// Second method name.
        b: String,
    },
    /// A free-form named law for laws not yet modeled structurally.
    Custom {
        /// Law name.
        name: String,
    },
}

/// A method family a Resource exposes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Interface {
    /// Stable interface id.
    pub id: InterfaceId,
    /// Interface family used for high-level classification.
    pub family: InterfaceFamily,
    /// Methods exposed by this interface.
    pub methods: Vec<Method>,
    /// Algebraic laws for validation / optimization / Sim. Empty by
    /// default; advisory metadata, never load-bearing for execution.
    #[serde(default)]
    pub laws: Vec<InterfaceLaw>,
}

impl Interface {
    /// Find a method by name and return its index (bit position in the
    /// [`MethodBitmap`](crate::grant::MethodBitmap)) and descriptor.
    pub fn method_index(&self, name: &str) -> Option<(u32, &Method)> {
        self.methods
            .iter()
            .enumerate()
            .find(|(_, m)| m.name == name)
            .map(|(i, m)| (i as u32, m))
    }
}

/// The set of interfaces a Resource exposes / a Binding/Driver implements.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct InterfaceSet {
    /// Interface ids in the set.
    pub interfaces: Vec<InterfaceId>,
}

impl InterfaceSet {
    /// Create a set from interface ids.
    pub fn new(interfaces: Vec<InterfaceId>) -> Self {
        Self { interfaces }
    }
    /// Does this set cover every interface in `required`?
    ///
    /// Admission requires a Binding's interfaces to cover the Resource's
    /// interfaces.
    pub fn covers(&self, required: &InterfaceSet) -> bool {
        required
            .interfaces
            .iter()
            .all(|i| self.interfaces.contains(i))
    }
}

/// Control-plane name of a Resource. `Path` form, e.g.
/// `effect://inference/infer`. Never appears in an Operation or on the hot
/// path — resolved to a [`ResourceId`] in the control plane.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceName(pub Path);

impl ResourceName {
    /// Wrap a parsed path as a resource name.
    pub fn new(path: Path) -> Self {
        Self(path)
    }
    /// Borrow the underlying path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Broad category of a Resource, for the console and for routing heuristics.
/// Not load-bearing on the hot path — kind never gates execution; rights and
/// interfaces do.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// An effect endpoint (model, command, remote API): `effect://…`.
    Effect,
    /// Durable state / memory / log: `state://…`.
    State,
    /// An external process projected as an Executor Resource: `proc://…`.
    Process,
    /// A device or sensor.
    Device,
    /// A kernel-internal resource (reserved prefixes).
    Kernel,
}

/// Control-plane metadata attached to a Resource descriptor.
///
/// Metadata is used for discovery and projection attribution. It is not
/// consulted by data-plane dispatch.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    /// Optional display label for consoles and descriptors.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Optional Provider or projection id that registered this resource.
    #[serde(default)]
    pub provider_id: Option<String>,
    /// Free-form tags for discovery and filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Descriptor for a Resource: control-plane addressing + kind +
/// metadata. The live binding is referenced by [`Resource::binding`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    /// Control-plane resource name.
    pub name: ResourceName,
    /// Broad resource category.
    pub kind: ResourceKind,
    /// Console/provider metadata.
    #[serde(default)]
    pub metadata: Metadata,
}

/// A passive object that can be operated on, authorized, audited, and bound to
/// a driver. The data plane only ever sees its [`ResourceId`] (inside a
/// Handle or Fact); the descriptor itself is never touched on the hot path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    /// Stable resource id assigned by the registry.
    pub id: ResourceId,
    /// Name, kind, and metadata.
    pub descriptor: ResourceDescriptor,
    /// Interfaces this resource exposes.
    pub interfaces: InterfaceSet,
    /// Binding selected for this resource.
    pub binding: BindingId,
}

/// Reference to a driver implementation (control plane). The live `dyn Driver`
/// lives in the kernel; this descriptor only names it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DriverRef {
    /// Stable driver id assigned by the registry.
    pub id: DriverId,
    /// Human-readable driver name.
    pub name: String,
}

/// Binds a Resource (by selector) to a Driver, with a link generation.
/// Hot replace = bump `generation` and atomically swap the dispatch entry
///; the descriptor here records the binding the control plane resolved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    /// Stable binding id assigned by the registry.
    pub id: BindingId,
    /// Path-pattern selector for the Resources this binding covers.
    pub selector: crate::grant::ResourceSelector,
    /// Interfaces this binding can serve.
    pub interfaces: InterfaceSet,
    /// Driver selected by the binding.
    pub driver: DriverRef,
    /// `None` = local inline driver; `Some` = remote endpoint.
    pub endpoint: Option<EndpointId>,
    /// Link epoch; incremented on hot replace.
    pub generation: u64,
}
