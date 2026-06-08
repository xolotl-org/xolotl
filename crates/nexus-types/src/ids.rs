//! Compact identifiers used across the data and control planes.
//!
//! The data plane never carries names or `Path` strings — it carries these
//! compact ids (§2.3, §10.2). `Path` / `ResourceName` exist only in the
//! control plane for addressing and are resolved to ids at `open()` time.
//!
//! All ids are `Copy` newtypes over small integers so the hot path pays no
//! allocation or hashing cost. `HandleId` is a generational `(index, gen)`
//! pair (§5.4) so revoke/reopen cannot be confused (ABA-safe).

use serde::{Deserialize, Serialize};

/// Macro for a `u64`-backed compact id newtype.
macro_rules! id_u64 {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub u64);

        impl $name {
            /// Construct an id from its raw integer value.
            pub const fn new(v: u64) -> Self { Self(v) }
            /// Return the raw integer value.
            pub const fn get(self) -> u64 { self.0 }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}#{}", stringify!($name), self.0)
            }
        }
    };
}

id_u64!(/// Identifies a [`Process`](crate::process::Process) — the only active entity.
    ProcessId);
id_u64!(/// Identifies a control-plane `Resource`.
    ResourceId);
id_u64!(/// Identifies a `Grant` (capability source form).
    GrantId);
id_u64!(/// Identifies a `Binding` (Resource → Driver link).
    BindingId);
id_u64!(/// Identifies a `Driver` implementation.
    DriverId);
id_u64!(/// Identifies an `Interface` (method family).
    InterfaceId);
id_u64!(/// Identifies a single method within an interface.
    MethodId);
id_u64!(/// Identifies a method input/output schema.
    SchemaId);
id_u64!(/// Identifies a remote endpoint (§7.4).
    EndpointId);
id_u64!(/// Identifies a compiled `ExecutionGraph`.
    GraphId);

/// A resolved identity prefix. The data plane carries this, never the raw
/// `Path` of the identity (§3, §2.5). `acting` on an operation is one of these.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct IdentityRef(pub u64);

impl IdentityRef {
    /// Root/system identity.
    pub const ROOT: IdentityRef = IdentityRef(0);
    /// Construct an identity ref from its raw integer value.
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// Return the raw integer value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for IdentityRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "identity#{}", self.0)
    }
}

/// Generational handle id: `(index, generation)` into the slotmap
/// `HandleTable` (§5.4). Lookup is `O(1)` array indexing; revoke bumps the
/// slot generation so a stale `HandleId` (old generation) is rejected.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct HandleId {
    /// Slot index in the handle table.
    pub index: u32,
    /// Slot generation used to reject stale handles.
    pub generation: u32,
}

impl HandleId {
    /// Construct a handle id from slot index and generation.
    pub const fn new(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }
}

impl std::fmt::Display for HandleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "handle#{}.{}", self.index, self.generation)
    }
}

/// Stable position of a node within a compiled `ExecutionGraph` (§13.2).
/// **`NodeId` == `CausalPosition`** (§6.1): it is assigned at compile time,
/// is stable while the Program is unchanged, and never depends on wall clock
/// or randomness. This is the anchor for idempotency dedup and replay.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct NodeId(pub u32);

impl NodeId {
    /// Root node id.
    pub const ROOT: NodeId = NodeId(0);
    /// Construct a node id from its raw integer value.
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
    /// Return the raw integer value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "n{}", self.0)
    }
}

/// `CausalPosition` is exactly a [`NodeId`] (§6.1 / §13.2). The alias exists
/// to keep call sites that speak in causal-position terms readable.
pub type CausalPosition = NodeId;

/// Wall-clock timestamp in milliseconds since the Unix epoch. Used only for
/// audit/projection ordering — never for identity or causal ordering (§9).
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// Construct a timestamp from milliseconds since the Unix epoch.
    pub const fn millis(v: i64) -> Self {
        Self(v)
    }
    /// Return milliseconds since the Unix epoch.
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_id_distinguishes_generations() {
        let a = HandleId::new(3, 1);
        let b = HandleId::new(3, 2);
        assert_ne!(
            a, b,
            "same index, different generation must differ (ABA safety)"
        );
    }

    #[test]
    fn id_serde_is_transparent() {
        let p = ProcessId::new(42);
        assert_eq!(serde_json::to_string(&p).unwrap(), "42");
        let back: ProcessId = serde_json::from_str("42").unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn node_id_is_causal_position() {
        let n: CausalPosition = NodeId::new(7);
        assert_eq!(n.get(), 7);
    }
}
