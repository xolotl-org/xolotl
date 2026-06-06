//! `Grant` — the *source* form of a capability (§5.1).
//!
//! A capability has two forms (§2.2):
//!
//! - [`Grant`] — attenuable, delegable, derivable. A selector + rights +
//!   constraints + expiry. This is the "source code".
//! - `Handle` (in `nexus-kernel`) — the compiled form produced by `open()`:
//!   a closed, executable, `O(1)` token. This is the "compiled product".
//!
//! `Grant` lives in `nexus-types` because it is pure data the control plane
//! reasons about and the console renders; `Handle` carries a live dispatch
//! table and lives in the kernel.

use crate::cap::Capability;
use crate::ids::{GrantId, ProcessId};
use crate::value::Value;
use serde::{Deserialize, Serialize};

/// Implements `Serialize`/`Deserialize` for a `bitflags`-generated type by
/// (de)serializing its raw integer bits. Used for bitflag sets whose bits are
/// not all named constants (e.g. `MethodBitmap`), where flag-name encoding
/// would be lossy.
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
    /// Method bitmap (§5.1): which methods of a Resource's interface this
    /// grant authorizes. `O(1)` subset check at `open()` and on the hot path.
    ///
    /// Methods are assigned bit positions per-interface at admission time; the
    /// bitmap is interpreted relative to the Resource's interface method order.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct MethodBitmap: u64 {
        const NONE = 0;
        const ALL  = u64::MAX;
    }
}
bitflags_serde_bits!(MethodBitmap, u64);

impl MethodBitmap {
    /// Bit for method index `i` (its position in the interface's method list).
    pub fn method(i: u32) -> Self {
        debug_assert!(i < 64, "interfaces are limited to 64 methods");
        MethodBitmap::from_bits_retain(1u64 << i)
    }

    /// Whether method index `i` is allowed.
    pub fn allows(self, i: u32) -> bool {
        i < 64 && self.contains(MethodBitmap::method(i))
    }

    /// Bitmap subset test: is `self` ⊆ `other`? (Attenuation invariant: a
    /// derived handle's methods must be a subset of its parent's, §5.3.)
    pub fn is_subset_of(self, other: MethodBitmap) -> bool {
        other.contains(self)
    }
}

bitflags::bitflags! {
    /// Derivation flags on a grant (§5.1). Independent of which methods are
    /// allowed: these govern how the resulting Handle may be *propagated*.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct RightFlags: u32 {
        /// May clone the Handle.
        const CLONE      = 0b0001;
        /// May transfer the Handle to another Process.
        const TRANSFER   = 0b0010;
        /// May pass the Handle to a child on Spawn.
        const SPAWN_WITH = 0b0100;
        /// May delegate (the basis for act-as identity).
        const DELEGATE   = 0b1000;
    }
}
bitflags_serde_bits!(RightFlags, u32);

/// Which derivation a [`derive`](crate::grant::Rights) request performs;
/// gated by the corresponding [`RightFlags`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeriveKind {
    Clone,
    Transfer,
    SpawnWith,
    Delegate,
}

impl DeriveKind {
    fn required_flag(self) -> RightFlags {
        match self {
            DeriveKind::Clone => RightFlags::CLONE,
            DeriveKind::Transfer => RightFlags::TRANSFER,
            DeriveKind::SpawnWith => RightFlags::SPAWN_WITH,
            DeriveKind::Delegate => RightFlags::DELEGATE,
        }
    }
}

/// The methods + derivation flags a grant authorizes (§5.1).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rights {
    pub methods: MethodBitmap,
    pub flags: RightFlags,
}

impl Rights {
    pub fn new(methods: MethodBitmap, flags: RightFlags) -> Self {
        Self { methods, flags }
    }

    /// Bitmap subset (used by `open()` step 2 and `derive_handle`, §5.2/§5.3):
    /// requested rights must be ⊆ the grant's rights, and flags monotonically
    /// attenuate.
    pub fn is_subset_of(&self, parent: &Rights) -> bool {
        self.methods.is_subset_of(parent.methods) && parent.flags.contains(self.flags)
    }

    /// Whether the parent's flags permit the requested derivation kind (§5.3).
    pub fn allows_derive(&self, kind: DeriveKind) -> bool {
        self.flags.contains(kind.required_flag())
    }
}

/// Which Resources a grant matches (§5.1). The same selector serves both
/// authorization (does `open()` of resource R hit this grant?) and capability
/// discovery (enumerate the Resources I may touch, §4.5). It is a path
/// pattern, reusing the [`Capability`] literal grammar (`*` / `**` segments).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceSelector {
    /// The path-pattern capability literal, e.g. `read://state/memory/alice/**`.
    /// `verb`/`scheme`/`segments` come straight from [`Capability`].
    pub pattern: Capability,
}

impl ResourceSelector {
    pub fn parse(literal: &str) -> Result<Self, crate::cap::CapError> {
        Ok(Self {
            pattern: Capability::parse(literal)?,
        })
    }

    /// The verb this selector authorizes (`perform`/`read`/`write`/…).
    pub fn verb(&self) -> &str {
        &self.pattern.verb
    }

    /// Does this selector match `(verb, target)`, ignoring constraints?
    pub fn matches(&self, verb: &str, target: &crate::path::Path) -> bool {
        // `covers` is fail-closed on predicates; selector matching is
        // structural only, so test the path pattern directly.
        self.pattern.verb_scheme_segments_match(verb, target)
    }
}

/// Dynamic narrowing conditions on a grant (§5.1): input-field predicates,
/// time windows, quotas. Evaluation is **fail-closed** — a missing field,
/// type mismatch, or expired window means "not covered". Reuses the
/// [`Capability`] predicate machinery; the constraints are the residual the
/// hot path checks for a `Conditional` handle.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConstraintSet {
    /// Each entry is a `@key<op>value` predicate carried on a capability.
    /// All must hold for the grant to cover a request.
    pub predicates: Vec<crate::cap::Predicate>,
}

impl ConstraintSet {
    pub fn empty() -> Self {
        Self { predicates: vec![] }
    }

    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    /// Fail-closed evaluation against an operation `input` at `now_millis`.
    /// Every predicate must hold.
    pub fn eval(&self, input: &Value, now_millis: i64) -> bool {
        self.predicates.iter().all(|p| p.eval(input, now_millis))
    }
}

/// When a grant stops being valid (§5.1).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expiry {
    /// Never expires on its own (revocation still applies).
    #[default]
    Never,
    /// Expires at this wall-clock millis-since-epoch.
    At(i64),
}

impl Expiry {
    pub fn is_expired(self, now_millis: i64) -> bool {
        matches!(self, Expiry::At(t) if now_millis > t)
    }
}

/// The source form of a capability (§5.1): attenuable, delegable, derivable.
/// `open()` (in `nexus-kernel`) compiles a Grant against a Resource into a
/// `Handle`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    pub holder: ProcessId,
    pub selector: ResourceSelector,
    pub rights: Rights,
    pub constraints: ConstraintSet,
    pub expires: Expiry,
}

impl Grant {
    /// Whether this grant currently covers `(verb, target)` with operation
    /// `input` at `now_millis`: selector matches, not expired, constraints
    /// hold. Fail-closed throughout.
    pub fn covers(
        &self,
        verb: &str,
        target: &crate::path::Path,
        input: &Value,
        now_millis: i64,
    ) -> bool {
        if self.expires.is_expired(now_millis) {
            return false;
        }
        self.selector.matches(verb, target) && self.constraints.eval(input, now_millis)
    }
}
