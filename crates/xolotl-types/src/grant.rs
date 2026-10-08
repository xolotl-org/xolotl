//! `Grant` — the *source* form of a capability.
//!
//! A capability has two forms:
//!
//! - [`Grant`] — attenuable, delegable, derivable. A selector + rights +
//!   constraints + expiry. This is the "source code".
//! - `Handle` (in `xolotl-kernel`) — the compiled form produced by `open()`:
//!   a closed, executable, `O(1)` token. This is the "compiled product".
//!
//! `Grant` lives in `xolotl-types` because it is pure data the control plane
//! reasons about and the console renders; `Handle` carries a live dispatch
//! table and lives in the kernel.

use crate::cap::Capability;
use crate::ids::{GrantId, ProcessId};
use crate::value::Value;
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

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
    /// Method bitmap in a resolved Resource contract. Handles and open
    /// requests use this compiled form; Grants use stable method names.
    ///
    /// Methods are assigned bit positions across the Resource's interfaces in
    /// declaration order. Admission rejects more than 64 methods in that set.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct MethodBitmap: u64 {
        /// No methods.
        const NONE = 0;
        /// All methods.
        const ALL  = u64::MAX;
    }
}
bitflags_serde_bits!(MethodBitmap, u64);

impl MethodBitmap {
    /// Bit for method index `i` (its position in the resource's combined method list).
    pub fn method(i: u32) -> Self {
        debug_assert!(i < 64, "resources are limited to 64 methods");
        MethodBitmap::from_bits_retain(1u64 << i)
    }

    /// Whether method index `i` is allowed.
    pub fn allows(self, i: u32) -> bool {
        i < 64 && self.contains(MethodBitmap::method(i))
    }

    /// Bitmap subset test: is `self` ⊆ `other`? This preserves the attenuation
    /// invariant that a derived handle's methods must be a subset of its
    /// parent's methods.
    pub fn is_subset_of(self, other: MethodBitmap) -> bool {
        other.contains(self)
    }
}

/// Method authority carried by a Grant before a Resource contract is opened.
/// Named methods survive interface reordering; only `all()` deliberately
/// includes methods added by a later resource relink.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GrantMethods(GrantMethodSelection);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum GrantMethodSelection {
    None,
    All,
    Names(Arc<[String]>),
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "names", rename_all = "snake_case")]
enum GrantMethodsWire {
    None,
    All,
    Names(Vec<String>),
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "names", rename_all = "snake_case")]
enum GrantMethodsRef<'a> {
    None,
    All,
    Names(&'a [String]),
}

impl Serialize for GrantMethods {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            GrantMethodSelection::None => GrantMethodsRef::None.serialize(serializer),
            GrantMethodSelection::All => GrantMethodsRef::All.serialize(serializer),
            GrantMethodSelection::Names(names) => {
                GrantMethodsRef::Names(names.as_ref()).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for GrantMethods {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match GrantMethodsWire::deserialize(deserializer)? {
            GrantMethodsWire::None => Self::none(),
            GrantMethodsWire::All => Self::all(),
            GrantMethodsWire::Names(names) => Self::names(names),
        })
    }
}

impl GrantMethods {
    /// Grant no callable methods; propagation flags may still be granted.
    pub const fn none() -> Self {
        Self(GrantMethodSelection::None)
    }

    /// Explicitly grant every matching method, including future methods.
    pub const fn all() -> Self {
        Self(GrantMethodSelection::All)
    }

    /// Grant these stable method names. Order and duplicates are normalized.
    pub fn names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut names: Vec<String> = names.into_iter().map(Into::into).collect();
        names.sort_unstable();
        names.dedup();
        if names.is_empty() {
            Self::none()
        } else {
            Self(GrantMethodSelection::Names(names.into()))
        }
    }

    /// Grant one stable method name.
    pub fn name(name: impl Into<String>) -> Self {
        Self(GrantMethodSelection::Names(Arc::from([name.into()])))
    }

    /// Whether this grants no callable methods.
    pub fn is_empty(&self) -> bool {
        matches!(self.0, GrantMethodSelection::None)
    }

    /// Whether a method in the selected Resource contract is covered.
    pub fn allows(&self, name: &str) -> bool {
        match &self.0 {
            GrantMethodSelection::None => false,
            GrantMethodSelection::All => true,
            GrantMethodSelection::Names(names) => names
                .binary_search_by(|candidate| candidate.as_str().cmp(name))
                .is_ok(),
        }
    }

    /// Explicit stable names, if this is not an open-ended `all` selection.
    /// `none` returns an empty slice.
    pub fn selected_names(&self) -> Option<&[String]> {
        match &self.0 {
            GrantMethodSelection::None => Some(&[]),
            GrantMethodSelection::All => None,
            GrantMethodSelection::Names(names) => Some(names.as_ref()),
        }
    }

    /// Compile a requested bitmap against one Resource's current method list.
    /// Unknown bit positions fail closed. Callers also check the request verb.
    pub fn covers_bitmap(&self, requested: MethodBitmap, methods: &[crate::Method]) -> bool {
        let mut bits = requested.bits();
        while bits != 0 {
            let index = bits.trailing_zeros() as usize;
            let Some(method) = methods.get(index) else {
                return false;
            };
            if !self.allows(&method.name) {
                return false;
            }
            bits &= bits - 1;
        }
        true
    }

    /// Whether this selection attenuates another Grant's method selection.
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        match (&self.0, &parent.0) {
            (GrantMethodSelection::None, _) | (_, GrantMethodSelection::All) => true,
            (GrantMethodSelection::All, _) | (_, GrantMethodSelection::None) => false,
            (GrantMethodSelection::Names(child), GrantMethodSelection::Names(parent)) => {
                child.iter().all(|name| parent.binary_search(name).is_ok())
            }
        }
    }

    /// Union two selections while preserving their explicit future-method policy.
    pub fn union(&self, other: &Self) -> Self {
        match (&self.0, &other.0) {
            (GrantMethodSelection::All, _) | (_, GrantMethodSelection::All) => Self::all(),
            (GrantMethodSelection::None, _) => other.clone(),
            (_, GrantMethodSelection::None) => self.clone(),
            (GrantMethodSelection::Names(left), GrantMethodSelection::Names(right)) => {
                Self::names(left.iter().chain(right.iter()).cloned())
            }
        }
    }
}

bitflags::bitflags! {
    /// Derivation flags on a grant. Independent of which methods are
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
    /// Clone a handle.
    Clone,
    /// Transfer a handle to another process.
    Transfer,
    /// Pass a handle to a spawned child.
    SpawnWith,
    /// Delegate authority.
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

/// Compiled method bits and derivation flags on an open request or Handle.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Rights {
    /// Authorized method bitmap.
    pub methods: MethodBitmap,
    /// Authorized propagation flags.
    pub flags: RightFlags,
}

impl Rights {
    /// Create rights from method and propagation bitsets.
    pub fn new(methods: MethodBitmap, flags: RightFlags) -> Self {
        Self { methods, flags }
    }

    /// Bitmap subset used by `open()` and handle derivation: requested rights
    /// must be ⊆ the grant's rights, and flags monotonically attenuate.
    pub fn is_subset_of(&self, parent: &Rights) -> bool {
        self.methods.is_subset_of(parent.methods) && parent.flags.contains(self.flags)
    }

    /// Whether the parent's flags permit the requested derivation kind.
    pub fn allows_derive(&self, kind: DeriveKind) -> bool {
        self.flags.contains(kind.required_flag())
    }
}

/// Stable method selection and propagation flags on a source Grant.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct GrantRights {
    /// Authorized method names, or an explicit grant of all matching methods.
    pub methods: GrantMethods,
    /// Authorized Handle propagation.
    pub flags: RightFlags,
}

impl GrantRights {
    /// Build source rights without consulting a Resource's current layout.
    pub fn new(methods: GrantMethods, flags: RightFlags) -> Self {
        Self { methods, flags }
    }

    /// Whether both method and propagation authority are empty.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty() && self.flags.is_empty()
    }

    /// Source-level attenuation is independent of method bit positions.
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.methods.is_subset_of(&parent.methods) && parent.flags.contains(self.flags)
    }
}

/// Which Resources a grant matches. The same selector serves both
/// authorization (does `open()` of resource R hit this grant?) and capability
/// discovery. It is a path pattern, reusing the [`Capability`] literal
/// grammar (cluster scope and `*` / `**` segments).
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ResourceSelector {
    /// The path-pattern capability literal, e.g. `read://state/memory/alice/**`.
    /// `verb`/`cluster`/`scheme`/`segments` come straight from [`Capability`].
    pub pattern: Capability,
}

impl ResourceSelector {
    /// Selector covering every verb and path.
    pub fn all() -> Self {
        Self {
            pattern: Capability {
                verb: "*".to_string(),
                cluster: None,
                scheme: "**".to_string(),
                segments: vec![SmolStr::from("**")],
                method: None,
                predicate: None,
            },
        }
    }

    /// Parse a selector from a capability literal.
    pub fn parse(literal: &str) -> Result<Self, crate::cap::CapError> {
        Ok(Self {
            pattern: Capability::parse(literal)?,
        })
    }

    /// Select one concrete resource path with the given capability verb.
    /// Preserves cluster qualification without formatting and reparsing a path.
    pub fn exact(verb: &str, target: &crate::path::Path) -> Result<Self, crate::cap::CapError> {
        if !target.is_concrete() {
            return Err(crate::cap::CapError::Malformed(
                "exact resource selector requires a concrete path".into(),
            ));
        }
        let pattern = Capability::try_new(
            verb,
            target.scheme(),
            target.segments().iter().map(|segment| segment.as_str()),
            None,
        )?;
        let pattern = match target.cluster() {
            Some(cluster) => pattern.try_with_cluster(cluster)?,
            None => pattern,
        };
        Ok(Self { pattern })
    }

    /// The verb this selector authorizes (`perform`/`read`/`write`/…).
    pub fn verb(&self) -> &str {
        &self.pattern.verb
    }

    /// Does this selector structurally match `(verb, target)`, including its
    /// cluster? Callers must check its predicate against the operation input.
    pub fn matches(&self, verb: &str, target: &crate::path::Path) -> bool {
        self.pattern.matches_structure(verb, target)
    }
}

/// Dynamic narrowing conditions on a grant: input-field predicates,
/// time windows, quotas. Evaluation is **fail-closed** — a missing field,
/// type mismatch, or expired window means "not covered". Reuses the
/// [`Capability`] predicate machinery; the constraints are the residual the
/// hot path checks for a `Conditional` handle.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ConstraintSet {
    /// Each entry is a `@key<op>value` predicate carried on a capability.
    /// All must hold for the grant to cover a request.
    pub predicates: Vec<crate::cap::Predicate>,
}

impl ConstraintSet {
    /// Empty constraint set.
    pub fn empty() -> Self {
        Self { predicates: vec![] }
    }

    /// Whether no constraints are present.
    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    /// Fail-closed evaluation against an operation `input` at `now_millis`.
    /// Every predicate must hold.
    pub fn eval(&self, input: &Value, now_millis: i64) -> bool {
        self.predicates.iter().all(|p| p.eval(input, now_millis))
    }
}

/// When a grant stops being valid.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Expiry {
    /// Never expires on its own (revocation still applies).
    #[default]
    Never,
    /// Expires at this wall-clock millis-since-epoch.
    At(i64),
}

impl Expiry {
    /// Return true if the expiry has passed at `now_millis`.
    pub fn is_expired(self, now_millis: i64) -> bool {
        matches!(self, Expiry::At(t) if now_millis > t)
    }
}

/// The source form of a capability: attenuable, delegable, derivable.
/// `open()` (in `xolotl-kernel`) compiles a Grant against a Resource into a
/// `Handle`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    /// Grant id.
    pub id: GrantId,
    /// Process holding the grant.
    pub holder: ProcessId,
    /// Resources and verb this grant selects.
    pub selector: ResourceSelector,
    /// Rights authorized by this grant.
    pub rights: GrantRights,
    /// Residual constraints on use.
    pub constraints: ConstraintSet,
    /// Expiry policy.
    pub expires: Expiry,
}

impl Grant {
    /// Whether this grant currently covers `(verb, target)` with operation
    /// `input` at `now_millis`: selector structure, its predicate, inherited
    /// constraints and expiry must all hold. Fail-closed throughout.
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
        self.selector.matches(verb, target)
            && self
                .selector
                .pattern
                .predicate
                .as_ref()
                .is_none_or(|predicate| predicate.eval(input, now_millis))
            && self.constraints.eval(input, now_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Path;
    use anyhow::{Result, ensure};

    #[test]
    fn grant_method_names_are_canonical_and_all_is_explicit() -> Result<()> {
        let names = GrantMethods::names(["write", "read", "read"]);
        ensure!(names == GrantMethods::names(["read", "write"]));
        ensure!(names.allows("read") && !names.allows("new_method"));
        ensure!(GrantMethods::name("read").is_subset_of(&names));
        ensure!(!names.is_subset_of(&GrantMethods::name("read")));
        ensure!(names.is_subset_of(&GrantMethods::all()));
        ensure!(!GrantMethods::all().is_subset_of(&names));
        let restored: GrantMethods =
            serde_json::from_str(r#"{"kind":"names","names":["write","read","read"]}"#)?;
        ensure!(restored == names);
        ensure!(
            serde_json::to_value(&restored)?
                == serde_json::json!({
                    "kind": "names", "names": ["read", "write"]
                })
        );
        Ok(())
    }

    #[test]
    fn exact_selector_preserves_cluster_and_rejects_patterns() -> Result<()> {
        let target = Path::parse("path://phone/effect/external-provider/acme/search")?;
        let selector = ResourceSelector::exact("perform", &target)?;
        ensure!(selector.matches("perform", &target));
        ensure!(!selector.matches(
            "perform",
            &Path::parse("effect://external-provider/acme/search")?
        ));
        ensure!(!selector.matches("read", &target));
        ensure!(ResourceSelector::exact("perform", &Path::parse("effect://tools/**")?).is_err());
        Ok(())
    }

    #[test]
    fn grant_covers_requires_selector_and_inherited_conditions() -> Result<()> {
        let grant = Grant {
            id: GrantId::new(1),
            holder: ProcessId::new(2),
            selector: ResourceSelector::parse("perform://effect/job/run@tenant=alice")?,
            rights: GrantRights::new(GrantMethods::none(), RightFlags::empty()),
            constraints: ConstraintSet {
                predicates: vec![crate::Predicate::parse("lane=east")?],
            },
            expires: Expiry::At(10),
        };
        let target = Path::parse("effect://job/run")?;
        for (tenant, lane, now_millis, allowed) in [
            ("alice", "east", 10, true),
            ("bob", "east", 10, false),
            ("alice", "west", 10, false),
            ("alice", "east", 11, false),
        ] {
            let input = Value::map(alloc::collections::BTreeMap::from([
                ("tenant".into(), Value::string(tenant.into())),
                ("lane".into(), Value::string(lane.into())),
            ]));
            ensure!(grant.covers("perform", &target, &input, now_millis) == allowed);
        }
        ensure!(!grant.covers("read", &target, &Value::null(), 0));
        Ok(())
    }
}
