//! Borrowed lookups for the Executor's flat, process-local caches.
//!
//! Keys are owned when inserted; a cache hit never needs to copy a concrete
//! path or method name. The maps retain Rust's randomized hasher because
//! resource names can originate outside the host.

use super::MethodMeta;
use hashbrown::{Equivalent, HashMap};
use std::collections::hash_map::RandomState;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use xolotl_types::{HandleId, IdentityRef, ResourceName};

pub(super) type OpenHandleMap = HashMap<(ResourceName, IdentityRef), HandleId, RandomState>;
pub(super) type MethodHandleMap =
    HashMap<(ResourceName, String, IdentityRef), MethodHandle, RandomState>;
pub(super) type MethodMetaMap = HashMap<(ResourceName, String), Arc<MethodMeta>, RandomState>;

/// Explicit bindings retain the host's selected authority. Automatic opens may
/// replace a narrow handle when a later call needs additional rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MethodHandle {
    Bound(HandleId),
    Opened(HandleId),
}

#[cfg(test)]
impl MethodHandle {
    pub fn id(self) -> HandleId {
        match self {
            Self::Bound(id) | Self::Opened(id) => id,
        }
    }
}

pub(super) struct OpenHandleKey<'a> {
    pub name: &'a ResourceName,
    pub acting: IdentityRef,
}

impl Hash for OpenHandleKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.name, self.acting).hash(state);
    }
}

impl Equivalent<(ResourceName, IdentityRef)> for OpenHandleKey<'_> {
    fn equivalent(&self, key: &(ResourceName, IdentityRef)) -> bool {
        self.name == &key.0 && self.acting == key.1
    }
}

pub(super) struct MethodHandleKey<'a> {
    pub name: &'a ResourceName,
    pub method: &'a str,
    pub acting: IdentityRef,
}

impl<'a> From<&'a (ResourceName, String, IdentityRef)> for MethodHandleKey<'a> {
    fn from(key: &'a (ResourceName, String, IdentityRef)) -> Self {
        Self {
            name: &key.0,
            method: &key.1,
            acting: key.2,
        }
    }
}

impl Hash for MethodHandleKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.name, self.method, self.acting).hash(state);
    }
}

impl Equivalent<(ResourceName, String, IdentityRef)> for MethodHandleKey<'_> {
    fn equivalent(&self, key: &(ResourceName, String, IdentityRef)) -> bool {
        self.name == &key.0 && self.method == key.1 && self.acting == key.2
    }
}

pub(super) struct MethodMetaKey<'a> {
    pub name: &'a ResourceName,
    pub method: &'a str,
}

impl Hash for MethodMetaKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.name, self.method).hash(state);
    }
}

impl Equivalent<(ResourceName, String)> for MethodMetaKey<'_> {
    fn equivalent(&self, key: &(ResourceName, String)) -> bool {
        self.name == &key.0 && self.method == key.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xolotl_types::Path;

    #[test]
    fn borrowed_keys_keep_path_method_and_identity_distinct() -> anyhow::Result<()> {
        macro_rules! ensure_eq {
            ($actual:expr, $expected:expr) => {
                anyhow::ensure!($actual == $expected, "borrowed cache key mismatch")
            };
        }
        let first = ResourceName::new(Path::parse("state://cache/first")?);
        let second = ResourceName::new(Path::parse("state://cache/second")?);
        let owner = IdentityRef::ROOT;
        let other = IdentityRef::new(42);
        let handle = HandleId::new(3, 1);
        let mut opens = OpenHandleMap::default();
        opens.insert((first.clone(), owner), handle);
        ensure_eq!(
            opens.get(&OpenHandleKey {
                name: &first,
                acting: owner
            }),
            Some(&handle)
        );
        ensure_eq!(
            opens.get(&OpenHandleKey {
                name: &second,
                acting: owner
            }),
            None
        );
        ensure_eq!(
            opens.get(&OpenHandleKey {
                name: &first,
                acting: other
            }),
            None
        );

        let mut methods = MethodHandleMap::default();
        methods.insert(
            (first.clone(), "read".into(), owner),
            MethodHandle::Bound(handle),
        );
        ensure_eq!(
            methods.get(&MethodHandleKey {
                name: &first,
                method: "read",
                acting: owner
            }),
            Some(&MethodHandle::Bound(handle))
        );
        ensure_eq!(
            methods.get(&MethodHandleKey {
                name: &first,
                method: "write",
                acting: owner
            }),
            None
        );
        ensure_eq!(
            methods.get(&MethodHandleKey {
                name: &second,
                method: "read",
                acting: owner
            }),
            None
        );
        ensure_eq!(
            methods.get(&MethodHandleKey {
                name: &first,
                method: "read",
                acting: other
            }),
            None
        );

        let mut metadata = HashMap::<(ResourceName, String), u8, RandomState>::default();
        metadata.insert((first.clone(), "read".into()), 1);
        ensure_eq!(
            metadata.get(&MethodMetaKey {
                name: &first,
                method: "read"
            }),
            Some(&1)
        );
        ensure_eq!(
            metadata.get(&MethodMetaKey {
                name: &first,
                method: "write"
            }),
            None
        );
        ensure_eq!(
            metadata.get(&MethodMetaKey {
                name: &second,
                method: "read"
            }),
            None
        );
        Ok(())
    }
}
