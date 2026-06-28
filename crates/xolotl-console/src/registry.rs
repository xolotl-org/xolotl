//! Action descriptor registry with a real, deterministic `registry_rev`.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::protocol::{ActionDescriptor, action_descriptors};

/// Bumped when the descriptor schema or any descriptor field set changes, so
/// clients caching by `registry_rev` refresh even if the id set is unchanged.
const DESCRIPTOR_SCHEMA_VERSION: u32 = 1;

pub struct DescriptorRegistry {
    actions_by_id: BTreeMap<String, ActionDescriptor>,
    registry_rev: u64,
}

impl DescriptorRegistry {
    pub fn new() -> Self {
        let mut actions_by_id = BTreeMap::new();
        for descriptor in action_descriptors() {
            actions_by_id.insert(descriptor.id.clone(), descriptor);
        }
        let registry_rev = compute_registry_rev(&actions_by_id);
        Self {
            actions_by_id,
            registry_rev,
        }
    }

    pub fn current_rev(&self) -> u64 {
        self.registry_rev
    }

    pub fn action_by_id(&self, id: &str) -> Option<&ActionDescriptor> {
        self.actions_by_id.get(id)
    }
}

impl Default for DescriptorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a deterministic revision: high 32 bits carry the descriptor schema
/// version, low 32 bits carry a stable hash of the canonical descriptor
/// serialization. The rev changes only when the descriptor set or schema
/// changes, and stays stable across restarts for an unchanged set.
fn compute_registry_rev(actions: &BTreeMap<String, ActionDescriptor>) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"xolotl-console-descriptor-registry-v1");
    for (id, descriptor) in actions {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
        match serde_json::to_vec(descriptor) {
            Ok(serialized) => hasher.update(serialized),
            Err(_) => hasher.update(b"<serialize-failed>"),
        }
        hasher.update(b"\0");
    }
    let digest = hasher.finalize();
    let low = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (u64::from(DESCRIPTOR_SCHEMA_VERSION) << 32) | u64::from(low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_rev_is_stable_across_rebuilds() {
        let a = DescriptorRegistry::new();
        let b = DescriptorRegistry::new();
        assert_eq!(
            a.current_rev(),
            b.current_rev(),
            "rev must be deterministic"
        );
    }

    #[test]
    fn registry_rev_encodes_schema_version_in_high_bits() {
        let registry = DescriptorRegistry::new();
        assert_eq!(
            registry.current_rev() >> 32,
            u64::from(DESCRIPTOR_SCHEMA_VERSION),
        );
    }

    #[test]
    fn known_actions_resolve_by_id() {
        let registry = DescriptorRegistry::new();
        assert!(registry.action_by_id("config.write_cas").is_some());
        assert!(registry.action_by_id("no.such.action").is_none());
    }
}
