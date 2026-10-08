//! Revision of the complete action, stream, resource and view discovery contract.

use std::{collections::BTreeMap, sync::OnceLock};

use sha2::{Digest, Sha256};

use crate::protocol::{
    ActionDescriptor, StreamDescriptor, action_descriptors, resource_type_registry,
    resource_type_summaries, resource_view_registry, stream_descriptors,
};
use xolotl_types::Value;

pub struct DescriptorRegistry {
    actions_by_id: &'static BTreeMap<&'static str, &'static ActionDescriptor>,
    streams: &'static [StreamDescriptor],
    local_accounts: bool,
    federation_management: bool,
    observations: bool,
    config_writes: ConfigWriteAvailability,
    registry_rev: u64,
}

#[derive(Clone, Copy, Default)]
struct ConfigWriteAvailability {
    manifests: bool,
    inference_backends: bool,
    inference_models: bool,
    inference_groups: bool,
    inference_routing: bool,
}

impl ConfigWriteAvailability {
    fn from_admissions(admissions: &crate::mgmt::ConfigAdmissionRegistry) -> Self {
        Self {
            manifests: admissions.overlaps_collection(&["kernel", "manifests"]),
            inference_backends: admissions.overlaps_collection(&[
                "kernel",
                "inference",
                "backends",
            ]),
            inference_models: admissions.overlaps_collection(&["kernel", "inference", "models"]),
            inference_groups: admissions.overlaps_collection(&["kernel", "inference", "groups"]),
            inference_routing: admissions.covers_path(&["kernel", "routing", "inference"]),
        }
    }

    fn bytes(self) -> [u8; 5] {
        [
            self.manifests.into(),
            self.inference_backends.into(),
            self.inference_models.into(),
            self.inference_groups.into(),
            self.inference_routing.into(),
        ]
    }
}

impl DescriptorRegistry {
    pub fn new() -> Self {
        Self::with_config(
            &crate::runtime::ConsoleRuntimeConfig::default(),
            &crate::ConsoleStreamConfig::default(),
            &crate::runtime::ConsoleModules::default(),
            true,
            &crate::mgmt::ConfigAdmissionRegistry::default(),
            false,
            false,
        )
    }

    pub fn with_config(
        runtime: &crate::runtime::ConsoleRuntimeConfig,
        limits: &crate::ConsoleStreamConfig,
        modules: &crate::runtime::ConsoleModules,
        local_accounts: bool,
        config_admissions: &crate::mgmt::ConfigAdmissionRegistry,
        federation_management: bool,
        observations: bool,
    ) -> Self {
        // Contracts are process-wide; only the revision also depends on this
        // host's execution configuration. The index borrows IDs and schemas.
        static ACTIONS_BY_ID: OnceLock<BTreeMap<&str, &ActionDescriptor>> = OnceLock::new();
        let actions_by_id = ACTIONS_BY_ID.get_or_init(|| {
            action_descriptors()
                .iter()
                .map(|descriptor| (descriptor.id.as_str(), descriptor))
                .collect()
        });
        let streams = stream_descriptors();
        let config_writes = ConfigWriteAvailability::from_admissions(config_admissions);
        let registry_rev = compute_registry_rev(
            actions_by_id,
            streams,
            resource_type_registry(),
            resource_view_registry(),
            RegistryRevisionConfig {
                runtime,
                limits,
                modules,
                local_accounts,
                federation_management,
                observations,
                config_writes,
            },
        );
        Self {
            actions_by_id,
            streams,
            local_accounts,
            federation_management,
            observations,
            config_writes,
            registry_rev,
        }
    }

    pub fn current_rev(&self) -> u64 {
        self.registry_rev
    }

    pub fn action_by_id(&self, id: &str) -> Option<&ActionDescriptor> {
        if !self.action_enabled(id) {
            return None;
        }
        self.actions_by_id.get(id).copied()
    }

    pub(crate) fn action_enabled(&self, id: &str) -> bool {
        if !self.observations
            && matches!(
                id,
                crate::protocol::ACTION_AUDIT_FACTS_RECENT
                    | crate::protocol::ACTION_LINEAGE_TRACE_READ
                    | crate::protocol::ACTION_LINEAGE_FACT_READ
            )
        {
            return false;
        }
        if !self.local_accounts && local_account_action(id) {
            return false;
        }
        if !self.federation_management && federation_management_action(id) {
            return false;
        }
        match id {
            crate::protocol::ACTION_EXTERNAL_MANIFEST_WRITE_CAS => self.config_writes.manifests,
            crate::protocol::ACTION_INFERENCE_BACKEND_WRITE_CAS => {
                self.config_writes.inference_backends
            }
            crate::protocol::ACTION_INFERENCE_MODEL_WRITE_CAS => {
                self.config_writes.inference_models
            }
            crate::protocol::ACTION_INFERENCE_GROUP_WRITE_CAS => {
                self.config_writes.inference_groups
            }
            crate::protocol::ACTION_INFERENCE_ROUTING_WRITE_CAS => {
                self.config_writes.inference_routing
            }
            _ => true,
        }
    }

    pub fn stream_by_id(&self, id: &str) -> Option<&StreamDescriptor> {
        if !self.observations && id == crate::protocol::STREAM_AUDIT_FACTS {
            return None;
        }
        self.streams.iter().find(|descriptor| descriptor.id == id)
    }

    pub(crate) fn resource_type_list_value(&self) -> Value {
        let types = resource_type_registry()
            .keys()
            .filter_map(|id| {
                self.resource_type_descriptor_value(id)
                    .map(|value| (*id, value))
            })
            .collect();
        resource_type_summaries(&types)
    }

    pub(crate) fn resource_type_descriptor_value(&self, resource_type: &str) -> Option<Value> {
        let mut descriptor = resource_type_registry()
            .get(resource_type)?
            .as_map()?
            .clone();
        let read_action = descriptor.get("read_action")?.as_str()?;
        if !self.action_enabled(read_action) {
            return None;
        }
        for field in ["list_action", "update_action", "validate_action"] {
            let Some(action) = descriptor.get(field).and_then(Value::as_str) else {
                continue;
            };
            if !self.action_enabled(action) {
                descriptor.insert(field.into(), Value::null()).ok()?;
                if field == "update_action" {
                    descriptor
                        .insert("revision_field".into(), Value::null())
                        .ok()?;
                }
            }
        }
        Some(Value::from(descriptor))
    }

    pub(crate) fn resource_view_descriptor_value(&self, view: &str) -> Option<Value> {
        let descriptor = resource_view_registry().get(view)?;
        let read_action = descriptor.as_map()?.get("read_action")?.as_str()?;
        self.action_enabled(read_action).then(|| descriptor.clone())
    }
}

fn local_account_action(id: &str) -> bool {
    matches!(
        id,
        crate::protocol::ACTION_ACCESS_USER_READ
            | crate::protocol::ACTION_ACCESS_USER_LIST
            | crate::protocol::ACTION_ACCESS_USER_WRITE_CAS
            | crate::protocol::ACTION_ACCESS_USER_DISABLE
            | crate::protocol::ACTION_ACCESS_ROLE_READ
            | crate::protocol::ACTION_ACCESS_ROLE_LIST
            | crate::protocol::ACTION_ACCESS_ROLE_WRITE_CAS
    )
}

fn federation_management_action(id: &str) -> bool {
    matches!(
        id,
        crate::protocol::ACTION_FEDERATION_PEER_READ
            | crate::protocol::ACTION_FEDERATION_PEER_LIST
            | crate::protocol::ACTION_FEDERATION_PEER_WRITE_CAS
            | crate::protocol::ACTION_FEDERATION_PEER_ADMISSION_READ
            | crate::protocol::ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS
            | crate::protocol::ACTION_FEDERATION_EXPORT_READ
            | crate::protocol::ACTION_FEDERATION_EXPORT_LIST
            | crate::protocol::ACTION_FEDERATION_EXPORT_WRITE_CAS
    )
}

impl Default for DescriptorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a deterministic 63-bit revision from the v1 descriptor contract.
/// The top bit is clear so Value's signed integer projection preserves it.
/// Protocol version is reported separately; the hash includes a v1 domain
/// separator and the effective host contract.
struct RegistryRevisionConfig<'a> {
    runtime: &'a crate::runtime::ConsoleRuntimeConfig,
    limits: &'a crate::ConsoleStreamConfig,
    modules: &'a crate::runtime::ConsoleModules,
    local_accounts: bool,
    federation_management: bool,
    observations: bool,
    config_writes: ConfigWriteAvailability,
}

fn compute_registry_rev(
    actions: &BTreeMap<&str, &ActionDescriptor>,
    streams: &[StreamDescriptor],
    resource_types: &BTreeMap<&str, Value>,
    resource_views: &BTreeMap<&str, Value>,
    config: RegistryRevisionConfig<'_>,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"xolotl-console-descriptor-registry-v1");
    hasher.update([u8::from(config.local_accounts)]);
    hasher.update([u8::from(config.federation_management)]);
    hasher.update([u8::from(config.observations)]);
    hasher.update(config.config_writes.bytes());
    for (id, descriptor) in actions {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
        match serde_json::to_vec(descriptor) {
            Ok(serialized) => hasher.update(serialized),
            Err(_) => hasher.update(b"<serialize-failed>"),
        }
        hasher.update(b"\0");
    }
    // Stream contracts are cached under the same revision as actions.
    let mut streams: Vec<_> = streams.iter().collect();
    streams.sort_by(|a, b| a.id.cmp(&b.id));
    hasher.update(b"streams\0");
    for descriptor in streams {
        match serde_json::to_vec(descriptor) {
            Ok(serialized) => hasher.update(serialized),
            Err(_) => hasher.update(b"<serialize-failed>"),
        }
        hasher.update(b"\0");
    }
    // Type editing metadata and view bindings are cached under this revision too.
    for (label, descriptors) in [
        ("resource_types", resource_types),
        ("resource_views", resource_views),
    ] {
        hasher.update(label.as_bytes());
        hasher.update(b"\0");
        for (id, descriptor) in descriptors {
            hasher.update(id.as_bytes());
            hasher.update(b"\0");
            match serde_json::to_vec(descriptor) {
                Ok(serialized) => hasher.update(serialized),
                Err(_) => hasher.update(b"<serialize-failed>"),
            }
            hasher.update(b"\0");
        }
    }
    hasher.update(b"resource_summaries\0");
    if let Ok(serialized) = serde_json::to_vec(&resource_type_summaries(resource_types)) {
        hasher.update(serialized);
    }
    hasher.update(b"runtime\0");
    if let Ok(serialized) = serde_json::to_vec(config.runtime) {
        hasher.update(serialized);
    }
    hasher.update(b"subscription_limits\0");
    if let Ok(serialized) = serde_json::to_vec(config.limits) {
        hasher.update(serialized);
    }
    hasher.update(b"modules\0");
    if let Ok(serialized) = serde_json::to_vec(&config.modules.manifests().collect::<Vec<_>>()) {
        hasher.update(serialized);
    }
    let digest = hasher.finalize();
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]) & (i64::MAX as u64)
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
    fn registry_rev_fits_its_signed_value_projection() {
        let registry = DescriptorRegistry::new();
        assert!(i64::try_from(registry.current_rev()).is_ok());
    }

    #[test]
    fn discovery_and_admission_share_complete_contracts() {
        let registry = DescriptorRegistry::new();
        let snapshot = crate::protocol::registry_snapshot(1, registry.current_rev(), 0);
        for descriptor in &snapshot.actions {
            assert_eq!(
                registry.action_by_id(&descriptor.id),
                registry
                    .action_enabled(&descriptor.id)
                    .then_some(descriptor)
            );
        }
        for descriptor in &snapshot.streams {
            assert_eq!(
                registry.stream_by_id(&descriptor.id),
                (descriptor.id != crate::protocol::STREAM_AUDIT_FACTS).then_some(descriptor)
            );
        }
        assert!(registry.action_by_id("no.such.action").is_none());
        assert!(registry.stream_by_id("no.such.stream").is_none());
    }

    #[test]
    fn observation_discovery_matches_installed_storage_and_changes_revision() {
        let disabled = DescriptorRegistry::new();
        let enabled = DescriptorRegistry::with_config(
            &crate::runtime::ConsoleRuntimeConfig::default(),
            &crate::ConsoleStreamConfig::default(),
            &crate::runtime::ConsoleModules::default(),
            true,
            &crate::mgmt::ConfigAdmissionRegistry::default(),
            false,
            true,
        );
        for action in [
            crate::protocol::ACTION_AUDIT_FACTS_RECENT,
            crate::protocol::ACTION_LINEAGE_TRACE_READ,
            crate::protocol::ACTION_LINEAGE_FACT_READ,
        ] {
            assert!(disabled.action_by_id(action).is_none());
            assert!(enabled.action_by_id(action).is_some());
        }
        assert!(
            disabled
                .stream_by_id(crate::protocol::STREAM_AUDIT_FACTS)
                .is_none()
        );
        assert!(
            enabled
                .stream_by_id(crate::protocol::STREAM_AUDIT_FACTS)
                .is_some()
        );
        assert!(
            disabled
                .stream_by_id(crate::protocol::STREAM_STATE_WATCH)
                .is_some()
        );
        assert_ne!(disabled.current_rev(), enabled.current_rev());
    }

    #[test]
    fn configuration_write_actions_follow_installed_owners() -> anyhow::Result<()> {
        use anyhow::{Context, ensure};

        let empty = DescriptorRegistry::new();
        ensure!(
            empty
                .action_by_id(crate::protocol::ACTION_EXTERNAL_MANIFEST_WRITE_CAS)
                .is_none()
        );
        ensure!(
            empty
                .action_by_id(crate::protocol::ACTION_INFERENCE_BACKEND_WRITE_CAS)
                .is_none()
        );
        ensure!(
            empty
                .action_by_id(crate::protocol::ACTION_CONFIG_WRITE_CAS)
                .is_some()
        );

        let admissions = crate::mgmt::ConfigAdmissionRegistry::new(vec![
            crate::ConfigNamespaceAdmission::new(
                xolotl_types::Path::parse("state://kernel/manifests/acme")?,
                |_path, _value| Ok(()),
            ),
            crate::ConfigNamespaceAdmission::new(
                xolotl_types::Path::parse("state://kernel/inference/backends/acme")?,
                |_path, _value| Ok(()),
            ),
        ])?;
        let configured = DescriptorRegistry::with_config(
            &crate::runtime::ConsoleRuntimeConfig::default(),
            &crate::ConsoleStreamConfig::default(),
            &crate::runtime::ConsoleModules::default(),
            true,
            &admissions,
            false,
            false,
        );
        ensure!(
            configured
                .action_by_id(crate::protocol::ACTION_INFERENCE_BACKEND_WRITE_CAS)
                .is_some()
        );
        ensure!(
            configured
                .action_by_id(crate::protocol::ACTION_EXTERNAL_MANIFEST_WRITE_CAS)
                .is_some()
        );
        ensure!(
            configured
                .action_by_id(crate::protocol::ACTION_INFERENCE_MODEL_WRITE_CAS)
                .is_none()
        );
        let backend = configured
            .resource_type_descriptor_value("inference.backend")
            .context("backend remains discoverable")?;
        ensure!(
            backend
                .as_map()
                .and_then(|descriptor| descriptor.get("update_action"))
                .and_then(Value::as_str)
                == Some(crate::protocol::ACTION_INFERENCE_BACKEND_WRITE_CAS)
        );
        let manifest = configured
            .resource_type_descriptor_value("external.manifest")
            .context("manifest remains discoverable")?;
        ensure!(
            manifest
                .as_map()
                .and_then(|descriptor| descriptor.get("update_action"))
                .and_then(Value::as_str)
                == Some(crate::protocol::ACTION_EXTERNAL_MANIFEST_WRITE_CAS)
        );
        ensure!(empty.current_rev() != configured.current_rev());
        Ok(())
    }

    #[test]
    fn federation_actions_follow_host_installed_management_port() {
        let unavailable = DescriptorRegistry::new();
        assert!(
            unavailable
                .action_by_id(crate::protocol::ACTION_FEDERATION_PEER_READ)
                .is_none()
        );
        let available = DescriptorRegistry::with_config(
            &crate::runtime::ConsoleRuntimeConfig::default(),
            &crate::ConsoleStreamConfig::default(),
            &crate::runtime::ConsoleModules::default(),
            true,
            &crate::mgmt::ConfigAdmissionRegistry::default(),
            true,
            false,
        );
        for action in [
            crate::protocol::ACTION_FEDERATION_PEER_READ,
            crate::protocol::ACTION_FEDERATION_PEER_LIST,
            crate::protocol::ACTION_FEDERATION_PEER_WRITE_CAS,
            crate::protocol::ACTION_FEDERATION_PEER_ADMISSION_READ,
            crate::protocol::ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS,
            crate::protocol::ACTION_FEDERATION_EXPORT_READ,
            crate::protocol::ACTION_FEDERATION_EXPORT_LIST,
            crate::protocol::ACTION_FEDERATION_EXPORT_WRITE_CAS,
        ] {
            assert!(available.action_by_id(action).is_some());
        }
        assert_ne!(available.current_rev(), unavailable.current_rev());
    }

    #[test]
    fn effective_resource_discovery_only_references_available_actions() -> anyhow::Result<()> {
        use anyhow::{Context, ensure};

        let registry = DescriptorRegistry::with_config(
            &crate::runtime::ConsoleRuntimeConfig::default(),
            &crate::ConsoleStreamConfig::default(),
            &crate::runtime::ConsoleModules::default(),
            false,
            &crate::mgmt::ConfigAdmissionRegistry::default(),
            false,
            false,
        );
        ensure!(
            registry
                .resource_type_descriptor_value("access.user")
                .is_none()
        );
        ensure!(
            registry
                .resource_view_descriptor_value("access.users")
                .is_none()
        );

        let manifest = registry
            .resource_type_descriptor_value("external.manifest")
            .context("manifest remains readable")?;
        let manifest = manifest.as_map().context("manifest descriptor")?;
        ensure!(manifest.get("update_action").is_some_and(Value::is_null));
        ensure!(manifest.get("revision_field").is_some_and(Value::is_null));

        let summaries = registry.resource_type_list_value();
        for summary in summaries.as_list().context("resource summaries")? {
            let summary = summary.as_map().context("resource summary")?;
            for field in ["read_action", "update_action"] {
                if let Some(action) = summary.get(field).and_then(Value::as_str) {
                    ensure!(
                        registry.action_by_id(action).is_some(),
                        "hidden {field}: {action}"
                    );
                }
            }
        }
        for resource_type in resource_type_registry().keys() {
            let Some(descriptor) = registry.resource_type_descriptor_value(resource_type) else {
                continue;
            };
            let descriptor = descriptor.as_map().context("resource type descriptor")?;
            for field in [
                "read_action",
                "list_action",
                "update_action",
                "validate_action",
            ] {
                if let Some(action) = descriptor.get(field).and_then(Value::as_str) {
                    ensure!(
                        registry.action_by_id(action).is_some(),
                        "hidden {field}: {action}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn stream_contract_changes_invalidate_registry_cache() {
        let registry = DescriptorRegistry::new();
        let mut streams = stream_descriptors().to_vec();
        let revision = |streams: &[StreamDescriptor]| {
            compute_registry_rev(
                registry.actions_by_id,
                streams,
                resource_type_registry(),
                resource_view_registry(),
                RegistryRevisionConfig {
                    runtime: &crate::runtime::ConsoleRuntimeConfig::default(),
                    limits: &crate::ConsoleStreamConfig::default(),
                    modules: &crate::runtime::ConsoleModules::default(),
                    local_accounts: true,
                    federation_management: false,
                    observations: false,
                    config_writes: ConfigWriteAvailability::default(),
                },
            )
        };
        let original = revision(&streams);
        streams.reverse();
        assert_eq!(original, revision(&streams));
        streams[0]
            .input
            .notes
            .push("changed stream contract".into());
        assert_ne!(original, revision(&streams));
    }

    #[test]
    fn editing_and_view_contract_changes_invalidate_registry_cache() -> anyhow::Result<()> {
        use anyhow::{Context, ensure};
        let registry = DescriptorRegistry::new();
        let streams = stream_descriptors();
        let mut types = resource_type_registry().clone();
        let mut views = resource_view_registry().clone();
        let revision = |types: &BTreeMap<&str, Value>, views: &BTreeMap<&str, Value>| {
            compute_registry_rev(
                registry.actions_by_id,
                streams,
                types,
                views,
                RegistryRevisionConfig {
                    runtime: &crate::runtime::ConsoleRuntimeConfig::default(),
                    limits: &crate::ConsoleStreamConfig::default(),
                    modules: &crate::runtime::ConsoleModules::default(),
                    local_accounts: true,
                    federation_management: false,
                    observations: false,
                    config_writes: ConfigWriteAvailability::default(),
                },
            )
        };
        let original = revision(&types, &views);
        ensure!(original == registry.current_rev());
        let mut descriptor = types["config.entry"].as_map().context("type map")?.clone();
        descriptor.insert("fields".into(), Value::list(vec![]))?;
        types.insert("config.entry", Value::from(descriptor));
        ensure!(original != revision(&types, &views));
        let with_type_change = revision(&types, &views);
        let mut descriptor = views["config.entries"]
            .as_map()
            .context("view map")?
            .clone();
        descriptor.insert("pagination".into(), Value::string("none".into()))?;
        views.insert("config.entries", Value::from(descriptor));
        ensure!(with_type_change != revision(&types, &views));
        Ok(())
    }

    #[test]
    fn resource_discovery_references_registered_contracts() -> anyhow::Result<()> {
        use anyhow::{Context, ensure};
        let registry = DescriptorRegistry::new();
        let types = resource_type_registry();
        let views = resource_view_registry();
        let summaries = resource_type_summaries(types);
        let summaries = summaries.as_list().context("summaries")?;
        ensure!(summaries.len() == types.len());
        for summary in summaries {
            let summary = summary.as_map().context("summary")?;
            ensure!(summary.len() == 5);
            let id = summary
                .get("resource_type")
                .and_then(Value::as_str)
                .context("resource type")?;
            let descriptor = types[id].as_map().context("type descriptor")?;
            for (key, value) in summary {
                ensure!(
                    descriptor.get(key) == Some(value),
                    "summary drift: {id}.{key}"
                );
            }
            let view = descriptor
                .get("default_view")
                .and_then(Value::as_str)
                .context("default view")?;
            ensure!(views.contains_key(view));
            for action in [
                "read_action",
                "list_action",
                "update_action",
                "validate_action",
            ] {
                if let Some(id) = descriptor.get(action).and_then(Value::as_str) {
                    ensure!(
                        registry.actions_by_id.contains_key(id),
                        "unknown {action}: {id}"
                    );
                }
            }
            let update = descriptor
                .get("update_action")
                .and_then(Value::as_str)
                .and_then(|id| registry.actions_by_id.get(id).copied());
            let expects_version = update.is_some_and(|action| {
                action
                    .input
                    .fields
                    .iter()
                    .any(|field| field.name == "expected_version")
            });
            ensure!(
                descriptor.get("revision_field").and_then(Value::as_str)
                    == expects_version.then_some("expected_version")
            );
        }
        for descriptor in views.values() {
            let descriptor = descriptor.as_map().context("view descriptor")?;
            ensure!(
                types.contains_key(
                    descriptor
                        .get("resource_type")
                        .and_then(Value::as_str)
                        .context("type")?
                )
            );
            let action = registry
                .actions_by_id
                .get(
                    descriptor
                        .get("read_action")
                        .and_then(Value::as_str)
                        .context("action")?,
                )
                .context("registered action")?;
            ensure!(descriptor.get("query_schema") == Some(&serde_value(&action.input)?));
            ensure!(descriptor.get("projection_schema") == Some(&serde_value(&action.output)?));
        }
        Ok(())
    }

    fn serde_value(value: &impl serde::Serialize) -> anyhow::Result<Value> {
        Ok(serde_json::from_value(serde_json::to_value(value)?)?)
    }
}
