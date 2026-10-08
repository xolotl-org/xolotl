//! Caller-visible module catalog. This is a structural discovery projection,
//! never a replacement for execution admission.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn visible_manifests<'a>(
    state: &'a ConsoleState,
    principal: &ConsolePrincipal,
) -> Vec<&'a crate::runtime::ModuleManifest> {
    let mut hidden = BTreeSet::new();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let registry = state.boot.kernel().registry();

    for manifest in state.modules.manifests() {
        for dependency in &manifest.modules {
            dependents
                .entry(dependency.as_str())
                .or_default()
                .push(manifest.name.as_str());
        }
        if !directly_visible(state, principal, registry, manifest) {
            hidden.insert(manifest.name.as_str());
        }
    }

    // A manifest may name a dependency only when that dependency's complete
    // manifest is visible too. Reverse propagation handles cycles without
    // repeatedly traversing each candidate's transitive closure.
    let mut pending: Vec<_> = hidden.iter().copied().collect();
    while let Some(name) = pending.pop() {
        if let Some(parents) = dependents.get(name) {
            for parent in parents {
                if hidden.insert(*parent) {
                    pending.push(*parent);
                }
            }
        }
    }

    state
        .modules
        .manifests()
        .filter(|manifest| !hidden.contains(manifest.name.as_str()))
        .collect()
}

fn directly_visible(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    registry: &xolotl_kernel::registry::Registry,
    manifest: &crate::runtime::ModuleManifest,
) -> bool {
    manifest.operations.iter().all(|operation| {
        method_visible(
            state,
            &principal.grants,
            registry,
            &operation.target,
            &operation.method,
            operation.output,
        )
    }) && manifest
        .identities
        .iter()
        .all(|identity| allowed(state, &principal.grants, "act-as", identity))
        && manifest.signals.iter().all(|path| {
            method_visible(
                state,
                &principal.grants,
                registry,
                &ResourceName::new(path.clone()),
                "subscribe",
                OutputMode::Unary,
            )
        })
}

fn method_visible(
    state: &ConsoleState,
    grants: &CapSet,
    registry: &xolotl_kernel::registry::Registry,
    target: &ResourceName,
    method: &str,
    output: OutputMode,
) -> bool {
    let path = target.path();
    // Mirror resource discovery's guard before resolving existence.
    if !target_allowed(state, grants, path) {
        return false;
    }
    let Some((_, contract)) = registry
        .resolve_resource(target)
        .ok()
        .and_then(|resource| registry.resource_method(resource, method))
    else {
        return false;
    };
    method_allowed(
        state,
        grants,
        contract.authority.verb(),
        path,
        &contract.name,
    ) && output_supported(state, output, contract.supports)
        && (output != OutputMode::AsyncProcess
            || propagation_method_allowed(state, grants, path, &contract.name))
}
