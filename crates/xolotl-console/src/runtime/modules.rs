//! Host-assembled portable loaders with explicit, transitive authority manifests.

use std::{collections::BTreeMap, io::Write, sync::Arc};
use xolotl_graph::{OperationTemplate, portable::Program};
use xolotl_types::{Failure, OutputMode, Path, ResourceName, Value};

/// One method/output allowance a module may import. Literal inputs remain program data.
/// `Collect { limit }` declares the maximum number of items the loader may request;
/// every other output mode is matched exactly.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleOperation {
    /// Concrete installed resource, local or cluster-qualified.
    pub target: ResourceName,
    /// Method resolved by name in that resource.
    pub method: String,
    /// Allowed output mode; for `Collect`, `limit` is an inclusive upper bound.
    pub output: OutputMode,
}

impl ModuleOperation {
    pub(crate) fn template(&self) -> OperationTemplate {
        OperationTemplate {
            target: self.target.clone(),
            method: self.method.clone(),
            output: self.output,
            method_id: None,
            literal_input: None,
        }
    }

    pub(crate) fn permits(&self, operation: &OperationTemplate) -> bool {
        operation.method_id.is_none()
            && self.target == operation.target
            && self.method == operation.method
            && match (self.output, operation.output) {
                (
                    OutputMode::Collect { limit: max_limit },
                    OutputMode::Collect { limit: requested },
                ) => requested > 0 && requested <= max_limit,
                (declared, requested) => declared == requested,
            }
    }
}

/// Discoverable bounds of a trusted host loader. Every declared dependency is
/// authorized before the enclosing execution starts, even for untaken branches.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    /// Name referenced by portable `Module` expressions.
    pub name: String,
    /// Host semantic fingerprint of the loader and captured configuration.
    /// Change it whenever the same input/argument could select different code.
    pub revision: [u8; 32],
    /// Direct operation allowances; one `Collect` bound covers smaller limits.
    pub operations: Vec<ModuleOperation>,
    /// Concrete local process identities this loader may enter with Acting.
    pub identities: Vec<Path>,
    /// Concrete paths this loader may await through unary `subscribe`.
    pub signals: Vec<Path>,
    /// Other installed module names this loader may reference. Cycles are allowed;
    /// kernel transition and resident code budgets bound recursion.
    pub modules: Vec<String>,
}

type Loader = dyn Fn(&Value, Option<&Value>) -> Result<Program, Failure> + Send + Sync;

// The whole canonical catalog is serialized in runtime discovery and registry
// revision hashing. Bound its encoded size before accepting a host assembly.
const MAX_MANIFEST_CATALOG_BYTES: usize = 512 * 1024;

#[derive(Default)]
struct BoundedCounter(usize);

impl Write for BoundedCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_MANIFEST_CATALOG_BYTES)
            .ok_or_else(|| std::io::Error::other("console module catalog byte limit exceeded"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A trusted, synchronous, effect-free loader. The piped input and optional
/// `StepRef.arg` select portable code; input and provenance remain in the kernel.
/// Loaders must be total and bounded. I/O, time and randomness belong in returned
/// Operations. Console cannot preempt blocking Rust code or enforce its purity.
#[derive(Clone)]
pub struct ConsoleModule {
    pub(crate) manifest: Arc<ModuleManifest>,
    pub(crate) loader: Arc<Loader>,
}

impl ConsoleModule {
    /// Bind a semantic manifest to a loader. Assembly checks names/dependencies;
    /// every returned program is checked against this manifest before execution.
    pub fn new<F>(manifest: ModuleManifest, loader: F) -> Self
    where
        F: Fn(&Value, Option<&Value>) -> Result<Program, Failure> + Send + Sync + 'static,
    {
        Self {
            manifest: Arc::new(manifest),
            loader: Arc::new(loader),
        }
    }
}

impl std::fmt::Debug for ConsoleModule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsoleModule")
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

/// Immutable module namespace composed independently of Console transports.
/// Module clones share loaders and canonical manifests. Remote clients cannot
/// install or replace native code.
#[derive(Clone, Debug, Default)]
pub struct ConsoleModules {
    pub(crate) entries: BTreeMap<String, ConsoleModule>,
}

/// Invalid host module assembly; rejected composition does not alter its inputs.
#[derive(Debug, thiserror::Error)]
pub enum ModuleConfigError {
    /// Empty, oversized or duplicate name, or an invalid operation declaration.
    #[error("invalid console module manifest: {0}")]
    Manifest(String),
    /// A declared module has not been installed in the final namespace.
    #[error("console module dependency is missing: {0}")]
    MissingDependency(String),
    /// Host assembly exceeds the bounded catalog or manifest size.
    #[error("console module catalog limit exceeded")]
    Capacity,
}

impl ConsoleModules {
    /// Assemble modules, rejecting duplicate names and malformed manifests.
    /// Dependencies are linked when ConsoleState is constructed, so independently
    /// assembled namespaces can depend on one another before composition.
    pub fn new(
        modules: impl IntoIterator<Item = ConsoleModule>,
    ) -> Result<Self, ModuleConfigError> {
        let mut entries = BTreeMap::new();
        let mut size = BoundedCounter::default();
        size.write_all(b"[")
            .map_err(|_error| ModuleConfigError::Capacity)?;
        for mut module in modules {
            // Assembly owns normalization. Copy only when the host retained a
            // clone of this module; execution bindings share the frozen result.
            let manifest = Arc::make_mut(&mut module.manifest);
            if entries.len() >= 1024
                || manifest.operations.len() > 1024
                || manifest.identities.len() > 1024
                || manifest.signals.len() > 1024
                || manifest.modules.len() > 1024
            {
                return Err(ModuleConfigError::Capacity);
            }
            if !valid_name(&manifest.name)
                || manifest.modules.iter().any(|name| !valid_name(name))
                || entries.contains_key(&manifest.name)
            {
                return Err(ModuleConfigError::Manifest(manifest.name.clone()));
            }
            for operation in &manifest.operations {
                let path = operation.target.path();
                if operation.method.is_empty()
                    || operation.method.len() > 256
                    || !valid_resource_path(path)
                    || matches!(operation.output, OutputMode::Collect { limit: 0 })
                {
                    return Err(ModuleConfigError::Manifest(manifest.name.clone()));
                }
            }
            if manifest.identities.iter().any(|path| !valid_identity(path)) {
                return Err(ModuleConfigError::Manifest(manifest.name.clone()));
            }
            manifest.identities.sort();
            manifest.identities.dedup();
            if manifest
                .signals
                .iter()
                .any(|path| !valid_resource_path(path))
            {
                return Err(ModuleConfigError::Manifest(manifest.name.clone()));
            }
            manifest.signals.sort();
            manifest.signals.dedup();
            manifest.modules.sort();
            manifest.modules.dedup();
            // Ordered, minimal allowances make revisions independent of
            // declaration order and redundant smaller Collect bounds.
            manifest.operations.sort_by(|a, b| {
                a.target
                    .path()
                    .cmp(b.target.path())
                    .then_with(|| a.method.cmp(&b.method))
                    .then_with(|| output_order(a.output).cmp(&output_order(b.output)))
            });
            manifest.operations.dedup_by(|next, previous| {
                if next.target != previous.target || next.method != previous.method {
                    return false;
                }
                if let (
                    OutputMode::Collect { limit: next_max },
                    OutputMode::Collect {
                        limit: previous_max,
                    },
                ) = (next.output, previous.output)
                {
                    previous.output = OutputMode::Collect {
                        limit: previous_max.max(next_max),
                    };
                    return true;
                }
                next.output == previous.output
            });
            if !entries.is_empty() {
                size.write_all(b",")
                    .map_err(|_error| ModuleConfigError::Capacity)?;
            }
            serde_json::to_writer(&mut size, &*manifest)
                .map_err(|_error| ModuleConfigError::Capacity)?;
            entries.insert(manifest.name.clone(), module);
        }
        size.write_all(b"]")
            .map_err(|_error| ModuleConfigError::Capacity)?;
        Ok(Self { entries })
    }

    /// Combine independently assembled namespaces; duplicate definitions fail.
    pub fn compose(modules: impl IntoIterator<Item = Self>) -> Result<Self, ModuleConfigError> {
        Self::new(
            modules
                .into_iter()
                .flat_map(|module| module.entries.into_values()),
        )
    }

    /// Inspect canonical manifests without exposing code or captured values.
    pub fn manifests(&self) -> impl Iterator<Item = &ModuleManifest> {
        self.entries.values().map(|module| module.manifest.as_ref())
    }

    pub(crate) fn link(&self) -> Result<(), ModuleConfigError> {
        for manifest in self.manifests() {
            for name in &manifest.modules {
                if !self.entries.contains_key(name) {
                    return Err(ModuleConfigError::MissingDependency(name.clone()));
                }
            }
        }
        Ok(())
    }
}

fn output_order(output: OutputMode) -> (u8, usize) {
    match output {
        OutputMode::Unary => (0, 0),
        OutputMode::Stream => (1, 0),
        OutputMode::Collect { limit } => (2, limit),
        OutputMode::AsyncProcess => (3, 0),
        OutputMode::SinkOnly => (4, 0),
    }
}

pub(crate) fn valid_identity(path: &Path) -> bool {
    path.cluster().is_none()
        && path.to_string().len() <= 4096
        && xolotl_kernel::identity::validate_path(path).is_ok()
}

fn valid_resource_path(path: &Path) -> bool {
    path.is_concrete()
        && !path.segments().is_empty()
        && path.to_string().len() <= 4096
        && !xolotl_types::is_kernel_reserved(path)
        && !xolotl_types::is_vault_reserved(path)
        && !xolotl_types::is_fact_reserved(path)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.trim() == name
        && !name.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use xolotl_graph::portable::Expression;

    #[test]
    fn module_clones_share_frozen_manifests_without_changing_host_inputs() -> anyhow::Result<()> {
        let module = ConsoleModule::new(
            ModuleManifest {
                name: "parent".into(),
                revision: [1; 32],
                operations: Vec::new(),
                identities: Vec::new(),
                signals: Vec::new(),
                modules: vec!["child".into(), "child".into()],
            },
            |_, _| Ok(Program::new(Expression::Input)),
        );
        let retained = module.clone();
        ensure!(Arc::ptr_eq(&module.manifest, &retained.manifest));

        let assembled = ConsoleModules::new([module])?;
        ensure!(retained.manifest.modules.len() == 2);
        ensure!(assembled.entries["parent"].manifest.modules == vec!["child".to_owned()]);
        ensure!(!Arc::ptr_eq(
            &retained.manifest,
            &assembled.entries["parent"].manifest
        ));

        let binding = assembled.entries["parent"].clone();
        ensure!(Arc::ptr_eq(
            &binding.manifest,
            &assembled.entries["parent"].manifest
        ));
        Ok(())
    }

    #[test]
    fn collect_allowances_canonicalize_to_the_largest_declared_bound() -> anyhow::Result<()> {
        let operation = ModuleOperation {
            target: ResourceName::new(Path::parse("effect://example/collect")?),
            method: "invoke".into(),
            output: OutputMode::Collect { limit: 3 },
        };
        let manifest = |operations| ModuleManifest {
            name: "collect".into(),
            revision: [1; 32],
            operations,
            identities: Vec::new(),
            signals: Vec::new(),
            modules: Vec::new(),
        };
        let assemble = |operations| {
            ConsoleModules::new([ConsoleModule::new(manifest(operations), |_, _| {
                Ok(Program::new(Expression::Input))
            })])
        };
        let canonical = assemble(vec![operation.clone()])?;
        let mut smaller = operation.clone();
        smaller.output = OutputMode::Collect { limit: 1 };
        let redundant = assemble(vec![operation, smaller.clone(), smaller])?;
        let revision = |modules: &ConsoleModules| {
            crate::registry::DescriptorRegistry::with_config(
                &crate::runtime::ConsoleRuntimeConfig::default(),
                &crate::ConsoleStreamConfig::default(),
                modules,
                true,
                &crate::mgmt::ConfigAdmissionRegistry::default(),
                false,
                false,
            )
            .current_rev()
        };
        ensure!(canonical.manifests().next() == redundant.manifests().next());
        ensure!(
            redundant
                .manifests()
                .next()
                .map(|entry| entry.operations.len())
                == Some(1)
        );
        ensure!(revision(&canonical) == revision(&redundant));
        let mut wider = canonical
            .manifests()
            .next()
            .context("canonical manifest")?
            .clone();
        wider.operations[0].output = OutputMode::Collect { limit: 4 };
        ensure!(revision(&canonical) != revision(&assemble(wider.operations)?));
        Ok(())
    }

    #[test]
    fn complete_canonical_catalog_has_a_bounded_encoded_size() -> anyhow::Result<()> {
        let mut identities = Vec::new();
        for index in 0..127 {
            let prefix = format!("identity://catalog/{index}/");
            identities.push(Path::parse(&format!(
                "{prefix}{}",
                "x".repeat(4096 - prefix.len())
            ))?);
        }
        let last_prefix = "identity://catalog/last/";
        identities.push(Path::parse(&format!("{last_prefix}x"))?);
        let mut manifest = ModuleManifest {
            name: "bounded".into(),
            revision: [1; 32],
            operations: Vec::new(),
            identities,
            signals: Vec::new(),
            modules: Vec::new(),
        };
        let encoded = serde_json::to_vec(&[&manifest])?.len();
        let remaining = MAX_MANIFEST_CATALOG_BYTES - encoded;
        ensure!(last_prefix.len() + 1 + remaining < 4096);
        *manifest.identities.last_mut().context("last identity")? =
            Path::parse(&format!("{last_prefix}{}", "x".repeat(1 + remaining)))?;
        ensure!(serde_json::to_vec(&[&manifest])?.len() == MAX_MANIFEST_CATALOG_BYTES);
        let install = |manifest| {
            ConsoleModules::new([ConsoleModule::new(manifest, |_, _| {
                Ok(Program::new(Expression::Input))
            })])
        };
        install(manifest.clone())?;
        *manifest.identities.last_mut().context("last identity")? =
            Path::parse(&format!("{last_prefix}{}", "x".repeat(2 + remaining)))?;
        ensure!(matches!(
            install(manifest),
            Err(ModuleConfigError::Capacity)
        ));
        Ok(())
    }
}
