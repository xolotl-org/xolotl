//! Shared continuation modules assembled independently of execution.
//!
//! Native functions and portable program loaders share one namespace. An executor
//! resolves names in its own module; continuations retain the caller's grants.

use crate::executor::PreparedProgram;
use std::collections::{HashMap, hash_map::Entry};
use std::sync::Arc;
use thiserror::Error;
use xolotl_graph::DoNode;
use xolotl_types::{Failure, Value};

/// A pure, total `(piped_value, optional_arg) -> Do<A>` function.
/// Time, randomness and I/O must go through returned Operation nodes.
/// Returned subgraphs resolve Step names in the executor's module and structured
/// `state://process/self/...` paths in the invoking process.
pub type StepFn = Arc<dyn Fn(Value, Option<Value>) -> DoNode + Send + Sync>;

/// Select or prepare portable code without consuming the invocation's input.
///
/// Loaders are synchronous and effect-free. Obtain external source data through
/// Operations before invoking a loader. The module retains the loader, not its
/// returned images; hosts may explicitly retain shared preparations in a loader.
pub type ProgramLoader =
    Arc<dyn Fn(&Value, Option<&Value>) -> Result<PreparedProgram, Failure> + Send + Sync>;

/// Host-declared semantic identity of a portable loader and its captured configuration.
///
/// The same revision must select the same code for the same input and argument.
/// Change it whenever the implementation or captured configuration changes. Recovery
/// verifies this declaration; it cannot detect an undeclared implementation change.
/// This is independent of the identities of the programs returned by the loader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "durable", derive(serde::Serialize, serde::Deserialize))]
pub struct LoaderRevision([u8; 32]);

impl LoaderRevision {
    /// Supply an immutable version or content fingerprint chosen by the host.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Inspect the persisted identity without allocating.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone)]
pub(crate) enum Continuation {
    Native(StepFn),
    Program {
        revision: LoaderRevision,
        loader: ProgramLoader,
    },
}

/// A named continuation supplied while assembling a [`StepModule`].
#[derive(Clone)]
pub struct StepBinding {
    /// Name referenced by `StepRef` in the composed module.
    pub name: String,
    continuation: Continuation,
}

impl StepBinding {
    /// Associate a name with a shared continuation.
    pub fn new(name: impl Into<String>, step: StepFn) -> Self {
        Self {
            name: name.into(),
            continuation: Continuation::Native(step),
        }
    }

    /// Associate a name with an on-demand portable program loader.
    pub fn program(
        name: impl Into<String>,
        revision: LoaderRevision,
        loader: ProgramLoader,
    ) -> Self {
        Self {
            name: name.into(),
            continuation: Continuation::Program { revision, loader },
        }
    }
}

/// Invalid module assembly. Rejected composition does not change inputs.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum StepModuleError {
    /// A name contains only whitespace or is empty.
    #[error("step name must not be empty")]
    EmptyName,
    /// More than one function defines the same name.
    #[error("duplicate step name {name:?}")]
    Duplicate {
        /// Conflicting name in the composed namespace.
        name: String,
    },
}

/// A validated, immutable collection of native and portable continuations.
///
/// Clones share the name table and functions. The empty module allocates nothing.
/// Composition happens before execution; runtime lookup borrows the function
/// without locking or incrementing its reference count.
#[derive(Clone, Default)]
pub struct StepModule {
    functions: Option<Arc<HashMap<String, Continuation>>>,
}

impl std::fmt::Debug for StepModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepModule")
            .field("len", &self.len())
            .finish()
    }
}

impl StepModule {
    /// Build a module with one named function.
    pub fn single<F>(name: impl Into<String>, function: F) -> Result<Self, StepModuleError>
    where
        F: Fn(Value, Option<Value>) -> DoNode + Send + Sync + 'static,
    {
        Self::new([StepBinding::new(name, Arc::new(function))])
    }

    /// Bind a portable loader in the same namespace as native continuations.
    ///
    /// The returned image enters the current execution with unchanged input,
    /// provenance and acting identity. Code is reclaimed when the call exits.
    /// A durable caller freezes the loader's revision in its imports, and the host
    /// must supply that revision again during recovery. Input and constant arguments
    /// are checkpointed; closures are not. Perform external reads as Operations.
    pub fn program<F>(
        name: impl Into<String>,
        revision: LoaderRevision,
        loader: F,
    ) -> Result<Self, StepModuleError>
    where
        F: Fn(&Value, Option<&Value>) -> Result<PreparedProgram, Failure> + Send + Sync + 'static,
    {
        Self::new([StepBinding::program(name, revision, Arc::new(loader))])
    }

    /// Validate names and assemble a module from shared continuations.
    pub fn new(bindings: impl IntoIterator<Item = StepBinding>) -> Result<Self, StepModuleError> {
        let mut functions = HashMap::new();
        for binding in bindings {
            if binding.name.trim().is_empty() {
                return Err(StepModuleError::EmptyName);
            }
            insert(&mut functions, binding.name, binding.continuation)?;
        }
        Ok(Self {
            functions: (!functions.is_empty()).then(|| Arc::new(functions)),
        })
    }

    /// Combine modules in one namespace, rejecting duplicate definitions.
    ///
    /// Functions remain shared. An already shared name table is copied only
    /// when it needs to be combined with another nonempty module.
    pub fn compose(modules: impl IntoIterator<Item = Self>) -> Result<Self, StepModuleError> {
        let mut composed = Self::default();
        for module in modules {
            let Some(functions) = module.functions else {
                continue;
            };
            let Some(current) = &mut composed.functions else {
                composed.functions = Some(functions);
                continue;
            };
            let current = Arc::make_mut(current);
            for (name, function) in Arc::unwrap_or_clone(functions) {
                insert(current, name, function)?;
            }
        }
        Ok(composed)
    }

    /// Number of installed names.
    pub fn len(&self) -> usize {
        self.functions
            .as_ref()
            .map_or(0, |functions| functions.len())
    }

    /// Whether the module contains no functions.
    pub fn is_empty(&self) -> bool {
        self.functions.is_none()
    }

    /// Whether a name is present in this module.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Continuation> {
        self.functions.as_ref()?.get(name)
    }
}

fn insert(
    functions: &mut HashMap<String, Continuation>,
    name: String,
    function: Continuation,
) -> Result<(), StepModuleError> {
    match functions.entry(name) {
        Entry::Occupied(entry) => Err(StepModuleError::Duplicate {
            name: entry.key().clone(),
        }),
        Entry::Vacant(entry) => {
            entry.insert(function);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    fn binding(name: &str, value: i64) -> StepBinding {
        StepBinding::new(name, Arc::new(move |_, _| DoNode::pure(value)))
    }

    fn native<'a>(module: &'a StepModule, name: &str) -> anyhow::Result<&'a StepFn> {
        match module.get(name).context("missing continuation")? {
            Continuation::Native(function) => Ok(function),
            Continuation::Program { .. } => anyhow::bail!("expected native function"),
        }
    }

    #[test]
    fn compose_keeps_inputs_independent_and_shares_functions() -> anyhow::Result<()> {
        let first = StepModule::new([binding("first", 1)])?;
        let second = StepModule::new([binding("second", 2)])?;
        let joined = StepModule::compose([first.clone(), StepModule::default(), second.clone()])?;
        ensure!(joined.len() == 2);
        ensure!(!first.contains("second") && !second.contains("first"));
        ensure!(Arc::ptr_eq(
            native(&joined, "first")?,
            native(&first, "first")?,
        ));
        ensure!(native(&joined, "second")?(Value::null(), None) == DoNode::pure(2));
        Ok(())
    }

    #[test]
    fn invalid_assembly_and_composition_leave_inputs_unchanged() -> anyhow::Result<()> {
        ensure!(matches!(
            StepModule::new([binding("  ", 1)]),
            Err(StepModuleError::EmptyName)
        ));
        ensure!(matches!(
            StepModule::new([binding("same", 1), binding("same", 2)]),
            Err(StepModuleError::Duplicate { .. })
        ));
        let first = StepModule::new([binding("same", 1)])?;
        let second = StepModule::new([binding("other", 2), binding("same", 3)])?;
        ensure!(matches!(
            StepModule::compose([first.clone(), second.clone()]),
            Err(StepModuleError::Duplicate { .. })
        ));
        ensure!(first.len() == 1 && second.len() == 2);
        ensure!(native(&first, "same")?(Value::null(), None) == DoNode::pure(1));
        ensure!(native(&second, "same")?(Value::null(), None) == DoNode::pure(3));
        Ok(())
    }

    #[test]
    fn functions_live_until_the_last_module_owner_releases_them() -> anyhow::Result<()> {
        let function: StepFn = Arc::new(|value, _| DoNode::pure(value));
        let weak = Arc::downgrade(&function);
        let module = StepModule::new([StepBinding::new("identity", function)])?;
        let shared = module.clone();
        drop(module);
        ensure!(weak.upgrade().is_some());
        drop(shared);
        ensure!(weak.upgrade().is_none());
        Ok(())
    }

    #[test]
    fn native_and_portable_bindings_share_validation_and_loader_ownership() -> anyhow::Result<()> {
        let loader: ProgramLoader = Arc::new(|_, _| Err(Failure::Cancelled));
        let weak = Arc::downgrade(&loader);
        let portable = StepModule::new([StepBinding::program(
            "shared",
            LoaderRevision::from_bytes([1; 32]),
            loader,
        )])?;
        let native = StepModule::single("shared", |value, _| DoNode::pure(value))?;
        ensure!(matches!(
            StepModule::compose([portable.clone(), native]),
            Err(StepModuleError::Duplicate { name }) if name == "shared"
        ));
        let shared = portable.clone();
        drop(portable);
        ensure!(weak.upgrade().is_some());
        drop(shared);
        ensure!(weak.upgrade().is_none());
        Ok(())
    }
}
