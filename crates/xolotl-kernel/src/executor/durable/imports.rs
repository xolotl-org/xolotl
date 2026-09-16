//! Freeze loader contracts beside host imports and revalidate them before replay.

use super::*;
use crate::step::Continuation;

impl Executor {
    pub(in crate::executor) fn bind_durable_imports(
        &self,
        program: &mut MachineProgram,
    ) -> Result<(), Failure> {
        self.validate_durable_imports(program, false)?;
        for import in &mut program.imports {
            if let Import::Step(step, revision) = import {
                *revision = Some(self.loader_revision(&step.name)?);
            }
        }
        Ok(())
    }

    pub(crate) fn validate_checkpoint_imports(
        &self,
        program: &PreparedProgram,
    ) -> Result<(), Failure> {
        self.validate_durable_imports(&program.inner, true)
    }

    pub(super) fn validate_durable_imports(
        &self,
        program: &MachineProgram,
        frozen: bool,
    ) -> Result<(), Failure> {
        for import in &program.imports {
            match import {
                Import::Step(step, revision) => {
                    let current = self.loader_revision(&step.name)?;
                    if revision.is_some_and(|saved| saved != current)
                        || (frozen && revision.is_none())
                    {
                        return Err(machine_error(format!(
                            "loader {:?} revision is missing or changed",
                            step.name
                        )));
                    }
                }
                Import::Operation(operation, _) => {
                    if matches!(
                        operation.output,
                        xolotl_types::OutputMode::AsyncProcess | xolotl_types::OutputMode::Stream
                    ) {
                        return Err(machine_error(
                            "durable requests require owned results; use unary, collect or sink-only output",
                        ));
                    }
                    let meta = self
                        .resolve_meta(&operation.target, &operation.method)
                        .ok_or_else(|| Failure::NoHandler {
                            path: operation.target.path().clone(),
                        })?;
                    if !operation.output.is_supported_by(meta.supports) {
                        return Err(machine_error(
                            "durable import output contract is unavailable",
                        ));
                    }
                }
                Import::Vacant | Import::Wait(_) | Import::Scope(_) | Import::Transform(_) => {}
            }
        }
        Ok(())
    }

    fn loader_revision(&self, name: &str) -> Result<crate::LoaderRevision, Failure> {
        match self.steps.get(name) {
            Some(Continuation::Program { revision, .. }) => Ok(*revision),
            Some(Continuation::Native(_)) => Err(machine_error(format!(
                "durable loader {name:?} cannot be a native continuation"
            ))),
            None => Err(machine_error(format!("loader {name:?} is unavailable"))),
        }
    }
}

impl ExecutionSnapshot {
    /// Portable loaders needed by the retained program, including pending loads
    /// and imports in active modules. Duplicate names may appear across modules.
    /// Arguments and pending inputs are stored separately in this same snapshot.
    /// A recovery host supplies matching implementations through its StepModule.
    pub fn loader_dependencies(&self) -> impl Iterator<Item = (&str, crate::LoaderRevision)> + '_ {
        self.program
            .inner
            .imports
            .iter()
            .filter_map(|import| match import {
                Import::Step(step, Some(revision)) => Some((step.name.as_str(), *revision)),
                _ => None,
            })
    }
}
