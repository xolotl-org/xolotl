//! Console action recipes executed as capability-scoped request Processes.

use xolotl_graph::{DoNode, OperationTemplate};
use xolotl_kernel::{Bootstrap, CompiledRequestGrantTemplate, RequestProcess};
use xolotl_types::{
    CapError, ExecutionOutput, Failure, GrantMethods, GrantRights, Outcome, OutputMode, Path,
    ResourceName, RightFlags, TaintSet, Value,
};

use crate::auth::{ConsolePrincipal, compile_principal_request_grants};
use crate::service::{ConsoleError, exact_resource_selector, principal_identity_path};

/// State-plane method invoked by a state recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateMethod {
    Read,
    List,
    Write,
    Append,
    Delete,
}

impl StateMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::List => "list",
            Self::Write => "write",
            Self::Append => "append",
            Self::Delete => "delete",
        }
    }

    pub fn verb(self) -> &'static str {
        match self {
            Self::Read | Self::List => "read",
            Self::Write | Self::Append | Self::Delete => "write",
        }
    }
}

/// A recipe with its request grant compiled to a parsed selector.
pub struct CompiledRecipe {
    target: ResourceName,
    verb: &'static str,
    method: String,
    input: Value,
    grant: CompiledRequestGrantTemplate,
}

impl CompiledRecipe {
    /// Compile a state-plane recipe. The capability selector is parsed once
    /// here so repeated calls avoid re-parsing.
    pub fn state(path: Path, method: StateMethod, input: Value) -> Result<Self, RecipeError> {
        let verb = method.verb();
        let selector = exact_resource_selector(verb, &path)?;
        let target = ResourceName::new(path);
        Ok(Self {
            target,
            verb,
            method: method.as_str().into(),
            input,
            grant: CompiledRequestGrantTemplate {
                selector,
                rights: GrantRights::new(GrantMethods::none(), RightFlags::empty()),
            },
        })
    }

    /// Compile an effect-plane recipe (`effect://...` invocation).
    pub fn effect(path: Path, input: Value) -> Result<Self, RecipeError> {
        let selector = exact_resource_selector("perform", &path)?;
        let target = ResourceName::new(path);
        Ok(Self {
            target,
            verb: "perform",
            method: "invoke".into(),
            input,
            grant: CompiledRequestGrantTemplate {
                selector,
                rights: GrantRights::new(GrantMethods::none(), RightFlags::empty()),
            },
        })
    }
}

/// Errors raised while compiling a recipe (before any kernel call).
#[derive(Debug, thiserror::Error)]
pub enum RecipeError {
    #[error("invalid capability selector: {0}")]
    Selector(#[from] CapError),
}

/// Execute a compiled recipe against the kernel: spawn a request Process under
/// the console root with the recipe's grant, open a handle (the kernel
/// authorizes here), evaluate the Operation, and finalize the Process so the
/// outcome lands as a Fact. Dropping the call cancels the request and revokes its
/// handles; the kernel retains interrupted lifecycle cleanup for the host to drain.
pub async fn execute(
    state: &crate::state::ConsoleState,
    principal: &ConsolePrincipal,
    recipe: CompiledRecipe,
) -> Result<Value, ConsoleError> {
    let boot = &state.boot;
    let identity = boot
        .kernel()
        .identities()
        .resolve_or_register(&principal_identity_path(principal)?)
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    let CompiledRecipe {
        target,
        verb,
        method,
        input,
        grant,
    } = recipe;
    let compiled_grants =
        compile_principal_request_grants(boot, principal, &target, verb, &method, grant.selector)
            .map_err(ConsoleError::from)?;
    let request = boot
        .request_under(boot.root(), identity, &compiled_grants)
        .map_err(|error| ConsoleError::Operation(error.to_string()))?;
    let handle = match boot.open_for_method(request.id(), &target, verb, &method) {
        Ok(handle) => handle,
        Err(error) => {
            return finish_as_failed(boot, request, ConsoleError::Operation(error.to_string()))
                .await;
        }
    };
    let executor = request.executor();
    if let Err(error) = executor.bind_handle(target.clone(), handle) {
        return finish_as_failed(boot, request, ConsoleError::Operation(error.to_string())).await;
    }
    let op = DoNode::Op(OperationTemplate {
        target,
        method,
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(input),
    });
    let mut output = executor.eval_tainted(&op, TaintSet::author()).await;
    let ticket = request.cleanup_ticket();
    let finished = request.finish(&output).await;
    let report = ticket.finalization_report();
    if let Some(unresolved) = ticket.unresolved_operations() {
        output.unresolved_operations.merge(&unresolved);
    }
    if finished.is_err()
        || report.as_ref().is_some_and(|report| {
            !report.finalizer_failures.is_empty() || !report.unresolved_operations.is_empty()
        })
    {
        use crate::runtime::executions::finalization::FinalizationProjection;
        let projection = report
            .as_ref()
            .map_or(FinalizationProjection::Pending, |report| {
                FinalizationProjection::encode(
                    report,
                    state.runtime.config.executions.max_finalization_bytes,
                )
            })
            .value()?;
        let error = finished
            .err()
            .map(ConsoleError::Finalization)
            .unwrap_or_else(|| {
                ConsoleError::Operation(
                    "recipe finalization requires inspection; effects may have occurred".into(),
                )
            });
        let retained =
            crate::service::retained_runtime_completion(state, &output, projection, Some(&error))?;
        let error = match &output.outcome {
            Outcome::Fail(failure) => {
                ConsoleError::Runtime(failure.clone()).with_cleanup_error(error)
            }
            _ => error,
        };
        return Err(error
            .with_runtime_completion(retained)
            .with_unresolved_operations(output.unresolved_operations));
    }
    match output.outcome {
        Outcome::Done(value) | Outcome::Short(value) => Ok(value),
        Outcome::Fail(failure) => Err(ConsoleError::Operation(failure.to_string())),
    }
}

async fn finish_as_failed(
    _boot: &Bootstrap,
    request: RequestProcess<'_>,
    error: ConsoleError,
) -> Result<Value, ConsoleError> {
    let output = ExecutionOutput::new(
        Outcome::Fail(Failure::Custom {
            kind: "console_recipe_preparation".into(),
            message: error.to_string(),
        }),
        TaintSet::pristine(),
    );
    match request.finish(&output).await {
        Ok(_) => Err(error),
        Err(cleanup_error) => {
            Err(error.with_cleanup_error(ConsoleError::Finalization(cleanup_error)))
        }
    }
}

#[cfg(test)]
mod tests;
