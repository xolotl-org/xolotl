//! Console action recipes executed as capability-scoped request Processes.

use xolotl_graph::{DoNode, OperationTemplate};
use xolotl_kernel::{Bootstrap, CompiledRequestGrantTemplate, intern_identity};
use xolotl_types::{
    CapError, MethodBitmap, Outcome, OutputMode, Path, ProcessId, ProcessStatus, ResourceName,
    ResourceSelector, TaintSet, Value,
};

use crate::auth::{ConsolePrincipal, compile_principal_request_grant};
use crate::ws::{
    ConsoleError, WsSession, capability_target, capability_verb_for_state_method,
    principal_identity_path,
};

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
        capability_verb_for_state_method(self.as_str())
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
        let literal = format!("{verb}://{}", capability_target(&path));
        let selector = ResourceSelector::parse(&literal)?;
        let target = ResourceName::new(path);
        Ok(Self {
            target,
            verb,
            method: method.as_str().into(),
            input,
            grant: CompiledRequestGrantTemplate {
                selector,
                methods: MethodBitmap::empty(),
            },
        })
    }

    /// Compile an effect-plane recipe (`effect://...` invocation).
    pub fn effect(path: Path, input: Value) -> Result<Self, RecipeError> {
        let literal = format!("perform://{}", capability_target(&path));
        let selector = ResourceSelector::parse(&literal)?;
        let target = ResourceName::new(path);
        Ok(Self {
            target,
            verb: "perform",
            method: "invoke".into(),
            input,
            grant: CompiledRequestGrantTemplate {
                selector,
                methods: MethodBitmap::empty(),
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
/// outcome lands as a Fact.
pub async fn execute(
    sess: &WsSession,
    principal: &ConsolePrincipal,
    recipe: CompiledRecipe,
) -> Result<Value, ConsoleError> {
    let boot = &sess.state.boot;
    let identity = intern_identity(&principal_identity_path(principal)?);
    let CompiledRecipe {
        target,
        verb,
        method,
        input,
        grant,
    } = recipe;
    let compiled_grant =
        compile_principal_request_grant(boot, principal, &target, verb, grant.selector)
            .map_err(ConsoleError::from)?;
    let process = boot
        .spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            identity,
            &[compiled_grant],
        )
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    let handle = match boot.open_for(process, &target, verb) {
        Ok(handle) => handle,
        Err(error) => {
            return finish_as_failed(boot, process, ConsoleError::Operation(error.to_string()))
                .await;
        }
    };
    let executor = boot.kernel.executor_for(process);
    executor.bind_handle(target.clone(), handle);
    let op = DoNode::Op(OperationTemplate {
        target,
        method,
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(input),
    });
    let outcome = executor.eval_tainted(&op, TaintSet::author()).await;
    let result = match &outcome {
        Outcome::Done(value) | Outcome::Short(value) => Ok(value.clone()),
        Outcome::Fail(failure) => Err(ConsoleError::Operation(failure.to_string())),
    };
    boot.finish_request_process(process, &outcome)
        .await
        .map_err(|e| ConsoleError::Operation(e.to_string()))?;
    result
}

async fn finish_as_failed(
    boot: &Bootstrap,
    process: ProcessId,
    error: ConsoleError,
) -> Result<Value, ConsoleError> {
    let original = error.to_string();
    match boot.finish_process_as(process, ProcessStatus::Failed).await {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(ConsoleError::Operation(format!(
            "{original}; request cleanup failed: {cleanup_error}"
        ))),
    }
}
