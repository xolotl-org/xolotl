//! Portable program preparation and capability admission before execution.

use super::{ExecutionMode, TypedRuntimeInput, enabled, modules, public_target, target_allowed};
use crate::auth::{
    AuthError, ConsolePrincipal, compile_principal_propagation_grants,
    compile_principal_request_grants,
};
use crate::protocol::{self, ACTION_RUNTIME_OPERATION_INVOKE, ActionCall};
use crate::service::{
    ConsoleError, exact_resource_selector, input_map, optional_string_arg, optional_u64_arg,
    optional_usize_arg, require_visibility_access, string_arg,
};
use crate::state::ConsoleState;
use std::io::{self, Write};
use std::time::Duration;
use xolotl_graph::{
    OperationTemplate,
    portable::{CompileLimits, Expression, Program},
};
use xolotl_kernel::host::HostDeadline;
use xolotl_kernel::{CompiledRequestGrantTemplate, PreparedProgram};
use xolotl_types::value::inspection;
use xolotl_types::{OutputMode, OutputModeSet, Path, ResourceName, Value, ValueView};

fn output_mode(
    input: &mut xolotl_types::ValueMap,
    default_stream: bool,
    allow_stream: bool,
) -> Result<OutputMode, ConsoleError> {
    let output = optional_string_arg(input, "output")?.unwrap_or_else(|| {
        if default_stream {
            "stream".into()
        } else {
            "unary".into()
        }
    });
    let limit = optional_usize_arg(input, "collect_limit")?;
    match (output.as_str(), limit) {
        ("stream", None) if allow_stream => Ok(OutputMode::Stream),
        ("unary", None) => Ok(OutputMode::Unary),
        ("sink_only", None) => Ok(OutputMode::SinkOnly),
        ("async_process", None) => Ok(OutputMode::AsyncProcess),
        ("collect", Some(limit)) => Ok(OutputMode::Collect { limit }),
        _ => Err(ConsoleError::BadRequest(
            "invalid output mode or collect_limit".into(),
        )),
    }
}

pub(super) fn output_supported(
    state: &ConsoleState,
    output: OutputMode,
    method_supports: OutputModeSet,
) -> bool {
    output.is_supported_by(method_supports)
        && !matches!(output, OutputMode::Collect { limit }
            if !(1..=state.runtime.config.max_collect_items).contains(&limit))
}

pub(super) fn admit_operation(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    operation: &OperationTemplate,
    mode: ExecutionMode,
) -> Result<
    (
        Vec<CompiledRequestGrantTemplate>,
        xolotl_types::MethodAuthority,
    ),
    ConsoleError,
> {
    let path = operation.target.path();
    public_target(path)?;
    if operation.method_id.is_some() {
        return Err(ConsoleError::BadRequest(
            "portable Console calls resolve methods by name; omit method_id".into(),
        ));
    }
    if !mode.supports_output(operation.output) {
        return Err(ConsoleError::BadRequest(
            "output mode is unavailable or exceeds the host collection limit".into(),
        ));
    }
    // Discovery, admission and execution all use the installed method contract.
    if !target_allowed(state, &principal.grants, path) {
        return Err(AuthError::PermissionDenied.into());
    }
    let registry = state.boot.kernel().registry();
    let (_, method) = registry
        .resolve_resource(&operation.target)
        .ok()
        .and_then(|id| registry.resource_method(id, &operation.method))
        .ok_or_else(|| ConsoleError::BadRequest("resource method is not installed".into()))?;
    let verb = method.authority.verb();
    if !super::method_allowed(state, &principal.grants, verb, path, &method.name) {
        return Err(AuthError::PermissionDenied.into());
    }
    if !output_supported(state, operation.output, method.supports) {
        return Err(ConsoleError::BadRequest(
            "resource method does not support the requested output mode or collection limit".into(),
        ));
    }
    let selector = exact_resource_selector(verb, path)
        .map_err(|error| ConsoleError::BadRequest(error.to_string()))?;
    let mut grants = compile_principal_request_grants(
        &state.boot,
        principal,
        &operation.target,
        verb,
        &method.name,
        selector.clone(),
    )?;
    if operation.output == OutputMode::AsyncProcess {
        // Method authority does not imply permission to propagate its handle.
        // Bootstrap still intersects this request with the kernel anchor's rights.
        if !super::propagation_method_allowed(state, &principal.grants, path, &method.name) {
            return Err(AuthError::PermissionDenied.into());
        }
        grants.extend(compile_principal_propagation_grants(
            &state.boot,
            principal,
            path,
            verb,
            &method.name,
            selector,
        )?);
    }
    Ok((grants, method.authority))
}

pub(super) struct AdmittedOperation {
    pub(super) template: OperationTemplate,
    pub(super) authority: xolotl_types::MethodAuthority,
}

pub(super) struct Plan {
    pub(super) prepared: PreparedProgram,
    pub(super) steps: xolotl_kernel::StepModule,
    pub(super) input: Value,
    pub(super) operations: Vec<AdmittedOperation>,
    pub(super) identities: Vec<Path>,
    pub(super) grants: Vec<CompiledRequestGrantTemplate>,
    pub(super) admission_deadline: HostDeadline,
    pub(super) deadline: HostDeadline,
    pub(super) program_id: String,
    pub(super) budget: xolotl_types::BudgetSpec,
}

impl Plan {
    pub(super) fn delivery_access(&self) -> super::super::subscriptions::Access {
        let operations = self
            .operations
            .iter()
            .flat_map(|operation| {
                let template = &operation.template;
                let invocation = (
                    operation.authority.verb().to_owned(),
                    template.target.path().clone(),
                    Some(template.method.clone()),
                );
                let propagation = (template.output == OutputMode::AsyncProcess).then(|| {
                    (
                        "spawn-with".into(),
                        template.target.path().clone(),
                        Some(template.method.clone()),
                    )
                });
                std::iter::once(invocation).chain(propagation)
            })
            .chain(
                self.identities
                    .iter()
                    .map(|identity| ("act-as".into(), identity.clone(), None)),
            )
            .collect();
        let expires_at = self
            .grants
            .iter()
            .filter_map(|grant| grant.selector.pattern.predicate.as_ref())
            .filter(|predicate| predicate.key == "until")
            .map(|predicate| predicate.value.parse::<i64>().unwrap_or(i64::MIN))
            .min();
        super::super::subscriptions::Access::Runtime {
            operations,
            expires_at,
        }
    }
}

pub(super) fn prepare_input(
    state: &ConsoleState,
    call: &ActionCall,
    streaming: bool,
    typed: Option<TypedRuntimeInput>,
) -> Result<TypedRuntimeInput, ConsoleError> {
    // Account for the outer input before taking even a shared clone of the
    // protocol argument map. A missing input is null and fits every valid
    // configured limit. This applies to calls, subscriptions and submissions.
    let input = typed.as_ref().map(|request| &request.input).or_else(|| {
        call.input
            .as_map()
            .and_then(|arguments| arguments.get("input"))
    });
    if !typed
        .as_ref()
        .is_some_and(|request| request.limits_admitted)
        && input
            .is_some_and(|value| inspection::admit(value, state.runtime.input_limits()).is_none())
    {
        return Err(ConsoleError::BadRequest(
            "runtime input exceeds host logical value limits".into(),
        ));
    }
    let mut prepared = if let Some(typed) = typed {
        typed
    } else {
        let mut arguments = input_map(call.input.clone())?;
        let budget = crate::runtime::budget::parse(arguments.remove("budget"))?;
        let duration = optional_u64_arg(&mut arguments, "timeout_ms")?;
        let submission_identity =
            super::request::submission_identity(arguments.remove("submission_identity"))?;
        let operation = matches!(
            call.action.as_str(),
            ACTION_RUNTIME_OPERATION_INVOKE | protocol::ACTION_RUNTIME_OPERATION_SUBMIT
        );
        let program = if operation {
            let operation = OperationTemplate {
                target: ResourceName::new(Path::parse(&string_arg(&mut arguments, "target")?)?),
                method: string_arg(&mut arguments, "method")?,
                method_id: None,
                output: output_mode(
                    &mut arguments,
                    streaming,
                    streaming || call.action == protocol::ACTION_RUNTIME_OPERATION_SUBMIT,
                )?,
                literal_input: None,
            };
            Program::new(Expression::Invoke { operation })
        } else {
            let source_value = arguments
                .remove("source")
                .ok_or_else(|| ConsoleError::BadRequest("source is required".into()))?;
            let source = match source_value.view() {
                ValueView::Str(source) if !source.is_empty() => source,
                _ => {
                    return Err(ConsoleError::BadRequest(
                        "source must be a non-empty string".into(),
                    ));
                }
            };
            Program::from_json_with_limits(source.as_bytes(), state.runtime.compile_limits())
                .map_err(|_error| {
                    ConsoleError::BadRequest(
                        "invalid portable program or source limit exceeded".into(),
                    )
                })?
        };
        TypedRuntimeInput {
            program,
            input: arguments.remove("input").unwrap_or(Value::null()),
            budget,
            timeout_ms: duration,
            submission_identity,
            limits_admitted: !operation,
        }
    };
    if !prepared.limits_admitted {
        admit_typed_source(&prepared.program, state.runtime.compile_limits())?;
        prepared.limits_admitted = true;
    }
    Ok(prepared)
}

pub(super) fn plan(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    call: &ActionCall,
    streaming: bool,
    typed: Option<TypedRuntimeInput>,
) -> Result<Plan, ConsoleError> {
    enabled(state)?;
    require_visibility_access(principal, call)?;
    let typed = prepare_input(state, call, streaming, typed)?;
    let submission = matches!(
        call.action.as_str(),
        protocol::ACTION_RUNTIME_OPERATION_SUBMIT | protocol::ACTION_RUNTIME_PROGRAM_SUBMIT
    );
    if typed.submission_identity.is_some() && !submission {
        return Err(ConsoleError::BadRequest(
            "submission_identity is only valid for independent submission".into(),
        ));
    }
    let TypedRuntimeInput {
        program,
        input,
        budget,
        timeout_ms: duration,
        ..
    } = typed;
    let budget = budget.intersect(&state.runtime.config.budget);
    let duration = duration.unwrap_or(state.runtime.config.max_duration_ms);
    if duration == 0 || duration > state.runtime.config.max_duration_ms {
        return Err(ConsoleError::BadRequest(
            "timeout_ms exceeds the host execution limit".into(),
        ));
    }
    if submission
        && i64::try_from(duration)
            .ok()
            .and_then(|millis| {
                state
                    .boot
                    .kernel()
                    .host_runtime()
                    .now_millis()
                    .checked_add(millis)
            })
            .is_none()
    {
        return Err(ConsoleError::BadRequest(
            "execution deadline is not representable".into(),
        ));
    }
    let now = state.boot.kernel().host_runtime().now();
    let visibility_deadline = now
        .checked_add(Duration::from_millis(call.ttl_ms.unwrap_or_default()))
        .ok_or_else(|| {
            ConsoleError::BadRequest("visibility deadline is not representable".into())
        })?;
    let execution_deadline = now
        .checked_add(Duration::from_millis(duration))
        .ok_or_else(|| {
            ConsoleError::BadRequest("execution deadline is not representable".into())
        })?;
    let admission_deadline = visibility_deadline
        .earliest(execution_deadline)
        .map_err(|error| ConsoleError::Runtime(error.into()))?;
    // Once accepted, an independent job owns its execution authority. Its
    // original absolute deadline remains fixed across observer disconnect;
    // the short call TTL only bounds the admission and immediate disclosure.
    let deadline = if submission {
        execution_deadline
    } else {
        admission_deadline
    };
    let mode = if streaming {
        ExecutionMode::Subscription
    } else if matches!(
        call.action.as_str(),
        protocol::ACTION_RUNTIME_OPERATION_SUBMIT | protocol::ACTION_RUNTIME_PROGRAM_SUBMIT
    ) {
        ExecutionMode::Submission
    } else {
        ExecutionMode::Call
    };
    let compiled = program
        .compile_with_limits(state.runtime.compile_limits())
        .map_err(|_error| {
            ConsoleError::BadRequest(
                "invalid portable program or compilation limit exceeded".into(),
            )
        })?;
    // Inspect every Signal as a subscribe method before starting effects;
    // Kernel preparation owns the executable lowering for all frontends.
    let modules::AdmittedImports {
        operations,
        identities,
        grants,
        steps,
    } = modules::admit(state, principal, compiled.imports(), mode)?;
    let prepared = PreparedProgram::from_compiled(compiled).map_err(ConsoleError::Runtime)?;
    let program_id: String = prepared
        .id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(Plan {
        prepared,
        steps,
        input,
        operations,
        identities,
        grants,
        admission_deadline,
        deadline,
        program_id,
        budget,
    })
}

/// Measure the same compact source representation accepted over the protocol
/// without allocating a second copy of an already owned Rust program.
pub(super) fn admit_typed_source(
    program: &Program,
    limits: CompileLimits,
) -> Result<(), ConsoleError> {
    program
        .validate_structure_with_limits(limits)
        .map_err(|_error| {
            ConsoleError::BadRequest("invalid portable program or source limit exceeded".into())
        })?;
    let mut sink = ByteLimit {
        remaining: limits.source_bytes,
        exceeded: false,
    };
    if serde_json::to_writer(&mut sink, program).is_err() {
        return Err(ConsoleError::BadRequest(
            if sink.exceeded {
                "portable program source limit exceeded"
            } else {
                "invalid portable program source"
            }
            .into(),
        ));
    }
    Ok(())
}

struct ByteLimit {
    remaining: usize,
    exceeded: bool,
}

impl Write for ByteLimit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("portable program source limit exceeded"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn signal_operation(path: Path) -> OperationTemplate {
    OperationTemplate {
        target: ResourceName::new(path),
        method: "subscribe".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    }
}
