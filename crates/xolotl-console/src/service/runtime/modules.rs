//! Resolve complete declared module authority before starting an execution.

use super::*;
use std::collections::BTreeSet;
use xolotl_kernel::{LoaderRevision, StepBinding, StepModule};

pub(super) struct AdmittedImports {
    pub operations: Vec<AdmittedOperation>,
    pub identities: Vec<Path>,
    pub grants: Vec<CompiledRequestGrantTemplate>,
    pub steps: StepModule,
}

pub(super) fn admit(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    imports: &[Import],
    mode: ExecutionMode,
) -> Result<AdmittedImports, ConsoleError> {
    let mut operations = Vec::new();
    let mut identities = Vec::new();
    let mut grants = Vec::new();
    let mut pending = BTreeSet::new();
    for import in imports {
        match import {
            Import::Operation(operation) => operation_import(
                state,
                principal,
                operation,
                mode,
                &mut operations,
                &mut grants,
            )?,
            Import::Module(module) => {
                pending.insert(module.name.clone());
            }
            Import::Transform(_) | Import::Wait(WaitSpec::Deadline(_)) => {}
            Import::Scope(identity) => {
                identity_import(state, principal, identity, &mut identities, &mut grants)?
            }
            Import::Wait(WaitSpec::Signal(path)) => operation_import(
                state,
                principal,
                &signal_operation(path.clone()),
                mode,
                &mut operations,
                &mut grants,
            )?,
        }
    }
    let mut visited = BTreeSet::new();
    let mut bindings = Vec::new();
    while let Some(name) = pending.pop_first() {
        if visited.contains(&name) {
            continue;
        }
        if visited.len() >= state.runtime.config.max_modules {
            return Err(ConsoleError::BadRequest(
                "program module import limit exceeded".into(),
            ));
        }
        visited.insert(name.clone());
        let module = state
            .modules
            .entries
            .get(&name)
            .ok_or_else(|| ConsoleError::BadRequest("program module is not installed".into()))?
            .clone();
        for operation in &module.manifest.operations {
            operation_import(
                state,
                principal,
                &operation.template(),
                mode,
                &mut operations,
                &mut grants,
            )?;
        }
        for identity in &module.manifest.identities {
            identity_import(state, principal, identity, &mut identities, &mut grants)?;
        }
        for signal in &module.manifest.signals {
            operation_import(
                state,
                principal,
                &signal_operation(signal.clone()),
                mode,
                &mut operations,
                &mut grants,
            )?;
        }
        // Each module is visited once, including recursive dependency graphs.
        pending.extend(
            module
                .manifest
                .modules
                .iter()
                .filter(|name| !visited.contains(*name))
                .cloned(),
        );
        bindings.push(binding(module, state.runtime.compile_limits()));
    }
    let steps = StepModule::new(bindings)
        .map_err(|_error| ConsoleError::Operation("module assembly failed".into()))?;
    Ok(AdmittedImports {
        operations,
        identities,
        grants,
        steps,
    })
}

fn identity_import(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    identity: &Path,
    identities: &mut Vec<Path>,
    grants: &mut Vec<CompiledRequestGrantTemplate>,
) -> Result<(), ConsoleError> {
    if !crate::runtime::valid_identity(identity) {
        return Err(ConsoleError::BadRequest(
            "acting requires a concrete local identity path".into(),
        ));
    }
    if !allowed(state, &principal.grants, "act-as", identity) {
        return Err(AuthError::PermissionDenied.into());
    }
    if identities.contains(identity) {
        return Ok(());
    }
    if identities.len() >= state.runtime.config.max_identities {
        return Err(ConsoleError::BadRequest(
            "program identity import limit exceeded".into(),
        ));
    }
    let selector = exact_resource_selector("act-as", identity)
        .map_err(|error| ConsoleError::BadRequest(error.to_string()))?;
    let selectors = crate::auth::principal_request_selectors(
        &state.boot,
        principal,
        identity,
        "act-as",
        selector,
    )?;
    if grants.len().saturating_add(selectors.len()) > state.runtime.config.max_request_grants {
        return Err(ConsoleError::BadRequest(
            "program request grant limit exceeded".into(),
        ));
    }
    // Delegation changes the acting identity only; it conveys no method rights.
    grants.extend(
        selectors
            .into_iter()
            .map(|selector| CompiledRequestGrantTemplate {
                selector,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::none(),
                    xolotl_types::RightFlags::DELEGATE,
                ),
            }),
    );
    identities.push(identity.clone());
    Ok(())
}

fn operation_import(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    operation: &OperationTemplate,
    mode: ExecutionMode,
    operations: &mut Vec<AdmittedOperation>,
    grants: &mut Vec<CompiledRequestGrantTemplate>,
) -> Result<(), ConsoleError> {
    // Validate even repeated declarations; a numeric method id must never hide
    // behind a previously admitted named method.
    let (new_grants, authority) = admit_operation(state, principal, operation, mode)?;
    if operations.iter().any(|present| {
        present.template.target == operation.target
            && present.template.method == operation.method
            && present.template.output == operation.output
    }) {
        return Ok(());
    }
    if operations.len() >= state.runtime.config.max_operations {
        return Err(ConsoleError::BadRequest(
            "program operation import limit exceeded".into(),
        ));
    }
    if grants.len().saturating_add(new_grants.len()) > state.runtime.config.max_request_grants {
        return Err(ConsoleError::BadRequest(
            "program request grant limit exceeded".into(),
        ));
    }
    operations.push(AdmittedOperation {
        template: operation.clone(),
        authority,
    });
    grants.extend(new_grants);
    Ok(())
}

fn rejected() -> Failure {
    Failure::InvalidInput {
        reason: "host module returned an invalid program or undeclared import".into(),
    }
}

fn binding(
    module: crate::runtime::ConsoleModule,
    limits: xolotl_graph::portable::CompileLimits,
) -> StepBinding {
    let revision = LoaderRevision::from_bytes(module.manifest.revision);
    StepBinding::program(
        module.manifest.name.clone(),
        revision,
        Arc::new(move |input, argument| {
            let program = (module.loader)(input, argument)?;
            super::plan::admit_typed_source(&program, limits).map_err(|_error| rejected())?;
            let compiled = program
                .compile_with_limits(limits)
                .map_err(|_error| rejected())?;
            for import in compiled.imports() {
                let declared = match import {
                    Import::Operation(operation) => module
                        .manifest
                        .operations
                        .iter()
                        .any(|declared| declared.permits(operation)),
                    Import::Module(reference) => module.manifest.modules.contains(&reference.name),
                    Import::Transform(_) | Import::Wait(WaitSpec::Deadline(_)) => true,
                    Import::Scope(identity) => module.manifest.identities.contains(identity),
                    Import::Wait(WaitSpec::Signal(path)) => module.manifest.signals.contains(path),
                };
                if !declared {
                    return Err(rejected());
                }
            }
            PreparedProgram::from_compiled(compiled)
        }),
    )
}
