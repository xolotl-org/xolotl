//! Named process admission and its state projection.

use super::*;
use crate::process::ProcessPublication;
use futures_util::FutureExt;
use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use xolotl_graph::{ActorSpec, DoNode, LintSeverity, lint_actor};
use xolotl_types::{ExecutionId, ExecutionOutput, Failure, Outcome, TaintSet, Value};

#[cfg(test)]
mod tests;

impl Bootstrap {
    /// Spawn a named long-lived actor Process under `anchor`.
    ///
    /// The actor receives only the capabilities declared by
    /// `spec.declared_capabilities`, intersected with the anchor's grants. Its
    /// body still runs through the ordinary Executor and every effect goes
    /// through `open()`, Handle checks, Policy, Driver dispatch, and Facts.
    pub async fn spawn_actor_under(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
    ) -> Result<SpawnedActor, BootstrapError> {
        self.spawn_actor_under_with_steps(
            anchor,
            identity,
            identity_segment,
            spec,
            StepModule::default(),
        )
        .await
    }

    /// Spawn an actor with one shared native module for its body and finalizers.
    pub async fn spawn_actor_under_with_steps(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
        steps: StepModule,
    ) -> Result<SpawnedActor, BootstrapError> {
        validate_actor_segment("actor name", &spec.name)?;
        validate_actor_segment("actor identity segment", identity_segment)?;
        validate_actor_steps(spec, &steps)?;
        let child = self.kernel.processes.fresh_id()?;
        let spec = spec.bind_process_local_refs(child).map_err(|source| {
            BootstrapError::ActorAdmission {
                actor: spec.name.clone(),
                message: source.to_string(),
            }
        })?;
        xolotl_graph::compile_do(&spec.body).map_err(|source| BootstrapError::ActorAdmission {
            actor: spec.name.clone(),
            message: source.to_string(),
        })?;
        for (index, finalizer) in spec.finalizers.iter().enumerate() {
            xolotl_graph::compile_do(finalizer).map_err(|source| {
                BootstrapError::ActorAdmission {
                    actor: spec.name.clone(),
                    message: format!("finalizer[{index}] compile failed: {source}"),
                }
            })?;
        }

        let lint_message = actor_lint_message(&spec);
        if let Some(message) = lint_message {
            return Err(BootstrapError::ActorLint {
                actor: spec.name.clone(),
                message,
            });
        }

        let parsed = spec
            .declared_capabilities
            .iter()
            .map(|literal| {
                ResourceSelector::parse(literal)
                    .map(|selector| ParsedRequestGrantTemplate {
                        selector,
                        methods: None,
                    })
                    .map_err(|source| BootstrapError::Selector {
                        literal: literal.clone(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let directory = actor_directory_path(identity_segment, &spec.name)?;
        let inbox = actor_inbox_path(identity_segment, &spec.name)?;
        let planned = self.plan_request_grants(anchor, &parsed)?;
        let execution = self.kernel.execution_ids().allocate()?;
        let initial =
            actor_directory_value(&spec, child, execution, ProcessStatus::Running, &inbox);
        let mut entry = self.request_process_entry(child, anchor, identity, planned);
        entry.scope.initialize_lifecycle(execution);
        entry.scope.set_budget_spec(spec.budget.clone());
        entry.steps = steps;
        entry.publication = Some(Arc::new(ActorDirectory {
            path: directory.clone(),
            execution,
            initial: initial.clone(),
        }));
        self.kernel.processes.admit_child(entry)?;

        let scope = self.own_process(child);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let task_directory = directory.clone();
        let boot = self.clone();
        self.kernel
            .processes
            .spawn_task(
                child,
                self.kernel.handles.clone(),
                move |owner| async move {
                    let admission = AssertUnwindSafe(async {
                        boot.kernel
                            .state
                            .write_cas(&task_directory, None, initial)
                            .await?;
                        if !boot.kernel.processes.activate_child(child, spec.finalizers) {
                            return Err(BootstrapError::ProcessUnavailable { process: anchor });
                        }
                        Ok(())
                    })
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|payload| {
                        Err(BootstrapError::ActorAdmission {
                            actor: spec.name.clone(),
                            message: panic_payload_message("actor admission", payload),
                        })
                    });
                    let output = match admission {
                        Err(error) => {
                            let message = error.to_string();
                            drop(ready_tx.send(Err(error)));
                            ExecutionOutput::new(
                                Outcome::Fail(Failure::HandlerError {
                                    kind: "actor-admission".into(),
                                    message,
                                }),
                                TaintSet::pristine(),
                            )
                        }
                        Ok(()) => {
                            if ready_tx.send(Ok(())).is_err() || start_rx.await.is_err() {
                                ExecutionOutput::new(
                                    Outcome::Fail(Failure::Cancelled),
                                    TaintSet::pristine(),
                                )
                            } else {
                                match AssertUnwindSafe(
                                    boot.kernel.executor_for(child).eval(&spec.body),
                                )
                                .catch_unwind()
                                .await
                                {
                                    Ok(output) => output,
                                    Err(payload) => ExecutionOutput::new(
                                        Outcome::Fail(Failure::HandlerError {
                                            kind: "panic".into(),
                                            message: panic_payload_message(
                                                "actor process",
                                                payload,
                                            ),
                                        }),
                                        TaintSet::pristine(),
                                    ),
                                }
                            }
                        }
                    };
                    if let Some(result) = owner.finish(output)
                        && let Err(error) = boot.finish_request_process(child, &result).await
                    {
                        tracing::error!(
                            actor = %spec.name,
                            process = child.get(),
                            %error,
                            "actor process terminal finalization failed"
                        );
                    }
                },
            )
            .map_err(|attachment| task_attachment_error(child, attachment))?;

        ready_rx
            .await
            .map_err(|_closed| BootstrapError::ProcessUnavailable { process: child })??;
        start_tx
            .send(())
            .map_err(|()| BootstrapError::ProcessUnavailable { process: child })?;
        scope.detach();
        Ok(SpawnedActor {
            process: child,
            directory,
        })
    }
}
fn actor_lint_message(spec: &ActorSpec) -> Option<String> {
    let mut messages = Vec::new();
    for finding in lint_actor(spec) {
        if finding.severity == LintSeverity::Error {
            messages.push(finding.message);
        }
    }
    if messages.is_empty() {
        None
    } else {
        Some(messages.join("; "))
    }
}

fn validate_actor_segment(label: &'static str, value: &str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() {
        return Err(BootstrapError::ActorAdmission {
            actor: value.to_string(),
            message: format!("{label} must not be empty"),
        });
    }
    let mut chars = value.chars();
    let valid = matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if valid {
        Ok(())
    } else {
        Err(BootstrapError::ActorAdmission {
            actor: value.to_string(),
            message: format!(
                "{label} must start with an ASCII letter or digit and contain only ASCII letters, digits, '_' or '-'"
            ),
        })
    }
}

fn validate_actor_steps(spec: &ActorSpec, steps: &StepModule) -> Result<(), BootstrapError> {
    let mut required = BTreeSet::new();
    collect_step_names(&spec.name, &spec.body, &mut required)?;
    for finalizer in &spec.finalizers {
        collect_step_names(&spec.name, finalizer, &mut required)?;
    }
    for name in required {
        if !steps.contains(name.as_str()) {
            return Err(BootstrapError::MissingStepBinding {
                actor: spec.name.clone(),
                name,
            });
        }
    }
    Ok(())
}

fn collect_step_names(
    actor: &str,
    node: &DoNode,
    out: &mut BTreeSet<String>,
) -> Result<(), BootstrapError> {
    match node {
        DoNode::AndThen { d, then } => {
            collect_step_names(actor, d, out)?;
            insert_step_name(actor, &then.name, out)
        }
        DoNode::OrElse { d, or } => {
            collect_step_names(actor, d, out)?;
            insert_step_name(actor, &or.name, out)
        }
        DoNode::Both(left, right) | DoNode::Race(left, right) => {
            collect_step_names(actor, left, out)?;
            collect_step_names(actor, right, out)
        }
        DoNode::Let { value, body, .. } => {
            collect_step_names(actor, value, out)?;
            collect_step_names(actor, body, out)
        }
        DoNode::Acting { body, .. } => collect_step_names(actor, body, out),
        DoNode::Pure(_) | DoNode::Use(_) | DoNode::Fail(_) | DoNode::Wait(_) | DoNode::Op(_) => {
            Ok(())
        }
    }
}

fn insert_step_name(
    actor: &str,
    name: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), BootstrapError> {
    if name.trim().is_empty() {
        return Err(BootstrapError::ActorAdmission {
            actor: actor.to_string(),
            message: "step reference name must not be empty".into(),
        });
    }
    out.insert(name.to_string());
    Ok(())
}

fn actor_directory_path(identity_segment: &str, name: &str) -> Result<Path, BootstrapError> {
    Path::try_new("state")
        .and_then(|path| path.try_push("agents"))
        .and_then(|path| path.try_push_literal(identity_segment))
        .and_then(|path| path.try_push_literal(name))
        .map_err(|source| BootstrapError::Path {
            literal: format!("state://agents/{identity_segment}/{name}"),
            source,
        })
}

fn actor_inbox_path(identity_segment: &str, name: &str) -> Result<Path, BootstrapError> {
    actor_directory_path(identity_segment, name)?
        .try_push("inbox")
        .map_err(|source| BootstrapError::Path {
            literal: format!("state://agents/{identity_segment}/{name}/inbox"),
            source,
        })
}

fn actor_directory_value(
    spec: &ActorSpec,
    process: ProcessId,
    execution: ExecutionId,
    status: ProcessStatus,
    inbox: &Path,
) -> xolotl_types::Value {
    let mut m = BTreeMap::new();
    m.insert(
        "name".into(),
        xolotl_types::Value::string(spec.name.clone()),
    );
    m.insert(
        "execution".into(),
        Value::string(execution.get().to_string()),
    );
    m.insert(
        "path".into(),
        xolotl_types::Value::string(format!("process://{}", process.get())),
    );
    m.insert(
        "process".into(),
        xolotl_types::Value::string(process.get().to_string()),
    );
    m.insert(
        "status".into(),
        xolotl_types::Value::string(process_status_label(status).into()),
    );
    m.insert(
        "inbox".into(),
        xolotl_types::Value::string(inbox.to_string()),
    );
    m.insert(
        "declared_capabilities".into(),
        xolotl_types::Value::list(
            spec.declared_capabilities
                .iter()
                .cloned()
                .map(xolotl_types::Value::string)
                .collect(),
        ),
    );
    xolotl_types::Value::map(m)
}

/// A terminal update can only modify the directory owned by this admission.
struct ActorDirectory {
    path: Path,
    execution: ExecutionId,
    initial: Value,
}

#[async_trait::async_trait]
impl ProcessPublication for ActorDirectory {
    async fn publish(
        &self,
        state: &xolotl_state::Backend,
        process: ProcessId,
        status: ProcessStatus,
        outcome: Option<&ExecutionOutput>,
    ) -> Result<(), BootstrapError> {
        let process = process.get().to_string();
        let execution = self.execution.get().to_string();
        for _ in 0..8 {
            let previous = state.read_tainted(&self.path).await?;
            let Some(mut updated) = previous
                .as_ref()
                .map_or(&self.initial, |previous| &previous.value)
                .as_map()
                .cloned()
            else {
                return Ok(());
            };
            if updated.get("process").and_then(Value::as_str) != Some(&process)
                || updated.get("execution").and_then(Value::as_str) != Some(&execution)
            {
                return Ok(());
            }
            let status = Value::string(process_status_label(status).into());
            let mut taint = previous
                .as_ref()
                .map(|previous| previous.taint.clone())
                .unwrap_or_default();
            if let Some(outcome) = outcome {
                taint.union(&outcome.taint);
            }
            if previous
                .as_ref()
                .is_some_and(|previous| previous.taint == taint)
                && updated.get("status") == Some(&status)
            {
                return Ok(());
            }
            drop(updated.insert("status".into(), status).map_err(|error| {
                BootstrapError::ActorAdmission {
                    actor: self.path.to_string(),
                    message: error.to_string(),
                }
            })?);
            // A terminal reservation also blocks a late initial CAS after cancellation.
            let expected = previous.map(|previous| previous.value);
            match state
                .write_cas_tainted(&self.path, expected, Value::from(updated), taint)
                .await
            {
                Ok(_commit) => return Ok(()),
                Err(xolotl_state::StateFailure {
                    error: xolotl_state::StateError::CasFailed { .. },
                    ..
                }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(BootstrapError::ActorAdmission {
            actor: self.path.to_string(),
            message: "actor directory changed during terminal publication".into(),
        })
    }
}
