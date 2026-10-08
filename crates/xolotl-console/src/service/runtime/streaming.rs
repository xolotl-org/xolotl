//! Attached execution with bounded, independently identified output ports.

use super::*;
use crate::protocol::{ConsoleEvent, StreamCall};
use futures_util::{
    StreamExt,
    stream::{BoxStream, SelectAll},
};
use std::num::NonZeroUsize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use xolotl_kernel::host::stream::{self, DynStreamSink, StreamItem, StreamReceiver};
use xolotl_kernel::stream::{StreamError, StreamRouter, StreamWindow};
use xolotl_types::OperationId;

pub(in crate::service) struct RuntimeStream {
    pub events: BoxStream<'static, Result<ConsoleEvent, ConsoleFailure>>,
    pub worker: crate::host_task::HostTask<()>,
    pub authority: super::super::subscriptions::Access,
    pub execution: ExecutionReference,
}

pub(super) struct Port {
    operation: OperationId,
    receiver: StreamReceiver,
    _capacity: OwnedSemaphorePermit,
}

pub(super) struct Router {
    ports: mpsc::Sender<Port>,
    capacity: Arc<Semaphore>,
    window: StreamWindow,
}

pub(super) fn ports(config: &crate::ConsoleRuntimeConfig) -> (Arc<Router>, mpsc::Receiver<Port>) {
    let (port_tx, ports) = mpsc::channel(config.max_output_streams);
    let router = Arc::new(Router {
        ports: port_tx,
        capacity: Arc::new(Semaphore::new(config.max_output_streams)),
        window: StreamWindow {
            max_chunks: NonZeroUsize::new(config.stream_window_chunks).unwrap_or(NonZeroUsize::MIN),
            max_inline_bytes: NonZeroUsize::new(config.stream_window_bytes)
                .unwrap_or(NonZeroUsize::MIN),
        },
    });
    (router, ports)
}

impl StreamRouter for Router {
    type Sink = DynStreamSink;

    fn open(&self, operation: OperationId) -> Result<Self::Sink, StreamError> {
        let capacity = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_error| {
                StreamError::Failed(Failure::Custom {
                    kind: "stream_capacity".into(),
                    message: "runtime output port capacity exhausted".into(),
                })
            })?;
        let (sink, receiver) = stream::channel(self.window);
        self.ports
            .try_send(Port {
                operation,
                receiver,
                _capacity: capacity,
            })
            .map_err(|_error| StreamError::Closed)?;
        Ok(sink)
    }
}

pub(in crate::service) async fn stream(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    sid: &str,
    source: Option<&str>,
    subscription: &StreamCall,
    visibility_deadline: HostDeadline,
    typed: Option<TypedRuntimeInput>,
) -> Result<RuntimeStream, ConsoleError> {
    let call = ActionCall {
        action: if subscription.stream == protocol::STREAM_RUNTIME_OPERATION {
            ACTION_RUNTIME_OPERATION_INVOKE
        } else {
            protocol::ACTION_RUNTIME_PROGRAM_RUN
        }
        .into(),
        input: subscription.input.clone(),
        scope: subscription.scope.clone(),
        justification: subscription.justification.clone(),
        ttl_ms: subscription.ttl_ms,
        ..Default::default()
    };
    // Reserve execution work before parsing and compiling the program or
    // traversing host module dependencies. The permit remains with the worker
    // through execution, just as it did after planning previously.
    let capacity = state
        .calls
        .clone()
        .try_acquire_owned()
        .map_err(|_error| ConsoleError::RateLimited)?;
    let plan = plan(state, principal, &call, true, typed)?;
    let authority = plan.delivery_access();
    let request = begin(
        &ActionContext {
            delivery: None,
            state,
            source_addr: source,
            session_id: sid,
        },
        principal,
        &call,
        &plan,
    )?;
    let deadline = plan
        .deadline
        .earliest(visibility_deadline)
        .map_err(|error| ConsoleError::Runtime(error.into()))?;
    // Delivery remains subject to the subscription's original visibility
    // lease. If execution ends earlier, its already-started Kernel evaluation
    // has a bounded interval to settle before that lease expires.
    let delivery_deadline =
        settlement_deadline(deadline, state.runtime.config.executions.cleanup_timeout_ms)
            .earliest(visibility_deadline)
            .map_err(|error| ConsoleError::Runtime(error.into()))?;
    let execution = ExecutionReference {
        execution_id: None,
        process_id: request.id().get().to_string(),
        program_id: plan.program_id.clone(),
    };
    let config = &state.runtime.config;
    let (router, ports) = ports(config);
    let executor = request
        .executor()
        .with_steps(plan.steps.clone())
        .with_execution_config(
            state
                .runtime
                .execution_config(state.boot.kernel().execution_config()),
        )
        .with_deadline(deadline)?
        .with_stream_router(router);
    // No driver runs until every import has passed the same static preparation
    // used by unary calls. Dropping a rejected request revokes opened handles.
    for operation in &plan.operations {
        executor
            .prepare_operation(&operation.template)
            .map_err(|failure| ConsoleError::Runtime(failure).with_execution(execution.clone()))?;
    }
    let process_id = request.id().get().to_string();
    let program_id = plan.program_id.clone();
    let budget = crate::runtime::budget::value(&plan.budget)?;
    let max_event_bytes = state.streams.max_event_bytes();
    let (events_tx, events_rx) = mpsc::channel(1);
    let (terminal_tx, terminal_rx) = oneshot::channel();
    let state = state.clone();
    let host_runtime = state.boot.kernel().host_runtime().clone();
    let worker = crate::host_task::spawn(&host_runtime, async move {
        let result = async {
            let runtime = state.boot.kernel().host_runtime();
            crate::host_time::timeout_at(
                runtime,
                deadline,
                send(
                    &events_tx,
                    map_value([
                        ("kind", Value::string("started".into())),
                        ("budget", budget.clone()),
                        ("process_id", Value::string(process_id.clone())),
                        ("program_id", Value::string(program_id.clone())),
                    ]),
                    max_event_bytes,
                ),
            )
            .await
            .map_err(ConsoleError::Runtime)??;
            if crate::host_time::elapsed(runtime, deadline).map_err(ConsoleError::Runtime)? {
                return Err(ConsoleError::Runtime(Failure::Timeout));
            }
            let evaluation = async move {
                executor
                    .eval_prepared(
                        &plan.prepared,
                        TaintedValue::new(plan.input, TaintSet::author()),
                    )
                    .await
            };
            let mut output = None;
            let delivery = crate::host_time::timeout_at(
                runtime,
                delivery_deadline,
                pump(
                    evaluation,
                    ports,
                    &events_tx,
                    max_event_bytes,
                    &request,
                    &mut output,
                ),
            )
            .await;
            let delivery =
                delivery.unwrap_or_else(|_elapsed| Err(delivery_timeout(output.as_ref())));
            let result = match output {
                Some(output) => {
                    finish_delivery(&state, request, output, delivery, delivery_deadline).await
                }
                None => delivery
                    .and_then(|()| Err(ConsoleError::Operation("missing runtime outcome".into()))),
            };
            let (output, finalization) = result?;
            let retained =
                super::retained_runtime_completion(&state, &output, finalization.clone(), None)?;
            let unresolved = output.unresolved_operations;
            let (outcome, value, failure) = match output.outcome {
                Outcome::Done(value) => ("done", value, Value::null()),
                Outcome::Short(value) => ("short", value, Value::null()),
                Outcome::Fail(failure) => (
                    "failed",
                    Value::null(),
                    serde_value(ConsoleFailure::from(ConsoleError::Runtime(failure)))?,
                ),
            };
            Ok::<_, ConsoleError>((
                map_value([
                    ("kind", Value::string("finished".into())),
                    ("budget", budget),
                    ("process_id", Value::string(process_id)),
                    ("program_id", Value::string(program_id)),
                    ("outcome", Value::string(outcome.into())),
                    ("value", value),
                    ("failure", failure),
                    ("taint", serde_value(output.taint)?),
                    ("finalization", finalization),
                    ("unresolved_operations", serde_value(&unresolved)?),
                ]),
                unresolved,
                retained,
            ))
        }
        .await;
        // A slow reader cannot retain execution capacity beyond the bounded
        // settlement window following the execution deadline.
        drop(capacity);
        drop(events_tx);
        let result =
            result
                .map_err(ConsoleFailure::from)
                .and_then(|(event, unresolved, retained)| {
                    let event = ConsoleEvent::Runtime { event };
                    subscriptions::validate_event(&event, max_event_bytes).map_err(
                        |mut failure| {
                            failure.runtime_completion = Some(Box::new(retained));
                            if !unresolved.is_empty() {
                                failure.unresolved_operations = Some(Box::new(unresolved));
                            }
                            failure
                        },
                    )?;
                    Ok(event)
                });
        let _received = terminal_tx.send(result);
    })
    .map_err(|error| {
        ConsoleError::Operation(format!("runtime worker could not start: {error}"))
            .with_execution(execution.clone())
    })?;
    let events = futures_util::stream::unfold(
        (events_rx, Some(terminal_rx)),
        |(mut events, mut terminal)| async move {
            if let Some(event) = events.recv().await {
                return Some((Ok(event), (events, terminal)));
            }
            let result = terminal.take()?.await.unwrap_or_else(|_error| {
                Err(ConsoleFailure::new(
                    protocol::ConsoleErrorCode::Internal,
                    "runtime worker stopped; effects may have occurred".into(),
                ))
            });
            Some((result, (events, terminal)))
        },
    )
    .boxed();
    Ok(RuntimeStream {
        events,
        worker,
        authority,
        execution,
    })
}

async fn send(
    events: &mpsc::Sender<ConsoleEvent>,
    event: Value,
    max_bytes: usize,
) -> Result<(), ConsoleError> {
    let event = ConsoleEvent::Runtime { event };
    subscriptions::validate_event(&event, max_bytes)
        .map_err(|failure| ConsoleError::Operation(failure.message.into_string()))?;
    events
        .send(event)
        .await
        .map_err(|_error| ConsoleError::Runtime(Failure::Cancelled))
}

fn delivery_timeout(output: Option<&ExecutionOutput>) -> ConsoleError {
    ConsoleError::Runtime(if output.is_some() {
        Failure::Timeout
    } else {
        settlement_timeout()
    })
}

async fn pump(
    evaluation: impl std::future::Future<Output = ExecutionOutput>,
    mut ports: mpsc::Receiver<Port>,
    events: &mpsc::Sender<ConsoleEvent>,
    max_bytes: usize,
    request: &xolotl_kernel::RequestProcess<'_>,
    output: &mut Option<ExecutionOutput>,
) -> Result<(), ConsoleError> {
    tokio::pin!(evaluation);
    let mut receivers = SelectAll::new();
    loop {
        if output.is_some() && ports.is_closed() && ports.is_empty() && receivers.is_empty() {
            return Ok(());
        }
        tokio::select! {
            biased;
            completed = &mut evaluation, if output.is_none() => {
                let handoff = request.complete_body(&completed).map_err(request_error);
                *output = Some(completed);
                handoff?;
            }
            port = ports.recv(), if !ports.is_closed() || !ports.is_empty() => {
                let Some(port) = port else { continue };
                receivers.push(futures_util::stream::unfold(port, |mut port| async move {
                    port.receiver.recv().await.map(|item| ((port.operation, item), port))
                }).boxed());
            }
            received = receivers.next(), if !receivers.is_empty() => {
                let Some((operation, item)) = received else { continue };
                let event = output_event(operation, item)?;
                send(events, event, max_bytes).await?;
            }
        }
    }
}

async fn finish_delivery(
    state: &ConsoleState,
    request: xolotl_kernel::RequestProcess<'_>,
    mut output: ExecutionOutput,
    delivery: Result<(), ConsoleError>,
    deadline: HostDeadline,
) -> Result<(ExecutionOutput, Value), ConsoleError> {
    let ticket = request.cleanup_ticket();
    let completion = crate::host_time::timeout_at(
        state.boot.kernel().host_runtime(),
        deadline,
        request.finish(&output),
    )
    .await
    .map_err(|_elapsed| {
        ConsoleError::Finalization(xolotl_kernel::RequestFinishError {
            source: xolotl_kernel::BootstrapError::CleanupWaitExpired {
                process: ticket.process(),
            },
            cleanup: ticket.clone(),
        })
    })
    .and_then(|result| result.map_err(ConsoleError::Finalization));
    let (finalization, mut unresolved) = super::finalization_projection(state, &ticket)?;
    unresolved.merge(&output.unresolved_operations);
    output.unresolved_operations = unresolved;
    let (error, cleanup_error) = match (delivery, completion) {
        (Ok(()), Ok(_report)) => return Ok((output, finalization)),
        (Err(error), Ok(_report)) => (error, None),
        (delivery, Err(cleanup)) => {
            let error = match delivery {
                Err(error) => error,
                Ok(()) => match &output.outcome {
                    Outcome::Fail(failure) => ConsoleError::Runtime(failure.clone()),
                    Outcome::Done(_) | Outcome::Short(_) => {
                        let retained = super::retained_runtime_completion(
                            state,
                            &output,
                            finalization,
                            Some(&cleanup),
                        )?;
                        return Err(cleanup
                            .with_runtime_completion(retained)
                            .with_unresolved_operations(output.unresolved_operations));
                    }
                },
            };
            (error, Some(cleanup))
        }
    };
    let retained =
        super::retained_runtime_completion(state, &output, finalization, cleanup_error.as_ref())?;
    let error = match cleanup_error {
        Some(cleanup) => error.with_cleanup_error(cleanup),
        None => error,
    };
    Err(error
        .with_runtime_completion(retained)
        .with_unresolved_operations(output.unresolved_operations))
}

#[cfg(test)]
mod tests;

pub(super) async fn pump_log(
    evaluation: impl std::future::Future<Output = ExecutionOutput>,
    mut ports: mpsc::Receiver<Port>,
    registration: &crate::runtime::executions::Registration,
    event_limit: usize,
    cancel: impl FnOnce(),
    output: &mut Option<ExecutionOutput>,
) -> Option<Failure> {
    tokio::pin!(evaluation);
    let mut receivers = SelectAll::new();
    let mut failure = None;
    let mut cancel = Some(cancel);
    loop {
        if output.is_some() && ports.is_closed() && ports.is_empty() && receivers.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            completed = &mut evaluation, if output.is_none() => { *output = Some(completed); }
            port = ports.recv(), if !ports.is_closed() || !ports.is_empty() => {
                let Some(port) = port else { continue };
                receivers.push(futures_util::stream::unfold(port, |mut port| async move {
                    port.receiver.recv().await.map(|item| ((port.operation, item), port))
                }).boxed());
            }
            received = receivers.next(), if !receivers.is_empty() => {
                let Some((operation, item)) = received else { continue };
                if failure.is_some() {
                    // The log is no longer writable, but keep draining the
                    // Stream while Kernel settles the cancelled invocation.
                    // Closing the receiver first can turn an in-flight effect
                    // into an ordinary transport error with no reconciliation ID.
                    continue;
                }
                let event = output_event(operation, item).map_err(|_error| Failure::BudgetExhausted {
                    dim: "console.output.event".into(),
                });
                let recorded = event.and_then(|event| registration.append_output(event, event_limit));
                if let Err(error) = recorded {
                    failure = Some(error);
                    if let Some(cancel) = cancel.take() {
                        cancel();
                    }
                }
            }
        }
    }
    failure
}

fn output_event(operation: OperationId, item: StreamItem) -> Result<Value, ConsoleError> {
    Ok(match item {
        StreamItem::Chunk(chunk) => {
            let chunk = chunk.into_value();
            map_value([
                ("kind", Value::string("output".into())),
                ("operation_id", Value::string(operation.to_string())),
                ("value", chunk.value),
                ("taint", serde_value(chunk.taint)?),
            ])
        }
        StreamItem::End(end) => map_value([
            ("kind", Value::string("operation_finished".into())),
            ("operation_id", Value::string(operation.to_string())),
            (
                "failure",
                match end.outcome {
                    Ok(()) => Value::null(),
                    Err(failure) => {
                        serde_value(ConsoleFailure::from(ConsoleError::Runtime(failure)))?
                    }
                },
            ),
            ("taint", serde_value(end.taint)?),
            (
                "origin",
                Value::string(
                    match end.origin {
                        xolotl_types::CompletionOrigin::CurrentAttempt => "current_attempt",
                        xolotl_types::CompletionOrigin::CachedOutcome => "cached_outcome",
                    }
                    .into(),
                ),
            ),
        ]),
    })
}
