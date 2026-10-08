//! Kernel endpoint for one Source projection's command effect.

use super::source::{SourceCommandHub, SourceDispatchError};
use super::*;
use xolotl_kernel::driver::RemoteEndpoint;
use xolotl_types::external::{ObservedGenerations, OutboundCommand};

pub(super) struct SourceRoleEndpoint {
    pub(super) hub: SourceCommandHub,
    pub(super) installation_id: String,
    pub(super) projection_id: String,
    pub(super) effect_path: Path,
    pub(super) endpoint_id: xolotl_types::EndpointId,
    pub(super) binding_generation: u64,
}

#[async_trait::async_trait]
impl RemoteEndpoint for SourceRoleEndpoint {
    async fn invoke(
        &self,
        dispatch: RemoteInvokeDispatch,
        invoke: Invoke,
    ) -> Result<InvokeResult, DriverError> {
        if dispatch.endpoint_id != self.endpoint_id
            || dispatch.binding_generation != self.binding_generation
            || dispatch.method_id != MethodId::new(0)
            || invoke.method_id != MethodId::new(0)
            || invoke.effect_path != self.effect_path
            || invoke.output_stream_to.is_some()
        {
            return Err(DriverError::Transport(
                "source command endpoint binding changed".into(),
            ));
        }
        let command_id = invoke.invocation_id;
        let result = self
            .hub
            .dispatch_for_projection(
                &self.installation_id,
                &self.projection_id,
                OutboundCommand {
                    id: command_id.clone(),
                    action: invoke.input,
                    observed: ObservedGenerations::default(),
                },
                invoke.deadline_ms,
            )
            .await;
        let outcome = match result {
            Ok(result) => {
                if result.id != command_id {
                    return Err(DriverError::OutcomeUnknown {
                        operation_id: command_id,
                        reason: "result_identity_mismatch".into(),
                    });
                }
                result.outcome
            }
            Err(SourceDispatchError::Rejected(status)) => {
                return Err(DriverError::Transport(format!(
                    "source command rejected before dispatch: {status}"
                )));
            }
            Err(SourceDispatchError::OutcomeUnknown { command_id, cause }) => {
                return Err(DriverError::OutcomeUnknown {
                    operation_id: command_id,
                    reason: match cause.code() {
                        tonic::Code::DeadlineExceeded => "deadline_exceeded",
                        _ => "delivery_or_session_lost",
                    }
                    .into(),
                });
            }
        };
        Ok(InvokeResult {
            invocation_id: command_id,
            outcome,
        })
    }
}
