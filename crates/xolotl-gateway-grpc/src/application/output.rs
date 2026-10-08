//! Typed output conversion retains kernel credits through encoded-size admission.

use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::Code;
use tonic::Status;
use tonic::codegen::tokio_stream::Stream;
use xolotl_gateway::{Gateway, GatewayOutputEvent, GatewayOutputStream, GatewaySession};
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_types::UnresolvedOperations;

use super::{gateway_status, validate_reconciliation_access, wire};
use std::sync::Arc;

#[cfg(feature = "structured-output")]
mod structured;
#[cfg(feature = "structured-output")]
pub(super) use structured::ObjectDelivery;

/// One output RPC, driven directly by tonic's response-body polling.
/// Dropping it releases execution. Ingress owns the RPC lifecycle through the
/// HTTP body; transport capacity also follows encoded DATA beyond body Drop.
pub struct ApplicationOutputStream {
    output: Option<GatewayOutputStream>,
    gateway: Arc<dyn Gateway>,
    session: GatewaySession,
    accepted: Option<pb::SubmitOutputResponse>,
    max_frame_bytes: usize,
    done: bool,
    #[cfg(feature = "structured-output")]
    objects: Option<ObjectDelivery>,
}

impl ApplicationOutputStream {
    pub(super) fn new(
        output: GatewayOutputStream,
        gateway: Arc<dyn Gateway>,
        session: GatewaySession,
        max_frame_bytes: usize,
    ) -> Result<Self, Status> {
        let accepted = wire::output_accepted_to_pb(output.accepted(), max_frame_bytes)?;
        Ok(Self {
            output: Some(output),
            gateway,
            session,
            accepted: Some(accepted),
            max_frame_bytes,
            done: false,
            #[cfg(feature = "structured-output")]
            objects: None,
        })
    }

    #[cfg(feature = "structured-output")]
    pub(super) fn with_objects(mut self, objects: Option<ObjectDelivery>) -> Self {
        self.objects = objects;
        self
    }

    fn close(&mut self) {
        self.done = true;
        self.accepted = None;
        self.output = None;
        #[cfg(feature = "structured-output")]
        {
            self.objects = None;
        }
    }
}

impl Stream for ApplicationOutputStream {
    type Item = Result<pb::SubmitOutputResponse, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if let Some(accepted) = this.accepted.take() {
            let access = this
                .output
                .as_ref()
                .ok_or_else(|| Status::internal("output owner is missing"))
                .and_then(|output| {
                    validate_reconciliation_access(
                        this.gateway.as_ref(),
                        &this.session,
                        &output.accepted().surface_id,
                    )
                });
            if let Err(error) = access {
                this.close();
                return Poll::Ready(Some(Err(error)));
            }
            return Poll::Ready(Some(Ok(accepted)));
        }
        #[cfg(feature = "structured-output")]
        if let Some(objects) = &mut this.objects
            && objects.is_pending()
        {
            if this
                .output
                .as_mut()
                .is_some_and(|output| output.poll_interruption(cx).is_ready())
            {
                objects.cancel_pending();
            } else {
                let result = objects.poll_next(cx, this.max_frame_bytes);
                return this.object_result(result);
            }
        }
        let Some(output) = this.output.as_mut() else {
            this.close();
            return Poll::Ready(Some(Err(Status::internal("output owner is missing"))));
        };
        match output.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(event))) => {
                if let Err(error) = validate_reconciliation_access(
                    this.gateway.as_ref(),
                    &this.session,
                    &output.accepted().surface_id,
                ) {
                    this.close();
                    return Poll::Ready(Some(Err(error)));
                }
                // Keep the chunk's kernel credits until borrowed conversion and
                // encoded-size admission finish. Tonic owns its bounded copy.
                let frame = wire::output_event_to_pb(&event, this.max_frame_bytes);
                #[cfg(feature = "structured-output")]
                if frame
                    .as_ref()
                    .is_err_and(|status| status.code() == tonic::Code::ResourceExhausted)
                    && let Some(objects) = &mut this.objects
                {
                    objects.start(output.accepted().clone(), event);
                    let result = objects.poll_next(cx, this.max_frame_bytes);
                    return this.object_result(result);
                }
                let frame = match frame {
                    Err(status) if status.code() == Code::ResourceExhausted => {
                        if let Err(denied) = validate_reconciliation_access(
                            this.gateway.as_ref(),
                            &this.session,
                            &output.accepted().surface_id,
                        ) {
                            this.close();
                            return Poll::Ready(Some(Err(denied)));
                        }
                        let unresolved = match &event {
                            GatewayOutputEvent::Complete(result) => {
                                result.output.unresolved_operations.clone()
                            }
                            GatewayOutputEvent::Chunk(_) => UnresolvedOperations {
                                operation_ids: Vec::new(),
                                identities_incomplete: true,
                            },
                        };
                        wire::output_indeterminate_to_pb(
                            &unresolved,
                            "response_encoding_failed",
                            this.max_frame_bytes,
                        )
                    }
                    other => other,
                };
                if frame.is_err()
                    || matches!(event, GatewayOutputEvent::Complete(_))
                    || matches!(
                        frame.as_ref().ok().and_then(|frame| frame.event.as_ref()),
                        Some(pb::submit_output_response::Event::Indeterminate(_))
                    )
                {
                    this.close();
                }
                Poll::Ready(Some(frame))
            }
            Poll::Ready(Some(Err(error))) => {
                let frame = match error {
                    xolotl_gateway::GatewayError::SubmissionIndeterminate(unknown) => {
                        validate_reconciliation_access(
                            this.gateway.as_ref(),
                            &this.session,
                            &unknown.accepted.surface_id,
                        )
                        .and_then(|()| {
                            wire::output_indeterminate_to_pb(
                                &unknown.unresolved_operations,
                                unknown.reason_code,
                                this.max_frame_bytes,
                            )
                        })
                    }
                    other => Err(gateway_status(other)),
                };
                this.close();
                Poll::Ready(Some(frame))
            }
            Poll::Ready(None) => {
                this.close();
                Poll::Ready(Some(Err(Status::internal(
                    "output ended without request completion",
                ))))
            }
        }
    }
}

#[cfg(feature = "structured-output")]
impl ApplicationOutputStream {
    fn object_result(
        &mut self,
        result: Poll<(Result<pb::SubmitOutputResponse, Status>, bool)>,
    ) -> Poll<Option<Result<pb::SubmitOutputResponse, Status>>> {
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready((frame, complete)) => {
                if frame.is_err() || complete {
                    self.close();
                }
                Poll::Ready(Some(frame))
            }
        }
    }
}
