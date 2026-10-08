//! A single owned encoding future, polled only by the response body.

use std::future::Future;
use std::sync::Arc;
use xolotl_gateway::{
    Gateway, GatewayAccepted, GatewayExternalizedOutput, GatewayOutputExternalizationError,
    GatewayOutputExternalizer, GatewaySession,
};

use super::*;

type PendingOutput = Pin<
    Box<
        dyn Future<Output = Result<GatewayExternalizedOutput, GatewayOutputExternalizationError>>
            + Send,
    >,
>;

pub(in crate::application) struct ObjectDelivery {
    encoder: Arc<dyn GatewayOutputExternalizer>,
    gateway: Arc<dyn Gateway>,
    session: GatewaySession,
    pending: Option<PendingOutput>,
    reconciliation: Option<UnresolvedOperations>,
    surface_id: Option<String>,
}

impl ObjectDelivery {
    pub(in crate::application) fn new(
        encoder: Arc<dyn GatewayOutputExternalizer>,
        gateway: Arc<dyn Gateway>,
        session: GatewaySession,
    ) -> Self {
        Self {
            encoder,
            gateway,
            session,
            pending: None,
            reconciliation: None,
            surface_id: None,
        }
    }

    pub(super) fn start(&mut self, accepted: GatewayAccepted, event: GatewayOutputEvent) {
        self.surface_id = Some(accepted.surface_id.clone());
        self.reconciliation = Some(match &event {
            GatewayOutputEvent::Complete(result) => result.output.unresolved_operations.clone(),
            GatewayOutputEvent::Chunk(_) => UnresolvedOperations {
                operation_ids: Vec::new(),
                identities_incomplete: true,
            },
        });
        self.pending = Some(self.encoder.clone().externalize(
            self.session.clone(),
            accepted,
            event,
        ));
    }

    pub(super) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn cancel_pending(&mut self) {
        self.pending = None;
        self.reconciliation = None;
        self.surface_id = None;
    }

    pub(super) fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
        max_frame_bytes: usize,
    ) -> Poll<(Result<pb::SubmitOutputResponse, Status>, bool)> {
        let Some(future) = self.pending.as_mut() else {
            return Poll::Ready((
                Err(Status::internal("output encoding owner is missing")),
                true,
            ));
        };
        let result = match future.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.pending = None;
        let reconciliation = self.reconciliation.take().unwrap_or(UnresolvedOperations {
            operation_ids: Vec::new(),
            identities_incomplete: true,
        });
        let surface_id = self.surface_id.take();
        let access = surface_id
            .as_deref()
            .ok_or_else(|| Status::internal("output surface identity is missing"))
            .and_then(|surface_id| {
                validate_reconciliation_access(self.gateway.as_ref(), &self.session, surface_id)
            });
        if let Err(error) = access {
            return Poll::Ready((Err(error), true));
        }
        Poll::Ready(match result {
            Ok(output) => {
                let complete = matches!(output.original_event(), GatewayOutputEvent::Complete(_));
                // The owner and its credits survive the whole bounded projection.
                match wire::structured::event_to_pb(&output, max_frame_bytes) {
                    Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                        let Some(surface_id) = surface_id.as_deref() else {
                            return Poll::Ready((
                                Err(Status::internal("output surface identity is missing")),
                                true,
                            ));
                        };
                        if let Err(denied) = validate_reconciliation_access(
                            self.gateway.as_ref(),
                            &self.session,
                            surface_id,
                        ) {
                            return Poll::Ready((Err(denied), true));
                        }
                        let unresolved = match output.original_event() {
                            GatewayOutputEvent::Complete(result) => {
                                result.output.unresolved_operations.clone()
                            }
                            GatewayOutputEvent::Chunk(_) => UnresolvedOperations {
                                operation_ids: Vec::new(),
                                identities_incomplete: true,
                            },
                        };
                        (
                            wire::output_indeterminate_to_pb(
                                &unresolved,
                                "response_encoding_failed",
                                max_frame_bytes,
                            ),
                            true,
                        )
                    }
                    frame => (frame, complete),
                }
            }
            Err(failure) => {
                let frame = match surface_id.as_deref() {
                    Some(surface_id) => validate_reconciliation_access(
                        self.gateway.as_ref(),
                        &self.session,
                        surface_id,
                    )
                    .and_then(|()| {
                        wire::output_indeterminate_to_pb(
                            &reconciliation,
                            "response_delivery_failed",
                            max_frame_bytes,
                        )
                    }),
                    None => Err(gateway_status(failure.error)),
                };
                (frame, true)
            }
        })
    }
}
