//! A single owned encoding future, polled only by the response body.

use std::future::Future;
use std::sync::Arc;
use xolotl_gateway::{
    GatewayAccepted, GatewayExternalizedOutput, GatewayOutputExternalizationError,
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
    session: GatewaySession,
    pending: Option<PendingOutput>,
}

impl ObjectDelivery {
    pub(in crate::application) fn new(
        encoder: Arc<dyn GatewayOutputExternalizer>,
        session: GatewaySession,
    ) -> Self {
        Self {
            encoder,
            session,
            pending: None,
        }
    }

    pub(super) fn start(&mut self, accepted: GatewayAccepted, event: GatewayOutputEvent) {
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
        Poll::Ready(match result {
            Ok(output) => {
                let complete = matches!(output.original_event(), GatewayOutputEvent::Complete(_));
                // The owner and its credits survive the whole bounded projection.
                (
                    wire::structured::event_to_pb(&output, max_frame_bytes),
                    complete,
                )
            }
            Err(failure) => (Err(gateway_status(failure.error)), true),
        })
    }
}
