//! Typed output conversion retains kernel credits through encoded-size admission.

use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::Status;
use tonic::codegen::tokio_stream::Stream;
use xolotl_gateway::{GatewayOutputEvent, GatewayOutputStream};
use xolotl_proto::xolotl::v1::application as pb;

use super::{gateway_status, wire};

#[cfg(feature = "structured-output")]
mod structured;
#[cfg(feature = "structured-output")]
pub(super) use structured::ObjectDelivery;

/// One output RPC, driven directly by tonic's response-body polling.
/// Dropping it releases execution. Ingress owns the RPC lifecycle through the
/// HTTP body; transport capacity also follows encoded DATA beyond body Drop.
pub struct ApplicationOutputStream {
    output: Option<GatewayOutputStream>,
    accepted: Option<pb::SubmitOutputResponse>,
    max_frame_bytes: usize,
    done: bool,
    #[cfg(feature = "structured-output")]
    objects: Option<ObjectDelivery>,
}

impl ApplicationOutputStream {
    pub(super) fn new(output: GatewayOutputStream, max_frame_bytes: usize) -> Result<Self, Status> {
        let accepted = wire::output_accepted_to_pb(output.accepted(), max_frame_bytes)?;
        Ok(Self {
            output: Some(output),
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
                if frame.is_err() || matches!(event, GatewayOutputEvent::Complete(_)) {
                    this.close();
                }
                Poll::Ready(Some(frame))
            }
            Poll::Ready(Some(Err(error))) => {
                this.close();
                Poll::Ready(Some(Err(gateway_status(error))))
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
