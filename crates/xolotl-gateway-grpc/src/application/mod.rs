//! Profile-bound application transport. Upload futures and encoded output data
//! own their resources; no detached worker or duplicate receipt registry exists.

use pb::application_gateway_server::{ApplicationGateway, ApplicationGatewayServer};
use pb::upload_object_request::Frame;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tonic::{Request, Response, Status, Streaming};
use xolotl_gateway::{Gateway, GatewayError, GatewaySession, GatewaySubmissionHead, StreamWindow};
use xolotl_proto::xolotl::v1::application as pb;

mod auth;
mod config;
mod download;
mod ingress;
mod output;
mod wire;

pub use config::ApplicationGrpcConfig;
pub use download::ApplicationObjectDownloadStream;
pub use ingress::ApplicationIngress;
use ingress::{RequestEvidence, ResponsePermit, RpcDeadline};
pub use output::ApplicationOutputStream;

/// Authenticated application ingress over one shared Gateway runtime.
/// Submission response bodies retain the original session and surface through
/// encoding and check current disclosure authority before handing off frames.
/// Revocation withholds pending bytes and successful completion, not effects or
/// bytes already handed to the network. Encoded buffers retain only capacity.
#[derive(Clone)]
pub struct ApplicationGrpcService {
    gateway: Arc<dyn Gateway>,
    config: Arc<ApplicationGrpcConfig>,
    uploads: Arc<Semaphore>,
    outputs: Arc<Semaphore>,
    output_window: StreamWindow,
    shutdown: watch::Sender<bool>,
    #[cfg(feature = "structured-output")]
    output_externalizer: Option<Arc<dyn xolotl_gateway::GatewayOutputExternalizer>>,
}

impl ApplicationGrpcService {
    /// Use an existing runtime and explicit transport windows. Invalid settings
    /// fail construction; no hidden clamp changes deployment intent.
    pub fn from_arc_with_config(
        gateway: Arc<dyn Gateway>,
        mut config: ApplicationGrpcConfig,
    ) -> Result<Self, Status> {
        config.validate()?;
        let uploads = Arc::new(Semaphore::new(config.max_concurrent_uploads));
        let outputs = Arc::new(Semaphore::new(config.max_concurrent_output_responses));
        let output_window = StreamWindow {
            max_chunks: NonZeroUsize::new(config.output_window_chunks)
                .ok_or_else(|| Status::invalid_argument("output_window_chunks must be nonzero"))?,
            max_inline_bytes: NonZeroUsize::new(config.output_window_bytes)
                .ok_or_else(|| Status::invalid_argument("output_window_bytes must be nonzero"))?,
        };
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            gateway,
            config: Arc::new(config),
            uploads,
            outputs,
            output_window,
            shutdown,
            #[cfg(feature = "structured-output")]
            output_externalizer: None,
        })
    }

    /// Enable object delivery when a result cannot fit the inline frame budget.
    /// The host supplies the workspace and disclosure policy through Gateway's
    /// externalizer. Each response polls at most one encoding future; cancellation
    /// releases its original output credits and staging. Client preferences do
    /// not authorize object reads. Metadata still shares the frame budget.
    #[cfg(feature = "structured-output")]
    pub fn with_output_externalizer(
        mut self,
        externalizer: Arc<dyn xolotl_gateway::GatewayOutputExternalizer>,
    ) -> Self {
        self.output_externalizer = Some(externalizer);
        self
    }

    /// Wrap the generated service with HTTP authority and clean-body evidence.
    /// Serving the generated service directly bypasses required evidence and is
    /// rejected by the application handlers.
    pub fn into_server(self) -> ApplicationIngress<ApplicationGatewayServer<Self>> {
        let max_frame_bytes = self.config.max_frame_bytes;
        let shutdown = self.shutdown.subscribe();
        ApplicationIngress::new(
            ApplicationGatewayServer::new(self)
                .max_decoding_message_size(max_frame_bytes)
                .max_encoding_message_size(max_frame_bytes),
        )
        .with_shutdown(shutdown)
    }

    /// Reject new RPCs and cancel active operations across every clone. The
    /// listener owner must also stop accepting connections and join the server.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
        self.uploads.close();
        self.outputs.close();
    }

    async fn deliver_result(
        &self,
        session: GatewaySession,
        result: xolotl_gateway::GatewaySubmitResult,
        permit: ResponsePermit,
        retained_delivery: bool,
    ) -> Result<Response<pb::SubmitResponse>, Status> {
        validate_reconciliation_access(
            self.gateway.as_ref(),
            &session,
            &result.accepted.surface_id,
        )?;
        let response = wire::submit_response_to_pb(&result, self.config.max_frame_bytes);
        #[cfg(feature = "structured-output")]
        if response
            .as_ref()
            .is_err_and(|status| status.code() == tonic::Code::ResourceExhausted)
            && let Some(externalizer) = &self.output_externalizer
        {
            let accepted = result.accepted.clone();
            let unresolved = result.output.unresolved_operations.clone();
            let current_session = session.clone();
            let object = externalizer
                .clone()
                .externalize(
                    session,
                    result.accepted.clone(),
                    xolotl_gateway::GatewayOutputEvent::Complete(result),
                )
                .await;
            validate_reconciliation_access(
                self.gateway.as_ref(),
                &current_session,
                &accepted.surface_id,
            )?;
            let object = match object {
                Ok(object) => object,
                Err(failure) => {
                    // A later revocation must not be bypassed by the
                    // reconciliation fallback.
                    validate_reconciliation_access(
                        self.gateway.as_ref(),
                        &current_session,
                        &accepted.surface_id,
                    )?;
                    if retained_delivery
                        && !matches!(
                            failure.error,
                            GatewayError::Indeterminate(_)
                                | GatewayError::SubmissionIndeterminate(_)
                        )
                    {
                        return Err(match failure.error {
                            GatewayError::Rejected(_) => {
                                Status::failed_precondition("retained result delivery unavailable")
                            }
                            error => gateway_status(error),
                        });
                    }
                    let mut response = Response::new(wire::submit_indeterminate_to_pb(
                        &accepted,
                        &unresolved,
                        "response_delivery_failed",
                        self.config.max_frame_bytes,
                    )?);
                    tracing::debug!(error = %failure.error, "gateway result delivery failed");
                    response.extensions_mut().insert(permit);
                    return Ok(response);
                }
            };
            let mut response = Response::new(
                match wire::structured::submit_to_pb(&object, self.config.max_frame_bytes) {
                    Ok(response) => response,
                    Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                        validate_reconciliation_access(
                            self.gateway.as_ref(),
                            &current_session,
                            &accepted.surface_id,
                        )?;
                        wire::submit_indeterminate_to_pb(
                            &accepted,
                            &unresolved,
                            "response_encoding_failed",
                            self.config.max_frame_bytes,
                        )?
                    }
                    Err(status) => return Err(status),
                },
            );
            response.extensions_mut().insert(permit);
            return Ok(response);
        }
        let mut response = Response::new(match response {
            Ok(response) => response,
            Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                if retained_delivery {
                    return Err(Status::resource_exhausted(
                        "retained result exceeds the inline envelope and no usable externalizer is configured",
                    ));
                }
                validate_reconciliation_access(
                    self.gateway.as_ref(),
                    &session,
                    &result.accepted.surface_id,
                )?;
                wire::submit_indeterminate_to_pb(
                    &result.accepted,
                    &result.output.unresolved_operations,
                    "response_encoding_failed",
                    self.config.max_frame_bytes,
                )?
            }
            Err(status) => return Err(status),
        });
        response.extensions_mut().insert(permit);
        Ok(response)
    }

    fn submission_permit(
        &self,
        permit: OwnedSemaphorePermit,
        session: GatewaySession,
        surface_id: String,
    ) -> ResponsePermit {
        let gateway = self.gateway.clone();
        ResponsePermit::new(permit).with_access(move || {
            validate_reconciliation_access(gateway.as_ref(), &session, &surface_id)
        })
    }

    async fn run<T>(
        &self,
        operation: impl Future<Output = Result<T, Status>>,
    ) -> Result<T, Status> {
        let mut shutdown = self.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(Status::unavailable("application gateway is closed"));
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => Err(Status::unavailable("application gateway is closed")),
            result = operation => result,
        }
    }

    async fn storage<T>(
        &self,
        operation: impl Future<Output = Result<T, GatewayError>>,
    ) -> Result<T, Status> {
        tokio::time::timeout(self.config.storage_timeout, operation)
            .await
            .map_err(|_error| Status::deadline_exceeded("gateway storage wait expired"))?
            .map_err(gateway_status)
    }

    fn with_transport_deadline(
        &self,
        mut submission: GatewaySubmissionHead,
        deadline: Option<RpcDeadline>,
    ) -> Result<GatewaySubmissionHead, Status> {
        let Some(deadline) = deadline else {
            return Ok(submission);
        };
        let host_deadline = self
            .gateway
            .deadline_after(deadline.remaining())
            .map_err(gateway_status)?;
        submission.server_deadline = Some(host_deadline);
        Ok(submission)
    }

    async fn receive(
        stream: &mut Streaming<pb::UploadObjectRequest>,
        wait: Duration,
    ) -> Result<Option<Frame>, Status> {
        tokio::time::timeout(wait, stream.message())
            .await
            .map_err(|_error| Status::deadline_exceeded("upload frame wait expired"))??
            .map(|message| {
                message
                    .frame
                    .ok_or_else(|| Status::invalid_argument("upload frame is required"))
            })
            .transpose()
    }

    async fn upload(
        &self,
        request: Request<Streaming<pb::UploadObjectRequest>>,
    ) -> Result<Response<pb::UploadObjectResponse>, Status> {
        let _permit = self
            .uploads
            .clone()
            .try_acquire_owned()
            .map_err(|_error| Status::resource_exhausted("upload window is full"))?;
        let session = self.authenticate(&request).await?;
        let evidence = request
            .extensions()
            .get::<RequestEvidence>()
            .cloned()
            .ok_or_else(|| {
                Status::failed_precondition("application ingress evidence is missing")
            })?;
        let mut stream = request.into_inner();
        let Some(Frame::Begin(begin)) =
            Self::receive(&mut stream, self.config.first_frame_timeout).await?
        else {
            return Err(Status::invalid_argument("upload must start with Begin"));
        };
        let mut upload = self
            .storage(
                self.gateway
                    .begin_object_upload(&session, wire::begin_upload_from_pb(begin)),
            )
            .await?;
        let kind = loop {
            match Self::receive(&mut stream, self.config.idle_timeout).await? {
                Some(Frame::Chunk(bytes)) => {
                    self.storage(upload.write(&bytes)).await?;
                }
                Some(Frame::Finish(finish)) => break wire::finish_upload_from_pb(finish)?,
                Some(Frame::Begin(_)) => {
                    return Err(Status::invalid_argument("duplicate upload Begin"));
                }
                None => return Err(Status::invalid_argument("upload Finish is required")),
            }
        };
        if Self::receive(&mut stream, self.config.idle_timeout)
            .await?
            .is_some()
        {
            return Err(Status::invalid_argument("upload frame after Finish"));
        }
        // Tonic can translate an HTTP/2 CANCEL into None. Only the underlying
        // HTTP body's successful completion authorizes publication.
        if !evidence.input_finished_cleanly() {
            return Err(Status::cancelled("upload input did not finish cleanly"));
        }
        let response = self.storage(upload.commit(kind)).await?;
        Ok(Response::new(wire::upload_response_to_pb(
            &response,
            self.config.max_frame_bytes,
        )?))
    }
}

#[tonic::async_trait]
impl ApplicationGateway for ApplicationGrpcService {
    type SubmitOutputStream = ApplicationOutputStream;
    type DownloadObjectStream = ApplicationObjectDownloadStream;

    async fn download_object(
        &self,
        request: Request<pb::DownloadObjectRequest>,
    ) -> Result<Response<Self::DownloadObjectStream>, Status> {
        self.run(async {
            let permit =
                self.outputs.clone().try_acquire_owned().map_err(|_error| {
                    Status::resource_exhausted("output response window is full")
                })?;
            let session = self.authenticate(&request).await?;
            let download = self
                .storage(self.gateway.open_object_read(
                    &session,
                    wire::download::request_from_pb(request.into_inner()),
                ))
                .await?;
            let mut response = Response::new(ApplicationObjectDownloadStream::new(
                download,
                self.config.max_frame_bytes,
                self.config.storage_timeout,
            )?);
            response
                .extensions_mut()
                .insert(ResponsePermit::new(permit));
            Ok(response)
        })
        .await
    }

    async fn describe(
        &self,
        request: Request<pb::DescribeRequest>,
    ) -> Result<Response<pb::DescribeResponse>, Status> {
        self.run(async {
            let session = self.authenticate(&request).await?;
            let retry_epoch = self.storage(self.gateway.retry_epoch(&session)).await?;
            let descriptor = self.gateway.describe(&session).map_err(gateway_status)?;
            Ok(Response::new(wire::descriptor_to_pb(
                &descriptor,
                retry_epoch,
                self.config.max_frame_bytes,
            )?))
        })
        .await
    }

    async fn lookup_request(
        &self,
        request: Request<pb::LookupRequestRequest>,
    ) -> Result<Response<pb::LookupRequestResponse>, Status> {
        self.run(async {
            let permit =
                self.outputs.clone().try_acquire_owned().map_err(|_error| {
                    Status::resource_exhausted("output response window is full")
                })?;
            let session = self.authenticate(&request).await?;
            let lookup = wire::lookup_request_from_pb(request.into_inner())?;
            let permit = self.submission_permit(permit, session.clone(), lookup.surface_id.clone());
            let evidence = self
                .storage(self.gateway.lookup_request(&session, lookup))
                .await?;
            let mut response = Response::new(wire::lookup_response_to_pb(
                evidence,
                self.config.max_frame_bytes,
            )?);
            response.extensions_mut().insert(permit);
            Ok(response)
        })
        .await
    }

    async fn deliver_request_result(
        &self,
        request: Request<pb::LookupRequestRequest>,
    ) -> Result<Response<pb::SubmitResponse>, Status> {
        self.run(async {
            let permit =
                self.outputs.clone().try_acquire_owned().map_err(|_error| {
                    Status::resource_exhausted("output response window is full")
                })?;
            let session = self.authenticate(&request).await?;
            let lookup = wire::lookup_request_from_pb(request.into_inner())?;
            let permit = self.submission_permit(permit, session.clone(), lookup.surface_id.clone());
            let retained = self
                .storage(self.gateway.read_retained_request_result(&session, lookup))
                .await?;
            use xolotl_gateway::GatewayRetainedRequestResult;
            let result = match retained {
                GatewayRetainedRequestResult::Available(result) => *result,
                GatewayRetainedRequestResult::Unproven => {
                    return Err(Status::failed_precondition(
                        "retained result unavailable: unproven",
                    ));
                }
                GatewayRetainedRequestResult::Reserved => {
                    return Err(Status::failed_precondition(
                        "retained result unavailable: reserved",
                    ));
                }
                GatewayRetainedRequestResult::Retired => {
                    return Err(Status::failed_precondition(
                        "retained result unavailable: retired",
                    ));
                }
            };
            self.deliver_result(session, result, permit, true).await
        })
        .await
    }

    async fn issue_upload_ticket(
        &self,
        request: Request<pb::IssueUploadTicketRequest>,
    ) -> Result<Response<pb::IssueUploadTicketResponse>, Status> {
        self.run(async {
            let session = self.authenticate(&request).await?;
            let ticket = self
                .storage(self.gateway.issue_object_upload_ticket(
                    &session,
                    wire::issue_upload_ticket_from_pb(request.into_inner())?,
                ))
                .await?;
            Ok(Response::new(wire::upload_ticket_to_pb(&ticket)))
        })
        .await
    }

    async fn upload_object(
        &self,
        request: Request<Streaming<pb::UploadObjectRequest>>,
    ) -> Result<Response<pb::UploadObjectResponse>, Status> {
        self.run(self.upload(request)).await
    }

    async fn submit(
        &self,
        request: Request<pb::SubmitRequest>,
    ) -> Result<Response<pb::SubmitResponse>, Status> {
        self.run(async {
            let permit =
                self.outputs.clone().try_acquire_owned().map_err(|_error| {
                    Status::resource_exhausted("output response window is full")
                })?;
            let session = self.authenticate(&request).await?;
            let deadline = request
                .extensions()
                .get::<RequestEvidence>()
                .and_then(RequestEvidence::deadline);
            let submission = self.with_transport_deadline(
                wire::submission_head_from_pb(request.get_ref(), false)?,
                deadline,
            )?;
            let permit =
                self.submission_permit(permit, session.clone(), submission.surface_id.clone());
            let preparation = self
                .gateway
                .prepare_submission(&session, submission, None)
                .map_err(gateway_status)?;
            let (payload, provenance) = wire::submission_payload_from_pb(request.into_inner())?;
            let result = match self
                .gateway
                .submit_prepared(preparation, payload, provenance)
                .await
            {
                Ok(result) => result,
                Err(GatewayError::SubmissionIndeterminate(unknown)) => {
                    validate_reconciliation_access(
                        self.gateway.as_ref(),
                        &session,
                        &unknown.accepted.surface_id,
                    )?;
                    let mut response = Response::new(wire::submit_indeterminate_to_pb(
                        &unknown.accepted,
                        &unknown.unresolved_operations,
                        unknown.reason_code,
                        self.config.max_frame_bytes,
                    )?);
                    response.extensions_mut().insert(permit);
                    return Ok(response);
                }
                Err(error) => return Err(gateway_status(error)),
            };
            self.deliver_result(session, result, permit, false).await
        })
        .await
    }

    async fn submit_output(
        &self,
        request: Request<pb::SubmitRequest>,
    ) -> Result<Response<Self::SubmitOutputStream>, Status> {
        self.run(async {
            let permit =
                self.outputs.clone().try_acquire_owned().map_err(|_error| {
                    Status::resource_exhausted("output response window is full")
                })?;
            let session = self.authenticate(&request).await?;
            let deadline = request
                .extensions()
                .get::<RequestEvidence>()
                .and_then(RequestEvidence::deadline);
            let submission = self.with_transport_deadline(
                wire::submission_head_from_pb(request.get_ref(), true)?,
                deadline,
            )?;
            let permit =
                self.submission_permit(permit, session.clone(), submission.surface_id.clone());
            let preparation = self
                .gateway
                .prepare_submission(&session, submission, Some(self.output_window))
                .map_err(gateway_status)?;
            let (payload, provenance) = wire::submission_payload_from_pb(request.into_inner())?;
            let output = self
                .storage(self.gateway.submit_output_stream_prepared(
                    preparation,
                    payload,
                    provenance,
                ))
                .await?;
            let output = ApplicationOutputStream::new(
                output,
                self.gateway.clone(),
                session.clone(),
                self.config.max_frame_bytes,
            )?;
            #[cfg(feature = "structured-output")]
            let output = output.with_objects(self.output_externalizer.as_ref().map(|encoder| {
                output::ObjectDelivery::new(encoder.clone(), self.gateway.clone(), session)
            }));
            let mut response = Response::new(output);
            response.extensions_mut().insert(permit);
            Ok(response)
        })
        .await
    }
}

fn gateway_status(error: GatewayError) -> Status {
    let message = error.public_message();
    let code = error.code();
    let mut status = match error {
        GatewayError::Unauthenticated => Status::unauthenticated(message),
        GatewayError::Unauthorized(_) => Status::permission_denied(message),
        GatewayError::LimitExceeded(_) => Status::resource_exhausted(message),
        GatewayError::InvalidProfile(_) => Status::failed_precondition(message),
        GatewayError::Rejected(_) => Status::invalid_argument(message),
        GatewayError::Indeterminate(_) | GatewayError::SubmissionIndeterminate(_) => {
            Status::failed_precondition(message)
        }
    };
    let _previous = status.metadata_mut().insert(
        "x-xolotl-error-code",
        tonic::metadata::MetadataValue::from_static(code),
    );
    status
}

fn validate_reconciliation_access(
    gateway: &dyn Gateway,
    session: &GatewaySession,
    surface_id: &str,
) -> Result<(), Status> {
    gateway
        .validate_submission_access(session, surface_id)
        .map_err(|_access_error| {
            gateway_status(GatewayError::Indeterminate(
                "submission delivery access unavailable".into(),
            ))
        })
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn unknown_outcome_maps_to_reconciliation_required_status() {
        let status = gateway_status(GatewayError::Indeterminate("private detail".into()));
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            status.message(),
            "outcome unknown; reconcile before retrying"
        );
        assert_eq!(
            status
                .metadata()
                .get("x-xolotl-error-code")
                .and_then(|value| value.to_str().ok()),
            Some("outcome_unknown")
        );
    }
}
