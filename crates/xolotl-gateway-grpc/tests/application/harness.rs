use super::ports::{Pause, ProbeOptions, ProbeStore, ReceiptState, ResponseProbe, Signal};
use anyhow::{Context as _, ensure};
use http_body::{Body, Frame, SizeHint};
use pb::application_gateway_client::ApplicationGatewayClient;
use prost::Message;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tonic::codegen::tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{BoxFuture, Bytes, Service, StdError, http};
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};
use xolotl_gateway::{
    GatewayPrincipalSurfaceBinding, GatewayProfile, GatewayRuntime, GatewaySurface,
};
use xolotl_gateway_grpc::{ApplicationGrpcConfig, ApplicationGrpcService};
use xolotl_kernel::{Bootstrap, Driver, EchoDriver, FactSink, Kernel, MethodSpec};
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_state::Backend;
use xolotl_state::host::object::ObjectStore;
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{Path, Purity, Value};

pub fn output_value(value: &Value) -> pb::OutputValue {
    pb::OutputValue {
        content: Some(pb::output_value::Content::Inline(
            xolotl_proto::value_to_pb(value),
        )),
    }
}

pub fn output_outcome(outcome: &xolotl_types::Outcome) -> pb::OutputOutcome {
    use pb::output_outcome::Kind;
    use xolotl_types::Outcome;
    let kind = match outcome {
        Outcome::Done(value) => Kind::Done(output_value(value)),
        Outcome::Short(value) => Kind::Short(output_value(value)),
        Outcome::Fail(failure) => Kind::Fail(pb::OutputFailure {
            content: Some(pb::output_failure::Content::Inline(
                xolotl_proto::failure_to_pb(failure),
            )),
        }),
    };
    pb::OutputOutcome { kind: Some(kind) }
}

pub fn inline_value(value: &pb::OutputValue) -> anyhow::Result<&xolotl_proto::xolotl::v1::Value> {
    match &value.content {
        Some(pb::output_value::Content::Inline(value)) => Ok(value),
        other => anyhow::bail!("expected inline value, got {other:?}"),
    }
}

pub const TEST_WAIT: Duration = Duration::from_secs(10);
pub const TOKEN: &str = "application-test-alice-credential";
const UPLOAD_PATH: &str = "/xolotl.v1.application.ApplicationGateway/UploadObject";
pub const DESCRIBE_PATH: &str = "/xolotl.v1.application.ApplicationGateway/Describe";
pub const OUTPUT_PATH: &str = "/xolotl.v1.application.ApplicationGateway/SubmitOutput";
pub const DOWNLOAD_PATH: &str = "/xolotl.v1.application.ApplicationGateway/DownloadObject";

pub struct EffectOptions {
    driver: Arc<dyn Driver>,
    method: MethodSpec,
    pub output_schema: Option<Value>,
    pub stream_schema: Option<Value>,
    pub response_probe: Option<Arc<ResponseProbe>>,
    #[cfg(feature = "structured-output")]
    disclosure: Option<Arc<dyn xolotl_gateway::GatewayOutputDisclosurePolicy>>,
}

impl EffectOptions {
    pub fn stream(driver: Arc<dyn Driver>, purity: Purity) -> Self {
        Self {
            driver,
            method: MethodSpec::stream_async("invoke", purity),
            output_schema: None,
            stream_schema: None,
            response_probe: None,
            #[cfg(feature = "structured-output")]
            disclosure: None,
        }
    }

    #[cfg(feature = "structured-output")]
    pub fn unary(driver: Arc<dyn Driver>, purity: Purity) -> Self {
        Self {
            method: MethodSpec::unary_async("invoke", purity),
            ..Self::stream(driver, purity)
        }
    }

    #[cfg(feature = "structured-output")]
    pub fn with_disclosure(
        mut self,
        policy: Arc<dyn xolotl_gateway::GatewayOutputDisclosurePolicy>,
    ) -> Self {
        self.disclosure = Some(policy);
        self
    }
}

pub struct Fixture {
    _directory: tempfile::TempDir,
    pub files: FileObjectStore,
    pub boot: Arc<Bootstrap>,
    pub gateway: Arc<GatewayRuntime>,
    pub probe: Arc<ProbeStore>,
    pub service: ApplicationGrpcService,
    pub body_waits: Arc<Signal>,
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}

impl Fixture {
    pub async fn new(config: ApplicationGrpcConfig) -> anyhow::Result<Self> {
        Self::with_options(config, ProbeOptions::default(), None).await
    }

    pub async fn with_options(
        config: ApplicationGrpcConfig,
        options: ProbeOptions,
        receipt: Option<Pause>,
    ) -> anyhow::Result<Self> {
        Self::build(
            config,
            options,
            receipt.map(ReceiptState::new),
            EffectOptions {
                driver: Arc::new(EchoDriver),
                method: MethodSpec::unary_async("invoke", Purity::Pure),
                output_schema: None,
                stream_schema: None,
                response_probe: None,
                #[cfg(feature = "structured-output")]
                disclosure: None,
            },
        )
        .await
    }

    pub async fn with_effect(
        config: ApplicationGrpcConfig,
        effect: EffectOptions,
        consume_receipt: Option<Pause>,
    ) -> anyhow::Result<Self> {
        Self::build(
            config,
            ProbeOptions::default(),
            consume_receipt.map(ReceiptState::consuming),
            effect,
        )
        .await
    }

    #[cfg(feature = "structured-output")]
    pub async fn with_effect_and_options(
        config: ApplicationGrpcConfig,
        effect: EffectOptions,
        options: ProbeOptions,
    ) -> anyhow::Result<Self> {
        Self::build(config, options, None, effect).await
    }

    async fn build(
        config: ApplicationGrpcConfig,
        options: ProbeOptions,
        receipt: Option<ReceiptState>,
        effect: EffectOptions,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let directory = tempfile::tempdir()?;
        let files = FileObjectStore::open(directory.path())?;
        let probe = Arc::new(ProbeStore::new(files.clone(), options));
        let boot = match receipt {
            Some(state) => {
                let state = Arc::new(state);
                Arc::new(Bootstrap::from_kernel(Kernel::with_backends(
                    Backend::new().with_read(state.clone()).with_write(state),
                    FactSink::in_memory().0,
                )))
            }
            None => Arc::new(Bootstrap::in_memory()),
        };
        let name = boot.register_effect("effect://echo/say", &[effect.method], effect.driver)?;
        let mut surface =
            GatewaySurface::effect_invoke("echo", name).with_schema(None, effect.output_schema);
        if let Some(schema) = effect.stream_schema {
            surface = surface.with_output_stream_schema(schema);
        }
        let profile = GatewayProfile::new("application-test")
            .with_bearer_identity("alice-credential", "alice", TOKEN, "process://alice")?
            .with_registered_host(&addr.to_string())?
            .with_surface(surface)
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let gateway = Arc::new(
            GatewayRuntime::new(boot.clone(), profile)?.with_object_store(
                ObjectStore::new()
                    .with_read(probe.clone())
                    .with_write(probe.clone()),
            ),
        );
        let service = ApplicationGrpcService::from_arc_with_config(gateway.clone(), config)?;
        #[cfg(feature = "structured-output")]
        let service = if let Some(policy) = effect.disclosure {
            service.with_output_externalizer(gateway.clone().output_externalizer(
                std::num::NonZeroUsize::MIN.saturating_add(256),
                xolotl_gateway::GatewayOutputObjectOptions::default(),
                || std::future::ready(Ok::<_, std::convert::Infallible>(output_keys())),
                policy,
            ))
        } else {
            service
        };
        let body_waits = Signal::new();
        let observed = ObserveWaits {
            inner: service.clone().into_server(),
            waits: body_waits.clone(),
            response: effect.response_probe,
        };
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(observed)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _shutdown_received = stopped.await;
                })
                .await
        });
        Ok(Self {
            _directory: directory,
            files,
            boot,
            gateway,
            probe,
            service,
            body_waits,
            addr,
            stop: Some(stop),
            server: Some(server),
        })
    }

    pub async fn client(&self) -> anyhow::Result<ApplicationGatewayClient<Channel>> {
        Ok(tokio::time::timeout(
            TEST_WAIT,
            ApplicationGatewayClient::connect(format!("http://{}", self.addr)),
        )
        .await??)
    }

    pub async fn issue(
        &self,
        client: &mut ApplicationGatewayClient<Channel>,
    ) -> anyhow::Result<pb::IssueUploadTicketResponse> {
        Ok(client
            .issue_upload_ticket(request(pb::IssueUploadTicketRequest {
                surface_id: "echo".into(),
                submission_token: None,
                modality: pb::Modality::Bytes as i32,
                expected_size: None,
                expected_digest: None,
                allowed_media_types: vec![],
                expires_in_ms: Some(60_000),
                single_use: true,
            })?)
            .await?
            .into_inner())
    }

    pub async fn receipt_flag(&self, ticket: &str, flag: &str) -> anyhow::Result<bool> {
        let value = self
            .boot
            .kernel
            .state
            .read(&Path::parse(&format!(
                "state://gateway/upload-ticket/{ticket}"
            ))?)
            .await?
            .context("ticket record missing")?;
        let flag = value
            .as_map()
            .and_then(|map| map.get(flag))
            .context("ticket state field missing")?;
        let Some(flag) = flag.as_bool() else {
            anyhow::bail!("ticket state field is not boolean")
        };
        Ok(flag)
    }

    pub async fn raw(&self) -> anyhow::Result<RawConnection> {
        self.raw_with_window(65_535).await
    }

    pub async fn raw_with_window(&self, bytes: u32) -> anyhow::Result<RawConnection> {
        let stream = TcpStream::connect(self.addr).await?;
        let (sender, mut connection) = h2::client::Builder::new()
            .initial_window_size(bytes)
            .handshake(stream)
            .await?;
        let (window, mut updates) = mpsc::channel::<ReceiveWindow>(1);
        let driver = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = &mut connection => {
                        if let Err(error) = result {
                            tracing::debug!(?error, "test HTTP/2 connection closed");
                        }
                        break;
                    }
                    update = updates.recv() => {
                        let Some(update) = update else { break };
                        let result = connection.set_initial_window_size(update.bytes);
                        let _applied = update.applied.send(result);
                    }
                }
            }
        });
        Ok(RawConnection {
            sender,
            driver,
            addr: self.addr,
            window,
        })
    }

    pub async fn close(mut self) -> anyhow::Result<()> {
        self.service.shutdown();
        if let Some(stop) = self.stop.take() {
            let _shutdown_sent = stop.send(());
        }
        if let Some(mut server) = self.server.take() {
            match tokio::time::timeout(TEST_WAIT, &mut server).await {
                Ok(result) => result??,
                Err(error) => {
                    server.abort();
                    match server.await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(error.into()),
                        Err(error) if error.is_cancelled() => {}
                        Err(error) => return Err(error.into()),
                    }
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "structured-output")]
pub fn output_keys() -> xolotl_value_codec::validation::MemoryKeyStore {
    use xolotl_value_codec::validation::{MemoryKeyOptions, MemoryKeyStore};
    MemoryKeyStore::new(MemoryKeyOptions {
        page_bytes: std::num::NonZeroUsize::MIN.saturating_add(126),
        max_keys: None,
        max_bytes: None,
    })
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.service.shutdown();
        if let Some(stop) = self.stop.take() {
            let _shutdown_sent = stop.send(());
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

pub fn request<T>(message: T) -> anyhow::Result<Request<T>> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse()?);
    Ok(request)
}

pub fn begin(ticket: &str) -> pb::UploadObjectRequest {
    pb::UploadObjectRequest {
        frame: Some(pb::upload_object_request::Frame::Begin(
            pb::BeginObjectUpload {
                ticket_id: ticket.into(),
                media_type: Some("application/octet-stream".into()),
                submission_token: None,
            },
        )),
    }
}

pub fn finish() -> pb::UploadObjectRequest {
    pb::UploadObjectRequest {
        frame: Some(pb::upload_object_request::Frame::Finish(
            pb::FinishObjectUpload {
                kind: Some(pb::finish_object_upload::Kind::Blob(pb::BlobUpload {})),
            },
        )),
    }
}

pub fn chunk(bytes: &[u8]) -> pb::UploadObjectRequest {
    pb::UploadObjectRequest {
        frame: Some(pb::upload_object_request::Frame::Chunk(bytes.to_vec())),
    }
}

pub fn encode_frames(frames: &[impl Message]) -> anyhow::Result<Bytes> {
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.push(0);
        bytes.extend_from_slice(&u32::try_from(frame.encoded_len())?.to_be_bytes());
        frame.encode(&mut bytes)?;
    }
    Ok(Bytes::from(bytes))
}

pub fn decode_frames<M: Message + Default>(mut bytes: &[u8]) -> anyhow::Result<Vec<M>> {
    let mut messages = Vec::new();
    while !bytes.is_empty() {
        ensure!(
            bytes.len() >= 5 && bytes[0] == 0,
            "invalid gRPC frame prefix"
        );
        let size = usize::try_from(u32::from_be_bytes(bytes[1..5].try_into()?))?;
        let (message, rest) = bytes[5..]
            .split_at_checked(size)
            .context("incomplete gRPC frame")?;
        messages.push(M::decode(message)?);
        bytes = rest;
    }
    Ok(messages)
}

pub struct RawConnection {
    sender: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
    addr: SocketAddr,
    window: mpsc::Sender<ReceiveWindow>,
}

struct ReceiveWindow {
    bytes: u32,
    applied: oneshot::Sender<Result<(), h2::Error>>,
}

impl RawConnection {
    pub async fn set_receive_window(&self, bytes: u32) -> anyhow::Result<()> {
        let (applied, received) = oneshot::channel();
        tokio::time::timeout(TEST_WAIT, async {
            self.window.send(ReceiveWindow { bytes, applied }).await?;
            received.await??;
            Ok(())
        })
        .await?
    }

    pub async fn upload(
        &self,
        _ticket: &str,
        frames: &[pb::UploadObjectRequest],
        end: bool,
    ) -> anyhow::Result<RawRequest> {
        self.request(UPLOAD_PATH, encode_frames(frames)?, end).await
    }

    pub async fn request(&self, path: &str, bytes: Bytes, end: bool) -> anyhow::Result<RawRequest> {
        self.request_with_headers(path, bytes, end, &[]).await
    }

    pub async fn request_with_headers(
        &self,
        path: &str,
        bytes: Bytes,
        end: bool,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<RawRequest> {
        let mut sender = self.sender.clone().ready().await?;
        let mut request = http::Request::builder()
            .method("POST")
            .uri(format!("http://{}{path}", self.addr))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("authorization", format!("Bearer {TOKEN}"));
        for &(name, value) in headers {
            request = request.header(name, value);
        }
        let (response, mut stream) = sender.send_request(request.body(())?, false)?;
        if !bytes.is_empty() || end {
            stream.send_data(bytes, end)?;
        }
        Ok(RawRequest { response, stream })
    }
}

impl Drop for RawConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub struct RawRequest {
    response: h2::client::ResponseFuture,
    pub stream: h2::SendStream<Bytes>,
}

impl RawRequest {
    pub async fn streaming_response(
        self,
    ) -> anyhow::Result<(h2::SendStream<Bytes>, http::Response<h2::RecvStream>)> {
        let response = tokio::time::timeout(TEST_WAIT, self.response).await??;
        Ok((self.stream, response))
    }

    pub async fn response(self) -> anyhow::Result<RawResponse> {
        let Self {
            response,
            stream: _stream,
        } = self;
        tokio::time::timeout(TEST_WAIT, async move {
            let response = response.await?;
            let mut message = Vec::new();
            let status = if let Some(status) = response.headers().get("grpc-status") {
                // Trailers-only is terminal; h2 may then reset an unfinished request.
                status.clone()
            } else {
                let mut body = response.into_body();
                while let Some(bytes) = body.data().await {
                    let bytes = bytes?;
                    body.flow_control().release_capacity(bytes.len())?;
                    message.extend_from_slice(&bytes);
                }
                body.trailers()
                    .await?
                    .and_then(|trailers| trailers.get("grpc-status").cloned())
                    .context("gRPC status missing")?
            };
            let status = status.to_str()?.parse::<i32>()?;
            Ok(RawResponse {
                code: Code::from_i32(status),
                message,
            })
        })
        .await?
    }
}

pub struct RawResponse {
    pub code: Code,
    message: Vec<u8>,
}

impl RawResponse {
    pub fn frames<M: Message + Default>(&self) -> anyhow::Result<Vec<M>> {
        decode_frames(&self.message)
    }

    pub fn upload(&self) -> anyhow::Result<pb::UploadObjectResponse> {
        ensure!(self.code == Code::Ok && self.message.len() >= 5);
        ensure!(self.message[0] == 0);
        let size = u32::from_be_bytes(self.message[1..5].try_into()?) as usize;
        ensure!(self.message.len() == size + 5);
        Ok(pb::UploadObjectResponse::decode(&self.message[5..])?)
    }
}

#[derive(Clone)]
struct ObserveWaits<S> {
    inner: S,
    waits: Arc<Signal>,
    response: Option<Arc<ResponseProbe>>,
}

impl<S: tonic::server::NamedService> tonic::server::NamedService for ObserveWaits<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, B> Service<http::Request<B>> for ObserveWaits<S>
where
    S: Service<http::Request<tonic::body::Body>, Response = http::Response<tonic::body::Body>>,
    S::Future: Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<StdError>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let waits =
            matches!(parts.uri.path(), UPLOAD_PATH | DESCRIBE_PATH).then(|| self.waits.clone());
        let response_probe = self
            .response
            .clone()
            .filter(|_| matches!(parts.uri.path(), OUTPUT_PATH | DOWNLOAD_PATH));
        let download = parts.uri.path() == DOWNLOAD_PATH;
        let body = ObservedBody {
            inner: tonic::body::Body::new(body),
            waits,
            saw_data: false,
            announced: false,
        };
        let response = self.inner.call(http::Request::from_parts(
            parts,
            tonic::body::Body::new(body),
        ));
        Box::pin(async move {
            let response = response.await?;
            let Some(probe) = response_probe else {
                return Ok(response);
            };
            if response.headers().contains_key("grpc-status") {
                return Ok(response);
            }
            let (parts, inner) = response.into_parts();
            Ok(http::Response::from_parts(
                parts,
                tonic::body::Body::new(ObservedResponseBody {
                    inner,
                    probe,
                    download,
                }),
            ))
        })
    }
}

struct ObservedResponseBody {
    inner: tonic::body::Body,
    probe: Arc<ResponseProbe>,
    download: bool,
}

impl Drop for ObservedResponseBody {
    fn drop(&mut self) {
        drop(std::mem::replace(
            &mut self.inner,
            tonic::body::Body::empty(),
        ));
        self.probe.dropped.notify();
    }
}

impl Body for ObservedResponseBody {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, tonic::Status>>> {
        let frame = match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => frame,
            other => return other,
        };
        let bytes = match frame.into_data() {
            Ok(bytes) => bytes,
            Err(frame) => return Poll::Ready(Some(Ok(frame))),
        };
        let completed = if self.download {
            decode_frames::<pb::DownloadObjectResponse>(&bytes).is_ok_and(|messages| {
                messages.iter().any(|message| {
                    matches!(
                        message.event,
                        Some(pb::download_object_response::Event::Completed(_))
                    )
                })
            })
        } else {
            decode_frames::<pb::SubmitOutputResponse>(&bytes).is_ok_and(|messages| {
                messages.iter().any(|message| {
                    matches!(
                        message.event,
                        Some(pb::submit_output_response::Event::Completed(_))
                    )
                })
            })
        };
        if completed {
            self.probe.completed.notify();
        }
        self.probe.retain_data();
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_owner(
            ObservedResponseData {
                inner: bytes,
                probe: self.probe.clone(),
            },
        )))))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct ObservedResponseData {
    inner: Bytes,
    probe: Arc<ResponseProbe>,
}

impl AsRef<[u8]> for ObservedResponseData {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Drop for ObservedResponseData {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.inner));
        self.probe.release_data();
    }
}

struct ObservedBody {
    inner: tonic::body::Body,
    waits: Option<Arc<Signal>>,
    saw_data: bool,
    announced: bool,
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = tonic::Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, tonic::Status>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) if frame.is_data() => self.saw_data = true,
            Poll::Pending if self.saw_data && !self.announced => {
                self.announced = true;
                if let Some(waits) = &self.waits {
                    waits.notify();
                }
            }
            _ => {}
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
