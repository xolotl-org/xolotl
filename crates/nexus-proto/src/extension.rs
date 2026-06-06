// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/nexus/v1/extension.proto` (package `nexus.v1.extension`). `include!`d
// into the `nexus::v1::extension` module. Keep in sync with the `.proto` spec.

/// Top-level frame envelope.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtensionFrame {
    #[prost(oneof = "extension_frame::Frame", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11")]
    pub frame: ::core::option::Option<extension_frame::Frame>,
}
/// Nested message and enum types in `ExtensionFrame`.
pub mod extension_frame {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Frame {
        #[prost(message, tag = "1")]
        RoleSessionClientHello(super::RoleSessionClientHello),
        #[prost(message, tag = "2")]
        SessionContext(super::SessionContext),
        #[prost(message, tag = "3")]
        RoleReady(super::RoleReady),
        #[prost(message, tag = "4")]
        InboundEvent(super::InboundEvent),
        #[prost(message, tag = "5")]
        OutboundCommand(super::OutboundCommand),
        #[prost(message, tag = "6")]
        CommandResult(super::CommandResult),
        #[prost(message, tag = "7")]
        EventAck(super::EventAck),
        #[prost(message, tag = "8")]
        Invoke(super::Invoke),
        #[prost(message, tag = "9")]
        InvokeResult(super::InvokeResult),
        #[prost(message, tag = "10")]
        PluginReady(super::PluginReady),
        #[prost(message, tag = "11")]
        Control(super::ControlFrame),
    }
}
/// Stage 1: extension reports identity plus locally observed generations/hash.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RoleSessionClientHello {
    #[prost(enumeration = "ExtensionRole", tag = "1")]
    pub role: i32,
    #[prost(string, tag = "2")]
    pub installation_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub registry_hash: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub observed: ::core::option::Option<ObservedGenerations>,
    #[prost(message, optional, tag = "5")]
    pub config_schema: ::core::option::Option<super::Value>,
}
/// Stage 2: daemon adjudicates authoritative registry hash/generations.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionContext {
    #[prost(string, tag = "1")]
    pub extension_def_id: ::prost::alloc::string::String,
    #[prost(enumeration = "ExtensionRole", tag = "2")]
    pub role: i32,
    #[prost(string, tag = "3")]
    pub registry_hash: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub credential_generation: u64,
    #[prost(uint64, tag = "5")]
    pub binding_generation: u64,
    #[prost(uint64, tag = "6")]
    pub extension_config_version: u64,
    #[prost(uint64, tag = "7")]
    pub presentation_config_generation: u64,
    #[prost(uint64, tag = "8")]
    pub alias_catalog_generation: u64,
}
/// Stage 3: extension confirms it has aligned to the daemon-selected context.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RoleReady {
    #[prost(message, optional, tag = "1")]
    pub accepted_context: ::core::option::Option<SessionContext>,
}
/// Bridge → Daemon: platform event occurred.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InboundEvent {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub payload: ::core::option::Option<super::Value>,
    #[prost(int64, tag = "3")]
    pub timestamp_ms: i64,
    /// Lightweight presentation/alias generation tags (§16.3.3).
    #[prost(message, optional, tag = "4")]
    pub observed: ::core::option::Option<ObservedGenerations>,
}
/// Daemon → Bridge: execute this action on the platform.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutboundCommand {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub action: ::core::option::Option<super::Value>,
    #[prost(message, optional, tag = "3")]
    pub observed: ::core::option::Option<ObservedGenerations>,
}
/// The two lightweight generation axes carried on each Source frame (§16.3.3).
/// Session-level generations live in SessionContext instead.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObservedGenerations {
    #[prost(uint64, tag = "1")]
    pub presentation_config_generation: u64,
    #[prost(uint64, tag = "2")]
    pub alias_catalog_generation: u64,
}
/// Bridge → Daemon: command execution result.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommandResult {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(oneof = "command_result::Outcome", tags = "2, 3")]
    pub outcome: ::core::option::Option<command_result::Outcome>,
}
/// Nested message and enum types in `CommandResult`.
pub mod command_result {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Outcome {
        #[prost(message, tag = "2")]
        Success(super::super::Value),
        #[prost(message, tag = "3")]
        Error(super::ErrorInfo),
    }
}
/// Daemon → Bridge: event acknowledgment.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventAck {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(enumeration = "AckStatus", tag = "2")]
    pub status: i32,
    #[prost(string, optional, tag = "3")]
    pub reject_reason: ::core::option::Option<::prost::alloc::string::String>,
}
/// Daemon → Plugin: invoke an effect.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Invoke {
    #[prost(string, tag = "1")]
    pub invocation_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub effect_path: ::core::option::Option<super::Path>,
    #[prost(message, optional, tag = "3")]
    pub input: ::core::option::Option<super::Value>,
    #[prost(int64, optional, tag = "4")]
    pub deadline_ms: ::core::option::Option<i64>,
    #[prost(string, optional, tag = "5")]
    pub output_stream_to: ::core::option::Option<::prost::alloc::string::String>,
}
/// Plugin → Daemon: invocation result.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvokeResult {
    #[prost(string, tag = "1")]
    pub invocation_id: ::prost::alloc::string::String,
    #[prost(oneof = "invoke_result::Outcome", tags = "2, 3")]
    pub outcome: ::core::option::Option<invoke_result::Outcome>,
}
/// Nested message and enum types in `InvokeResult`.
pub mod invoke_result {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Outcome {
        #[prost(message, tag = "2")]
        Success(super::super::Value),
        #[prost(message, tag = "3")]
        Error(super::ErrorInfo),
    }
}
/// Plugin → Daemon: initialization complete, declare capabilities.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PluginReady {
    #[prost(message, repeated, tag = "1")]
    pub provides: ::prost::alloc::vec::Vec<EffectHandlerSpec>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EffectHandlerSpec {
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    #[prost(enumeration = "super::Purity", tag = "2")]
    pub purity: i32,
    #[prost(string, optional, tag = "3")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ControlFrame {
    #[prost(oneof = "control_frame::Kind", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub kind: ::core::option::Option<control_frame::Kind>,
}
/// Nested message and enum types in `ControlFrame`.
pub mod control_frame {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Heartbeat(super::Heartbeat),
        #[prost(message, tag = "2")]
        Shutdown(super::Shutdown),
        #[prost(message, tag = "3")]
        FlowControl(super::FlowControl),
        #[prost(message, tag = "4")]
        PresentationProfileUpdate(super::PresentationProfileUpdate),
        #[prost(message, tag = "5")]
        ExtensionConfigUpdate(super::ExtensionConfigUpdate),
        #[prost(message, tag = "6")]
        PresentationConfigUpdate(super::PresentationConfigUpdate),
        #[prost(message, tag = "7")]
        ConfigAck(super::ConfigAck),
    }
}
/// Extension → daemon: report what this end can render (§16.3.3).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PresentationProfileUpdate {
    #[prost(uint64, tag = "1")]
    pub profile_generation: u64,
    #[prost(string, tag = "2")]
    pub profile_hash: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub profile: ::core::option::Option<super::Value>,
}
/// Daemon → extension: authority config update (§16.3.3), via §18.4 CAS.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtensionConfigUpdate {
    #[prost(uint64, tag = "1")]
    pub config_version: u64,
    #[prost(message, optional, tag = "2")]
    pub config: ::core::option::Option<super::Value>,
}
/// Daemon → extension: presentation-only config (§16.3.3), never grants capability.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PresentationConfigUpdate {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    #[prost(string, tag = "2")]
    pub profile_hash: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub config: ::core::option::Option<super::Value>,
}
/// Extension → daemon: how a config/presentation update was applied (§16.3.3).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConfigAck {
    #[prost(enumeration = "ConfigAxis", tag = "1")]
    pub axis: i32,
    #[prost(uint64, tag = "2")]
    pub version: u64,
    #[prost(enumeration = "ApplyStatus", tag = "3")]
    pub status: i32,
    /// Set only when `status == Rejected`.
    #[prost(enumeration = "RejectReason", optional, tag = "4")]
    pub reject_reason: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Heartbeat {
    #[prost(int64, tag = "1")]
    pub timestamp_ms: i64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Shutdown {
    #[prost(bool, tag = "1")]
    pub graceful: bool,
    #[prost(uint64, tag = "2")]
    pub timeout_ms: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowControl {
    #[prost(enumeration = "FlowSignal", tag = "1")]
    pub signal: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorInfo {
    #[prost(string, tag = "1")]
    pub code: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
    #[prost(map = "string, string", tag = "3")]
    pub details:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
}
/// Role = which primitive the extension projects (orthogonal to transport/trust).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ExtensionRole {
    Unspecified = 0,
    /// Source: provides a state:// inbound event stream (chat bridge, webhook).
    Source = 1,
    /// Provider: registers effect:// handlers (plugin, MCP server, remote device).
    Provider = 2,
}
impl ExtensionRole {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "EXTENSION_ROLE_UNSPECIFIED",
            Self::Source => "EXTENSION_ROLE_SOURCE",
            Self::Provider => "EXTENSION_ROLE_PROVIDER",
        }
    }
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "EXTENSION_ROLE_UNSPECIFIED" => Some(Self::Unspecified),
            "EXTENSION_ROLE_SOURCE" => Some(Self::Source),
            "EXTENSION_ROLE_PROVIDER" => Some(Self::Provider),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AckStatus {
    Unspecified = 0,
    Accepted = 1,
    Duplicate = 2,
    Rejected = 3,
}
impl AckStatus {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "ACK_STATUS_UNSPECIFIED",
            Self::Accepted => "ACK_STATUS_ACCEPTED",
            Self::Duplicate => "ACK_STATUS_DUPLICATE",
            Self::Rejected => "ACK_STATUS_REJECTED",
        }
    }
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ACK_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "ACK_STATUS_ACCEPTED" => Some(Self::Accepted),
            "ACK_STATUS_DUPLICATE" => Some(Self::Duplicate),
            "ACK_STATUS_REJECTED" => Some(Self::Rejected),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum FlowSignal {
    Unspecified = 0,
    Pause = 1,
    Resume = 2,
}
impl FlowSignal {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "FLOW_SIGNAL_UNSPECIFIED",
            Self::Pause => "FLOW_SIGNAL_PAUSE",
            Self::Resume => "FLOW_SIGNAL_RESUME",
        }
    }
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FLOW_SIGNAL_UNSPECIFIED" => Some(Self::Unspecified),
            "FLOW_SIGNAL_PAUSE" => Some(Self::Pause),
            "FLOW_SIGNAL_RESUME" => Some(Self::Resume),
            _ => None,
        }
    }
}
/// Which config axis a [`ConfigAck`] answers (§16.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ConfigAxis {
    Unspecified = 0,
    ExtensionConfig = 1,
    PresentationConfig = 2,
}
/// Result of applying a config/presentation update (§16.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ApplyStatus {
    Unspecified = 0,
    Applied = 1,
    Rejected = 2,
}
/// Why an extension rejected an update (§16.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RejectReason {
    Unspecified = 0,
    ProfileMismatch = 1,
    SchemaInvalid = 2,
    GenerationStale = 3,
    Unsupported = 4,
}
/// Generated server implementations.
pub mod extension_service_server {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value
    )]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with ExtensionServiceServer.
    #[async_trait]
    pub trait ExtensionService: std::marker::Send + std::marker::Sync + 'static {
        /// Server streaming response type for the Session method.
        type SessionStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::ExtensionFrame, tonic::Status>,
            > + std::marker::Send
            + 'static;
        async fn session(
            &self,
            request: tonic::Request<tonic::Streaming<super::ExtensionFrame>>,
        ) -> std::result::Result<tonic::Response<Self::SessionStream>, tonic::Status>;
    }
    /// ExtensionService — daemon-side gRPC service (out-of-process Sources/Providers connect to it).
    #[derive(Debug)]
    pub struct ExtensionServiceServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T> ExtensionServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for ExtensionServiceServer<T>
    where
        T: ExtensionService,
        B: Body + std::marker::Send + 'static,
        B::Error: Into<StdError> + std::marker::Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/nexus.v1.extension.ExtensionService/Session" => {
                    #[allow(non_camel_case_types)]
                    struct SessionSvc<T: ExtensionService>(pub Arc<T>);
                    impl<T: ExtensionService>
                        tonic::server::StreamingService<super::ExtensionFrame> for SessionSvc<T>
                    {
                        type Response = super::ExtensionFrame;
                        type ResponseStream = T::SessionStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::ExtensionFrame>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as ExtensionService>::session(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SessionSvc(inner);
                        let codec = tonic_prost::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    let headers = response.headers_mut();
                    headers.insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    headers.insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                }),
            }
        }
    }
    impl<T> Clone for ExtensionServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    /// Generated gRPC service name
    pub const SERVICE_NAME: &str = "nexus.v1.extension.ExtensionService";
    impl<T> tonic::server::NamedService for ExtensionServiceServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
/// Generated client implementations.
pub mod extension_service_client {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value
    )]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// ExtensionService client.
    #[derive(Debug, Clone)]
    pub struct ExtensionServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ExtensionServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ExtensionServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ExtensionServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::Body>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::Body>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::Body>>>::Error:
                Into<StdError> + std::marker::Send + std::marker::Sync,
        {
            ExtensionServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn session(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::ExtensionFrame>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::ExtensionFrame>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/nexus.v1.extension.ExtensionService/Session",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "nexus.v1.extension.ExtensionService",
                "Session",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}
