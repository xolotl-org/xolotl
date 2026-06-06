// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/nexus/v1/gateway.proto`. `include!`d into the `nexus::v1` module so the
// crate builds without `protoc`. Keep in sync with the `.proto` spec.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitRequest {
    /// Bearer token mapped to a request identity by the gateway (§18.1 step 1-2).
    #[prost(string, tag = "1")]
    pub auth_token: ::prost::alloc::string::String,
    /// Structured Do<A> program, compiled and run by the kernel.
    #[prost(message, optional, tag = "2")]
    pub program: ::core::option::Option<Program>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitResponse {
    #[prost(message, optional, tag = "1")]
    pub outcome: ::core::option::Option<Outcome>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HealthRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HealthResponse {
    #[prost(bool, tag = "1")]
    pub ready: bool,
    #[prost(string, tag = "2")]
    pub version: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Program {
    #[prost(message, optional, tag = "1")]
    pub root: ::core::option::Option<DoNode>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DoNode {
    #[prost(oneof = "do_node::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11")]
    pub kind: ::core::option::Option<do_node::Kind>,
}
pub mod do_node {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Pure(super::Value),
        #[prost(message, tag = "2")]
        AndThen(super::AndThen),
        #[prost(message, tag = "3")]
        OrElse(super::OrElse),
        #[prost(message, tag = "4")]
        Both(super::Parallel),
        #[prost(message, tag = "5")]
        Race(super::Parallel),
        #[prost(message, tag = "6")]
        Let(super::Let),
        #[prost(string, tag = "7")]
        UseName(::prost::alloc::string::String),
        #[prost(message, tag = "8")]
        Acting(super::Acting),
        #[prost(message, tag = "9")]
        Fail(super::Failure),
        #[prost(message, tag = "10")]
        Wait(super::WaitSpec),
        #[prost(message, tag = "11")]
        Op(super::OperationTemplate),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndThen {
    #[prost(message, optional, boxed, tag = "1")]
    pub d: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, tag = "2")]
    pub then: ::core::option::Option<StepRef>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OrElse {
    #[prost(message, optional, boxed, tag = "1")]
    pub d: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, tag = "2")]
    pub or: ::core::option::Option<StepRef>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parallel {
    #[prost(message, optional, boxed, tag = "1")]
    pub left: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, boxed, tag = "2")]
    pub right: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Let {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, boxed, tag = "2")]
    pub value: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
    #[prost(message, optional, boxed, tag = "3")]
    pub body: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Acting {
    #[prost(message, optional, tag = "1")]
    pub identity: ::core::option::Option<Path>,
    #[prost(message, optional, boxed, tag = "2")]
    pub body: ::core::option::Option<::prost::alloc::boxed::Box<DoNode>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WaitSpec {
    #[prost(oneof = "wait_spec::Kind", tags = "1, 2")]
    pub kind: ::core::option::Option<wait_spec::Kind>,
}
pub mod wait_spec {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Signal(super::Path),
        #[prost(int64, tag = "2")]
        DeadlineMillis(i64),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StepRef {
    #[prost(uint64, tag = "1")]
    pub process_id: u64,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub arg: ::core::option::Option<Value>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OperationTemplate {
    #[prost(message, optional, tag = "1")]
    pub target: ::core::option::Option<Path>,
    #[prost(string, tag = "2")]
    pub method: ::prost::alloc::string::String,
    #[prost(uint64, optional, tag = "3")]
    pub method_id: ::core::option::Option<u64>,
    #[prost(message, optional, tag = "4")]
    pub output: ::core::option::Option<OutputMode>,
    #[prost(message, optional, tag = "5")]
    pub literal_input: ::core::option::Option<Value>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputMode {
    #[prost(enumeration = "OutputModeKind", tag = "1")]
    pub kind: i32,
    #[prost(uint64, tag = "2")]
    pub collect_limit: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OutputModeKind {
    Unspecified = 0,
    Unary = 1,
    Stream = 2,
    Collect = 3,
    AsyncProcess = 4,
    SinkOnly = 5,
}
impl OutputModeKind {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "OUTPUT_MODE_KIND_UNSPECIFIED",
            Self::Unary => "OUTPUT_MODE_UNARY",
            Self::Stream => "OUTPUT_MODE_STREAM",
            Self::Collect => "OUTPUT_MODE_COLLECT",
            Self::AsyncProcess => "OUTPUT_MODE_ASYNC_PROCESS",
            Self::SinkOnly => "OUTPUT_MODE_SINK_ONLY",
        }
    }
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "OUTPUT_MODE_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "OUTPUT_MODE_UNARY" => Some(Self::Unary),
            "OUTPUT_MODE_STREAM" => Some(Self::Stream),
            "OUTPUT_MODE_COLLECT" => Some(Self::Collect),
            "OUTPUT_MODE_ASYNC_PROCESS" => Some(Self::AsyncProcess),
            "OUTPUT_MODE_SINK_ONLY" => Some(Self::SinkOnly),
            _ => None,
        }
    }
}
/// Generated server implementations.
pub mod gateway_service_server {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value
    )]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with GatewayServiceServer.
    #[async_trait]
    pub trait GatewayService: std::marker::Send + std::marker::Sync + 'static {
        /// Run one submitted program and return its outcome.
        async fn submit(
            &self,
            request: tonic::Request<super::SubmitRequest>,
        ) -> std::result::Result<tonic::Response<super::SubmitResponse>, tonic::Status>;
        /// Health / readiness probe.
        async fn health(
            &self,
            request: tonic::Request<super::HealthRequest>,
        ) -> std::result::Result<tonic::Response<super::HealthResponse>, tonic::Status>;
    }
    /// Gateway service (§18.1): the primary entry point for external gRPC clients.
    #[derive(Debug)]
    pub struct GatewayServiceServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T> GatewayServiceServer<T> {
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
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for GatewayServiceServer<T>
    where
        T: GatewayService,
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
                "/nexus.v1.GatewayService/Submit" => {
                    #[allow(non_camel_case_types)]
                    struct SubmitSvc<T: GatewayService>(pub Arc<T>);
                    impl<T: GatewayService> tonic::server::UnaryService<super::SubmitRequest> for SubmitSvc<T> {
                        type Response = super::SubmitResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SubmitRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as GatewayService>::submit(&inner, request).await
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
                        let method = SubmitSvc(inner);
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
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/nexus.v1.GatewayService/Health" => {
                    #[allow(non_camel_case_types)]
                    struct HealthSvc<T: GatewayService>(pub Arc<T>);
                    impl<T: GatewayService> tonic::server::UnaryService<super::HealthRequest> for HealthSvc<T> {
                        type Response = super::HealthResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::HealthRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as GatewayService>::health(&inner, request).await
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
                        let method = HealthSvc(inner);
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
                        let res = grpc.unary(method, req).await;
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
    impl<T> Clone for GatewayServiceServer<T> {
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
    pub const SERVICE_NAME: &str = "nexus.v1.GatewayService";
    impl<T> tonic::server::NamedService for GatewayServiceServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
/// Generated client implementations.
pub mod gateway_service_client {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value
    )]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// Gateway service (§18.1) client.
    #[derive(Debug, Clone)]
    pub struct GatewayServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl GatewayServiceClient<tonic::transport::Channel> {
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
    impl<T> GatewayServiceClient<T>
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
        ) -> GatewayServiceClient<InterceptedService<T, F>>
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
            GatewayServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Run one submitted program and return its outcome.
        pub async fn submit(
            &mut self,
            request: impl tonic::IntoRequest<super::SubmitRequest>,
        ) -> std::result::Result<tonic::Response<super::SubmitResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/nexus.v1.GatewayService/Submit");
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("nexus.v1.GatewayService", "Submit"));
            self.inner.unary(req, path, codec).await
        }
        /// Health / readiness probe.
        pub async fn health(
            &mut self,
            request: impl tonic::IntoRequest<super::HealthRequest>,
        ) -> std::result::Result<tonic::Response<super::HealthResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/nexus.v1.GatewayService/Health");
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("nexus.v1.GatewayService", "Health"));
            self.inner.unary(req, path, codec).await
        }
    }
}
