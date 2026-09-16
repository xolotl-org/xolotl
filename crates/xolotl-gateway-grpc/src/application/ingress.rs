//! HTTP evidence, RPC lifetime, and response resources across tonic conversion.

use http_body::{Body, Frame, SizeHint};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, watch};
use tokio::time::{Instant, Sleep};
use tonic::Status;
use tonic::codegen::{BoxFuture, Bytes, Service, StdError, http};

const CLEAN_INPUT: u8 = 1;
const FAILED_INPUT: u8 = 2;

/// Observations from the HTTP request before tonic removes URI information or
/// converts a cancelled request body into an apparently successful stream EOF.
#[derive(Clone, Debug)]
pub(crate) struct RequestEvidence {
    authority: Option<String>,
    input_state: Arc<AtomicU8>,
    deadline: Option<RpcDeadline>,
}

impl RequestEvidence {
    fn new(authority: Option<String>) -> Self {
        Self {
            authority,
            input_state: Arc::new(AtomicU8::new(0)),
            deadline: None,
        }
    }

    pub(crate) fn authority(&self) -> Option<&str> {
        self.authority.as_deref()
    }

    pub(super) fn deadline(&self) -> Option<RpcDeadline> {
        self.deadline
    }

    /// This must accompany a protocol-level EOF after the required Finish frame.
    pub(crate) fn input_finished_cleanly(&self) -> bool {
        self.input_state.load(Ordering::Acquire) == CLEAN_INPUT
    }

    fn record_clean_input(&self) {
        self.input_state.fetch_or(CLEAN_INPUT, Ordering::Release);
    }

    fn record_input_error(&self) {
        self.input_state.fetch_or(FAILED_INPUT, Ordering::Release);
    }
}

/// Both clocks are captured at HTTP admission, before decoding or authentication.
#[derive(Clone, Copy, Debug)]
pub(super) struct RpcDeadline {
    instant: Instant,
    unix_ms: u64,
}

impl RpcDeadline {
    pub(super) fn unix_ms(self) -> u64 {
        self.unix_ms
    }

    fn from_headers(headers: &http::HeaderMap) -> Result<Option<Self>, Status> {
        let mut values = headers.get_all("grpc-timeout").iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(Status::invalid_argument("ambiguous grpc-timeout"));
        }
        let text = value
            .to_str()
            .map_err(|_error| Status::invalid_argument("invalid grpc-timeout"))?;
        let duration = parse_grpc_timeout(text)?;
        let instant = Instant::now()
            .checked_add(duration)
            .ok_or_else(|| Status::invalid_argument("grpc-timeout is out of range"))?;
        let wall = SystemTime::now()
            .checked_add(duration)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .ok_or_else(|| Status::invalid_argument("grpc-timeout is out of range"))?;
        // The Gateway uses millisecond deadlines. Round up so converting its
        // clock cannot expire a sub-millisecond RPC before the exact timer.
        let unix_ms = u64::try_from(wall.as_nanos().div_ceil(1_000_000))
            .map_err(|_error| Status::invalid_argument("grpc-timeout is out of range"))?;
        Ok(Some(Self { instant, unix_ms }))
    }
}

fn parse_grpc_timeout(text: &str) -> Result<Duration, Status> {
    let invalid = || Status::invalid_argument("invalid grpc-timeout");
    let bytes = text.as_bytes();
    let Some((&unit, digits)) = bytes.split_last() else {
        return Err(invalid());
    };
    if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    let value = digits
        .iter()
        .fold(0u64, |value, digit| value * 10 + u64::from(digit - b'0'));
    match unit {
        b'H' => Ok(Duration::from_secs(value * 3600)),
        b'M' => Ok(Duration::from_secs(value * 60)),
        b'S' => Ok(Duration::from_secs(value)),
        b'm' => Ok(Duration::from_millis(value)),
        b'u' => Ok(Duration::from_micros(value)),
        b'n' => Ok(Duration::from_nanos(value)),
        _ => Err(invalid()),
    }
}

/// Tonic preserves response extensions while constructing its encoded Body.
#[derive(Clone, Debug)]
pub(super) struct ResponsePermit {
    _permit: Arc<OwnedSemaphorePermit>,
}

impl ResponsePermit {
    pub(super) fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            _permit: Arc::new(permit),
        }
    }
}

struct ResponseBytes {
    bytes: Bytes,
    _permit: ResponsePermit,
}

impl AsRef<[u8]> for ResponseBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

struct Shutdown {
    state: watch::Receiver<bool>,
    wait: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Shutdown {
    fn new(state: watch::Receiver<bool>) -> Self {
        let mut changes = state.clone();
        let wait = Box::pin(async move {
            while !*changes.borrow_and_update() {
                if changes.changed().await.is_err() {
                    break;
                }
            }
        });
        Self { state, wait }
    }

    fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // The wait registers a waker; exhausted cooperative budget must not
        // hide a published shutdown or the loss of every sender.
        let requested = *self.state.borrow();
        if requested || self.state.has_changed().is_err() {
            return Poll::Ready(());
        }
        self.wait.as_mut().poll(cx)
    }
}

struct RequestLifecycle {
    shutdown: Option<Shutdown>,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl RequestLifecycle {
    fn new(shutdown: Option<watch::Receiver<bool>>, deadline: Option<RpcDeadline>) -> Self {
        Self {
            shutdown: shutdown.map(Shutdown::new),
            deadline: deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline.instant))),
        }
    }

    fn poll_status(&mut self, cx: &mut Context<'_>) -> Poll<Status> {
        if let Some(shutdown) = &mut self.shutdown
            && shutdown.poll_closed(cx).is_ready()
        {
            return Poll::Ready(Status::unavailable("application gateway is closed"));
        }
        // Timer readiness may lag the clock or exhaust its cooperative budget.
        if let Some(deadline) = &mut self.deadline
            && (Instant::now() >= deadline.deadline() || deadline.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(Status::deadline_exceeded(
                "application RPC deadline expired",
            ));
        }
        Poll::Pending
    }
}

/// Wrap a generated tonic server with HTTP authority, clean-input evidence and
/// one lifecycle covering decoding and streamed responses. Configure the
/// generated service's message limits first.
#[derive(Clone, Debug)]
pub struct ApplicationIngress<S> {
    inner: S,
    shutdown: Option<watch::Receiver<bool>>,
}

impl<S> ApplicationIngress<S> {
    /// Wrap the service before handing it to the HTTP server.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            shutdown: None,
        }
    }

    pub(crate) fn with_shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }
}

impl<S> tonic::server::NamedService for ApplicationIngress<S>
where
    S: tonic::server::NamedService,
{
    const NAME: &'static str = S::NAME;
}

impl<S, B> Service<http::Request<B>> for ApplicationIngress<S>
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
        let (mut parts, body) = request.into_parts();
        let deadline = match RpcDeadline::from_headers(&parts.headers) {
            Ok(deadline) => deadline,
            Err(status) => return Box::pin(async move { Ok(status.into_http()) }),
        };
        let mut evidence = RequestEvidence::new(
            parts
                .uri
                .authority()
                .map(|authority| authority.as_str().to_string()),
        );
        evidence.deadline = deadline;
        parts.extensions.insert(evidence.clone());
        let body = EvidenceBody::new(tonic::body::Body::new(body), evidence);
        let response = self.inner.call(http::Request::from_parts(
            parts,
            tonic::body::Body::new(body),
        ));
        let mut lifecycle = RequestLifecycle::new(self.shutdown.clone(), deadline);
        Box::pin(async move {
            // The same absolute timer covers decoding, admission, and the
            // response body; returning response headers never restarts it.
            let mut response = std::pin::pin!(response);
            let mut response = poll_fn(|cx| {
                if let Poll::Ready(status) = lifecycle.poll_status(cx) {
                    return Poll::Ready(Ok(status.into_http()));
                }
                let result = response.as_mut().poll(cx);
                if let Poll::Ready(status) = lifecycle.poll_status(cx) {
                    return Poll::Ready(Ok(status.into_http()));
                }
                result
            })
            .await?;
            if let Some(permit) = response.extensions_mut().remove::<ResponsePermit>() {
                return Ok(response.map(|body| {
                    tonic::body::Body::new(ResponseBody {
                        inner: Some(body),
                        lifecycle,
                        ended: false,
                        permit,
                    })
                }));
            }
            Ok(response)
        })
    }
}

struct ResponseBody {
    inner: Option<tonic::body::Body>,
    lifecycle: RequestLifecycle,
    ended: bool,
    permit: ResponsePermit,
}

impl ResponseBody {
    fn close(&mut self, status: Status) -> Result<Frame<Bytes>, Status> {
        self.ended = true;
        self.inner = None;
        let mut trailers = http::HeaderMap::new();
        status.add_header(&mut trailers)?;
        Ok(Frame::trailers(trailers))
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        if let Poll::Ready(status) = this.lifecycle.poll_status(cx) {
            return Poll::Ready(Some(this.close(status)));
        }
        let Some(inner) = &mut this.inner else {
            this.ended = true;
            return Poll::Ready(None);
        };
        let frame = Pin::new(inner).poll_frame(cx);
        // Decoding or encoding can cross the deadline within one synchronous
        // poll, before the runtime has had a chance to drive its timer queue.
        if let Poll::Ready(status) = this.lifecycle.poll_status(cx) {
            return Poll::Ready(Some(this.close(status)));
        }
        match frame {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_trailers() {
                    this.ended = true;
                    this.inner = None;
                }
                // Hyper may finish this Body while h2 still retains DATA.
                // Each encoded buffer shares the permit without copying bytes.
                Poll::Ready(Some(Ok(frame.map_data(|bytes| {
                    Bytes::from_owner(ResponseBytes {
                        bytes,
                        _permit: this.permit.clone(),
                    })
                }))))
            }
            Poll::Ready(frame) => {
                this.ended = true;
                this.inner = None;
                Poll::Ready(frame)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended || self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(SizeHint::default, Body::size_hint)
    }
}

struct EvidenceBody {
    inner: tonic::body::Body,
    evidence: RequestEvidence,
}

impl EvidenceBody {
    fn new(inner: tonic::body::Body, evidence: RequestEvidence) -> Self {
        // Body::new may discard an already-ended body without polling it.
        if inner.is_end_stream() {
            evidence.record_clean_input();
        }
        Self { inner, evidence }
    }
}

impl Body for EvidenceBody {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Err(_))) => self.evidence.record_input_error(),
            Poll::Ready(None) => self.evidence.record_clean_input(),
            Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => {
                // Tonic stops at trailers and may never poll the body again.
                self.evidence.record_clean_input();
            }
            Poll::Ready(Some(Ok(_))) | Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        let ended = self.inner.is_end_stream();
        if ended {
            self.evidence.record_clean_input();
        }
        ended
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests;
