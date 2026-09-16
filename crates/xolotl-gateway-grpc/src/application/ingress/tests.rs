use super::*;
use anyhow::{Context as _, ensure};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::sync::atomic::AtomicBool;
use std::task::Waker;
use tokio::sync::Semaphore;
use tonic::Status;

struct TestBody {
    frames: VecDeque<Result<Frame<Bytes>, Status>>,
    end_after_last_frame: bool,
    wait_after_frames: bool,
    eof_polled: bool,
    dropped: Option<Arc<AtomicBool>>,
    advance_on_poll: Option<Duration>,
    shutdown_on_poll: Option<watch::Sender<bool>>,
}

impl TestBody {
    fn new(frames: impl IntoIterator<Item = Result<Frame<Bytes>, Status>>) -> Self {
        Self {
            frames: frames.into_iter().collect(),
            end_after_last_frame: false,
            wait_after_frames: false,
            eof_polled: false,
            dropped: None,
            advance_on_poll: None,
            shutdown_on_poll: None,
        }
    }
}

impl Drop for TestBody {
    fn drop(&mut self) {
        if let Some(dropped) = &self.dropped {
            dropped.store(true, Ordering::Release);
        }
    }
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        if let Some(duration) = self.advance_on_poll.take()
            && let Err(error) = advance_clock_without_timers(duration)
        {
            return Poll::Ready(Some(Err(error)));
        }
        if let Some(shutdown) = self.shutdown_on_poll.take() {
            shutdown.send_replace(true);
            if let Err(error) = exhaust_cooperative_budget() {
                return Poll::Ready(Some(Err(error)));
            }
        }
        if let Some(frame) = self.frames.pop_front() {
            return Poll::Ready(Some(frame));
        }
        if self.wait_after_frames {
            return Poll::Pending;
        }
        self.eof_polled = true;
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.eof_polled || (self.end_after_last_frame && self.frames.is_empty())
    }
}

fn tracked(body: TestBody) -> (tonic::body::Body, RequestEvidence) {
    let evidence = RequestEvidence::new(None);
    let body = EvidenceBody::new(tonic::body::Body::new(body), evidence.clone());
    (tonic::body::Body::new(body), evidence)
}

fn poll_frame(body: &mut tonic::body::Body) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(body).poll_frame(&mut cx)
}

fn advance_clock_without_timers(duration: Duration) -> Result<(), Status> {
    // Tokio advances the paused clock before yielding to its timer driver.
    // Poll only that first step to reproduce a stalled driver deterministically.
    let mut advance = std::pin::pin!(tokio::time::advance(duration));
    let mut cx = Context::from_waker(Waker::noop());
    if advance.as_mut().poll(&mut cx).is_ready() {
        return Err(Status::internal(
            "clock advance did not yield before polling timers",
        ));
    }
    Ok(())
}

fn exhaust_cooperative_budget() -> Result<(), Status> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1024 {
        match tokio::task::coop::poll_proceed(&mut cx) {
            Poll::Ready(progress) => progress.made_progress(),
            Poll::Pending => return Ok(()),
        }
    }
    Err(Status::internal(
        "test task has no bounded cooperative budget",
    ))
}

fn ready_frame(body: &mut tonic::body::Body) -> anyhow::Result<Frame<Bytes>> {
    match poll_frame(body) {
        Poll::Ready(Some(frame)) => Ok(frame?),
        _ => anyhow::bail!("expected a ready response frame"),
    }
}

fn response_body(
    input: TestBody,
    shutdown: Option<watch::Receiver<bool>>,
    deadline: Option<RpcDeadline>,
) -> anyhow::Result<(tonic::body::Body, Arc<Semaphore>)> {
    let outputs = Arc::new(Semaphore::new(1));
    let permit = ResponsePermit::new(outputs.clone().try_acquire_owned()?);
    let body = ResponseBody {
        inner: Some(tonic::body::Body::new(input)),
        lifecycle: RequestLifecycle::new(shutdown, deadline),
        ended: false,
        permit,
    };
    Ok((tonic::body::Body::new(body), outputs))
}

#[test]
fn grpc_timeout_accepts_protocol_units_and_rejects_ambiguous_values() -> anyhow::Result<()> {
    for (text, duration) in [
        ("0n", Duration::ZERO),
        ("1H", Duration::from_secs(3600)),
        ("2M", Duration::from_secs(120)),
        ("3S", Duration::from_secs(3)),
        ("4m", Duration::from_millis(4)),
        ("5u", Duration::from_micros(5)),
        ("6n", Duration::from_nanos(6)),
        ("00000001S", Duration::from_secs(1)),
        ("99999999H", Duration::from_secs(99_999_999 * 3600)),
    ] {
        ensure!(parse_grpc_timeout(text)? == duration, "timeout {text}");
    }
    for text in [
        "",
        "S",
        "1",
        "-1S",
        "+1S",
        " 1S",
        "1 S",
        "1S ",
        "1s",
        "1.0S",
        "123456789S",
        "1S,2S",
    ] {
        ensure!(
            parse_grpc_timeout(text)
                .is_err_and(|error| error.code() == tonic::Code::InvalidArgument),
            "accepted invalid timeout {text:?}"
        );
    }
    Ok(())
}

#[test]
fn grpc_timeout_header_is_optional_and_must_be_unique() -> anyhow::Result<()> {
    let mut headers = http::HeaderMap::new();
    ensure!(RpcDeadline::from_headers(&headers)?.is_none());
    headers.insert("grpc-timeout", http::HeaderValue::from_static("1u"));
    let before = Instant::now();
    let deadline = RpcDeadline::from_headers(&headers)?.context("missing deadline")?;
    ensure!(deadline.instant >= before + Duration::from_micros(1));
    ensure!(deadline.instant <= Instant::now() + Duration::from_micros(1));
    ensure!(deadline.unix_ms() > 0);
    headers.append("grpc-timeout", http::HeaderValue::from_static("1u"));
    ensure!(RpcDeadline::from_headers(&headers).is_err());
    headers.remove("grpc-timeout");
    headers.insert("grpc-timeout", http::HeaderValue::from_bytes(b"\xff")?);
    ensure!(RpcDeadline::from_headers(&headers).is_err());
    Ok(())
}

#[test]
fn output_permit_survives_source_eof_until_body_drop() -> anyhow::Result<()> {
    let (mut body, outputs) = response_body(TestBody::new([]), None, None)?;
    ensure!(outputs.available_permits() == 0);
    ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
    ensure!(body.is_end_stream());
    ensure!(outputs.available_permits() == 0);
    drop(body);
    ensure!(outputs.available_permits() == 1);
    Ok(())
}

#[test]
fn encoded_data_retains_output_permit_without_copying_until_last_slice_drops() -> anyhow::Result<()>
{
    let bytes = Bytes::from_static(b"encoded output");
    let original = bytes.as_ptr();
    let mut trailers = http::HeaderMap::new();
    Status::ok("").add_header(&mut trailers)?;
    let input = TestBody::new([Ok(Frame::data(bytes)), Ok(Frame::trailers(trailers))]);
    let (mut body, outputs) = response_body(input, None, None)?;
    let bytes = ready_frame(&mut body)?
        .into_data()
        .map_err(|_frame| anyhow::anyhow!("expected encoded data"))?;
    ensure!(bytes.as_ptr() == original);
    let retained_slice = bytes.slice(1..);
    let retained_clone = bytes.clone();
    drop(bytes);
    ensure!(ready_frame(&mut body)?.is_trailers());
    ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
    drop(body);
    ensure!(outputs.available_permits() == 0);
    drop(retained_clone);
    ensure!(outputs.available_permits() == 0);
    ensure!(retained_slice.as_ref() == b"ncoded output");
    drop(retained_slice);
    ensure!(outputs.available_permits() == 1);
    Ok(())
}

#[tokio::test]
async fn response_deadline_drops_execution_and_emits_one_status_trailer() -> anyhow::Result<()> {
    let dropped = Arc::new(AtomicBool::new(false));
    let mut input = TestBody::new([]);
    input.wait_after_frames = true;
    input.dropped = Some(dropped.clone());
    let deadline = RpcDeadline {
        instant: Instant::now(),
        unix_ms: 0,
    };
    let (mut body, outputs) = response_body(input, None, Some(deadline))?;
    let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
        .await
        .context("missing deadline trailer")??;
    ensure!(
        frame
            .trailers_ref()
            .and_then(|headers| headers.get("grpc-status"))
            == Some(&http::HeaderValue::from_static("4"))
    );
    ensure!(dropped.load(Ordering::Acquire));
    ensure!(body.is_end_stream());
    ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
    ensure!(outputs.available_permits() == 0);
    drop(body);
    ensure!(outputs.available_permits() == 1);
    Ok(())
}

#[tokio::test]
async fn shutdown_drops_execution_and_emits_one_unavailable_trailer() -> anyhow::Result<()> {
    let dropped = Arc::new(AtomicBool::new(false));
    let mut input = TestBody::new([]);
    input.wait_after_frames = true;
    input.dropped = Some(dropped.clone());
    let (shutdown, watch) = watch::channel(false);
    let (mut body, outputs) = response_body(input, Some(watch), None)?;
    ensure!(poll_frame(&mut body).is_pending());
    shutdown.send_replace(true);
    let frame = ready_frame(&mut body)?;
    ensure!(
        frame
            .trailers_ref()
            .and_then(|headers| headers.get("grpc-status"))
            == Some(&http::HeaderValue::from_static("14"))
    );
    ensure!(dropped.load(Ordering::Acquire));
    ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
    ensure!(outputs.available_permits() == 0);
    drop(body);
    ensure!(outputs.available_permits() == 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn rpc_expiry_does_not_depend_on_timer_driver_readiness() -> anyhow::Result<()> {
    let deadline = RpcDeadline {
        instant: Instant::now() + Duration::from_millis(10),
        unix_ms: 0,
    };
    let mut lifecycle = RequestLifecycle::new(None, Some(deadline));
    let mut cx = Context::from_waker(Waker::noop());
    ensure!(lifecycle.poll_status(&mut cx).is_pending());
    advance_clock_without_timers(Duration::from_millis(11))?;
    ensure!(Instant::now() >= deadline.instant);
    ensure!(
        !lifecycle
            .deadline
            .as_ref()
            .context("missing timer")?
            .is_elapsed()
    );
    let Poll::Ready(status) = lifecycle.poll_status(&mut cx) else {
        anyhow::bail!("expired RPC waited for the timer driver");
    };
    ensure!(status.code() == tonic::Code::DeadlineExceeded);
    Ok(())
}

#[tokio::test]
async fn shutdown_and_sender_loss_bypass_exhausted_cooperative_budget() -> anyhow::Result<()> {
    for close_sender in [false, true] {
        tokio::spawn(async move {
            let (shutdown, watch) = watch::channel(false);
            let mut lifecycle = RequestLifecycle::new(Some(watch), None);
            let mut cx = Context::from_waker(Waker::noop());
            ensure!(lifecycle.poll_status(&mut cx).is_pending());
            if close_sender {
                drop(shutdown);
            } else {
                shutdown.send_replace(true);
            }
            exhaust_cooperative_budget()?;
            ensure!(!tokio::task::coop::has_budget_remaining());
            ensure!(
                lifecycle
                    .shutdown
                    .as_mut()
                    .context("missing shutdown")?
                    .wait
                    .as_mut()
                    .poll(&mut cx)
                    .is_pending()
            );
            let Poll::Ready(status) = lifecycle.poll_status(&mut cx) else {
                anyhow::bail!("shutdown waited for cooperative budget");
            };
            ensure!(status.code() == tonic::Code::Unavailable);
            anyhow::Ok(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn shutdown_during_a_body_poll_discards_data_trailers_and_eof() -> anyhow::Result<()> {
    let mut trailers = http::HeaderMap::new();
    Status::ok("").add_header(&mut trailers)?;
    for frame in [
        Some(Frame::data(Bytes::from_static(b"closed output"))),
        Some(Frame::trailers(trailers)),
        None,
    ] {
        tokio::spawn(async move {
            let (shutdown, watch) = watch::channel(false);
            let dropped = Arc::new(AtomicBool::new(false));
            let mut input = TestBody::new(frame.into_iter().map(Ok));
            input.dropped = Some(dropped.clone());
            input.shutdown_on_poll = Some(shutdown.clone());
            let (mut body, outputs) = response_body(input, Some(watch), None)?;
            let frame = ready_frame(&mut body)?;
            ensure!(*shutdown.borrow());
            ensure!(!tokio::task::coop::has_budget_remaining());
            ensure!(
                frame
                    .trailers_ref()
                    .and_then(|headers| headers.get("grpc-status"))
                    == Some(&http::HeaderValue::from_static("14"))
            );
            ensure!(dropped.load(Ordering::Acquire));
            ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
            ensure!(outputs.available_permits() == 0);
            drop(body);
            ensure!(outputs.available_permits() == 1);
            anyhow::Ok(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn output_generated_during_a_poll_that_crosses_the_deadline_is_discarded()
-> anyhow::Result<()> {
    let mut trailers = http::HeaderMap::new();
    Status::ok("").add_header(&mut trailers)?;
    for frame in [
        Some(Frame::data(Bytes::from_static(b"late output"))),
        Some(Frame::trailers(trailers)),
        None,
    ] {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut input = TestBody::new(frame.into_iter().map(Ok));
        input.dropped = Some(dropped.clone());
        input.advance_on_poll = Some(Duration::from_millis(11));
        let deadline = RpcDeadline {
            instant: Instant::now() + Duration::from_millis(10),
            unix_ms: 0,
        };
        let (mut body, outputs) = response_body(input, None, Some(deadline))?;
        let frame = ready_frame(&mut body)?;
        ensure!(
            frame
                .trailers_ref()
                .and_then(|headers| headers.get("grpc-status"))
                == Some(&http::HeaderValue::from_static("4"))
        );
        ensure!(dropped.load(Ordering::Acquire));
        ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
        ensure!(outputs.available_permits() == 0);
        drop(body);
        ensure!(outputs.available_permits() == 1);
    }
    Ok(())
}

#[test]
fn empty_body_completion_survives_tonic_body_elision() -> anyhow::Result<()> {
    let evidence = RequestEvidence::new(None);
    let body = EvidenceBody::new(tonic::body::Body::empty(), evidence.clone());
    ensure!(evidence.input_finished_cleanly());
    let body = tonic::body::Body::new(body);
    ensure!(body.is_end_stream() && evidence.input_finished_cleanly());
    Ok(())
}

#[test]
fn final_data_and_trailers_record_completion_without_an_eof_poll() -> anyhow::Result<()> {
    for frame in [
        Frame::data(Bytes::from_static(b"input")),
        Frame::trailers(http::HeaderMap::new()),
    ] {
        let mut input = TestBody::new([Ok(frame)]);
        input.end_after_last_frame = true;
        let (mut body, evidence) = tracked(input);
        ensure!(!evidence.input_finished_cleanly());
        ensure!(matches!(poll_frame(&mut body), Poll::Ready(Some(Ok(_)))));
        ensure!(evidence.input_finished_cleanly());
    }
    Ok(())
}

#[test]
fn incomplete_input_requires_a_real_eof_and_drop_does_not_supply_it() -> anyhow::Result<()> {
    let input = TestBody::new([Ok(Frame::data(Bytes::from_static(b"input")))]);
    let (mut body, evidence) = tracked(input);
    ensure!(matches!(poll_frame(&mut body), Poll::Ready(Some(Ok(_)))));
    ensure!(!evidence.input_finished_cleanly());
    ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
    ensure!(evidence.input_finished_cleanly());

    let mut input = TestBody::new([]);
    input.wait_after_frames = true;
    let (mut body, evidence) = tracked(input);
    ensure!(poll_frame(&mut body).is_pending());
    drop(body);
    ensure!(!evidence.input_finished_cleanly());
    Ok(())
}

#[test]
fn errors_cannot_be_overwritten_by_subsequent_eof() -> anyhow::Result<()> {
    for status in [Status::cancelled("reset"), Status::internal("body error")] {
        let mut input = TestBody::new([Err(status)]);
        input.end_after_last_frame = true;
        let (mut body, evidence) = tracked(input);
        ensure!(matches!(poll_frame(&mut body), Poll::Ready(Some(Err(_)))));
        ensure!(body.is_end_stream());
        ensure!(!evidence.input_finished_cleanly());
        ensure!(matches!(poll_frame(&mut body), Poll::Ready(None)));
        ensure!(!evidence.input_finished_cleanly());
    }
    Ok(())
}

struct EmptyDecoder;

impl tonic::codec::Decoder for EmptyDecoder {
    type Item = ();
    type Error = Status;

    fn decode(
        &mut self,
        _source: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Status> {
        Ok(None)
    }
}

#[tokio::test]
async fn tonic_cancelled_request_is_not_evidence_of_clean_eof() -> anyhow::Result<()> {
    let (body, evidence) = tracked(TestBody::new([Err(Status::cancelled("reset"))]));
    let mut stream = tonic::Streaming::new_request(EmptyDecoder, body, None, None);
    ensure!(stream.message().await?.is_none());
    ensure!(!evidence.input_finished_cleanly());
    Ok(())
}

#[derive(Clone)]
struct EchoService;

impl tonic::server::NamedService for EchoService {
    const NAME: &'static str = "test.Echo";
}

impl Service<http::Request<tonic::body::Body>> for EchoService {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let mut response = http::Response::new(body);
        *response.extensions_mut() = parts.extensions;
        ready(Ok(response))
    }
}

struct AdvanceDuringResponse;

impl Service<http::Request<tonic::body::Body>> for AdvanceDuringResponse {
    type Response = http::Response<tonic::body::Body>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let response = EchoService.call(request);
        Box::pin(async move {
            advance_clock_without_timers(Duration::from_millis(11))?;
            match response.await {
                Ok(response) => Ok(response),
                Err(never) => match never {},
            }
        })
    }
}

struct ShutdownDuringResponse(watch::Sender<bool>);

impl Service<http::Request<tonic::body::Body>> for ShutdownDuringResponse {
    type Response = http::Response<tonic::body::Body>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let response = EchoService.call(request);
        let shutdown = self.0.clone();
        Box::pin(async move {
            shutdown.send_replace(true);
            exhaust_cooperative_budget()?;
            match response.await {
                Ok(response) => Ok(response),
                Err(never) => match never {},
            }
        })
    }
}

#[tokio::test]
async fn shutdown_during_a_response_poll_discards_successful_headers() -> anyhow::Result<()> {
    tokio::spawn(async move {
        let (shutdown, watch) = watch::channel(false);
        let outputs = Arc::new(Semaphore::new(1));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut input = TestBody::new([]);
        input.wait_after_frames = true;
        input.dropped = Some(dropped.clone());
        let request = http::Request::builder()
            .extension(ResponsePermit::new(outputs.clone().try_acquire_owned()?))
            .body(input)?;
        let mut service =
            ApplicationIngress::new(ShutdownDuringResponse(shutdown)).with_shutdown(watch);
        let response = service.call(request).await?;
        ensure!(!tokio::task::coop::has_budget_remaining());
        ensure!(
            response.headers().get("grpc-status") == Some(&http::HeaderValue::from_static("14"))
        );
        ensure!(response.extensions().get::<ResponsePermit>().is_none());
        ensure!(dropped.load(Ordering::Acquire));
        ensure!(outputs.available_permits() == 1);
        anyhow::Ok(())
    })
    .await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn response_generated_during_a_poll_that_crosses_the_deadline_is_discarded()
-> anyhow::Result<()> {
    let outputs = Arc::new(Semaphore::new(1));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut input = TestBody::new([]);
    input.wait_after_frames = true;
    input.dropped = Some(dropped.clone());
    let request = http::Request::builder()
        .header("grpc-timeout", "10m")
        .extension(ResponsePermit::new(outputs.clone().try_acquire_owned()?))
        .body(input)?;
    let mut service = ApplicationIngress::new(AdvanceDuringResponse);
    let response = service.call(request).await?;
    ensure!(response.headers().get("grpc-status") == Some(&http::HeaderValue::from_static("4")));
    ensure!(response.extensions().get::<ResponsePermit>().is_none());
    ensure!(dropped.load(Ordering::Acquire));
    ensure!(outputs.available_permits() == 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn absolute_rpc_deadline_survives_the_response_header_transition() -> anyhow::Result<()> {
    let outputs = Arc::new(Semaphore::new(1));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut input = TestBody::new([]);
    input.wait_after_frames = true;
    input.dropped = Some(dropped.clone());
    let request = http::Request::builder()
        .header("grpc-timeout", "100m")
        .extension(ResponsePermit::new(outputs.clone().try_acquire_owned()?))
        .body(input)?;
    let mut service = ApplicationIngress::new(EchoService);
    let response = service.call(request);
    tokio::time::sleep(Duration::from_millis(40)).await;
    let mut response = response.await?;
    ensure!(response.extensions().get::<ResponsePermit>().is_none());
    let evidence = response
        .extensions()
        .get::<RequestEvidence>()
        .context("missing request evidence after response headers")?
        .clone();
    let deadline = evidence.deadline().context("missing RPC deadline")?;
    ensure!(outputs.available_permits() == 0);
    ensure!(!dropped.load(Ordering::Acquire));

    tokio::time::sleep_until(deadline.instant + Duration::from_millis(1)).await;
    let frame = ready_frame(response.body_mut())?;
    ensure!(
        frame
            .trailers_ref()
            .and_then(|headers| headers.get("grpc-status"))
            == Some(&http::HeaderValue::from_static("4"))
    );
    ensure!(dropped.load(Ordering::Acquire));
    ensure!(!evidence.input_finished_cleanly());
    ensure!(matches!(poll_frame(response.body_mut()), Poll::Ready(None)));
    ensure!(outputs.available_permits() == 0);
    drop(response);
    ensure!(outputs.available_permits() == 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_before_response_headers_drops_the_pending_response_and_permit()
-> anyhow::Result<()> {
    let outputs = Arc::new(Semaphore::new(1));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut input = TestBody::new([]);
    input.wait_after_frames = true;
    input.dropped = Some(dropped.clone());
    let request = http::Request::builder()
        .header("grpc-timeout", "1m")
        .extension(ResponsePermit::new(outputs.clone().try_acquire_owned()?))
        .body(input)?;
    let mut service = ApplicationIngress::new(EchoService);
    let response = service.call(request);
    tokio::time::sleep(Duration::from_millis(3)).await;
    let response = response.await?;
    ensure!(response.headers().get("grpc-status") == Some(&http::HeaderValue::from_static("4")));
    ensure!(dropped.load(Ordering::Acquire));
    ensure!(outputs.available_permits() == 1);
    Ok(())
}

#[tokio::test]
async fn wrapper_preserves_uri_authority_and_uses_independent_request_evidence()
-> anyhow::Result<()> {
    let mut service = ApplicationIngress::new(EchoService);
    let request = http::Request::builder()
        .uri("https://app.example:8443/test.Echo/Call")
        .header(http::header::HOST, "different.example")
        .body(TestBody::new([]))?;
    let mut response = service.call(request).await?;
    let evidence = response
        .extensions()
        .get::<RequestEvidence>()
        .context("missing HTTP request evidence")?
        .clone();
    ensure!(evidence.authority() == Some("app.example:8443"));
    ensure!(!evidence.input_finished_cleanly());
    ensure!(matches!(poll_frame(response.body_mut()), Poll::Ready(None)));
    ensure!(evidence.input_finished_cleanly());

    let request = http::Request::builder()
        .uri("/test.Echo/Call")
        .header(http::header::HOST, "different.example")
        .extension(evidence)
        .body(TestBody::new([]))?;
    let response = service.clone().call(request).await?;
    let evidence = response
        .extensions()
        .get::<RequestEvidence>()
        .context("missing second HTTP request evidence")?;
    ensure!(evidence.authority().is_none());
    ensure!(!evidence.input_finished_cleanly());
    ensure!(<ApplicationIngress<EchoService> as tonic::server::NamedService>::NAME == "test.Echo");
    Ok(())
}
