use super::{
    CapturedRequest, HttpInferenceAuth, HttpInferenceBackend, HttpInferenceConfig,
    HttpInferenceDialect, HttpInferenceError, header_end,
};
use crate::inference::InferenceStream;
use anyhow::{Context, bail, ensure};
use serde_json::{Value as JsonValue, json};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use xolotl_kernel::DriverContext;
use xolotl_kernel::host::stream::channel;
use xolotl_kernel::stream::StreamWindow;
use xolotl_types::{IdentityRef, ProcessId, Value};

const ERROR_PREFIX_BYTES: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const SERVER_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_POLL: Duration = Duration::from_millis(20);
const SECRET: &str = "sk-boundary-credential-abc123";
const TEXT: &str = "quoted \"text\" \\ path\n\t\u{4f60}\u{597d} \u{e9} \u{1d11e}";
// Provider-native u64 options retain their full unsigned wire range. Ordinary
// Value overrides below separately exercise the signed resident integer range.
const MAX_OUTPUT_TOKENS: u64 = u64::MAX;

const DIALECTS: &[HttpInferenceDialect] = &[
    #[cfg(feature = "openai-responses")]
    HttpInferenceDialect::OpenAiResponses,
    #[cfg(feature = "openai-chat")]
    HttpInferenceDialect::OpenAiChatCompletions,
    #[cfg(feature = "anthropic-messages")]
    HttpInferenceDialect::AnthropicMessages,
    #[cfg(feature = "gemini-generate-content")]
    HttpInferenceDialect::GeminiGenerateContent,
];

struct TestResponse {
    status: &'static str,
    chunks: Vec<Vec<u8>>,
    finish: bool,
}

impl TestResponse {
    fn json(value: JsonValue) -> anyhow::Result<Self> {
        let bytes = serde_json::to_vec(&value)?;
        let chunks = if let Some(offset) = bytes.iter().position(|byte| !byte.is_ascii()) {
            // Split inside a UTF-8 scalar to exercise transport fragment assembly.
            vec![bytes[..offset + 1].to_vec(), bytes[offset + 1..].to_vec()]
        } else {
            vec![bytes]
        };
        Ok(Self {
            status: "200 OK",
            chunks,
            finish: true,
        })
    }
}

struct HttpServer {
    base_url: String,
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<anyhow::Result<CapturedRequest>>>,
}

impl HttpServer {
    fn spawn(response: TestResponse) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").context("bind HTTP fixture")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (stop, stopped) = mpsc::channel();
        let thread = thread::spawn(move || serve(listener, response, &stopped));
        Ok(Self {
            base_url: format!("http://{address}/v1"),
            stop,
            thread: Some(thread),
        })
    }

    fn finish(mut self) -> anyhow::Result<CapturedRequest> {
        self.signal_stop();
        self.thread
            .take()
            .context("HTTP fixture thread already joined")?
            .join()
            .map_err(|_error| anyhow::anyhow!("HTTP fixture thread panicked"))?
    }

    fn signal_stop(&self) {
        let _stopped = self.stop.send(());
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.signal_stop();
        if let Some(thread) = self.thread.take() {
            // The stop signal and socket timeouts also bound assertion-failure cleanup.
            let _joined = thread.join();
        }
    }
}

fn check_running(stopped: &Receiver<()>, deadline: Instant) -> anyhow::Result<()> {
    match stopped.try_recv() {
        Ok(()) | Err(TryRecvError::Disconnected) => bail!("HTTP fixture stopped"),
        Err(TryRecvError::Empty) => {}
    }
    ensure!(Instant::now() < deadline, "HTTP fixture timed out");
    Ok(())
}

fn serve(
    listener: TcpListener,
    response: TestResponse,
    stopped: &Receiver<()>,
) -> anyhow::Result<CapturedRequest> {
    let deadline = Instant::now() + SERVER_TIMEOUT;
    let mut stream = loop {
        check_running(stopped, deadline)?;
        match listener.accept() {
            Ok((stream, _address)) => break stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                match stopped.recv_timeout(SERVER_POLL) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                        bail!("HTTP fixture stopped before connection");
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
            Err(error) => return Err(error).context("accept HTTP fixture connection"),
        }
    };
    stream.set_read_timeout(Some(SERVER_POLL))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    let request = read_request(&mut stream, stopped, deadline)?;
    match write_response(&mut stream, &response) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
            ) =>
        {
            return Ok(request);
        }
        Err(error) => return Err(error).context("write HTTP fixture response"),
    }
    if !response.finish {
        // Leave HTTP unfinished until the owner is dropped, with a finite fallback.
        match stopped.recv_timeout(SERVER_TIMEOUT) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
            Err(RecvTimeoutError::Timeout) => bail!("unfinished HTTP fixture was not stopped"),
        }
    }
    Ok(request)
}

fn write_response(stream: &mut TcpStream, response: &TestResponse) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
        response.status
    )?;
    for chunk in &response.chunks {
        if !chunk.is_empty() {
            write!(stream, "{:x}\r\n", chunk.len())?;
            stream.write_all(chunk)?;
            stream.write_all(b"\r\n")?;
            stream.flush()?;
        }
    }
    if response.finish {
        stream.write_all(b"0\r\n\r\n")?;
    }
    Ok(())
}

fn read_request(
    stream: &mut TcpStream,
    stopped: &Receiver<()>,
    deadline: Instant,
) -> anyhow::Result<CapturedRequest> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    let body = loop {
        check_running(stopped, deadline)?;
        let count = match stream.read(&mut buffer) {
            Ok(0) => bail!("HTTP fixture request ended before its body"),
            Ok(count) => count,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(error) => return Err(error).context("read HTTP fixture request"),
        };
        bytes.extend_from_slice(&buffer[..count]);
        ensure!(bytes.len() <= 64 * 1024, "HTTP fixture request too large");
        if let Some(body) = super::decode_request_body(&bytes)? {
            break body;
        }
    };
    let end = header_end(&bytes).context("HTTP fixture request headers missing")?;
    Ok(CapturedRequest {
        head: String::from_utf8(bytes[..end].to_vec())?,
        body: String::from_utf8(body)?,
    })
}

fn config(
    server: &HttpServer,
    dialect: HttpInferenceDialect,
    auth: HttpInferenceAuth,
) -> HttpInferenceConfig {
    HttpInferenceConfig::new("transport-test", dialect, &server.base_url, "model-1", auth)
}

fn successful_response(dialect: HttpInferenceDialect, text: &str) -> JsonValue {
    match dialect {
        HttpInferenceDialect::OpenAiResponses => json!({"output_text": text}),
        HttpInferenceDialect::OpenAiChatCompletions => {
            json!({"choices": [{"message": {"content": text}}]})
        }
        HttpInferenceDialect::AnthropicMessages => {
            json!({"content": [{"type": "text", "text": text}]})
        }
        HttpInferenceDialect::GeminiGenerateContent => {
            json!({"candidates": [{"content": {"parts": [{"text": text}]}}]})
        }
    }
}

fn expected_request(dialect: HttpInferenceDialect, json_mode: bool, text: &str) -> JsonValue {
    let mut expected = match dialect {
        HttpInferenceDialect::OpenAiResponses => json!({
            "model": "model-1", "input": text, "store": false,
            "max_output_tokens": MAX_OUTPUT_TOKENS, "temperature": 0.125,
        }),
        HttpInferenceDialect::OpenAiChatCompletions | HttpInferenceDialect::AnthropicMessages => {
            json!({
                "model": "model-1", "messages": [{"role": "user", "content": text}],
                "max_tokens": MAX_OUTPUT_TOKENS, "temperature": 0.125,
            })
        }
        HttpInferenceDialect::GeminiGenerateContent => json!({
            "contents": [{"parts": [{"text": text}]}],
            "generationConfig": {"maxOutputTokens": MAX_OUTPUT_TOKENS, "temperature": 0.125},
        }),
    };
    if json_mode {
        match dialect {
            HttpInferenceDialect::OpenAiResponses => {
                expected["text"] = json!({"format": {"type": "json_object"}});
            }
            HttpInferenceDialect::OpenAiChatCompletions => {
                expected["response_format"] = json!({"type": "json_object"});
            }
            HttpInferenceDialect::AnthropicMessages => {}
            HttpInferenceDialect::GeminiGenerateContent => {
                expected["generationConfig"]["responseMimeType"] = json!("application/json");
            }
        }
    }
    expected["metadata"] = override_metadata();
    expected
}

fn override_metadata() -> JsonValue {
    json!({"values": [null, true, 12.25, i64::MIN, i64::MAX, {"label": TEXT}]})
}

#[tokio::test]
async fn unary_dialects_preserve_nested_text_options_and_json_values() -> anyhow::Result<()> {
    for &dialect in DIALECTS {
        for json_mode in [false, true] {
            let server =
                HttpServer::spawn(TestResponse::json(successful_response(dialect, TEXT))?)?;
            let mut config = config(
                &server,
                dialect,
                HttpInferenceAuth::BearerToken(SECRET.into()),
            );
            config.options.max_output_tokens = Some(MAX_OUTPUT_TOKENS);
            config.options.temperature = Some(0.125);
            config.options.json_mode = json_mode;
            config.options.api_version = Some("2023-06-01".into());
            config
                .options
                .default_headers
                .insert("x-request-label".into(), "transport-fixture".into());
            config.options.request_overrides.insert(
                "metadata".into(),
                serde_json::from_value(override_metadata())?,
            )?;
            let backend = HttpInferenceBackend::new(config)?;
            let input = Value::map(BTreeMap::from([
                ("json".into(), Value::boolean(true)),
                (
                    "text".into(),
                    Value::list(vec![
                        Value::string(TEXT.into()),
                        Value::map(BTreeMap::from([(
                            "prompt".into(),
                            Value::list(vec![
                                Value::string("nested".into()),
                                Value::string("tail".into()),
                            ]),
                        )])),
                    ]),
                ),
            ]));
            let text = tokio::time::timeout(REQUEST_TIMEOUT, backend.infer_inner(&input))
                .await
                .context("unary response timed out")??;
            ensure!(text == TEXT, "{dialect:?}: valid UTF-8 response changed");
            let request = server.finish()?;
            let actual: JsonValue = serde_json::from_str(&request.body)?;
            let expected = expected_request(dialect, json_mode, &format!("{TEXT} nested tail"));
            ensure!(
                actual == expected,
                "{dialect:?}: request JSON semantics changed"
            );
            let expected_path = match dialect {
                HttpInferenceDialect::OpenAiResponses => "/v1/responses",
                HttpInferenceDialect::OpenAiChatCompletions => "/v1/chat/completions",
                HttpInferenceDialect::AnthropicMessages => "/v1/messages",
                HttpInferenceDialect::GeminiGenerateContent => "/v1/models/model-1:generateContent",
            };
            ensure!(request.head.starts_with(&format!("POST {expected_path} ")));
            let head = request.head.to_ascii_lowercase();
            ensure!(head.contains("content-type: application/json\r\n"));
            ensure!(head.contains("x-request-label: transport-fixture\r\n"));
            if dialect == HttpInferenceDialect::AnthropicMessages {
                ensure!(head.contains("anthropic-version: 2023-06-01\r\n"));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn successful_json_rejects_invalid_utf8_instead_of_replacing_it() -> anyhow::Result<()> {
    for &dialect in DIALECTS {
        let mut body = serde_json::to_vec(&successful_response(dialect, "invalid-utf8-marker"))?;
        let offset = body
            .windows(b"invalid-utf8-marker".len())
            .position(|bytes| bytes == b"invalid-utf8-marker")
            .context("response marker missing")?;
        body[offset] = 0xff;
        let server = HttpServer::spawn(TestResponse {
            status: "200 OK",
            chunks: vec![body],
            finish: true,
        })?;
        let backend = HttpInferenceBackend::new(config(&server, dialect, HttpInferenceAuth::None))?;
        let result = tokio::time::timeout(
            REQUEST_TIMEOUT,
            backend.infer_inner(&Value::string("prompt".into())),
        )
        .await
        .context("invalid UTF-8 response timed out")?;
        ensure!(
            matches!(result, Err(HttpInferenceError::ResponseJson(_))),
            "{dialect:?}: invalid UTF-8 response was not rejected as JSON"
        );
        server.finish()?;
    }
    Ok(())
}

async fn provider_error(
    server: &HttpServer,
    dialect: HttpInferenceDialect,
    auth: HttpInferenceAuth,
    streaming: bool,
) -> anyhow::Result<HttpInferenceError> {
    let backend = HttpInferenceBackend::new(config(server, dialect, auth))?;
    let (sink, _receiver) = channel(StreamWindow::default());
    let context = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_stream_sink(sink);
    let output = InferenceStream::new(&context);
    let input = Value::string("prompt".into());
    let request = async {
        if streaming {
            backend.stream_text(&input, &output).await.map(|_output| ())
        } else {
            backend.infer_inner(&input).await.map(|_output| ())
        }
    };
    tokio::time::timeout(REQUEST_TIMEOUT, request)
        .await
        .with_context(|| {
            format!("{dialect:?}, streaming={streaming}: error response waited for EOF")
        })?
        .err()
        .context("provider error response unexpectedly succeeded")
}

fn diagnostic(error: &HttpInferenceError) -> anyhow::Result<&str> {
    let HttpInferenceError::ProviderHttpStatus { status, body } = error else {
        bail!("provider status was replaced by another error: {error}");
    };
    ensure!(*status == 429, "provider HTTP status changed");
    ensure!(
        body.len() <= ERROR_PREFIX_BYTES,
        "diagnostic body is unbounded"
    );
    Ok(body)
}

fn auth(secret: &str, api_key: bool) -> HttpInferenceAuth {
    if api_key {
        HttpInferenceAuth::ApiKeyHeader {
            header: "x-api-key".into(),
            value: secret.into(),
        }
    } else {
        HttpInferenceAuth::BearerToken(secret.into())
    }
}

#[tokio::test]
async fn error_responses_stop_at_a_bounded_prefix_without_waiting_for_eof() -> anyhow::Result<()> {
    for &dialect in DIALECTS {
        for streaming in [false, true] {
            for finish in [false, true] {
                let mut body = b"bounded diagnostic: ".to_vec();
                body.resize(ERROR_PREFIX_BYTES, b'.');
                if finish {
                    body.extend_from_slice(b"this-tail-must-not-appear");
                    body.resize(2 * ERROR_PREFIX_BYTES, b'!');
                }
                let server = HttpServer::spawn(TestResponse {
                    status: "429 Too Many Requests",
                    chunks: vec![body],
                    finish,
                })?;
                let error =
                    provider_error(&server, dialect, HttpInferenceAuth::None, streaming).await?;
                let body = diagnostic(&error)?;
                ensure!(body.starts_with("bounded diagnostic: "));
                ensure!(!body.contains("this-tail-must-not-appear"));
                server.finish()?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn error_diagnostics_redact_secrets_across_http_chunks_and_display_truncation()
-> anyhow::Result<()> {
    for &dialect in DIALECTS {
        for streaming in [false, true] {
            for api_key in [false, true] {
                let mut body = format!("credential={SECRET};").into_bytes();
                body.resize(500, b'.');
                body.extend_from_slice(SECRET.as_bytes());
                body.resize(ERROR_PREFIX_BYTES, b'.');
                let split = "credential=".len() + SECRET.len() / 2;
                let server = HttpServer::spawn(TestResponse {
                    status: "429 Too Many Requests",
                    chunks: vec![body[..split].to_vec(), body[split..].to_vec()],
                    finish: false,
                })?;
                let error =
                    provider_error(&server, dialect, auth(SECRET, api_key), streaming).await?;
                let body = diagnostic(&error)?;
                ensure!(
                    body.contains("<redacted>"),
                    "credential redaction marker missing"
                );
                ensure!(!body.contains("sk-boundary"), "credential prefix leaked");
                server.finish()?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn error_diagnostics_redact_credentials_cut_by_the_read_limit() -> anyhow::Result<()> {
    let secret = format!("sk-truncated-{}", "q".repeat(ERROR_PREFIX_BYTES + 128));
    for &dialect in DIALECTS {
        for streaming in [false, true] {
            for api_key in [false, true] {
                let body = format!("credential={secret}").into_bytes();
                let server = HttpServer::spawn(TestResponse {
                    status: "429 Too Many Requests",
                    chunks: vec![body],
                    finish: false,
                })?;
                let error =
                    provider_error(&server, dialect, auth(&secret, api_key), streaming).await?;
                let body = diagnostic(&error)?;
                ensure!(body.starts_with("credential="), "diagnostic prefix changed");
                ensure!(
                    body.contains("<redacted>"),
                    "truncated credential redaction marker missing"
                );
                ensure!(
                    !body.contains("sk-truncated-"),
                    "truncated credential prefix leaked"
                );
                ensure!(
                    !body.contains("qqqqqqqq"),
                    "truncated credential body leaked"
                );
                server.finish()?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn error_diagnostics_prefer_complete_credentials_to_overlapping_partial_suffixes()
-> anyhow::Result<()> {
    let &dialect = DIALECTS.first().context("no HTTP dialect enabled")?;
    let secret = format!("sk-{}sk-", "x".repeat(ERROR_PREFIX_BYTES - 6));
    for streaming in [false, true] {
        for api_key in [false, true] {
            let server = HttpServer::spawn(TestResponse {
                status: "429 Too Many Requests",
                chunks: vec![secret.as_bytes().to_vec()],
                finish: false,
            })?;
            let error = provider_error(&server, dialect, auth(&secret, api_key), streaming).await?;
            ensure!(
                diagnostic(&error)? == "<redacted>",
                "complete credential at the read limit was only partially redacted"
            );
            server.finish()?;
        }
    }
    Ok(())
}
