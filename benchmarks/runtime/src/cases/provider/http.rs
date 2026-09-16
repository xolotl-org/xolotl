//! Bounded loopback fixture. It fully validates the fixed request before replying.

use anyhow::{Context, ensure};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const DELTA: &[u8] = b"data: {\"delta\":\"ok\",\"type\":\"response.output_text.delta\"}\n\n";
const SNAPSHOT_BEGIN: &[u8] = b"data: {\"response\":{\"output\":[{\"content\":[{\"text\":\"";
const SNAPSHOT_END: &[u8] = b"\"}]}],\"usage\":{\"input_tokens\":5,\"output_tokens\":7}},\"type\":\"response.completed\"}\n\n";
// These protect the finite fixture request, not the provider response or task.
const REQUEST_BYTES: usize = 16 * 1024;
const HEADER_BYTES: usize = 16 * 1024;

pub(super) async fn serve(listener: TcpListener, work: usize, window: usize) -> anyhow::Result<()> {
    let (socket, peer) = listener.accept().await?;
    ensure!(peer.ip().is_loopback());
    let mut request = BufReader::with_capacity(window, socket);
    read_request(&mut request).await?;
    ensure!(
        request.buffer().is_empty(),
        "unexpected pipelined fixture request"
    );
    let mut socket = request.into_inner();
    let length = work
        .checked_add(DELTA.len() + SNAPSHOT_BEGIN.len() + SNAPSHOT_END.len())
        .context("provider response length overflow")?;
    let headers = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n"
    );
    socket.write_all(headers.as_bytes()).await?;
    drop(headers);
    socket.write_all(DELTA).await?;
    socket.write_all(SNAPSHOT_BEGIN).await?;
    let chunk = vec![b'x'; window];
    let mut remaining = work;
    while remaining != 0 {
        let count = remaining.min(chunk.len());
        socket.write_all(&chunk[..count]).await?;
        remaining -= count;
    }
    socket.write_all(SNAPSHOT_END).await?;
    socket.shutdown().await?;
    drop((socket, chunk, listener));
    Ok(())
}

async fn line(reader: &mut BufReader<TcpStream>, line: &mut Vec<u8>) -> anyhow::Result<()> {
    line.clear();
    loop {
        let available = reader.fill_buf().await?;
        ensure!(!available.is_empty(), "fixture request ended within a line");
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        ensure!(
            line.len() + count <= HEADER_BYTES,
            "fixture request line too long"
        );
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if line.last() == Some(&b'\n') {
            ensure!(line.ends_with(b"\r\n"), "fixture request requires CRLF");
            line.truncate(line.len() - 2);
            return Ok(());
        }
    }
}

async fn read_request(reader: &mut BufReader<TcpStream>) -> anyhow::Result<()> {
    let mut current = Vec::new();
    line(reader, &mut current).await?;
    ensure!(
        current == b"POST /v1/responses HTTP/1.1",
        "unexpected provider fixture endpoint"
    );
    let mut headers = current.len();
    let mut length = None;
    let mut chunked = false;
    let mut accepts_stream = false;
    loop {
        line(reader, &mut current).await?;
        headers += current.len() + 2;
        ensure!(headers <= HEADER_BYTES, "fixture request headers too large");
        if current.is_empty() {
            break;
        }
        let (name, value) = std::str::from_utf8(&current)?
            .split_once(':')
            .context("malformed fixture request header")?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "duplicate request content-length");
            length = Some(value.parse::<usize>()?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            ensure!(
                !chunked && value.eq_ignore_ascii_case("chunked"),
                "unsupported request transfer coding"
            );
            chunked = true;
        } else if name.eq_ignore_ascii_case("accept") {
            accepts_stream = value.eq_ignore_ascii_case("text/event-stream");
        }
    }
    ensure!(
        accepts_stream && (chunked != length.is_some()),
        "fixture request framing or accept is invalid"
    );
    let mut body = Vec::new();
    if let Some(length) = length {
        read_body(reader, &mut body, length).await?;
    } else {
        loop {
            line(reader, &mut current).await?;
            let size = std::str::from_utf8(&current)?
                .split(';')
                .next()
                .context("missing request chunk size")?;
            let size = usize::from_str_radix(size, 16)?;
            if size == 0 {
                break;
            }
            read_body(reader, &mut body, size).await?;
            let mut ending = [0; 2];
            reader.read_exact(&mut ending).await?;
            ensure!(&ending == b"\r\n", "invalid fixture request chunk ending");
        }
        // Consume the entire trailer section, including its final blank line.
        loop {
            line(reader, &mut current).await?;
            headers += current.len() + 2;
            ensure!(
                headers <= HEADER_BYTES,
                "fixture request trailers too large"
            );
            if current.is_empty() {
                break;
            }
            ensure!(current.contains(&b':'), "invalid fixture request trailer");
        }
    }
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    ensure!(
        value.get("stream").and_then(serde_json::Value::as_bool) == Some(true)
            && value.get("model").and_then(serde_json::Value::as_str) == Some("bench")
            && value.get("input").and_then(serde_json::Value::as_str) == Some("prompt"),
        "provider fixture received an unexpected request"
    );
    Ok(())
}

async fn read_body(
    reader: &mut BufReader<TcpStream>,
    body: &mut Vec<u8>,
    count: usize,
) -> anyhow::Result<()> {
    let end = body
        .len()
        .checked_add(count)
        .context("fixture request length overflow")?;
    ensure!(end <= REQUEST_BYTES, "fixed fixture request body too large");
    let start = body.len();
    body.resize(end, 0);
    reader.read_exact(&mut body[start..]).await?;
    Ok(())
}
