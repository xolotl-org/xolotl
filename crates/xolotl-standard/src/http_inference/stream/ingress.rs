//! SSE framing forwards data spans before a whole line or event exists.
//! One reader owns its response and unfinished record through backpressure.

use crate::http_inference::config::HttpInferenceDialect;
use crate::http_inference::dialects::projection;
use crate::http_inference::error::HttpInferenceError;
use crate::http_inference::json::{Document, Utf8, project::Limits};
use bytes::Bytes;
use serde_json::Value;

pub(super) enum Record {
    Json(Value),
    Done,
}

pub(super) struct Reader {
    response: reqwest::Response,
    bytes: Bytes,
    offset: usize,
    framing: Framing,
    record: Data,
    dialect: HttpInferenceDialect,
    limits: Limits,
    window: usize,
}

impl Reader {
    pub(super) fn new(
        response: reqwest::Response,
        dialect: HttpInferenceDialect,
        limits: Limits,
        window: usize,
    ) -> Self {
        Self {
            response,
            bytes: Bytes::new(),
            offset: 0,
            framing: Framing::default(),
            record: Data::new(dialect, limits),
            dialect,
            limits,
            window,
        }
    }

    pub(super) async fn next(&mut self) -> Result<Option<Record>, HttpInferenceError> {
        loop {
            if self.offset == self.bytes.len() {
                match self.response.chunk().await? {
                    Some(bytes) => {
                        self.bytes = bytes;
                        self.offset = 0;
                    }
                    None => {
                        self.framing.finish()?;
                        // SSE dispatch requires an actual blank line. An
                        // unfinished final record cannot complete a request.
                        return Ok(None);
                    }
                }
            }
            let end = self
                .offset
                .saturating_add(self.window)
                .min(self.bytes.len());
            while self.offset < end {
                let (used, event) = self.framing.next(&self.bytes[self.offset..end])?;
                self.offset += used;
                match event {
                    Some(Frame::Data(bytes)) => self.record.push(bytes)?,
                    Some(Frame::Byte(byte)) => self.record.push(&[byte])?,
                    Some(Frame::End) => {
                        let record = std::mem::replace(
                            &mut self.record,
                            Data::new(self.dialect, self.limits),
                        );
                        return record.finish().map(Some);
                    }
                    None => {}
                }
            }
            tokio::task::consume_budget().await;
        }
    }
}

enum Data {
    Json(Document),
    Chat {
        prefix: [u8; 6],
        len: usize,
        document: Option<Document>,
        limits: Limits,
    },
}

impl Data {
    fn new(dialect: HttpInferenceDialect, limits: Limits) -> Self {
        if dialect == HttpInferenceDialect::OpenAiChatCompletions {
            Self::Chat {
                prefix: [0; 6],
                len: 0,
                document: None,
                limits,
            }
        } else {
            Self::Json(Document::new(projection::stream(dialect), limits))
        }
    }

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), HttpInferenceError> {
        match self {
            Self::Json(document) => document.push(bytes),
            Self::Chat {
                prefix,
                len,
                document,
                limits,
            } => {
                if let Some(document) = document {
                    return document.push(bytes);
                }
                let count = bytes.len().min(prefix.len() - *len);
                prefix[*len..*len + count].copy_from_slice(&bytes[..count]);
                *len += count;
                bytes = &bytes[count..];
                if *len < prefix.len() {
                    return Ok(());
                }
                if prefix == b"[DONE]" {
                    if bytes.is_empty() {
                        return Ok(());
                    }
                    return Err(HttpInferenceError::Stream(
                        "data follows the provider completion marker".into(),
                    ));
                }
                let mut json = Document::new(
                    projection::stream(HttpInferenceDialect::OpenAiChatCompletions),
                    *limits,
                );
                json.push(prefix)?;
                json.push(bytes)?;
                *document = Some(json);
                Ok(())
            }
        }
    }

    fn finish(self) -> Result<Record, HttpInferenceError> {
        match self {
            Self::Json(document) => document.finish().map(Record::Json),
            Self::Chat {
                document: Some(document),
                ..
            } => document.finish().map(Record::Json),
            Self::Chat {
                prefix,
                len: 6,
                document: None,
                ..
            } if &prefix == b"[DONE]" => Ok(Record::Done),
            Self::Chat {
                prefix,
                len,
                limits,
                ..
            } => {
                let mut document = Document::new(
                    projection::stream(HttpInferenceDialect::OpenAiChatCompletions),
                    limits,
                );
                document.push(&prefix[..len])?;
                document.finish().map(Record::Json)
            }
        }
    }
}

enum Frame<'a> {
    Data(&'a [u8]),
    Byte(u8),
    End,
}

#[derive(Default)]
struct Framing {
    utf8: Utf8,
    prefix: [u8; 3],
    prefix_len: usize,
    started: bool,
    line: Line,
    previous_cr: bool,
    has_data: bool,
}

enum Line {
    Field { data: bool, bytes: usize },
    Data { first: bool },
    Ignore,
}

impl Default for Line {
    fn default() -> Self {
        Self::Field {
            data: true,
            bytes: 0,
        }
    }
}

impl Framing {
    fn next<'a>(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<(usize, Option<Frame<'a>>), HttpInferenceError> {
        let mut offset = 0;
        while offset < bytes.len() {
            let byte = bytes[offset];
            if !self.started {
                self.utf8.push(&[byte])?;
                self.prefix[self.prefix_len] = byte;
                self.prefix_len += 1;
                offset += 1;
                if self.prefix_len == self.prefix.len() {
                    self.started = true;
                    if self.prefix != [0xef, 0xbb, 0xbf] {
                        // Three prefix bytes cannot complete a data field.
                        for byte in self.prefix {
                            self.byte(byte);
                        }
                    }
                }
                continue;
            }
            if matches!(self.line, Line::Ignore | Line::Field { data: false, .. })
                && !matches!(byte, b'\r' | b'\n')
            {
                let count = bytes[offset..]
                    .iter()
                    .position(|byte| matches!(byte, b'\r' | b'\n'))
                    .unwrap_or(bytes.len() - offset);
                self.utf8.push(&bytes[offset..offset + count])?;
                self.line = Line::Ignore;
                self.previous_cr = false;
                offset += count;
                continue;
            }
            if matches!(self.line, Line::Data { first: false }) && !matches!(byte, b'\r' | b'\n') {
                let count = bytes[offset..]
                    .iter()
                    .position(|byte| matches!(byte, b'\r' | b'\n'))
                    .unwrap_or(bytes.len() - offset);
                let data = &bytes[offset..offset + count];
                self.utf8.push(data)?;
                self.previous_cr = false;
                return Ok((offset + count, Some(Frame::Data(data))));
            }
            self.utf8.push(&[byte])?;
            offset += 1;
            if let Some(event) = self.byte(byte) {
                return Ok((offset, Some(event)));
            }
        }
        Ok((offset, None))
    }

    fn byte(&mut self, byte: u8) -> Option<Frame<'static>> {
        if self.previous_cr && byte == b'\n' {
            self.previous_cr = false;
            return None;
        }
        self.previous_cr = byte == b'\r';
        if matches!(byte, b'\r' | b'\n') {
            let line = std::mem::take(&mut self.line);
            return match line {
                Line::Field { bytes: 0, .. } if self.has_data => {
                    self.has_data = false;
                    Some(Frame::End)
                }
                Line::Field {
                    data: true,
                    bytes: 4,
                } => self.begin_data(),
                _ => None,
            };
        }
        match &mut self.line {
            Line::Field { data, bytes } => {
                if byte == b':' {
                    let selected = *data && *bytes == 4;
                    self.line = if selected {
                        Line::Data { first: true }
                    } else {
                        Line::Ignore
                    };
                    if selected {
                        return self.begin_data();
                    }
                } else {
                    *data &= b"data".get(*bytes) == Some(&byte);
                    *bytes = bytes.saturating_add(1).min(5);
                }
            }
            Line::Data { first } => {
                if *first {
                    *first = false;
                    if byte == b' ' {
                        return None;
                    }
                }
                return Some(Frame::Byte(byte));
            }
            Line::Ignore => {}
        }
        None
    }

    fn begin_data(&mut self) -> Option<Frame<'static>> {
        let previous = self.has_data;
        self.has_data = true;
        previous.then_some(Frame::Data(b"\n"))
    }

    fn finish(&self) -> Result<(), HttpInferenceError> {
        self.utf8.finish()
    }
}

#[cfg(test)]
mod tests;
