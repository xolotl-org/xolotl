//! Resumable ordinary JSON encoding over immutable resident values.

use crate::http_inference::error::HttpInferenceError;
use crate::inference::{TextCursor, TextPart, TextProgress};
use bytes::Bytes;
use core::num::NonZeroUsize;
use serde::Serialize;
use xolotl_types::{StreamMarker, Value, ValueBytes, ValueList, ValueMap, ValueText, ValueView};

pub(in crate::http_inference) struct Body {
    steps: Vec<Step>,
    leaf: Option<Leaf>,
    window: NonZeroUsize,
}

pub(super) enum Step {
    Leaf(Leaf),
    Value(Value),
    String(Source),
    Text(TextCursor),
    TextParts(TextCursor),
    List {
        values: ValueList,
        index: usize,
    },
    Bytes {
        values: ValueBytes,
        index: usize,
    },
    Blob(Value),
    Shape {
        value: Value,
        index: usize,
    },
    Map {
        values: ValueMap,
        index: usize,
        overrides: bool,
        skip_usage: bool,
    },
}

impl Step {
    pub(super) fn raw(text: &'static str) -> Self {
        Self::Leaf(Leaf::new(Source::Static(text), false))
    }
    pub(super) fn string(text: String) -> Self {
        Self::String(Source::Text(text.into()))
    }
    pub(super) fn escaped(text: String) -> Self {
        Self::Leaf(Leaf::new(Source::Text(text.into()), true))
    }
    pub(super) fn text(value: Value) -> Self {
        Self::Text(TextCursor::new(value))
    }
    pub(super) fn number(value: impl Serialize) -> Result<Self, HttpInferenceError> {
        // All call sites supply one integer, f64 or finite enum discriminator.
        // Their JSON spelling fits this scalar scratch independently of input
        // payload length; bytes and tensor shapes never allocate per element.
        let mut bytes = [0; 64];
        let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut writer, &value).map_err(HttpInferenceError::RequestJson)?;
        let len = usize::try_from(writer.position()).map_err(|_overflow| invalid_source())?;
        Ok(Self::Leaf(Leaf::new(Source::Inline { bytes, len }, false)))
    }
    pub(super) fn overrides(values: ValueMap, skip_usage: bool) -> Self {
        Self::Map {
            values,
            index: 0,
            overrides: true,
            skip_usage,
        }
    }
}

impl Body {
    pub(super) fn new(mut steps: Vec<Step>, window: NonZeroUsize) -> Self {
        steps.reverse();
        Self {
            steps,
            leaf: None,
            window,
        }
    }

    pub(in crate::http_inference) fn next(&mut self) -> Result<Option<Bytes>, HttpInferenceError> {
        if self.steps.is_empty() && self.leaf.is_none() {
            return Ok(None);
        }
        // A permissive maximum is not a request to reserve that much memory
        // before any input has been projected.
        let mut output = Vec::with_capacity(self.window.get().min(16 * 1024));
        let mut work = 4096;
        while output.len() < self.window.get() && work != 0 {
            if let Some(leaf) = &mut self.leaf {
                leaf.write(&mut output, self.window.get())?;
                if !leaf.complete()? {
                    break;
                }
                self.leaf = None;
            }
            let Some(step) = self.steps.pop() else {
                break;
            };
            work -= 1;
            self.advance(step, &mut work)?;
        }
        Ok(
            (!output.is_empty() || !self.steps.is_empty() || self.leaf.is_some())
                .then(|| Bytes::from(output)),
        )
    }

    fn advance(&mut self, step: Step, work: &mut usize) -> Result<(), HttpInferenceError> {
        match step {
            Step::Leaf(leaf) => self.leaf = Some(leaf),
            Step::String(source) => self.push([
                Step::raw("\""),
                Step::Leaf(Leaf::new(source, true)),
                Step::raw("\""),
            ]),
            Step::Text(cursor) => {
                self.push([Step::raw("\""), Step::TextParts(cursor), Step::raw("\"")])
            }
            Step::TextParts(mut cursor) => match cursor.advance(work) {
                TextProgress::Part(part) => {
                    let source = match part {
                        TextPart::Space => Source::Static(" "),
                        TextPart::Value(value) => match value.as_str() {
                            Some(_) => Source::Text(value.into_text().ok_or_else(invalid_source)?),
                            None => Source::Text(format!("{value:?}").into()),
                        },
                    };
                    self.steps.push(Step::TextParts(cursor));
                    self.leaf = Some(Leaf::new(source, true));
                }
                TextProgress::Pending => self.steps.push(Step::TextParts(cursor)),
                TextProgress::Done => {}
            },
            Step::Value(value) => match value.view() {
                ValueView::Null => self.steps.push(Step::raw("null")),
                ValueView::Bool(true) => self.steps.push(Step::raw("true")),
                ValueView::Bool(false) => self.steps.push(Step::raw("false")),
                ValueView::Int(number) => self.steps.push(Step::number(number)?),
                ValueView::Float(number) => self.steps.push(Step::number(number.0)?),
                ValueView::Str(_) => self.steps.push(Step::String(Source::Text(
                    value.into_text().ok_or_else(invalid_source)?,
                ))),
                ValueView::List(values) => self.push([
                    Step::raw("["),
                    Step::List {
                        values: values.clone(),
                        index: 0,
                    },
                    Step::raw("]"),
                ]),
                ValueView::Map(values) => self.push([
                    Step::raw("{"),
                    Step::Map {
                        values: values.clone(),
                        index: 0,
                        overrides: false,
                        skip_usage: false,
                    },
                    Step::raw("}"),
                ]),
                ValueView::Bytes(_) => self.push([
                    Step::raw("["),
                    Step::Bytes {
                        values: value.into_bytes().ok_or_else(invalid_source)?,
                        index: 0,
                    },
                    Step::raw("]"),
                ]),
                ValueView::Blob(_) => self.steps.push(Step::Blob(value)),
                ValueView::Tensor(tensor) => {
                    let dtype = Step::number(tensor.dtype)?;
                    self.push([
                        Step::raw("{\"blob\":"),
                        Step::Blob(value.clone()),
                        Step::raw(",\"dtype\":"),
                        dtype,
                        Step::raw(",\"shape\":["),
                        Step::Shape { value, index: 0 },
                        Step::raw("]}"),
                    ]);
                }
                ValueView::Frame(frame) => {
                    let time = Step::number(frame.ts_nanos)?;
                    let kind = Step::number(frame.kind)?;
                    self.push([
                        Step::raw("{\"blob\":"),
                        Step::Blob(value),
                        Step::raw(",\"ts_nanos\":"),
                        time,
                        Step::raw(",\"kind\":"),
                        kind,
                        Step::raw("}"),
                    ]);
                }
                ValueView::StreamEnd(StreamMarker::Done) => {
                    self.steps.push(Step::raw("{\"__stream_marker\":\"Done\"}"))
                }
                ValueView::StreamEnd(StreamMarker::Error { .. }) => self.push([
                    Step::raw("{\"__stream_marker\":\"Error\",\"message\":"),
                    Step::String(Source::Metadata {
                        value,
                        field: Metadata::Message,
                    }),
                    Step::raw("}"),
                ]),
            },
            Step::List { values, index } => {
                if let Some(value) = values.get(index) {
                    let next = Step::Value(value.clone());
                    self.steps.push(Step::List {
                        values,
                        index: index + 1,
                    });
                    self.steps.push(next);
                    if index != 0 {
                        self.steps.push(Step::raw(","));
                    }
                }
            }
            Step::Bytes { values, index } => {
                if let Some(value) = values.get(index) {
                    let next = Step::number(*value)?;
                    self.steps.push(Step::Bytes {
                        values,
                        index: index + 1,
                    });
                    self.steps.push(next);
                    if index != 0 {
                        self.steps.push(Step::raw(","));
                    }
                }
            }
            Step::Blob(value) => {
                let blob = value.backing_blob().ok_or_else(invalid_source)?;
                let size = Step::number(blob.size)?;
                let mime = if blob.mime.is_some() {
                    Step::String(Source::Metadata {
                        value: value.clone(),
                        field: Metadata::Mime,
                    })
                } else {
                    Step::raw("null")
                };
                self.push([
                    Step::raw("{\"hash\":"),
                    Step::String(Source::Metadata {
                        value,
                        field: Metadata::Hash,
                    }),
                    Step::raw(",\"size\":"),
                    size,
                    Step::raw(",\"mime\":"),
                    mime,
                    Step::raw("}"),
                ]);
            }
            Step::Shape { value, index } => {
                let ValueView::Tensor(tensor) = value.view() else {
                    return Err(invalid_source());
                };
                if let Some(dimension) = tensor.shape.get(index) {
                    let next = Step::number(dimension)?;
                    self.steps.push(Step::Shape {
                        value,
                        index: index + 1,
                    });
                    self.steps.push(next);
                    if index != 0 {
                        self.steps.push(Step::raw(","));
                    }
                }
            }
            Step::Map {
                values,
                mut index,
                overrides,
                skip_usage,
            } => {
                while let Some((key, value)) = values.get_index(index) {
                    if skip_usage && key == "stream_options" {
                        index += 1;
                        continue;
                    }
                    let next = Step::Value(value.clone());
                    let key = Step::String(Source::MapKey {
                        values: values.clone(),
                        index,
                    });
                    self.steps.push(Step::Map {
                        values,
                        index: index + 1,
                        overrides,
                        skip_usage,
                    });
                    self.push([key, Step::raw(":"), next]);
                    if overrides || index != 0 {
                        self.steps.push(Step::raw(","));
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn push<const N: usize>(&mut self, steps: [Step; N]) {
        self.steps.extend(steps.into_iter().rev());
    }
}

pub(super) enum Source {
    Static(&'static str),
    Text(ValueText),
    Inline { bytes: [u8; 64], len: usize },
    MapKey { values: ValueMap, index: usize },
    Metadata { value: Value, field: Metadata },
}

pub(super) enum Metadata {
    Hash,
    Mime,
    Message,
}

impl Source {
    fn bytes(&self) -> Result<&[u8], HttpInferenceError> {
        match self {
            Self::Static(text) => Ok(text.as_bytes()),
            Self::Text(text) => Ok(text.as_bytes()),
            Self::Inline { bytes, len } => Ok(&bytes[..*len]),
            Self::MapKey { values, index } => values
                .get_index(*index)
                .map(|(key, _)| key.as_bytes())
                .ok_or_else(invalid_source),
            Self::Metadata { value, field } => match field {
                Metadata::Hash => value
                    .backing_blob()
                    .map(|blob| blob.hash.as_bytes())
                    .ok_or_else(invalid_source),
                Metadata::Mime => value
                    .backing_blob()
                    .and_then(|blob| blob.mime.as_ref())
                    .map(|mime| mime.as_bytes())
                    .ok_or_else(invalid_source),
                Metadata::Message => match value.view() {
                    ValueView::StreamEnd(StreamMarker::Error { message }) => Ok(message.as_bytes()),
                    _ => Err(invalid_source()),
                },
            },
        }
    }
}

pub(super) struct Leaf {
    source: Source,
    offset: usize,
    escape: bool,
    pending: [u8; 6],
    start: usize,
    end: usize,
}

impl Leaf {
    fn new(source: Source, escape: bool) -> Self {
        Self {
            source,
            offset: 0,
            escape,
            pending: [0; 6],
            start: 0,
            end: 0,
        }
    }
    fn complete(&self) -> Result<bool, HttpInferenceError> {
        Ok(self.offset == self.source.bytes()?.len() && self.start == self.end)
    }
    fn write(&mut self, output: &mut Vec<u8>, capacity: usize) -> Result<(), HttpInferenceError> {
        while output.len() < capacity {
            if self.start < self.end {
                let count = (self.end - self.start).min(capacity - output.len());
                output.extend_from_slice(&self.pending[self.start..self.start + count]);
                self.start += count;
                continue;
            }
            let bytes = &self.source.bytes()?[self.offset..];
            if bytes.is_empty() {
                break;
            }
            let offer = &bytes[..bytes.len().min(capacity - output.len())];
            let plain = if self.escape {
                offer
                    .iter()
                    .position(|byte| *byte == b'"' || *byte == b'\\' || *byte < 0x20)
                    .unwrap_or(offer.len())
            } else {
                offer.len()
            };
            if plain != 0 {
                let count = plain.min(capacity - output.len());
                output.extend_from_slice(&bytes[..count]);
                self.offset += count;
                continue;
            }
            let byte = bytes[0];
            self.offset += 1;
            self.pending[0] = b'\\';
            self.start = 0;
            self.end = 2;
            self.pending[1] = match byte {
                b'"' | b'\\' => byte,
                b'\n' => b'n',
                b'\r' => b'r',
                b'\t' => b't',
                8 => b'b',
                12 => b'f',
                _ => {
                    self.pending[1..4].copy_from_slice(b"u00");
                    self.pending[4] = b"0123456789abcdef"[usize::from(byte >> 4)];
                    self.pending[5] = b"0123456789abcdef"[usize::from(byte & 0xf)];
                    self.end = 6;
                    b'u'
                }
            };
        }
        Ok(())
    }
}

fn invalid_source() -> HttpInferenceError {
    HttpInferenceError::UnsupportedPayload("invalid request cursor source")
}
