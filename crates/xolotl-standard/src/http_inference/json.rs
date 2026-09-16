//! Incremental JSON syntax and selected provider projection.
//!
//! The decoder never collects a token or a document. Consumers decide which
//! decoded bytes to retain, and whether their result requires materialization.

mod decode;
pub(super) mod project;
mod utf8;

pub(super) use decode::{Decoder, Event, Kind};
pub(super) use utf8::Utf8;

use super::error::HttpInferenceError;

pub(super) struct Document {
    decoder: Decoder,
    projection: project::Projection,
}

impl Document {
    pub(super) fn new(rule: &'static project::Rule, limits: project::Limits) -> Self {
        Self {
            decoder: Decoder::new(limits.max_json_frames),
            projection: project::Projection::new(rule, limits),
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<(), HttpInferenceError> {
        self.decoder
            .push(bytes, |event| self.projection.event(event))
    }

    pub(super) fn finish(mut self) -> Result<serde_json::Value, HttpInferenceError> {
        self.decoder.finish(|event| self.projection.event(event))?;
        self.projection.finish()
    }
}

fn invalid(message: &'static str) -> HttpInferenceError {
    HttpInferenceError::ResponseJson(<serde_json::Error as serde::de::Error>::custom(message))
}

#[cfg(test)]
mod tests;
