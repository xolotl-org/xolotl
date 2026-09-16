//! Validate raw UTF-8 without retaining more than one unfinished scalar.

use super::invalid;
use crate::http_inference::error::HttpInferenceError;

#[derive(Default)]
pub(in crate::http_inference) struct Utf8 {
    pending: [u8; 4],
    len: usize,
}

impl Utf8 {
    pub(in crate::http_inference) fn push(
        &mut self,
        mut bytes: &[u8],
    ) -> Result<(), HttpInferenceError> {
        while self.len != 0 && !bytes.is_empty() {
            self.pending[self.len] = bytes[0];
            self.len += 1;
            bytes = &bytes[1..];
            match std::str::from_utf8(&self.pending[..self.len]) {
                Ok(_) => self.len = 0,
                Err(error) if error.error_len().is_some() => return Err(invalid("invalid UTF-8")),
                Err(_) => {}
            }
        }
        match std::str::from_utf8(bytes) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_some() => Err(invalid("invalid UTF-8")),
            Err(error) => {
                let tail = &bytes[error.valid_up_to()..];
                self.pending[..tail.len()].copy_from_slice(tail);
                self.len = tail.len();
                Ok(())
            }
        }
    }

    pub(in crate::http_inference) fn finish(&self) -> Result<(), HttpInferenceError> {
        if self.len == 0 {
            Ok(())
        } else {
            Err(invalid("truncated UTF-8"))
        }
    }
}
