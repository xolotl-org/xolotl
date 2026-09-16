use super::ValidationError;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Utf8 {
    tail: [u8; 3],
    length: u8,
}

impl Utf8 {
    pub(super) fn push(&mut self, mut bytes: &[u8]) -> Result<(), ValidationError> {
        if self.length > 0 {
            let length = usize::from(self.length);
            let mut joined = [0; 4];
            joined[..length].copy_from_slice(&self.tail[..length]);
            let mut filled = length;
            loop {
                let Some((&byte, rest)) = bytes.split_first() else {
                    self.tail[..filled].copy_from_slice(&joined[..filled]);
                    self.length = u8::try_from(filled).map_err(|_error| ValidationError::Utf8)?;
                    return Ok(());
                };
                joined[filled] = byte;
                filled += 1;
                bytes = rest;
                match core::str::from_utf8(&joined[..filled]) {
                    Ok(_) => {
                        self.length = 0;
                        break;
                    }
                    Err(error) if error.error_len().is_none() && filled < 4 => {}
                    Err(_error) => return Err(ValidationError::Utf8),
                }
            }
        }
        match core::str::from_utf8(bytes) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_none() => {
                let tail = &bytes[error.valid_up_to()..];
                if tail.len() > self.tail.len() {
                    return Err(ValidationError::Utf8);
                }
                self.tail[..tail.len()].copy_from_slice(tail);
                self.length = u8::try_from(tail.len()).map_err(|_error| ValidationError::Utf8)?;
                Ok(())
            }
            Err(_error) => Err(ValidationError::Utf8),
        }
    }

    pub(super) fn finish(&self) -> Result<(), ValidationError> {
        if self.length == 0 {
            Ok(())
        } else {
            Err(ValidationError::Utf8)
        }
    }
}
