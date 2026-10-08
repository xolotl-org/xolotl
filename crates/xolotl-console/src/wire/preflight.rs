//! Allocation-free accounting of client input Values before Prost decoding.

use super::{FrameDecodeError, MAX_FRAME_VALUE_NODES};

const MAX_VALUE_DEPTH: usize = xolotl_proto::MAX_VALUE_ENCODE_DEPTH;

/// Count every Value that Prost may decode, including fields later replaced by
/// a repeated oneof or singular input. The encoded frame byte ceiling bounds
/// inline field payloads; this scan bounds small-message allocation fanout.
pub(super) fn scan_client_frame(bytes: &[u8]) -> Result<(), FrameDecodeError> {
    let mut budget = ValueBudget {
        remaining: MAX_FRAME_VALUE_NODES,
    };
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        match field.number {
            3 => scan_invocation(field.message()?, 4, &mut budget)?,
            4 => scan_invocation(field.message()?, 3, &mut budget)?,
            // Do not let a server-only frame allocate its reply or event tree
            // before the directional check in the public decoder.
            11..=16 => return Err(FrameDecodeError::ServerOnly),
            _ => {}
        }
    }
    Ok(())
}

fn scan_invocation(
    bytes: &[u8],
    input_field: u64,
    budget: &mut ValueBudget,
) -> Result<(), FrameDecodeError> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        if field.number == input_field {
            scan_value(field.message()?, 1, false, budget)?;
        }
    }
    Ok(())
}

fn scan_value(
    bytes: &[u8],
    depth: usize,
    root_charged: bool,
    budget: &mut ValueBudget,
) -> Result<(), FrameDecodeError> {
    if depth > MAX_VALUE_DEPTH {
        return Err(FrameDecodeError::ValueDepth {
            limit: MAX_VALUE_DEPTH,
        });
    }
    if !root_charged {
        budget.node()?;
    }
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        match field.number {
            7 => scan_list(field.message()?, depth, budget)?,
            8 => scan_map(field.message()?, depth, budget)?,
            _ => {}
        }
    }
    Ok(())
}

fn scan_list(
    bytes: &[u8],
    parent_depth: usize,
    budget: &mut ValueBudget,
) -> Result<(), FrameDecodeError> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        if field.number == 1 {
            scan_value(field.message()?, parent_depth + 1, false, budget)?;
        }
    }
    Ok(())
}

fn scan_map(
    bytes: &[u8],
    parent_depth: usize,
    budget: &mut ValueBudget,
) -> Result<(), FrameDecodeError> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        if field.number == 1 {
            scan_map_entry(field.message()?, parent_depth + 1, budget)?;
        }
    }
    Ok(())
}

fn scan_map_entry(
    bytes: &[u8],
    depth: usize,
    budget: &mut ValueBudget,
) -> Result<(), FrameDecodeError> {
    // Prost inserts a default Value even when the entry omits its value field.
    // The first explicit value consumes that charge; repeated value fields are
    // each decoded and therefore receive their own charge.
    if depth > MAX_VALUE_DEPTH {
        return Err(FrameDecodeError::ValueDepth {
            limit: MAX_VALUE_DEPTH,
        });
    }
    budget.node()?;
    let mut first_value = true;
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        if field.number == 2 {
            scan_value(field.message()?, depth, first_value, budget)?;
            first_value = false;
        }
    }
    Ok(())
}

struct ValueBudget {
    remaining: usize,
}

impl ValueBudget {
    fn node(&mut self) -> Result<(), FrameDecodeError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(FrameDecodeError::ValueNodes {
                limit: MAX_FRAME_VALUE_NODES,
            })?;
        Ok(())
    }
}

struct Field<'a> {
    number: u64,
    wire: u8,
    payload: &'a [u8],
}

impl<'a> Field<'a> {
    fn message(self) -> Result<&'a [u8], FrameDecodeError> {
        if self.wire == 2 {
            Ok(self.payload)
        } else {
            Err(FrameDecodeError::MalformedWire)
        }
    }
}

struct Fields<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next(&mut self) -> Result<Option<Field<'a>>, FrameDecodeError> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let key = read_varint(self.bytes, &mut self.offset)?;
        let number = key >> 3;
        if number == 0 {
            return Err(FrameDecodeError::MalformedWire);
        }
        let wire = (key & 7) as u8;
        let payload = match wire {
            0 => {
                read_varint(self.bytes, &mut self.offset)?;
                &self.bytes[0..0]
            }
            1 => take(self.bytes, &mut self.offset, 8)?,
            2 => {
                let length = usize::try_from(read_varint(self.bytes, &mut self.offset)?)
                    .map_err(|_error| FrameDecodeError::MalformedWire)?;
                take(self.bytes, &mut self.offset, length)?
            }
            5 => take(self.bytes, &mut self.offset, 4)?,
            // Groups are obsolete and not used by this protocol. Rejecting
            // them avoids silently skipping nested Values inside a group.
            _ => return Err(FrameDecodeError::MalformedWire),
        };
        Ok(Some(Field {
            number,
            wire,
            payload,
        }))
    }
}

fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], FrameDecodeError> {
    let end = offset
        .checked_add(length)
        .ok_or(FrameDecodeError::MalformedWire)?;
    let payload = bytes
        .get(*offset..end)
        .ok_or(FrameDecodeError::MalformedWire)?;
    *offset = end;
    Ok(payload)
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, FrameDecodeError> {
    let mut result = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *bytes.get(*offset).ok_or(FrameDecodeError::MalformedWire)?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err(FrameDecodeError::MalformedWire);
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(FrameDecodeError::MalformedWire)
}
