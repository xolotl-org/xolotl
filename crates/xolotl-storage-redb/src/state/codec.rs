//! Each record atomically stores a length-delimited provenance prefix followed
//! by its lossless payload. Metadata reads never traverse or materialize Value.

use serde::{Deserialize, Serialize};
use xolotl_state::{
    StateError, StateEvent, StateFailure, StateHistoryEntry, StateResult, TaintedValue,
};
use xolotl_types::{Path, TaintSet, Value};

const VALUE_FORMAT: &[u8; 4] = b"XSV1";
const HISTORY_FORMAT: &[u8; 4] = b"XSH1";
const PREFIX_BYTES: usize = 12;

struct Record<'a> {
    taint: TaintSet,
    payload: &'a [u8],
}

fn record<'a>(bytes: &'a [u8], format: &[u8; 4]) -> StateResult<Record<'a>> {
    if bytes.get(..4) != Some(format.as_slice()) {
        return Err(invalid("unsupported storage record format"));
    }
    let length: [u8; 8] = bytes
        .get(4..PREFIX_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| invalid("missing provenance length"))?;
    let length = usize::try_from(u64::from_le_bytes(length))
        .map_err(|_error| invalid("provenance length exceeds this platform"))?;
    let end = PREFIX_BYTES
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| invalid("provenance extends past the record"))?;
    let taint = serde_json::from_slice(&bytes[PREFIX_BYTES..end])?;
    Ok(Record {
        taint,
        payload: &bytes[end..],
    })
}

fn encode(format: &[u8; 4], taint: &TaintSet, payload: &impl Serialize) -> StateResult<Vec<u8>> {
    let result = (|| -> StateResult<Vec<u8>> {
        let mut bytes = vec![0; PREFIX_BYTES];
        bytes[..4].copy_from_slice(format);
        serde_json::to_writer(&mut bytes, taint)?;
        let length = u64::try_from(bytes.len() - PREFIX_BYTES)
            .map_err(|_error| invalid("provenance length exceeds u64"))?;
        bytes[4..PREFIX_BYTES].copy_from_slice(&length.to_le_bytes());
        serde_json::to_writer(&mut bytes, payload)?;
        Ok(bytes)
    })();
    result.map_err(|failure| failure.with_taint(taint))
}

fn invalid(reason: &str) -> StateFailure {
    StateError::Serde(reason.into()).into()
}

pub(super) fn envelope_taint(bytes: &[u8]) -> StateResult<TaintSet> {
    Ok(record(bytes, VALUE_FORMAT)?.taint)
}

pub(super) fn history_taint(bytes: &[u8]) -> StateResult<TaintSet> {
    Ok(record(bytes, HISTORY_FORMAT)?.taint)
}

pub(super) fn encode_envelope(value: &Value, taint: &TaintSet) -> StateResult<Vec<u8>> {
    encode(
        VALUE_FORMAT,
        taint,
        &xolotl_types::tagged_value::serializable(value),
    )
}

pub(super) fn decode_envelope(bytes: &[u8]) -> StateResult<TaintedValue> {
    let Record { taint, payload } = record(bytes, VALUE_FORMAT)?;
    let result = (|| -> StateResult<Value> {
        let mut decoder = serde_json::Deserializer::from_slice(payload);
        let value = xolotl_types::tagged_value::deserialize(&mut decoder)?;
        decoder.end()?;
        Ok(value)
    })();
    let value = result.map_err(|failure| failure.with_taint(&taint))?;
    Ok(TaintedValue::new(value, taint))
}

#[derive(Serialize)]
struct HistoryRef<'a> {
    at_millis: i64,
    event: EventRef<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    at_millis: i64,
    event: Event,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EventRef<'a> {
    Set {
        path: &'a Path,
        #[serde(serialize_with = "xolotl_types::tagged_value::serialize")]
        value: &'a Value,
    },
    Append {
        path: &'a Path,
        #[serde(serialize_with = "xolotl_types::tagged_value::serialize")]
        item: &'a Value,
    },
    Delete {
        path: &'a Path,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Set {
        path: Path,
        #[serde(with = "xolotl_types::tagged_value")]
        value: Value,
    },
    Append {
        path: Path,
        #[serde(with = "xolotl_types::tagged_value")]
        item: Value,
    },
    Delete {
        path: Path,
    },
}

pub(super) fn encode_history_entry(at_millis: i64, event: &StateEvent) -> StateResult<Vec<u8>> {
    let payload = match event {
        StateEvent::Set { path, value, .. } => EventRef::Set { path, value },
        StateEvent::Append { path, item, .. } => EventRef::Append { path, item },
        StateEvent::Delete { path, .. } => EventRef::Delete { path },
    };
    encode(
        HISTORY_FORMAT,
        event.taint(),
        &HistoryRef {
            at_millis,
            event: payload,
        },
    )
}

pub(super) fn decode_history_entry(bytes: &[u8]) -> StateResult<StateHistoryEntry> {
    let Record { taint, payload } = record(bytes, HISTORY_FORMAT)?;
    let history: History = serde_json::from_slice(payload)
        .map_err(|error| StateFailure::from(error).with_taint(&taint))?;
    let event = match history.event {
        Event::Set { path, value } => StateEvent::Set { path, value, taint },
        Event::Append { path, item } => StateEvent::Append { path, item, taint },
        Event::Delete { path } => StateEvent::Delete { path, taint },
    };
    Ok(StateHistoryEntry {
        at_millis: history.at_millis,
        event,
    })
}

#[cfg(test)]
mod tests;
