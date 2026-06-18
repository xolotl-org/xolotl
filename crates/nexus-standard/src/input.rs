use nexus_kernel::DriverError;
use nexus_types::Value;
use std::collections::BTreeMap;

pub(crate) fn map(
    input: Value,
    method: &'static str,
) -> Result<BTreeMap<String, Value>, DriverError> {
    match input {
        Value::Null => Ok(BTreeMap::new()),
        Value::Map(m) => Ok(m),
        other => Err(DriverError::InvalidInput(format!(
            "{method} input must be a map or null, got {}",
            value_kind(&other)
        ))),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "string",
        Value::List(_) => "list",
        Value::Map(_) => "map",
        Value::Bytes(_) => "bytes",
        Value::Blob(_) => "blob",
        Value::Tensor(_) => "tensor",
        Value::Frame(_) => "frame",
        Value::StreamEnd(_) => "stream-end",
    }
}
