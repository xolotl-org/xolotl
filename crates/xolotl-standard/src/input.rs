use xolotl_kernel::DriverError;
use xolotl_types::{Value, ValueMap, ValueView};

#[cfg(feature = "standard-core")]
mod inspect;
#[cfg(feature = "standard-core")]
pub(crate) use inspect::inspection_values;

pub(crate) fn map(input: Value, method: &'static str) -> Result<ValueMap, DriverError> {
    if input.is_null() {
        return Ok(ValueMap::new());
    }
    let kind = value_kind(&input);
    input.into_map().ok_or_else(|| {
        DriverError::InvalidInput(format!(
            "{method} input must be a map or null, got {}",
            kind
        ))
    })
}

fn value_kind(value: &Value) -> &'static str {
    match value.view() {
        ValueView::Null => "null",
        ValueView::Bool(_) => "bool",
        ValueView::Int(_) => "int",
        ValueView::Float(_) => "float",
        ValueView::Str(_) => "string",
        ValueView::List(_) => "list",
        ValueView::Map(_) => "map",
        ValueView::Bytes(_) => "bytes",
        ValueView::Blob(_) => "blob",
        ValueView::Tensor(_) => "tensor",
        ValueView::Frame(_) => "frame",
        ValueView::StreamEnd(_) => "stream-end",
    }
}
