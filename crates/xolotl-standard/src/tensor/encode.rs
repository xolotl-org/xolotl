//! Dense little-endian numeric encoding for the standard tensor writer.

use serde::Deserialize;
use xolotl_kernel::DriverError;
use xolotl_types::{DType, FloatBits, Value, ValueView};

pub(super) struct Encoding {
    pub(super) dtype: DType,
    pub(super) shape: Vec<u64>,
}

impl Encoding {
    pub(super) fn new(
        elements: usize,
        dtype: Option<&Value>,
        shape: Option<&Value>,
    ) -> Result<Self, DriverError> {
        let dtype = match dtype.map(Value::view) {
            None => DType::F32,
            Some(ValueView::Str(name)) => DType::deserialize(serde::de::value::StrDeserializer::<
                serde::de::value::Error,
            >::new(name))
            .map_err(|error| invalid(format!("unsupported tensor dtype: {error}")))?,
            Some(_) => return Err(invalid("tensor dtype must be a string")),
        };
        let shape = match shape.map(Value::view) {
            None => vec![elements as u64],
            Some(ValueView::List(dimensions)) => dimensions
                .iter()
                .map(|dimension| match dimension.view() {
                    ValueView::Int(number) if number >= 0 => Ok(number as u64),
                    _ => Err(invalid(
                        "tensor shape dimensions must be nonnegative integers",
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(invalid("tensor shape must be a list")),
        };
        // A zero dimension makes the tensor empty even if the product of other
        // dimensions would overflow. The empty shape represents one scalar.
        let shape_elements = if shape.contains(&0) {
            0
        } else {
            shape.iter().try_fold(1_u64, |count, dimension| {
                count
                    .checked_mul(*dimension)
                    .ok_or_else(|| invalid("tensor shape element count overflowed"))
            })?
        };
        if shape_elements != elements as u64 {
            return Err(invalid(format!(
                "tensor shape describes {shape_elements} elements but data has {elements}"
            )));
        }
        let encoding = Self { dtype, shape };
        shape_elements
            .checked_mul(encoding.element_bytes() as u64)
            .ok_or_else(|| invalid("tensor byte count overflowed"))?;
        Ok(encoding)
    }

    pub(super) fn element_bytes(&self) -> usize {
        match self.dtype {
            DType::F16 | DType::Bf16 | DType::I16 => 2,
            DType::F32 | DType::I32 => 4,
            DType::F64 | DType::I64 => 8,
            DType::I8 | DType::U8 | DType::Bool => 1,
        }
    }

    pub(super) fn encode<'a>(
        &self,
        data: impl IntoIterator<Item = &'a Value>,
        bytes: &mut Vec<u8>,
    ) -> Result<(), DriverError> {
        bytes.clear();
        for value in data {
            match self.dtype {
                DType::F16 => bytes
                    .extend_from_slice(&half::f16::from_f64(narrow_input(value)?).to_le_bytes()),
                DType::Bf16 => bytes
                    .extend_from_slice(&half::bf16::from_f64(narrow_input(value)?).to_le_bytes()),
                DType::F32 => bytes.extend_from_slice(&single_number(value)?.to_le_bytes()),
                DType::F64 => bytes.extend_from_slice(&number(value)?.to_le_bytes()),
                DType::I8 => {
                    bytes.extend_from_slice(&integer::<i8>(value, self.dtype)?.to_le_bytes())
                }
                DType::I16 => {
                    bytes.extend_from_slice(&integer::<i16>(value, self.dtype)?.to_le_bytes())
                }
                DType::I32 => {
                    bytes.extend_from_slice(&integer::<i32>(value, self.dtype)?.to_le_bytes())
                }
                DType::I64 => {
                    bytes.extend_from_slice(&integer::<i64>(value, self.dtype)?.to_le_bytes())
                }
                DType::U8 => bytes.push(integer::<u8>(value, self.dtype)?),
                DType::Bool => match value.view() {
                    ValueView::Bool(flag) => bytes.push(u8::from(flag)),
                    _ => return Err(invalid("boolean tensor data elements must be bools")),
                },
            }
        }
        Ok(())
    }
}

fn narrow_input(value: &Value) -> Result<f64, DriverError> {
    // half 2.7's f64 fallback drops 32 low bits without a sticky bit. Rounding
    // to odd at 21-bit precision preserves midpoint direction for f16 and bf16,
    // including the f16 hardware path's intermediate f32 conversion.
    let number = match value.view() {
        ValueView::Int(integer) => {
            // Preserve direction before converting integers beyond f64's exact
            // range. The resulting 21 significant bits fit f64 exactly.
            let magnitude = integer.unsigned_abs();
            let shift = (u64::BITS - magnitude.leading_zeros()).saturating_sub(21);
            let sticky = u64::from(magnitude & ((1_u64 << shift) - 1) != 0);
            let odd = (((magnitude >> shift) | sticky) << shift) as f64;
            if integer < 0 { -odd } else { odd }
        }
        _ => number(value)?,
    };
    let bits = number.to_bits();
    let sticky = u64::from(bits & 0xffff_ffff != 0) << 32;
    Ok(f64::from_bits((bits & !0xffff_ffff) | sticky))
}

fn single_number(value: &Value) -> Result<f32, DriverError> {
    match value.view() {
        ValueView::Int(integer) => Ok(integer as f32),
        _ => number(value).map(|number| number as f32),
    }
}

fn number(value: &Value) -> Result<f64, DriverError> {
    match value.view() {
        ValueView::Float(FloatBits(number)) => Ok(number),
        ValueView::Int(number) => Ok(number as f64),
        _ => Err(invalid("floating tensor data elements must be numeric")),
    }
}

fn integer<T: TryFrom<i64>>(value: &Value, dtype: DType) -> Result<T, DriverError> {
    let ValueView::Int(number) = value.view() else {
        return Err(invalid("integer tensor data elements must be ints"));
    };
    T::try_from(number).map_err(|_error| invalid(format!("tensor {dtype:?} element out of range")))
}

fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::InvalidInput(message.into())
}
