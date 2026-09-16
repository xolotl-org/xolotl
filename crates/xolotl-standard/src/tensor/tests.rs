use super::{TensorDriver, encode::Encoding};
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use std::future::{Ready, ready};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput};
use xolotl_state::object::{
    ObjectMetadata, ObjectWrite, ObjectWriteChunk, UploadId, UploadOptions,
};
use xolotl_state::{StateError, StateResult, host::object::ObjectStore};
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{
    DType, FloatBits, IdentityRef, MethodId, Outcome, OutputMode, ProcessId, TaintSet, TaintSource,
    TensorRef, Value,
};

fn context() -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
        .with_taint(TaintSet::of(TaintSource::ModelOutput))
}

fn failure_message(result: std::result::Result<DriverOutput, DriverError>) -> Result<String> {
    match result {
        Err(error) => Ok(error.to_string()),
        Ok(DriverOutput {
            outcome: Outcome::Fail(failure),
            ..
        }) => Ok(failure.to_string()),
        Ok(_) => bail!("invalid tensor input was accepted"),
    }
}

fn floats(numbers: &[f64]) -> Vec<Value> {
    numbers
        .iter()
        .map(|number| Value::float(FloatBits(*number)))
        .collect()
}

fn ints(numbers: &[i64]) -> Vec<Value> {
    numbers.iter().copied().map(Value::integer).collect()
}

fn input(data: Vec<Value>, dtype: &str, shape: Option<&[i64]>) -> Value {
    let mut fields = BTreeMap::from([
        ("data".into(), Value::list(data)),
        ("dtype".into(), Value::string(dtype.into())),
    ]);
    if let Some(shape) = shape {
        fields.insert("shape".into(), Value::list(ints(shape)));
    }
    Value::map(fields)
}

struct Fixture {
    directory: tempfile::TempDir,
    files: Arc<FileObjectStore>,
    reader: ObjectStore,
    driver: TensorDriver,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let files = Arc::new(FileObjectStore::open(directory.path())?);
        let writer = ObjectStore::new().with_write(files.clone());
        ensure!(writer.can_write() && !writer.can_read() && !writer.can_delete());
        Ok(Self {
            directory,
            reader: ObjectStore::new().with_read(files.clone()),
            driver: TensorDriver::new(writer),
            files,
        })
    }

    async fn write(&self, value: Value) -> Result<TensorRef> {
        let output = self
            .driver
            .call(MethodId::new(0), value, OutputMode::Unary, &context())
            .await?;
        ensure!(output.taint == context().taint);
        let Outcome::Done(tensor_value) = output.outcome else {
            bail!("expected committed tensor reference");
        };
        let xolotl_types::ValueView::Tensor(tensor) = tensor_value.view() else {
            bail!("expected tensor");
        };
        Ok(tensor.clone())
    }

    async fn check_bytes(&self, tensor: &TensorRef, expected: &[u8]) -> Result<()> {
        ensure!(tensor.blob.hash == blake3::hash(expected).to_hex().as_str());
        ensure!(tensor.blob.size == expected.len() as u64);
        ensure!(tensor.blob.mime.as_deref() == Some("application/x-xolotl-tensor"));
        let metadata = self
            .reader
            .metadata(&tensor.blob)
            .await?
            .context("missing committed object")?;
        ensure!(metadata.blob == tensor.blob);
        ensure!(metadata.taint == context().taint);
        let mut buffer = [0_u8; 17];
        let mut offset = 0;
        loop {
            let read = self
                .reader
                .read_chunk(&tensor.blob, offset as u64, &mut buffer)
                .await?;
            ensure!(read.taint == context().taint);
            ensure!(read.bytes_read <= buffer.len());
            ensure!(read.bytes_read > 0 || read.end);
            let end = offset + read.bytes_read;
            ensure!(end <= expected.len());
            ensure!(buffer[..read.bytes_read] == expected[offset..end]);
            offset = end;
            if read.end {
                break;
            }
        }
        ensure!(offset == expected.len());
        self.check_no_staging()
    }

    fn check_no_staging(&self) -> Result<()> {
        ensure!(self.files.pending_uploads() == 0);
        ensure!(
            std::fs::read_dir(self.directory.path().join("staging"))?
                .next()
                .is_none()
        );
        Ok(())
    }
}

#[tokio::test]
async fn every_dtype_writes_expected_little_endian_bytes_without_state_or_read_access() -> Result<()>
{
    let fixture = Fixture::new()?;
    let cases = [
        (
            "f16",
            DType::F16,
            floats(&[1.0, -2.0, 0.5]),
            vec![0x00, 0x3c, 0x00, 0xc0, 0x00, 0x38],
        ),
        (
            "bf16",
            DType::Bf16,
            floats(&[1.0, -2.0, 0.5]),
            vec![0x80, 0x3f, 0x00, 0xc0, 0x00, 0x3f],
        ),
        (
            "f32",
            DType::F32,
            floats(&[1.0, -2.0, 0.5]),
            vec![
                0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x3f,
            ],
        ),
        (
            "f64",
            DType::F64,
            floats(&[1.0, -2.0, 0.5]),
            vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x3f,
            ],
        ),
        (
            "i8",
            DType::I8,
            ints(&[-128, 0, 127]),
            vec![0x80, 0x00, 0x7f],
        ),
        (
            "i16",
            DType::I16,
            ints(&[-32768, 0, 32767]),
            vec![0x00, 0x80, 0x00, 0x00, 0xff, 0x7f],
        ),
        (
            "i32",
            DType::I32,
            ints(&[-2147483648, 0, 2147483647]),
            vec![
                0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f,
            ],
        ),
        (
            "i64",
            DType::I64,
            ints(&[i64::MIN, 0, i64::MAX]),
            vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ],
        ),
        ("u8", DType::U8, ints(&[0, 1, 255]), vec![0x00, 0x01, 0xff]),
        (
            "bool",
            DType::Bool,
            vec![
                Value::boolean(false),
                Value::boolean(true),
                Value::boolean(false),
            ],
            vec![0x00, 0x01, 0x00],
        ),
    ];
    for (name, dtype, data, expected) in cases {
        let tensor = fixture
            .write(input(data, name, None))
            .await
            .with_context(|| format!("write {name}"))?;
        ensure!(tensor.dtype == dtype && tensor.shape == [3]);
        fixture
            .check_bytes(&tensor, &expected)
            .await
            .with_context(|| format!("read {name}"))?;
    }
    Ok(())
}

#[tokio::test]
async fn default_dtype_and_integer_inputs_to_float_codecs_keep_numeric_meaning() -> Result<()> {
    let fixture = Fixture::new()?;
    let default = fixture
        .write(Value::map(BTreeMap::from([(
            "data".into(),
            Value::list(ints(&[1, -2])),
        )])))
        .await?;
    ensure!(default.dtype == DType::F32 && default.shape == [2]);
    fixture
        .check_bytes(&default, &[0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0xc0])
        .await?;
    for (dtype, expected) in [
        ("f16", vec![0x00, 0x3c, 0x00, 0xc0]),
        ("bf16", vec![0x80, 0x3f, 0x00, 0xc0]),
        (
            "f64",
            vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xc0,
            ],
        ),
    ] {
        let tensor = fixture.write(input(ints(&[1, -2]), dtype, None)).await?;
        fixture.check_bytes(&tensor, &expected).await?;
    }
    Ok(())
}

fn check_integer_float_encoding(
    encoding: &Encoding,
    bytes: &mut Vec<u8>,
    number: i64,
    expected_bits: u64,
) -> Result<()> {
    encoding.encode(&[Value::integer(number)], bytes)?;
    let expected = expected_bits.to_le_bytes();
    ensure!(
        bytes.as_slice() == &expected[..encoding.element_bytes()],
        "{:?} integer {number}: expected bits {expected_bits:016x}, got bytes {bytes:02x?}",
        encoding.dtype
    );
    Ok(())
}

#[test]
fn integer_float_conversion_preserves_direction_at_midpoint_neighbors() -> Result<()> {
    let mut bytes = Vec::with_capacity(8);
    for (name, midpoint, lower_bits, tie_bits, upper_bits, sign_bit) in [
        (
            "bf16",
            9_042_383_626_829_824_i64,
            0x5a00_u64,
            0x5a00_u64,
            0x5a01_u64,
            0x8000_u64,
        ),
        (
            "bf16",
            9_112_752_371_007_488,
            0x5a01,
            0x5a02,
            0x5a02,
            0x8000,
        ),
        (
            "f32",
            9_007_199_791_611_904,
            0x5a00_0000,
            0x5a00_0000,
            0x5a00_0001,
            0x8000_0000,
        ),
        (
            "f32",
            9_007_200_865_353_728,
            0x5a00_0001,
            0x5a00_0002,
            0x5a00_0002,
            0x8000_0000,
        ),
    ] {
        let dtype = Value::string(name.into());
        let encoding = Encoding::new(1, Some(&dtype), None)?;
        for (number, expected) in [
            (midpoint - 1, lower_bits),
            (midpoint, tie_bits),
            (midpoint + 1, upper_bits),
        ] {
            check_integer_float_encoding(&encoding, &mut bytes, number, expected)?;
            check_integer_float_encoding(&encoding, &mut bytes, -number, expected | sign_bit)?;
        }
    }
    Ok(())
}

#[test]
fn integer_float_conversion_handles_i64_limits_and_zero() -> Result<()> {
    let mut bytes = Vec::with_capacity(8);
    for (name, positive_bits, negative_bits) in [
        ("f16", 0x7c00_u64, 0xfc00_u64),
        ("bf16", 0x5f00, 0xdf00),
        ("f32", 0x5f00_0000, 0xdf00_0000),
        ("f64", 0x43e0_0000_0000_0000, 0xc3e0_0000_0000_0000),
    ] {
        let dtype = Value::string(name.into());
        let encoding = Encoding::new(1, Some(&dtype), None)?;
        for (number, expected) in [
            (i64::MIN, negative_bits),
            (i64::MAX, positive_bits),
            (-i64::MAX, negative_bits),
            (0, 0),
        ] {
            check_integer_float_encoding(&encoding, &mut bytes, number, expected)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn floating_codecs_preserve_infinities_signed_zero_and_nan() -> Result<()> {
    let fixture = Fixture::new()?;
    for (dtype, width, exponent_mask, fraction_mask, prefix) in [
        (
            "f16",
            2,
            0x7c00_u64,
            0x03ff_u64,
            vec![0x00, 0x7c, 0x00, 0xfc, 0x00, 0x80],
        ),
        (
            "bf16",
            2,
            0x7f80,
            0x007f,
            vec![0x80, 0x7f, 0x80, 0xff, 0x00, 0x80],
        ),
        (
            "f32",
            4,
            0x7f80_0000,
            0x007f_ffff,
            vec![
                0x00, 0x00, 0x80, 0x7f, 0x00, 0x00, 0x80, 0xff, 0x00, 0x00, 0x00, 0x80,
            ],
        ),
        (
            "f64",
            8,
            0x7ff0_0000_0000_0000,
            0x000f_ffff_ffff_ffff,
            vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
            ],
        ),
    ] {
        let tensor = fixture
            .write(input(
                floats(&[f64::INFINITY, f64::NEG_INFINITY, -0.0, f64::NAN]),
                dtype,
                None,
            ))
            .await?;
        let mut bytes = vec![0_u8; 4 * width];
        let read = fixture
            .reader
            .read_chunk(&tensor.blob, 0, &mut bytes)
            .await?;
        ensure!(read.end && read.bytes_read == bytes.len());
        ensure!(bytes[..prefix.len()] == prefix);
        let mut nan_bytes = [0_u8; 8];
        nan_bytes[..width].copy_from_slice(&bytes[prefix.len()..]);
        let nan_bits = u64::from_le_bytes(nan_bytes);
        ensure!(nan_bits & exponent_mask == exponent_mask);
        ensure!(
            nan_bits & fraction_mask != 0,
            "{dtype} converted NaN to infinity"
        );
        fixture.check_bytes(&tensor, &bytes).await?;
    }
    Ok(())
}

#[tokio::test]
async fn f32_rounds_midpoints_and_adjacent_f64_values() -> Result<()> {
    let fixture = Fixture::new()?;
    let midpoint = 1.000_000_059_604_644_8_f64;
    let tensor = fixture
        .write(input(
            floats(&[midpoint, midpoint.next_up(), -midpoint, -midpoint.next_up()]),
            "f32",
            None,
        ))
        .await?;
    fixture
        .check_bytes(
            &tensor,
            &[
                0x00, 0x00, 0x80, 0x3f, 0x01, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x80, 0xbf, 0x01, 0x00,
                0x80, 0xbf,
            ],
        )
        .await
}

type NarrowDecoder = fn(u16) -> f64;

const NARROW_FORMATS: [(&str, u16, NarrowDecoder); 2] = [
    ("f16", 0x7bff, |bits| half::f16::from_bits(bits).to_f64()),
    ("bf16", 0x7f7f, |bits| half::bf16::from_bits(bits).to_f64()),
];

fn check_narrow_encoding(
    encoding: &Encoding,
    bytes: &mut Vec<u8>,
    number: f64,
    expected: u16,
) -> Result<()> {
    encoding.encode(&[Value::float(FloatBits(number))], bytes)?;
    ensure!(
        bytes.len() == 2,
        "narrow scalar encoded {} bytes",
        bytes.len()
    );
    let actual = u16::from_le_bytes([bytes[0], bytes[1]]);
    ensure!(
        actual == expected,
        "{:?} input {number:?} (f64 bits {:016x}): expected {expected:04x}, got {actual:04x}",
        encoding.dtype,
        number.to_bits()
    );
    Ok(())
}

#[test]
fn narrow_floats_round_every_finite_adjacent_midpoint_and_neighbor() -> Result<()> {
    let mut bytes = Vec::with_capacity(2);
    for (name, maximum_bits, decode) in NARROW_FORMATS {
        let dtype = Value::string(name.into());
        let encoding = Encoding::new(1, Some(&dtype), None)?;
        for lower_bits in 0..maximum_bits {
            let upper_bits = lower_bits + 1;
            let midpoint = (decode(lower_bits) + decode(upper_bits)) * 0.5;
            let tie_bits = if lower_bits & 1 == 0 {
                lower_bits
            } else {
                upper_bits
            };
            for (number, expected) in [
                (midpoint.next_down(), lower_bits),
                (midpoint, tie_bits),
                (midpoint.next_up(), upper_bits),
            ] {
                check_narrow_encoding(&encoding, &mut bytes, number, expected)?;
                check_narrow_encoding(&encoding, &mut bytes, -number, expected | 0x8000)?;
            }
        }
    }
    Ok(())
}

#[test]
fn narrow_floats_handle_subnormal_and_overflow_thresholds() -> Result<()> {
    let mut bytes = Vec::with_capacity(2);
    for (name, maximum_bits, decode) in NARROW_FORMATS {
        let dtype = Value::string(name.into());
        let encoding = Encoding::new(1, Some(&dtype), None)?;
        let minimum = decode(1);
        let underflow = minimum * 0.5;
        let maximum = decode(maximum_bits);
        let overflow = maximum + (maximum - decode(maximum_bits - 1)) * 0.5;
        let infinity_bits = maximum_bits + 1;
        for (number, expected) in [
            (0.0, 0),
            (f64::from_bits(1), 0),
            (f64::MIN_POSITIVE, 0),
            (underflow.next_down(), 0),
            (underflow, 0),
            (underflow.next_up(), 1),
            (minimum, 1),
            (maximum, maximum_bits),
            (overflow.next_down(), maximum_bits),
            (overflow, infinity_bits),
            (overflow.next_up(), infinity_bits),
            (f64::MAX, infinity_bits),
            (f64::INFINITY, infinity_bits),
        ] {
            check_narrow_encoding(&encoding, &mut bytes, number, expected)?;
            check_narrow_encoding(&encoding, &mut bytes, -number, expected | 0x8000)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn shared_content_keeps_each_dtype_and_shape_view() -> Result<()> {
    let fixture = Fixture::new()?;
    let flat = fixture
        .write(input(floats(&[1.0, 0.0]), "f32", Some(&[2])))
        .await?;
    let row = fixture
        .write(input(floats(&[1.0, 0.0]), "f32", Some(&[1, 2])))
        .await?;
    let bits = fixture
        .write(input(ints(&[1065353216, 0]), "i32", Some(&[2, 1])))
        .await?;
    ensure!(flat.blob == row.blob && row.blob == bits.blob);
    ensure!(flat.dtype == DType::F32 && flat.shape == [2]);
    ensure!(row.dtype == DType::F32 && row.shape == [1, 2]);
    ensure!(bits.dtype == DType::I32 && bits.shape == [2, 1]);
    for tensor in [&flat, &row, &bits] {
        fixture
            .check_bytes(tensor, &[0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0x00])
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn scalar_and_empty_shapes_preserve_their_dimensions() -> Result<()> {
    let fixture = Fixture::new()?;
    let scalar = fixture
        .write(input(floats(&[3.5]), "f32", Some(&[])))
        .await?;
    ensure!(scalar.shape.is_empty());
    fixture
        .check_bytes(&scalar, &[0x00, 0x00, 0x60, 0x40])
        .await?;
    let default_empty = fixture.write(input(Vec::new(), "f32", None)).await?;
    ensure!(default_empty.shape == [0]);
    fixture.check_bytes(&default_empty, &[]).await?;
    for shape in [
        vec![0],
        vec![2, 0, 3],
        vec![i64::MAX, i64::MAX, 0],
        vec![0, i64::MAX, i64::MAX],
    ] {
        let tensor = fixture
            .write(input(Vec::new(), "i64", Some(&shape)))
            .await?;
        ensure!(
            tensor.shape
                == shape
                    .iter()
                    .map(|dimension| *dimension as u64)
                    .collect::<Vec<_>>()
        );
        ensure!(tensor.dtype == DType::I64);
        ensure!(tensor.blob == default_empty.blob);
        fixture.check_bytes(&tensor, &[]).await?;
    }
    Ok(())
}

#[derive(Default)]
struct UnexpectedObjectWrite {
    calls: AtomicUsize,
}

impl UnexpectedObjectWrite {
    fn reject<T>(&self) -> Ready<StateResult<T>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        ready(Err(
            StateError::Backend("unexpected object write".into()).into()
        ))
    }
}

impl ObjectWrite for UnexpectedObjectWrite {
    type BeginUpload<'a> = Ready<StateResult<UploadId>>;
    type WriteChunk<'a> = Ready<StateResult<ObjectWriteChunk>>;
    type CommitUpload<'a> = Ready<StateResult<ObjectMetadata>>;
    type AbortUpload<'a> = Ready<StateResult<()>>;

    fn begin_upload(&self, _options: UploadOptions) -> Self::BeginUpload<'_> {
        self.reject()
    }

    fn write_chunk<'a>(
        &'a self,
        _upload: &'a UploadId,
        _offset: u64,
        _bytes: &'a [u8],
    ) -> Self::WriteChunk<'a> {
        self.reject()
    }

    fn commit_upload<'a>(
        &'a self,
        _upload: &'a UploadId,
        _final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a> {
        self.reject()
    }

    fn abort_upload<'a>(&'a self, _upload: &'a UploadId) -> Self::AbortUpload<'a> {
        self.reject()
    }
}

#[tokio::test]
async fn invalid_shape_is_rejected_before_any_object_write() -> Result<()> {
    let probe = Arc::new(UnexpectedObjectWrite::default());
    let driver = TensorDriver::new(ObjectStore::new().with_write(probe.clone()));
    for value in [
        input(floats(&[1.0]), "f32", Some(&[2])),
        input(floats(&[1.0]), "f32", Some(&[0])),
        input(Vec::new(), "f32", Some(&[])),
        input(Vec::new(), "f32", Some(&[-1, 0])),
        input(Vec::new(), "f32", Some(&[0, -1])),
        input(Vec::new(), "f64", Some(&[i64::MAX, i64::MAX])),
        Value::map(BTreeMap::from([
            ("data".into(), Value::list(floats(&[1.0]))),
            ("shape".into(), Value::string("1".into())),
        ])),
        Value::map(BTreeMap::from([
            ("data".into(), Value::list(floats(&[1.0]))),
            (
                "shape".into(),
                Value::list(vec![Value::float(FloatBits(1.0))]),
            ),
        ])),
    ] {
        let result = driver
            .call(MethodId::new(0), value, OutputMode::Unary, &context())
            .await;
        failure_message(result)?;
        ensure!(
            probe.calls.load(Ordering::Relaxed) == 0,
            "shape validation reached object storage"
        );
    }
    Ok(())
}

#[tokio::test]
async fn integer_and_bool_codecs_reject_type_and_range_errors() -> Result<()> {
    let probe = Arc::new(UnexpectedObjectWrite::default());
    let driver = TensorDriver::new(ObjectStore::new().with_write(probe.clone()));
    for (dtype, value) in [
        ("i8", Value::integer(-129)),
        ("i8", Value::integer(128)),
        ("i16", Value::integer(-32769)),
        ("i16", Value::integer(32768)),
        ("i32", Value::integer(-2147483649)),
        ("i32", Value::integer(2147483648)),
        ("u8", Value::integer(-1)),
        ("u8", Value::integer(256)),
        ("i8", Value::float(FloatBits(1.0))),
        ("i16", Value::float(FloatBits(1.0))),
        ("i32", Value::float(FloatBits(1.0))),
        ("i64", Value::float(FloatBits(1.0))),
        ("u8", Value::float(FloatBits(1.0))),
        ("bool", Value::integer(1)),
        ("bool", Value::integer(0)),
        ("bool", Value::float(FloatBits(1.0))),
        ("bool", Value::string("true".into())),
    ] {
        let result = driver
            .call(
                MethodId::new(0),
                input(vec![value], dtype, None),
                OutputMode::Unary,
                &context(),
            )
            .await;
        failure_message(result)?;
        ensure!(
            probe.calls.load(Ordering::Relaxed) == 0,
            "invalid {dtype} data reached object storage"
        );
    }
    Ok(())
}

#[tokio::test]
async fn malformed_data_and_dtype_are_rejected() -> Result<()> {
    let driver = TensorDriver::new(ObjectStore::new());
    for value in [
        Value::null(),
        Value::map(BTreeMap::new()),
        Value::map(BTreeMap::from([("data".into(), Value::integer(1))])),
        Value::map(BTreeMap::from([
            ("data".into(), Value::list(floats(&[1.0]))),
            ("dtype".into(), Value::integer(1)),
        ])),
        input(floats(&[1.0]), "complex64", None),
        input(vec![Value::string("not-a-number".into())], "f32", None),
        input(vec![Value::boolean(true)], "f64", None),
    ] {
        let result = driver
            .call(MethodId::new(0), value, OutputMode::Unary, &context())
            .await;
        let error = failure_message(result)?;
        ensure!(
            !error.to_string().contains("object.write"),
            "input validation reached object writer lookup"
        );
    }
    Ok(())
}

#[tokio::test]
async fn invalid_later_chunk_releases_unpublished_staging() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut values = vec![Value::float(FloatBits(1.0)); crate::object::CHUNK_BYTES + 1];
    values.push(Value::string("invalid final tensor element".into()));
    let result = fixture
        .driver
        .call(
            MethodId::new(0),
            input(values, "f64", None),
            OutputMode::Unary,
            &context(),
        )
        .await;
    failure_message(result)?;
    fixture.check_no_staging()?;
    ensure!(
        std::fs::read_dir(fixture.directory.path().join("objects"))?
            .next()
            .is_none()
    );
    Ok(())
}
