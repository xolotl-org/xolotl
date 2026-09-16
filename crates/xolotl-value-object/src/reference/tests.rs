use super::*;
use alloc::{collections::BTreeMap, format};
use anyhow::{Context, ensure};
use xolotl_types::{DType, FrameKind};

fn descriptor() -> EncodedValueRef {
    EncodedValueRef {
        blob: BlobRef {
            hash: "opaque-store-content-identity".into(),
            size: u64::MAX,
            mime: Some("application/custom-description".into()),
        },
        encoding: ValueEncoding::CborV1,
    }
}

#[test]
fn explicit_descriptor_roundtrips_full_width_metadata_without_codec_or_store() -> anyhow::Result<()>
{
    let expected = descriptor();
    let value = expected.clone().into_value();
    let snapshot = value.clone();
    let identity = value.identity();
    let parsed = EncodedValueRef::try_from_value(&value)?;
    ensure!(parsed == expected);
    ensure!(value == snapshot && value.identity() == identity);
    let map = value.as_map().context("descriptor map")?;
    ensure!(map.len() == 2);
    ensure!(map.get("encoding").and_then(Value::as_str) == Some("xolotl.value.cbor.v1"));
    ensure!(map.get("blob").and_then(Value::backing_blob) == Some(&expected.blob));
    ensure!(ValueEncoding::from_id(expected.encoding.as_str()) == Some(expected.encoding));
    ensure!(ValueEncoding::from_id(expected.encoding.media_type()).is_none());
    Ok(())
}

#[test]
fn descriptor_admission_rejects_extra_fields_guessed_encodings_and_untyped_references()
-> anyhow::Result<()> {
    let reference = descriptor();
    let fields = || {
        BTreeMap::from([
            (
                "encoding".into(),
                Value::string(reference.encoding.as_str().into()),
            ),
            ("blob".into(), Value::blob(reference.blob.clone())),
        ])
    };
    for input in [Value::null(), Value::blob(reference.blob.clone())] {
        ensure!(EncodedValueRef::try_from_value(&input) == Err(ReferenceError::Fields));
    }
    for remove in ["encoding", "blob"] {
        let mut map = fields();
        drop(map.remove(remove));
        ensure!(EncodedValueRef::try_from_value(&Value::map(map)) == Err(ReferenceError::Fields));
    }
    let mut extra = fields();
    extra.insert("authority".into(), Value::boolean(true));
    ensure!(EncodedValueRef::try_from_value(&Value::map(extra)) == Err(ReferenceError::Fields));
    for encoding in [
        Value::null(),
        Value::string(reference.encoding.media_type().into()),
        Value::string("xolotl.value.cbor.v2".into()),
        Value::string(format!("{} ", reference.encoding.as_str())),
    ] {
        let mut map = fields();
        map.insert("encoding".into(), encoding);
        ensure!(EncodedValueRef::try_from_value(&Value::map(map)) == Err(ReferenceError::Encoding));
    }
    for blob in [
        Value::string(reference.blob.hash.clone()),
        Value::map(BTreeMap::from([(
            "hash".into(),
            Value::string("claimed".into()),
        )])),
        Value::tensor(reference.blob.clone(), DType::U8, alloc::vec![u64::MAX]),
        Value::frame(reference.blob.clone(), i64::MIN, FrameKind::Sensor),
        reference.clone().into_value(),
    ] {
        let mut map = fields();
        map.insert("blob".into(), blob);
        ensure!(EncodedValueRef::try_from_value(&Value::map(map)) == Err(ReferenceError::Blob));
    }
    Ok(())
}
