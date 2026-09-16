//! A real storage/grant/download path consuming events without collecting bytes.

use super::*;
use crate::OpenObjectReadRequest;
use std::{collections::BTreeMap, future::Future, num::NonZeroUsize, pin::Pin};
use xolotl_state::{
    StateResult,
    object::{ObjectMetadata, ObjectRead, ObjectReadChunk},
};
use xolotl_storage_fs::key_workspace::{FileKeyOptions, FileKeyStore};
use xolotl_types::{
    BlobRef, DType, FloatBits, FrameKind, Path, StreamMarker, TaintedValue,
    value::event::{Atom, Event, Kind, ValueCursor},
};
use xolotl_value_codec::{
    cbor::{DecodeStatus, Decoder},
    validation::{KeyStore, MemoryKeyOptions, MemoryKeyStore},
};
use xolotl_value_object::{CommittedValue, ValueEncoding, ValueObjectWriter};

type Request<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

struct ReadSources(FileObjectStore);

fn late_read_taint() -> TaintSet {
    TaintSet::of(TaintSource::Fetched {
        host: "incremental-object-reader".into(),
    })
}

impl ObjectRead for ReadSources {
    type Metadata<'a> = Request<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = Request<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        Box::pin(self.0.metadata(blob))
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        Box::pin(async move {
            let mut chunk = self.0.read_chunk(blob, offset, buffer).await?;
            if offset != 0 {
                chunk.taint.union(&late_read_taint());
            }
            Ok(chunk)
        })
    }
}

#[derive(Default)]
struct EventDigest {
    hash: blake3::Hasher,
    data_bytes: u64,
    records: usize,
}

impl EventDigest {
    fn accept(&mut self, event: Event<'_>) {
        match event {
            Event::Data(bytes) => {
                self.hash.update(bytes);
                self.data_bytes += bytes.len() as u64;
            }
            other => {
                // Test-only event fingerprint: boundaries delimit fields, while
                // arbitrary Data fragmentation has no effect on their contents.
                self.hash.update(format!("{other:?}\0").as_bytes());
                self.records += 1;
            }
        }
    }

    fn equals(&self, other: &Self) -> bool {
        self.hash.finalize() == other.hash.finalize()
            && self.data_bytes == other.data_bytes
            && self.records == other.records
    }
}

fn resident_keys() -> MemoryKeyStore {
    MemoryKeyStore::new(MemoryKeyOptions {
        page_bytes: NonZeroUsize::MIN.saturating_add(255),
        max_keys: Some(4),
        max_bytes: Some(4096),
    })
}

async fn file_keys(root: &std::path::Path) -> anyhow::Result<FileKeyStore> {
    Ok(FileKeyStore::open(
        root,
        FileKeyOptions {
            io_bytes: NonZeroUsize::MIN.saturating_add(1023),
            max_keys: NonZeroUsize::MIN.saturating_add(3),
        },
    )
    .await?)
}

async fn export_and_digest<K: KeyStore>(
    fixture: &mut Fixture,
    committed: CommittedValue,
    keys: K,
) -> anyhow::Result<(EventDigest, TaintSet)>
where
    K::Error: core::error::Error + Send + Sync + 'static,
{
    ensure!(committed.reference.encoding == ValueEncoding::CborV1);
    let blob = committed.reference.blob;
    fixture.gateway.objects = ObjectStore::new()
        .with_read(Arc::new(ReadSources(fixture.files.clone())))
        .with_write(Arc::new(fixture.files.clone()));
    ensure!(
        fixture
            .gateway
            .open_object_read(
                &fixture.session,
                OpenObjectReadRequest {
                    grant_id: blob.hash.clone(),
                    offset: 0,
                    length: None,
                },
            )
            .await
            .is_err()
    );
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            IssueObjectReadGrantRequest {
                surface_id: "echo".into(),
                object: TaintedValue::new(Value::blob(blob.clone()), committed.taint),
                offset: 0,
                length: None,
                expires_in_ms: Some(60_000),
            },
        )
        .await?;
    let mut download = fixture
        .gateway
        .open_object_read(
            &fixture.session,
            OpenObjectReadRequest {
                grant_id: grant.grant_id().into(),
                offset: 0,
                length: None,
            },
        )
        .await?;
    let mut actual_sources = download.metadata().taint.clone();
    let mut decoder = Decoder::new(keys, None);
    let mut digest = EventDigest::default();
    let mut input = [0; 4079];
    let mut wire_end = false;
    let mut object_end = false;
    while !download.is_complete() {
        let chunk = download.read(&mut input).await?;
        actual_sources.union(&chunk.taint);
        object_end = chunk.end;
        let mut remaining = &input[..chunk.bytes_read];
        while !remaining.is_empty() {
            let step = decoder.decode(remaining).await?;
            ensure!(step.consumed != 0);
            remaining = &remaining[step.consumed..];
            match step.status {
                DecodeStatus::Event(event) => digest.accept(event),
                DecodeStatus::NeedInput => ensure!(remaining.is_empty()),
                DecodeStatus::End => wire_end = true,
            }
        }
    }
    ensure!(object_end && wire_end);
    ensure!(!decoder.is_complete());
    ensure!(decoder.bytes_read() == blob.size);
    download.finish().await?;
    decoder.finish()?;
    ensure!(decoder.is_complete());
    // No authoritative result is produced before both owners confirm EOF.
    Ok((digest, actual_sources))
}

fn every_value() -> Value {
    let blob = BlobRef {
        hash: "external-artifact".repeat(70),
        size: u64::MAX,
        mime: Some("application/x-arbitrary-metadata".repeat(30)),
    };
    let mut values = vec![
        Value::null(),
        Value::boolean(false),
        Value::boolean(true),
        Value::integer(i64::MIN),
        Value::integer(i64::MAX),
        Value::float(FloatBits(-0.0)),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_0042))),
        Value::string("通用内核🧠".repeat(500)),
        Value::bytes((0..=255).cycle().take(8192).collect()),
        Value::blob(blob.clone()),
        Value::blob(BlobRef {
            hash: String::new(),
            size: 0,
            mime: None,
        }),
        Value::stream_end(StreamMarker::Done),
        Value::stream_end(StreamMarker::Error {
            message: "分片错误🧠".repeat(300),
        }),
        Value::list(Vec::new()),
    ];
    for dtype in [
        DType::F16,
        DType::Bf16,
        DType::F32,
        DType::F64,
        DType::I8,
        DType::I16,
        DType::I32,
        DType::I64,
        DType::U8,
        DType::Bool,
    ] {
        values.push(Value::tensor(blob.clone(), dtype, vec![0, 1, u64::MAX]));
    }
    for kind in [
        FrameKind::Audio,
        FrameKind::Video,
        FrameKind::Pose,
        FrameKind::Sensor,
    ] {
        values.push(Value::frame(blob.clone(), i64::MIN, kind));
    }
    // Each key exceeds the entire 4 KiB resident-key policy used below.
    let prefix = "a".repeat(96 * 1024);
    Value::map(BTreeMap::from([
        (format!("{prefix}0"), Value::list(values)),
        (format!("{prefix}1"), Value::map(BTreeMap::new())),
    ]))
}

#[tokio::test]
async fn structured_values_round_trip_through_storage_grants_and_small_downloads()
-> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let workspace = tempfile::tempdir()?;
    let value = every_value();
    let lineage: TaintSet = serde_json::from_str(
        r#"{"sources":["model_output",{"inbound":{"source":"user","channel":"text"}},"author_constant",{"fetched":{"host":"origin"}},{"protected":{"path":"path://remote/state/key"}},"model_output"]}"#,
    )?;
    let trusted_source = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://host/structured-source")?,
    });
    let final_taint = trusted_source.clone().merged(&lineage);
    let objects = fixture.files.clone().into_object_store();
    let mut scratch = [0; 4093];
    let mut cursor = ValueCursor::new(
        &value,
        &lineage,
        NonZeroUsize::MIN.saturating_add(2046),
        None,
    )?;
    let mut writer = ValueObjectWriter::begin(
        &objects,
        &mut scratch,
        file_keys(workspace.path()).await?,
        None,
        final_taint.clone(),
    )
    .await?;
    let mut expected = EventDigest::default();
    while let Some(event) = cursor.next_event()? {
        expected.accept(event);
        writer.write(event, &TaintSet::pristine()).await?;
    }
    let committed = writer.finish(&TaintSet::pristine()).await?;
    ensure!(!writer.is_open());
    ensure!(committed.taint == final_taint);
    ensure!(committed.reference.blob.size > 200_000);
    let (received, actual_sources) =
        export_and_digest(&mut fixture, committed, file_keys(workspace.path()).await?).await?;
    ensure!(received.equals(&expected));
    ensure!(received.data_bytes > 200_000);
    ensure!(actual_sources == final_taint.merged(&late_read_taint()));
    ensure!(
        actual_sources
            .sources()
            .contains(&trusted_source.sources()[0])
    );

    // The explicit resident policy fails at the same large keys, while the
    // external workspace above handles the document with a 1 KiB I/O window.
    let mut resident = xolotl_value_codec::validation::EventValidator::new(resident_keys(), None);
    let mut cursor = ValueCursor::new(&value, &lineage, NonZeroUsize::MAX, None)?;
    let mut failed = false;
    while let Some(event) = cursor.next_event()? {
        if resident.accept(event).await.is_err() {
            failed = true;
            break;
        }
    }
    ensure!(failed && !resident.is_open());
    Ok(())
}

#[tokio::test]
async fn deep_event_source_reaches_authorized_download_without_recursive_value_ownership()
-> anyhow::Result<()> {
    const DEPTH: usize = 20_000;
    let mut fixture = Fixture::new().await?;
    let objects = fixture.files.clone().into_object_store();
    let mut scratch = [0; 4096];
    let taint = TaintSet::author();
    let mut writer =
        ValueObjectWriter::begin(&objects, &mut scratch, resident_keys(), None, taint.clone())
            .await?;
    let events = [
        Event::Begin(Kind::Document),
        Event::Begin(Kind::Taint),
        Event::Atom(Atom::Author),
        Event::End(Kind::Taint),
    ]
    .into_iter()
    .chain(core::iter::repeat_n(Event::Begin(Kind::List), DEPTH))
    .chain([Event::Atom(Atom::F64Bits(0xffff_ffff_ffff_ffff))])
    .chain(core::iter::repeat_n(Event::End(Kind::List), DEPTH))
    .chain([Event::End(Kind::Document)]);
    let mut expected = EventDigest::default();
    for event in events {
        expected.accept(event);
        writer.write(event, &TaintSet::pristine()).await?;
    }
    let committed = writer.finish(&TaintSet::pristine()).await?;
    let (received, sources) = export_and_digest(&mut fixture, committed, resident_keys()).await?;
    ensure!(received.equals(&expected));
    ensure!(received.records > 40_000 && received.data_bytes == 0);
    ensure!(sources == taint.merged(&late_read_taint()));
    Ok(())
}
