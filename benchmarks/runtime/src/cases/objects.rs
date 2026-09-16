use super::{Config, Work};
use anyhow::ensure;
use std::num::NonZeroUsize;
use xolotl_state::object::{ObjectDelete, ObjectRead};
use xolotl_storage_fs::{FileObjectOptions, FileObjectStore};
use xolotl_types::{
    TaintSet,
    value::event::{Event, Kind},
};
use xolotl_value_codec::validation::{MemoryKeyOptions, MemoryKeyStore};
use xolotl_value_object::{ValueObjectReader, ValueObjectWriter};

pub struct ObjectCase {
    store: FileObjectStore,
    _directory: tempfile::TempDir,
}

fn keys(config: &Config) -> MemoryKeyStore {
    MemoryKeyStore::new(MemoryKeyOptions {
        page_bytes: config.window,
        max_keys: None,
        max_bytes: None,
    })
}

impl ObjectCase {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let store = FileObjectStore::with_options(
            directory.path(),
            FileObjectOptions {
                chunk_bytes: config.window,
                max_uploads: NonZeroUsize::MIN,
                max_io_tasks: NonZeroUsize::MIN,
                ..FileObjectOptions::default()
            },
        )?;
        Ok(Self {
            store,
            _directory: directory,
        })
    }

    pub async fn run(&self, config: &Config) -> anyhow::Result<Work> {
        let mut scratch = vec![0; config.window.get()];
        let chunk = vec![0x5a; config.window.get()];
        let sources = TaintSet::pristine();
        let mut writer = ValueObjectWriter::begin(
            &self.store,
            &mut scratch,
            keys(config),
            None,
            sources.clone(),
        )
        .await?;
        for event in [
            Event::Begin(Kind::Document),
            Event::Begin(Kind::Taint),
            Event::End(Kind::Taint),
            Event::Begin(Kind::Bytes),
        ] {
            writer.write(event, &sources).await?;
        }
        let mut remaining = config.work.get();
        while remaining != 0 {
            let offered = remaining.min(chunk.len());
            writer
                .write(Event::Data(&chunk[..offered]), &sources)
                .await?;
            remaining -= offered;
        }
        writer.write(Event::End(Kind::Bytes), &sources).await?;
        writer.write(Event::End(Kind::Document), &sources).await?;
        let committed = writer.finish(&sources).await?;
        ensure!(!writer.is_open() && self.store.pending_uploads() == 0);
        drop(writer);
        let mut reader = ValueObjectReader::open(
            &self.store,
            &committed.reference,
            &mut scratch,
            keys(config),
            None,
            sources,
        )
        .await?;
        let mut bytes = 0usize;
        while let Some(event) = reader.next_event().await? {
            if let Event::Data(data) = event.event {
                ensure!(data.iter().all(|byte| *byte == 0x5a));
                bytes = bytes
                    .checked_add(data.len())
                    .ok_or_else(|| anyhow::anyhow!("read counter overflow"))?;
            }
        }
        let receipt = reader.finish()?;
        ensure!(bytes == config.work.get() && receipt.reference() == &committed.reference);
        drop((reader, receipt));
        self.store.delete(&committed.reference.blob).await?;
        ensure!(
            self.store
                .metadata(&committed.reference.blob)
                .await?
                .is_none()
        );
        ensure!(self.store.pending_uploads() == 0);
        drop((committed, scratch, chunk));
        Ok(Work {
            units: u64::try_from(bytes)?,
            unit: "logical bytes encoded, committed, read through EOF and deleted",
        })
    }
}
