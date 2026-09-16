//! Run each profile in a separate process under `/usr/bin/time -v` to measure RSS.
use anyhow::{Context, Result, bail, ensure};
use std::{io::Write, mem::size_of_val, num::NonZeroUsize};
use xolotl_state::{InMemoryBackend, InMemoryOptions, MemoryHistory, StateReadExt, StateWriteExt};
use xolotl_types::{Path, Value};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let history = match args.next().as_deref() {
        Some("full") => MemoryHistory::Full,
        Some("disabled") => MemoryHistory::Disabled,
        _ => bail!("usage: state_footprint <full|disabled> <read-shards>"),
    };
    let read_shards: NonZeroUsize = args.next().context("missing read-shards")?.parse()?;
    ensure!(args.next().is_none(), "unexpected extra argument");
    let backend = InMemoryBackend::with_options(InMemoryOptions {
        read_shards,
        history,
        ..InMemoryOptions::default()
    })?;
    let path = Path::parse("state://footprint/value")?;
    let rt = tokio::runtime::Builder::new_current_thread().build()?;
    const WRITES: i64 = 100_000;
    rt.block_on(async {
        for value in 0..WRITES {
            backend.write_set(&path, Value::integer(value)).await?;
        }
        ensure!(backend.read(&path).await? == Some(Value::integer(WRITES - 1)));
        Ok::<(), anyhow::Error>(())
    })?;
    writeln!(
        std::io::stdout().lock(),
        "history={history:?}, read_shards={read_shards}, scalar overwrites={WRITES}, backend inline bytes={}",
        size_of_val(&backend)
    )?;
    Ok(())
}
