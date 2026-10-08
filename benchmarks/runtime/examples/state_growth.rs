//! Sustained, single-writer State overwrites through the public redb adapter.
//! Linux `/proc` supplies process RSS and block-write observations.

use anyhow::{Context, ensure};
use serde::Serialize;
use std::{fs, io::Write, path::PathBuf, time::Duration, time::Instant};
use xolotl_state::StateHistoryQuery;
use xolotl_storage_redb::{RedbHistory, RedbStore};
use xolotl_types::{Path, Value};

#[derive(Clone, Debug, Serialize)]
struct Config {
    db: PathBuf,
    history: &'static str,
    writes: usize,
    keys: usize,
    payload_bytes: usize,
    report_every: usize,
}

impl Config {
    fn parse() -> anyhow::Result<Option<Self>> {
        let mut db = None;
        let mut history = "current_only";
        let mut writes: usize = 10_000;
        let mut keys: usize = 64;
        let mut payload_bytes: usize = 256;
        let mut report_every: usize = 1_000;
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" {
                writeln!(
                    std::io::stdout().lock(),
                    "usage: state_growth --db NEW_FILE [--history current_only|full] [--writes N] [--keys N] [--payload-bytes N] [--report-every N]"
                )?;
                return Ok(None);
            }
            let value = args
                .next()
                .with_context(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--db" => db = Some(PathBuf::from(value)),
                "--history" => match value.as_str() {
                    "current_only" => history = "current_only",
                    "full" => history = "full",
                    _ => anyhow::bail!("history must be current_only or full"),
                },
                "--writes" => writes = value.parse()?,
                "--keys" => keys = value.parse()?,
                "--payload-bytes" => payload_bytes = value.parse()?,
                "--report-every" => report_every = value.parse()?,
                _ => anyhow::bail!("unknown option {flag}"),
            }
        }
        let db = db.context("--db is required")?;
        ensure!(
            db.parent().is_some_and(|parent| parent.is_dir()),
            "database parent directory must already exist"
        );
        ensure!(!db.exists(), "database path must be new: {}", db.display());
        ensure!(writes > 0 && keys > 0 && keys <= writes);
        ensure!(payload_bytes >= 8 && report_every > 0);
        u64::try_from(writes).context("write count exceeds u64")?;
        writes
            .checked_mul(payload_bytes)
            .context("logical payload byte count overflow")?;
        Ok(Some(Self {
            db,
            history,
            writes,
            keys,
            payload_bytes,
            report_every,
        }))
    }

    fn history_mode(&self) -> RedbHistory {
        if self.history == "full" {
            RedbHistory::Full
        } else {
            RedbHistory::CurrentOnly
        }
    }
}

#[derive(Serialize)]
struct Checkpoint {
    kind: &'static str,
    writes_done: usize,
    write_elapsed_ms: u128,
    logical_payload_bytes: usize,
    rss_kib: u64,
    peak_rss_kib: u64,
    db_file_bytes: u64,
    process_write_bytes_delta: u64,
}

fn proc_field(file: &str, name: &str) -> anyhow::Result<u64> {
    let contents = fs::read_to_string(file).with_context(|| format!("read {file}"))?;
    contents
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|tail| tail.split_whitespace().next())
        })
        .with_context(|| format!("missing {name} in {file}"))?
        .parse()
        .with_context(|| format!("invalid {name} in {file}"))
}

fn emit<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn checkpoint(
    config: &Config,
    writes_done: usize,
    write_elapsed: Duration,
    initial_write_bytes: u64,
) -> anyhow::Result<()> {
    emit(&Checkpoint {
        kind: "checkpoint",
        writes_done,
        write_elapsed_ms: write_elapsed.as_millis(),
        logical_payload_bytes: writes_done * config.payload_bytes,
        rss_kib: proc_field("/proc/self/status", "VmRSS:")?,
        peak_rss_kib: proc_field("/proc/self/status", "VmHWM:")?,
        db_file_bytes: fs::metadata(&config.db)?.len(),
        process_write_bytes_delta: proc_field("/proc/self/io", "write_bytes:")?
            .saturating_sub(initial_write_bytes),
    })
}

fn payload(sequence: usize, bytes: usize) -> Vec<u8> {
    let mut value = vec![0xa5; bytes];
    value[..8].copy_from_slice(&(sequence as u64).to_le_bytes());
    value
}

async fn verify_current(
    state: &xolotl_state::Backend,
    paths: &[Path],
    config: &Config,
) -> anyhow::Result<()> {
    for (key, path) in paths.iter().enumerate() {
        let last = key + ((config.writes - 1 - key) / config.keys) * config.keys;
        let stored = state
            .read(path)
            .await?
            .with_context(|| format!("missing {path}"))?;
        ensure!(
            stored.as_bytes() == Some(payload(last, config.payload_bytes).as_slice()),
            "last value mismatch at {path}"
        );
    }
    Ok(())
}

async fn count_history(state: &xolotl_state::Backend) -> anyhow::Result<usize> {
    let mut query = StateHistoryQuery::new(Path::parse("state://benchmark/growth")?, 0, i64::MAX);
    let mut count = 0usize;
    loop {
        let page = state.history(&query).await?;
        count = count
            .checked_add(page.entries.len())
            .context("history row count overflow")?;
        match page.next {
            Some(next) => {
                ensure!(
                    query.cursor.as_ref() != Some(&next),
                    "history cursor stalled"
                );
                query.cursor = Some(next);
            }
            None => break,
        }
    }
    Ok(count)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Some(config) = Config::parse()? else {
        return Ok(());
    };
    ensure!(
        cfg!(target_os = "linux"),
        "state_growth requires Linux /proc/self"
    );
    let store = RedbStore::open_with_history(&config.db, config.history_mode())?;
    let state = store.state_backend().into_backend();
    let paths = (0..config.keys)
        .map(|index| Path::parse(&format!("state://benchmark/growth/{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    emit(&serde_json::json!({
        "kind": "configuration",
        "format": 1,
        "config": config,
        "pid": std::process::id(),
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        "measurement": "single writer; one committed State::Set per write; new bytes value per write"
    }))?;
    let initial_write_bytes = proc_field("/proc/self/io", "write_bytes:")?;
    checkpoint(&config, 0, Duration::ZERO, initial_write_bytes)?;
    let mut completed = 0usize;
    let mut write_elapsed = Duration::ZERO;
    while completed < config.writes {
        let end = completed
            .saturating_add(config.report_every)
            .min(config.writes);
        let start = Instant::now();
        for sequence in completed..end {
            state
                .write_set(
                    &paths[sequence % config.keys],
                    Value::bytes(payload(sequence, config.payload_bytes)),
                )
                .await?;
        }
        write_elapsed += start.elapsed();
        completed = end;
        checkpoint(&config, completed, write_elapsed, initial_write_bytes)?;
    }
    verify_current(&state, &paths, &config).await?;
    drop(state);
    drop(store);

    let reopened = RedbStore::open_with_history(&config.db, config.history_mode())?;
    let state = reopened.state_backend().into_backend();
    verify_current(&state, &paths, &config).await?;
    let history_entries = if config.history == "full" {
        let entries = count_history(&state).await?;
        ensure!(entries == config.writes, "history row count mismatch");
        Some(entries)
    } else {
        None
    };
    emit(&serde_json::json!({
        "kind": "verified",
        "reopened": true,
        "current_keys": config.keys,
        "history_entries": history_entries,
        "db_file_bytes": fs::metadata(&config.db)?.len(),
        "rss_kib": proc_field("/proc/self/status", "VmRSS:")?,
        "peak_rss_kib": proc_field("/proc/self/status", "VmHWM:")?
    }))?;
    Ok(())
}
