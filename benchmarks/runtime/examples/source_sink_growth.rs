//! Measure Source commits as one ordinary State sink list grows.
//! Run each configuration in a fresh process against a new redb file.

use anyhow::{Context, ensure};
use serde::Serialize;
use std::{fs, io::Write, path::PathBuf, time::Instant};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimId,
    SourceCommit, SourceCommitOutcome, SourceEventCommit,
};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{
    Path, Purity, TaintSet, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        StreamCapacity,
    },
};

const INSTALLATION: &str = "sink-growth";
const PROJECTION: &str = "events";
const MAX_SINK_BYTES: usize = 64 * 1024 * 1024;
const INLINE_OVERHEAD_BYTES: usize = 128;

#[derive(Serialize)]
struct Config {
    db: PathBuf,
    events: usize,
    capacity: usize,
    payload_bytes: usize,
    report_every: usize,
    prefill: usize,
    ordinary_append_every: usize,
}

impl Config {
    fn parse() -> anyhow::Result<Option<Self>> {
        let mut db = None;
        let mut events: usize = 1_024;
        let mut capacity: usize = 1_024;
        let mut payload_bytes: usize = 1_024;
        let mut report_every: usize = 256;
        let mut prefill: usize = 0;
        let mut ordinary_append_every: usize = 0;
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" {
                writeln!(
                    std::io::stdout().lock(),
                    "usage: source_sink_growth --db NEW_FILE [--events N] [--capacity N] [--payload-bytes N] [--report-every N] [--prefill N] [--ordinary-append-every N]"
                )?;
                return Ok(None);
            }
            let value = args
                .next()
                .with_context(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--db" => db = Some(PathBuf::from(value)),
                "--events" => events = value.parse()?,
                "--capacity" => capacity = value.parse()?,
                "--payload-bytes" => payload_bytes = value.parse()?,
                "--report-every" => report_every = value.parse()?,
                "--prefill" => prefill = value.parse()?,
                "--ordinary-append-every" => ordinary_append_every = value.parse()?,
                _ => anyhow::bail!("unknown option {flag}"),
            }
        }
        let db = db.context("--db is required")?;
        ensure!(
            db.parent().is_some_and(|parent| parent.is_dir()),
            "database parent directory must exist"
        );
        ensure!(!db.exists(), "database path must be new: {}", db.display());
        ensure!(events > 0 && (1..=65_536).contains(&capacity));
        ensure!((16..=1_000_000).contains(&payload_bytes));
        ensure!(report_every > 0);
        ensure!(prefill <= capacity);
        ensure!(
            capacity
                .checked_mul(payload_bytes.saturating_add(INLINE_OVERHEAD_BYTES))
                .is_some_and(|bound| bound <= MAX_SINK_BYTES),
            "declared sink budget exceeds 64 MiB"
        );
        Ok(Some(Self {
            db,
            events,
            capacity,
            payload_bytes,
            report_every,
            prefill,
            ordinary_append_every,
        }))
    }

    fn inline_limit(&self) -> usize {
        self.payload_bytes + INLINE_OVERHEAD_BYTES
    }
}

#[derive(Serialize)]
struct Checkpoint {
    kind: &'static str,
    events_done: usize,
    batch_events: usize,
    batch_elapsed_ms: u128,
    batch_state_appends: usize,
    state_append_elapsed_ns: u128,
    source_commit_elapsed_ns: u128,
    sink_events: usize,
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

fn payload(sequence: usize, bytes: usize) -> Value {
    let mut value = format!("{sequence:016x}");
    value.extend(std::iter::repeat_n('x', bytes - 16));
    Value::string(value)
}

async fn install(
    source: &(impl ExternalInstallationAuthority + ?Sized),
    sink: &Path,
    capacity: &StreamCapacity,
    inline_limit: usize,
) -> anyhow::Result<u64> {
    let definition = ExternalInstallationDef {
        id: INSTALLATION.into(),
        platform: "benchmark".into(),
        transport: Transport::Grpc { endpoint: None },
        trust: TrustLevel::Full,
        config_schema: Value::map(Default::default()),
        config: Value::null(),
        projections: vec![ExternalProjectionDef {
            id: PROJECTION.into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: sink.clone(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: inline_limit,
                capacity: capacity.clone(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            version: 1,
        }],
        version: 0,
    };
    let ExternalInstallationMutation::Applied(Some(record)) =
        source.compare_install(definition, None).await?
    else {
        anyhow::bail!("Source installation was not applied")
    };
    record
        .scope_epoch(PROJECTION)
        .context("missing Source scope")
}

async fn sink_count(state: &xolotl_state::Backend, sink: &Path) -> anyhow::Result<usize> {
    Ok(state
        .read(sink)
        .await?
        .context("missing sink")?
        .as_list()
        .context("sink is not a list")?
        .len())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Some(config) = Config::parse()? else {
        return Ok(());
    };
    ensure!(cfg!(target_os = "linux"), "requires Linux /proc/self");
    let store = RedbStore::open(&config.db)?;
    let (state, source) = store.state_backend().into_source_parts();
    let sink = Path::parse("state://benchmark/sink-growth/events")?;
    let capacity = StreamCapacity {
        max_events: u32::try_from(config.capacity)?,
        on_overflow: OverflowPolicy::DropOldest,
    };
    let scope_epoch = install(source.as_ref(), &sink, &capacity, config.inline_limit()).await?;
    if config.prefill != 0 {
        state
            .write_set(
                &sink,
                Value::from(
                    (0..config.prefill)
                        .map(|sequence| payload(sequence, config.payload_bytes))
                        .collect::<xolotl_types::ValueList>(),
                ),
            )
            .await?;
    }
    emit(&serde_json::json!({
        "kind": "configuration",
        "format": 1,
        "config": config,
        "measurement": "ordinary List Set prefill, optional ordinary Append immediately followed by Source commit, and configurable DropOldest; prefill, checkpoint reads and /proc sampling excluded from batch time; State and Source durations reported separately"
    }))?;
    let initial_write_bytes = proc_field("/proc/self/io", "write_bytes:")?;
    let taint = TaintSet::pristine();
    let mut done = 0usize;
    let mut ordinary_appends = 0usize;
    while done < config.events {
        let end = done.saturating_add(config.report_every).min(config.events);
        let start = Instant::now();
        let mut batch_state_appends = 0usize;
        let mut state_append_elapsed_ns = 0u128;
        let mut source_commit_elapsed_ns = 0u128;
        for sequence in done..end {
            let id = format!("event-{sequence}");
            let value = payload(sequence, config.payload_bytes);
            if config.ordinary_append_every != 0 && sequence % config.ordinary_append_every == 0 {
                let append_start = Instant::now();
                state.write_append(&sink, value.clone()).await?;
                state_append_elapsed_ns += append_start.elapsed().as_nanos();
                ordinary_appends += 1;
                batch_state_appends += 1;
            }
            let commit_start = Instant::now();
            let outcome = source
                .commit(SourceCommit {
                    claim: SourceClaim {
                        installation_id: INSTALLATION,
                        projection_id: PROJECTION,
                        scope_epoch,
                        stream_epoch: None,
                        event_id: &id,
                        claim_id: SourceClaimId::from_bytes((sequence as u128).to_le_bytes()),
                    },
                    received_at_ms: i64::try_from(sequence)?,
                    decision_clock: {
                        let decision_time = i64::try_from(sequence)?;
                        std::sync::Arc::new(move || decision_time)
                    },
                    dedupe_window_ms: 1_000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: config.inline_limit(),
                    payload: &value,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                })
                .await?;
            source_commit_elapsed_ns += commit_start.elapsed().as_nanos();
            ensure!(
                outcome == SourceCommitOutcome::Accepted,
                "Source event was not accepted at {sequence}: {outcome:?}"
            );
        }
        let elapsed = start.elapsed();
        let before = done;
        done = end;
        let count = sink_count(&state, &sink).await?;
        ensure!(
            count
                == config
                    .prefill
                    .saturating_add(done)
                    .saturating_add(ordinary_appends)
                    .min(config.capacity),
            "sink event count changed unexpectedly"
        );
        emit(&Checkpoint {
            kind: "checkpoint",
            events_done: done,
            batch_events: done - before,
            batch_elapsed_ms: elapsed.as_millis(),
            batch_state_appends,
            state_append_elapsed_ns,
            source_commit_elapsed_ns,
            sink_events: count,
            rss_kib: proc_field("/proc/self/status", "VmRSS:")?,
            peak_rss_kib: proc_field("/proc/self/status", "VmHWM:")?,
            db_file_bytes: fs::metadata(&config.db)?.len(),
            process_write_bytes_delta: proc_field("/proc/self/io", "write_bytes:")?
                .saturating_sub(initial_write_bytes),
        })?;
    }
    let expected_count = config
        .prefill
        .saturating_add(config.events)
        .saturating_add(ordinary_appends)
        .min(config.capacity);
    let idle = store.wait_idle();
    drop(source);
    drop(state);
    drop(store);
    idle.await;
    let reopened = RedbStore::open(&config.db)?;
    let state = reopened.state_backend().into_backend();
    ensure!(sink_count(&state, &sink).await? == expected_count);
    emit(&serde_json::json!({
        "kind": "verified",
        "reopened": true,
        "events": config.events,
        "sink_events": expected_count,
        "db_file_bytes": fs::metadata(&config.db)?.len(),
    }))?;
    Ok(())
}
