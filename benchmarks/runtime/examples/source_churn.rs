//! Sustained Source stream open/commit/retire churn through the public redb adapter.
//! Linux `/proc` supplies process RSS and block-write observations.

use anyhow::{Context, ensure};
use serde::Serialize;
use std::{
    fs,
    io::Write,
    num::NonZeroUsize,
    path::PathBuf,
    time::{Duration, Instant},
};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimId,
    SourceCommit, SourceCommitOutcome, SourceEventCommit, SourceEventMaintenance,
    SourceMaintenance, SourceStreamLifecycle, SourceStreamOpen, SourceStreamOpenOutcome,
    SourceStreamPosition, SourceStreamRetire, SourceStreamRetireOutcome, SourceStreamScope,
};
use xolotl_storage_redb::{RedbOptions, RedbStore};
use xolotl_types::{
    Path, Purity, TaintSet, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        StreamCapacity,
    },
};

const INSTALLATION: &str = "benchmark-installation";
const PROJECTION: &str = "benchmark-source";
const STREAM: &str = "reused-stream";
const DEDUPE_WINDOW_MS: u64 = 1_000;

#[derive(Clone, Debug, Serialize)]
struct Config {
    db: PathBuf,
    cycles: usize,
    report_every: usize,
}

impl Config {
    fn parse() -> anyhow::Result<Option<Self>> {
        let mut db = None;
        let mut cycles = 10_000usize;
        let mut report_every = 1_000usize;
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" {
                writeln!(
                    std::io::stdout().lock(),
                    "usage: source_churn --db NEW_FILE [--cycles N] [--report-every N]"
                )?;
                return Ok(None);
            }
            let value = args
                .next()
                .with_context(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--db" => db = Some(PathBuf::from(value)),
                "--cycles" => cycles = value.parse()?,
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
        ensure!(cycles > 0 && report_every > 0);
        Ok(Some(Self {
            db,
            cycles,
            report_every,
        }))
    }
}

#[derive(Serialize)]
struct Checkpoint {
    kind: &'static str,
    cycles_done: usize,
    churn_elapsed_ms: u128,
    maintenance_elapsed_ms: u128,
    maintenance_rows_examined: usize,
    maintenance_rows_removed: usize,
    scope_revision: u64,
    last_stream_epoch: u64,
    sink_events: usize,
    rss_kib: u64,
    peak_rss_kib: u64,
    db_file_bytes: u64,
    process_write_bytes_delta: u64,
}

#[derive(Default)]
struct Progress {
    completed: usize,
    last_stream_epoch: u64,
    churn_elapsed: Duration,
    maintenance_elapsed: Duration,
    maintenance_rows_examined: usize,
    maintenance_rows_removed: usize,
    initial_write_bytes: u64,
    now_millis: i64,
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

fn sink() -> anyhow::Result<Path> {
    Path::parse("state://benchmark/source-churn/events").map_err(Into::into)
}

fn scope(epoch: u64) -> SourceStreamScope<'static> {
    SourceStreamScope {
        installation_id: INSTALLATION,
        projection_id: PROJECTION,
        scope_epoch: epoch,
        stream_id: STREAM,
    }
}

async fn install_source<S: ExternalInstallationAuthority + ?Sized>(
    source: &S,
    sink: &Path,
    capacity: &StreamCapacity,
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
                max_inline_payload_bytes: 128,
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
        .context("Source scope missing")
}

async fn sink_events(state: &xolotl_state::Backend, sink: &Path) -> anyhow::Result<usize> {
    Ok(state
        .read(sink)
        .await?
        .context("Source sink missing")?
        .as_list()
        .context("Source sink is not a list")?
        .len())
}

async fn checkpoint(
    config: &Config,
    state: &xolotl_state::Backend,
    source: &(impl SourceStreamLifecycle + ?Sized),
    sink: &Path,
    scope_epoch: u64,
    progress: &Progress,
) -> anyhow::Result<()> {
    let snapshot = source
        .inspect_stream(scope(scope_epoch))
        .await?
        .context("Source scope inactive")?;
    ensure!(snapshot.active.is_none(), "retired stream remains active");
    let events = sink_events(state, sink).await?;
    ensure!(
        events == progress.completed.min(16),
        "sink retention differs from capacity"
    );
    emit(&Checkpoint {
        kind: "checkpoint",
        cycles_done: progress.completed,
        churn_elapsed_ms: progress.churn_elapsed.as_millis(),
        maintenance_elapsed_ms: progress.maintenance_elapsed.as_millis(),
        maintenance_rows_examined: progress.maintenance_rows_examined,
        maintenance_rows_removed: progress.maintenance_rows_removed,
        scope_revision: snapshot.revision,
        last_stream_epoch: progress.last_stream_epoch,
        sink_events: events,
        rss_kib: proc_field("/proc/self/status", "VmRSS:")?,
        peak_rss_kib: proc_field("/proc/self/status", "VmHWM:")?,
        db_file_bytes: fs::metadata(&config.db)?.len(),
        process_write_bytes_delta: proc_field("/proc/self/io", "write_bytes:")?
            .saturating_sub(progress.initial_write_bytes),
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Some(config) = Config::parse()? else {
        return Ok(());
    };
    ensure!(
        cfg!(target_os = "linux"),
        "source_churn requires Linux /proc/self"
    );
    let options = RedbOptions {
        source_stream_limit: NonZeroUsize::MIN,
        ..RedbOptions::default()
    };
    let store = RedbStore::open_with_options(&config.db, options)?;
    let (state, source) = store.state_backend().into_source_parts();
    let sink = sink()?;
    let capacity = StreamCapacity {
        max_events: 16,
        on_overflow: OverflowPolicy::DropOldest,
    };
    let scope_epoch = install_source(source.as_ref(), &sink, &capacity).await?;
    emit(&serde_json::json!({
        "kind": "configuration",
        "format": 1,
        "config": config,
        "pid": std::process::id(),
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        "measurement": "one Open, accepted ordered event, Retire per cycle; fixed sink capacity; complete bounded private maintenance per report"
    }))?;
    let mut progress = Progress {
        initial_write_bytes: proc_field("/proc/self/io", "write_bytes:")?,
        ..Progress::default()
    };
    while progress.completed < config.cycles {
        let end = progress
            .completed
            .saturating_add(config.report_every)
            .min(config.cycles);
        let start = Instant::now();
        for sequence in progress.completed..end {
            progress.now_millis = progress
                .now_millis
                .checked_add(1)
                .context("benchmark clock overflow")?;
            let identity = format!("event-{sequence}");
            let before = source
                .inspect_stream(scope(scope_epoch))
                .await?
                .context("Source scope inactive")?;
            ensure!(before.active.is_none(), "retired stream remains active");
            let SourceStreamOpenOutcome::Opened(opened) = source
                .open_stream(SourceStreamOpen {
                    stream: scope(scope_epoch),
                    open_id: &identity,
                    expected_revision: before.revision,
                })
                .await?
            else {
                anyhow::bail!("Source stream did not open")
            };
            let stream_epoch = opened.active.context("opened stream missing")?.stream_epoch;
            ensure!(
                stream_epoch > progress.last_stream_epoch,
                "stream epoch was reused"
            );
            progress.last_stream_epoch = stream_epoch;
            let payload = Value::integer(i64::try_from(sequence)?);
            let taint = TaintSet::pristine();
            ensure!(
                source
                    .commit(SourceCommit {
                        claim: SourceClaim {
                            installation_id: INSTALLATION,
                            projection_id: PROJECTION,
                            scope_epoch,
                            stream_epoch: Some(stream_epoch),
                            event_id: &identity,
                            claim_id: SourceClaimId::from_bytes((sequence as u128).to_le_bytes()),
                        },
                        received_at_ms: progress.now_millis,
                        decision_clock: {
                            let decision_time = progress.now_millis;
                            std::sync::Arc::new(move || decision_time)
                        },
                        dedupe_window_ms: DEDUPE_WINDOW_MS,
                        sink: &sink,
                        capacity: &capacity,
                        max_inline_payload_bytes: 128,
                        payload: &payload,
                        taint: &taint,
                        stream: Some(SourceStreamPosition {
                            stream_id: STREAM,
                            stream_epoch,
                            seq: 1,
                        }),
                        rate_limit: None,
                    })
                    .await?
                    == SourceCommitOutcome::Accepted,
                "ordered Source event was not accepted"
            );
            ensure!(
                matches!(
                    source
                        .retire_stream(SourceStreamRetire {
                            stream: scope(scope_epoch),
                            stream_epoch,
                        })
                        .await?,
                    SourceStreamRetireOutcome::Retired { .. }
                ),
                "Source stream did not retire"
            );
        }
        progress.churn_elapsed += start.elapsed();
        progress.completed = end;
        progress.now_millis = progress
            .now_millis
            .checked_add(i64::try_from(DEDUPE_WINDOW_MS)? + 1)
            .context("benchmark clock overflow")?;
        let start = Instant::now();
        loop {
            let result = source
                .maintain(SourceMaintenance {
                    decision_clock: {
                        let decision_time = progress.now_millis;
                        std::sync::Arc::new(move || decision_time)
                    },
                    limit: NonZeroUsize::new(64).context("nonzero maintenance limit")?,
                })
                .await?;
            progress.maintenance_rows_examined += result.examined;
            progress.maintenance_rows_removed += result.removed;
            if result.reached_end {
                break;
            }
            ensure!(result.examined > 0, "Source maintenance did not progress");
        }
        progress.maintenance_elapsed += start.elapsed();
        checkpoint(
            &config,
            &state,
            source.as_ref(),
            &sink,
            scope_epoch,
            &progress,
        )
        .await?;
    }
    drop(source);
    drop(state);
    drop(store);

    let reopened = RedbStore::open_with_options(&config.db, options)?;
    let (state, source) = reopened.state_backend().into_source_parts();
    let snapshot = source
        .inspect_stream(scope(scope_epoch))
        .await?
        .context("Source scope missing after reopen")?;
    ensure!(
        snapshot.active.is_none(),
        "retired stream revived after reopen"
    );
    ensure!(sink_events(&state, &sink).await? == config.cycles.min(16));
    let SourceStreamOpenOutcome::Opened(opened) = source
        .open_stream(SourceStreamOpen {
            stream: scope(scope_epoch),
            open_id: "reopen-check",
            expected_revision: snapshot.revision,
        })
        .await?
    else {
        anyhow::bail!("Source quota was not released after reopen")
    };
    let next_epoch = opened
        .active
        .context("reopened stream missing")?
        .stream_epoch;
    ensure!(
        next_epoch > progress.last_stream_epoch,
        "stream epoch reused after reopen"
    );
    ensure!(matches!(
        source
            .retire_stream(SourceStreamRetire {
                stream: scope(scope_epoch),
                stream_epoch: next_epoch,
            })
            .await?,
        SourceStreamRetireOutcome::Retired { .. }
    ));
    emit(&serde_json::json!({
        "kind": "verified",
        "reopened": true,
        "cycles": config.cycles,
        "sink_events": config.cycles.min(16),
        "last_stream_epoch": progress.last_stream_epoch,
        "next_stream_epoch": next_epoch,
        "db_file_bytes": fs::metadata(&config.db)?.len(),
        "rss_kib": proc_field("/proc/self/status", "VmRSS:")?,
        "peak_rss_kib": proc_field("/proc/self/status", "VmHWM:")?
    }))?;
    Ok(())
}
