use anyhow::{Context, ensure};
use serde::Serialize;
use std::{
    collections::BTreeMap, fs, io::Write, num::NonZeroUsize, path::PathBuf, sync::Arc,
    time::Instant,
};
use xolotl_gateway::{
    GatewayEvidenceNamespace, GatewayIdempotencyLimits, GatewayIdempotencyRecord,
    GatewayIdempotencyStore, GatewayIdempotencyUsage, MemoryGatewayIdempotencyStore,
};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{TaintSet, TaintSource, TaintedValue, Value};

const RECORD_BYTES: usize = 64 * 1024;
const PREFILL_PAYLOAD_BYTES: usize = 1024;

#[derive(Serialize)]
struct Config {
    backend: &'static str,
    db: Option<PathBuf>,
    prefill: usize,
    events: usize,
    payload_bytes: usize,
    report_every: usize,
}

impl Config {
    fn parse() -> anyhow::Result<Option<Self>> {
        let mut config = Self {
            backend: "memory",
            db: None,
            prefill: 0,
            events: 10_000,
            payload_bytes: 1024,
            report_every: 1000,
        };
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" {
                writeln!(
                    std::io::stdout().lock(),
                    "usage: gateway_request_growth --backend memory|redb [--db NEW_PATH_UNDER_TARGET] [--prefill N] [--events N] [--payload-bytes N] [--report-every N]"
                )?;
                return Ok(None);
            }
            let value = args
                .next()
                .with_context(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--backend" => {
                    config.backend = match value.as_str() {
                        "memory" => "memory",
                        "redb" => "redb",
                        _ => anyhow::bail!("backend must be memory or redb"),
                    }
                }
                "--db" => config.db = Some(PathBuf::from(value)),
                "--prefill" => config.prefill = value.parse()?,
                "--events" => config.events = value.parse()?,
                "--payload-bytes" => config.payload_bytes = value.parse()?,
                "--report-every" => config.report_every = value.parse()?,
                _ => anyhow::bail!("unknown option {flag}"),
            }
        }
        ensure!(
            config.events > 0 && config.report_every > 0,
            "events and report-every must be positive"
        );
        ensure!(
            config.payload_bytes <= RECORD_BYTES,
            "payload exceeds per-record capacity before metadata"
        );
        config
            .prefill
            .checked_add(config.events)
            .and_then(|count| count.checked_add(1))
            .context("record count overflow")?;
        if config.backend == "redb" {
            let db = config.db.as_ref().context("--db is required for redb")?;
            let parent = db
                .parent()
                .context("database needs a parent directory")?
                .canonicalize()
                .context("database parent must already exist")?;
            let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target")
                .canonicalize()
                .context("workspace target directory must exist")?;
            ensure!(
                parent.starts_with(target),
                "database must be under workspace target, not /tmp"
            );
            ensure!(
                !parent.starts_with("/tmp"),
                "database target must not resolve under /tmp"
            );
            let db = parent.join(db.file_name().context("database needs a file name")?);
            match db.symlink_metadata() {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => anyhow::bail!("database path must be new: {}", db.display()),
            }
            config.db = Some(db);
        } else {
            ensure!(config.db.is_none(), "--db is only valid for redb");
        }
        Ok(Some(config))
    }
}

fn key(sequence: usize) -> String {
    format!("{sequence:064x}")
}

fn base(sequence: usize) -> BTreeMap<String, Value> {
    let key = key(sequence);
    BTreeMap::from([
        (
            "schema".into(),
            Value::string("gateway-idempotency-v1".into()),
        ),
        ("effective_key_hash".into(), Value::string(key.clone())),
        ("submission_hash".into(), Value::string(key.clone())),
        (
            "caller_material_kind".into(),
            Value::string("idempotency_key".into()),
        ),
        ("caller_material_hash".into(), Value::string(key)),
        ("profile_name".into(), Value::string("growth".into())),
        ("profile_rev".into(), Value::string("1".into())),
        ("principal_id".into(), Value::string("alice".into())),
        ("surface_id".into(), Value::string("charge".into())),
    ])
}

fn pending(sequence: usize) -> TaintedValue {
    let mut fields = base(sequence);
    fields.insert("state".into(), Value::string("pending".into()));
    fields.insert("created_at_ms".into(), Value::integer(1));
    fields.insert("reservation_id".into(), Value::string(key(sequence)));
    TaintedValue::new(
        Value::map(fields),
        TaintSet::of(TaintSource::Inbound {
            source: "gateway/growth".into(),
            channel: "value".into(),
        }),
    )
}

fn completed(sequence: usize, payload_bytes: usize) -> TaintedValue {
    let mut fields = base(sequence);
    fields.extend([
        ("state".into(), Value::string("committed".into())),
        ("committed_at_ms".into(), Value::integer(2)),
        (
            "accepted_submission_id".into(),
            Value::string(key(sequence)),
        ),
        ("accepted_trace_root".into(), Value::string(key(sequence))),
        ("accepted_profile_rev".into(), Value::integer(1)),
        ("accepted_surface_id".into(), Value::string("charge".into())),
        ("outcome_status".into(), Value::string("done".into())),
        (
            "outcome_value".into(),
            Value::string("x".repeat(payload_bytes)),
        ),
        (
            "unresolved_operations".into(),
            Value::map(BTreeMap::from([
                ("operation_ids".into(), Value::list(Vec::new())),
                ("identities_incomplete".into(), Value::boolean(false)),
            ])),
        ),
    ]);
    TaintedValue::new(
        Value::map(fields),
        TaintSet::of(TaintSource::Fetched {
            host: "growth-driver".into(),
        }),
    )
}

fn expected_result(sequence: usize, payload_bytes: usize) -> TaintedValue {
    let mut result = completed(sequence, payload_bytes);
    result.taint.union(&pending(sequence).taint);
    result
}

struct Charges {
    pending: usize,
    prefilled: usize,
    completed: usize,
    retired: usize,
}

fn capacity(config: &Config) -> anyhow::Result<(GatewayIdempotencyLimits, Charges)> {
    let records = config
        .prefill
        .checked_add(config.events)
        .and_then(|count| count.checked_add(1))
        .context("record count overflow")?;
    let mut limits = GatewayIdempotencyLimits {
        max_records: NonZeroUsize::new(records).context("zero records")?,
        max_bytes: NonZeroUsize::MAX,
        max_record_bytes: NonZeroUsize::new(RECORD_BYTES).context("zero record bytes")?,
    };
    let result = GatewayIdempotencyRecord::completed(
        expected_result(records, config.payload_bytes),
        limits,
    )?;
    let charges = Charges {
        pending: GatewayIdempotencyRecord::pending(pending(records), limits)?.charged_bytes(),
        prefilled: GatewayIdempotencyRecord::completed(
            expected_result(records, PREFILL_PAYLOAD_BYTES),
            limits,
        )?
        .charged_bytes(),
        completed: result.charged_bytes(),
        retired: result.retired(limits)?.charged_bytes(),
    };
    let bytes = config
        .prefill
        .checked_mul(charges.prefilled)
        .and_then(|bytes| {
            config
                .events
                .checked_mul(charges.retired)
                .and_then(|retired| bytes.checked_add(retired))
        })
        .and_then(|bytes| bytes.checked_add(charges.pending))
        .context("byte capacity overflow")?;
    limits.max_bytes = NonZeroUsize::new(bytes).context("zero byte capacity")?;
    limits.validate()?;
    Ok((limits, charges))
}

fn proc_field(name: &str) -> anyhow::Result<u64> {
    fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|tail| tail.split_whitespace().next())
        })
        .with_context(|| format!("missing {name} in /proc/self/status"))?
        .parse()
        .context("invalid RSS field")
}

fn emit(value: serde_json::Value) -> anyhow::Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn filesystem(db: &Option<PathBuf>) -> anyhow::Result<serde_json::Value> {
    let Some(db) = db else {
        return Ok(serde_json::Value::Null);
    };
    let mounts = fs::read_to_string("/proc/mounts")?;
    let mount = mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let device = fields.next()?;
            let path = fields
                .next()?
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\134", "\\");
            let kind = fields.next()?;
            db.starts_with(&path).then_some((device, path, kind))
        })
        .max_by_key(|(_, path, _)| path.len())
        .context("database filesystem mount not found")?;
    ensure!(
        !matches!(mount.2, "tmpfs" | "ramfs"),
        "redb disk measurement must not use tmpfs/ramfs"
    );
    Ok(serde_json::json!({"device": mount.0, "mount": mount.1, "type": mount.2}))
}

#[derive(Default, Serialize)]
struct Timing {
    reserve_elapsed_ns: u128,
    complete_elapsed_ns: u128,
    lookup_elapsed_ns: u128,
    retire_elapsed_ns: u128,
    replay_reserve_elapsed_ns: u128,
}

async fn checkpoint(
    config: &Config,
    store: &dyn GatewayIdempotencyStore,
    charges: &Charges,
    done: usize,
    batch: usize,
    timing: &Timing,
) -> anyhow::Result<()> {
    let usage = store.usage().await?;
    let expected_bytes = config
        .prefill
        .checked_mul(charges.prefilled)
        .and_then(|bytes| {
            done.checked_mul(charges.retired)
                .and_then(|retired| bytes.checked_add(retired))
        })
        .context("usage overflow")?;
    ensure!(
        usage.records == config.prefill + done && usage.bytes == expected_bytes,
        "accounting mismatch after retirement"
    );
    emit(serde_json::json!({
        "kind": "checkpoint", "events_done": done, "batch_events": batch, "timing": timing,
        "port_calls_per_event": {"reserve": 1, "complete": 1, "committed_lookup": 1, "retire": 1},
        "batch_replay_reserve_calls": usize::from(batch != 0),
        "usage": {"records": usage.records, "charged_bytes": usage.bytes},
        "rss_kib": proc_field("VmRSS:")?, "peak_rss_kib": proc_field("VmHWM:")?,
        "db_file_bytes": config.db.as_ref().map(fs::metadata).transpose()?.map(|metadata| metadata.len()),
    }))
}

async fn verify(
    store: &dyn GatewayIdempotencyStore,
    config: &Config,
    limits: GatewayIdempotencyLimits,
    usage: GatewayIdempotencyUsage,
    namespace: GatewayEvidenceNamespace,
) -> anyhow::Result<()> {
    ensure!(
        store.evidence_namespace()? == namespace,
        "ledger namespace changed"
    );
    ensure!(
        store.limits() == limits && store.usage().await? == usage,
        "reopen changed limits or usage"
    );
    let total = config.prefill + config.events;
    for sequence in [1, config.prefill, config.prefill + 1, total / 2, total] {
        if sequence == 0 {
            continue;
        }
        let expected = if sequence <= config.prefill {
            expected_result(sequence, PREFILL_PAYLOAD_BYTES)
        } else {
            GatewayIdempotencyRecord::completed(
                expected_result(sequence, config.payload_bytes),
                limits,
            )?
            .retired(limits)?
            .observe()?
        };
        ensure!(
            store.observe(&key(sequence)).await? == Some(expected),
            "retained sample mismatch at {sequence}"
        );
    }
    let old = config.prefill + 1;
    let retired = store
        .observe(&key(old))
        .await?
        .context("old retired identity missing")?;
    ensure!(
        store.reserve(&key(old), pending(old)).await? == Some(retired),
        "retired identity became executable"
    );
    ensure!(
        store.usage().await? == usage,
        "verification or retired replay changed usage"
    );
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Some(config) = Config::parse()? else {
        return Ok(());
    };
    ensure!(
        cfg!(target_os = "linux"),
        "gateway_request_growth requires Linux /proc"
    );
    let (limits, charges) = capacity(&config)?;
    let filesystem = filesystem(&config.db)?;
    let owner = config.db.as_ref().map(RedbStore::open).transpose()?;
    let store: Arc<dyn GatewayIdempotencyStore> = match &owner {
        Some(owner) => Arc::new(owner.gateway_idempotency_store(limits)?),
        None => Arc::new(MemoryGatewayIdempotencyStore::new(limits)?),
    };
    let namespace = store.evidence_namespace()?;
    ensure!(
        store.usage().await? == GatewayIdempotencyUsage::default(),
        "store must start empty"
    );
    emit(serde_json::json!({
        "kind": "configuration", "format": 1, "config": config,
        "pid": std::process::id(), "target_os": std::env::consts::OS, "target_arch": std::env::consts::ARCH,
        "kernel_release": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
        "cpu_model": fs::read_to_string("/proc/cpuinfo")?.lines().find(|line| line.starts_with("model name")),
        "package_version": env!("CARGO_PKG_VERSION"), "debug_assertions": cfg!(debug_assertions), "filesystem": filesystem,
        "limits": {"max_records": limits.max_records.get(), "max_bytes": limits.max_bytes.get(), "max_record_bytes": limits.max_record_bytes.get()},
        "charges": {"pending": charges.pending, "prefilled": charges.prefilled, "completed": charges.completed, "retired": charges.retired},
        "scope": "single sequential writer; real Gateway request-store port only, no GatewayRuntime/Kernel execution or transport; synthetic schema-valid fingerprints; no speedup baseline",
        "timing": "per-batch sum of independently timed awaited reserve, complete, committed observe, retire and one old retired reserve replay; includes adapter encoding/decoding, allocations, argument ownership/destruction, provenance union, locking, and redb blocking admission/transactions; excludes prefill, key/record/payload construction, expected-value clones, harness consistency checks, usage/RSS sampling, reporting and reopen",
        "prefill": "ordinary committed 1024-byte string outcomes retained without retirement, excluded from timing",
        "memory": "only current-event records and fixed sample identities retained by harness; store identity fingerprints grow; logical charged bytes are not RSS; /proc VmHWM covers the entire process including prefill and verification",
    }))?;
    for sequence in 1..=config.prefill {
        let pending = pending(sequence);
        let expected = pending.value.clone();
        ensure!(
            store.reserve(&key(sequence), pending).await?.is_none(),
            "prefill identity already present"
        );
        store
            .complete(
                &key(sequence),
                expected,
                completed(sequence, PREFILL_PAYLOAD_BYTES),
            )
            .await?;
    }
    checkpoint(&config, store.as_ref(), &charges, 0, 0, &Timing::default()).await?;
    let mut done = 0;
    while done < config.events {
        let end = done.saturating_add(config.report_every).min(config.events);
        let mut timing = Timing::default();
        for event in done..end {
            let sequence = config.prefill + event + 1;
            let key = key(sequence);
            let pending = pending(sequence);
            let expected_pending = pending.value.clone();
            let result = completed(sequence, config.payload_bytes);
            let mut expected_result = result.clone();
            expected_result.taint.union(&pending.taint);
            let start = Instant::now();
            let reserved = store.reserve(&key, pending).await;
            timing.reserve_elapsed_ns += start.elapsed().as_nanos();
            ensure!(reserved?.is_none(), "event identity already present");
            let start = Instant::now();
            let settled = store.complete(&key, expected_pending, result).await;
            timing.complete_elapsed_ns += start.elapsed().as_nanos();
            settled?;
            let start = Instant::now();
            let observed = store.observe(&key).await;
            timing.lookup_elapsed_ns += start.elapsed().as_nanos();
            let observed = observed?.context("committed event missing")?;
            ensure!(
                observed == expected_result,
                "event result or provenance changed"
            );
            drop(expected_result);
            let start = Instant::now();
            let retired = store.retire(&key, observed.value).await;
            timing.retire_elapsed_ns += start.elapsed().as_nanos();
            retired?;
        }
        let old = config.prefill + 1;
        let old_key = key(old);
        let old_pending = pending(old);
        let retained = store
            .observe(&old_key)
            .await?
            .context("old retired identity missing")?;
        ensure!(
            retained
                .value
                .as_map()
                .and_then(|fields| fields.get("state"))
                .and_then(Value::as_str)
                == Some("retired"),
            "old identity did not retire"
        );
        let start = Instant::now();
        let replay = store.reserve(&old_key, old_pending).await;
        timing.replay_reserve_elapsed_ns += start.elapsed().as_nanos();
        ensure!(
            replay? == Some(retained),
            "old retired identity became executable"
        );
        checkpoint(&config, store.as_ref(), &charges, end, end - done, &timing).await?;
        done = end;
    }
    let usage = store.usage().await?;
    verify(store.as_ref(), &config, limits, usage, namespace).await?;
    drop(store);
    let reopened = if let Some(owner) = owner {
        let idle = owner.wait_idle();
        drop(owner);
        idle.await;
        let owner = RedbStore::open(config.db.as_ref().context("redb path missing")?)?;
        let store = owner.gateway_idempotency_store(limits)?;
        verify(&store, &config, limits, usage, namespace).await?;
        true
    } else {
        false
    };
    emit(serde_json::json!({
        "kind": "verified", "reopened": reopened,
        "retired_replay_rejected_execution": true,
        "evidence_namespace_preserved": true,
        "usage": {"records": usage.records, "charged_bytes": usage.bytes},
        "rss_kib": proc_field("VmRSS:")?, "peak_rss_kib": proc_field("VmHWM:")?,
    }))
}
