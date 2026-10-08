use anyhow::{Context, ensure};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{fs::OpenOptions, io::Write, num::NonZeroUsize, path::PathBuf, sync::Arc, time::Instant};
use xolotl_gateway::{
    Gateway, GatewayIdempotencyLimits, GatewayIdempotencyStore, GatewayPrincipalSurfaceBinding,
    GatewayProfile, GatewayRequestEvidence, GatewayRequestIdentity, GatewayRequestLookup,
    GatewayRequestResultClass, GatewayRetainedRequestResult, GatewayRuntime, GatewaySession,
    GatewaySubmission, GatewaySubmitResult, GatewaySurface, MemoryGatewayIdempotencyStore,
    PresentedCredential, SubmitOptions,
};
use xolotl_kernel::{Bootstrap, EchoDriver, KernelBuilder, MethodSpec};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{CompletionOrigin, MethodAuthority, Outcome, Purity, Value};

const TOKEN: &str = "lookup-benchmark-token-at-least-32-bytes";
const AUTHORITY: &str = "lookup-benchmark.example";
const KEY: &str = "original-echo-request";
const MAX_EVENTS: usize = 1_000_000;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

struct Config {
    backend: &'static str,
    db: Option<PathBuf>,
    events: usize,
    payload_bytes: usize,
}

impl Config {
    fn parse() -> anyhow::Result<Option<Self>> {
        let mut config = Self {
            backend: "memory",
            db: None,
            events: 5000,
            payload_bytes: 1024,
        };
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" {
                writeln!(
                    std::io::stdout().lock(),
                    "usage: gateway_evidence_lookup --backend memory|redb [--db NEW_PATH_UNDER_TARGET] [--events 1..1000000] [--payload-bytes 1..65536]"
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
                "--events" => config.events = value.parse()?,
                "--payload-bytes" => config.payload_bytes = value.parse()?,
                _ => anyhow::bail!("unknown option {flag}"),
            }
        }
        ensure!(
            (1..=MAX_EVENTS).contains(&config.events),
            "events must be 1..={MAX_EVENTS}"
        );
        ensure!(
            (1..=MAX_PAYLOAD_BYTES).contains(&config.payload_bytes),
            "payload-bytes must be 1..={MAX_PAYLOAD_BYTES}"
        );
        if config.backend == "redb" {
            let db = config.db.as_ref().context("--db is required for redb")?;
            let parent = db
                .parent()
                .context("database needs a parent directory")?
                .canonicalize()
                .context("database parent must already exist")?;
            let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target")
                .canonicalize()?;
            ensure!(
                parent.starts_with(&target),
                "database must be under workspace target"
            );
            ensure!(
                !parent.starts_with("/tmp"),
                "database target must not resolve under /tmp"
            );
            config.db = Some(parent.join(db.file_name().context("database needs a file name")?));
        } else {
            ensure!(config.db.is_none(), "--db is only valid for redb");
        }
        Ok(Some(config))
    }
}

fn limits() -> GatewayIdempotencyLimits {
    GatewayIdempotencyLimits {
        max_records: NonZeroUsize::MIN,
        max_bytes: NonZeroUsize::MIN.saturating_add(2 * 1024 * 1024 - 1),
        max_record_bytes: NonZeroUsize::MIN.saturating_add(1024 * 1024 - 1),
    }
}

async fn build_gateway(
    store: Arc<dyn GatewayIdempotencyStore>,
) -> anyhow::Result<(GatewayRuntime, GatewaySession)> {
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend()).build(),
    ));
    let target = boot.register_effect(
        "effect://lookup-benchmark/echo",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(EchoDriver),
    )?;
    let profile = GatewayProfile::new("lookup-benchmark")
        .with_bearer_identity(
            "benchmark-credential",
            "benchmark",
            TOKEN,
            "identity://lookup-benchmark",
        )?
        .with_registered_host(AUTHORITY)?
        .with_surface(GatewaySurface::effect_invoke("echo", target))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "benchmark",
            ["echo"],
            ["perform://effect/lookup-benchmark/echo"],
        ));
    let gateway = GatewayRuntime::new_manual(boot, profile, store)?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(TOKEN))
        .await?;
    gateway.validate_session_authority(&session, AUTHORITY)?;
    Ok((gateway, session))
}

fn verify(evidence: GatewayRequestEvidence, original: &GatewaySubmitResult) -> anyhow::Result<()> {
    let GatewayRequestEvidence::Settled(result) = evidence else {
        anyhow::bail!("original request did not produce Settled evidence");
    };
    ensure!(result.accepted == original.accepted, "acceptance changed");
    ensure!(
        result.unresolved_operations == original.output.unresolved_operations,
        "unresolved effects changed"
    );
    ensure!(
        result.result_class == GatewayRequestResultClass::Done,
        "lookup result class changed"
    );
    drop(result);
    Ok(())
}

fn verify_result(
    retained: GatewayRetainedRequestResult,
    original: &GatewaySubmitResult,
) -> anyhow::Result<()> {
    let GatewayRetainedRequestResult::Available(result) = retained else {
        anyhow::bail!("original request result is unavailable");
    };
    ensure!(result.accepted == original.accepted, "acceptance changed");
    ensure!(result.output == original.output, "retained output changed");
    ensure!(
        result.origin == CompletionOrigin::CachedOutcome,
        "result was not cached"
    );
    Ok(())
}

fn percentile(samples: &[u64], percent: usize) -> u64 {
    samples[(samples.len() * percent).div_ceil(100) - 1]
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Some(config) = Config::parse()? else {
        return Ok(());
    };
    let owner = if let Some(db) = &config.db {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        drop(
            options
                .open(db)
                .context("database path must be new; refusing to overwrite")?,
        );
        Some(RedbStore::open(db)?)
    } else {
        None
    };
    let store: Arc<dyn GatewayIdempotencyStore> = match &owner {
        Some(owner) => Arc::new(owner.gateway_idempotency_store(limits())?),
        None => Arc::new(MemoryGatewayIdempotencyStore::new(limits())?),
    };
    ensure!(store.usage().await?.records == 0, "store must start empty");
    let namespace = store.evidence_namespace()?;
    let (gateway, session) = build_gateway(store.clone()).await?;
    let scope = gateway
        .describe(&session)?
        .surfaces
        .into_iter()
        .find(|surface| surface.surface_id == "echo")
        .context("missing echo surface")?
        .request_scope;
    let epoch = gateway.retry_epoch(&session).await?;
    let payload = Value::string("x".repeat(config.payload_bytes));
    let original = gateway
        .submit(
            &session,
            GatewaySubmission::direct_input("echo", payload.clone()).with_options(SubmitOptions {
                idempotency_key: Some(KEY.into()),
                expected_request_scope: Some(scope.clone()),
                retry_epoch: epoch,
                ..SubmitOptions::default()
            }),
        )
        .await?;
    ensure!(
        original.output.outcome == Outcome::Done(payload),
        "Echo did not return the input"
    );
    ensure!(
        original.origin == CompletionOrigin::CurrentAttempt,
        "initial submission was not executed"
    );
    let lookup = GatewayRequestLookup {
        surface_id: "echo".into(),
        expected_request_scope: scope.clone(),
        retry_epoch: epoch,
        identity: GatewayRequestIdentity::IdempotencyKey(KEY.into()),
    };
    let usage = store.usage().await?;
    ensure!(
        usage.records == 1,
        "submission must retain exactly one identity"
    );
    verify(
        gateway.lookup_request(&session, lookup.clone()).await?,
        &original,
    )?;
    let mut samples = Vec::<u64>::with_capacity(config.events);
    let mut result_samples = Vec::<u64>::with_capacity(config.events);
    let loop_started = Instant::now();
    for _ in 0..config.events {
        let started = Instant::now();
        let evidence = gateway.lookup_request(&session, lookup.clone()).await?;
        let elapsed =
            u64::try_from(started.elapsed().as_nanos()).context("lookup duration overflow")?;
        verify(evidence, &original)?;
        samples.push(elapsed);
        let started = Instant::now();
        let retained = gateway
            .read_retained_request_result(&session, lookup.clone())
            .await?;
        let elapsed =
            u64::try_from(started.elapsed().as_nanos()).context("result duration overflow")?;
        verify_result(retained, &original)?;
        result_samples.push(elapsed);
    }
    let loop_elapsed_ns = loop_started.elapsed().as_nanos();
    ensure!(
        store.usage().await? == usage,
        "lookup changed request storage usage"
    );
    ensure!(
        gateway.retry_epoch(&session).await? == epoch,
        "lookup advanced epoch"
    );
    ensure!(
        store.evidence_namespace()? == namespace,
        "lookup changed namespace"
    );
    drop(session);
    drop(gateway);
    let reopened_owner;
    let reopened_store: Arc<dyn GatewayIdempotencyStore>;
    if let Some(db) = &config.db {
        drop(store);
        drop(owner);
        reopened_owner = Some(RedbStore::open(db)?);
        reopened_store = Arc::new(
            reopened_owner
                .as_ref()
                .context("missing reopened owner")?
                .gateway_idempotency_store(limits())?,
        );
    } else {
        reopened_owner = None;
        reopened_store = store;
    }
    ensure!(
        reopened_store.evidence_namespace()? == namespace,
        "reopen changed namespace"
    );
    let (reopened_gateway, reopened_session) = build_gateway(reopened_store.clone()).await?;
    let reopened_scope = reopened_gateway
        .describe(&reopened_session)?
        .surfaces
        .into_iter()
        .find(|surface| surface.surface_id == "echo")
        .context("missing reopened surface")?
        .request_scope;
    ensure!(reopened_scope == scope, "reopen changed original scope");
    verify(
        reopened_gateway
            .lookup_request(&reopened_session, lookup.clone())
            .await?,
        &original,
    )?;
    verify_result(
        reopened_gateway
            .read_retained_request_result(&reopened_session, lookup)
            .await?,
        &original,
    )?;
    ensure!(
        reopened_store.usage().await? == usage,
        "reopen changed usage"
    );
    ensure!(
        reopened_gateway.retry_epoch(&reopened_session).await? == epoch,
        "reopen advanced epoch"
    );
    samples.sort_unstable();
    result_samples.sort_unstable();
    let total_ns: u128 = samples.iter().map(|sample| u128::from(*sample)).sum();
    let result_total_ns: u128 = result_samples
        .iter()
        .map(|sample| u128::from(*sample))
        .sum();
    let report = serde_json::json!({
        "format": 1, "case": "native-gateway-evidence-lookup", "backend": config.backend,
        "events": config.events, "payload_bytes": config.payload_bytes, "db": config.db,
        "latency_ns": {"p50": percentile(&samples, 50), "p95": percentile(&samples, 95), "total": total_ns},
        "retained_result_latency_ns": {"p50": percentile(&result_samples, 50), "p95": percentile(&result_samples, 95), "total": result_total_ns},
        "loop_elapsed_ns": loop_elapsed_ns, "sample_bytes": (samples.len() + result_samples.len()) * size_of::<u64>(),
        "usage": {"records": usage.records, "charged_bytes": usage.bytes}, "retry_epoch": epoch,
        "verified": true, "reopen_verified": true,
        "reopen_kind": if reopened_owner.is_some() { "redb-close-open" } else { "memory-owner-reattach" },
        "debug_assertions": cfg!(debug_assertions), "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
    });
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.write_all(b"\n")?;
    Ok(())
}
