use crate::{cases::Case, config::Config};
use anyhow::ensure;
use serde::Serialize;
use std::io::Write;
#[cfg(not(feature = "heap-profile"))]
use std::time::Instant;

#[derive(Serialize)]
struct Report<'a, T> {
    format: u32,
    config: &'a Config,
    target_arch: &'static str,
    target_os: &'static str,
    heap_instrumented: bool,
    measurement: T,
}

#[cfg(not(feature = "heap-profile"))]
#[derive(Serialize)]
struct Timing {
    sample_kind: &'static str,
    measured_samples: usize,
    work_units_per_sample: u64,
    work_unit: &'static str,
    elapsed_seconds: f64,
    work_units_per_second: f64,
    latency_p50_ns: u128,
    latency_p95_ns: u128,
    latency_p99_ns: u128,
}

pub fn run(config: Config) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut case = Case::new(&config)?;
    for _ in 0..config.warmup {
        case.run_sample(&runtime, &config)?;
    }
    #[cfg(feature = "heap-profile")]
    {
        heap(config, runtime, case)
    }
    #[cfg(not(feature = "heap-profile"))]
    {
        let mut samples = Vec::with_capacity(config.samples.get());
        let mut work = None;
        let mut elapsed = std::time::Duration::ZERO;
        for _ in 0..config.samples.get() {
            let start = Instant::now();
            let completed = case.run_sample(&runtime, &config)?;
            let time = start.elapsed();
            ensure!(
                work.is_none_or(|previous| previous == completed),
                "sample semantics changed"
            );
            work = Some(completed);
            elapsed += time;
            samples.push(time.as_nanos());
        }
        let work = work.ok_or_else(|| anyhow::anyhow!("no measured samples"))?;
        samples.sort_unstable();
        // Evaluate the rank without overflowing for a large sample count.
        let quantile = |percent: usize| {
            let rank = (samples.len() as u128 * percent as u128).div_ceil(100);
            samples[(rank - 1) as usize]
        };
        let timing = Timing {
            sample_kind: "complete workload, including its owner release",
            measured_samples: samples.len(),
            work_units_per_sample: work.units,
            work_unit: work.unit,
            elapsed_seconds: elapsed.as_secs_f64(),
            work_units_per_second: (work.units as f64 * samples.len() as f64)
                / elapsed.as_secs_f64(),
            latency_p50_ns: quantile(50),
            latency_p95_ns: quantile(95),
            latency_p99_ns: quantile(99),
        };
        output(&config, timing)
    }
}

fn output<T: Serialize>(config: &Config, measurement: T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(
        &mut out,
        &Report {
            format: 1,
            config,
            target_arch: std::env::consts::ARCH,
            target_os: std::env::consts::OS,
            heap_instrumented: cfg!(feature = "heap-profile"),
            measurement,
        },
    )?;
    writeln!(out)?;
    Ok(())
}

#[cfg(feature = "heap-profile")]
fn heap(config: Config, runtime: tokio::runtime::Runtime, mut case: Case) -> anyhow::Result<()> {
    #[derive(Serialize)]
    struct Heap {
        scope: &'static str,
        samples: usize,
        total_allocations: u64,
        total_allocated_bytes: u64,
        peak_live_allocations: usize,
        peak_live_bytes: usize,
        live_allocations_after_samples: usize,
        live_bytes_after_samples: usize,
        live_allocations_after_teardown: usize,
        live_bytes_after_teardown: usize,
    }
    let builder = dhat::Profiler::builder();
    let profiler = match &config.heap_file {
        // Diagnostic profiles retain complete stacks, including allocations
        // first made during fixture/runtime teardown. Measurement boundaries
        // remain identical to the ordinary aggregate-only heap run.
        Some(path) => builder.file_name(path).trim_backtraces(None).build(),
        None => builder.testing().trim_backtraces(Some(4)).build(),
    };
    for _ in 0..config.samples.get() {
        case.run_sample(&runtime, &config)?;
    }
    let returned = dhat::HeapStats::get();
    if config.case == "core" {
        ensure!(returned.total_blocks == 0, "core control allocated");
    }
    drop(case);
    drop(runtime);
    let released = dhat::HeapStats::get();
    let heap = Heap {
        scope: "allocations after fixture and warmup; final live heap after fixture and runtime teardown",
        samples: config.samples.get(),
        total_allocations: returned.total_blocks,
        total_allocated_bytes: returned.total_bytes,
        peak_live_allocations: returned.max_blocks,
        peak_live_bytes: returned.max_bytes,
        live_allocations_after_samples: returned.curr_blocks,
        live_bytes_after_samples: returned.curr_bytes,
        live_allocations_after_teardown: released.curr_blocks,
        live_bytes_after_teardown: released.curr_bytes,
    };
    drop(profiler);
    output(&config, heap)
}
