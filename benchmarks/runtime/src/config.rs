use anyhow::{Context, ensure};
use serde::Serialize;
use std::{io::Write, num::NonZeroUsize, path::PathBuf};

pub const CASES: &[&str] = &[
    "core",
    "resident",
    "portable",
    "hosted",
    "stream",
    "stream-cancel",
    "provider-stream",
    "object-file",
    "state-fact",
];

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Time,
    Heap,
}

#[derive(Serialize)]
pub struct Config {
    pub case: String,
    pub mode: Mode,
    pub samples: NonZeroUsize,
    pub warmup: usize,
    pub work: NonZeroUsize,
    pub width: NonZeroUsize,
    pub depth: NonZeroUsize,
    pub window: NonZeroUsize,
    pub slow_every: NonZeroUsize,
    pub delay_micros: u64,
    pub heap_file: Option<PathBuf>,
}

impl Config {
    pub fn parse() -> anyhow::Result<Option<Self>> {
        let mut config = Self {
            case: "core".into(),
            mode: Mode::Time,
            samples: NonZeroUsize::MIN.saturating_add(19),
            warmup: 1,
            work: NonZeroUsize::MIN.saturating_add(999_999),
            width: NonZeroUsize::MIN.saturating_add(8191),
            depth: NonZeroUsize::MIN.saturating_add(11_999),
            window: NonZeroUsize::MIN.saturating_add(4095),
            slow_every: NonZeroUsize::MIN.saturating_add(63),
            delay_micros: 0,
            heap_file: None,
        };
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--list" {
                let mut out = std::io::stdout().lock();
                for case in CASES {
                    writeln!(out, "{case}")?;
                }
                return Ok(None);
            }
            if flag == "--help" {
                writeln!(
                    std::io::stdout().lock(),
                    "usage: xolotl-runtime-bench --case <{}> --mode <time|heap> [--samples N --warmup N --work N --width N --depth N --window N --slow-every N --delay-micros N --heap-file PATH]; see benchmarks/runtime/README.md",
                    CASES.join("|")
                )?;
                return Ok(None);
            }
            let value = args
                .next()
                .with_context(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--case" => config.case = value,
                "--mode" => {
                    config.mode = match value.as_str() {
                        "time" => Mode::Time,
                        "heap" => Mode::Heap,
                        _ => anyhow::bail!("mode must be time or heap"),
                    }
                }
                "--samples" => config.samples = value.parse()?,
                "--warmup" => config.warmup = value.parse()?,
                "--work" => config.work = value.parse()?,
                "--width" => config.width = value.parse()?,
                "--depth" => config.depth = value.parse()?,
                "--window" => config.window = value.parse()?,
                "--slow-every" => config.slow_every = value.parse()?,
                "--delay-micros" => config.delay_micros = value.parse()?,
                "--heap-file" => {
                    ensure!(!value.is_empty(), "--heap-file requires a nonempty path");
                    config.heap_file = Some(value.into());
                }
                _ => anyhow::bail!("unknown option {flag}"),
            }
        }
        ensure!(
            CASES.contains(&config.case.as_str()),
            "unknown workload {}",
            config.case
        );
        ensure!(
            config.heap_file.is_none() || matches!(config.mode, Mode::Heap),
            "--heap-file is only accepted in heap mode"
        );
        ensure!(
            matches!(config.mode, Mode::Heap) == cfg!(feature = "heap-profile"),
            "time mode requires a build without heap-profile; heap mode requires --features heap-profile"
        );
        Ok(Some(config))
    }
}
