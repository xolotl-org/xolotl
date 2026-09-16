//! Each process measures exactly one workload and one measurement mode.

mod cases;
mod config;
mod harness;

#[cfg(feature = "heap-profile")]
#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

fn main() -> anyhow::Result<()> {
    if let Some(config) = config::Config::parse()? {
        harness::run(config)?;
    }
    Ok(())
}
