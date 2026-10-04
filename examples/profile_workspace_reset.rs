//! Targeted reset benchmark. Runs no migration candidates or build commands.
//! Usage: cargo run --example profile_workspace_reset -- BASELINE MANIFEST WORKSPACE TARGET REPEATS

use std::{path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use dtk_migrate::workspace::{
    Manifest, reset_workspace_profiled, seed_build_cache_profiled, seed_objdiff,
};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 5 {
        anyhow::bail!("Usage: profile_workspace_reset BASELINE MANIFEST WORKSPACE TARGET REPEATS");
    }
    let baseline = PathBuf::from(&args[0]);
    let manifest_path = PathBuf::from(&args[1]);
    let workspace = PathBuf::from(&args[2]);
    let target = &args[3];
    let repeats: usize = args[4].parse().context("REPEATS must be a positive integer")?;
    if repeats == 0 {
        anyhow::bail!("REPEATS must be positive");
    }
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    println!(
        "iteration,total_s,manifest_s,baseline_verify_s,restore_s,restored_files,restored_bytes,cache_s,cache_files,cache_bytes,objdiff_s"
    );
    for iteration in 1..=repeats {
        let started = Instant::now();
        let reset = reset_workspace_profiled(&baseline, &workspace, &manifest)?;
        let cache = seed_build_cache_profiled(&baseline, &workspace, target)?;
        let objdiff_started = Instant::now();
        seed_objdiff(&baseline, &workspace)?;
        let objdiff_seconds = objdiff_started.elapsed().as_secs_f64();
        println!(
            "{iteration},{:.3},{:.3},{:.3},{:.3},{},{},{:.3},{},{},{:.3}",
            started.elapsed().as_secs_f64(),
            reset.manifest_seconds,
            reset.baseline_verify_seconds,
            reset.restore_seconds,
            reset.restored_files,
            reset.restored_bytes,
            cache.seconds,
            cache.files,
            cache.bytes,
            objdiff_seconds,
        );
    }
    Ok(())
}
