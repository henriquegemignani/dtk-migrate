use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use tracing::info;

use crate::derive::explore::{self, Request};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Built dtk-template project to inspect. No project files are changed.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    #[arg(long)]
    pub target: String,
    #[arg(long, default_value = "main")]
    pub module: String,
    /// Restrict the inventory by unit prefix, e.g. Kyoto/. Repeat for several.
    #[arg(long)]
    pub unit_prefix: Vec<String>,
    /// JSON inventory of every selected file and every unresolved function.
    #[arg(long)]
    pub report: PathBuf,
    /// Retain the union of this many body matches and this many graph leads per function.
    #[arg(long, default_value_t = 5)]
    pub alternatives: usize,
    /// Report lower-scoring pairs too when callers, references, or vtables support them.
    #[arg(long, default_value_t = 25.0)]
    pub min_percent: f32,
    /// Body-search size ratio; graph-supported pairs bypass this filter.
    #[arg(long, default_value_t = 3.5)]
    pub size_ratio: f64,
    /// Cache measurements by both object contents and the search parameters.
    #[arg(long)]
    pub cache: Option<PathBuf>,
    /// Prior report, used to report resolved and newly encountered functions.
    #[arg(long)]
    pub previous: Option<PathBuf>,
    /// Parallel file comparisons.
    #[arg(long, default_value_t = 4)]
    pub workers: usize,
}

pub fn run(args: Args) -> Result<()> {
    let request = Request {
        root: std::path::absolute(args.project_root)?,
        version: args.target,
        module: args.module,
        prefixes: args.unit_prefix,
        alternatives: args.alternatives,
        min_percent: args.min_percent,
        size_ratio: args.size_ratio,
        cache: args.cache,
        previous: args.previous,
        workers: args.workers,
    };
    let report = explore::run(&request)?;
    std::fs::write(&args.report, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("Failed to write {}", args.report.display()))?;
    info!(
        "{} units, {} unresolved functions, {} with candidates; {} unavailable units; {} cache hits",
        report.units.len(),
        report.unresolved,
        report.with_candidates,
        report.unavailable_units,
        report.cache_hits,
    );
    info!(
        "Candidate evidence is for review; no renames were applied. Report: {}",
        args.report.display()
    );
    Ok(())
}
