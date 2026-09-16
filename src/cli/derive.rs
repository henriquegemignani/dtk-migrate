//! `dtk-migrate derive` — name target symbols from the compiled objects,
//! without running a migration.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use tracing::{info, warn};

use crate::{
    derive::{self, propose::Tier, render_renames},
    project::config::DOL_NAME,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum TierArg {
    /// A body match that scores high and leads clearly, or a call site inside a
    /// name-anchored function whose relocation lists align exactly.
    Confident,
    /// A body match past both thresholds, a call site in a shorter alignment,
    /// or a positional name whose size also agrees.
    Probable,
    /// A positional name whose size disagrees.
    Candidate,
}

impl From<TierArg> for Tier {
    fn from(value: TierArg) -> Self {
        match value {
            TierArg::Confident => Tier::Confident,
            TierArg::Probable => Tier::Probable,
            TierArg::Candidate => Tier::Candidate,
        }
    }
}

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The dtk-template project to read.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    /// The version to name.
    #[arg(long)]
    pub target: String,
    /// Another version's symbols, used to tell a misplaced name apart from a
    /// unit whose source has not been matched yet.
    #[arg(long)]
    pub reference: Option<String>,
    /// The linked module to read, when it is not the main executable.
    #[arg(long, default_value = DOL_NAME)]
    pub module: String,
    /// Derive names for this unit only. Repeat to name more than one.
    #[arg(long)]
    pub unit: Vec<String>,
    /// Examine at most this many units.
    #[arg(long)]
    pub limit: Option<usize>,
    /// How much evidence a name needs before it is written.
    #[arg(long, value_enum, default_value_t = TierArg::Probable)]
    pub tier: TierArg,
    /// Write the rename file here, ready for `symbols rename`.
    #[arg(long, default_value = "renames.txt")]
    pub out: PathBuf,
    /// Also write the full JSON report here.
    #[arg(long)]
    pub report: Option<PathBuf>,
    /// The lowest body-match score worth believing.
    #[arg(long)]
    pub body_percent: Option<f32>,
    /// The smallest lead over the runner-up worth believing.
    #[arg(long)]
    pub body_margin: Option<f32>,
    /// How far two function sizes may differ before a pairing is not scored.
    #[arg(long)]
    pub size_ratio: Option<f64>,
}

pub fn run(args: Args) -> Result<()> {
    let root = std::path::absolute(&args.project_root)?;
    let mut request = derive::Request::new(root, args.target.clone());
    request.module = args.module.clone();
    request.only = args.unit.clone();
    request.limit = args.limit;
    request.reference = args.reference.clone();
    if let Some(percent) = args.body_percent {
        request.limits.percent = percent;
    }
    if let Some(margin) = args.body_margin {
        request.limits.margin = margin;
    }
    if let Some(ratio) = args.size_ratio {
        request.limits.size_ratio = ratio;
    }

    let report = derive::derive(&request)?;
    info!(
        "{} units, {} proposals, {} accepted, {} rejected",
        report.units,
        report.proposed,
        report.accepted.len(),
        report.rejected.len()
    );
    for failure in &report.failures {
        warn!("{}: {}", failure.unit, failure.error);
    }
    for correction in &report.corrections {
        warn!(
            "{} carries {}, which belongs to {}{}",
            correction.unit,
            correction.address_named,
            correction.should_be,
            if correction.contested { " (contested by the reference version)" } else { "" }
        );
    }

    let text = render_renames(&report.accepted, args.tier.into());
    let count = text.lines().filter(|line| !line.trim().is_empty()).count();
    std::fs::write(&args.out, &text)
        .with_context(|| format!("Failed to write {}", args.out.display()))?;
    info!("Wrote {count} renames to {}", args.out.display());

    if let Some(path) = &args.report {
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        info!("Wrote the full report to {}", path.display());
    }
    Ok(())
}
