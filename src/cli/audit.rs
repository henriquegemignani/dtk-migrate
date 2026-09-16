//! `dtk-migrate audit` — what the existing splits already get wrong.
//!
//! Nothing here is acted on. These are the blind spots every stage shares: a
//! unit that owns any range counts as represented, so nothing looks for its real
//! one, and a module nobody has begun splitting is invisible to the whole
//! pipeline.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Serialize;

use crate::project::audit;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The dtk-template project to read.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    /// The version whose splits are the yardstick.
    #[arg(long)]
    pub source: String,
    /// The version being audited.
    #[arg(long)]
    pub target: String,
    /// The section to compare sizes in.
    #[arg(long, default_value = ".text")]
    pub section: String,
    /// Write the findings here as JSON instead of printing them.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct Findings {
    stunted_splits: Vec<audit::Stunted>,
    unsplit_modules: Vec<audit::UnsplitModule>,
    relocated_units: Vec<audit::RelocatedUnit>,
}

pub fn run(args: Args) -> Result<()> {
    let root = std::path::absolute(&args.project_root)?;
    let findings = Findings {
        stunted_splits: audit::audit_modules(&root, &args.source, &args.target, &args.section)?,
        unsplit_modules: audit::unsplit_modules(&root, &args.source, &args.target)?,
        relocated_units: audit::relocated_units(&root, &args.source, &args.target)?,
    };

    if let Some(path) = &args.output {
        std::fs::write(path, serde_json::to_vec_pretty(&findings)?)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        println!("Wrote the audit to {}", path.display());
        return Ok(());
    }

    println!("# Split audit: {} against {}\n", args.target, args.source);

    println!("## Stunted splits\n");
    if findings.stunted_splits.is_empty() {
        println!("None. Every split claims a plausible share of its unit.\n");
    } else {
        println!(
            "{} units claim less than half the bytes the same unit claims in {}. A range this \
             small is usually built on a symbol several source objects define, so the two \
             versions' linkers placed it in different units and matching its name proved nothing \
             about ownership.\n",
            findings.stunted_splits.len(),
            args.source
        );
        for entry in findings.stunted_splits.iter().take(30) {
            let module = entry.module.as_deref().unwrap_or("main");
            println!(
                "- {} [{module}] claims {} of {} bytes ({:.1}%)",
                entry.unit,
                entry.claimed_bytes,
                entry.expected_bytes,
                entry.ratio * 100.0
            );
        }
        if findings.stunted_splits.len() > 30 {
            println!("- …and {} more", findings.stunted_splits.len() - 30);
        }
        println!();
    }

    println!("## Modules with no splits at all\n");
    if findings.unsplit_modules.is_empty() {
        println!("None.\n");
    } else {
        for entry in &findings.unsplit_modules {
            println!(
                "- {} (against {}): {} units and {} code bytes in the source version; {}",
                entry.module,
                entry.against,
                entry.source_units,
                entry.source_code_bytes,
                if entry.built {
                    "the version does build it"
                } else {
                    "the version does not build it, so no stage could see it anyway"
                }
            );
        }
        println!();
    }

    println!("## Units that changed module\n");
    if findings.relocated_units.is_empty() {
        println!("None.");
    } else {
        println!(
            "Reported rather than acted on: whether a move is real or an artefact of one side \
             being unsplit cannot be told from splits alone.\n"
        );
        for entry in &findings.relocated_units {
            println!("- {}: {} → {}", entry.unit, entry.source_module, entry.target_module);
        }
    }
    Ok(())
}
