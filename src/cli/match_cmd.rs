//! `dtk-migrate match` — carry names, splits and coverage evidence from a
//! version that has them to one that does not.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::{
    cli::{native, native_opt},
    matching::{self, Outputs, Request},
};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Source project configuration: the version whose symbol names are known.
    pub source: PathBuf,
    /// Target project configuration: the version to name.
    pub target: PathBuf,
    /// Write the full JSON report here.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    /// Write `target_name = source_name` pairs here. Confident matches only,
    /// meaning the ones safe to apply without review.
    #[arg(short = 'r', long)]
    pub renames: Option<PathBuf>,
    /// Write everything short of confident here, with alternatives, for review.
    /// Never mixed into --renames.
    #[arg(long)]
    pub candidates: Option<PathBuf>,
    /// Write proposed split boundaries here, grouped by unit, in splits.txt
    /// syntax. Candidates are commented out with the reason they fell short.
    #[arg(long)]
    pub splits: Option<PathBuf>,
    /// Write evidence for conservative partial translation-unit coverage here.
    #[arg(long)]
    pub coverage: Option<PathBuf>,
    /// Write source-independent function attribution and TU identification here.
    /// This inventory is produced even when no boundary is safe to apply.
    #[arg(long)]
    pub identifications: Option<PathBuf>,
    /// Minimum confidence for a match to be reported at all.
    #[arg(short = 'c', long, default_value_t = 0.5)]
    pub min_confidence: f32,
    /// Cap on propagation rounds. Propagation stops on its own once a round
    /// finds nothing; raise this only if it reports hitting the cap.
    #[arg(long, default_value_t = 100)]
    pub max_rounds: u32,
    /// Project root the source configuration's relative paths resolve against.
    /// Defaults to the working directory, else the configuration's location.
    #[arg(long)]
    pub source_root: Option<PathBuf>,
    /// The same, for the target configuration.
    #[arg(long)]
    pub target_root: Option<PathBuf>,
    /// Checkout containing objdiff.json and compiled target-version source
    /// objects. Existing objects are read; none are built by this command.
    #[arg(long)]
    pub object_root: Option<PathBuf>,
    /// Ignore the target's existing names while matching, then score the result
    /// against them. Use on an already-named version to measure accuracy.
    #[arg(long)]
    pub validate: bool,
}

pub fn run(args: Args) -> Result<()> {
    matching::run(&Request {
        source_config: native(&args.source)?,
        target_config: native(&args.target)?,
        source_root: native_opt(args.source_root.as_ref())?,
        target_root: native_opt(args.target_root.as_ref())?,
        object_root: args.object_root.clone(),
        min_confidence: args.min_confidence,
        max_rounds: args.max_rounds,
        validate: args.validate,
        mask: Default::default(),
        outputs: Outputs {
            report: args.output,
            renames: args.renames,
            candidates: args.candidates,
            splits: args.splits,
            coverage: args.coverage,
            identifications: args.identifications,
        },
    })
}
