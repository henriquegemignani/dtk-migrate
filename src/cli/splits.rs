//! `dtk-migrate splits merge` — fold a proposal into a project's `splits.txt`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use tracing::{info, warn};

use crate::{cli::native, project::split_merge::merge_splits};

#[derive(ClapArgs, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Merge the confident units of a `match --splits` proposal into a splits
    /// file, in place.
    Merge(MergeArgs),
}

#[derive(ClapArgs, Debug)]
pub struct MergeArgs {
    /// Splits file to update, in place.
    pub splits: PathBuf,
    /// Proposal file, as written by `match --splits`.
    pub proposal: PathBuf,
    /// Report what would change without writing anything.
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Merge(c_args) => merge(c_args),
    }
}

fn merge(args: MergeArgs) -> Result<()> {
    let splits = native(&args.splits)?;
    let proposal = native(&args.proposal)?;
    let report = merge_splits(&splits, &proposal, args.dry_run)
        .with_context(|| format!("While merging {proposal} into {splits}"))?;

    if args.dry_run {
        info!("Would add {} units to {}", report.added.len(), splits);
    } else {
        info!("Added {} units to {}", report.added.len(), splits);
    }
    if !report.already_present.is_empty() {
        warn!(
            "{} proposed units already have a split, left untouched (first: {})",
            report.already_present.len(),
            report.already_present[0]
        );
    }
    Ok(())
}
