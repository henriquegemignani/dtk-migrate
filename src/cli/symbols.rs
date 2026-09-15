//! `dtk-migrate symbols rename` — apply a rename file to a `symbols.txt`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use tracing::{info, warn};
use typed_path::Utf8NativePath;

use crate::{
    cli::native,
    project::symbols::{RenameReport, Renames, apply_renames},
};

#[derive(ClapArgs, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Apply `old_name = new_name` pairs to a symbols file, in place.
    Rename(RenameArgs),
}

#[derive(ClapArgs, Debug)]
pub struct RenameArgs {
    /// Symbols file to rewrite, in place.
    pub symbols: PathBuf,
    /// Rename file, as written by `match --renames` or `--candidates`.
    pub renames: PathBuf,
    /// Report what would change without writing anything.
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Rename(c_args) => rename(c_args),
    }
}

fn rename(args: RenameArgs) -> Result<()> {
    let symbols = native(&args.symbols)?;
    let renames_path = native(&args.renames)?;
    let renames = Renames::read(&renames_path)?;
    info!("Read {} renames from {}", renames.len(), renames_path);

    let report = apply_renames(&symbols, &renames, args.dry_run)
        .with_context(|| format!("While applying renames to {symbols}"))?;
    report_outcome(&report, &symbols, args.dry_run);
    Ok(())
}

pub fn report_outcome(report: &RenameReport, symbols: &Utf8NativePath, dry_run: bool) {
    if dry_run {
        info!("Would rename {} symbols in {}", report.applied, symbols);
    } else {
        info!("Renamed {} symbols in {}", report.applied, symbols);
    }

    if !report.missing.is_empty() {
        warn!(
            "{} names were not found in {} (first: {})",
            report.missing.len(),
            symbols,
            report.missing[0]
        );
    }
    // A collision means the new name is already held by a symbol that isn't
    // being renamed away, so applying it would leave two symbols with one name.
    // Skipping keeps the file unambiguous, which is the point of the exercise.
    for (from, to) in &report.collisions {
        warn!("Skipped {from} -> {to}: '{to}' is already taken by another symbol");
    }
    if !report.collisions.is_empty() {
        warn!("{} renames skipped due to name collisions", report.collisions.len());
    }
}
