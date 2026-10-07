//! `dtk-migrate symbols rename` — apply a rename file to a `symbols.txt`.

use std::{path::PathBuf, process::Command as Process};

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use tracing::{info, warn};
use typed_path::Utf8NativePath;

use crate::{
    cli::native,
    project::{
        rename_sync::{self, Skipped},
        symbols::{RenameReport, Renames, apply_renames, read_symbols},
    },
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
    /// Carry renames the source version made over a commit range into the
    /// target version's symbols.
    Sync(SyncArgs),
}

#[derive(ClapArgs, Debug)]
pub struct SyncArgs {
    /// The project's git checkout, which holds both versions' `config/`.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    /// The version whose symbols were renamed.
    #[arg(long)]
    pub source: String,
    /// The version to carry the renames into.
    #[arg(long)]
    pub target: String,
    /// The source's revision before the renames. Together with `--to`, or
    /// instead of both, `--range A..B`.
    #[arg(long, requires = "to_or_default", conflicts_with = "range")]
    pub from: Option<String>,
    /// The revision after the renames: a commit, or `WORKTREE` for the file as
    /// it is on disk.
    #[arg(long, default_value = "HEAD", id = "to_or_default")]
    pub to: String,
    /// A git range, `A..B`: the source's symbols at `A` against `B`.
    #[arg(long)]
    pub range: Option<String>,
    /// A symbols file under `config/<version>/`; repeat for REL modules, e.g.
    /// `rels/Foo/symbols.txt`.
    #[arg(long = "file", default_value = "symbols.txt")]
    pub files: Vec<String>,
    /// Write the target's symbols. Without this, only report.
    #[arg(long)]
    pub apply: bool,
    /// Also write the resolved `old = new` pairs here, for review.
    #[arg(long)]
    pub renames: Option<PathBuf>,
    /// Write the source renames that found nothing to rename in the target.
    #[arg(long)]
    pub unresolved: Option<PathBuf>,
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
        Command::Sync(c_args) => sync(c_args),
    }
}

/// A file at a revision, read through git so the working tree is untouched.
fn git_show(root: &std::path::Path, revision: &str, path: &str) -> Result<String> {
    if revision == "WORKTREE" {
        let file = root.join(path);
        return std::fs::read_to_string(&file)
            .with_context(|| format!("While reading {}", file.display()));
    }
    // `./` makes the path relative to the project root rather than the
    // repository root, which differs when the project is a subdirectory.
    let output = Process::new("git")
        .arg("-C")
        .arg(root)
        .arg("show")
        .arg(format!("{revision}:./{path}"))
        .output()
        .context("While running git")?;
    anyhow::ensure!(
        output.status.success(),
        "git show {revision}:{path} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).with_context(|| format!("{path} at {revision} is not UTF-8"))
}

fn sync(args: SyncArgs) -> Result<()> {
    let (from, to) = match (&args.range, &args.from) {
        (Some(range), _) => {
            let (from, to) = range
                .split_once("..")
                .filter(|(from, to)| !from.is_empty() && !to.is_empty() && !to.starts_with('.'))
                .with_context(|| format!("Expected a range like A..B, got '{range}'"))?;
            (from.to_string(), to.to_string())
        }
        (None, Some(from)) => (from.clone(), args.to.clone()),
        (None, None) => anyhow::bail!("Name the source's earlier revision with --from or --range"),
    };

    let mut applied_total = 0;
    let mut pairs = String::new();
    let mut unresolved = String::new();
    for file in &args.files {
        let source_path = format!("config/{}/{file}", args.source);
        let target_path = format!("config/{}/{file}", args.target);
        let changes = rename_sync::source_renames(
            &git_show(&args.project_root, &from, &source_path)?,
            &git_show(&args.project_root, &to, &source_path)?,
        );
        let target = native(&args.project_root.join(&target_path))?;
        let plan = rename_sync::plan(changes, &read_symbols(&target)?)?;

        let count =
            |wanted: fn(&Skipped) -> bool| plan.skipped.iter().filter(|s| wanted(s)).count();
        info!(
            "{file}: {} renamed in {}; {} apply to {}, {} already there, {} not in the target, {} ambiguous in the target, {} colliding",
            args.source,
            args.range.as_deref().unwrap_or(&format!("{from}..{to}")),
            plan.applied.len(),
            args.target,
            count(|s| matches!(s, Skipped::AlreadyApplied(_))),
            count(|s| matches!(s, Skipped::NotInTarget(_))),
            count(|s| matches!(s, Skipped::AmbiguousInTarget(_))),
            count(|s| matches!(s, Skipped::DuplicateNewName(_))),
        );
        if !plan.ambiguous_places.is_empty() {
            warn!(
                "{file}: {} places hold several symbols and changed names; none was paired",
                plan.ambiguous_places.len()
            );
        }
        for rename in &plan.applied {
            pairs.push_str(&format!(
                "{} = {}{}
",
                rename.old,
                rename.new,
                if rename.local { " local" } else { "" }
            ));
        }
        for skipped in &plan.skipped {
            let (reason, rename) = match skipped {
                Skipped::NotInTarget(r) => ("not in target", r),
                Skipped::AmbiguousInTarget(r) => ("ambiguous in target", r),
                Skipped::DuplicateNewName(r) => ("duplicate new name", r),
                Skipped::AlreadyApplied(_) => continue,
            };
            unresolved.push_str(&format!(
                "{} = {} # {file} {}:{:#X} {reason}
",
                rename.old, rename.new, rename.section, rename.address
            ));
        }
        let report = apply_renames(&target, &plan.renames, !args.apply)
            .with_context(|| format!("While applying renames to {target}"))?;
        applied_total += report.applied;
        report_outcome(&report, &target, !args.apply);
    }
    if let Some(path) = &args.renames {
        std::fs::write(path, pairs).with_context(|| format!("While writing {}", path.display()))?;
    }
    if let Some(path) = &args.unresolved {
        std::fs::write(path, unresolved)
            .with_context(|| format!("While writing {}", path.display()))?;
    }
    info!("{applied_total} renames {}", if args.apply { "applied" } else { "would apply" });
    Ok(())
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
