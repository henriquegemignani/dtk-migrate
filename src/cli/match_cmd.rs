//! `dtk-migrate match` — carry names, splits and coverage evidence from a
//! version that has them to one that does not.

use std::{io::Write, path::PathBuf};

use anyhow::Result;
use clap::Args as ClapArgs;
use decomp_toolkit::util::file::buf_writer;
use tracing::info;

use crate::{
    analysis::{
        coverage::build_report as build_coverage_report,
        data_matching::match_data,
        matching::{MatchOptions, MatchTarget, MatchTier, match_functions},
        unit_matching::propose_units,
    },
    cli::{native, native_opt},
    matching::{
        proposals::write_unit_proposals,
        report::{Report, ReportMatch, renameable_data},
    },
    project::analyze::{extract_specs, load_analyzed},
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
    /// Ignore the target's existing names while matching, then score the result
    /// against them. Use on an already-named version to measure accuracy.
    #[arg(long)]
    pub validate: bool,
}

pub fn run(args: Args) -> Result<()> {
    let options = MatchOptions {
        min_confidence: args.min_confidence,
        ignore_names: args.validate,
        max_rounds: args.max_rounds,
        ..Default::default()
    };

    let source_path = native(&args.source)?;
    let target_path = native(&args.target)?;
    let (source_config, source_obj) = load_analyzed(
        &source_path,
        native_opt(args.source_root.as_ref())?.as_deref(),
        "--source-root",
    )?;
    let (target_config, target_obj) = load_analyzed(
        &target_path,
        native_opt(args.target_root.as_ref())?.as_deref(),
        "--target-root",
    )?;

    let source = MatchTarget::new(source_path.to_string(), source_obj);
    let target = MatchTarget::new(target_path.to_string(), target_obj);
    info!("Matching {} functions against {} functions", source.graph.len(), target.graph.len());

    let result = match_functions(&source, &target, &options);
    let data_matches = match_data(&source, &target, &result);
    let report = Report::build(&source, &target, &result, args.validate);
    report.print_summary();

    if let Some(path) = native_opt(args.output.as_ref())? {
        let mut file = buf_writer(&path)?;
        serde_json::to_writer_pretty(&mut file, &report)?;
        file.flush()?;
        info!("Wrote report to {}", path);
    }
    if let Some(path) = native_opt(args.renames.as_ref())? {
        let mut file = buf_writer(&path)?;
        let mut count = 0;
        for m in report.renameable().filter(|m| m.tier == MatchTier::Confident) {
            write!(file, "{} = {}", m.target_name, m.source_name)?;
            if m.source_local {
                write!(file, " local")?;
            }
            writeln!(file)?;
            count += 1;
        }
        let mut data_count = 0;
        for dm in renameable_data(&source, &target, &data_matches) {
            write!(
                file,
                "{} = {}",
                target.symbol_name_at(dm.target),
                source.symbol_name_at(dm.source)
            )?;
            if source.is_local_at(dm.source) {
                write!(file, " local")?;
            }
            writeln!(file)?;
            data_count += 1;
        }
        file.flush()?;
        info!("Wrote {} confident renames ({} data) to {}", count + data_count, data_count, path);
    }
    if let Some(path) = native_opt(args.candidates.as_ref())? {
        let mut file = buf_writer(&path)?;
        writeln!(file, "# Candidate names: {} -> {}", report.source, report.target)?;
        writeln!(file, "#")?;
        writeln!(
            file,
            "# These are NOT confident enough to apply unreviewed. Move a line into the"
        )?;
        writeln!(
            file,
            "# renames file once you've confirmed it; delete it otherwise. Lines starting"
        )?;
        writeln!(file, "# with '#' are alternatives that lost, kept so you can see what else it")?;
        writeln!(file, "# could have been.")?;
        writeln!(file)?;

        // Strongest tier first, then by confidence, so a reviewer working top to
        // bottom hits the most likely names first and can stop when quality drops.
        let mut pending: Vec<&ReportMatch> =
            report.renameable().filter(|m| m.tier != MatchTier::Confident).collect();
        pending.sort_by(|a, b| {
            a.tier
                .cmp(&b.tier)
                .then(b.confidence.total_cmp(&a.confidence))
                .then(a.target_address.cmp(&b.target_address))
        });

        let mut count = 0;
        for m in pending {
            let local = if m.source_local { " local" } else { "" };
            writeln!(
                file,
                "{} = {}{local}  # {} {:.2} {}",
                m.target_name,
                m.source_name,
                m.tier.as_str(),
                m.confidence,
                m.method
            )?;
            if let Some(alternative) = &m.alternative {
                writeln!(
                    file,
                    "#{:>width$} = {}  # alternative, {:.0}% as strong",
                    "alt",
                    alternative.name,
                    alternative.relative_score * 100.0,
                    width = m.target_name.len().saturating_sub(1)
                )?;
            }
            count += 1;
        }
        file.flush()?;
        info!("Wrote {} candidates to {}", count, path);
    }
    if let Some(path) = native_opt(args.splits.as_ref())? {
        let proposals = propose_units(&source, &target, &result, &data_matches);
        write_unit_proposals(&path, &target, &proposals)?;
    }
    if let Some(path) = native_opt(args.coverage.as_ref())? {
        let source_extracts = extract_specs(&source_config);
        let target_extracts = extract_specs(&target_config);
        let coverage = build_coverage_report(
            &source,
            &target,
            &result,
            args.validate,
            &source_extracts,
            &target_extracts,
        );
        let mut file = buf_writer(&path)?;
        serde_json::to_writer_pretty(&mut file, &coverage)?;
        file.flush()?;
        info!("Wrote coverage evidence to {}", path);
    }
    Ok(())
}
