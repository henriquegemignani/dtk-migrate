//! Turning two analysed executables into names, splits and coverage evidence.
//!
//! One entry point, [`run`], serves both `dtk-migrate match` and the stages
//! that need proposals mid-run. They were separate processes in the Python,
//! which meant the stage could only read back whatever the command chose to
//! write; here the difference is only which outputs are requested.

use std::{io::Write, path::PathBuf};

use anyhow::Result;
use decomp_toolkit::util::file::buf_writer;
use tracing::info;
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    analysis::{
        coverage::{ExtractCatalogs, build_report as build_coverage_report},
        data_matching::match_data,
        mask::{self, Scenario},
        matching::{MatchOptions, MatchTarget, MatchTier, match_functions},
        ownership::identify_units,
        unit_matching::propose_units,
    },
    matching::{
        proposals::write_unit_proposals,
        report::{Report, ReportMatch, renameable_data},
    },
    project::analyze::{extract_specs, load_analyzed},
};

pub mod proposals;
pub mod report;

/// Which files a run should write. Everything is optional; the matching itself
/// happens either way.
#[derive(Debug, Clone, Default)]
pub struct Outputs {
    pub report: Option<PathBuf>,
    pub renames: Option<PathBuf>,
    pub candidates: Option<PathBuf>,
    pub splits: Option<PathBuf>,
    pub coverage: Option<PathBuf>,
    pub identifications: Option<PathBuf>,
}

/// What to match, and how hard to look.
#[derive(Debug, Clone)]
pub struct Request {
    pub source_config: Utf8NativePathBuf,
    pub target_config: Utf8NativePathBuf,
    pub source_root: Option<Utf8NativePathBuf>,
    pub target_root: Option<Utf8NativePathBuf>,
    pub min_confidence: f32,
    pub max_rounds: u32,
    /// Ignore the target's existing names while matching, then score against
    /// them. Used to measure accuracy on a version that is already named.
    pub validate: bool,
    /// Hide some of the target's split ownership before analysing it, so
    /// calibration can ask for boundaries the project already has. A migration
    /// leaves this at [`Scenario::Nothing`]: it has nothing to hide.
    pub mask: Scenario,
    pub outputs: Outputs,
}

impl Request {
    pub fn new(source_config: Utf8NativePathBuf, target_config: Utf8NativePathBuf) -> Self {
        Self {
            source_config,
            target_config,
            source_root: None,
            target_root: None,
            min_confidence: 0.5,
            max_rounds: 100,
            validate: false,
            mask: Scenario::Nothing,
            outputs: Outputs::default(),
        }
    }
}

pub fn run(request: &Request) -> Result<()> {
    let options = MatchOptions {
        min_confidence: request.min_confidence,
        ignore_names: request.validate,
        max_rounds: request.max_rounds,
        ..Default::default()
    };

    let (source_config, source_obj) =
        load_analyzed(&request.source_config, request.source_root.as_deref(), "--source-root")?;
    let (target_config, mut target_obj) =
        load_analyzed(&request.target_config, request.target_root.as_deref(), "--target-root")?;

    // Before anything reads the target: a scenario that hid ownership after the
    // fact would only be hiding it from whichever reader remembered to ask.
    let masked = mask::apply(&mut target_obj, request.mask);
    if masked.hides_anything() {
        info!(
            "Hid {} of the target's units, scenario {}",
            masked.hidden.len(),
            masked.scenario.as_str()
        );
    }

    let source = MatchTarget::new(request.source_config.to_string(), source_obj);
    let target = MatchTarget::new(request.target_config.to_string(), target_obj);
    info!("Matching {} functions against {} functions", source.graph.len(), target.graph.len());

    let result = match_functions(&source, &target, &options);
    let data_matches = match_data(&source, &target, &result);
    // Identification is an observation layer, so build it before any output
    // chooses eligibility thresholds or attempts a mutation.
    let identifications = identify_units(&source, &target, &result);
    let report = Report::build(&source, &target, &result, request.validate);
    report.print_summary();

    let outputs = &request.outputs;
    if let Some(path) = native(outputs.report.as_ref()) {
        let mut file = buf_writer(&path)?;
        serde_json::to_writer_pretty(&mut file, &report)?;
        file.flush()?;
        info!("Wrote report to {}", path);
    }
    if let Some(path) = native(outputs.renames.as_ref()) {
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
    if let Some(path) = native(outputs.candidates.as_ref()) {
        write_candidates(&path, &report)?;
    }
    if let Some(path) = native(outputs.splits.as_ref()) {
        let proposals = propose_units(&source, &target, &result, &data_matches);
        write_unit_proposals(&path, &target, &proposals)?;
    }
    if let Some(path) = native(outputs.coverage.as_ref()) {
        let source_extracts = extract_specs(&source_config);
        let target_extracts = extract_specs(&target_config);
        let coverage = build_coverage_report(
            &source,
            &target,
            &result,
            identifications.clone(),
            request.validate,
            &masked,
            ExtractCatalogs { source: &source_extracts, target: &target_extracts },
        );
        let mut file = buf_writer(&path)?;
        serde_json::to_writer_pretty(&mut file, &coverage)?;
        file.flush()?;
        info!("Wrote coverage evidence to {}", path);
    }
    if let Some(path) = native(outputs.identifications.as_ref()) {
        let mut file = buf_writer(&path)?;
        serde_json::to_writer_pretty(&mut file, &identifications)?;
        file.flush()?;
        info!("Wrote TU identifications to {}", path);
    }
    Ok(())
}

fn write_candidates(path: &Utf8NativePath, report: &Report) -> Result<()> {
    let mut file = buf_writer(path)?;
    writeln!(file, "# Candidate names: {} -> {}", report.source, report.target)?;
    writeln!(file, "#")?;
    writeln!(file, "# These are NOT confident enough to apply unreviewed. Move a line into the")?;
    writeln!(file, "# renames file once you've confirmed it; delete it otherwise. Lines starting")?;
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
    Ok(())
}

fn native(path: Option<&PathBuf>) -> Option<Utf8NativePathBuf> {
    // Every caller inside the library builds these paths itself, and the CLI
    // has already rejected anything that is not UTF-8.
    path.map(|p| Utf8NativePathBuf::from(p.to_string_lossy().into_owned()))
}
