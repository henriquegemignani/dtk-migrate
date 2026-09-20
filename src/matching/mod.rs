//! Turning two analysed executables into names, splits and coverage evidence.
//!
//! One entry point, [`run`], serves both `dtk-migrate match` and the stages
//! that need proposals mid-run. They were separate processes in the Python,
//! which meant the stage could only read back whatever the command chose to
//! write; here the difference is only which outputs are requested.

use std::{
    collections::BTreeSet,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use decomp_toolkit::util::file::buf_writer;
use tracing::info;
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    analysis::{
        coverage::{ExtractCatalogs, build_report as build_coverage_report},
        mask::{self, Scenario},
        matching::{MatchOptions, MatchTier},
        object_evidence,
        ownership::identify_units,
        unit_matching::propose_units,
    },
    matching::{
        data_evidence::DataEvidenceReport,
        proposals::write_unit_proposals,
        report::{Report, ReportMatch, renameable_data},
    },
    project::analyze::{extract_specs, load_analyzed},
};

mod cache;
pub mod data_evidence;
pub mod proposals;
pub mod report;

pub(crate) use cache::{CacheUse, MatchingCache};

/// Which files a run should write. Everything is optional; the matching itself
/// happens either way.
#[derive(Debug, Clone, Default)]
pub struct Outputs {
    pub report: Option<PathBuf>,
    pub renames: Option<PathBuf>,
    pub candidates: Option<PathBuf>,
    pub splits: Option<PathBuf>,
    pub data_evidence: Option<PathBuf>,
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
    /// Optional checkout containing objdiff.json and existing compiled source
    /// objects. Missing objects remain an unavailable evidence channel.
    pub object_root: Option<PathBuf>,
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
            object_root: None,
            min_confidence: 0.5,
            max_rounds: 100,
            validate: false,
            mask: Scenario::Nothing,
            outputs: Outputs::default(),
        }
    }
}

pub fn run(request: &Request) -> Result<()> {
    let mut cache = MatchingCache::default();
    run_with_cache(request, &mut cache).map(|_| ())
}

pub(crate) fn run_with_cache(request: &Request, cache: &mut MatchingCache) -> Result<CacheUse> {
    let object_root = request
        .object_root
        .as_ref()
        .map(|root| check_object_root(root, &request.target_config).map(|version| (root, version)))
        .transpose()?;
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

    let prepared = cache.prepare(
        request.source_config.to_string(),
        request.target_config.to_string(),
        source_obj,
        target_obj,
        &options,
    );
    let source = prepared.source.as_ref();
    let target = prepared.target.as_ref();
    info!("Matching {} functions against {} functions", source.graph.len(), target.graph.len());
    info!("Function matching cache: {:?}", prepared.cache_use);
    let result = prepared.result.as_ref();
    let data_matches = prepared.data_matches.as_ref();
    // Identification is an observation layer, so build it before any output
    // chooses eligibility thresholds or attempts a mutation.
    let mut identifications = identify_units(source, target, result);
    if let Some((root, version)) = &object_root {
        let units = identifications.units.iter().map(|item| item.unit.clone()).collect();
        let target_hashes: BTreeSet<String> = identifications
            .target_functions
            .iter()
            .filter_map(|item| item.normalized_body_sha256.clone())
            .collect();
        let mut evidence = object_evidence::inspect(root, version, &units, &target_hashes);
        if evidence.status == object_evidence::ScanStatus::Scanned {
            evidence.target_image_sha256 = Some(object_evidence::target_image_digest(target));
        }
        let validated = evidence.canonicalize(&units, &target_hashes, true).and_then(|()| {
            evidence.target_references = object_evidence::capture_target_references(
                target,
                &identifications.target_functions,
                &evidence.definitions,
            );
            evidence.canonicalize_target_references(&identifications.target_functions)
        });
        if let Err(error) = validated {
            tracing::warn!("Compiled-object inventory is unavailable: {error}");
            evidence = object_evidence::ObjectEvidence::unavailable(
                object_evidence::ScanStatus::InvalidObjectInventory,
            );
        }
        evidence.relocation_matches = object_evidence::relocation_matches(
            &evidence,
            &identifications.target_functions,
            &identifications.attributions,
        );
        evidence.order_matches = object_evidence::order_matches(
            &evidence,
            &identifications.target_functions,
            &identifications.attributions,
        );
        evidence.emitted_owners = object_evidence::emitted_owner_resolutions(
            &evidence,
            &units,
            &identifications.source_functions,
            &identifications.target_functions,
            &identifications.attributions,
        );
        evidence.relocation_placements = object_evidence::relocation_placements(
            &evidence,
            &units,
            &identifications.source_functions,
            &identifications.target_functions,
            &identifications.attributions,
        );
        evidence.source_bridges = object_evidence::compiled_source_bridges(
            &evidence,
            &units,
            &identifications.source_functions,
            &identifications.target_functions,
            &identifications.attributions,
        );
        identifications.object_evidence = Some(evidence);
        let compiled = &identifications.object_evidence.as_ref().unwrap().definitions;
        identifications.helper_families = crate::analysis::helpers::families_with_inventory(
            &identifications.source_functions,
            &identifications.target_functions,
            compiled,
        );
        identifications.helper_tail_hypotheses = crate::analysis::helpers::tail_hypotheses(
            &identifications.source_functions,
            &identifications.target_functions,
            &identifications.attributions,
            compiled,
        );
    }
    let report = Report::build(source, target, result, request.validate);
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
        for dm in renameable_data(source, target, data_matches) {
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
    if outputs.splits.is_some() || outputs.data_evidence.is_some() {
        let proposals = propose_units(source, target, result, data_matches);
        let version = |config: &Utf8NativePath| -> String {
            Path::new(config.as_str())
                .parent()
                .and_then(Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let mut evidence = DataEvidenceReport::build(
            source,
            target,
            data_matches,
            &proposals,
            &version(&request.source_config),
            &version(&request.target_config),
        );
        evidence.add_compiled_bss(
            source,
            target,
            identifications.object_evidence.as_ref(),
            object_root.as_ref().map(|(root, _)| root.as_path()),
        );
        if let Some(path) = native(outputs.splits.as_ref()) {
            write_unit_proposals(&path, target, &proposals, &evidence)?;
        }
        if let Some(path) = native(outputs.data_evidence.as_ref()) {
            let mut file = buf_writer(&path)?;
            serde_json::to_writer_pretty(&mut file, &evidence)?;
            file.flush()?;
            info!("Wrote data range evidence to {}", path);
        }
    }
    if let Some(path) = native(outputs.coverage.as_ref()) {
        let source_extracts = extract_specs(&source_config);
        let target_extracts = extract_specs(&target_config);
        let coverage = build_coverage_report(
            source,
            target,
            result,
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
    Ok(prepared.cache_use)
}

fn check_object_root(object_root: &Path, target_config: &Utf8NativePath) -> Result<String> {
    let config_path = PathBuf::from(target_config.as_str());
    let Some(config_dir) = config_path.parent().and_then(Path::parent) else {
        bail!("--object-root requires a target config in <checkout>/config/<version>/config.yml");
    };
    if config_path.file_name().is_none_or(|name| name != "config.yml")
        || config_dir.file_name().is_none_or(|name| name != "config")
    {
        bail!("--object-root requires a target config in <checkout>/config/<version>/config.yml");
    }
    let Some(version) = config_path.parent().and_then(Path::file_name) else {
        bail!("--object-root requires a target version directory");
    };
    let Some(expected) = config_dir.parent() else {
        bail!("Cannot locate the target checkout for --object-root");
    };
    let expected = if expected.as_os_str().is_empty() { Path::new(".") } else { expected };
    if object_root.canonicalize()? != expected.canonicalize()? {
        bail!("--object-root must be the same checkout as the target configuration");
    }
    Ok(version.to_string_lossy().into_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_evidence_cannot_come_from_a_different_checkout() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let config = first.path().join("config").join("PAL").join("config.yml");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let config = Utf8NativePathBuf::from(config.to_str().unwrap());
        assert_eq!(check_object_root(first.path(), &config).unwrap(), "PAL");
        assert!(check_object_root(second.path(), &config).is_err());
        let current = std::env::current_dir().unwrap();
        assert!(check_object_root(&current, Utf8NativePath::new("config/PAL/config.yml")).is_ok());
    }
}
