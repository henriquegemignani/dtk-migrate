//! Corroborate cross-version name candidates with relocation-aware objdiffs.
//! Function views are built in memory, so target ownership need not exist yet.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use objdiff_core::diff::DiffSide;
use serde::{Deserialize, Serialize};
use typed_path::Utf8NativePathBuf;

use crate::{
    analysis::{
        callgraph::NodeIndex,
        matching::{MatchOptions, MatchTarget, MatchTier, match_functions},
    },
    derive::{
        Request,
        body::{self, Ranked},
        objects::Compiled,
        propose::{self, Proposal, Tier},
        unit_key,
    },
    project::{analyze::load_analyzed, config},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredName {
    pub name: String,
    pub percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonStatus {
    Decisive,
    Ambiguous,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub status: ComparisonStatus,
    pub candidates: Vec<ScoredName>,
    pub winner: Option<String>,
    pub margin: Option<f32>,
    pub reason: Option<String>,
}

impl Comparison {
    fn unavailable(reason: impl ToString) -> Self {
        Self {
            status: ComparisonStatus::Unavailable,
            candidates: Vec::new(),
            winner: None,
            margin: None,
            reason: Some(reason.to_string()),
        }
    }

    fn scored(mut scores: Vec<ScoredName>, request: &Request) -> Self {
        if scores.is_empty() {
            return Self::unavailable("No size-compatible function bodies");
        }
        scores.sort_by(|a, b| b.percent.total_cmp(&a.percent).then(a.name.cmp(&b.name)));
        let first = &scores[0];
        let margin = first.percent - scores.get(1).map_or(0.0, |entry| entry.percent);
        let ranked = Ranked {
            name: first.name.clone(),
            percent: first.percent,
            margin,
            candidates: scores.len(),
            exact: scores.iter().filter(|s| s.percent >= request.limits.exact_percent).count(),
            order: scores.iter().map(|s| (s.name.clone(), s.percent)).collect(),
        };
        let decisive = propose::decide(&ranked, &request.limits).is_some();
        Self {
            status: if decisive { ComparisonStatus::Decisive } else { ComparisonStatus::Ambiguous },
            winner: decisive.then(|| first.name.clone()),
            margin: Some(margin),
            candidates: scores,
            reason: (!decisive).then(|| "Body scores do not separate the alternatives".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evaluation {
    pub old: String,
    pub new: String,
    pub target_address: u32,
    pub unit: Option<String>,
    pub matcher_tier: MatchTier,
    pub binary: Comparison,
    pub compiled: Comparison,
    pub verdict: String,
}

/// A positive score is evidence only in its candidate field. A partial field
/// cannot promote a tentative binary match, and tiny bodies need independent
/// confident matching evidence. A decisive disagreement always abstains.
fn decision(
    name: &str,
    binary: &Comparison,
    compiled: &Comparison,
    matcher_tier: MatchTier,
    complete_field: bool,
    size: u32,
) -> (&'static str, Option<Tier>) {
    if [&binary.winner, &compiled.winner].into_iter().flatten().any(|winner| winner != name) {
        return ("conflicting-evidence", None);
    }
    let source_supports = compiled.winner.as_deref() == Some(name);
    let binary_supports = binary.winner.as_deref() == Some(name);
    if !source_supports && !binary_supports {
        return ("ambiguous", None);
    }
    if matcher_tier != MatchTier::Confident && size < 16 {
        return ("ambiguous-small-body", None);
    }
    if !source_supports && matcher_tier != MatchTier::Confident {
        if !complete_field || binary.candidates.len() < 2 {
            return ("incomplete-candidate-field", None);
        }
        if matcher_tier == MatchTier::Candidate
            && binary.candidates[0].percent < body::EXACT_PERCENT
        {
            return ("ambiguous", None);
        }
    }
    (
        "accepted",
        Some(if matcher_tier == MatchTier::Confident { Tier::Confident } else { Tier::Probable }),
    )
}

fn compatible(a: u64, b: u64, ratio: f64) -> bool {
    a != 0 && b != 0 && a.max(b) as f64 / a.min(b) as f64 <= ratio
}

fn percent(target: &Compiled, source: &Compiled, source_name: &str, ratio: f64) -> Result<f32> {
    let target_function = target.functions.first().context("Target function view is empty")?;
    let source_function = source.function(source_name).context("Source function is unavailable")?;
    let scores = body::score_matrix(target, source, &[target_function], &[source_function], ratio)?;
    scores
        .get(&target_function.name)
        .and_then(|row| row.get(source_name))
        .copied()
        .context("Objdiff did not score the explicit function mapping")
}

fn compiled_comparison(
    target: &Compiled,
    source: &Compiled,
    request: &Request,
) -> Result<Comparison> {
    let mut seen = BTreeSet::new();
    ensure!(
        source.functions.iter().all(|f| seen.insert(&f.name)),
        "Compiled object has duplicate function names"
    );
    let targets: Vec<_> = target.functions.iter().collect();
    let sources: Vec<_> = source.functions.iter().collect();
    let matrix = body::score_matrix(target, source, &targets, &sources, request.limits.size_ratio)?;
    let scores = matrix
        .values()
        .next()
        .into_iter()
        .flat_map(|row| row.iter())
        .map(|(name, &percent)| ScoredName { name: name.clone(), percent })
        .collect();
    Ok(Comparison::scored(scores, request))
}

/// Requires a reference executable; the standalone source-only command keeps
/// working without one. The pipeline already supplies its source version.
pub fn evaluate(request: &Request) -> Result<(Vec<Proposal>, Vec<Evaluation>)> {
    let Some(reference) = &request.reference else {
        return Ok((Vec::new(), Vec::new()));
    };
    ensure!(
        request.module == config::DOL_NAME,
        "Binary body validation is currently available for the main executable"
    );
    let root = Utf8NativePathBuf::from(request.root.to_string_lossy().into_owned());
    let source_path = Utf8NativePathBuf::from(
        config::config_path(&request.root, reference).to_string_lossy().into_owned(),
    );
    let target_path = Utf8NativePathBuf::from(
        config::config_path(&request.root, &request.version).to_string_lossy().into_owned(),
    );
    let (_, source_obj) = load_analyzed(&source_path, Some(&root), "--project-root")?;
    let (_, target_obj) = load_analyzed(&target_path, Some(&root), "--project-root")?;
    let source = MatchTarget::new(reference.clone(), source_obj);
    let target = MatchTarget::new(request.version.clone(), target_obj);
    evaluate_loaded(request, &source, &target)
}

fn evaluate_loaded(
    request: &Request,
    source: &MatchTarget,
    target: &MatchTarget,
) -> Result<(Vec<Proposal>, Vec<Evaluation>)> {
    let matches = match_functions(source, target, &MatchOptions::default());

    let module = config::find(&request.root, &request.version, &request.module)?;
    let mut compiled_paths = BTreeMap::new();
    for entry in walkdir::WalkDir::new(module.sources()).sort_by_file_name() {
        let Ok(entry) = entry else { continue };
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|s| s == "o") {
            let relative =
                entry.path().strip_prefix(module.sources()).unwrap().to_string_lossy().into_owned();
            compiled_paths.insert(unit_key(&relative), entry.path().to_path_buf());
        }
    }
    let mut names = BTreeMap::new();
    let mut by_unit = BTreeMap::<&str, Vec<NodeIndex>>::new();
    for node in 0..source.graph.len() as NodeIndex {
        *names.entry(source.symbol_name(node)).or_insert(0usize) += 1;
        if let Some(unit) = source.unit_of(node) {
            by_unit.entry(unit).or_default().push(node);
        }
    }
    let mut views = BTreeMap::<NodeIndex, Compiled>::new();
    let mut compiled_views = BTreeMap::<String, std::result::Result<Compiled, String>>::new();
    let mut proposals = Vec::new();
    let mut evaluations = Vec::new();
    let mut selected_units = BTreeSet::new();
    for matched in &matches.matches {
        if !source.is_named(matched.source) || target.is_named(matched.target) {
            continue;
        }
        let new = source.symbol_name(matched.source);
        let old = target.symbol_name(matched.target);
        let unit =
            source.unit_of(matched.source).filter(|unit| !source.obj.is_unit_autogenerated(unit));
        if !request.only.is_empty()
            && !unit
                .is_some_and(|u| request.only.iter().any(|wanted| unit_key(wanted) == unit_key(u)))
        {
            continue;
        }
        let group = unit.unwrap_or("<unowned>").to_string();
        if !selected_units.contains(&group)
            && request.limit.is_some_and(|limit| selected_units.len() >= limit)
        {
            continue;
        }
        selected_units.insert(group);
        let target_node = target.graph.node(matched.target);
        let target_view =
            Compiled::from_function(&target.obj, target_node.symbol, DiffSide::Target);
        let mut pool = BTreeSet::from([matched.source]);
        if let Some(alternative) = matched.runner_up {
            pool.insert(alternative.source);
        }
        if let Some(unit) = unit {
            pool.extend(by_unit.get(unit).into_iter().flatten().copied());
        }
        let binary = (|| -> Result<Comparison> {
            let target_view = target_view.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
            let mut scores = Vec::new();
            for node in pool {
                let source_node = source.graph.node(node);
                if !compatible(
                    u64::from(target_node.size),
                    u64::from(source_node.size),
                    request.limits.size_ratio,
                ) {
                    continue;
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = views.entry(node) {
                    entry.insert(Compiled::from_function(
                        &source.obj,
                        source_node.symbol,
                        DiffSide::Base,
                    )?);
                }
                scores.push(ScoredName {
                    name: source.symbol_name(node).to_string(),
                    percent: percent(
                        target_view,
                        &views[&node],
                        "__dtk_candidate",
                        request.limits.size_ratio,
                    )?,
                });
            }
            Ok(Comparison::scored(scores, request))
        })()
        .unwrap_or_else(|e| Comparison::unavailable(format!("{e:#}")));
        let compiled = (|| -> Result<Comparison> {
            let view = target_view.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
            let Some(key) = unit.map(unit_key) else {
                return Ok(Comparison::unavailable("Source unit is unknown"));
            };
            let Some(path) = compiled_paths.get(&key) else {
                return Ok(Comparison::unavailable("Compiled source object is missing"));
            };
            let source_view = compiled_views.entry(key).or_insert_with(|| {
                Compiled::read(path, DiffSide::Base).map_err(|e| format!("{e:#}"))
            });
            let source_view = source_view.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
            compiled_comparison(view, source_view, request)
        })()
        .unwrap_or_else(|e| Comparison::unavailable(format!("{e:#}")));
        let (mut verdict, mut tier) =
            decision(new, &binary, &compiled, matched.tier(), unit.is_some(), target_node.size);
        // Existing rename files identify names, not local symbol instances.
        // Keep their scores, but do not flatten duplicate/local identities.
        if source.is_local(matched.source) || names.get(new).copied().unwrap_or(0) > 1 {
            verdict = "ambiguous-symbol-identity";
            tier = None;
        }
        if let Some(tier) = tier {
            let mut proposal =
                Proposal::new(old, new, unit.unwrap_or("<unowned>"), "binary-body-match", tier);
            proposal.signal = Some(
                if compiled.winner.is_some() {
                    "compiled-corroboration"
                } else {
                    "binary-corroboration"
                }
                .into(),
            );
            let channel = if compiled.winner.is_some() { &compiled } else { &binary };
            proposal.percent = channel.candidates.first().map(|s| s.percent);
            proposal.margin = channel.margin;
            proposal.candidates = Some(channel.candidates.len());
            proposals.push(proposal);
        }
        evaluations.push(Evaluation {
            old: old.into(),
            new: new.into(),
            target_address: target_node.address,
            unit: unit.map(String::from),
            matcher_tier: matched.tier(),
            binary,
            compiled,
            verdict: verdict.into(),
        });
    }
    Ok((proposals, evaluations))
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjRelocations, ObjSection,
        ObjSectionKind, ObjSplit, ObjSplits, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags,
        ObjSymbolKind,
    };

    use super::*;

    const A: [u32; 5] = [0x3863_0001, 0x3884_0002, 0x7C63_2214, 0x5463_083C, 0x4E80_0020];
    const B: [u32; 5] = [0x8063_0000, 0x2C03_0000, 0x4182_0008, 0x3860_0000, 0x4E80_0020];

    fn image(base: u32, entries: &[(&str, [u32; 5])], unit: Option<&str>) -> ObjInfo {
        let symbols = entries
            .iter()
            .enumerate()
            .map(|(index, (name, _))| ObjSymbol {
                name: (*name).into(),
                address: u64::from(base) + index as u64 * 20,
                size: 20,
                size_known: true,
                section: Some(0),
                kind: ObjSymbolKind::Function,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..Default::default()
            })
            .collect();
        let data: Vec<u8> = entries
            .iter()
            .flat_map(|(_, words)| words.iter().flat_map(|w| w.to_be_bytes()))
            .collect();
        let mut splits = ObjSplits::default();
        if let Some(unit) = unit {
            splits.push(base, ObjSplit {
                unit: unit.into(),
                end: base + data.len() as u32,
                align: None,
                common: false,
                autogenerated: false,
                skip: false,
                rename: None,
            });
        }
        ObjInfo::new(
            if base == 0 { ObjKind::Relocatable } else { ObjKind::Executable },
            ObjArchitecture::PowerPc,
            "fixture".into(),
            symbols,
            vec![ObjSection {
                name: ".text".into(),
                kind: ObjSectionKind::Code,
                address: base.into(),
                size: data.len() as u64,
                data,
                align: 4,
                elf_index: 1,
                relocations: Default::default(),
                virtual_address: None,
                file_offset: 0,
                section_known: true,
                splits,
            }],
        )
    }

    fn comparison(scores: &[(&str, f32)]) -> Comparison {
        Comparison::scored(
            scores
                .iter()
                .map(|(name, percent)| ScoredName { name: (*name).into(), percent: *percent })
                .collect(),
            &Request::new(".".into(), "PAL".into()),
        )
    }

    #[test]
    fn competing_exact_bodies_are_ambiguous_and_partial_fields_cannot_promote() {
        let missing = Comparison::unavailable("missing");
        let tied = comparison(&[("A", 100.0), ("B", 100.0)]);
        assert_eq!(decision("A", &tied, &missing, MatchTier::Probable, true, 20).1, None);
        let unique = comparison(&[("A", 100.0)]);
        assert_eq!(decision("A", &unique, &missing, MatchTier::Probable, false, 20).1, None);
        let separated = comparison(&[("A", 100.0), ("B", 45.0)]);
        assert_eq!(
            decision("A", &separated, &missing, MatchTier::Probable, true, 20).1,
            Some(Tier::Probable)
        );
        assert_eq!(decision("A", &separated, &missing, MatchTier::Candidate, true, 8).1, None);
    }

    #[test]
    fn decisive_channels_disagree_without_overwriting_each_other() {
        let binary = comparison(&[("A", 100.0), ("B", 40.0)]);
        let compiled = comparison(&[("B", 100.0), ("A", 40.0)]);
        assert_eq!(
            decision("A", &binary, &compiled, MatchTier::Confident, true, 20),
            ("conflicting-evidence", None)
        );
    }

    #[test]
    fn binary_candidates_are_scored_without_target_splits_or_compiled_objects() {
        let root = tempfile::tempdir().unwrap();
        let request = Request::new(root.path().to_path_buf(), "PAL".into());
        let source = MatchTarget::new(
            "NTSC".into(),
            image(0x8000_1000, &[("A", A), ("B", B)], Some("Unit.cpp")),
        );
        let target =
            MatchTarget::new("PAL".into(), image(0x8000_2000, &[("fn_80002000", A)], None));
        let (proposals, evaluations) = evaluate_loaded(&request, &source, &target).unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].new, "A");
        assert_eq!(evaluations[0].binary.candidates.len(), 2);
        assert_eq!(evaluations[0].binary.winner.as_deref(), Some("A"));
        assert!(matches!(evaluations[0].compiled.status, ComparisonStatus::Unavailable));
    }

    #[test]
    fn compiled_objects_can_corroborate_or_contest_an_unsplit_target() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("build/PAL/src");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("Unit.o");
        let request = Request::new(root.path().to_path_buf(), "PAL".into());
        let source = MatchTarget::new(
            "NTSC".into(),
            image(0x8000_1000, &[("A", A), ("B", B)], Some("Unit.cpp")),
        );
        let target =
            MatchTarget::new("PAL".into(), image(0x8000_2000, &[("fn_80002000", A)], None));
        std::fs::write(
            &path,
            decomp_toolkit::util::elf::write_elf(&image(0, &[("A", A), ("B", B)], None), true)
                .unwrap(),
        )
        .unwrap();
        let (proposals, evaluations) = evaluate_loaded(&request, &source, &target).unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(evaluations[0].compiled.winner.as_deref(), Some("A"));
        std::fs::write(
            &path,
            decomp_toolkit::util::elf::write_elf(&image(0, &[("A", B), ("B", A)], None), true)
                .unwrap(),
        )
        .unwrap();
        let (proposals, evaluations) = evaluate_loaded(&request, &source, &target).unwrap();
        assert!(proposals.is_empty());
        assert_eq!(evaluations[0].compiled.winner.as_deref(), Some("B"));
        assert_eq!(evaluations[0].verdict, "conflicting-evidence");
    }

    #[test]
    fn function_views_preserve_relocations_across_address_changes() {
        let mut source = image(0x8000_1000, &[("A", A), ("Helper", B)], None);
        let mut target = image(0x8000_5000, &[("fn_80005000", A), ("Helper", B)], None);
        for (obj, word) in [(&mut source, 0x4800_0011u32), (&mut target, 0x4800_0101u32)] {
            let section = &mut obj.sections[0];
            section.data[4..8].copy_from_slice(&word.to_be_bytes());
            section.relocations =
                ObjRelocations::new(vec![(section.address as u32 + 4, ObjReloc {
                    kind: ObjRelocKind::PpcRel24,
                    target_symbol: 1,
                    addend: 0,
                    module: None,
                })])
                .unwrap();
        }
        let left = Compiled::from_function(&target, 0, DiffSide::Target).unwrap();
        let right = Compiled::from_function(&source, 0, DiffSide::Base).unwrap();
        assert_eq!(percent(&left, &right, "__dtk_candidate", 2.5).unwrap(), 100.0);
        assert_eq!(target.symbols[0].address, 0x8000_5000);
        assert_eq!(left.object.sections[0].relocations.len(), 1);
    }
}
