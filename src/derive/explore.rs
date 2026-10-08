//! Review-oriented search over the unresolved functions in a built project.
//!
//! Scores are observations, never names or propagation seeds. Only names
//! already present in the extracted objects supply graph anchors. Rebuilding
//! after a reviewed rename and rerunning this scan exposes the next candidates.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use anyhow::{Context, Result, ensure};
use objdiff_core::{
    diff::DiffSide,
    obj::{Object, SymbolKind},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    derive::{
        body,
        objects::{Compiled, Function, is_derivable, is_usable_source_name},
    },
    project::config,
};

const SCHEMA: u32 = 2;
// Include the implementation and pinned dependencies, not just the JSON format.
static SCORER_FINGERPRINT: LazyLock<String> = LazyLock::new(|| {
    let mut hash = Sha256::new();
    for source in [
        include_str!("explore.rs"),
        include_str!("body.rs"),
        include_str!("objects.rs"),
        include_str!("../../Cargo.lock"),
    ] {
        hash.update(source.as_bytes());
    }
    format!("{:x}", hash.finalize())
});

pub struct Request {
    pub root: PathBuf,
    pub version: String,
    pub module: String,
    pub prefixes: Vec<String>,
    pub alternatives: usize,
    pub min_percent: f32,
    pub size_ratio: f64,
    pub cache: Option<PathBuf>,
    pub previous: Option<PathBuf>,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// These names are read from the objects, not from candidate hypotheses.
    SharedReference {
        name: String,
    },
    SharedCaller {
        name: String,
    },
    VtableSlot {
        target_table: String,
        source_table: String,
        offset: u64,
        named_slots: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub name: String,
    pub source_size: u64,
    pub percent: f32,
    pub evidence: Vec<Evidence>,
    pub review_requirements: Vec<String>,
    pub name_already_present: bool,
    pub ranked_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unresolved {
    pub name: String,
    pub placement: Option<crate::derive::Placement>,
    pub size: u64,
    pub scored_pairs: usize,
    pub size_filtered_pairs: usize,
    pub below_report_threshold: usize,
    pub omitted_alternatives: usize,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unit {
    pub name: String,
    pub active: bool,
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    pub source_digest: Option<String>,
    pub target_digest: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub native_functions: usize,
    pub source_functions: usize,
    pub named_functions: usize,
    pub named_locations: BTreeSet<crate::derive::Placement>,
    pub unresolved: Vec<Unresolved>,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Progress {
    pub resolved: Vec<String>,
    pub newly_unresolved: Vec<String>,
    pub no_longer_observed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema: u32,
    pub scorer_fingerprint: String,
    pub version: String,
    pub module: String,
    pub root: PathBuf,
    pub search_limits: SearchLimits,
    pub unresolved: usize,
    pub with_candidates: usize,
    pub unavailable_units: usize,
    pub cache_hits: usize,
    pub progress: Option<Progress>,
    pub units: Vec<Unit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchLimits {
    pub size_ratio: f64,
    pub min_percent: f32,
    pub alternatives: usize,
    pub scope: String,
}

type Scores = BTreeMap<String, BTreeMap<String, f32>>;
type Hints = BTreeMap<(String, String), Vec<Evidence>>;

/// Include missing and empty objects: silence must never look like exhaustion.
fn inventory(
    source: &Path,
    target: &Path,
    expected: &BTreeSet<String>,
) -> Result<Vec<(String, PathBuf, PathBuf, bool)>> {
    let mut names = expected.clone();
    for root in [source, target] {
        if !root.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(root) {
            let entry = entry?;
            if entry.file_type().is_file() && entry.path().extension().is_some_and(|s| s == "o") {
                names.insert(entry.path().strip_prefix(root)?.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(names
        .into_iter()
        .map(|name| {
            (name.clone(), source.join(&name), target.join(&name), expected.contains(&name))
        })
        .collect())
}

fn read_object(path: &Path, side: DiffSide) -> Result<(Compiled, String)> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok((Compiled::parse(&bytes, side)?, format!("{:x}", Sha256::digest(&bytes))))
}

fn placement_for_name(
    symbols: &BTreeMap<String, crate::derive::Placement>,
    name: &str,
) -> Option<crate::derive::Placement> {
    if let Some(place) = symbols.get(name) {
        return Some(place.clone());
    }
    let (base, suffix) = name.rsplit_once('_')?;
    if suffix.len() != 8 {
        return None;
    }
    let address = u64::from_str_radix(suffix, 16).ok()?;
    symbols.get(base).filter(|(_, actual)| *actual == address).cloned()
}

fn canonical_name(symbols: &BTreeMap<String, crate::derive::Placement>, name: &str) -> String {
    if !symbols.contains_key(name) && placement_for_name(symbols, name).is_some() {
        return name.rsplit_once('_').unwrap().0.into();
    }
    name.into()
}

fn canonicalize_view(target: &mut Compiled, symbols: &BTreeMap<String, crate::derive::Placement>) {
    for function in &mut target.functions {
        function.name = canonical_name(symbols, &function.name);
        for reference in &mut function.relocations {
            reference.target = canonical_name(symbols, &reference.target);
        }
    }
}

fn meaningful(name: &str) -> bool { is_usable_source_name(name) && name != "__pure_virtual" }

fn shared_references(a: &Function, b: &Function) -> Vec<Evidence> {
    let left: BTreeSet<_> = a
        .relocations
        .iter()
        .filter(|r| meaningful(&r.target))
        .map(|r| (r.kind, r.target.as_str()))
        .collect();
    let right: BTreeSet<_> = b
        .relocations
        .iter()
        .filter(|r| meaningful(&r.target))
        .map(|r| (r.kind, r.target.as_str()))
        .collect();
    left.intersection(&right)
        .map(|(_, name)| Evidence::SharedReference { name: (*name).into() })
        .collect()
}

/// A shared caller is a lead, not proof that two call positions correspond.
fn caller_hints(target: &Compiled, source: &Compiled) -> Hints {
    let mut result = Hints::new();
    for caller in &target.functions {
        if !meaningful(&caller.name) {
            continue;
        }
        let Some(other) = source.function(&caller.name) else {
            continue;
        };
        for a in caller
            .relocations
            .iter()
            .filter(|r| matches!(r.kind, 10 | 11 | 18) && is_derivable(&r.target))
        {
            for b in other
                .relocations
                .iter()
                .filter(|r| matches!(r.kind, 10 | 11 | 18) && meaningful(&r.target))
            {
                result
                    .entry((a.target.clone(), b.target.clone()))
                    .or_default()
                    .push(Evidence::SharedCaller { name: caller.name.clone() });
            }
        }
    }
    result
}

#[derive(Debug)]
struct Table {
    name: String,
    size: u64,
    slots: BTreeMap<u64, String>,
}

fn tables(object: &Object) -> Vec<Table> {
    object
        .symbols
        .iter()
        .filter_map(|symbol| {
            if symbol.kind != SymbolKind::Object
                || symbol.size < 12
                || !(symbol.name.starts_with("__vt__") || is_derivable(&symbol.name))
            {
                return None;
            }
            let section = object.sections.get(symbol.section?)?;
            let slots: BTreeMap<_, _> = section
                .relocations
                .iter()
                .filter(|r| r.address >= symbol.address && r.address < symbol.address + symbol.size)
                .filter_map(|r| {
                    Some((
                        r.address - symbol.address,
                        object.symbols.get(r.target_symbol)?.name.clone(),
                    ))
                })
                .collect();
            (slots.len() >= 2).then(|| Table {
                name: symbol.name.clone(),
                size: symbol.size,
                slots,
            })
        })
        .collect()
}

fn vtable_hints(
    target: &Compiled,
    source: &Compiled,
    symbols: &BTreeMap<String, crate::derive::Placement>,
) -> Hints {
    let mut native = tables(&target.object);
    for table in &mut native {
        table.name = canonical_name(symbols, &table.name);
        for value in table.slots.values_mut() {
            *value = canonical_name(symbols, value);
        }
    }
    table_hints(&native, &tables(&source.object))
}

fn table_hints(target_tables: &[Table], source_tables: &[Table]) -> Hints {
    let mut hints = Hints::new();
    for a in target_tables {
        for b in source_tables.iter().filter(|b| b.name.starts_with("__vt__")) {
            if a.size != b.size || !a.slots.keys().eq(b.slots.keys()) {
                continue;
            }
            let named = a
                .slots
                .iter()
                .filter(|(offset, name)| meaningful(name) && b.slots.get(offset) == Some(name))
                .map(|(_, name)| name)
                .collect::<BTreeSet<_>>()
                .len();
            let conflict = a
                .slots
                .iter()
                .any(|(offset, name)| meaningful(name) && b.slots.get(offset) != Some(name));
            if conflict || (a.name != b.name && named < 2) {
                continue;
            }
            for (offset, old) in &a.slots {
                let new = &b.slots[offset];
                if is_derivable(old) && meaningful(new) {
                    hints.entry((old.clone(), new.clone())).or_default().push(
                        Evidence::VtableSlot {
                            target_table: a.name.clone(),
                            source_table: b.name.clone(),
                            offset: *offset,
                            named_slots: named,
                        },
                    );
                }
            }
        }
    }
    hints
}

fn requirements(name: &str, evidence: &[Evidence], taken: bool) -> Vec<String> {
    let mut out = vec!["Confirm the native operation and argument ABI; objdiff percentage does not establish identity.".into()];
    if name.contains('<') {
        out.push("Establish concrete template types through native owners or typed callers; identical code and element size are insufficient.".into());
    }
    if evidence.iter().any(|e| matches!(e, Evidence::SharedCaller { .. })) {
        out.push("Check the specific call path and argument flow; a shared caller may call several unrelated helpers.".into());
    }
    if taken {
        out.push("This source name already occurs in the extracted unit; resolve duplicate identity before renaming.".into());
    }
    out
}

fn candidate_order(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    let weight = |c: &Candidate| {
        c.evidence
            .iter()
            .map(|e| match e {
                Evidence::VtableSlot { .. } => 4usize,
                Evidence::SharedReference { .. } => 2,
                Evidence::SharedCaller { .. } => 1,
            })
            .sum::<usize>()
    };
    weight(b)
        .cmp(&weight(a))
        .then_with(|| b.percent.total_cmp(&a.percent))
        .then_with(|| a.name.cmp(&b.name))
}

/// Preserve strong bodies even when weak graph leads have many references.
/// Each channel gets its own quota; the displayed list is their union.
fn select_alternatives(candidates: &mut Vec<Candidate>, limit: usize) -> usize {
    candidates.sort_by(|a, b| b.percent.total_cmp(&a.percent).then_with(|| a.name.cmp(&b.name)));
    for c in candidates.iter_mut().take(limit) {
        c.ranked_by.push("body".into());
    }
    candidates.sort_by(candidate_order);
    for c in candidates.iter_mut().filter(|c| !c.evidence.is_empty()).take(limit) {
        c.ranked_by.push("graph".into());
    }
    let before = candidates.len();
    candidates.retain(|c| !c.ranked_by.is_empty());
    before - candidates.len()
}

fn scan(
    unit: &mut Unit,
    request: &Request,
    symbols: &BTreeMap<String, crate::derive::Placement>,
) -> Result<()> {
    if !unit.active {
        unit.status = if unit.target_path.is_file() {
            "inactive_extracted_object"
        } else {
            "reference_only_object"
        }
        .into();
        return Ok(());
    }
    if !unit.target_path.is_file() && !unit.source_path.is_file() {
        unit.status = "missing_both_objects".into();
        return Ok(());
    }
    if !unit.target_path.is_file() {
        unit.status = "missing_target_object".into();
        return Ok(());
    }
    let (mut target, digest) = read_object(&unit.target_path, DiffSide::Target)?;
    canonicalize_view(&mut target, symbols);
    unit.target_digest = Some(digest);
    unit.native_functions = target.functions.len();
    unit.named_functions = target.functions.iter().filter(|f| !is_derivable(&f.name)).count();
    unit.named_locations = target
        .functions
        .iter()
        .filter(|f| !is_derivable(&f.name))
        .filter_map(|f| placement_for_name(symbols, &f.name))
        .collect();
    unit.unresolved = target
        .functions
        .iter()
        .filter(|f| is_derivable(&f.name))
        .map(|f| Unresolved {
            name: f.name.clone(),
            placement: placement_for_name(symbols, &f.name),
            size: f.size,
            scored_pairs: 0,
            size_filtered_pairs: 0,
            below_report_threshold: 0,
            omitted_alternatives: 0,
            candidates: Vec::new(),
        })
        .collect();
    if !unit.source_path.is_file() {
        unit.status = "missing_source_object".into();
        return Ok(());
    }
    let (source, digest) = read_object(&unit.source_path, DiffSide::Base)?;
    unit.source_digest = Some(digest);
    let sources: Vec<_> = source.functions.iter().filter(|f| meaningful(&f.name)).collect();
    unit.source_functions = sources.len();
    if sources.is_empty() {
        unit.status = "no_source_function_bodies".into();
        return Ok(());
    }
    let targets: Vec<_> = target.functions.iter().filter(|f| is_derivable(&f.name)).collect();
    if targets.is_empty() {
        unit.status = "no_unresolved_functions".into();
        return Ok(());
    }
    let mut hints = caller_hints(&target, &source);
    for (pair, evidence) in vtable_hints(&target, &source, symbols) {
        hints.entry(pair).or_default().extend(evidence);
    }
    let mut pairs = Vec::new();
    for a in &targets {
        for b in &sources {
            let pair = (a.name.clone(), b.name.clone());
            let evidence = hints.entry(pair).or_default();
            evidence.extend(shared_references(a, b));
            evidence.sort();
            evidence.dedup();
            let ratio = a.size.max(b.size) as f64 / a.size.min(b.size) as f64;
            if ratio <= request.size_ratio || !evidence.is_empty() {
                pairs.push((a.name.as_str(), b.name.as_str()));
            }
        }
    }
    let cache_key = format!(
        "{:x}",
        Sha256::digest(format!(
            "explore-{}-{}-{}-{}-{:x}",
            *SCORER_FINGERPRINT,
            unit.source_digest.as_deref().unwrap(),
            unit.target_digest.as_deref().unwrap(),
            request.size_ratio,
            Sha256::digest(serde_json::to_vec(&pairs)?)
        ))
    );
    let cache_path = request.cache.as_ref().map(|p| p.join(format!("{cache_key}.json")));
    let cached = cache_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice::<Scores>(&b).ok());
    let scores = if let Some(scores) = cached {
        unit.cache_hit = true;
        scores
    } else {
        let scores = body::score_pairs(&target, &source, &pairs)?;
        if let Some(path) = cache_path {
            std::fs::create_dir_all(path.parent().unwrap())?;
            let mut temp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
            serde_json::to_writer(&mut temp, &scores)?;
            temp.persist(&path).with_context(|| format!("Failed to save {}", path.display()))?;
        }
        scores
    };
    for item in &mut unit.unresolved {
        let measured = scores.get(&item.name);
        item.scored_pairs = measured.map_or(0, BTreeMap::len);
        item.size_filtered_pairs =
            sources.len() - pairs.iter().filter(|(name, _)| *name == item.name).count();
        for (name, percent) in measured.into_iter().flatten() {
            let evidence =
                hints.get(&(item.name.clone(), name.clone())).cloned().unwrap_or_default();
            if *percent < request.min_percent && evidence.is_empty() {
                item.below_report_threshold += 1;
                continue;
            }
            let taken = target.function(name).is_some();
            item.candidates.push(Candidate {
                name: name.clone(),
                source_size: source.function(name).map_or(0, |f| f.size),
                percent: *percent,
                review_requirements: requirements(name, &evidence, taken),
                evidence,
                name_already_present: taken,
                ranked_by: Vec::new(),
            });
        }
        item.omitted_alternatives = select_alternatives(&mut item.candidates, request.alternatives);
    }
    unit.status = if unit.unresolved.iter().any(|f| !f.candidates.is_empty()) {
        "review_needed"
    } else {
        "no_candidates_within_search_limits"
    }
    .into();
    Ok(())
}

fn changes(previous: &Report, current: &[Unit]) -> Progress {
    let ids = |units: &[Unit]| -> BTreeSet<String> {
        units
            .iter()
            .flat_map(|u| u.unresolved.iter().map(|f| format!("{}:{}", u.name, f.name)))
            .collect()
    };
    let before = ids(&previous.units);
    let after = ids(current);
    let named: BTreeSet<_> = current
        .iter()
        .filter(|u| u.target_digest.is_some() && u.status != "error")
        .flat_map(|u| u.named_locations.iter().cloned())
        .collect();
    let old_locations: BTreeMap<_, _> = previous
        .units
        .iter()
        .flat_map(|u| {
            u.unresolved.iter().map(|f| (format!("{}:{}", u.name, f.name), f.placement.as_ref()))
        })
        .collect();
    let mut result = Progress::default();
    for old in before.difference(&after) {
        if old_locations.get(old).and_then(|p| *p).is_some_and(|p| named.contains(p)) {
            result.resolved.push(old.clone());
        } else {
            result.no_longer_observed.push(old.clone());
        }
    }
    result.newly_unresolved = after.difference(&before).cloned().collect();
    result
}

pub fn run(request: &Request) -> Result<Report> {
    ensure!(
        request.alternatives > 0 && request.workers > 0,
        "alternatives and workers must be positive"
    );
    ensure!(
        request.size_ratio.is_finite() && request.size_ratio >= 1.0,
        "size ratio must be finite and at least 1"
    );
    ensure!(
        request.min_percent.is_finite() && (0.0..=100.0).contains(&request.min_percent),
        "min percent must be between 0 and 100"
    );
    let module = config::find(&request.root, &request.version, &request.module)?;
    let symbols = crate::derive::load_symbols(&module.symbols)?;
    let splits = crate::project::splits::Splits::read(&module.splits)?;
    let expected =
        splits.blocks.keys().map(|name| format!("{}.o", crate::derive::unit_key(name))).collect();
    let mut entries = inventory(&module.sources(), &module.extracted(), &expected)?;
    entries.retain(|(name, _, _, _)| {
        request.prefixes.is_empty()
            || request.prefixes.iter().any(|p| name.starts_with(&p.replace('\\', "/")))
    });
    ensure!(
        !entries.is_empty(),
        "No extracted or compiled objects match the requested units; build the project and check the unit prefixes"
    );
    let pool = rayon::ThreadPoolBuilder::new().num_threads(request.workers).build()?;
    let units: Vec<_> = pool.install(|| {
        entries
            .par_iter()
            .map(|(name, source, target, active)| {
                let mut unit = Unit {
                    name: name.clone(),
                    active: *active,
                    source_path: source.clone(),
                    target_path: target.clone(),
                    source_digest: None,
                    target_digest: None,
                    status: String::new(),
                    error: None,
                    native_functions: 0,
                    source_functions: 0,
                    named_functions: 0,
                    named_locations: BTreeSet::new(),
                    unresolved: Vec::new(),
                    cache_hit: false,
                };
                if let Err(error) = scan(&mut unit, request, &symbols) {
                    unit.status = "error".into();
                    unit.error = Some(format!("{error:#}"));
                }
                unit
            })
            .collect()
    });
    let progress = request
        .previous
        .as_ref()
        .map(|path| -> Result<_> {
            let previous: Report = serde_json::from_slice(&std::fs::read(path)?)?;
            ensure!(
                previous.schema == SCHEMA
                    && previous.version == request.version
                    && previous.module == request.module
                    && previous.root == request.root,
                "previous report belongs to a different project, version, module, or schema"
            );
            Ok(changes(&previous, &units))
        })
        .transpose()?;
    Ok(Report { schema: SCHEMA, scorer_fingerprint: SCORER_FINGERPRINT.clone(), version: request.version.clone(), module: request.module.clone(), root: request.root.clone(),
        search_limits: SearchLimits { size_ratio: request.size_ratio, min_percent: request.min_percent, alternatives: request.alternatives,
            scope: "Same-unit compiled function bodies; existing-name caller/reference and vtable leads. Candidates are not propagated as facts. Missing objects and filtered comparisons do not establish exhaustion.".into() },
        unresolved: units.iter().map(|u| u.unresolved.len()).sum(),
        with_candidates: units.iter().flat_map(|u| &u.unresolved).filter(|f| !f.candidates.is_empty()).count(),
        unavailable_units: units.iter().filter(|u| u.active && matches!(u.status.as_str(), "error" | "missing_both_objects" | "missing_source_object" | "missing_target_object" | "no_source_function_bodies")).count(),
        cache_hits: units.iter().filter(|u| u.cache_hit).count(), progress, units,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::objects::Reference;

    fn function(name: &str, refs: &[&str]) -> Function {
        Function {
            name: name.into(),
            address: 0,
            size: 16,
            relocations: refs
                .iter()
                .enumerate()
                .map(|(i, r)| Reference { offset: (i * 4) as u64, kind: 10, target: (*r).into() })
                .collect(),
        }
    }

    #[test]
    fn compiler_labels_and_placeholders_never_become_shared_anchors() {
        let a = function("fn_1", &["@123", "fn_2", "Free"]);
        let b = function("Candidate", &["@123", "fn_2", "Free"]);
        assert_eq!(shared_references(&a, &b), vec![Evidence::SharedReference {
            name: "Free".into()
        }]);
    }

    #[test]
    fn exact_generic_bodies_still_require_concrete_type_review() {
        let notes = requirements("destroy<13CPASAnimState>", &[], false);
        assert!(notes.iter().any(|n| n.contains("element size are insufficient")));
        assert!(notes.iter().any(|n| n.contains("argument ABI")));
    }

    #[test]
    fn inventory_keeps_target_only_and_source_only_files() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("src");
        let target = temp.path().join("obj");
        std::fs::create_dir_all(source.join("Kyoto")).unwrap();
        std::fs::create_dir_all(target.join("Kyoto")).unwrap();
        std::fs::write(source.join("Kyoto/Reference.o"), []).unwrap();
        std::fs::write(target.join("Kyoto/Native.o"), []).unwrap();
        let expected = BTreeSet::from(["Kyoto/Missing.o".into(), "Kyoto/Native.o".into()]);
        let units = inventory(&source, &target, &expected).unwrap();
        assert_eq!(units.iter().map(|u| u.0.as_str()).collect::<Vec<_>>(), [
            "Kyoto/Missing.o",
            "Kyoto/Native.o",
            "Kyoto/Reference.o"
        ]);
        assert!(units[0].3 && units[1].3 && !units[2].3);
    }

    fn table(name: &str, size: u64, slots: &[(u64, &str)]) -> Table {
        Table {
            name: name.into(),
            size,
            slots: slots.iter().map(|(i, n)| (*i, (*n).into())).collect(),
        }
    }

    #[test]
    fn shifted_virtual_slots_never_inherit_the_old_slot_signature() {
        let source = [table("__vt__Reader", 24, &[
            (8, "Advance"),
            (12, "State"),
            (16, "Named"),
            (20, "Tail"),
        ])];
        let target = [table("__vt__Reader", 28, &[
            (8, "Advance"),
            (12, "fn_NewList"),
            (16, "fn_State"),
            (20, "Named"),
            (24, "Tail"),
        ])];
        assert!(table_hints(&target, &source).is_empty());
    }

    #[test]
    fn table_anchor_conflict_is_retained_as_uncertainty() {
        let source = [table("__vt__Reader", 24, &[
            (8, "Advance"),
            (12, "State"),
            (16, "Named"),
            (20, "Tail"),
        ])];
        let target =
            [table("lbl_1", 24, &[(8, "Advance"), (12, "fn_State"), (16, "Wrong"), (20, "Tail")])];
        assert!(table_hints(&target, &source).is_empty());
        let target =
            [table("lbl_1", 24, &[(8, "Advance"), (12, "fn_State"), (16, "Named"), (20, "Tail")])];
        assert!(table_hints(&target, &source).contains_key(&("fn_State".into(), "State".into())));
    }

    fn write_object(path: &Path, names: &[&str]) {
        use decomp_toolkit::obj::{
            ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSymbol,
            ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
        };
        let data: Vec<_> = names
            .iter()
            .flat_map(|_| [0x3863_0001u32, 0x4e80_0020].into_iter().flat_map(u32::to_be_bytes))
            .collect();
        let symbols = names
            .iter()
            .enumerate()
            .map(|(i, n)| ObjSymbol {
                name: (*n).into(),
                address: i as u64 * 8,
                size: 8,
                size_known: true,
                section: Some(0),
                kind: ObjSymbolKind::Function,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..Default::default()
            })
            .collect();
        let obj = ObjInfo::new(
            ObjKind::Relocatable,
            ObjArchitecture::PowerPc,
            "test".into(),
            symbols,
            vec![ObjSection {
                name: ".text".into(),
                kind: ObjSectionKind::Code,
                address: 0,
                size: data.len() as u64,
                data,
                align: 4,
                elf_index: 1,
                relocations: Default::default(),
                virtual_address: None,
                file_offset: 0,
                section_known: true,
                splits: Default::default(),
            }],
        );
        std::fs::write(path, decomp_toolkit::util::elf::write_elf(&obj, true).unwrap()).unwrap();
    }

    fn blank_unit(root: &Path) -> Unit {
        Unit {
            name: "Unit.o".into(),
            active: true,
            source_path: root.join("source.o"),
            target_path: root.join("target.o"),
            source_digest: None,
            target_digest: None,
            status: String::new(),
            error: None,
            native_functions: 0,
            source_functions: 0,
            named_functions: 0,
            named_locations: BTreeSet::new(),
            unresolved: vec![],
            cache_hit: false,
        }
    }

    #[test]
    fn real_objdiff_scan_preserves_ambiguous_templates_and_invalidates_changed_objects() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut unit = blank_unit(root);
        write_object(&unit.target_path, &["fn_1000"]);
        write_object(&unit.source_path, &["destroy<TypeA>", "destroy<TypeB>"]);
        let original = std::fs::read(&unit.target_path).unwrap();
        let request = Request {
            root: root.into(),
            version: "TEST".into(),
            module: "main".into(),
            prefixes: vec![],
            alternatives: 5,
            min_percent: 25.0,
            size_ratio: 3.5,
            cache: Some(root.join("cache")),
            previous: None,
            workers: 1,
        };
        let symbols = BTreeMap::from([("fn_1000".into(), (".text".into(), 0x1000))]);
        scan(&mut unit, &request, &symbols).unwrap();
        assert_eq!(unit.unresolved[0].candidates.len(), 2);
        assert_eq!(unit.unresolved[0].scored_pairs, 2);
        assert!(
            unit.unresolved[0]
                .candidates
                .iter()
                .all(|c| c.percent == 100.0 && c.evidence.is_empty())
        );
        assert_eq!(unit.status, "review_needed");
        let mut second = blank_unit(root);
        scan(&mut second, &request, &symbols).unwrap();
        assert!(second.cache_hit);
        write_object(&unit.source_path, &["Replacement"]);
        let mut third = blank_unit(root);
        scan(&mut third, &request, &symbols).unwrap();
        assert!(!third.cache_hit);
        assert_eq!(third.unresolved[0].candidates[0].name, "Replacement");
        assert_eq!(std::fs::read(&unit.target_path).unwrap(), original);
        write_object(&unit.target_path, &["Replacement"]);
        let mut fourth = blank_unit(root);
        scan(&mut fourth, &request, &symbols).unwrap();
        assert_eq!(fourth.status, "no_unresolved_functions");
    }

    #[test]
    fn shared_caller_hypotheses_do_not_create_new_named_anchors() {
        let target = Compiled {
            object: Object::default(),
            functions: vec![function("Named", &["fn_1"]), function("fn_1", &["fn_2"])],
        };
        let source = Compiled {
            object: Object::default(),
            functions: vec![function("Named", &["Candidate"]), function("Candidate", &["Other"])],
        };
        let hints = caller_hints(&target, &source);
        assert!(hints.contains_key(&("fn_1".into(), "Candidate".into())));
        assert!(!hints.contains_key(&("fn_2".into(), "Other".into())));
    }

    #[test]
    fn disappeared_objects_are_not_counted_as_successful_renames() {
        let mut old = blank_unit(Path::new("."));
        old.unresolved.push(Unresolved {
            name: "fn_1000".into(),
            placement: Some((".text".into(), 0x1000)),
            size: 8,
            scored_pairs: 0,
            size_filtered_pairs: 0,
            below_report_threshold: 0,
            omitted_alternatives: 0,
            candidates: vec![],
        });
        let report = Report {
            schema: SCHEMA,
            scorer_fingerprint: SCORER_FINGERPRINT.clone(),
            version: "TEST".into(),
            module: "main".into(),
            root: ".".into(),
            search_limits: SearchLimits {
                size_ratio: 3.5,
                min_percent: 25.0,
                alternatives: 5,
                scope: String::new(),
            },
            unresolved: 1,
            with_candidates: 0,
            unavailable_units: 0,
            cache_hits: 0,
            progress: None,
            units: vec![old],
        };
        let mut now = blank_unit(Path::new("."));
        now.target_digest = Some("changed".into());
        now.status = "no_unresolved_functions".into();
        let lost = changes(&report, &[now.clone()]);
        assert!(lost.resolved.is_empty());
        assert_eq!(lost.no_longer_observed, ["Unit.o:fn_1000"]);
        now.named_locations.insert((".text".into(), 0x1000));
        let renamed = changes(&report, &[now]);
        assert_eq!(renamed.resolved, ["Unit.o:fn_1000"]);
    }

    #[test]
    fn strongest_body_survives_many_low_score_graph_leads() {
        let candidate = |name: &str, percent, evidence| Candidate {
            name: name.into(),
            source_size: 8,
            percent,
            evidence,
            review_requirements: vec![],
            name_already_present: false,
            ranked_by: vec![],
        };
        let mut options = vec![
            candidate("Body", 99.5, vec![]),
            candidate("Noise", 0.0, vec![Evidence::SharedCaller { name: "Caller".into() }]),
            candidate("Other", 12.5, vec![Evidence::SharedCaller { name: "Caller".into() }]),
        ];
        assert_eq!(select_alternatives(&mut options, 1), 1);
        assert!(options.iter().any(|c| c.name == "Body" && c.ranked_by == ["body"]));
        assert!(options.iter().any(|c| c.name == "Other" && c.ranked_by == ["graph"]));
    }

    #[test]
    fn repeated_inherited_slots_are_only_one_independent_anchor() {
        let source = [table("__vt__Reader", 24, &[(8, "Base"), (12, "Method"), (16, "Base")])];
        let target = [table("lbl_1", 24, &[(8, "Base"), (12, "fn_1"), (16, "Base")])];
        assert!(table_hints(&target, &source).is_empty());
    }

    #[test]
    fn local_suffix_requires_the_symbols_file_to_confirm_its_address() {
        let symbols = BTreeMap::from([("Local".into(), (".text".into(), 0x80518608))]);
        assert_eq!(
            placement_for_name(&symbols, "Local_80518608"),
            Some((".text".into(), 0x80518608))
        );
        assert_eq!(placement_for_name(&symbols, "Local_80518609"), None);
    }

    #[test]
    fn confirmed_local_aliases_anchor_callers_references_and_taken_names() {
        let symbols = BTreeMap::from([("Local".into(), (".text".into(), 0x80518608))]);
        let mut target = Compiled {
            object: Object::default(),
            functions: vec![
                function("Local_80518608", &["fn_1"]),
                function("fn_1", &["Local_80518608"]),
            ],
        };
        let source = Compiled {
            object: Object::default(),
            functions: vec![function("Local", &["Candidate"]), function("Candidate", &["Local"])],
        };
        canonicalize_view(&mut target, &symbols);
        assert!(target.function("Local").is_some());
        assert!(caller_hints(&target, &source).contains_key(&("fn_1".into(), "Candidate".into())));
        assert_eq!(
            shared_references(
                target.function("fn_1").unwrap(),
                source.function("Candidate").unwrap()
            ),
            vec![Evidence::SharedReference { name: "Local".into() }]
        );
        assert_eq!(canonical_name(&symbols, "Local_80518609"), "Local_80518609");
    }

    #[test]
    fn stale_native_objects_are_reported_but_not_scored() {
        let temp = tempfile::tempdir().unwrap();
        let mut unit = blank_unit(temp.path());
        unit.active = false;
        std::fs::write(&unit.target_path, b"stale invalid object").unwrap();
        let request = Request {
            root: temp.path().into(),
            version: "TEST".into(),
            module: "main".into(),
            prefixes: vec![],
            alternatives: 5,
            min_percent: 25.0,
            size_ratio: 3.5,
            cache: None,
            previous: None,
            workers: 1,
        };
        scan(&mut unit, &request, &BTreeMap::new()).unwrap();
        assert_eq!(unit.status, "inactive_extracted_object");
        assert!(unit.target_digest.is_none());
    }
}
