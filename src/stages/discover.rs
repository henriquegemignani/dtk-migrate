//! Discovering useful split boundaries by measured compiler progress.
//!
//! A split says "this range of the target belongs to that source file". Getting
//! one right lets the comparison pair up functions that were already correct
//! and simply unattributed, so matched code goes up without a line of source
//! changing. Getting one wrong costs a build and is undone.
//!
//! The gate is a measured gain: a code candidate is kept only if the unit's own
//! matched code went up and no other unit's went down. The retail hash is also
//! required, but it proves something narrower than it looks — it says the split
//! is internally consistent, not that the candidate's source is right, because
//! a unit `configure.py` has not enabled still links from its extracted
//! original. That distinction is what [`super::verify`] exists to settle.

use std::{
    cmp::{Ordering, Reverse},
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::{
    analysis::{
        coverage::CoverageReport,
        ownership::{ObservationIndex, ObservationReference, OwnershipAssessment, load_reference},
    },
    build::context::{BuildContext, is_trial_failure},
    matching::data_evidence::{DataEvidenceReference, DataEvidenceReport},
    project::{
        link_order::cyclic_units,
        report::Report,
        splits::{Splits, entry_line, entry_suffix, parse_attributes, parse_range},
        transaction::Owned,
    },
    stages::{
        Candidate, Event, MutationScope, Outcome, Prepared, Selections, Stage,
        refusal::{Kind as RefusalKind, Refusal},
    },
};

#[derive(Default)]
pub struct Discover {
    observations: Mutex<BTreeMap<ObservationKey, Arc<ObservationIndex>>>,
}

type ObservationKey = (u32, String, String, String, String);

impl Discover {
    fn observations(
        &self,
        reference: &ObservationReference,
        source: &str,
        target: &str,
    ) -> Result<Arc<ObservationIndex>> {
        let key = (
            reference.schema,
            reference.sha256.clone(),
            reference.file.clone(),
            source.to_owned(),
            target.to_owned(),
        );
        let mut cached = self
            .observations
            .lock()
            .map_err(|_| anyhow::anyhow!("Ownership observation cache was poisoned"))?;
        if !cached.contains_key(&key) {
            let started = Instant::now();
            cached.insert(key.clone(), Arc::new(load_reference(reference, source, target)?));
            tracing::info!(
                "discover: loaded ownership observations once in {:.3}s ({})",
                started.elapsed().as_secs_f64(),
                reference.file
            );
        }
        Ok(cached[&key].clone())
    }
}

const VALIDATION: &str = "canonical attributed ownership and objdiff matched code; retail hash checks split integrity, not candidate source linkage";

/// Sections whose ranges a code candidate may claim.
pub const CODE_SECTIONS: [&str; 2] = [".text", ".init"];

/// What a discovery candidate proposes: a complete replacement body for a unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub lines: Vec<String>,
    pub kind: Kind,
    #[serde(default)]
    pub before_lines: Vec<String>,
    /// For a code candidate that also adds data, this is the complete body
    /// after code alone. Data evidence must reproduce `lines` from this body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_lines: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<ObservationReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<OwnershipAssessment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_evidence: Option<DataEvidenceReference>,
    /// Independently evidenced data body to try if neither the combined nor
    /// the code-only body survives its trial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_data: Option<Box<Proposal>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Code,
    Data,
}

fn format_range(section: &str, start: u32, end: u32) -> String {
    format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
}

fn ranges_in(lines: &[String], section: &str) -> Vec<(u32, u32)> {
    lines
        .iter()
        .filter_map(|line| parse_range(line))
        .filter(|range| range.section == section)
        .map(|range| (range.start, range.end))
        .collect()
}

fn code_ranges(lines: &[String]) -> BTreeMap<String, Vec<(u32, u32)>> {
    let mut result: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
    for range in lines
        .iter()
        .filter_map(|line| parse_range(line))
        .filter(|range| CODE_SECTIONS.contains(&range.section.as_str()))
    {
        result.entry(range.section).or_default().push((range.start, range.end));
    }
    result
}

fn assess_code(
    observations: &ObservationIndex,
    unit: &str,
    before: &[String],
    after: &[String],
) -> OwnershipAssessment {
    observations.assess(unit, "main", &code_ranges(before), &code_ranges(after))
}

fn claimed_code_bytes(lines: &[String]) -> u32 {
    lines
        .iter()
        .filter_map(|line| parse_range(line))
        .filter(|range| CODE_SECTIONS.contains(&range.section.as_str()))
        .map(|range| range.end - range.start)
        .sum()
}

fn compare_code_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    let left_proposal = proposal_of(left).expect("fresh discovery candidate must be valid");
    let left_ownership = left_proposal
        .ownership
        .as_ref()
        .expect("fresh code candidate must contain an ownership certificate");
    let right_proposal = proposal_of(right).expect("fresh discovery candidate must be valid");
    let right_ownership = right_proposal
        .ownership
        .as_ref()
        .expect("fresh code candidate must contain an ownership certificate");
    (
        Reverse(left_ownership.complete_membership),
        Reverse(left_ownership.supported_edges),
        Reverse(left_ownership.independent_members),
        left_ownership.padding_bytes,
        Reverse(claimed_code_bytes(&left_proposal.lines)),
    )
        .cmp(&(
            Reverse(right_ownership.complete_membership),
            Reverse(right_ownership.supported_edges),
            Reverse(right_ownership.independent_members),
            right_ownership.padding_bytes,
            Reverse(claimed_code_bytes(&right_proposal.lines)),
        ))
        .then_with(|| left.name.cmp(&right.name))
}

/// Ranges every unit other than `name` already claims in `section`.
fn occupied(
    existing: &IndexMap<String, Vec<String>>,
    name: &str,
    section: &str,
) -> Vec<(u32, u32)> {
    existing
        .iter()
        .filter(|(other, _)| other.as_str() != name)
        .flat_map(|(_, lines)| ranges_in(lines, section))
        .collect()
}

/// Merges a unit's proposed and existing ranges in one section into one span.
///
/// Returns `None` when there is nothing to change, or when the span would
/// overlap a range another unit already owns.
fn merged_span(
    proposed: &[(u32, u32)],
    current: &[(u32, u32)],
    taken: &[(u32, u32)],
) -> Option<(u32, u32)> {
    let start = proposed.iter().chain(current).map(|r| r.0).min()?;
    let end = proposed.iter().chain(current).map(|r| r.1).max()?;
    if current == [(start, end)] {
        return None;
    }
    if taken.iter().any(|&(a, b)| start < b && a < end) {
        return None;
    }
    Some((start, end))
}

/// Proposals that widen or create a unit's code range.
///
/// Gaps inside the proposed span are kept rather than trimmed: the compiler
/// comparison is what tests ownership, and a partial code split can expose many
/// matching functions even when the rest of the translation unit is unfinished
/// or genuinely differs between versions. A span is never allowed to cross into
/// a range another established unit owns.
pub fn code_proposals(
    proposals: &IndexMap<String, Vec<String>>,
    existing: &IndexMap<String, Vec<String>>,
) -> Vec<(String, Vec<String>)> {
    let mut result: Vec<(String, Vec<String>)> = Vec::new();
    for (name, lines) in proposals {
        let sections: BTreeSet<String> = lines
            .iter()
            .filter_map(|line| parse_range(line))
            .filter(|range| CODE_SECTIONS.contains(&range.section.as_str()))
            .map(|range| range.section)
            .collect();
        if sections.is_empty() {
            continue;
        }
        let mut body: Vec<String> = existing.get(name).cloned().unwrap_or_default();
        for section in &sections {
            let proposed = ranges_in(lines, section);
            let current = ranges_in(&body, section);
            let taken = occupied(existing, name, section);
            let Some((start, end)) = merged_span(&proposed, &current, &taken) else { continue };
            body.retain(|line| parse_range(line).is_none_or(|r| &r.section != section));
            body.push(format_range(section, start, end));
        }
        if !body.is_empty() && Some(&body) != existing.get(name) {
            result.push((name.clone(), body));
        }
    }
    // Most code first: the biggest measurable gain per build.
    result.sort_by_key(|(_, body)| {
        let bytes: i64 = body
            .iter()
            .filter_map(|line| parse_range(line))
            .filter(|range| CODE_SECTIONS.contains(&range.section.as_str()))
            .map(|range| i64::from(range.end) - i64::from(range.start))
            .sum();
        -bytes
    });
    result
}

/// True when this unit emits no code at all in the source version.
///
/// Such a unit can never be reached by a code pass: there is no `.text` to
/// anchor on. Its data can still be proposed by symbol name, so it is the one
/// case where a data proposal may create a target unit outright. This asks the
/// *source* split rather than the proposal, because a proposal missing `.text`
/// usually means the matcher could not place the code — which is the case this
/// rule exists to reject.
fn data_only_in_source(source: &IndexMap<String, Vec<String>>, name: &str) -> bool {
    source.get(name).is_some_and(|body| {
        !body.is_empty()
            && !body
                .iter()
                .filter_map(|line| parse_range(line))
                .any(|range| CODE_SECTIONS.contains(&range.section.as_str()))
    })
}

fn is_bss_section(section: &str) -> bool { matches!(section, ".bss" | ".sbss" | ".sbss2") }

/// Proposals that extend an established unit with its non-code sections.
///
/// The matcher proposes a range for every section by symbol-name
/// correspondence, but [`code_proposals`] only ever acts on code. A unit whose
/// code is already split and matched can still be missing its `.rodata`,
/// `.bss`, `.sdata` or `.sbss`: the symbols are already correctly named, the
/// range was already proposed, nothing ever claimed it, it was simply never
/// carried over.
pub fn data_proposals(
    proposals: &IndexMap<String, Vec<String>>,
    existing: &IndexMap<String, Vec<String>>,
    source: &IndexMap<String, Vec<String>>,
) -> Vec<(String, Vec<String>)> {
    data_proposals_with_certificates(
        proposals,
        existing,
        source,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
}

type DataProofKey = (String, String, u32, u32);
type OrdinaryBssProofs = BTreeMap<DataProofKey, String>;
type JumpTableProofs = BTreeMap<DataProofKey, String>;

fn ordinary_bss_proofs(report: &DataEvidenceReport) -> OrdinaryBssProofs {
    report
        .ranges
        .iter()
        .filter(|range| range.eligible() && range.ordinary_bss_proven())
        .map(|range| {
            (
                (range.unit.clone(), range.section.clone(), range.start, range.end),
                range.compiled_ordinary_bss.as_ref().unwrap().next_owner.clone(),
            )
        })
        .collect()
}

fn jump_table_proofs(report: &DataEvidenceReport) -> JumpTableProofs {
    report
        .ranges
        .iter()
        .filter(|range| range.eligible() && range.jump_table_proven())
        .map(|range| {
            (
                (range.unit.clone(), range.section.clone(), range.start, range.end),
                range.compiled_jump_table.as_ref().unwrap().next_unit.clone(),
            )
        })
        .collect()
}

fn holds_next_range(
    existing: &IndexMap<String, Vec<String>>,
    owner: &str,
    section: &str,
    end: u32,
) -> bool {
    existing.get(owner).is_some_and(|lines| {
        lines.iter().any(|line| {
            parse_range(line).is_some_and(|range| {
                range.section == section
                    && range.start == end
                    && range.end > end
                    && !parse_attributes(line).contains("common")
            })
        })
    })
}

/// The paired next data symbol may still be unrepresented. If its source
/// unit has acquired a split, that split must begin at the observed seam.
fn preserves_named_next_boundary(
    existing: &IndexMap<String, Vec<String>>,
    expected: &str,
    section: &str,
    end: u32,
) -> bool {
    if existing.iter().any(|(unit, lines)| {
        unit != expected && ranges_in(lines, section).iter().any(|&(start, _)| start == end)
    }) {
        return false;
    }
    let next_ranges = existing.get(expected).map(|lines| ranges_in(lines, section));
    next_ranges.is_none_or(|ranges| {
        ranges.is_empty() || ranges.iter().any(|&(start, right)| start == end && right > end)
    })
}

fn data_proposals_with_certificates(
    proposals: &IndexMap<String, Vec<String>>,
    existing: &IndexMap<String, Vec<String>>,
    source: &IndexMap<String, Vec<String>>,
    ordinary_bss: &OrdinaryBssProofs,
    jump_tables: &JumpTableProofs,
) -> Vec<(String, Vec<String>)> {
    let mut names: Vec<String> = existing.keys().cloned().collect();
    names.extend(
        proposals
            .keys()
            .filter(|name| !existing.contains_key(*name) && data_only_in_source(source, name))
            .cloned(),
    );

    let mut result: Vec<(String, Vec<String>)> = Vec::new();
    for name in names {
        let body = existing.get(&name).cloned().unwrap_or_default();
        let Some(lines) = proposals.get(&name) else { continue };
        let mut new_body = body.clone();
        for line in lines {
            let Some(range) = parse_range(line) else { continue };
            if CODE_SECTIONS.contains(&range.section.as_str()) || range.start >= range.end {
                continue;
            }
            // A matched data range is evidence for its own addresses only.
            // Neither a gap between two ranges nor the source version's total
            // section size establishes ownership of intervening bytes.
            if occupied(existing, &name, &range.section)
                .iter()
                .any(|&(start, end)| range.start < end && start < range.end)
            {
                continue;
            }
            let proposed_attributes = parse_attributes(line);
            // An unannotated new BSS interval may be ordinary or common.
            // An existing ordinary range can establish its own mode; a new
            // allocation needs the exact whole-range compiled certificate.
            let existing_overlap = new_body.iter().any(|current_line| {
                parse_range(current_line).is_some_and(|current| {
                    current.section == range.section
                        && range.start < current.end
                        && current.start < range.end
                })
            });
            if is_bss_section(&range.section)
                && !existing_overlap
                && !proposed_attributes.contains("common")
                && !ordinary_bss
                    .get(&(name.clone(), range.section.clone(), range.start, range.end))
                    .is_some_and(|owner| {
                        holds_next_range(existing, owner, &range.section, range.end)
                    })
            {
                continue;
            }
            if let Some(owner) =
                jump_tables.get(&(name.clone(), range.section.clone(), range.start, range.end))
                && !preserves_named_next_boundary(existing, owner, &range.section, range.end)
            {
                continue;
            }
            let mut overlapping = Vec::new();
            let mut conflict = false;
            for (index, current_line) in new_body.iter().enumerate() {
                let Some(current) = parse_range(current_line) else { continue };
                if current.section != range.section {
                    continue;
                }
                let same_attributes = parse_attributes(current_line) == proposed_attributes;
                if range.start < current.end && current.start < range.end && !same_attributes {
                    conflict = true;
                    break;
                }
                if range.start < current.end && current.start < range.end && same_attributes {
                    overlapping.push((index, current.start, current.end));
                }
            }
            // One existing interval may be widened without changing its
            // split attributes. Several overlapping intervals remain separate;
            // folding them together would erase a potentially real allocation
            // boundary inside this section.
            if conflict || overlapping.len() > 1 {
                continue;
            }
            if let Some((index, start, end)) = overlapping.into_iter().next() {
                let suffix = entry_suffix(&new_body[index]);
                new_body[index] =
                    entry_line(&range.section, start.min(range.start), end.max(range.end), &suffix);
            } else {
                let insert_at = new_body
                    .iter()
                    .rposition(|current| {
                        parse_range(current).is_some_and(|current| current.section == range.section)
                    })
                    .map_or(new_body.len(), |index| index + 1);
                new_body.insert(
                    insert_at,
                    entry_line(&range.section, range.start, range.end, &entry_suffix(line)),
                );
            }
        }
        if new_body != body {
            result.push((name, new_body));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// A text proposal is usable as data only when the typed matcher record names
/// the identical range and every member of that record cleared its gates.
fn evidenced_data_lines(
    proposals: &IndexMap<String, Vec<String>>,
    report: &DataEvidenceReport,
) -> IndexMap<String, Vec<String>> {
    let witnessed: BTreeSet<(&str, &str, u32, u32)> = report
        .ranges
        .iter()
        .filter(|range| range.eligible())
        .map(|range| (range.unit.as_str(), range.section.as_str(), range.start, range.end))
        .collect();
    proposals
        .iter()
        .filter_map(|(unit, lines)| {
            let supported: Vec<String> = lines
                .iter()
                .filter(|line| {
                    parse_range(line).is_some_and(|range| {
                        witnessed.contains(&(
                            unit.as_str(),
                            range.section.as_str(),
                            range.start,
                            range.end,
                        ))
                    })
                })
                .cloned()
                .collect();
            (!supported.is_empty()).then_some((unit.clone(), supported))
        })
        .collect()
}

/// Complete one code claim with every compatible, independently witnessed
/// data range for the same unit. The projected map keeps the other owners in
/// place while testing overlaps, and the result is one complete candidate.
fn data_completion(
    unit: &str,
    code_lines: &[String],
    witnessed_data: &IndexMap<String, Vec<String>>,
    existing: &IndexMap<String, Vec<String>>,
    source: &IndexMap<String, Vec<String>>,
    ordinary_bss: &OrdinaryBssProofs,
    jump_tables: &JumpTableProofs,
) -> Option<Vec<String>> {
    let ranges = witnessed_data.get(unit)?;
    let mut projected = existing.clone();
    projected.insert(unit.to_string(), code_lines.to_vec());
    let proposed = IndexMap::from([(unit.to_string(), ranges.clone())]);
    data_proposals_with_certificates(&proposed, &projected, source, ordinary_bss, jump_tables)
        .into_iter()
        .find(|(name, _)| name == unit)
        .map(|(_, lines)| lines)
}

/// Whether any unit's matched code went down.
fn regresses(before: &Report, after: &Report) -> bool {
    let new = after.by_source_name();
    before.by_source_name().iter().any(|(name, unit)| {
        new.get(name).map(|u| u.matched_code()).unwrap_or(0) < unit.matched_code()
    })
}

fn matched(report: &Report, name: &str) -> u64 {
    report.by_source_name().get(name).map(|u| u.matched_code()).unwrap_or(0)
}

impl Stage for Discover {
    fn name(&self) -> &'static str { "discover" }

    fn scopes(&self, candidate: &Candidate) -> Result<BTreeSet<MutationScope>> {
        let proposal = proposal_of(candidate)?;
        let name = candidate.name.clone();
        Ok(match proposal.kind {
            Kind::Data => BTreeSet::from([MutationScope::UnitData(name)]),
            Kind::Code if proposal.code_lines.is_some() => {
                BTreeSet::from([MutationScope::Unit(name.clone()), MutationScope::UnitData(name)])
            }
            Kind::Code => BTreeSet::from([MutationScope::Unit(name)]),
        })
    }

    fn choose_variants(&self, candidates: Vec<Candidate>) -> Result<Vec<Candidate>> {
        let mut names = BTreeSet::new();
        Ok(candidates
            .into_iter()
            .filter(|candidate| names.insert(candidate.name.clone()))
            .collect())
    }

    fn prepare(&self, ctx: &BuildContext, limit: Option<usize>) -> Result<Prepared> {
        std::fs::create_dir_all(&ctx.output)?;
        let splits_path = ctx.root.join("config").join(&ctx.target).join("splits.txt");
        let symbols_path = splits_path.with_file_name("symbols.txt");

        let starting = ctx.build(None)?;
        let mut symbols = Owned::take(&symbols_path)?;
        let mut events: Vec<Event> = Vec::new();

        let proposals_path = ctx.output.join("proposals.txt");
        let data_evidence_path = ctx.output.join("data-evidence.json");
        let renames_path = ctx.output.join("renames.txt");
        let coverage_path = ctx.output.join("ownership-evidence.json");
        let mut request = crate::matching::Request::new(
            config_path(ctx, &ctx.source),
            config_path(ctx, &ctx.target),
        );
        request.object_root = Some(ctx.root.clone());
        request.outputs = crate::matching::Outputs {
            splits: Some(proposals_path.clone()),
            data_evidence: Some(data_evidence_path.clone()),
            renames: Some(renames_path.clone()),
            report: Some(ctx.output.join("matches.json")),
            coverage: Some(coverage_path.clone()),
            ..Default::default()
        };
        if let Some(directory) = crate::stages::coverage::injected_evidence_dir() {
            // The same frozen directory as coverage's coordinator fixture.
            // Its digest is recorded in the run environment, including these
            // typed discovery inputs, so resume cannot silently replace them.
            for (source, destination) in [
                ("discover-proposals.txt", &proposals_path),
                ("discover-data-evidence.json", &data_evidence_path),
                ("discover-renames.txt", &renames_path),
            ] {
                std::fs::copy(directory.join(source), destination)?;
            }
            let named = Splits::read(&splits_path)?.blocks.len();
            std::fs::copy(directory.join(format!("{named}.json")), &coverage_path)?;
        } else {
            crate::matching::run(&request)?;
        }

        // Confident renames are applied once, up front: `dtk match` anchors its
        // proposals on symbol names, so a name established here widens what
        // every later candidate can be. The batch is kept only if it builds and
        // costs no existing unit its matched code.
        let reason = if ctx.only.is_empty() {
            match apply_renames(ctx, &mut symbols, &renames_path, &starting) {
                Ok(None) => None,
                Ok(Some(reason)) => Some((reason, Refusal {
                    kind: RefusalKind::MeasuredRegression,
                    affected: Vec::new(),
                    command: None,
                })),
                Err(error) if is_trial_failure(&error) => {
                    Some((format!("{error:#}"), Refusal::from_error(&error)))
                }
                Err(error) => return Err(error),
            }
        } else {
            // These renames span the whole executable, not only the selected
            // TU. The matcher's split proposals were generated before this
            // batch, so a focused run can still evaluate its requested unit
            // without publishing unrelated symbol changes.
            let renames = std::fs::read_to_string(&renames_path)
                .with_context(|| format!("Failed to read {}", renames_path.display()))?;
            if renames
                .lines()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            {
                events.push(Event::new("", "rename-batch-skipped-by-only"));
            }
            None
        };
        if let Some((reason, refusal)) = reason {
            symbols.restore()?;
            events.push(Event::new("", "rename-batch-reverted").because(reason).refused(refusal));
        }
        symbols.commit();

        let baseline = ctx.build(None)?;
        let blocks = Splits::read(&splits_path)?.blocks;
        let proposals = Splits::read(&proposals_path)?.blocks;
        let data_evidence =
            DataEvidenceReference::of(&data_evidence_path, &ctx.source, &ctx.target)?;
        let data_report = data_evidence.load(&ctx.source, &ctx.target)?;
        let witnessed_data = evidenced_data_lines(&proposals, &data_report);
        let ordinary_bss = ordinary_bss_proofs(&data_report);
        let jump_tables = jump_table_proofs(&data_report);
        let source_blocks =
            Splits::read(&ctx.root.join("config").join(&ctx.source).join("splits.txt"))?.blocks;
        let evidence: CoverageReport = serde_json::from_slice(&std::fs::read(&coverage_path)?)?;
        let expected: BTreeSet<String> = source_blocks.keys().cloned().collect();
        let observations = ObservationIndex::load_enclosed_for_run(
            evidence.identifications,
            &evidence.source,
            &evidence.target,
            &ctx.source,
            &ctx.target,
            &expected,
        )?;
        let observation = observations.persist(&ctx.output)?;
        let _ = std::fs::remove_file(&coverage_path);

        let mut candidates: Vec<Candidate> = code_proposals(&proposals, &blocks)
            .into_iter()
            .filter_map(|(name, code_lines)| {
                let before = blocks.get(&name).cloned().unwrap_or_default();
                let ownership = assess_code(&observations, &name, &before, &code_lines);
                ownership.permits_automatic_claim().then(|| {
                    let completion = data_completion(
                        &name,
                        &code_lines,
                        &witnessed_data,
                        &blocks,
                        &source_blocks,
                        &ordinary_bss,
                        &jump_tables,
                    );
                    candidate(name, Proposal {
                        lines: completion.clone().unwrap_or_else(|| code_lines.clone()),
                        kind: Kind::Code,
                        before_lines: before,
                        code_lines: completion.as_ref().map(|_| code_lines),
                        observation: Some(observation.clone()),
                        ownership: Some(ownership),
                        data_evidence: completion.map(|_| data_evidence.clone()),
                        fallback_data: None,
                    })
                })
            })
            .collect::<Result<_>>()?;
        candidates.sort_by(compare_code_candidates);
        if let Some(limit) = limit {
            candidates.truncate(limit);
        }

        // The ordinary parser includes commented, whole-unit candidate ranges.
        // A data range enters only when the typed member record independently
        // proves its own bytes, even if other data in that TU is still unknown.
        // Keep the data-only form behind a combined code/data candidate. The
        // coordinator selects one form after applying reservations: if an
        // earlier stage owns the code, supported data can still be completed.
        let mut data: Vec<Candidate> = data_proposals_with_certificates(
            &witnessed_data,
            &blocks,
            &source_blocks,
            &ordinary_bss,
            &jump_tables,
        )
        .into_iter()
        .map(|(name, lines)| {
            let before_lines = blocks.get(&name).cloned().unwrap_or_default();
            candidate(name, Proposal {
                lines,
                kind: Kind::Data,
                before_lines,
                code_lines: None,
                observation: None,
                ownership: None,
                data_evidence: Some(data_evidence.clone()),
                fallback_data: None,
            })
        })
        .collect::<Result<_>>()?;
        if let Some(limit) = limit {
            // A data fallback for one of the chosen code units must not use
            // up the budget for an independent data-only unit.
            data.truncate(limit.saturating_add(candidates.len()));
        }
        let data_by_name: BTreeMap<String, Proposal> = data
            .iter()
            .map(|candidate| Ok((candidate.name.clone(), proposal_of(candidate)?)))
            .collect::<Result<_>>()?;
        for code in &mut candidates {
            if let Some(fallback) = data_by_name.get(&code.name) {
                let mut proposal = proposal_of(code)?;
                proposal.fallback_data = Some(Box::new(fallback.clone()));
                code.evidence = serde_json::to_value(proposal)?;
            }
        }
        let mut variants = Vec::new();
        for code in candidates {
            let code_only = proposal_of(&code)?.code_lines.is_some().then(|| next_fallback(&code));
            variants.push(code);
            if let Some(Some(code_only)) = code_only.transpose()? {
                variants.push(code_only);
            }
        }
        variants.extend(data);

        let mut extra = serde_json::Map::new();
        extra.insert("starting".into(), serde_json::to_value(&starting)?);
        Ok(Prepared {
            candidates: variants,
            baseline,
            events,
            extra,
            permitted: Default::default(),
        })
    }

    fn evaluate(
        &self,
        ctx: &BuildContext,
        _prepared: &Prepared,
        candidates: &[Candidate],
        _preferred: &Selections,
    ) -> Result<Outcome> {
        let names: BTreeSet<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        if names.len() != candidates.len() {
            bail!("Duplicate discovery candidate names");
        }
        let splits_path = ctx.root.join("config").join(&ctx.target).join("splits.txt");
        let mut owned = Owned::take(&splits_path)?;
        let mut splits = Splits::parse(&String::from_utf8(owned.original().to_vec())?)?;

        let mut state =
            Trials { report: ctx.build(None)?, accepted: IndexMap::new(), events: Vec::new() };
        let baseline_cycles = cyclic_units(&splits.blocks);
        if !candidates.is_empty() {
            let mut queue = vec![candidates.to_vec()];
            while let Some(batch) = queue.pop() {
                let retry =
                    state.trial(self, ctx, &mut owned, &mut splits, &batch, &baseline_cycles)?;
                match retry {
                    Retry::Done => {}
                    Retry::Split(halves) => queue.extend(halves.into_iter().rev()),
                }
            }
        }
        write(&mut owned, &splits)?;
        let final_report = ctx.build(None)?;
        if regresses(&state.report, &final_report) {
            bail!("Final discovery report regressed after validation");
        }
        owned.commit();

        let accepted: Vec<Candidate> = state.accepted.values().cloned().collect();
        let deferred: Vec<Candidate> =
            candidates.iter().filter(|c| !state.accepted.contains_key(&c.name)).cloned().collect();
        Ok(Outcome {
            tried: Default::default(),
            accepted,
            deferred,
            events: state.events,
            report: final_report,
            validation: VALIDATION.to_string(),
            applied: Vec::new(),
            selections: Selections::new(),
        })
    }

    fn validate(
        &self,
        ctx: &BuildContext,
        accepted: &[Candidate],
        _prepared: &Prepared,
        _selections: &Selections,
        _applied: &[crate::stages::Applied],
    ) -> Result<Report> {
        let blocks =
            Splits::read(&ctx.root.join("config").join(&ctx.target).join("splits.txt"))?.blocks;
        for candidate in accepted {
            let proposal = proposal_of(candidate)?;
            if blocks.get(&candidate.name) != Some(&proposal.lines) {
                bail!("Discovery split for {} changed after selection", candidate.name);
            }
            validate_proposal(self, ctx, &candidate.name, &proposal, true)?;
        }
        ctx.build(None)
    }
}

/// A version's project configuration, as the matcher wants it.
pub fn config_path(ctx: &BuildContext, version: &str) -> typed_path::Utf8NativePathBuf {
    let path = ctx.root.join("config").join(version).join("config.yml");
    typed_path::Utf8NativePathBuf::from(path.to_string_lossy().into_owned())
}

fn candidate(name: String, proposal: Proposal) -> Result<Candidate> {
    Ok(Candidate { evidence: serde_json::to_value(proposal)?, name })
}

fn proposal_of(candidate: &Candidate) -> Result<Proposal> {
    serde_json::from_value(candidate.evidence.clone())
        .with_context(|| format!("Missing split proposal for {}", candidate.name))
}

fn write(owned: &mut Owned, splits: &Splits) -> Result<()> {
    owned.write(splits.render().as_bytes())
}

/// Applies the matcher's confident renames, returning why they were reverted.
fn apply_renames(
    ctx: &BuildContext,
    symbols: &mut Owned,
    renames: &std::path::Path,
    starting: &Report,
) -> Result<Option<String>> {
    let text = std::fs::read_to_string(renames)
        .with_context(|| format!("Failed to read {}", renames.display()))?;
    if text.lines().all(|line| line.trim().is_empty() || line.trim_start().starts_with('#')) {
        return Ok(None);
    }
    let rename_set = crate::project::symbols::Renames::parse(&text)?;
    let current = String::from_utf8(std::fs::read(symbols.path())?)?;
    let (renamed, _) = crate::project::symbols::render_renames(&current, &rename_set);
    symbols.write(renamed.as_bytes())?;
    let after = ctx.build(None)?;
    Ok(regresses(starting, &after).then(|| "regressed existing matched code".to_string()))
}

enum Retry {
    Done,
    Split(Vec<Vec<Candidate>>),
}

struct Trials {
    report: Report,
    accepted: IndexMap<String, Candidate>,
    events: Vec<Event>,
}

fn next_fallback(candidate: &Candidate) -> Result<Option<Candidate>> {
    let mut proposal = proposal_of(candidate)?;
    if let Some(code_lines) = proposal.code_lines.take() {
        if proposal.kind != Kind::Code || proposal.data_evidence.is_none() {
            bail!(
                "Discovery code/data fallback has no paired data evidence for {}",
                candidate.name
            );
        }
        proposal.lines = code_lines;
        proposal.data_evidence = None;
        return Ok(Some(self::candidate(candidate.name.clone(), proposal)?));
    }
    proposal
        .fallback_data
        .take()
        .map(|fallback| {
            if fallback.kind != Kind::Data || fallback.fallback_data.is_some() {
                bail!("Invalid discovery data fallback for {}", candidate.name);
            }
            self::candidate(candidate.name.clone(), *fallback)
        })
        .transpose()
}

impl Trials {
    fn trial(
        &mut self,
        discover: &Discover,
        ctx: &BuildContext,
        owned: &mut Owned,
        splits: &mut Splits,
        batch: &[Candidate],
        baseline_cycles: &BTreeSet<String>,
    ) -> Result<Retry> {
        if batch.is_empty() {
            return Ok(Retry::Done);
        }
        let mut staged = splits.clone();
        let mut new_names: Vec<String> = Vec::new();
        for (index, candidate) in batch.iter().enumerate() {
            let proposal = proposal_of(candidate)?;
            if let Err(error) = validate_proposal(discover, ctx, &candidate.name, &proposal, false)
            {
                let mut alternative = next_fallback(candidate)?;
                while let Some(fallback) = alternative {
                    match validate_proposal(
                        discover,
                        ctx,
                        &candidate.name,
                        &proposal_of(&fallback)?,
                        false,
                    ) {
                        Ok(()) => {
                            self.events.push(
                                Event::new(&candidate.name, "evidence-refused")
                                    .because(format!("{error:#}"))
                                    .refused(Refusal::from_error(&error)),
                            );
                            let mut revised = batch.to_vec();
                            revised[index] = fallback;
                            return Ok(Retry::Split(vec![revised]));
                        }
                        Err(_) => alternative = next_fallback(&fallback)?,
                    }
                }
                return Err(error);
            }
            if !staged.blocks.contains_key(&candidate.name) {
                new_names.push(candidate.name.clone());
            }
            staged.blocks.insert(candidate.name.clone(), proposal.lines);
        }

        // dtk rejects a cyclic link order before compiling anything, so a batch
        // that implies one can be bisected without paying for a build. Only a
        // cycle this batch introduces counts: candidates drag otherwise-fine
        // units into a component with them, and an input that was already
        // cyclic is the caller's problem, not this batch's.
        let introduced: BTreeSet<String> =
            cyclic_units(&staged.blocks).difference(baseline_cycles).cloned().collect();
        if batch.iter().any(|c| introduced.contains(&c.name)) {
            return self.reject(
                owned,
                splits,
                batch,
                "link-order-cycle",
                Some(Refusal {
                    kind: RefusalKind::LinkOrderCycle,
                    affected: introduced.into_iter().collect(),
                    command: None,
                }),
            );
        }

        staged.place_new_units(&new_names)?;
        write(owned, &staged)?;
        let tested = match ctx.trial_build() {
            Ok(report) => report,
            Err(error) if is_trial_failure(&error) => {
                return self.reject(
                    owned,
                    splits,
                    batch,
                    "build-conflict",
                    Some(Refusal::from_error(&error)),
                );
            }
            Err(error) => return Err(error),
        };

        // A data candidate only extends an already-matched unit's data ranges;
        // it never moves the matched-code count, so the gain test does not apply
        // to it. It still passes the build and retail check above and the
        // regression check below.
        let (keep, dropped): (Vec<&Candidate>, Vec<&Candidate>) =
            batch.iter().partition(|candidate| {
                proposal_of(candidate).map(|p| p.kind).unwrap_or(Kind::Code) == Kind::Data
                    || matched(&tested, &candidate.name) > matched(&self.report, &candidate.name)
            });
        if !dropped.is_empty() {
            self.events.extend(dropped.iter().map(|c| Event::new(&c.name, "no-matched-code-gain")));
            write(owned, splits)?;
            let mut retry: Vec<Vec<Candidate>> = Vec::new();
            if !keep.is_empty() {
                retry.push(keep.into_iter().cloned().collect());
            }
            for candidate in dropped {
                if let Some(fallback) = next_fallback(candidate)? {
                    retry.push(vec![fallback]);
                }
            }
            return Ok(if retry.is_empty() { Retry::Done } else { Retry::Split(retry) });
        }
        if regresses(&self.report, &tested) {
            return self.reject(
                owned,
                splits,
                batch,
                "regresses-existing-code",
                Some(Refusal {
                    kind: RefusalKind::MeasuredRegression,
                    affected: batch.iter().map(|c| c.name.clone()).collect(),
                    command: None,
                }),
            );
        }

        for candidate in batch {
            let gain = matched(&tested, &candidate.name) as i64
                - matched(&self.report, &candidate.name) as i64;
            self.events.push(
                Event::new(&candidate.name, "accepted").because(format!("{gain} code bytes")),
            );
            let proposal = proposal_of(candidate)?;
            let is_new = !splits.blocks.contains_key(&candidate.name);
            splits.blocks.insert(candidate.name.clone(), proposal.lines);
            if is_new {
                splits.place_new_units(std::slice::from_ref(&candidate.name))?;
            }
            self.accepted.insert(candidate.name.clone(), candidate.clone());
        }
        self.report = tested;
        Ok(Retry::Done)
    }

    /// Puts the accepted state back, then halves the batch or records a single
    /// candidate's rejection.
    fn reject(
        &mut self,
        owned: &mut Owned,
        splits: &Splits,
        batch: &[Candidate],
        status: &str,
        refusal: Option<Refusal>,
    ) -> Result<Retry> {
        write(owned, splits)?;
        if batch.len() > 1 {
            let middle = batch.len() / 2;
            return Ok(Retry::Split(vec![batch[..middle].to_vec(), batch[middle..].to_vec()]));
        }
        let mut event = Event::new(&batch[0].name, status);
        if let Some(refusal) = refusal {
            event = event.refused(refusal);
        }
        self.events.push(event);
        if let Some(fallback) = next_fallback(&batch[0])? {
            return Ok(Retry::Split(vec![vec![fallback]]));
        }
        Ok(Retry::Done)
    }
}

fn validate_proposal(
    discover: &Discover,
    ctx: &BuildContext,
    unit: &str,
    proposal: &Proposal,
    applied: bool,
) -> Result<()> {
    if proposal.kind == Kind::Data {
        return validate_data_proposal(ctx, unit, proposal, applied);
    }
    if proposal.code_lines.is_some() != proposal.data_evidence.is_some() {
        bail!("Discovery code/data evidence is incomplete for {unit}");
    }
    let reference = proposal
        .observation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Code proposal for {unit} has no ownership observations"))?;
    let recorded = proposal
        .ownership
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Code proposal for {unit} has no ownership certificate"))?;
    let observations = discover.observations(reference, &ctx.source, &ctx.target)?;
    let blocks =
        Splits::read(&ctx.root.join("config").join(&ctx.target).join("splits.txt"))?.blocks;
    let expected = if applied { &proposal.lines } else { &proposal.before_lines };
    if blocks.get(unit).map(Vec::as_slice).unwrap_or_default() != expected {
        bail!("Discovery ownership baseline changed for {unit}");
    }
    let actual = assess_code(&observations, unit, &proposal.before_lines, &proposal.lines);
    if &actual != recorded || actual.observation_sha256 != reference.sha256 {
        bail!("Discovery ownership certificate is stale for {unit}");
    }
    if !actual.permits_automatic_claim() {
        bail!("Discovery ownership evidence does not support {unit}");
    }
    if proposal.data_evidence.is_some() {
        validate_data_proposal(ctx, unit, proposal, applied)?;
    }
    Ok(())
}

fn validate_data_proposal(
    ctx: &BuildContext,
    unit: &str,
    proposal: &Proposal,
    applied: bool,
) -> Result<()> {
    let reference = proposal
        .data_evidence
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Data proposal for {unit} has no member evidence"))?;
    let report = reference.load(&ctx.source, &ctx.target)?;
    let mut blocks =
        Splits::read(&ctx.root.join("config").join(&ctx.target).join("splits.txt"))?.blocks;
    let expected = if applied { &proposal.lines } else { &proposal.before_lines };
    if blocks.get(unit).map(Vec::as_slice).unwrap_or_default() != expected {
        bail!("Discovery data baseline changed for {unit}");
    }
    if proposal.before_lines.is_empty() {
        blocks.shift_remove(unit);
    } else {
        blocks.insert(unit.to_string(), proposal.before_lines.clone());
    }
    if let Some(code_lines) = &proposal.code_lines {
        if proposal.kind != Kind::Code
            || code_ranges(code_lines) != code_ranges(&proposal.lines)
            || unchanged_non_code(code_lines) != unchanged_non_code(&proposal.before_lines)
        {
            bail!("Discovery code and data bodies disagree for {unit}");
        }
        blocks.insert(unit.to_string(), code_lines.clone());
    }
    let source =
        Splits::read(&ctx.root.join("config").join(&ctx.source).join("splits.txt"))?.blocks;
    if reproduced_data_body(&report, unit, &blocks, &source).as_ref() != Some(&proposal.lines) {
        bail!("Discovery data evidence does not reproduce the complete body for {unit}");
    }
    Ok(())
}

fn unchanged_non_code(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| {
            parse_range(line).is_none_or(|range| !CODE_SECTIONS.contains(&range.section.as_str()))
        })
        .collect()
}

fn reproduced_data_body(
    report: &DataEvidenceReport,
    unit: &str,
    before: &IndexMap<String, Vec<String>>,
    source: &IndexMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    let witnessed: IndexMap<String, Vec<String>> = report
        .ranges
        .iter()
        .filter(|range| range.unit == unit && range.eligible())
        .map(|range| {
            (
                unit.to_string(),
                format_range(&range.section, range.start, range.end) + &range.split_suffix(),
            )
        })
        .fold(IndexMap::new(), |mut blocks, (name, line)| {
            blocks.entry(name).or_default().push(line);
            blocks
        });
    data_proposals_with_certificates(
        &witnessed,
        before,
        source,
        &ordinary_bss_proofs(report),
        &jump_table_proofs(report),
    )
    .into_iter()
    .find(|(name, _)| name == unit)
    .map(|(_, lines)| lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{ownership::IdentificationReport, unit_matching::UnitTier},
        matching::data_evidence::{
            CommonAlignBasis, DataMemberEvidence, DataRangeEvidence, DataSizeBasis,
        },
    };

    fn blocks(entries: &[(&str, &[&str])]) -> IndexMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(name, lines)| {
                ((*name).to_string(), lines.iter().map(|l| (*l).to_string()).collect())
            })
            .collect()
    }

    fn text(start: u32, end: u32) -> String { format_range(".text", start, end) }
    fn data(start: u32, end: u32) -> String { format_range(".data", start, end) }
    fn bss(start: u32, end: u32) -> String { format_range(".bss", start, end) }
    fn sbss(start: u32, end: u32) -> String { format_range(".sbss", start, end) }

    #[test]
    fn code_trials_share_one_verified_ownership_report() {
        let directory = tempfile::tempdir().unwrap();
        let index = ObservationIndex::load_self_contained(
            IdentificationReport::empty("NTSC", "PAL"),
            "NTSC",
            "PAL",
        )
        .unwrap();
        let reference = index.persist(directory.path()).unwrap();
        let discover = Discover::default();
        let first = discover.observations(&reference, "NTSC", "PAL").unwrap();
        let second = discover.observations(&reference, "NTSC", "PAL").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(discover.observations(&reference, "NTSC", "different-target").is_err());
    }

    #[test]
    fn a_bounded_ordinary_bss_witness_does_not_admit_any_other_bss_range() {
        let before =
            blocks(&[("audio.cpp", &[&text(0x100, 0x200)]), ("next.cpp", &[&bss(0x20f0, 0x2180)])]);
        let source = blocks(&[("audio.cpp", &[&text(0x100, 0x200), &bss(0x400, 0x500)])]);
        let proposals = blocks(&[("audio.cpp", &[&bss(0x2000, 0x20f0), &bss(0x2100, 0x2180)])]);
        assert!(data_proposals(&proposals, &before, &source).is_empty());
        let ordinary = BTreeMap::from([(
            ("audio.cpp".into(), ".bss".into(), 0x2000, 0x20f0),
            "next.cpp".into(),
        )]);
        let result = data_proposals_with_certificates(
            &proposals,
            &before,
            &source,
            &ordinary,
            &BTreeMap::new(),
        );
        assert_eq!(result, vec![("audio.cpp".into(), vec![
            text(0x100, 0x200),
            bss(0x2000, 0x20f0),
        ])]);
        let moved =
            blocks(&[("audio.cpp", &[&text(0x100, 0x200)]), ("next.cpp", &[&bss(0x2100, 0x2180)])]);
        assert!(
            data_proposals_with_certificates(
                &proposals,
                &moved,
                &source,
                &ordinary,
                &BTreeMap::new(),
            )
            .is_empty()
        );
        let changed_mode = blocks(&[
            ("audio.cpp", &[&text(0x100, 0x200)]),
            ("next.cpp", &[&format!("{} common", bss(0x20f0, 0x2180))]),
        ]);
        assert!(
            data_proposals_with_certificates(
                &proposals,
                &changed_mode,
                &source,
                &ordinary,
                &BTreeMap::new(),
            )
            .is_empty()
        );
    }

    #[test]
    fn a_compiled_jump_table_requires_its_recorded_following_owner_at_replay() {
        let source = blocks(&[("sound.cpp", &[&data(0x3000, 0x3100)])]);
        let proposals = blocks(&[("sound.cpp", &[&data(0x1000, 0x1100)])]);
        let before = blocks(&[
            ("sound.cpp", &[&data(0x1000, 0x1070)]),
            ("next.cpp", &[&data(0x1100, 0x1200)]),
        ]);
        let jump_tables = BTreeMap::from([(
            ("sound.cpp".into(), ".data".into(), 0x1000, 0x1100),
            "next.cpp".into(),
        )]);
        let accepted = data_proposals_with_certificates(
            &proposals,
            &before,
            &source,
            &BTreeMap::new(),
            &jump_tables,
        );
        assert_eq!(accepted, vec![("sound.cpp".into(), vec![data(0x1000, 0x1100)])]);

        let unrepresented = blocks(&[("sound.cpp", &[&data(0x1000, 0x1070)])]);
        assert_eq!(
            data_proposals_with_certificates(
                &proposals,
                &unrepresented,
                &source,
                &BTreeMap::new(),
                &jump_tables,
            ),
            accepted,
        );

        let moved = blocks(&[
            ("sound.cpp", &[&data(0x1000, 0x1070)]),
            ("next.cpp", &[&data(0x1110, 0x1200)]),
        ]);
        assert!(
            data_proposals_with_certificates(
                &proposals,
                &moved,
                &source,
                &BTreeMap::new(),
                &jump_tables,
            )
            .is_empty()
        );
    }

    #[test]
    fn data_candidate_is_reproduced_only_from_its_member_evidence() {
        let report = DataEvidenceReport {
            schema: crate::matching::data_evidence::SCHEMA,
            source: "NTSC".into(),
            target: "PAL".into(),
            source_image_sha256: "0".repeat(64),
            target_image_sha256: "1".repeat(64),
            ranges: vec![DataRangeEvidence {
                unit: "a.cpp".into(),
                section: ".data".into(),
                start: 0x900,
                end: 0xA00,
                tier: UnitTier::Candidate,
                reasons: vec!["source unit has other unresolved data".into()],
                required_alignment: 4,
                members: vec![DataMemberEvidence {
                    source_index: 0,
                    target_index: 0,
                    source_name: "source_data".into(),
                    target_name: "target_data".into(),
                    target_start: 0x900,
                    target_end: 0xA00,
                    source_extent_known: true,
                    target_extent_known: true,
                    target_size_basis: DataSizeBasis::FixedWidth,
                    source_wholly_owned: true,
                    source_weak: false,
                    target_weak: false,
                    target_symbol_common: false,
                    target_common_align: None,
                    target_common_align_basis: None,
                    reference_positions: 2,
                    target_owner: None,
                    target_common: None,
                }],
                compiled_ordinary_bss: None,
                compiled_jump_table: None,
            }],
        };
        let text_proposals = blocks(&[("a.cpp", &[&data(0x900, 0xA00), &data(0xA00, 0xB00)])]);
        let witnessed = evidenced_data_lines(&text_proposals, &report);
        assert_eq!(witnessed["a.cpp"], [data(0x900, 0xA00)]);

        let before = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let source = blocks(&[("a.cpp", &[&text(0x100, 0x200), &data(0x800, 0x900)])]);
        assert_eq!(
            reproduced_data_body(&report, "a.cpp", &before, &source),
            Some(vec![text(0x100, 0x200), data(0x900, 0xA00)])
        );
        let code_lines = vec![text(0x100, 0x300)];
        let completed = data_completion(
            "a.cpp",
            &code_lines,
            &witnessed,
            &before,
            &source,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(completed, vec![text(0x100, 0x300), data(0x900, 0xA00)]);
        assert_eq!(code_ranges(&completed), code_ranges(&code_lines));
        assert_eq!(unchanged_non_code(&code_lines), unchanged_non_code(&before["a.cpp"]));
        let mut joint = candidate("a.cpp".into(), Proposal {
            lines: completed,
            kind: Kind::Code,
            before_lines: before["a.cpp"].clone(),
            code_lines: Some(code_lines.clone()),
            observation: None,
            ownership: None,
            data_evidence: Some(DataEvidenceReference {
                schema: crate::matching::data_evidence::SCHEMA,
                sha256: "0".repeat(64),
                file: "data-evidence.json".into(),
            }),
            fallback_data: None,
        })
        .unwrap();
        let data_only = candidate("a.cpp".into(), Proposal {
            lines: vec![text(0x100, 0x200), data(0x900, 0xA00)],
            kind: Kind::Data,
            before_lines: before["a.cpp"].clone(),
            code_lines: None,
            observation: None,
            ownership: None,
            data_evidence: proposal_of(&joint).unwrap().data_evidence,
            fallback_data: None,
        })
        .unwrap();
        let mut joint_proposal = proposal_of(&joint).unwrap();
        joint_proposal.fallback_data = Some(Box::new(proposal_of(&data_only).unwrap()));
        joint.evidence = serde_json::to_value(joint_proposal).unwrap();
        let fallback = next_fallback(&joint).unwrap().unwrap();
        let fallback_body = proposal_of(&fallback).unwrap();
        assert_eq!(fallback_body.lines, code_lines);
        assert!(fallback_body.code_lines.is_none());
        assert!(fallback_body.data_evidence.is_none());
        assert_eq!(
            proposal_of(&next_fallback(&fallback).unwrap().unwrap()).unwrap().kind,
            Kind::Data
        );
        let variants = [joint.clone(), fallback.clone(), data_only.clone()];
        for (reserved, expected) in [
            (BTreeSet::new(), Kind::Code),
            (BTreeSet::from([MutationScope::Unit("a.cpp".into())]), Kind::Data),
            (BTreeSet::from([MutationScope::UnitData("a.cpp".into())]), Kind::Code),
        ] {
            let available = variants
                .iter()
                .filter(|candidate| !Discover::default().is_reserved(candidate, &reserved).unwrap())
                .cloned()
                .collect();
            let selected = Discover::default().choose_variants(available).unwrap();
            assert_eq!(selected.len(), 1);
            let body = proposal_of(&selected[0]).unwrap();
            assert_eq!(body.kind, expected);
            if expected == Kind::Code && !reserved.is_empty() {
                assert!(body.code_lines.is_none(), "reserved data needs the code-only form");
            }
        }
        assert_eq!(proposal_of(&joint).unwrap().lines.len(), 2);
        let directory =
            tempfile::Builder::new().prefix("discover-fallback-").tempdir_in("target").unwrap();
        let splits_path = directory.path().join("splits.txt");
        let splits = Splits::parse(&format!("a.cpp:\n{}\n", text(0x100, 0x200))).unwrap();
        std::fs::write(&splits_path, splits.render()).unwrap();
        let mut owned = Owned::take(&splits_path).unwrap();
        let mut trials = Trials {
            report: Report {
                measures: Default::default(),
                units: Vec::new(),
                rest: Default::default(),
            },
            accepted: IndexMap::new(),
            events: Vec::new(),
        };
        let retry = trials
            .reject(&mut owned, &splits, std::slice::from_ref(&joint), "build-conflict", None)
            .unwrap();
        let Retry::Split(groups) = retry else { panic!("failed joint claim must retry code") };
        assert_eq!(groups.len(), 1);
        assert_eq!(proposal_of(&groups[0][0]).unwrap().lines, code_lines);
        assert_eq!(trials.events[0].status, "build-conflict");
        let foreign =
            blocks(&[("a.cpp", &[&text(0x100, 0x200)]), ("b.cpp", &[&data(0x980, 0xA80)])]);
        assert!(reproduced_data_body(&report, "a.cpp", &foreign, &source).is_none());
        assert!(
            data_completion(
                "a.cpp",
                &code_lines,
                &witnessed,
                &foreign,
                &source,
                &BTreeMap::new(),
                &BTreeMap::new(),
            )
            .is_none()
        );

        let mut common_report = report.clone();
        common_report.ranges[0].section = ".bss".into();
        common_report.ranges[0].members[0].target_symbol_common = true;
        common_report.ranges[0].members[0].target_common_align = Some(4);
        common_report.ranges[0].members[0].target_common_align_basis =
            Some(CommonAlignBasis::TargetSymbol);
        let source_bss = blocks(&[("a.cpp", &[&text(0x100, 0x200), &bss(0x800, 0x900)])]);
        assert_eq!(
            reproduced_data_body(&common_report, "a.cpp", &before, &source_bss),
            Some(vec![text(0x100, 0x200), format!("{} align:4 common", bss(0x900, 0xA00))])
        );
        common_report.ranges[0].members[0].target_symbol_common = false;
        assert!(reproduced_data_body(&common_report, "a.cpp", &before, &source_bss).is_none());
    }

    #[test]
    fn a_new_code_unit_is_proposed_whole() {
        let proposals = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = code_proposals(&proposals, &IndexMap::new());
        assert_eq!(result, vec![("a.cpp".to_string(), vec![text(0x100, 0x200)])]);
    }

    #[test]
    fn an_existing_unit_is_widened_to_cover_both_ranges() {
        let proposals = blocks(&[("a.cpp", &[&text(0x300, 0x400)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = code_proposals(&proposals, &existing);
        // The gap in the middle is kept: the comparison tests ownership.
        assert_eq!(result[0].1, vec![text(0x100, 0x400)]);
    }

    #[test]
    fn a_span_that_would_cross_another_unit_is_dropped() {
        let proposals = blocks(&[("a.cpp", &[&text(0x300, 0x400)])]);
        let existing =
            blocks(&[("a.cpp", &[&text(0x100, 0x200)]), ("b.cpp", &[&text(0x250, 0x280)])]);
        assert!(code_proposals(&proposals, &existing).is_empty());
    }

    #[test]
    fn a_unit_already_covering_the_span_proposes_nothing() {
        let proposals = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        assert!(code_proposals(&proposals, &existing).is_empty());
    }

    #[test]
    fn a_data_only_proposal_is_not_a_code_candidate() {
        let proposals = blocks(&[("a.cpp", &[&data(0x100, 0x200)])]);
        assert!(code_proposals(&proposals, &IndexMap::new()).is_empty());
    }

    #[test]
    fn candidates_are_ordered_by_how_much_code_they_claim() {
        let proposals =
            blocks(&[("small.cpp", &[&text(0x100, 0x110)]), ("big.cpp", &[&text(0x200, 0x400)])]);
        let result = code_proposals(&proposals, &IndexMap::new());
        assert_eq!(result[0].0, "big.cpp");
    }

    #[test]
    fn prepared_code_candidates_rank_evidence_before_size() {
        let make = |name: &str, end: u32, independent_members: u32| {
            candidate(name.into(), Proposal {
                lines: vec![text(0x100, end)],
                kind: Kind::Code,
                before_lines: Vec::new(),
                code_lines: None,
                observation: Some(ObservationReference {
                    schema: 2,
                    sha256: "observed".into(),
                    file: "observed.json".into(),
                }),
                ownership: Some(OwnershipAssessment {
                    complete_membership: true,
                    independent_members,
                    ..Default::default()
                }),
                data_evidence: None,
                fallback_data: None,
            })
            .unwrap()
        };
        let smaller_but_stronger = make("strong.cpp", 0x180, 2);
        let larger_but_weaker = make("large.cpp", 0x400, 1);
        assert_eq!(
            compare_code_candidates(&smaller_but_stronger, &larger_but_weaker),
            Ordering::Less
        );
    }

    #[test]
    fn data_extends_an_established_unit_without_touching_its_code() {
        let proposals = blocks(&[("a.cpp", &[&text(0x100, 0x200), &data(0x900, 0xA00)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = data_proposals(&proposals, &existing, &IndexMap::new());
        assert_eq!(result[0].1, vec![text(0x100, 0x200), data(0x900, 0xA00)]);
    }

    #[test]
    fn data_never_creates_a_unit_that_has_code_in_the_source_version() {
        let proposals = blocks(&[("new.cpp", &[&data(0x900, 0xA00)])]);
        let source = blocks(&[("new.cpp", &[&text(0x100, 0x200), &data(0x900, 0xA00)])]);
        assert!(data_proposals(&proposals, &IndexMap::new(), &source).is_empty());
    }

    #[test]
    fn data_may_create_a_unit_that_emits_no_code_at_all() {
        // No .text exists to anchor on, so no code pass could ever place it.
        let proposals = blocks(&[("table.cpp", &[&data(0x900, 0xA00)])]);
        let source = blocks(&[("table.cpp", &[&data(0x900, 0xA00)])]);
        let result = data_proposals(&proposals, &IndexMap::new(), &source);
        assert_eq!(result[0].0, "table.cpp");
    }

    #[test]
    fn unowned_small_bss_requires_target_linker_mode_too() {
        let proposals = blocks(&[("a.cpp", &[&sbss(0x1000, 0x1008)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        assert!(data_proposals(&proposals, &existing, &IndexMap::new()).is_empty());
    }

    #[test]
    fn source_size_does_not_prove_the_unmatched_tail() {
        // synth.c's four-byte tail needs a symbol or relocation witness. The
        // source version's section size alone does not establish its owner.
        let proposals = blocks(&[("synth.c", &[&data(0x900, 0x9FC)])]);
        let existing = blocks(&[("synth.c", &[&text(0x100, 0x200)])]);
        let source = blocks(&[("synth.c", &[&data(0x800, 0x900)])]);
        let result = data_proposals(&proposals, &existing, &source);
        assert_eq!(result[0].1, vec![text(0x100, 0x200), data(0x900, 0x9FC)]);
    }

    #[test]
    fn a_proposed_range_overlapping_another_owner_is_withheld() {
        let proposals = blocks(&[("a.cpp", &[&data(0x900, 0xA00)])]);
        let existing =
            blocks(&[("a.cpp", &[&text(0x100, 0x200)]), ("b.cpp", &[&data(0x9FE, 0xB00)])]);
        assert!(data_proposals(&proposals, &existing, &IndexMap::new()).is_empty());
    }

    #[test]
    fn a_range_near_another_owner_is_not_grown_into_it() {
        let proposals = blocks(&[("a.cpp", &[&data(0x900, 0x9FC)])]);
        let existing =
            blocks(&[("a.cpp", &[&text(0x100, 0x200)]), ("b.cpp", &[&data(0x9FE, 0xB00)])]);
        let source = blocks(&[("a.cpp", &[&data(0x800, 0x900)])]);
        let result = data_proposals(&proposals, &existing, &source);
        assert!(result[0].1.contains(&data(0x900, 0x9FC)), "{:?}", result[0].1);
    }

    #[test]
    fn a_source_size_smaller_than_the_proposal_does_not_discard_evidence() {
        let proposals = blocks(&[("a.cpp", &[&data(0x900, 0x9FC)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        // The proposal's own interval remains usable regardless of the source
        // version's shorter section.
        let source = blocks(&[("a.cpp", &[&data(0x800, 0x810)])]);
        let result = data_proposals(&proposals, &existing, &source);
        assert!(result[0].1.contains(&data(0x900, 0x9FC)), "{:?}", result[0].1);
    }

    #[test]
    fn a_unit_with_no_source_body_is_not_grown() {
        let proposals = blocks(&[("a.cpp", &[&data(0x900, 0x9FC)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = data_proposals(&proposals, &existing, &IndexMap::new());
        assert!(result[0].1.contains(&data(0x900, 0x9FC)), "{:?}", result[0].1);
    }

    #[test]
    fn separate_bss_and_common_bss_ranges_keep_their_gap_and_attributes() {
        let ordinary = bss(0x1000, 0x1100);
        let common = format!("{} align:4 common", bss(0x2000, 0x2050));
        let proposals = blocks(&[("stream.cpp", &[&ordinary, &common])]);
        let after_bss = data(0x3000, 0x3010);
        let existing = blocks(&[("stream.cpp", &[&text(0x100, 0x200), &ordinary, &after_bss])]);
        let result = data_proposals(&proposals, &existing, &IndexMap::new());
        assert_eq!(result[0].1, vec![text(0x100, 0x200), ordinary, common, after_bss]);
        assert!(!result[0].1.iter().any(|line| {
            parse_range(line).is_some_and(|range| {
                range.section == ".bss" && range.start < 0x2000 && range.end > 0x1100
            })
        }));
    }

    #[test]
    fn data_extension_preserves_existing_attributes_and_widens_one_range() {
        let old = format!("{} align:4 common", bss(0x2000, 0x2040));
        let proposed = format!("{} align:4 common", bss(0x2000, 0x2050));
        let proposals = blocks(&[("stream.cpp", &[&proposed])]);
        let existing = blocks(&[("stream.cpp", &[&text(0x100, 0x200), &old])]);
        let result = data_proposals(&proposals, &existing, &IndexMap::new());
        assert_eq!(result[0].1, vec![
            text(0x100, 0x200),
            format!("{} align:4 common", bss(0x2000, 0x2050))
        ]);
    }

    #[test]
    fn a_broad_proposal_does_not_collapse_two_existing_bss_ranges() {
        let common = |start, end| format!("{} align:4 common", bss(start, end));
        let proposals = blocks(&[("stream.cpp", &[&common(0x1000, 0x2050)])]);
        let existing = blocks(&[("stream.cpp", &[
            &text(0x100, 0x200),
            &common(0x1000, 0x1100),
            &common(0x2000, 0x2050),
        ])]);
        assert!(data_proposals(&proposals, &existing, &IndexMap::new()).is_empty());
    }

    #[test]
    fn adjacent_data_allocations_stay_separate_even_with_matching_attributes() {
        let first = data(0x1000, 0x1100);
        let second = data(0x1100, 0x1150);
        let proposals = blocks(&[("stream.cpp", &[&second])]);
        let existing = blocks(&[("stream.cpp", &[&text(0x100, 0x200), &first])]);
        let result = data_proposals(&proposals, &existing, &IndexMap::new());
        assert_eq!(result[0].1, vec![text(0x100, 0x200), first, second]);
    }

    #[test]
    fn an_unannotated_new_bss_range_is_withheld() {
        let ordinary = bss(0x1000, 0x1100);
        let common = format!("{} align:4 common", bss(0x2000, 0x2050));
        // The current matcher writes both proposals without attributes, so
        // the second interval cannot be distinguished from ordinary BSS here.
        let proposals = blocks(&[("stream.cpp", &[&ordinary, &bss(0x2000, 0x2050)])]);
        let existing = blocks(&[("stream.cpp", &[&text(0x100, 0x200), &ordinary])]);
        let source = blocks(&[("stream.cpp", &[&ordinary, &common])]);
        assert!(data_proposals(&proposals, &existing, &source).is_empty());
    }

    #[test]
    fn an_unannotated_new_bss_range_is_withheld_even_without_common_source_bss() {
        let proposals = blocks(&[("stream.cpp", &[&bss(0x1000, 0x1100)])]);
        let existing = blocks(&[("stream.cpp", &[&text(0x100, 0x200)])]);
        assert!(data_proposals(&proposals, &existing, &IndexMap::new()).is_empty());
    }

    #[test]
    fn a_conflicting_data_attribute_does_not_rewrite_an_existing_range() {
        let ordinary = bss(0x2000, 0x2040);
        let proposed = format!("{} align:4 common", bss(0x2000, 0x2050));
        let proposals = blocks(&[("stream.cpp", &[&proposed])]);
        let existing = blocks(&[("stream.cpp", &[&text(0x100, 0x200), &ordinary])]);
        assert!(data_proposals(&proposals, &existing, &IndexMap::new()).is_empty());
    }
}
