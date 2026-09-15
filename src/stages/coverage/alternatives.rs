//! Turning coverage evidence into ranges worth trying.
//!
//! The matcher's coverage report says what it observed: which functions have an
//! identical body in both versions, which differ only by a member offset that
//! moved, which sit in a run bounded by two units whose position is already
//! known. It does not say what to do about any of it.
//!
//! This decides that. Each *alternative* is one complete way a unit could claim
//! a target range, with the evidence behind it. A unit may have several, tried
//! strongest first, and the build settles which — if any — is right.
//!
//! Everything here re-derives what the evidence asserts rather than trusting
//! it. That looks redundant when both sides are the same program, and it is not
//! quite: a resumed run reads the evidence back from disk, and a policy that
//! only ever checks itself is a policy nobody can audit.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    analysis::coverage::{
        AdjacentOwnerTransition, BoundarySequence, CoverageAnchor, CoverageUnit, GapHelper,
        LayoutShiftAnchor, SequenceFunction,
    },
    project::splits::parse_range,
};

/// Tiers a matched function may carry. Anything else is not a match this
/// evidence understands.
const MATCH_TIERS: [&str; 3] = ["confident", "probable", "candidate"];
/// Tiers strong enough to count toward a policy minimum.
const STRONG_TIERS: [&str; 2] = ["confident", "probable"];

pub const MIN_LAYOUT_BOUNDARY_FUNCTIONS: usize = 4;
pub const MIN_LAYOUT_BOUNDARY_BYTES: u32 = 1024;
pub const MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES: u32 = 16;
pub const MAX_LAYOUT_BOUNDARY_SIZE_DELTA: f32 = 0.02;
pub const MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA: i64 = 1;

pub const MIN_VTABLE_BOUNDARY_FUNCTIONS: usize = 8;
pub const MIN_VTABLE_BOUNDARY_MATCH_RATIO: f32 = 0.85;
pub const MIN_VTABLE_BOUNDARY_TARGET_COVERAGE: f32 = 0.85;
pub const MIN_VTABLE_BOUNDARY_MATCHED_SLOTS: u32 = 8;
pub const MIN_VTABLE_BOUNDARY_UNIT_SLOTS: usize = 4;
pub const MAX_VTABLE_BOUNDARY_SIZE_DELTA: f32 = 0.03;
pub const MAX_VTABLE_BOUNDARY_FUNCTION_DELTA: i64 = 1;
pub const MAX_VTABLE_BOUNDARY_GAP_HELPERS: usize = 1;
pub const MAX_VTABLE_SIZE_PADDING: i64 = 16;

pub const MIN_OWNERSHIP_TRANSITION_FUNCTIONS: usize = 8;
pub const MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS: u32 = 2;
pub const MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS: u32 = 1;
pub const MAX_OWNERSHIP_TRANSITION_SIZE_DELTA: f32 = 0.02;

pub const MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS: usize = 8;
pub const MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS: u32 = 2;
pub const MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS: u32 = 2;
pub const MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS: usize = 4;
pub const MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS: u32 = 2;
pub const MAX_ADJACENT_OWNER_SIZE_DELTA: f32 = 0.10;
pub const MAX_ADJACENT_OWNER_GAP_HELPERS: usize = 1;

/// The smallest alignment margin a boundary decision may rest on.
///
/// Below this the best alignment and the runner-up are close enough that the
/// choice between them is arbitrary.
const MIN_ALIGNMENT_MARGIN: f32 = 0.1;

/// A change to a unit other than the candidate, applied with it or not at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerRevision {
    pub unit: String,
    pub section: String,
    pub original_start: String,
    pub original_end: String,
    pub revised_start: String,
    pub revised_end: String,
}

/// One complete way a unit could claim a target range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alternative {
    /// A stable digest of everything that makes this range what it is, so a
    /// worker and the coordinator can agree on which one was proved.
    pub id: String,
    pub evidence: String,
    pub support_group: Option<String>,
    pub section: String,
    pub start: String,
    pub end: String,
    pub covered_bytes: u32,
    /// The `splits.txt` lines this alternative would write.
    pub lines: Vec<String>,
    /// The evidence records behind it, kept as written so the run's report can
    /// show exactly what was believed.
    pub anchors: Vec<serde_json::Value>,
    #[serde(default)]
    pub owner_revisions: Vec<OwnerRevision>,
}

pub fn parse_address(text: &str) -> Option<u32> {
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    u32::from_str_radix(digits, 16).ok()
}

pub fn format_address(value: u32) -> String { format!("0x{value:08X}") }

fn split_line(section: &str, start: u32, end: u32) -> String {
    format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
}

fn alternative(
    section: &str,
    start: u32,
    end: u32,
    anchors: Vec<serde_json::Value>,
    evidence: &str,
    group: Option<String>,
    owner_revisions: Vec<OwnerRevision>,
) -> Alternative {
    // Sorted keys, so the identity of a revision does not depend on field
    // order and two runs agree on the digest.
    let revisions: Vec<BTreeMap<&str, &str>> = owner_revisions
        .iter()
        .map(|revision| {
            BTreeMap::from([
                ("unit", revision.unit.as_str()),
                ("section", revision.section.as_str()),
                ("original_start", revision.original_start.as_str()),
                ("original_end", revision.original_end.as_str()),
                ("revised_start", revision.revised_start.as_str()),
                ("revised_end", revision.revised_end.as_str()),
            ])
        })
        .collect();
    let identity = format!(
        "{evidence}:{}:{section}:{start:08X}-{end:08X}:{}",
        group.as_deref().unwrap_or(""),
        serde_json::to_string(&revisions).unwrap_or_default()
    );
    let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
    Alternative {
        id: digest[..16].to_string(),
        evidence: evidence.to_string(),
        support_group: group,
        section: section.to_string(),
        start: format_address(start),
        end: format_address(end),
        covered_bytes: end - start,
        lines: vec![split_line(section, start, end)],
        anchors,
        owner_revisions,
    }
}

type Blocks = IndexMap<String, Vec<String>>;

fn overlaps_existing(section: &str, start: u32, end: u32, blocks: &Blocks) -> bool {
    blocks
        .values()
        .flatten()
        .filter_map(|line| parse_range(line))
        .any(|range| range.section == section && start < range.end && range.start < end)
}

/// The one range a unit claims in a section, when it claims exactly one.
fn single_section_range(blocks: &Blocks, unit: &str, section: &str) -> Option<(u32, u32)> {
    let mut ranges = blocks
        .get(unit)?
        .iter()
        .filter_map(|line| parse_range(line))
        .filter(|range| range.section == section);
    let first = ranges.next()?;
    ranges.next().is_none().then_some((first.start, first.end))
}

fn relative_size_delta(source_bytes: u32, target_bytes: u32) -> f32 {
    let base = source_bytes.max(target_bytes);
    if base == 0 { 0.0 } else { source_bytes.abs_diff(target_bytes) as f32 / base as f32 }
}

fn round_ratio(value: f32) -> f32 { (value * 1000.0).round() / 1000.0 }

fn agrees(reported: f32, computed: f32) -> bool {
    (reported - round_ratio(computed)).abs() <= 0.000_001
}

fn strong_count<'a>(tiers: impl Iterator<Item = &'a str>) -> u32 {
    tiers.filter(|tier| STRONG_TIERS.contains(tier)).count() as u32
}

/// Checks a run of matched functions is a usable ordered sequence, returning
/// its target ranges and how many matches are strong.
///
/// The requirements are what make a sequence evidence at all: every function is
/// a primary match of a known tier, the source addresses ascend without
/// repeating, each target range is non-empty and exactly its stated size, and
/// the ranges do not overlap.
fn sequence_details(functions: &[SequenceFunction]) -> Option<(Vec<(u32, u32)>, u32)> {
    let mut source_addresses = Vec::with_capacity(functions.len());
    let mut ranges = Vec::with_capacity(functions.len());
    for function in functions {
        source_addresses.push(parse_address(&function.source_address)?);
        let start = parse_address(&function.target_address)?;
        let end = parse_address(&function.target_end)?;
        if end <= start || end - start != function.size {
            return None;
        }
        ranges.push((start, end));
    }
    if functions.iter().any(|f| !MATCH_TIERS.contains(&f.tier.as_str()))
        || functions.iter().any(|f| !f.primary)
        || !source_addresses.windows(2).all(|pair| pair[0] < pair[1])
        || ranges.windows(2).any(|pair| pair[0].1 > pair[1].0)
    {
        return None;
    }
    Some((ranges, strong_count(functions.iter().map(|f| f.tier.as_str()))))
}

/// Whether the given function and helper ranges tile `start..end` exactly, with
/// no gap and no overlap.
fn partition_covers(
    start: u32,
    end: u32,
    function_ranges: &[(u32, u32)],
    helpers: &[GapHelper],
) -> bool {
    let mut pieces = function_ranges.to_vec();
    for helper in helpers {
        let (Some(left), Some(right)) =
            (parse_address(&helper.target_address), parse_address(&helper.target_end))
        else {
            return false;
        };
        if right.saturating_sub(left) != helper.size {
            return false;
        }
        pieces.push((left, right));
    }
    pieces.sort();
    !pieces.is_empty()
        && pieces[0].0 == start
        && pieces[pieces.len() - 1].1 == end
        && pieces.iter().all(|(left, right)| right > left)
        && pieces.windows(2).all(|pair| pair[0].1 == pair[1].0)
}

/// How many exact-body anchors of this unit sit wholly inside a range and meet
/// every strictness the policy asks of an anchor.
///
/// This is the independent corroboration an ownership transfer needs: the
/// sequence says where the unit's functions line up, and these say that some of
/// them are byte-identical in a way nothing else could claim.
fn direct_anchor_count(
    unit: &CoverageUnit,
    section: &str,
    start: u32,
    end: u32,
    owner: &str,
) -> u32 {
    unit.anchors
        .iter()
        .filter(|anchor| {
            let (Some(anchor_start), Some(anchor_end)) =
                (parse_address(&anchor.target_address), parse_address(&anchor.target_end))
            else {
                return false;
            };
            let owned_elsewhere = match &anchor.existing_target_owner {
                None => false,
                Some(existing) => {
                    existing != &unit.name
                        && existing != owner
                        && !anchor.existing_owner_autogenerated
                }
            };
            anchor.section == section
                && start <= anchor_start
                && anchor_start < anchor_end
                && anchor_end <= end
                && anchor_end - anchor_start == anchor.size
                && anchor.size >= 16
                && !anchor.source_weak
                && !anchor.target_weak
                && anchor.source_extent_known
                && anchor.target_extent_known
                && anchor.source_unit_explicit
                && anchor.source_unit_wholly_owned
                && !anchor.template_instantiation
                && anchor.unique_source
                && anchor.unique_target
                && anchor.normalized_body_equal
                && anchor.relocation_layout_equal
                && !owned_elsewhere
        })
        .count() as u32
}

fn value(item: &impl Serialize) -> serde_json::Value {
    serde_json::to_value(item).unwrap_or(serde_json::Value::Null)
}

/// Adds the section a sequence function belongs to, which the function record
/// itself does not carry.
fn anchor_value(function: &SequenceFunction, section: &str) -> serde_json::Value {
    let mut item = value(function);
    if let Some(object) = item.as_object_mut() {
        object.insert("section".into(), serde_json::Value::String(section.to_string()));
    }
    item
}

fn sort_alternatives(alternatives: &mut [Alternative]) {
    alternatives.sort_by(|a, b| {
        b.covered_bytes
            .cmp(&a.covered_bytes)
            .then_with(|| parse_address(&a.start).cmp(&parse_address(&b.start)))
    });
}

/// Every range this unit could claim, strongest evidence first.
pub fn build(
    unit: &CoverageUnit,
    target_blocks: &Blocks,
    source_units: &BTreeMap<String, &CoverageUnit>,
    source_blocks: &Blocks,
) -> Vec<Alternative> {
    let eligible: Vec<&CoverageAnchor> = unit.anchors.iter().filter(|a| a.eligible).collect();

    // One anchor at a time: the narrowest claim, and the one most likely to
    // survive when a wider one overlaps something.
    let mut individual: Vec<Alternative> = eligible
        .iter()
        .filter_map(|anchor| {
            let start = parse_address(&anchor.target_address)?;
            let end = parse_address(&anchor.target_end)?;
            (!overlaps_existing(&anchor.section, start, end, target_blocks)).then(|| {
                alternative(
                    &anchor.section,
                    start,
                    end,
                    vec![value(anchor)],
                    "exact-body",
                    None,
                    vec![],
                )
            })
        })
        .collect();
    sort_alternatives(&mut individual);

    // Adjacent anchors merged into one range: more bytes claimed per build.
    let mut ordered: Vec<&&CoverageAnchor> = eligible.iter().collect();
    ordered.sort_by(|a, b| {
        a.section
            .cmp(&b.section)
            .then_with(|| parse_address(&a.target_address).cmp(&parse_address(&b.target_address)))
    });
    let mut runs: Vec<Vec<&CoverageAnchor>> = Vec::new();
    let mut current: Vec<&CoverageAnchor> = Vec::new();
    for anchor in ordered {
        if let Some(last) = current.last()
            && (anchor.section != last.section
                || parse_address(&anchor.target_address) != parse_address(&last.target_end))
        {
            if current.len() > 1 {
                runs.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
        current.push(anchor);
    }
    if current.len() > 1 {
        runs.push(current);
    }
    let mut combined: Vec<Alternative> = runs
        .iter()
        .filter_map(|anchors| {
            let start = parse_address(&anchors[0].target_address)?;
            let end = parse_address(&anchors[anchors.len() - 1].target_end)?;
            (!overlaps_existing(&anchors[0].section, start, end, target_blocks)).then(|| {
                alternative(
                    &anchors[0].section,
                    start,
                    end,
                    anchors.iter().map(|a| value(a)).collect(),
                    "exact-body",
                    None,
                    vec![],
                )
            })
        })
        .collect();
    sort_alternatives(&mut combined);

    let mut shifted = layout_shift_alternatives(unit, target_blocks);
    sort_alternatives(&mut shifted);

    let mut sequences: Vec<Alternative> = unit
        .boundary_sequences
        .iter()
        .filter_map(|sequence| sequence_alternative(unit, sequence, target_blocks))
        .collect();
    sort_alternatives(&mut sequences);

    let mut adjacent: Vec<Alternative> = unit
        .adjacent_owner_transitions
        .iter()
        .filter_map(|transition| {
            adjacent_owner_alternative(unit, transition, target_blocks, source_units, source_blocks)
        })
        .collect();
    sort_alternatives(&mut adjacent);

    // Strongest kind first, and within a kind the biggest range first. A range
    // reached two ways is listed once.
    let mut result: Vec<Alternative> = Vec::new();
    let mut seen: BTreeSet<(String, String, String, String)> = BTreeSet::new();
    for item in
        adjacent.into_iter().chain(sequences).chain(shifted).chain(individual).chain(combined)
    {
        let key = (
            item.section.clone(),
            item.start.clone(),
            item.end.clone(),
            serde_json::to_string(&item.owner_revisions).unwrap_or_default(),
        );
        if seen.insert(key) {
            result.push(item);
        }
    }
    result
}

/// Ranges claimed by a group of functions that differ only where a member
/// offset moved.
fn layout_shift_alternatives(unit: &CoverageUnit, target_blocks: &Blocks) -> Vec<Alternative> {
    let mut groups: IndexMap<String, Vec<&LayoutShiftAnchor>> = IndexMap::new();
    for anchor in unit.layout_shift_anchors.iter().filter(|a| a.eligible) {
        groups.entry(anchor.support_group.clone()).or_default().push(anchor);
    }

    let mut found = Vec::new();
    for (group, mut anchors) in groups {
        anchors.sort_by_key(|anchor| parse_address(&anchor.target_address));
        let sections: BTreeSet<&str> = anchors.iter().map(|a| a.section.as_str()).collect();
        let deltas: BTreeSet<&[i32]> = anchors.iter().map(|a| a.offset_deltas.as_slice()).collect();
        let breakpoints: BTreeSet<Option<i32>> =
            anchors.iter().map(|a| a.inferred_breakpoint).collect();
        let source_addresses: Vec<Option<u32>> =
            anchors.iter().map(|a| parse_address(&a.source_address)).collect();
        let ranges: Vec<(Option<u32>, Option<u32>)> = anchors
            .iter()
            .map(|a| (parse_address(&a.target_address), parse_address(&a.target_end)))
            .collect();

        // Every member must agree on the same group, the same transformation,
        // and the same totals; a group whose members disagree about itself is
        // not evidence of anything.
        let total_size: u32 = anchors.iter().map(|a| a.size).sum();
        let total_changed: u32 = anchors.iter().map(|a| a.changed_this_accesses).sum();
        if anchors.len() < 2
            || sections.len() != 1
            || deltas.len() != 1
            || breakpoints.len() != 1
            || source_addresses.iter().any(Option::is_none)
            || !source_addresses.windows(2).all(|pair| pair[0] < pair[1])
            || ranges.iter().any(|(a, b)| a.is_none() || b.is_none())
            || ranges.windows(2).any(|pair| pair[1].0 < pair[0].1)
            || anchors.iter().any(|a| a.support_functions as usize != anchors.len())
            || anchors.iter().any(|a| a.support_bytes != total_size)
            || anchors.iter().any(|a| a.support_changed_accesses != total_changed)
        {
            continue;
        }
        let start = ranges[0].0.unwrap();
        let end = ranges.iter().filter_map(|(_, end)| *end).max().unwrap_or(start);
        // A group spanning more than twice the unit's own code has drifted into
        // something else's territory.
        if u64::from(end - start) > 2 * unit.code_bytes {
            continue;
        }
        let section = anchors[0].section.clone();
        if overlaps_existing(&section, start, end, target_blocks) {
            continue;
        }
        found.push(alternative(
            &section,
            start,
            end,
            anchors.iter().map(|a| value(a)).collect(),
            "this-layout-shift",
            Some(group),
            vec![],
        ));
    }
    found
}

/// A range bounded by two units whose position is already known.
fn sequence_alternative(
    unit: &CoverageUnit,
    sequence: &BoundarySequence,
    target_blocks: &Blocks,
) -> Option<Alternative> {
    let start = parse_address(&sequence.target_start)?;
    let end = parse_address(&sequence.target_end)?;
    if !sequence.eligible
        || sequence.section != ".text"
        || end <= start
        || sequence.target_bytes != end - start
        || overlaps_existing(&sequence.section, start, end, target_blocks)
    {
        return None;
    }

    match sequence.acceptance_method.as_str() {
        "ownership-transition-boundary" => ownership_transition(unit, sequence, start, end),
        "layout-corroborated-boundary" => layout_corroborated(unit, sequence, start, end),
        "vtable-corroborated-boundary" => vtable_corroborated(unit, sequence, start, end),
        "matched-sequence" => matched_sequence(sequence, start, end),
        _ => None,
    }
}

/// A stale neighbouring split made the bounded gap too wide; the candidate's
/// own aligned run trims it, and the two edges must transfer cleanly.
fn ownership_transition(
    unit: &CoverageUnit,
    sequence: &BoundarySequence,
    start: u32,
    end: u32,
) -> Option<Alternative> {
    let functions = &sequence.functions;
    let support = sequence.ownership_transition_support.as_ref()?;
    let (ranges, strong) = sequence_details(functions)?;
    let original_start = parse_address(&support.original_target_start)?;
    let original_end = parse_address(&support.original_target_end)?;
    let aligned_start = parse_address(&support.aligned_target_start)?;
    let aligned_end = parse_address(&support.aligned_target_end)?;
    let size_delta = relative_size_delta(unit.code_bytes as u32, end - start);

    if functions.len() < MIN_OWNERSHIP_TRANSITION_FUNCTIONS
        || sequence.aligned_functions as usize != functions.len()
        || sequence.source_functions as usize != functions.len()
        || sequence.target_functions as usize != functions.len()
        || sequence.aligned_bytes != end - start
        || sequence.match_ratio != 1.0
        || sequence.order_ratio != 1.0
        || sequence.target_coverage != 1.0
        || sequence.alignment_margin < MIN_ALIGNMENT_MARGIN
        || strong < MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS
        || sequence.strong_functions != strong
        // The run must tile the whole claimed range, end to end.
        || ranges.windows(2).any(|pair| pair[0].1 != pair[1].0)
        || ranges.first()?.0 != start
        || ranges.last()?.1 != end
        || aligned_start != start
        || aligned_end != end
        || support.source_bytes != unit.code_bytes as u32
        || support.aligned_target_bytes != end - start
        // The original range must strictly contain the trimmed one.
        || original_start > start
        || original_end < end
        || original_start >= original_end
        || (original_start == start && original_end == end)
        || size_delta > MAX_OWNERSHIP_TRANSITION_SIZE_DELTA
        || !agrees(support.size_delta, size_delta)
        || !valid_transition_edge(&support.left, &sequence.previous_unit, original_start, start)
        || !valid_transition_edge(&support.right, &sequence.next_unit, end, original_end)
    {
        return None;
    }
    Some(alternative(
        &sequence.section,
        start,
        end,
        functions.iter().map(|f| anchor_value(f, &sequence.section)).collect(),
        "ownership-transition-boundary",
        Some(format!(
            "{}|{}|{}|{}",
            sequence.previous_unit,
            sequence.next_unit,
            support.original_target_start,
            support.original_target_end
        )),
        vec![],
    ))
}

/// One side of an ownership transfer: the part of the old range that stays with
/// its original owner.
fn valid_transition_edge(
    edge: &crate::analysis::coverage::OwnershipTransitionEdge,
    unit: &str,
    start: u32,
    end: u32,
) -> bool {
    let mut ranges = Vec::with_capacity(edge.functions.len());
    let mut source_addresses = Vec::with_capacity(edge.functions.len());
    for function in &edge.functions {
        let (Some(left), Some(right), Some(source)) = (
            parse_address(&function.target_address),
            parse_address(&function.target_end),
            parse_address(&function.source_address),
        ) else {
            return false;
        };
        if right <= left || right - left != function.size {
            return false;
        }
        ranges.push((left, right));
        source_addresses.push(source);
    }
    let strong = strong_count(edge.functions.iter().map(|f| f.tier.as_str()));
    if edge.unit != unit
        || parse_address(&edge.start) != Some(start)
        || parse_address(&edge.end) != Some(end)
        || edge.bytes != end - start
        || edge.strong_functions != strong
        || edge.functions.iter().any(|f| !MATCH_TIERS.contains(&f.tier.as_str()))
        || !source_addresses.windows(2).all(|pair| pair[0] < pair[1])
        || ranges.windows(2).any(|pair| pair[0].1 != pair[1].0)
    {
        return false;
    }
    // An empty edge is allowed, and then it must really be empty.
    if start == end {
        return edge.functions.is_empty() && strong == 0;
    }
    !edge.functions.is_empty()
        && ranges[0].0 == start
        && ranges[ranges.len() - 1].1 == end
        && strong >= MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS
}

/// Ordinary matching was inconclusive, but enough layout-shift functions agree
/// to corroborate the whole neighbour-bounded gap.
fn layout_corroborated(
    unit: &CoverageUnit,
    sequence: &BoundarySequence,
    start: u32,
    end: u32,
) -> Option<Alternative> {
    let group = sequence.layout_support_group.as_ref()?;
    let mut anchors: Vec<&LayoutShiftAnchor> = unit
        .layout_shift_anchors
        .iter()
        .filter(|anchor| anchor.eligible && &anchor.support_group == group)
        .collect();
    anchors.sort_by_key(|anchor| parse_address(&anchor.source_address));
    if anchors.is_empty() {
        return None;
    }

    let total_size: u32 = anchors.iter().map(|a| a.size).sum();
    let total_changed: u32 = anchors.iter().map(|a| a.changed_this_accesses).sum();
    let deltas: BTreeSet<&[i32]> = anchors.iter().map(|a| a.offset_deltas.as_slice()).collect();
    let breakpoints: BTreeSet<Option<i32>> =
        anchors.iter().map(|a| a.inferred_breakpoint).collect();
    let source_addresses: Vec<Option<u32>> =
        anchors.iter().map(|a| parse_address(&a.source_address)).collect();
    let ranges: Vec<(Option<u32>, Option<u32>)> = anchors
        .iter()
        .map(|a| (parse_address(&a.target_address), parse_address(&a.target_end)))
        .collect();
    let size_delta = relative_size_delta(unit.code_bytes as u32, sequence.target_bytes);
    let delta_length = deltas.iter().next().map(|d| d.len()).unwrap_or(0);

    if anchors.iter().any(|a| a.support_functions as usize != anchors.len())
        || anchors.iter().any(|a| a.support_bytes != total_size)
        || anchors.iter().any(|a| a.support_changed_accesses != total_changed)
        || deltas.len() != 1
        // One constant offset shift, or two separated by a single breakpoint.
        || !(1..=2).contains(&delta_length)
        || breakpoints.len() != 1
        || anchors.len() < MIN_LAYOUT_BOUNDARY_FUNCTIONS
        || total_size < MIN_LAYOUT_BOUNDARY_BYTES
        || total_changed < MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES
        || size_delta > MAX_LAYOUT_BOUNDARY_SIZE_DELTA
        || (i64::from(sequence.source_functions) - i64::from(sequence.target_functions)).abs()
            > MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA
        || source_addresses.iter().any(Option::is_none)
        || !source_addresses.windows(2).all(|pair| pair[0] < pair[1])
        || ranges.iter().any(|(a, b)| a.is_none() || b.is_none())
        || ranges.windows(2).any(|pair| pair[1].0 < pair[0].1)
        || ranges.iter().any(|(a, b)| a.unwrap() < start || b.unwrap() > end)
    {
        return None;
    }
    Some(alternative(
        &sequence.section,
        start,
        end,
        anchors.iter().map(|a| value(a)).collect(),
        "layout-corroborated-boundary",
        Some(format!("{}|{}|{group}", sequence.previous_unit, sequence.next_unit)),
        vec![],
    ))
}

/// A polymorphic class whose compiler output moved one body into a local
/// helper, corroborated by a uniquely paired vtable.
fn vtable_corroborated(
    unit: &CoverageUnit,
    sequence: &BoundarySequence,
    start: u32,
    end: u32,
) -> Option<Alternative> {
    let functions = &sequence.functions;
    let support = sequence.vtable_support.as_ref()?;
    let helpers = &sequence.gap_helpers;

    let mut ranges = Vec::with_capacity(functions.len());
    let mut source_addresses = Vec::with_capacity(functions.len());
    for function in functions {
        let (Some(left), Some(right), Some(source)) = (
            parse_address(&function.target_address),
            parse_address(&function.target_end),
            parse_address(&function.source_address),
        ) else {
            return None;
        };
        if right <= left || right - left != function.size {
            return None;
        }
        ranges.push((left, right));
        source_addresses.push(source);
    }
    let mut helper_ranges = Vec::with_capacity(helpers.len());
    for helper in helpers {
        let (Some(left), Some(right)) =
            (parse_address(&helper.target_address), parse_address(&helper.target_end))
        else {
            return None;
        };
        helper_ranges.push((left, right));
    }

    let target_addresses: BTreeSet<u32> = ranges.iter().map(|(left, _)| *left).collect();
    let helper_addresses: BTreeSet<u32> = helper_ranges.iter().map(|(left, _)| *left).collect();
    let allowed_callers: BTreeSet<u32> =
        target_addresses.union(&helper_addresses).copied().collect();
    let function_pairs: BTreeSet<(&str, &str)> =
        functions.iter().map(|f| (f.source_address.as_str(), f.target_address.as_str())).collect();
    let slot_pairs: BTreeSet<(&str, &str)> = support
        .unit_slots
        .iter()
        .map(|slot| (slot.source_address.as_str(), slot.target_address.as_str()))
        .collect();
    let slot_offsets: BTreeSet<u32> = support.unit_slots.iter().map(|s| s.slot_offset).collect();

    let aligned_bytes: u32 = functions.iter().map(|f| f.size).sum();
    let size_delta = relative_size_delta(unit.code_bytes as u32, sequence.target_bytes);
    let source_functions = sequence.source_functions;
    let target_functions = sequence.target_functions;

    let helper_ok = |index: usize| -> bool {
        let helper = &helpers[index];
        let (left, right) = helper_ranges[index];
        let callers: Vec<Option<u32>> = helper.callers.iter().map(|c| parse_address(c)).collect();
        right > left
            && right - left == helper.size
            && left >= start
            && right <= end
            && !helper.callers.is_empty()
            && callers.iter().all(|c| c.is_some_and(|c| allowed_callers.contains(&c)))
            // The helper must be called from inside the gap, not only by
            // another helper.
            && callers.iter().any(|c| c.is_some_and(|c| target_addresses.contains(&c)))
    };

    if sequence.aligned_functions as usize != functions.len()
        || sequence.aligned_bytes != aligned_bytes
        || functions.len() < MIN_VTABLE_BOUNDARY_FUNCTIONS
        || source_functions == 0
        || (functions.len() as f32 / source_functions as f32) < MIN_VTABLE_BOUNDARY_MATCH_RATIO
        || (aligned_bytes as f32 / sequence.target_bytes as f32)
            < MIN_VTABLE_BOUNDARY_TARGET_COVERAGE
        // At most one source function may be unaccounted for.
        || !(0..=1).contains(&(i64::from(source_functions) - functions.len() as i64))
        || (i64::from(source_functions) - i64::from(target_functions)).abs()
            > MAX_VTABLE_BOUNDARY_FUNCTION_DELTA
        || size_delta > MAX_VTABLE_BOUNDARY_SIZE_DELTA
        || functions.iter().any(|f| !f.primary)
        || !source_addresses.windows(2).all(|pair| pair[0] < pair[1])
        || ranges.windows(2).any(|pair| pair[1].0 < pair[0].1)
        || ranges.iter().any(|(left, right)| *left < start || *right > end)
        || support.source_address.is_empty()
        || support.target_address.is_empty()
        || support.matched_slots < MIN_VTABLE_BOUNDARY_MATCHED_SLOTS
        || support.agreeing_slots != support.matched_slots
        || support.unit_slots.len() < MIN_VTABLE_BOUNDARY_UNIT_SLOTS
        || support.unit_slots.len() > support.agreeing_slots as usize
        || slot_offsets.len() != support.unit_slots.len()
        || slot_offsets.iter().any(|offset| offset % 4 != 0 || *offset >= support.source_size)
        // Every vtable slot must name a function this sequence also matched.
        || !slot_pairs.is_subset(&function_pairs)
        || support.source_size == 0
        || support.target_size == 0
        || (i64::from(support.source_size) - i64::from(support.target_size)).abs()
            > MAX_VTABLE_SIZE_PADDING
        || !(1..=MAX_VTABLE_BOUNDARY_GAP_HELPERS).contains(&helpers.len())
        || helpers.len() as i64 != i64::from(target_functions) - functions.len() as i64
        || !(0..helpers.len()).all(helper_ok)
        || helper_ranges
            .iter()
            .any(|(left, right)| ranges.iter().any(|(a, b)| left < b && a < right))
        || helper_ranges.iter().enumerate().any(|(index, (left, right))| {
            helper_ranges[index + 1..].iter().any(|(a, b)| left < b && a < right)
        })
    {
        return None;
    }
    Some(alternative(
        &sequence.section,
        start,
        end,
        functions.iter().map(|f| anchor_value(f, &sequence.section)).collect(),
        "vtable-corroborated-boundary",
        Some(format!(
            "{}|{}|{}|{}",
            sequence.previous_unit,
            sequence.next_unit,
            support.source_address,
            support.target_address
        )),
        vec![],
    ))
}

/// The plain case: a decisive monotone alignment across the whole gap.
fn matched_sequence(sequence: &BoundarySequence, start: u32, end: u32) -> Option<Alternative> {
    let functions = &sequence.functions;
    let mut ranges = Vec::with_capacity(functions.len());
    let mut source_addresses = Vec::with_capacity(functions.len());
    for function in functions {
        let (Some(left), Some(right), Some(source)) = (
            parse_address(&function.target_address),
            parse_address(&function.target_end),
            parse_address(&function.source_address),
        ) else {
            return None;
        };
        ranges.push((left, right));
        source_addresses.push(source);
    }
    let aligned_bytes: u32 = functions.iter().map(|f| f.size).sum();
    if sequence.aligned_functions as usize != functions.len()
        || sequence.aligned_bytes != aligned_bytes
        || functions.iter().any(|f| !f.primary)
        || !source_addresses.windows(2).all(|pair| pair[0] < pair[1])
        || ranges.windows(2).any(|pair| pair[1].0 < pair[0].1)
        || ranges.iter().any(|(left, right)| *left < start || *right > end)
    {
        return None;
    }
    Some(alternative(
        &sequence.section,
        start,
        end,
        functions.iter().map(|f| anchor_value(f, &sequence.section)).collect(),
        "boundary-sequence",
        Some(format!("{}|{}", sequence.previous_unit, sequence.next_unit)),
        vec![],
    ))
}

/// The candidate's run occupies a prefix or suffix of an adjacent unit's
/// declared range, so that unit shrinks and the candidate takes what it gives
/// up — one transaction, both or neither.
fn adjacent_owner_alternative(
    unit: &CoverageUnit,
    transition: &AdjacentOwnerTransition,
    target_blocks: &Blocks,
    source_units: &BTreeMap<String, &CoverageUnit>,
    source_blocks: &Blocks,
) -> Option<Alternative> {
    let section = transition.section.as_str();
    let side = transition.side.as_str();
    let start = parse_address(&transition.target_start)?;
    let end = parse_address(&transition.target_end)?;
    let owner = &transition.owner;
    let original_start = parse_address(&owner.original_start)?;
    let original_end = parse_address(&owner.original_end)?;
    let revised_start = parse_address(&owner.revised_start)?;
    let revised_end = parse_address(&owner.revised_end)?;

    let owner_source = source_units.get(owner.unit.as_str())?;
    let (candidate_ranges, candidate_strong) = sequence_details(&transition.functions)?;
    let (owner_ranges, owner_strong) = sequence_details(&owner.functions)?;
    let current_owner_range = single_section_range(target_blocks, &owner.unit, section);
    let previous_range = single_section_range(target_blocks, &transition.previous_unit, section);
    let next_range = single_section_range(target_blocks, &transition.next_unit, section);
    let source_previous = single_section_range(source_blocks, &transition.previous_unit, section)?;
    let source_candidate = single_section_range(source_blocks, &unit.name, section)?;
    let source_next = single_section_range(source_blocks, &transition.next_unit, section)?;

    // The three units must be contiguous in the source version, in that order,
    // and the candidate's source range must be exactly its code.
    if !transition.eligible
        || section != ".text"
        || !matches!(side, "next-prefix" | "previous-suffix")
        || end <= start
        || current_owner_range != Some((original_start, original_end))
        || owner.unit == unit.name
        || !source_units.contains_key(transition.previous_unit.as_str())
        || !source_units.contains_key(transition.next_unit.as_str())
        || source_previous.1 != source_candidate.0
        || source_candidate.1 != source_next.0
        || u64::from(source_candidate.1 - source_candidate.0) != unit.code_bytes
    {
        return None;
    }

    let helpers = &owner.gap_helpers;
    let candidate_bytes = end - start;
    let owner_bytes = revised_end.checked_sub(revised_start)?;
    let candidate_delta = relative_size_delta(unit.code_bytes as u32, candidate_bytes);
    let owner_delta = relative_size_delta(owner_source.code_bytes as u32, owner_bytes);
    let direct_anchors = direct_anchor_count(unit, section, start, end, &owner.unit);
    let target_addresses: BTreeSet<u32> = owner_ranges.iter().map(|(left, _)| *left).collect();
    let helper_addresses: BTreeSet<u32> =
        helpers.iter().filter_map(|h| parse_address(&h.target_address)).collect();
    let allowed_callers: BTreeSet<u32> =
        target_addresses.union(&helper_addresses).copied().collect();

    if transition.functions.len() < MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS
        || transition.source_functions as usize != transition.functions.len()
        || transition.aligned_functions as usize != transition.functions.len()
        || transition.strong_functions != candidate_strong
        || candidate_strong < MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS
        || transition.direct_anchors != direct_anchors
        || direct_anchors < MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS
        || u64::from(transition.source_bytes) != unit.code_bytes
        || transition.target_bytes != candidate_bytes
        || transition.match_ratio != 1.0
        || transition.target_coverage != 1.0
        || transition.alignment_margin < MIN_ALIGNMENT_MARGIN
        || [start, end, revised_start, revised_end].iter().any(|value| value % 4 != 0)
        || candidate_delta > MAX_ADJACENT_OWNER_SIZE_DELTA
        || !agrees(transition.size_delta, candidate_delta)
        || !partition_covers(start, end, &candidate_ranges, &[])
        || owner.source_functions as usize != owner.functions.len()
        || owner.aligned_functions as usize != owner.functions.len()
        || owner.functions.len() < MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS
        || owner.strong_functions != owner_strong
        || owner_strong < MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS
        || owner.target_functions as usize != owner.functions.len() + helpers.len()
        || u64::from(owner.source_bytes) != owner_source.code_bytes
        || owner.target_bytes != owner_bytes
        || owner_delta > MAX_ADJACENT_OWNER_SIZE_DELTA
        || !agrees(owner.size_delta, owner_delta)
        || helpers.len() > MAX_ADJACENT_OWNER_GAP_HELPERS
        || !partition_covers(revised_start, revised_end, &owner_ranges, helpers)
        || helpers.iter().any(|helper| {
            let callers: Vec<Option<u32>> =
                helper.callers.iter().map(|c| parse_address(c)).collect();
            helper.callers.is_empty()
                || !callers.iter().all(|c| c.is_some_and(|c| allowed_callers.contains(&c)))
                || !callers.iter().any(|c| c.is_some_and(|c| target_addresses.contains(&c)))
        })
    {
        return None;
    }

    // The candidate must sit exactly where the retained owner gives way, with
    // the far side already pinned by a unit that is not moving.
    let valid_boundary = if side == "next-prefix" {
        owner.unit == transition.next_unit
            && previous_range.is_some_and(|range| range.1 == start)
            && next_range == current_owner_range
            && source_next.1 - source_next.0 == owner.source_bytes
            && original_start < end
            && end < original_end
            && revised_start == end
            && revised_end == original_end
    } else {
        owner.unit == transition.previous_unit
            && next_range.is_some_and(|range| range.0 == end)
            && previous_range == current_owner_range
            && source_previous.1 - source_previous.0 == owner.source_bytes
            && original_start < start
            && start < original_end
            && revised_start == original_start
            && revised_end == start
    };
    let relinquished = if side == "next-prefix" {
        (original_start, revised_start)
    } else {
        (revised_end, original_end)
    };

    // Nothing but the retained owner may overlap the claimed range, and what it
    // gives up must be exactly the overlap.
    let overlaps: Vec<(&str, u32, u32)> = target_blocks
        .iter()
        .flat_map(|(name, lines)| lines.iter().map(move |line| (name, line)))
        .filter_map(|(name, line)| {
            let range = parse_range(line)?;
            (range.section == section && start < range.end && range.start < end).then_some((
                name.as_str(),
                range.start,
                range.end,
            ))
        })
        .collect();

    if !valid_boundary
        || relinquished.0 >= relinquished.1
        || overlaps.iter().any(|(name, _, _)| *name != owner.unit)
        || !overlaps.iter().any(|(name, other_start, other_end)| {
            *name == owner.unit
                && start.max(*other_start) == relinquished.0
                && end.min(*other_end) == relinquished.1
        })
    {
        return None;
    }

    Some(alternative(
        section,
        start,
        end,
        transition.functions.iter().map(|f| anchor_value(f, section)).collect(),
        "adjacent-owner-transition-boundary",
        Some(format!(
            "{}|{}|{side}|{}|{}",
            transition.previous_unit,
            transition.next_unit,
            owner.original_start,
            owner.original_end
        )),
        vec![OwnerRevision {
            unit: owner.unit.clone(),
            section: section.to_string(),
            original_start: owner.original_start.clone(),
            original_end: owner.original_end.clone(),
            revised_start: owner.revised_start.clone(),
            revised_end: owner.revised_end.clone(),
        }],
    ))
}

/// Why a unit produced no alternative, in one word.
///
/// Every missing unit gets one, so the report accounts for all of them rather
/// than only the ones something could be done about.
pub fn disposition(unit: &CoverageUnit, alternatives: &[Alternative]) -> String {
    if !alternatives.is_empty() {
        return "eligible".into();
    }
    if unit.code_bytes == 0 {
        return "zero-code".into();
    }
    if unit.code_bytes < 256 {
        return "tiny-code".into();
    }
    if unit.ambiguous_exact_bodies > 0 {
        return "ambiguous-shared-evidence".into();
    }
    let reasons: BTreeSet<&str> = unit
        .anchors
        .iter()
        .flat_map(|a| a.reasons.iter())
        .chain(unit.layout_shift_anchors.iter().flat_map(|a| a.reasons.iter()))
        .map(String::as_str)
        .collect();
    if reasons.contains("target range is owned by another explicit unit") {
        return "overlap".into();
    }
    if reasons.contains("function range is not split-aligned") {
        return "alignment".into();
    }
    if unit.layout_shift_candidates > 0 {
        return "layout-shift-insufficient-support".into();
    }
    if !unit.boundary_sequences.is_empty() {
        return "boundary-sequence-insufficient-support".into();
    }
    "no-qualifying-anchor".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(entries: &[(&str, u32, u32)]) -> Blocks {
        let mut map: Blocks = IndexMap::new();
        for (name, start, end) in entries {
            map.entry((*name).to_string()).or_default().push(split_line(".text", *start, *end));
        }
        map
    }

    fn anchor(address: u32, end: u32) -> CoverageAnchor {
        CoverageAnchor {
            source_name: "f".into(),
            source_address: format_address(0x1000),
            target_name: "g".into(),
            target_address: format_address(address),
            target_end: format_address(end),
            section: ".text".into(),
            size: end - address,
            source_local: false,
            target_local: false,
            source_weak: false,
            target_weak: false,
            source_extent_known: true,
            target_extent_known: true,
            source_unit_explicit: true,
            source_unit_wholly_owned: true,
            template_instantiation: false,
            unique_source: true,
            unique_target: true,
            normalized_body_equal: true,
            relocation_layout_equal: true,
            required_alignment: 4,
            existing_target_owner: None,
            existing_owner_autogenerated: false,
            eligible: true,
            reasons: Vec::new(),
        }
    }

    fn unit(anchors: Vec<CoverageAnchor>) -> CoverageUnit {
        CoverageUnit {
            name: "a.cpp".into(),
            code_bytes: 4096,
            autogenerated: false,
            source_functions: anchors.len() as u32,
            no_exact_target_body: 0,
            name_only_candidates: 0,
            ambiguous_exact_bodies: 0,
            anchors,
            layout_shift_candidates: 0,
            layout_shift_anchors: Vec::new(),
            boundary_sequences: Vec::new(),
            adjacent_owner_transitions: Vec::new(),
            required_extracts: Vec::new(),
        }
    }

    #[test]
    fn one_eligible_anchor_becomes_one_range() {
        let found = build(
            &unit(vec![anchor(0x8000_0100, 0x8000_0200)]),
            &IndexMap::new(),
            &BTreeMap::new(),
            &IndexMap::new(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].evidence, "exact-body");
        assert_eq!(found[0].start, "0x80000100");
        assert_eq!(found[0].covered_bytes, 0x100);
        assert_eq!(found[0].lines, [split_line(".text", 0x8000_0100, 0x8000_0200)]);
    }

    #[test]
    fn adjacent_anchors_also_offer_the_merged_range() {
        let found = build(
            &unit(vec![anchor(0x8000_0100, 0x8000_0200), anchor(0x8000_0200, 0x8000_0300)]),
            &IndexMap::new(),
            &BTreeMap::new(),
            &IndexMap::new(),
        );
        assert_eq!(found.len(), 3, "each anchor alone, and the merged range");
        // Narrow claims are tried before the wide one: a single anchor is the
        // least that has to be right for the range to be kept.
        assert_eq!(found[0].covered_bytes, 0x100);
        assert_eq!(found[2].covered_bytes, 0x200);
    }

    #[test]
    fn separated_anchors_are_never_merged() {
        let found = build(
            &unit(vec![anchor(0x8000_0100, 0x8000_0200), anchor(0x8000_0400, 0x8000_0500)]),
            &IndexMap::new(),
            &BTreeMap::new(),
            &IndexMap::new(),
        );
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|a| a.covered_bytes == 0x100));
    }

    #[test]
    fn a_range_another_unit_already_owns_is_not_offered() {
        let existing = blocks(&[("other.cpp", 0x8000_0180, 0x8000_0280)]);
        let found = build(
            &unit(vec![anchor(0x8000_0100, 0x8000_0200)]),
            &existing,
            &BTreeMap::new(),
            &IndexMap::new(),
        );
        assert!(found.is_empty());
    }

    #[test]
    fn an_ineligible_anchor_is_not_offered() {
        let mut only = anchor(0x8000_0100, 0x8000_0200);
        only.eligible = false;
        assert!(
            build(&unit(vec![only]), &IndexMap::new(), &BTreeMap::new(), &IndexMap::new())
                .is_empty()
        );
    }

    #[test]
    fn the_same_range_reached_twice_is_listed_once() {
        // A single anchor's run and the anchor alone are the same range.
        let found = build(
            &unit(vec![anchor(0x8000_0100, 0x8000_0200)]),
            &IndexMap::new(),
            &BTreeMap::new(),
            &IndexMap::new(),
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn an_identity_depends_on_the_range_and_the_evidence() {
        let one = alternative(".text", 0x100, 0x200, vec![], "exact-body", None, vec![]);
        let same = alternative(".text", 0x100, 0x200, vec![], "exact-body", None, vec![]);
        let other = alternative(".text", 0x100, 0x200, vec![], "boundary-sequence", None, vec![]);
        let wider = alternative(".text", 0x100, 0x300, vec![], "exact-body", None, vec![]);
        assert_eq!(one.id, same.id);
        assert_ne!(one.id, other.id);
        assert_ne!(one.id, wider.id);
        assert_eq!(one.id.len(), 16);
    }

    #[test]
    fn an_identity_covers_the_owner_revisions_too() {
        let revision = OwnerRevision {
            unit: "b.cpp".into(),
            section: ".text".into(),
            original_start: "0x80000100".into(),
            original_end: "0x80000400".into(),
            revised_start: "0x80000200".into(),
            revised_end: "0x80000400".into(),
        };
        let plain = alternative(".text", 0x100, 0x200, vec![], "exact-body", None, vec![]);
        let revised =
            alternative(".text", 0x100, 0x200, vec![], "exact-body", None, vec![revision]);
        assert_ne!(plain.id, revised.id);
    }

    #[test]
    fn a_unit_with_no_code_is_dispositioned_as_such() {
        let mut empty = unit(vec![]);
        empty.code_bytes = 0;
        assert_eq!(disposition(&empty, &[]), "zero-code");
        empty.code_bytes = 100;
        assert_eq!(disposition(&empty, &[]), "tiny-code");
        empty.code_bytes = 4096;
        assert_eq!(disposition(&empty, &[]), "no-qualifying-anchor");
    }

    #[test]
    fn an_overlap_reason_is_reported_over_the_generic_one() {
        let mut blocked = anchor(0x8000_0100, 0x8000_0200);
        blocked.eligible = false;
        blocked.reasons = vec!["target range is owned by another explicit unit".into()];
        assert_eq!(disposition(&unit(vec![blocked]), &[]), "overlap");
    }

    #[test]
    fn a_unit_with_an_alternative_is_eligible() {
        let one = alternative(".text", 0x100, 0x200, vec![], "exact-body", None, vec![]);
        assert_eq!(disposition(&unit(vec![]), std::slice::from_ref(&one)), "eligible");
    }

    #[test]
    fn a_partition_must_tile_its_range_exactly() {
        assert!(partition_covers(0x100, 0x300, &[(0x100, 0x200), (0x200, 0x300)], &[]));
        assert!(!partition_covers(0x100, 0x300, &[(0x100, 0x200)], &[]), "a gap at the end");
        assert!(!partition_covers(0x100, 0x300, &[(0x100, 0x280), (0x200, 0x300)], &[]), "overlap");
        assert!(!partition_covers(0x100, 0x300, &[(0x100, 0x180), (0x200, 0x300)], &[]), "hole");
    }

    #[test]
    fn an_address_round_trips() {
        assert_eq!(parse_address("0x80003100"), Some(0x8000_3100));
        assert_eq!(format_address(0x8000_3100), "0x80003100");
        assert_eq!(parse_address("nonsense"), None);
    }
}
