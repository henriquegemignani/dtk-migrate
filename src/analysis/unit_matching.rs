use std::collections::{HashMap, HashSet};

use decomp_toolkit::{
    obj::{ObjSectionKind, ObjSymbolKind, SectionIndex},
    util::split::default_section_align,
};
use serde::{Deserialize, Serialize};

use crate::analysis::{
    data_matching::DataMatch,
    matching::{MatchResult, MatchTarget, MatchTier},
};

/// How much trust a proposed split boundary has earned.
///
/// Mirrors [`MatchTier`]: only [`Confident`](UnitTier::Confident) is safe to
/// write into a splits file unreviewed — a wrong boundary silently pulls the
/// wrong code into a unit with nothing to prompt a re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitTier {
    /// Full member count, matched confident, in source order, edges bounded,
    /// no overlap with an existing split, and (for a code run) no non-code
    /// source content left behind uncovered.
    Confident,
    /// Same shape of evidence with something unproven — see [`classify`]'s
    /// reasons.
    Candidate,
}

/// A proposed split boundary for one unit, derived from function and data
/// symbol matches.
#[derive(Debug, Clone)]
pub struct UnitProposal {
    pub unit: String,
    pub section: SectionIndex,
    pub start: u32,
    pub end: u32,
    /// Target functions or data symbols covered by this run, in address order.
    pub members: Vec<u32>,
    pub tier: UnitTier,
    /// Empty when [`UnitTier::Confident`]; otherwise what kept it from being.
    pub reasons: Vec<&'static str>,
}

/// One item in a target section's address layout — a function node when
/// grouping code, a data symbol when grouping data. [`group_runs`] doesn't
/// need to know which; it just needs contiguous, addressable, attributable
/// pieces to group.
struct Item {
    index: u32,
    section: SectionIndex,
    start: u32,
    end: u32,
}

/// Groups the target's matched functions and data symbols into contiguous
/// same-section, same-unit runs and proposes a split boundary for each.
///
/// Data runs are proposed first, since whether a code run counts as
/// [`UnitTier::Confident`] depends on whether its source unit's non-code
/// content (if any) was itself confidently covered by a data run — see
/// [`non_text_migrated_units`].
pub fn propose_units(
    source: &MatchTarget,
    target: &MatchTarget,
    result: &MatchResult,
    data_matches: &[DataMatch],
) -> Vec<UnitProposal> {
    let data_attribution = attribute_data(source, data_matches);
    let data_layout = data_layout(target);
    let source_data_counts = source_unit_counts(source, false);
    // DataMatch has no weaker tier to fall back on, so there's nothing to feed
    // bridge_gap's low-confidence check for data runs.
    let data_proposals = group_runs(
        target,
        &data_layout,
        &data_attribution,
        &HashMap::new(),
        &source_data_counts,
        false,
        |_| true,
    );

    let text_only = text_only_units(source);
    let migrated = non_text_migrated_units(source, target, &data_proposals);

    let function_attribution = attribute_functions(source, result);
    let low_confidence_attribution = attribute_functions_candidates(source, result);
    let function_layout: Vec<Item> = target
        .layout()
        .iter()
        .map(|&n| {
            let node = target.graph.node(n);
            Item {
                index: n,
                section: node.section,
                start: node.address,
                end: node.address + node.size,
            }
        })
        .collect();
    let source_function_counts = source_unit_counts(source, true);
    let code_proposals = group_runs(
        target,
        &function_layout,
        &function_attribution,
        &low_confidence_attribution,
        &source_function_counts,
        true,
        |unit| text_only.contains(unit) || migrated.contains(unit),
    );

    code_proposals.into_iter().chain(data_proposals).collect()
}

/// Attributes each target function to a source unit and remembers the tier
/// that vouches for it, plus the source function's own address (to check
/// source-order below). Probable matches are trusted for grouping — their
/// disagreement tends to be between siblings in the same unit — but a run
/// still needs every member at Confident to be Confident itself.
fn attribute_functions(
    source: &MatchTarget,
    result: &MatchResult,
) -> HashMap<u32, (String, MatchTier, u32)> {
    let mut attribution = HashMap::new();
    for m in &result.matches {
        let tier = m.tier();
        if !matches!(tier, MatchTier::Confident | MatchTier::Probable) {
            continue;
        }
        if let Some(unit) = source.unit_of(m.source) {
            let source_address = source.graph.node(m.source).address;
            attribution.insert(m.target, (unit.to_string(), tier, source_address));
        }
    }
    attribution
}

/// Target functions matched only at [`MatchTier::Candidate`] — too weak for
/// [`attribute_functions`] to attribute, but still real evidence of ownership
/// when [`bridge_gap`] decides whether a gap is safe to cross.
fn attribute_functions_candidates(
    source: &MatchTarget,
    result: &MatchResult,
) -> HashMap<u32, String> {
    result
        .matches
        .iter()
        .filter(|m| m.tier() == MatchTier::Candidate)
        .filter_map(|m| Some((m.target, source.unit_of(m.source)?.to_string())))
        .collect()
}

/// Attributes each target data symbol to a source unit via [`DataMatch`].
/// Every surviving `DataMatch` already cleared a strict bar (alignment inside
/// a confidently-matched function, with no disagreement anywhere), so unlike
/// function attribution there's no weaker tier to carry through.
fn attribute_data(
    source: &MatchTarget,
    data_matches: &[DataMatch],
) -> HashMap<u32, (String, MatchTier, u32)> {
    let mut attribution = HashMap::new();
    for dm in data_matches {
        if let Some(unit) = source.unit_of_symbol(dm.source) {
            let source_address = source.obj.symbols[dm.source].address as u32;
            attribution.insert(dm.target, (unit.to_string(), MatchTier::Confident, source_address));
        }
    }
    attribution
}

/// Every sized data (`ObjSymbolKind::Object`) symbol in the target's non-code
/// sections, sorted by section then address — the data equivalent of
/// [`MatchTarget::layout`], which only covers functions.
fn data_layout(target: &MatchTarget) -> Vec<Item> {
    let mut items: Vec<Item> = target
        .obj
        .symbols
        .iter()
        .filter(|(_, s)| s.kind == ObjSymbolKind::Object && s.size_known && s.size > 0)
        .filter_map(|(index, s)| {
            let section = s.section?;
            (target.obj.sections.get(section)?.kind != ObjSectionKind::Code).then_some(Item {
                index,
                section,
                start: s.address as u32,
                end: s.address as u32 + s.size as u32,
            })
        })
        .collect();
    items.sort_by_key(|it| (it.section, it.start));
    items
}

/// How many source functions (or, with `functions: false`, data symbols) each
/// unit claims, so a run that found all of them can be told apart from one
/// that only found some.
fn source_unit_counts(source: &MatchTarget, functions: bool) -> HashMap<&str, usize> {
    let mut counts = HashMap::new();
    if functions {
        for (node, _) in source.graph.iter() {
            if let Some(unit) = source.unit_of(node) {
                *counts.entry(unit).or_default() += 1;
            }
        }
    } else {
        for (_, s) in source.obj.symbols.iter() {
            if s.kind != ObjSymbolKind::Object || !s.size_known || s.size == 0 {
                continue;
            }
            let Some(section) = s.section.and_then(|i| source.obj.sections.get(i)) else {
                continue;
            };
            if section.kind == ObjSectionKind::Code {
                continue;
            }
            if let Some((_, split)) = section.splits.for_address(s.address as u32) {
                *counts.entry(split.unit.as_str()).or_default() += 1;
            }
        }
    }
    counts
}

/// Groups `layout` into contiguous same-section, same-unit runs (per
/// `attribution`) and classifies each as a [`UnitProposal`].
///
/// `non_text_migrated` answers, for a run's unit, whether any non-code source
/// content it owns has already been accounted for elsewhere — trivially true
/// for a data run, since it has no further content to leave behind.
fn group_runs(
    target: &MatchTarget,
    layout: &[Item],
    attribution: &HashMap<u32, (String, MatchTier, u32)>,
    low_confidence: &HashMap<u32, String>,
    source_unit_size: &HashMap<&str, usize>,
    is_code: bool,
    non_text_migrated: impl Fn(&str) -> bool,
) -> Vec<UnitProposal> {
    let mut proposals = Vec::new();
    let mut i = 0;
    while i < layout.len() {
        let Some((unit, _, _)) = attribution.get(&layout[i].index) else {
            i += 1;
            continue;
        };
        let section = layout[i].section;
        let same_run = |j: usize| -> bool {
            layout.get(j).is_some_and(|it| {
                it.section == section
                    && attribution.get(&it.index).is_some_and(|(u, _, _)| u == unit)
                    && (is_code
                        || (layout[j - 1].end == it.start
                            && !has_split_at(target, section, it.start)))
            })
        };
        let mut j = i + 1;
        let mut bridged_gap_bytes = 0u32;
        loop {
            while same_run(j) {
                j += 1;
            }
            let bridged = if is_code {
                bridge_gap(target, layout, attribution, low_confidence, section, unit, j)
            } else {
                None
            };
            match bridged {
                Some(k) => {
                    bridged_gap_bytes += layout[k].start - layout[j].start;
                    j = k;
                }
                None => break,
            }
        }

        let run = &layout[i..j];
        let unit = unit.clone();
        let same_section =
            |k: usize| -> bool { layout.get(k).is_some_and(|it| it.section == section) };

        let start = run[0].start;
        // A data symbol only proves its own sized extent. Padding up to the
        // next symbol, or to the section end, may belong to another object;
        // code retains its established next-member boundary rule.
        let end = if !is_code {
            run.last().unwrap().end
        } else if same_section(j) {
            layout[j].start
        } else {
            target
                .obj
                .sections
                .get(section)
                .map(|s| (s.address + s.size) as u32)
                .unwrap_or_else(|| run.last().unwrap().end)
        };

        // Already split correctly: nothing to propose.
        if existing_split(target, section, start) == Some((start, end, unit.as_str())) {
            i = j;
            continue;
        }

        let section_bounds = target.obj.sections.get(section);
        let left_pinned = has_split_at(target, section, start)
            || if is_code {
                i == 0 || !same_section(i - 1) || attribution.contains_key(&layout[i - 1].index)
            } else {
                section_bounds.is_some_and(|s| start == s.address as u32)
                    || (i > 0
                        && same_section(i - 1)
                        && layout[i - 1].end == start
                        && attribution.contains_key(&layout[i - 1].index))
            };
        let right_pinned = has_split_at(target, section, end)
            || if is_code {
                !same_section(j) || attribution.contains_key(&layout[j].index)
            } else {
                section_bounds.is_some_and(|s| end == (s.address + s.size) as u32)
                    || (same_section(j)
                        && end == layout[j].start
                        && attribution.contains_key(&layout[j].index))
            };

        // Sections don't overlap in address space, so comparing the matched
        // source addresses directly orders members the same way sorting by
        // (section, address) would.
        let source_positions: Vec<u32> = run
            .iter()
            .filter_map(|it| attribution.get(&it.index))
            .map(|&(_, _, addr)| addr)
            .collect();
        let monotonic = source_positions.windows(2).all(|w| w[0] < w[1]);

        // Bridged gap members (below) are deliberately excluded here: they
        // were never matched at all, which classify() reports as its own,
        // more specific reason rather than folding it into "some member
        // matched below Confident."
        let all_confident = run
            .iter()
            .filter_map(|it| attribution.get(&it.index))
            .all(|(_, t, _)| *t == MatchTier::Confident);

        let expected = source_unit_size.get(unit.as_str()).copied().unwrap_or(0);
        let (tier, reasons) = classify(
            run.len(),
            expected,
            left_pinned,
            right_pinned,
            monotonic,
            overlaps_split(target, section, start, end),
            all_confident,
            non_text_migrated(unit.as_str()),
            aligned_boundary(target, section, start, end),
            bridged_gap_bytes,
        );

        proposals.push(UnitProposal {
            unit,
            section,
            start,
            end,
            members: run.iter().map(|it| it.index).collect(),
            tier,
            reasons,
        });
        i = j;
    }
    proposals
}

/// Bounds how much genuinely evidence-free content [`bridge_gap`] will
/// assume is a matching gap rather than a real function boundary. Large
/// enough to cover a handful of tiny unmatched helper functions, small
/// enough to not plausibly hide a whole unrelated function.
const MAX_BRIDGE_GAP_BYTES: u32 = 512;

/// A run breaks the moment [`group_runs`]'s `same_run` hits a function the
/// matcher didn't attribute to `unit` at all. Two different things produce
/// that: a function with no useful signal at any tier, or one only matched
/// at [`MatchTier::Candidate`] — too weak to attribute, but still real
/// evidence, checked here against `low_confidence`. When the run resumes
/// with the *same* unit, bridge across the gap instead of ending the run
/// there — otherwise one real function boundary gets reported as two
/// disjoint, riskier proposals instead of one verifiable one.
///
/// Refuses to bridge past a section boundary, an address some other unit's
/// split has already claimed, or a function — at any tier, including
/// Candidate — attributed to a *different* unit: real evidence the gap
/// isn't this unit's, not just a matching gap. Content with no evidence
/// either way is still capped at [`MAX_BRIDGE_GAP_BYTES`], since absence of
/// evidence isn't evidence of this unit. Returns the index the run should
/// resume at, or `None` if the gap isn't safely bridgeable.
fn bridge_gap(
    target: &MatchTarget,
    layout: &[Item],
    attribution: &HashMap<u32, (String, MatchTier, u32)>,
    low_confidence: &HashMap<u32, String>,
    section: SectionIndex,
    unit: &str,
    from: usize,
) -> Option<usize> {
    let mut k = from;
    let mut blind_bytes = 0u32;
    loop {
        let it = layout.get(k)?;
        if it.section != section {
            return None;
        }
        if let Some((u, _, _)) = attribution.get(&it.index) {
            return (u == unit).then_some(k);
        }
        match low_confidence.get(&it.index) {
            // Fresh positive evidence -- reset the blind-content budget so a
            // long gap doesn't fail just because *unrelated* blind stretches
            // on either side of a real, same-unit checkpoint add up past the
            // cap. Each stretch is judged against the cap on its own.
            Some(u) if u == unit => {
                k += 1;
                blind_bytes = 0;
            }
            Some(_) => return None,
            None => {
                if overlaps_split(target, section, it.start, it.end) {
                    return None;
                }
                blind_bytes += it.end - it.start;
                if blind_bytes > MAX_BRIDGE_GAP_BYTES {
                    return None;
                }
                k += 1;
            }
        }
    }
}

/// Source units whose every declared split lives in a code section.
///
/// Migrating just the `.text` of a unit that also owns data/`.ctors`/extab
/// content leaves that content claimed by a leftover auto-generated object —
/// multiply-defined or undefined at link time — unless the data itself was
/// also migrated, which [`non_text_migrated_units`] checks for separately.
fn text_only_units(source: &MatchTarget) -> HashSet<String> {
    let mut all_units: HashSet<&str> = HashSet::new();
    let mut has_non_code: HashSet<&str> = HashSet::new();
    for (_, section) in source.obj.sections.iter() {
        for (_, split) in section.splits.iter() {
            all_units.insert(split.unit.as_str());
            if section.kind != ObjSectionKind::Code {
                has_non_code.insert(split.unit.as_str());
            }
        }
    }
    all_units.difference(&has_non_code).map(|&s| s.to_string()).collect()
}

/// Source units whose non-code sections are *all* covered by a Confident data
/// proposal in the target — i.e. migrating this unit's `.text` won't leave
/// any of its data behind unaccounted for.
fn non_text_migrated_units(
    source: &MatchTarget,
    target: &MatchTarget,
    data_proposals: &[UnitProposal],
) -> HashSet<String> {
    let mut needed: HashMap<&str, HashSet<&str>> = HashMap::new();
    for (_, section) in source.obj.sections.iter() {
        if section.kind == ObjSectionKind::Code {
            continue;
        }
        for (_, split) in section.splits.iter() {
            needed.entry(split.unit.as_str()).or_default().insert(section.name.as_str());
        }
    }

    let mut covered: HashMap<&str, HashSet<&str>> = HashMap::new();
    for p in data_proposals {
        if p.tier != UnitTier::Confident {
            continue;
        }
        if let Some(name) = target.obj.sections.get(p.section).map(|s| s.name.as_str()) {
            covered.entry(p.unit.as_str()).or_default().insert(name);
        }
    }

    needed
        .into_iter()
        .filter(|(unit, sections)| covered.get(unit).is_some_and(|got| sections.is_subset(got)))
        .map(|(unit, _)| unit.to_string())
        .collect()
}

/// Classifies a run of matched members from the evidence already gathered
/// about it.
///
/// Kept separate from the address/lookup mechanics in [`group_runs`] so the
/// classification rules can be tested without a real binary.
#[allow(clippy::too_many_arguments)]
fn classify(
    run_len: usize,
    expected: usize,
    left_pinned: bool,
    right_pinned: bool,
    source_order_monotonic: bool,
    overlaps_existing: bool,
    all_confident: bool,
    non_text_content_migrated: bool,
    aligned_boundary: bool,
    bridged_gap_bytes: u32,
) -> (UnitTier, Vec<&'static str>) {
    let mut reasons = Vec::new();
    if run_len < expected {
        reasons.push("target is missing functions the source unit has");
    }
    if !left_pinned {
        reasons.push("left edge borders an unmatched function");
    }
    if !right_pinned {
        reasons.push("right edge borders an unmatched function");
    }
    if !source_order_monotonic {
        reasons.push("source functions are out of order");
    }
    if overlaps_existing {
        reasons.push("overlaps an existing split");
    }
    if !all_confident {
        reasons.push("contains a function matched below the confident tier");
    }
    if !non_text_content_migrated {
        reasons.push("source unit has non-text content that wasn't migrated");
    }
    if !aligned_boundary {
        reasons.push("split boundary doesn't meet the section's required alignment");
    }
    if bridged_gap_bytes > 0 {
        reasons.push("bridges unmatched functions between two runs of the same unit");
    }
    let tier = if reasons.is_empty() { UnitTier::Confident } else { UnitTier::Candidate };
    (tier, reasons)
}

/// Whether `start`/`end` both satisfy the alignment a split in this section
/// actually needs to link without the linker inserting padding the original
/// binary never had.
///
/// Mirrors [`decomp_toolkit::obj::ObjSplit::alignment`]: the section's own default
/// (4 for code, 8 for most everything else) maxed with the largest `align`
/// any symbol in the range declares. `default_section_align` alone isn't
/// enough — a real migration produced a 448-byte-larger, hash-mismatched DOL
/// from splits that were 4-byte aligned but not the 8 several `.rodata`/
/// `.data` sections actually require.
fn aligned_boundary(target: &MatchTarget, section: SectionIndex, start: u32, end: u32) -> bool {
    let Some(align) = required_alignment(target, section, start, end) else { return false };
    start % align == 0 && end % align == 0
}

pub(crate) fn required_alignment(
    target: &MatchTarget,
    section: SectionIndex,
    start: u32,
    end: u32,
) -> Option<u32> {
    let s = target.obj.sections.get(section)?;
    let default_align = default_section_align(s) as u32;
    let align = target
        .obj
        .symbols
        .for_section_range(section, start..end)
        .filter(|&(_, sym)| sym.size_known && sym.size > 0)
        .filter_map(|(_, sym)| sym.align)
        .max()
        .unwrap_or(default_align)
        .max(default_align);
    Some(align)
}

fn has_split_at(target: &MatchTarget, section: SectionIndex, address: u32) -> bool {
    target.obj.sections.get(section).is_some_and(|s| s.splits.has_split_at(address))
}

fn overlaps_split(target: &MatchTarget, section: SectionIndex, start: u32, end: u32) -> bool {
    let Some(s) = target.obj.sections.get(section) else { return false };
    s.splits.for_range(start..end).next().is_some() || s.splits.for_address(start).is_some()
}

/// The existing split starting exactly at `address`, if any, as
/// `(start, end, unit)`.
fn existing_split(
    target: &MatchTarget,
    section: SectionIndex,
    address: u32,
) -> Option<(u32, u32, &str)> {
    let s = target.obj.sections.get(section)?;
    let (addr, split) = s.splits.for_address(address)?;
    (addr == address).then_some((addr, split.end, split.unit.as_str()))
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocations, ObjSection, ObjSplit, ObjSplits,
        ObjSymbol,
    };

    use super::*;

    #[test]
    fn separated_data_symbols_do_not_claim_the_gap_or_section_tail() {
        let symbols = vec![
            ObjSymbol {
                name: "first".into(),
                address: 0x1000,
                section: Some(0),
                size: 4,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            ObjSymbol {
                name: "second".into(),
                address: 0x2000,
                section: Some(0),
                size: 4,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            ObjSymbol {
                name: "third".into(),
                address: 0x2004,
                section: Some(0),
                size: 4,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
        ];
        let mut splits = ObjSplits::default();
        splits.push(0x2004, ObjSplit {
            unit: "other.cpp".into(),
            end: 0x2008,
            align: Some(4),
            common: true,
            autogenerated: false,
            skip: false,
            rename: None,
        });
        let section = ObjSection {
            name: ".bss".into(),
            kind: ObjSectionKind::Bss,
            address: 0x1000,
            size: 0x2000,
            data: Vec::new(),
            align: 4,
            elf_index: 0,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits,
        };
        let target = MatchTarget::new(
            "target".into(),
            ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc,
                "target".into(),
                symbols,
                vec![section],
            ),
        );
        let attribution = HashMap::from([
            (0, ("unit.cpp".into(), MatchTier::Confident, 0x1000)),
            (1, ("unit.cpp".into(), MatchTier::Confident, 0x2000)),
            (2, ("unit.cpp".into(), MatchTier::Confident, 0x2004)),
        ]);
        let proposals = group_runs(
            &target,
            &data_layout(&target),
            &attribution,
            &HashMap::new(),
            &HashMap::from([("unit.cpp", 3)]),
            false,
            |_| true,
        );
        assert_eq!(proposals.iter().map(|p| (p.start, p.end)).collect::<Vec<_>>(), [
            (0x1000, 0x1004),
            (0x2000, 0x2004),
            (0x2004, 0x2008)
        ]);
        assert!(proposals.iter().all(|p| p.tier == UnitTier::Candidate));
    }

    fn baseline(run_len: usize, expected: usize) -> (UnitTier, Vec<&'static str>) {
        classify(run_len, expected, true, true, true, false, true, true, true, 0)
    }

    #[test]
    fn a_complete_pinned_run_is_confident() {
        let (tier, reasons) = baseline(3, 3);
        assert_eq!(tier, UnitTier::Confident);
        assert!(reasons.is_empty());
    }

    #[test]
    fn a_partial_run_is_a_candidate() {
        // The source unit has more functions than the target run found.
        let (tier, reasons) = baseline(2, 3);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["target is missing functions the source unit has"]);
    }

    #[test]
    fn an_unpinned_edge_is_a_candidate() {
        let (tier, reasons) = classify(3, 3, false, true, true, false, true, true, true, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["left edge borders an unmatched function"]);

        let (tier, reasons) = classify(3, 3, true, false, true, false, true, true, true, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["right edge borders an unmatched function"]);
    }

    #[test]
    fn a_reordered_run_is_a_candidate() {
        let (tier, reasons) = classify(3, 3, true, true, false, false, true, true, true, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["source functions are out of order"]);
    }

    #[test]
    fn overlap_with_an_existing_split_is_a_candidate() {
        let (tier, reasons) = classify(3, 3, true, true, true, true, true, true, true, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["overlaps an existing split"]);
    }

    #[test]
    fn a_non_confident_member_is_a_candidate() {
        // Attribution trusts Probable matches for grouping, but a run isn't
        // safe to write unreviewed unless every member earned Confident.
        let (tier, reasons) = classify(3, 3, true, true, true, false, false, true, true, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["contains a function matched below the confident tier"]);
    }

    #[test]
    fn a_source_unit_with_unmigrated_data_is_a_candidate() {
        // Migrating .text alone would leave the unit's data claimed by
        // whatever leftover object still covers it under another name.
        let (tier, reasons) = classify(3, 3, true, true, true, false, true, false, true, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["source unit has non-text content that wasn't migrated"]);
    }

    #[test]
    fn an_unaligned_boundary_is_a_candidate() {
        // The linker requires a split's boundary to meet its section's
        // alignment; a data run's raw symbol extents often don't.
        let (tier, reasons) = classify(3, 3, true, true, true, false, true, true, false, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["split boundary doesn't meet the section's required alignment"]);
    }

    #[test]
    fn a_bridged_gap_is_a_candidate() {
        // Bridging a gap of unmatched functions is a real bet, not proof --
        // it must never come back Confident, no matter how small the gap.
        let (tier, reasons) = classify(3, 3, true, true, true, false, true, true, true, 204);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec!["bridges unmatched functions between two runs of the same unit"]);
    }

    #[test]
    fn multiple_problems_all_get_reported() {
        let (tier, reasons) = classify(2, 3, false, false, true, false, true, true, true, 0);
        assert_eq!(tier, UnitTier::Candidate);
        assert_eq!(reasons, vec![
            "target is missing functions the source unit has",
            "left edge borders an unmatched function",
            "right edge borders an unmatched function",
        ]);
    }
}
