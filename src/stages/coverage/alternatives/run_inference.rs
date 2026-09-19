//! Joint source-order run inference and transaction generation.

use super::*;
use crate::analysis::unit_runs::{self, Piece, Placement, Search, SegmentScore};

/// A bounded joint search did not yield an automatic transaction. These are
/// kept in the preparation inventory rather than silently becoming a generic
/// "no alternative" disposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDiagnostic {
    pub units: Vec<String>,
    pub section: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub best_partition: Option<Vec<Placement>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub competing_partition: Option<Vec<Placement>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_independent_members: Option<Vec<String>>,
}

impl RunDiagnostic {
    fn new(units: &[String], section: &str, reason: &str) -> Self {
        Self {
            units: units.to_vec(),
            section: section.into(),
            reason: reason.into(),
            best_partition: None,
            competing_partition: None,
            shared_independent_members: None,
        }
    }
}

/// Replace exactly one section of a body while preserving every other line
/// and the attributes of the old section. Multiple old ranges would need a
/// separate interval-level hypothesis; this solver does not merge them.
fn joint_body(
    old: Option<&Vec<String>>,
    section: &str,
    start: u32,
    end: u32,
) -> Option<Vec<String>> {
    let mut body = old.cloned().unwrap_or_default();
    let old_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (parse_range(line)?.section == section).then_some(index))
        .collect();
    if old_positions.len() > 1 || end <= start {
        return None;
    }
    let (position, suffix) = match old_positions.first() {
        Some(&index) => (index, entry_suffix(&body.remove(index))),
        None => (body.len(), String::new()),
    };
    body.insert(position, entry_line(section, start, end, &suffix));
    Some(body)
}

fn segment_padding(pieces: &[&Piece], start: u32, end: u32) -> Option<u32> {
    let mut cursor = start;
    let mut padding = 0;
    for piece in pieces {
        let gap = piece.start.checked_sub(cursor)?;
        if gap > MAX_COMPOSED_PADDING_GAP {
            return None;
        }
        padding += gap;
        cursor = piece.end;
    }
    let gap = end.checked_sub(cursor)?;
    (gap <= MAX_COMPOSED_PADDING_GAP).then_some(padding + gap)
}

/// Source-order runs are hypotheses, not constraints on the whole binary.
/// Each unit must have an independent target member, those members must appear
/// in the same order, and independently attributed outsiders bound the run.
/// Reordered units are handled by their individual alternatives instead.
pub fn joint_runs(
    source_units: &BTreeMap<String, &CoverageUnit>,
    target_blocks: &Blocks,
    observations: &ObservationIndex,
) -> (BTreeMap<String, Vec<Alternative>>, Vec<RunDiagnostic>) {
    let mut offered: BTreeMap<String, Vec<Alternative>> = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut windows = 0;
    for section in [".text", ".init"] {
        let mut source: Vec<_> = observations
            .report()
            .source_functions
            .iter()
            .filter(|function| function.module == MODULE && function.section == section)
            .collect();
        source.sort_by_key(|function| parse_address(&function.address));
        let mut order = Vec::<String>::new();
        for function in source {
            if order.last() != Some(&function.unit) {
                order.push(function.unit.clone());
            }
        }
        // A unit interleaved with another in the source has no single source
        // position. It cannot participate in this ordered-run rule.
        let counts = order.iter().fold(BTreeMap::<&str, usize>::new(), |mut counts, name| {
            *counts.entry(name).or_default() += 1;
            counts
        });
        let functions = observations.section_functions(MODULE, section);
        if functions.is_empty() {
            continue;
        }
        let mut by_unit: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, function) in functions.iter().enumerate() {
            if let Some(item) = observations
                .at_target(MODULE, section, parse_address(&function.address).unwrap_or(0))
                .filter(|item| item.independent)
            {
                by_unit.entry(item.source.unit.clone()).or_default().push(index);
            }
        }
        let needed: Vec<bool> = order
            .iter()
            .map(|name| {
                let own: Vec<_> = target_blocks
                    .get(name)
                    .into_iter()
                    .flat_map(|lines| lines.iter().filter_map(|line| parse_range(line)))
                    .filter(|range| range.section == section)
                    .collect();
                own.is_empty()
                    || by_unit.get(name).is_some_and(|indices| {
                        indices.iter().any(|&index| {
                            let start = parse_address(&functions[index].address).unwrap_or(0);
                            let end = parse_address(&functions[index].end).unwrap_or(0);
                            !own.iter().any(|range| range.start <= start && end <= range.end)
                        })
                    })
                    || by_unit.iter().any(|(other, indices)| {
                        other != name
                            && indices.iter().any(|&index| {
                                let start = parse_address(&functions[index].address).unwrap_or(0);
                                own.iter().any(|range| range.start <= start && start < range.end)
                            })
                    })
            })
            .collect();
        let mut windows_to_try = Vec::new();
        let mut index = 0;
        while index < order.len() {
            if !needed[index] {
                index += 1;
                continue;
            }
            let start = index;
            while index < order.len() && needed[index] {
                index += 1;
            }
            for chunk_start in (start..index).step_by(MAX_JOINT_UNITS) {
                let chunk_end = (chunk_start + MAX_JOINT_UNITS).min(index);
                if chunk_end - chunk_start >= 2 {
                    windows_to_try.push((chunk_start, chunk_end));
                } else if chunk_end < order.len() {
                    windows_to_try.push((chunk_start, chunk_end + 1));
                } else if chunk_start > 0 {
                    windows_to_try.push((chunk_start - 1, chunk_end));
                }
            }
        }
        for (first, last) in windows_to_try {
            let names = &order[first..last];
            if names.iter().any(|name| {
                counts.get(name.as_str()) != Some(&1)
                    || !source_units.contains_key(name)
                    || source_units[name].autogenerated
            }) {
                continue;
            }
            let mut positions = Vec::new();
            let mut monotonic = true;
            for name in names {
                let Some(indices) = by_unit.get(name) else {
                    monotonic = false;
                    break;
                };
                let (Some(&left), Some(&right)) = (indices.first(), indices.last()) else {
                    monotonic = false;
                    break;
                };
                if positions.last().is_some_and(|&(_, previous_right)| previous_right >= left) {
                    monotonic = false;
                    break;
                }
                positions.push((left, right));
            }
            if !monotonic {
                continue;
            }
            let (mut left, mut right) = (positions[0].0, positions.last().unwrap().1 + 1);
            // Include nearby unattributed functions, stopping at an
            // independent outsider. A larger unbounded region is not a
            // safe finite search window.
            while left > 0 && positions[0].0 - left < 3 {
                let function = &functions[left - 1];
                if observations
                    .at_target(MODULE, section, parse_address(&function.address).unwrap_or(0))
                    .is_some_and(|item| item.independent)
                {
                    break;
                }
                left -= 1;
            }
            while right < functions.len() && right - (positions.last().unwrap().1 + 1) < 3 {
                let function = &functions[right];
                if observations
                    .at_target(MODULE, section, parse_address(&function.address).unwrap_or(0))
                    .is_some_and(|item| item.independent)
                {
                    break;
                }
                right += 1;
            }
            // A stopped expansion must have found an independent outside
            // member. Otherwise the run is not bounded by observations.
            let outside = |index: usize| {
                let function = &functions[index];
                observations
                    .at_target(MODULE, section, parse_address(&function.address).unwrap_or(0))
                    .is_some_and(|item| item.independent && !names.contains(&item.source.unit))
            };
            if (left > 0 && !outside(left - 1)) || (right < functions.len() && !outside(right)) {
                continue;
            }
            if right - left > MAX_JOINT_FUNCTIONS {
                diagnostics.push(RunDiagnostic::new(names, section, "function-limit-reached"));
                continue;
            }
            let pieces: Vec<Piece> = functions[left..right]
                .iter()
                .map(|function| {
                    let start = parse_address(&function.address).unwrap_or(0);
                    Piece {
                        start,
                        end: parse_address(&function.end).unwrap_or(0),
                        independent: observations
                            .at_target(MODULE, section, start)
                            .filter(|item| item.independent)
                            .map(|item| item.source.unit.clone()),
                    }
                })
                .collect();
            if pieces
                .iter()
                .any(|piece| piece.independent.as_ref().is_some_and(|unit| !names.contains(unit)))
            {
                continue;
            }
            // An outer independent function fixes the edge, but cannot
            // itself be moved. At a section end the outermost function
            // extent supplies the bound instead.
            let window_start = if left > 0 {
                parse_address(&functions[left - 1].end).unwrap_or(0)
            } else {
                pieces[0].start
            };
            let window_end = if right < functions.len() {
                parse_address(&functions[right].address).unwrap_or(0)
            } else {
                pieces.last().map_or(0, |piece| piece.end)
            };
            if pieces[0].start.saturating_sub(window_start) > MAX_COMPOSED_PADDING_GAP
                || window_end.saturating_sub(pieces.last().unwrap().end) > MAX_COMPOSED_PADDING_GAP
            {
                continue;
            }
            // No work if every independent member is already owned by
            // the unit the source evidence names.
            if pieces.iter().all(|piece| piece.independent.is_some())
                && pieces
                    .iter()
                    .filter_map(|piece| {
                        let item = observations.at_target(MODULE, section, piece.start)?;
                        item.independent.then_some((piece.start, item.source.unit.as_str()))
                    })
                    .all(|(address, unit)| {
                        target_blocks.get(unit).is_some_and(|body| {
                            body.iter().filter_map(|line| parse_range(line)).any(|range| {
                                range.section == section
                                    && range.start <= address
                                    && address < range.end
                            })
                        })
                    })
            {
                continue;
            }
            if windows >= MAX_JOINT_WINDOWS {
                diagnostics.push(RunDiagnostic::new(names, section, "window-limit-reached"));
                continue;
            }
            windows += 1;
            let found = unit_runs::search(
                names,
                &pieces,
                window_end,
                MAX_JOINT_SEARCH_STATES,
                |name, start, end| {
                    if start >= end || end - start > 0x10000 {
                        return None;
                    }
                    let after = joint_body(target_blocks.get(name), section, start, end)?;
                    let segment: Vec<&Piece> = pieces
                        .iter()
                        .filter(|piece| start <= piece.start && piece.start < end)
                        .collect();
                    if segment.is_empty() {
                        return None;
                    }
                    let padding = segment_padding(&segment, start, end)?;
                    if segment.iter().all(|piece| piece.independent.as_deref() == Some(name)) {
                        return Some(SegmentScore {
                            independent: segment.len() as u32,
                            complete: true,
                            explained: 0,
                            padding,
                        });
                    }
                    let before = section_ranges(
                        target_blocks.get(name).map(Vec::as_slice).unwrap_or_default(),
                    );
                    let after_ranges = section_ranges(&after);
                    let assessed = observations.assess(name, MODULE, &before, &after_ranges);
                    assessed.permits_automatic_claim().then_some(SegmentScore {
                        independent: assessed.independent_members,
                        complete: assessed.complete_membership,
                        explained: assessed.new_order_bracketed
                            + assessed.new_caller_confined_helpers
                            + assessed.new_complete_sequence_members,
                        padding: assessed.padding_bytes,
                    })
                },
            );
            let placements = match found {
                Search::Decisive(placements) => placements,
                Search::Ambiguous { best, competing, shared_independent } => {
                    let mut diagnostic = RunDiagnostic::new(names, section, "competing-partitions");
                    diagnostic.best_partition = Some(best);
                    diagnostic.competing_partition = Some(competing);
                    diagnostic.shared_independent_members =
                        Some(shared_independent.into_iter().map(format_address).collect());
                    diagnostics.push(diagnostic);
                    continue;
                }
                Search::Incomplete => {
                    diagnostics.push(RunDiagnostic::new(
                        names,
                        section,
                        "unresolved-target-or-source",
                    ));
                    continue;
                }
                Search::Exhausted => {
                    diagnostics.push(RunDiagnostic::new(names, section, "search-limit-reached"));
                    continue;
                }
            };
            // The worker and coordinator already schedule by transaction
            // read/write sets and apply it as one indivisible change.
            let changes: Vec<(String, Vec<String>)> = placements
                .iter()
                .filter_map(|placement| {
                    let (start, end) = placement.range?;
                    Some((
                        placement.unit.clone(),
                        joint_body(target_blocks.get(&placement.unit), section, start, end)?,
                    ))
                })
                .collect();
            if changes.len() != names.len() {
                continue;
            }
            let written: Vec<String> = changes
                .iter()
                .filter(|(name, body)| target_blocks.get(name) != Some(body))
                .map(|(name, _)| name.clone())
                .collect();
            let required_extracts = joint_required_extracts(&written, source_units);
            let evidence: Vec<String> = pieces
                .iter()
                .filter_map(|piece| observations.at_target(MODULE, section, piece.start))
                .filter(|item| item.independent)
                .map(|item| item.id.clone())
                .collect();
            let transaction =
                match OwnershipTransaction::build(target_blocks, changes, Provenance {
                    policy: policy_digest(),
                    observation_sha256: observations.digest().into(),
                    evidence: std::iter::once("joint-unit-run".into())
                        .chain(evidence.clone())
                        .collect(),
                    required_extracts,
                    releases: Vec::new(),
                }) {
                    Ok(transaction)
                        if transaction.members.len() >= 2
                            && transaction.preview(target_blocks).is_ok() =>
                    {
                        transaction
                    }
                    _ => continue,
                };
            let Some(root) = names.iter().find(|name| transaction.member(name).is_some()) else {
                continue;
            };
            let Some(root_change) = transaction.member(root) else { continue };
            let Some((start, end)) = placements
                .iter()
                .find(|placement| &placement.unit == root)
                .and_then(|placement| placement.range)
            else {
                continue;
            };
            let Some(ownership) = assess_member(observations, &transaction, root) else {
                continue;
            };
            if !ownership.permits_automatic_claim() {
                continue;
            }
            let mut receiver_ownership = BTreeMap::new();
            let mut certified = true;
            for receiver in transaction.receivers().into_iter().filter(|name| *name != root) {
                let Some(assessment) = assess_member(observations, &transaction, receiver) else {
                    certified = false;
                    break;
                };
                if !assessment.permits_automatic_claim() {
                    certified = false;
                    break;
                }
                receiver_ownership.insert(receiver.to_string(), assessment);
            }
            if !certified {
                continue;
            }
            let boundaries = [
                boundaries::judge(observations, root, MODULE, section, Side::Left, start, vec![
                    "joint-unit-run".into(),
                ]),
                boundaries::judge(observations, root, MODULE, section, Side::Right, end, vec![
                    "joint-unit-run".into(),
                ]),
            ]
            .to_vec();
            offered.entry(root.clone()).or_default().push(Alternative {
                id: transaction.id.clone(),
                evidence: "joint-unit-run".into(),
                support_group: Some(names.join("|")),
                section: section.into(),
                start: format_address(start),
                end: format_address(end),
                covered_bytes: end - start,
                gained_bytes: transaction.gained_bytes(root),
                lines: root_change.after.clone(),
                anchors: pieces
                    .iter()
                    .filter_map(|piece| observations.at_target(MODULE, section, piece.start))
                    .filter(|item| item.independent && item.source.unit == *root)
                    .map(|item| {
                        serde_json::json!({
                            "section": section,
                            "target_address": item.target.address,
                            "attribution_id": item.id,
                        })
                    })
                    .collect(),
                ownership,
                receiver_ownership,
                boundaries,
                transaction,
            });
        }
    }
    for alternatives in offered.values_mut() {
        alternatives.sort_by(|a, b| a.id.cmp(&b.id));
        alternatives.dedup_by(|a, b| a.id == b.id);
        sort_alternatives(alternatives);
    }
    (offered, diagnostics)
}

/// Stable union of every source unit whose joint body is being certified.
pub fn joint_required_extracts(
    names: &[String],
    units: &BTreeMap<String, &CoverageUnit>,
) -> Vec<crate::analysis::coverage::RequiredExtract> {
    let mut by_value = BTreeMap::new();
    for name in names {
        if let Some(unit) = units.get(name) {
            for extract in &unit.required_extracts {
                by_value
                    .insert(serde_json::to_string(extract).unwrap_or_default(), extract.clone());
            }
        }
    }
    by_value.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_joint_body_keeps_other_sections_and_split_attributes() {
        let old = vec![
            entry_line(".init", 0x100, 0x180, "align:4"),
            entry_line(".text", 0x1000, 0x1200, "align:16"),
            entry_line(".data", 0x4000, 0x4020, "align:8"),
        ];
        let body = joint_body(Some(&old), ".text", 0x1000, 0x1100).unwrap();
        assert_eq!(body[0], old[0]);
        assert_eq!(body[1], entry_line(".text", 0x1000, 0x1100, "align:16"));
        assert_eq!(body[2], old[2]);
    }

    #[test]
    fn a_joint_body_does_not_merge_two_existing_ranges() {
        let old =
            vec![entry_line(".text", 0x1000, 0x1100, ""), entry_line(".text", 0x1200, 0x1300, "")];
        assert!(joint_body(Some(&old), ".text", 0x1000, 0x1300).is_none());
    }

    #[test]
    fn mixed_evidence_cannot_hide_a_large_gap_as_padding() {
        let first = Piece { start: 0x1000, end: 0x1020, independent: Some("A".into()) };
        let second = Piece { start: 0x1100, end: 0x1120, independent: None };
        assert_eq!(segment_padding(&[&first, &second], 0x1000, 0x1120), None);
    }
}
