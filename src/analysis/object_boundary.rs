//! Ordered binary and compiled-function placement evidence.
//!
//! A compiled definition alone does not identify the object that emitted a
//! retail function. Each record therefore keeps an entire bounded arrangement
//! rather than promoting one matching body: a two-unit seam, or a terminal
//! suffix of one clean object bracketed by a held predecessor and an
//! independent foreign successor. The transaction path checks source split
//! ownership and the complete resulting bodies before using either record.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    object_evidence::{
        BuildFreshness, CompiledFunction, ObjectEvidence, ObjectRecord, ObjectStatus,
    },
    ownership::{FunctionAttribution, SourceFunctionObservation, TargetFunctionObservation},
    policy::{MAX_COMPILED_TERMINAL_MEMBERS, MIN_COMPILED_TERMINAL_MEMBERS},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledBoundary {
    pub section: String,
    pub left_unit: String,
    pub right_unit: String,
    /// The six source and target functions in corresponding order. The third
    /// is the left tail; the fourth and fifth begin the right unit.
    pub source_addresses: [String; 6],
    pub target_addresses: [String; 6],
    pub left_object_sha256: String,
    pub right_object_sha256: String,
}

/// A complete terminal run of a clean compiled object, in the same order at
/// the end of its source unit and just beyond the unit's current retail split.
/// The held predecessor and the independent following foreign function bound
/// the claim. Individual bridges remain identity evidence only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledTerminalSuffix {
    pub unit: String,
    pub section: String,
    pub source_addresses: Vec<String>,
    pub target_addresses: Vec<String>,
    pub predecessor_attribution_id: String,
    pub following_attribution_id: String,
    pub object_sha256: String,
}

/// One changed terminal function placed by a clean compiled caller/callee
/// relation and the same sole-caller relation in the retail binary. The
/// independently identified predecessor and its held neighbour pin the run;
/// neither a function name nor a sole caller on its own places the tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledCallLinkedTail {
    pub unit: String,
    pub section: String,
    pub source_caller: String,
    pub source_tail: String,
    pub target_caller: String,
    pub target_tail: String,
    pub predecessor_attribution_id: String,
    pub caller_attribution_id: String,
    pub object_sha256: String,
}

fn address(text: &str) -> Option<u32> { u32::from_str_radix(text.strip_prefix("0x")?, 16).ok() }

fn extent(start: &str, end: &str) -> Option<u32> { address(end)?.checked_sub(address(start)?) }

fn adjacent(left_end: &str, right_start: &str) -> bool { left_end == right_start }

fn sites_match(
    compiled: &CompiledFunction,
    target: &TargetFunctionObservation,
    evidence: &ObjectEvidence,
) -> bool {
    let Some(references) = evidence.target_references.iter().find(|item| {
        item.section == target.section && item.address == target.address && item.end == target.end
    }) else {
        return false;
    };
    compiled.references.len() == references.references.len()
        && compiled.references.iter().zip(&references.references).all(|(left, right)| {
            (left.offset, &left.kind, left.addend) == (right.offset, &right.kind, right.addend)
                && left
                    .target_section
                    .as_ref()
                    .zip(right.target_section.as_ref())
                    .is_none_or(|(left, right)| left == right)
        })
}

fn compiled_member<'a>(
    record: &'a ObjectRecord,
    source: &SourceFunctionObservation,
    target: &TargetFunctionObservation,
    evidence: &ObjectEvidence,
) -> Option<&'a CompiledFunction> {
    let hash = target.normalized_body_sha256.as_deref()?;
    let matches: Vec<_> = record
        .functions
        .iter()
        .filter(|function| {
            function.name == source.name
                && function.section == target.section
                && function.normalized_body_sha256.as_deref() == Some(hash)
                && extent(&function.address, &function.end)
                    .zip(extent(&target.address, &target.end))
                    .is_some_and(|(compiled, retail)| compiled == retail)
                && sites_match(function, target, evidence)
        })
        .collect();
    let [member] = matches.as_slice() else { return None };
    Some(member)
}

/// Recover a changed last function only when the source-version order, a
/// clean target-version object's internal call, and the retail call topology
/// independently select the same one-function tail. The compiled body need
/// not match the retail body: this rule is for a version-changed function.
pub fn compiled_call_linked_tails(
    evidence: &ObjectEvidence,
    source_functions: &[SourceFunctionObservation],
    target_functions: &[TargetFunctionObservation],
    attributions: &[FunctionAttribution],
) -> Vec<CompiledCallLinkedTail> {
    if evidence.status != super::object_evidence::ScanStatus::Scanned {
        return Vec::new();
    }
    let mut source_by_unit: BTreeMap<(&str, &str), Vec<&SourceFunctionObservation>> =
        BTreeMap::new();
    for function in source_functions.iter().filter(|item| item.module == "main") {
        source_by_unit.entry((&function.unit, &function.section)).or_default().push(function);
    }
    let mut target_by_section: BTreeMap<&str, Vec<&TargetFunctionObservation>> = BTreeMap::new();
    for function in target_functions.iter().filter(|item| item.module == "main") {
        target_by_section.entry(&function.section).or_default().push(function);
    }
    for functions in source_by_unit.values_mut() {
        functions.sort_by_key(|item| address(&item.address));
    }
    for functions in target_by_section.values_mut() {
        functions.sort_by_key(|item| address(&item.address));
    }
    let mut all_source_by_section: BTreeMap<&str, Vec<&SourceFunctionObservation>> =
        BTreeMap::new();
    for function in source_functions.iter().filter(|item| item.module == "main") {
        all_source_by_section.entry(&function.section).or_default().push(function);
    }
    for functions in all_source_by_section.values_mut() {
        functions.sort_by_key(|item| address(&item.address));
    }
    let mut result = Vec::new();
    for ((unit, section), source) in source_by_unit {
        if source.len() < 3 || source.iter().any(|item| !item.extent_known) {
            continue;
        }
        let (before, caller, tail) =
            (source[source.len() - 3], source[source.len() - 2], source[source.len() - 1]);
        if !adjacent(&before.end, &caller.address)
            || !adjacent(&caller.end, &tail.address)
            || caller.weak
            || tail.weak
            || tail.callers.len() != 1
            || tail.callers[0].section != section
            || tail.callers[0].address != caller.address
            || source_functions.iter().filter(|item| item.name == tail.name).count() != 1
            || attributions.iter().any(|item| {
                item.source.unit == unit
                    && item.source.section == section
                    && item.source.address == tail.address
            })
        {
            continue;
        }
        let Some(source_next) = all_source_by_section
            .get(section)
            .and_then(|functions| functions.iter().find(|item| item.address == tail.end))
        else {
            continue;
        };
        if source_next.unit == unit {
            continue;
        }
        let (Some(before_attr), Some(caller_attr)) = (
            attributions
                .iter()
                .find(|item| item.source.unit == unit && item.source.address == before.address),
            attributions
                .iter()
                .find(|item| item.source.unit == unit && item.source.address == caller.address),
        ) else {
            continue;
        };
        if [before_attr, caller_attr].iter().any(|item| {
            item.source.module != "main"
                || item.target.module != "main"
                || !item.independent
                || !item.binary_supported
                || item.ambiguous
                || item.source_weak
                || item.target_weak
                || item.target.section != section
        }) {
            continue;
        }
        let Some(target) = target_by_section.get(section) else { continue };
        let Some(position) =
            target.iter().position(|item| item.address == caller_attr.target.address)
        else {
            continue;
        };
        let (Some(previous), Some(target_caller), Some(target_tail), Some(next)) = (
            position.checked_sub(1).and_then(|index| target.get(index)),
            target.get(position),
            target.get(position + 1),
            target.get(position + 2),
        ) else {
            continue;
        };
        if previous.address != before_attr.target.address
            || previous.current_owner.as_deref() != Some(unit)
            || previous.owner_autogenerated
            || !previous.extent_known
            || !target_caller.extent_known
            || target_caller.current_owner.as_deref().is_some_and(|owner| owner != unit)
            || !target_tail.extent_known
            || target_tail.weak
            || target_tail.current_owner.is_some()
            || target_tail.owner_autogenerated
            || target_tail.callers.len() != 1
            || target_tail.callers[0].section != section
            || target_tail.callers[0].address != target_caller.address
            || target_tail.normalized_body_sha256.as_deref().is_none_or(|hash| {
                target_functions
                    .iter()
                    .filter(|item| item.normalized_body_sha256.as_deref() == Some(hash))
                    .count()
                    != 1
            })
            || !adjacent(&previous.end, &target_caller.address)
            || !adjacent(&target_caller.end, &target_tail.address)
            || !adjacent(&target_tail.end, &next.address)
            || next.current_owner.as_deref() == Some(unit)
            || attributions.iter().any(|item| {
                item.target.section == section && item.target.address == target_tail.address
            })
        {
            continue;
        }
        let records: Vec<_> = evidence.objects.iter().filter(|item| item.unit == unit).collect();
        let [record] = records.as_slice() else { continue };
        if record.status != ObjectStatus::Available
            || record.build_freshness != BuildFreshness::Clean
        {
            continue;
        }
        let Some(object_sha256) = record.sha256.as_deref() else { continue };
        let compiled_named: Vec<_> = evidence
            .objects
            .iter()
            .flat_map(|item| &item.functions)
            .filter(|item| item.name == tail.name)
            .collect();
        if compiled_named.len() != 1 {
            continue;
        }
        let compiled_caller: Vec<_> = record
            .functions
            .iter()
            .filter(|item| {
                item.name == caller.name
                    && item.section == section
                    && caller.normalized_body_sha256.is_some()
                    && item.normalized_body_sha256 == caller.normalized_body_sha256
                    && extent(&item.address, &item.end) == extent(&caller.address, &caller.end)
            })
            .collect();
        let compiled_tail: Vec<_> = record
            .functions
            .iter()
            .filter(|item| {
                item.name == tail.name
                    && item.section == section
                    && !item.weak
                    && tail.normalized_body_sha256.is_some()
                    && item.normalized_body_sha256 == tail.normalized_body_sha256
                    && extent(&item.address, &item.end) == extent(&tail.address, &tail.end)
            })
            .collect();
        let ([compiled_caller], [compiled_tail]) =
            (compiled_caller.as_slice(), compiled_tail.as_slice())
        else {
            continue;
        };
        let Some(tail_address) = address(&compiled_tail.address) else { continue };
        if !compiled_caller.references.iter().any(|reference| {
            reference.kind == "PpcRel24"
                && reference.target == tail.name
                && reference.target_section.as_deref() == Some(section)
                && reference.target_address == u64::from(tail_address)
                && reference.addend == 0
        }) {
            continue;
        }
        result.push(CompiledCallLinkedTail {
            unit: unit.into(),
            section: section.into(),
            source_caller: caller.address.clone(),
            source_tail: tail.address.clone(),
            target_caller: target_caller.address.clone(),
            target_tail: target_tail.address.clone(),
            predecessor_attribution_id: before_attr.id.clone(),
            caller_attribution_id: caller_attr.id.clone(),
            object_sha256: object_sha256.into(),
        });
    }
    result
}

/// Derive a bounded suffix without using an oracle split or unit-specific
/// names. A clean object and a bridge for one function do not suffice: every
/// terminal function must bridge, one must be non-weak, and both sides of the
/// retail gap must have independently checkable placement facts.
pub fn compiled_terminal_suffixes(
    evidence: &ObjectEvidence,
    source_functions: &[SourceFunctionObservation],
    target_functions: &[TargetFunctionObservation],
    attributions: &[FunctionAttribution],
) -> Vec<CompiledTerminalSuffix> {
    if evidence.target_references.is_empty() || evidence.source_bridges.is_empty() {
        return Vec::new();
    }
    let mut objects = BTreeMap::new();
    let mut duplicate = BTreeSet::new();
    for record in &evidence.objects {
        if objects.insert(record.unit.as_str(), record).is_some() {
            duplicate.insert(record.unit.as_str());
        }
    }
    for unit in duplicate {
        objects.remove(unit);
    }
    let mut sources: BTreeMap<(&str, &str), Vec<_>> = BTreeMap::new();
    for source in source_functions.iter().filter(|item| item.module == "main" && item.extent_known)
    {
        sources.entry((&source.unit, &source.section)).or_default().push(source);
    }
    for members in sources.values_mut() {
        members.sort_by_key(|item| address(&item.address));
    }
    let mut targets: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for target in target_functions.iter().filter(|item| item.module == "main" && item.extent_known)
    {
        targets.entry(&target.section).or_default().push(target);
    }
    for members in targets.values_mut() {
        members.sort_by_key(|item| address(&item.address));
    }
    let attributed: BTreeMap<_, _> = attributions
        .iter()
        .filter(|item| item.target.module == "main")
        .map(|item| ((item.target.section.as_str(), item.target.address.as_str()), item))
        .collect();
    let bridges: BTreeMap<_, _> = evidence
        .source_bridges
        .iter()
        .map(|item| {
            ((item.unit.as_str(), item.section.as_str(), item.target_address.as_str()), item)
        })
        .collect();
    let mut result = Vec::new();
    for ((unit, section), source) in sources {
        let (Some(record), Some(target)) = (objects.get(unit), targets.get(section)) else {
            continue;
        };
        if record.status != ObjectStatus::Available
            || record.build_freshness != BuildFreshness::Clean
            || record.sha256.is_none()
            || source.len() < MIN_COMPILED_TERMINAL_MEMBERS + 1
            || source_functions.iter().any(|item| {
                item.module == "main"
                    && item.unit == unit
                    && item.section == section
                    && !item.extent_known
            })
        {
            continue;
        }
        let mut compiled: Vec<_> =
            record.functions.iter().filter(|item| item.section == section).collect();
        compiled.sort_by_key(|item| address(&item.address));
        if compiled.len() < MIN_COMPILED_TERMINAL_MEMBERS + 1 {
            continue;
        }
        for first in evidence
            .source_bridges
            .iter()
            .filter(|bridge| bridge.unit == unit && bridge.section == section)
            .filter_map(|bridge| {
                target.iter().position(|item| item.address == bridge.target_address)
            })
            .filter(|&position| {
                position > 0 && position + MIN_COMPILED_TERMINAL_MEMBERS < target.len()
            })
        {
            let predecessor = target[first - 1];
            if predecessor.current_owner.as_deref() != Some(unit) {
                continue;
            }
            let Some(before) = attributed.get(&(section, predecessor.address.as_str())).copied()
            else {
                continue;
            };
            if before.source.unit != unit
                || before.ambiguous
                || !before.binary_supported
                || before.source_weak
                || before.target_weak
            {
                continue;
            }
            // The next independently identified foreign function is a right
            // bound, not an assertion about its retail split owner.
            let Some(last) = ((first + MIN_COMPILED_TERMINAL_MEMBERS)
                ..=(first + MAX_COMPILED_TERMINAL_MEMBERS).min(target.len() - 1))
                .find(|&last| {
                    let item = target[last];
                    attributed.get(&(section, item.address.as_str())).is_some_and(|next| {
                        next.independent
                            && next.binary_supported
                            && !next.ambiguous
                            && !next.source_weak
                            && !next.target_weak
                            && next.source.unit != unit
                    })
                })
            else {
                continue;
            };
            let count = last - first;
            if source.len() < count + 1 || compiled.len() < count + 1 {
                continue;
            }
            let source_run = &source[source.len() - count..];
            let compiled_run = &compiled[compiled.len() - count..];
            let target_run = &target[first..last];
            let source_before = source[source.len() - count - 1];
            let compiled_before = compiled[compiled.len() - count - 1];
            if before.source.address != source_before.address
                || target_functions.iter().any(|item| {
                    item.module == "main"
                        && item.section == section
                        && !item.extent_known
                        && address(&item.address).is_some_and(|start| {
                            address(&predecessor.address).is_some_and(|left| left <= start)
                                && address(&target[last].address)
                                    .is_some_and(|right| start <= right)
                        })
                })
                || compiled_member(record, source_before, predecessor, evidence)
                    .is_none_or(|member| member.address != compiled_before.address)
                || !adjacent(&predecessor.end, &target_run[0].address)
                || !adjacent(&target[last - 1].end, &target[last].address)
                || !adjacent(&source_before.end, &source_run[0].address)
                || !adjacent(&compiled_before.end, &compiled_run[0].address)
                || source_run.windows(2).any(|pair| !adjacent(&pair[0].end, &pair[1].address))
                || compiled_run.windows(2).any(|pair| !adjacent(&pair[0].end, &pair[1].address))
                || target_run.windows(2).any(|pair| !adjacent(&pair[0].end, &pair[1].address))
                || target_run.iter().any(|item| item.current_owner.is_some())
            {
                continue;
            }
            let mut nonweak = 0;
            let mut matched = true;
            for ((s, c), t) in source_run.iter().zip(compiled_run).zip(target_run) {
                let Some(bridge) = bridges.get(&(unit, section, t.address.as_str())).copied()
                else {
                    matched = false;
                    break;
                };
                if bridge.source_address != s.address
                    || bridge.source_name != s.name
                    || bridge.compiled_address != c.address
                    || bridge.object_sha256 != record.sha256.as_deref().unwrap_or_default()
                    || bridge.current_owner.is_some()
                    || c.name != s.name
                    || bridge.source_weak != s.weak
                    || bridge.compiled_weak != c.weak
                    || bridge.target_weak != t.weak
                    || c.normalized_body_sha256.as_deref()
                        != Some(bridge.normalized_body_sha256.as_str())
                    || t.normalized_body_sha256.as_deref()
                        != Some(bridge.normalized_body_sha256.as_str())
                    || extent(&c.address, &c.end) != extent(&t.address, &t.end)
                    || !sites_match(c, t, evidence)
                {
                    matched = false;
                    break;
                }
                nonweak += u32::from(!c.weak && !bridge.source_weak && !bridge.target_weak);
            }
            if !matched || nonweak == 0 {
                continue;
            }
            // The source's following unit must agree with the independently
            // identified foreign bound, even when its first function moved.
            let Some(next_source) = source_functions
                .iter()
                .filter(|item| item.module == "main" && item.section == section)
                .filter(|item| {
                    address(&item.address).is_some_and(|addr| {
                        addr > address(&source.last().unwrap().address).unwrap_or(u32::MAX)
                    })
                })
                .min_by_key(|item| address(&item.address))
            else {
                continue;
            };
            if !next_source.extent_known
                || !adjacent(&source.last().unwrap().end, &next_source.address)
                || next_source.unit
                    != attributed[&(section, target[last].address.as_str())].source.unit
            {
                continue;
            }
            result.push(CompiledTerminalSuffix {
                unit: unit.to_string(),
                section: section.to_string(),
                source_addresses: source_run.iter().map(|item| item.address.clone()).collect(),
                target_addresses: target_run.iter().map(|item| item.address.clone()).collect(),
                predecessor_attribution_id: before.id.clone(),
                following_attribution_id: attributed[&(section, target[last].address.as_str())]
                    .id
                    .clone(),
                object_sha256: record.sha256.clone().expect("checked above"),
            });
            break;
        }
    }
    result.sort_by(|a, b| {
        (&a.section, &a.target_addresses, &a.unit).cmp(&(&b.section, &b.target_addresses, &b.unit))
    });
    result
}

/// Derive cross-unit boundary hypotheses from the complete, canonical report.
/// No unit or address is special-cased, and the result grants no emitted owner.
pub fn compiled_boundaries(
    evidence: &ObjectEvidence,
    source_functions: &[SourceFunctionObservation],
    target_functions: &[TargetFunctionObservation],
    attributions: &[FunctionAttribution],
) -> Vec<CompiledBoundary> {
    if evidence.target_references.is_empty() || evidence.source_bridges.is_empty() {
        return Vec::new();
    }
    let mut records = BTreeMap::new();
    let mut duplicate_units = BTreeSet::new();
    let mut seen_units = BTreeSet::new();
    for record in &evidence.objects {
        if !seen_units.insert(record.unit.as_str()) {
            duplicate_units.insert(record.unit.as_str());
            continue;
        }
        if record.status != ObjectStatus::Available
            || record.build_freshness != BuildFreshness::Clean
            || record.sha256.is_none()
        {
            continue;
        }
        records.insert(record.unit.as_str(), record);
    }
    for unit in duplicate_units {
        records.remove(unit);
    }

    let mut sources: Vec<_> =
        source_functions.iter().filter(|item| item.module == "main" && item.extent_known).collect();
    sources.sort_by_key(|item| (&item.section, &item.address));
    let source_at: BTreeMap<_, _> = sources
        .iter()
        .enumerate()
        .map(|(position, item)| ((item.section.as_str(), item.address.as_str()), position))
        .collect();
    let mut targets: Vec<_> =
        target_functions.iter().filter(|item| item.module == "main" && item.extent_known).collect();
    targets.sort_by_key(|item| (&item.section, &item.address));
    let attributed: BTreeMap<_, _> = attributions
        .iter()
        .filter(|item| item.target.module == "main")
        .map(|item| ((item.target.section.as_str(), item.target.address.as_str()), item))
        .collect();
    let bridges: BTreeMap<_, _> = evidence
        .source_bridges
        .iter()
        .map(|item| ((item.section.as_str(), item.target_address.as_str()), item))
        .collect();
    let mut source_hashes = BTreeMap::new();
    let mut target_hashes = BTreeMap::new();
    let mut compiled_hashes = BTreeMap::new();
    for item in &sources {
        if let Some(hash) = item.normalized_body_sha256.as_deref() {
            *source_hashes.entry((item.section.as_str(), hash)).or_insert(0_usize) += 1;
        }
    }
    for item in &targets {
        if let Some(hash) = item.normalized_body_sha256.as_deref() {
            *target_hashes.entry((item.section.as_str(), hash)).or_insert(0_usize) += 1;
        }
    }
    for record in &evidence.objects {
        for item in &record.functions {
            if let Some(hash) = item.normalized_body_sha256.as_deref() {
                *compiled_hashes.entry((item.section.as_str(), hash)).or_insert(0_usize) += 1;
            }
        }
    }

    let mut result = Vec::new();
    for window in targets.windows(6) {
        if window.iter().any(|item| item.section != window[0].section)
            || window.windows(2).any(|pair| !adjacent(&pair[0].end, &pair[1].address))
        {
            continue;
        }
        let section = window[0].section.as_str();
        let get =
            |index: usize| attributed.get(&(section, window[index].address.as_str())).copied();
        let (Some(a0), Some(a1), Some(a2), Some(b0), Some(b2)) =
            (get(0), get(1), get(2), get(3), get(5))
        else {
            continue;
        };
        let Some(bridge) = bridges.get(&(section, window[4].address.as_str())).copied() else {
            continue;
        };
        let left = a2.source.unit.as_str();
        let right = b0.source.unit.as_str();
        if left == right
            || a0.source.unit != left
            || a1.source.unit != left
            || bridge.unit != right
            || b2.source.unit != right
            || [a0, a1, a2, b0, b2].iter().any(|item| item.ambiguous)
            || [a2, b0, b2].iter().any(|item| !item.binary_supported)
            || a0.source_weak
            || a0.target_weak
            || b0.source_weak
            || b0.target_weak
            || !b2.independent
            || b2.source_weak
            || b2.target_weak
            || b2.template_instantiation
            || bridge.source_weak
            || bridge.compiled_weak
            || bridge.target_weak
            || window[0].current_owner.as_deref() != Some(left)
            || window[1].current_owner.as_deref() != Some(left)
            || window[5].current_owner.as_deref() != Some(right)
            || window[2..5].iter().any(|item| item.current_owner.is_some())
            || !a2.source_weak
        {
            continue;
        }
        let source_addresses = [
            &a0.source.address,
            &a1.source.address,
            &a2.source.address,
            &b0.source.address,
            &bridge.source_address,
            &b2.source.address,
        ];
        let Some(&first) = source_at.get(&(section, source_addresses[0].as_str())) else {
            continue;
        };
        if first + 6 > sources.len()
            || (0..6).any(|index| {
                sources[first + index].section != section
                    || sources[first + index].address != *source_addresses[index]
                    || sources[first + index].unit != if index <= 2 { left } else { right }
                    || (index > 0
                        && !adjacent(
                            &sources[first + index - 1].end,
                            &sources[first + index].address,
                        ))
            })
            || sources[first + 4].name != bridge.source_name
        {
            continue;
        }
        let (Some(left_record), Some(right_record)) = (records.get(left), records.get(right))
        else {
            continue;
        };
        if bridge.object_sha256 != right_record.sha256.as_deref().unwrap_or_default() {
            continue;
        }
        let left_members: Option<Vec<_>> = (0..3)
            .map(|index| {
                compiled_member(left_record, sources[first + index], window[index], evidence)
            })
            .collect();
        let right_members: Option<Vec<_>> = (3..6)
            .map(|index| {
                compiled_member(right_record, sources[first + index], window[index], evidence)
            })
            .collect();
        let (Some(left_members), Some(right_members)) = (left_members, right_members) else {
            continue;
        };
        if left_members.windows(2).any(|pair| {
            address(&pair[0].address)
                .zip(address(&pair[1].address))
                .is_none_or(|(left, right)| left >= right)
        }) || right_members.windows(2).any(|pair| {
            address(&pair[0].address)
                .zip(address(&pair[1].address))
                .is_none_or(|(left, right)| left >= right)
        }) || right_members[1].address != bridge.compiled_address
            || left_members[0].weak
            || right_members[0].weak
            || right_members[2].weak
        {
            continue;
        }
        // At the disputed seam a repeated body is never exclusion evidence.
        if (2..4).any(|index| {
            let Some(hash) = window[index].normalized_body_sha256.as_deref() else { return true };
            source_hashes.get(&(section, hash)) != Some(&1)
                || target_hashes.get(&(section, hash)) != Some(&1)
                || compiled_hashes.get(&(section, hash)) != Some(&1)
        }) {
            continue;
        }
        result.push(CompiledBoundary {
            section: section.to_string(),
            left_unit: left.to_string(),
            right_unit: right.to_string(),
            source_addresses: source_addresses.map(|item| item.clone()),
            target_addresses: std::array::from_fn(|index| window[index].address.clone()),
            left_object_sha256: left_record.sha256.clone().expect("checked above"),
            right_object_sha256: right_record.sha256.clone().expect("checked above"),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{
        matching::{MatchMethod, MatchTier},
        object_evidence::{CompiledSourceBridge, ScanStatus, TargetFunctionReferences},
        ownership::{AttributionOrigin, FunctionLocation, SourceFunction},
    };

    fn hex(value: u32) -> String { format!("0x{value:08X}") }
    fn body(index: usize) -> String { format!("{:x}", index + 1).repeat(64) }

    fn fixture() -> (
        ObjectEvidence,
        Vec<SourceFunctionObservation>,
        Vec<TargetFunctionObservation>,
        Vec<FunctionAttribution>,
    ) {
        let mut evidence = ObjectEvidence::unavailable(ScanStatus::Scanned);
        let mut sources = Vec::new();
        let mut targets = Vec::new();
        let mut attributions = Vec::new();
        for index in 0..6 {
            let unit = if index <= 2 { "A.cpp" } else { "B.cpp" };
            let name = format!("member_{index}");
            let source = hex(0x2000 + index as u32 * 0x10);
            let source_end = hex(0x2010 + index as u32 * 0x10);
            let target = hex(0x1000 + index as u32 * 0x10);
            let target_end = hex(0x1010 + index as u32 * 0x10);
            sources.push(SourceFunctionObservation {
                name: name.clone(),
                unit: unit.into(),
                module: "main".into(),
                section: ".text".into(),
                address: source.clone(),
                end: source_end.clone(),
                extent_known: true,
                normalized_body_sha256: Some(if index == 4 { "f".repeat(64) } else { body(index) }),
                weak: index == 2,
                callers: Vec::new(),
            });
            targets.push(TargetFunctionObservation {
                name: name.clone(),
                module: "main".into(),
                section: ".text".into(),
                address: target.clone(),
                end: target_end.clone(),
                extent_known: true,
                current_owner: if index <= 1 || index == 5 { Some(unit.into()) } else { None },
                owner_autogenerated: false,
                callers: Vec::new(),
                normalized_body_sha256: Some(body(index)),
                weak: false,
            });
            evidence.target_references.push(TargetFunctionReferences {
                section: ".text".into(),
                address: target.clone(),
                end: target_end.clone(),
                references: Vec::new(),
            });
            if index == 4 {
                continue;
            }
            attributions.push(FunctionAttribution {
                id: format!("pair_{index}"),
                target: FunctionLocation {
                    module: "main".into(),
                    section: ".text".into(),
                    address: target,
                    end: target_end,
                },
                source: SourceFunction {
                    name,
                    unit: unit.into(),
                    module: "main".into(),
                    section: ".text".into(),
                    address: source,
                    end: source_end,
                },
                method: MatchMethod::ExactHash,
                tier: MatchTier::Confident,
                confidence: 1.0,
                evidence_count: 1,
                origin: AttributionOrigin::NormalizedBody,
                distinctive_body: true,
                unique_exact_body: true,
                binary_supported: true,
                independent: index == 5,
                ambiguous: false,
                competing: None,
                source_weak: index == 2,
                target_weak: false,
                template_instantiation: false,
                current_target_owner: if index <= 1 || index == 5 {
                    Some(unit.into())
                } else {
                    None
                },
                evidence: Vec::new(),
            });
        }
        for (unit, object_hash, indexes) in
            [("A.cpp", 'a', vec![0, 1, 2]), ("B.cpp", 'b', vec![3, 4, 5])]
        {
            evidence.objects.push(ObjectRecord {
                unit: unit.into(),
                base_path: format!("build/PAL/src/{unit}.o"),
                status: ObjectStatus::Available,
                sha256: Some(object_hash.to_string().repeat(64)),
                compiler: None,
                c_flags: None,
                c_flags_sha256: None,
                build_freshness: BuildFreshness::Clean,
                functions: indexes
                    .into_iter()
                    .map(|index| CompiledFunction {
                        name: format!("member_{index}"),
                        section: ".text".into(),
                        address: hex(index as u32 * 0x10),
                        end: hex((index as u32 + 1) * 0x10),
                        normalized_body_sha256: Some(body(index)),
                        weak: index == 2,
                        references: Vec::new(),
                    })
                    .collect(),
            });
        }
        evidence.source_bridges.push(CompiledSourceBridge {
            unit: "B.cpp".into(),
            source_name: "member_4".into(),
            source_address: hex(0x2040),
            compiled_address: hex(0x40),
            target_address: hex(0x1040),
            section: ".text".into(),
            current_owner: None,
            owner_autogenerated: false,
            object_sha256: "b".repeat(64),
            normalized_body_sha256: body(4),
            source_weak: false,
            compiled_weak: false,
            target_weak: false,
            inventory_complete: false,
        });
        (evidence, sources, targets, attributions)
    }

    fn suffix_fixture() -> (
        ObjectEvidence,
        Vec<SourceFunctionObservation>,
        Vec<TargetFunctionObservation>,
        Vec<FunctionAttribution>,
    ) {
        let (mut evidence, mut sources, mut targets, mut attributions) = fixture();
        sources[3].unit = "A.cpp".into();
        for target in &mut targets[1..4] {
            target.current_owner = None;
        }
        let mut following = attributions.iter().find(|item| item.id == "pair_5").unwrap().clone();
        following.id = "following".into();
        following.target.address = targets[4].address.clone();
        following.target.end = targets[4].end.clone();
        following.source.address = sources[4].address.clone();
        following.source.end = sources[4].end.clone();
        following.source.name = sources[4].name.clone();
        following.current_target_owner = None;
        attributions.retain(|item| item.id == "pair_0");
        attributions.push(following);
        let moved = evidence.objects[1].functions.remove(0);
        evidence.objects[0].functions.push(moved);
        for index in 1..4 {
            evidence.source_bridges.push(CompiledSourceBridge {
                unit: "A.cpp".into(),
                source_name: sources[index].name.clone(),
                source_address: sources[index].address.clone(),
                compiled_address: hex(index as u32 * 0x10),
                target_address: targets[index].address.clone(),
                section: ".text".into(),
                current_owner: None,
                owner_autogenerated: false,
                object_sha256: "a".repeat(64),
                normalized_body_sha256: body(index),
                source_weak: sources[index].weak,
                compiled_weak: index == 2,
                target_weak: false,
                inventory_complete: false,
            });
        }
        (evidence, sources, targets, attributions)
    }

    #[test]
    fn terminal_suffix_requires_the_whole_clean_run_and_both_bounds() {
        let (evidence, sources, targets, attributions) = suffix_fixture();
        let found = compiled_terminal_suffixes(&evidence, &sources, &targets, &attributions);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target_addresses, vec![hex(0x1010), hex(0x1020), hex(0x1030)]);
        assert_eq!(found[0].predecessor_attribution_id, "pair_0");
        assert_eq!(found[0].following_attribution_id, "following");

        let mut partial = evidence.clone();
        partial.source_bridges.retain(|item| item.target_address != hex(0x1020));
        assert!(compiled_terminal_suffixes(&partial, &sources, &targets, &attributions).is_empty());
        let mut dirty = evidence.clone();
        dirty.objects[0].build_freshness = BuildFreshness::Dirty;
        assert!(compiled_terminal_suffixes(&dirty, &sources, &targets, &attributions).is_empty());
        let mut extra = evidence.clone();
        extra.objects[0].functions.push(CompiledFunction {
            name: "unmatched_tail".into(),
            section: ".text".into(),
            address: hex(0x40),
            end: hex(0x50),
            normalized_body_sha256: Some(body(6)),
            weak: false,
            references: Vec::new(),
        });
        assert!(compiled_terminal_suffixes(&extra, &sources, &targets, &attributions).is_empty());
        let mut held_elsewhere = targets.clone();
        held_elsewhere[2].current_owner = Some("B.cpp".into());
        assert!(
            compiled_terminal_suffixes(&evidence, &sources, &held_elsewhere, &attributions)
                .is_empty()
        );
        let mut unknown_extent = targets.clone();
        unknown_extent.push(TargetFunctionObservation {
            address: hex(0x1028),
            end: hex(0x1028),
            extent_known: false,
            ..targets[2].clone()
        });
        assert!(
            compiled_terminal_suffixes(&evidence, &sources, &unknown_extent, &attributions)
                .is_empty()
        );
        let mut forged = evidence.clone();
        forged
            .source_bridges
            .iter_mut()
            .find(|item| item.target_address == hex(0x1020))
            .unwrap()
            .normalized_body_sha256 = body(7);
        assert!(compiled_terminal_suffixes(&forged, &sources, &targets, &attributions).is_empty());
        let mut all_weak = evidence.clone();
        for function in all_weak.objects[0].functions.iter_mut().skip(1) {
            function.weak = true;
        }
        for bridge in all_weak.source_bridges.iter_mut().filter(|item| item.unit == "A.cpp") {
            bridge.compiled_weak = true;
        }
        assert!(
            compiled_terminal_suffixes(&all_weak, &sources, &targets, &attributions).is_empty()
        );
        let mut weak_bound = attributions.clone();
        weak_bound[1].independent = false;
        assert!(compiled_terminal_suffixes(&evidence, &sources, &targets, &weak_bound).is_empty());
    }

    #[test]
    fn ordered_two_unit_seam_needs_both_objects_and_an_independent_right_flank() {
        let (evidence, sources, targets, attributions) = fixture();
        assert_eq!(compiled_boundaries(&evidence, &sources, &targets, &attributions).len(), 1);

        let mut duplicate = evidence.clone();
        let mut stale = duplicate.objects[0].clone();
        stale.build_freshness = BuildFreshness::Dirty;
        duplicate.objects.push(stale);
        assert!(compiled_boundaries(&duplicate, &sources, &targets, &attributions).is_empty());

        let mut unanchored = attributions.clone();
        unanchored.last_mut().unwrap().independent = false;
        assert!(compiled_boundaries(&evidence, &sources, &targets, &unanchored).is_empty());

        let mut foreign = targets.clone();
        foreign[2].current_owner = Some("C.cpp".into());
        assert!(compiled_boundaries(&evidence, &sources, &foreign, &attributions).is_empty());

        let mut repeated = evidence.clone();
        let copy = repeated.objects[0].functions[2].clone();
        repeated.objects[1].functions.push(copy);
        assert!(compiled_boundaries(&repeated, &sources, &targets, &attributions).is_empty());

        let mut invalid_extent = evidence.clone();
        invalid_extent.objects[0].functions[2].end = hex(0x10);
        assert!(compiled_boundaries(&invalid_extent, &sources, &targets, &attributions).is_empty());
    }
}
