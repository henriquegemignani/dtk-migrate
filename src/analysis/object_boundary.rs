//! A narrow, diagnostic boundary supported by ordered binary and compiled functions.
//!
//! A compiled definition alone does not identify the object that emitted a
//! retail function. This record instead keeps the entire two-unit arrangement:
//! two currently held functions of the left unit, its missing weak tail, two
//! functions of the right unit, and a held independent right anchor. Every
//! function occurs in the same unbroken order in the source and target
//! binaries. The compiled objects corroborate all six functions; a
//! source–compiled–target bridge supplies the changed fifth body.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    object_evidence::{
        BuildFreshness, CompiledFunction, ObjectEvidence, ObjectRecord, ObjectStatus,
    },
    ownership::{FunctionAttribution, SourceFunctionObservation, TargetFunctionObservation},
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
