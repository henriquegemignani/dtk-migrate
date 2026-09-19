//! Typed witnesses for the non-code ranges proposed by the matcher.
//!
//! `splits.txt` syntax is a useful review format, but it loses the symbol and
//! relocation evidence behind a range. Discovery reads this record as well as
//! the text proposal and only offers a range when both identify it exactly.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use anyhow::{Result, bail};
use decomp_toolkit::obj::{ObjDataKind, ObjSection, ObjSectionKind, ObjSymbol, SymbolIndex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::{
    data_matching::DataMatch,
    matching::MatchTarget,
    object_evidence::target_image_digest,
    unit_matching::{UnitProposal, UnitTier, required_alignment},
};

pub const SCHEMA: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataEvidenceReference {
    pub schema: u32,
    pub sha256: String,
    pub file: String,
}

impl DataEvidenceReference {
    pub fn of(path: &Path, source: &str, target: &str) -> Result<Self> {
        let file = std::path::absolute(path)?;
        let bytes = std::fs::read(&file)?;
        let report: DataEvidenceReport = serde_json::from_slice(&bytes)?;
        report.validate(source, target)?;
        Ok(Self {
            schema: report.schema,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            file: file.to_string_lossy().into_owned(),
        })
    }

    pub fn load(&self, source: &str, target: &str) -> Result<DataEvidenceReport> {
        let bytes = std::fs::read(&self.file)?;
        if self.schema != SCHEMA || format!("{:x}", Sha256::digest(&bytes)) != self.sha256 {
            bail!("Data evidence reference is stale or uses an unsupported schema");
        }
        let report: DataEvidenceReport = serde_json::from_slice(&bytes)?;
        report.validate(source, target)?;
        Ok(report)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataEvidenceReport {
    pub schema: u32,
    pub source: String,
    pub target: String,
    pub source_image_sha256: String,
    pub target_image_sha256: String,
    pub ranges: Vec<DataRangeEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRangeEvidence {
    pub unit: String,
    pub section: String,
    pub start: u32,
    pub end: u32,
    pub tier: UnitTier,
    pub reasons: Vec<String>,
    pub required_alignment: u32,
    pub members: Vec<DataMemberEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataMemberEvidence {
    pub source_index: SymbolIndex,
    pub target_index: SymbolIndex,
    pub source_name: String,
    pub target_name: String,
    pub target_start: u32,
    pub target_end: u32,
    pub source_extent_known: bool,
    pub target_extent_known: bool,
    pub target_size_basis: DataSizeBasis,
    pub source_wholly_owned: bool,
    pub source_weak: bool,
    pub target_weak: bool,
    /// An explicit target symbol flag is positive evidence of common linkage.
    /// Its absence says nothing about ordinary versus common BSS.
    pub target_symbol_common: bool,
    /// The common allocation's linker alignment, taken from an existing
    /// target split or an explicit target symbol alignment. This differs from
    /// the section boundary alignment required to place a split.
    pub target_common_align: Option<u32>,
    /// Which target-side record supplied `target_common_align`.
    pub target_common_align_basis: Option<CommonAlignBasis>,
    pub reference_positions: u32,
    pub target_owner: Option<String>,
    /// This is known only when a target split already records it. In
    /// particular, `None` never means ordinary rather than common BSS.
    pub target_common: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataSizeBasis {
    FixedWidth,
    StringContent,
    ExistingSplit,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommonAlignBasis {
    TargetSplit,
    TargetSymbol,
}

/// dtk guesses unknown object sizes from the next symbol and then marks them
/// `size_known`. Only a size fixed by the target's own kind/content or an
/// existing exact split is a boundary witness for automatic discovery.
fn size_basis(symbol: &ObjSymbol, section: &ObjSection, split_exact: bool) -> DataSizeBasis {
    let width = match symbol.data_kind {
        ObjDataKind::Byte => Some(1),
        ObjDataKind::Byte2 | ObjDataKind::Short => Some(2),
        ObjDataKind::Byte4 | ObjDataKind::Float | ObjDataKind::Int => Some(4),
        ObjDataKind::Byte8 | ObjDataKind::Double => Some(8),
        _ => None,
    };
    if width == Some(symbol.size) {
        return DataSizeBasis::FixedWidth;
    }
    if matches!(symbol.data_kind, ObjDataKind::String | ObjDataKind::String16)
        && matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
        && section.symbol_data(symbol).is_ok_and(|bytes| match symbol.data_kind {
            ObjDataKind::String => bytes.strip_suffix(&[0]).is_some_and(|content| {
                !content.is_empty()
                    && content
                        .iter()
                        .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
            }),
            ObjDataKind::String16 => {
                let values: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                    .collect();
                bytes.len() % 2 == 0
                    && values.strip_suffix(&[0]).is_some_and(|content| {
                        !content.is_empty()
                            && content.iter().all(|&value| {
                                u8::try_from(value).is_ok_and(|byte| {
                                    byte.is_ascii_graphic() || byte.is_ascii_whitespace()
                                })
                            })
                    })
            }
            _ => false,
        })
    {
        return DataSizeBasis::StringContent;
    }
    if split_exact {
        return DataSizeBasis::ExistingSplit;
    }
    DataSizeBasis::Inferred
}

impl DataRangeEvidence {
    /// Target-side linker mode, only when every member agrees. A missing
    /// `common` symbol flag never establishes ordinary BSS on its own.
    pub fn common_mode(&self) -> Option<bool> {
        let mut mode = None;
        for member in &self.members {
            let current = if member.target_symbol_common {
                if member.target_common == Some(false) {
                    return None;
                }
                true
            } else {
                member.target_common?
            };
            if mode.is_some_and(|previous| previous != current) {
                return None;
            }
            mode = Some(current);
        }
        mode
    }

    pub fn common_alignment(&self) -> Option<u32> {
        if self.common_mode() != Some(true) {
            return None;
        }
        let mut align = 0u32;
        for member in &self.members {
            let supported = match member.target_common_align_basis {
                Some(CommonAlignBasis::TargetSplit) => member.target_common == Some(true),
                Some(CommonAlignBasis::TargetSymbol) => member.target_symbol_common,
                None => false,
            };
            let member_align = member.target_common_align?;
            if !supported || !member_align.is_power_of_two() {
                return None;
            }
            align = align.max(member_align);
        }
        (align > 0 && self.start % align == 0).then_some(align)
    }

    /// Attributes that can be justified by this target-side record. A new
    /// ordinary BSS range remains unannotated and is withheld by discovery.
    pub fn split_suffix(&self) -> String {
        if matches!(self.section.as_str(), ".bss" | ".sbss" | ".sbss2")
            && let Some(align) = self.common_alignment()
        {
            format!(" align:{align} common")
        } else {
            String::new()
        }
    }

    /// A complete, aligned, contiguous row of independently paired, sized
    /// symbols proves its own bytes even when the source unit has other data
    /// that the matcher could not place. The whole-unit tier is diagnostic;
    /// it is not the authority for this narrower range claim.
    pub fn eligible(&self) -> bool {
        if self.start >= self.end
            || self.members.is_empty()
            || self.required_alignment == 0
            || self.start % self.required_alignment != 0
            || self.end % self.required_alignment != 0
            || (self.members.iter().any(|member| member.target_symbol_common)
                && (!matches!(self.section.as_str(), ".bss" | ".sbss" | ".sbss2")
                    || self.common_alignment().is_none()))
        {
            return false;
        }
        let mut cursor = self.start;
        for member in &self.members {
            if member.target_start != cursor
                || member.target_end <= cursor
                || !member.source_extent_known
                || !member.target_extent_known
                || member.target_size_basis == DataSizeBasis::Inferred
                || !member.source_wholly_owned
                || member.source_weak
                || member.target_weak
                || (member.target_symbol_common && member.target_common == Some(false))
                || member.reference_positions == 0
                || member.target_owner.as_ref().is_some_and(|owner| owner != &self.unit)
            {
                return false;
            }
            cursor = member.target_end;
        }
        cursor == self.end
    }
}

impl DataEvidenceReport {
    pub fn build(
        source: &MatchTarget,
        target: &MatchTarget,
        data_matches: &[DataMatch],
        proposals: &[UnitProposal],
        source_version: &str,
        target_version: &str,
    ) -> Self {
        let paired: HashMap<SymbolIndex, &DataMatch> =
            data_matches.iter().map(|item| (item.target, item)).collect();
        let mut ranges = Vec::new();
        for proposal in proposals {
            let Some(section) = target.obj.sections.get(proposal.section) else { continue };
            if section.kind == ObjSectionKind::Code {
                continue;
            }
            let mut members = Vec::new();
            for &index in &proposal.members {
                let Some(pair) = paired.get(&index) else { break };
                let source_symbol = &source.obj.symbols[pair.source];
                let target_symbol = &target.obj.symbols[pair.target];
                let Some(source_address) = u32::try_from(source_symbol.address).ok() else { break };
                let Some(target_start) = u32::try_from(target_symbol.address).ok() else { break };
                let Some(target_end) = target_symbol
                    .address
                    .checked_add(target_symbol.size)
                    .and_then(|end| u32::try_from(end).ok())
                else {
                    break;
                };
                let source_wholly_owned = source_symbol.section.is_some_and(|section_index| {
                    source.obj.sections.get(section_index).is_some_and(|source_section| {
                        source_section.kind != ObjSectionKind::Code
                            && u64::from(source_address) >= source_section.address
                            && source_symbol.address.checked_add(source_symbol.size).is_some_and(
                                |end| {
                                    source_section
                                        .address
                                        .checked_add(source_section.size)
                                        .is_some_and(|section_end| end <= section_end)
                                },
                            )
                            && source_section.splits.for_address(source_address).is_some_and(
                                |(_, split)| {
                                    split.unit == proposal.unit
                                        && source_symbol
                                            .address
                                            .checked_add(source_symbol.size)
                                            .is_some_and(|end| end <= u64::from(split.end))
                                },
                            )
                    })
                });
                let target_split = section
                    .splits
                    .for_address(target_start)
                    .filter(|(_, split)| u64::from(target_end) <= u64::from(split.end));
                let target_common = target_split.map(|(_, split)| split.common);
                let (target_common_align, target_common_align_basis) =
                    if let Some(align) = target_split.and_then(|(_, split)| split.align) {
                        (Some(align), Some(CommonAlignBasis::TargetSplit))
                    } else if target_symbol.flags.is_common() {
                        (
                            target_symbol.align,
                            target_symbol.align.map(|_| CommonAlignBasis::TargetSymbol),
                        )
                    } else {
                        (None, None)
                    };
                let target_owner = target_split.map(|(_, split)| split.unit.clone());
                let split_exact = target_split.is_some_and(|(start, split)| {
                    start == target_start && split.end == target_end && split.unit == proposal.unit
                });
                members.push(DataMemberEvidence {
                    source_index: pair.source,
                    target_index: pair.target,
                    source_name: source_symbol.name.clone(),
                    target_name: target_symbol.name.clone(),
                    target_start,
                    target_end,
                    source_extent_known: source_symbol.size_known && source_symbol.size > 0,
                    target_extent_known: target_symbol.size_known
                        && target_symbol.size > 0
                        && target_symbol.section == Some(proposal.section)
                        && u64::from(target_start) >= section.address
                        && section
                            .address
                            .checked_add(section.size)
                            .is_some_and(|section_end| u64::from(target_end) <= section_end),
                    target_size_basis: size_basis(target_symbol, section, split_exact),
                    source_wholly_owned,
                    source_weak: source_symbol.flags.is_weak(),
                    target_weak: target_symbol.flags.is_weak(),
                    target_symbol_common: target_symbol.flags.is_common(),
                    target_common_align,
                    target_common_align_basis,
                    reference_positions: pair.evidence,
                    target_owner,
                    target_common,
                });
            }
            if members.len() != proposal.members.len() {
                continue;
            }
            ranges.push(DataRangeEvidence {
                unit: proposal.unit.clone(),
                section: section.name.clone(),
                start: proposal.start,
                end: proposal.end,
                tier: proposal.tier,
                reasons: proposal.reasons.iter().map(|reason| (*reason).to_string()).collect(),
                required_alignment: required_alignment(
                    target,
                    proposal.section,
                    proposal.start,
                    proposal.end,
                )
                .unwrap_or(0),
                members,
            });
        }
        Self {
            schema: SCHEMA,
            source: source_version.to_string(),
            target: target_version.to_string(),
            source_image_sha256: target_image_digest(source),
            target_image_sha256: target_image_digest(target),
            ranges,
        }
    }

    pub fn validate(&self, source: &str, target: &str) -> Result<()> {
        if self.schema != SCHEMA || self.source != source || self.target != target {
            bail!("Data evidence schema or version pair does not match this run");
        }
        if [&self.source_image_sha256, &self.target_image_sha256].iter().any(|digest| {
            digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            bail!("Data evidence lacks binary provenance");
        }
        let mut keys = BTreeSet::new();
        for range in &self.ranges {
            if !keys.insert((&range.unit, &range.section, range.start, range.end)) {
                bail!("Data evidence repeats a unit range");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocations, ObjSection, ObjSplit, ObjSplits,
        ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    };

    use super::*;

    fn target(name: &str, address: u32, owner: Option<&str>) -> MatchTarget {
        let mut splits = ObjSplits::default();
        if let Some(owner) = owner {
            splits.push(address, ObjSplit {
                unit: owner.into(),
                end: address + 8,
                align: Some(8),
                common: false,
                autogenerated: false,
                skip: false,
                rename: None,
            });
        }
        MatchTarget::new(
            name.into(),
            ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc,
                name.into(),
                vec![ObjSymbol {
                    name: format!("{name}_data"),
                    address: u64::from(address),
                    section: Some(0),
                    size: 8,
                    size_known: true,
                    kind: ObjSymbolKind::Object,
                    data_kind: ObjDataKind::Double,
                    ..Default::default()
                }],
                vec![ObjSection {
                    name: ".data".into(),
                    kind: ObjSectionKind::Data,
                    address: u64::from(address),
                    size: 8,
                    data: vec![0; 8],
                    align: 8,
                    elf_index: 0,
                    relocations: ObjRelocations::default(),
                    virtual_address: None,
                    file_offset: 0,
                    section_known: true,
                    splits,
                }],
            ),
        )
    }

    #[test]
    fn member_record_requires_sized_source_ownership_and_a_tiled_target_range() {
        let source = target("source", 0x1000, Some("unit.cpp"));
        let target_obj = target("target", 0x2000, None);
        let proposal = UnitProposal {
            unit: "unit.cpp".into(),
            section: 0,
            start: 0x2000,
            end: 0x2008,
            members: vec![0],
            tier: UnitTier::Confident,
            reasons: Vec::new(),
        };
        let report = DataEvidenceReport::build(
            &source,
            &target_obj,
            &[DataMatch { source: 0, target: 0, evidence: 2 }],
            std::slice::from_ref(&proposal),
            "NTSC",
            "PAL",
        );
        report.validate("NTSC", "PAL").unwrap();
        assert!(report.ranges[0].eligible());
        assert_eq!(report.ranges[0].members[0].target_size_basis, DataSizeBasis::FixedWidth);
        assert_eq!(report.ranges[0].members[0].reference_positions, 2);
        assert_eq!(report.ranges[0].members[0].target_common, None);

        let directory =
            tempfile::Builder::new().prefix("data-evidence-").tempdir_in("target").unwrap();
        let path = directory.path().join("witnesses.json");
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        let reference = DataEvidenceReference::of(&path, "NTSC", "PAL").unwrap();
        assert!(Path::new(&reference.file).is_absolute());
        assert!(reference.load("NTSC", "PAL").is_ok());
        assert!(reference.load("NTSC", "other").is_err());
        std::fs::write(&path, b"{}").unwrap();
        assert!(reference.load("NTSC", "PAL").is_err());

        let mut gap = report.ranges[0].clone();
        gap.end += 4;
        assert!(!gap.eligible());
        let mut tentative = report.ranges[0].clone();
        tentative.tier = UnitTier::Candidate;
        assert!(tentative.eligible(), "whole-unit incompleteness does not erase a symbol witness");
        tentative.required_alignment = 16;
        assert!(!tentative.eligible());

        let mut guessed_target = target("target", 0x2000, None);
        let mut guessed_symbol = guessed_target.obj.symbols[0].clone();
        guessed_symbol.data_kind = ObjDataKind::Unknown;
        guessed_target.obj.symbols.replace(0, guessed_symbol).unwrap();
        let guessed = DataEvidenceReport::build(
            &source,
            &guessed_target,
            &[DataMatch { source: 0, target: 0, evidence: 2 }],
            std::slice::from_ref(&proposal),
            "NTSC",
            "PAL",
        );
        assert_eq!(guessed.ranges[0].members[0].target_size_basis, DataSizeBasis::Inferred);
        assert!(!guessed.ranges[0].eligible());

        let mut string = target_obj.obj.symbols[0].clone();
        string.size = 4;
        string.data_kind = ObjDataKind::String;
        let mut data_section = target_obj.obj.sections[0].clone();
        data_section.data[..4].copy_from_slice(b"ABC\0");
        assert_eq!(size_basis(&string, &data_section, false), DataSizeBasis::StringContent);
        data_section.data[..4].copy_from_slice(b"ABCD");
        assert_eq!(size_basis(&string, &data_section, false), DataSizeBasis::Inferred);

        let unowned_source = target("source", 0x1000, Some("other.cpp"));
        let unowned = DataEvidenceReport::build(
            &unowned_source,
            &target_obj,
            &[DataMatch { source: 0, target: 0, evidence: 2 }],
            std::slice::from_ref(&proposal),
            "NTSC",
            "PAL",
        );
        assert!(!unowned.ranges[0].eligible());

        let mut common_target = target("target", 0x2000, None);
        let mut common_symbol = common_target.obj.symbols[0].clone();
        common_symbol.flags = ObjSymbolFlagSet(ObjSymbolFlags::Common.into());
        common_symbol.align = Some(4);
        common_target.obj.symbols.replace(0, common_symbol).unwrap();
        common_target.obj.sections[0].name = ".bss".into();
        common_target.obj.sections[0].kind = ObjSectionKind::Bss;
        let common = DataEvidenceReport::build(
            &source,
            &common_target,
            &[DataMatch { source: 0, target: 0, evidence: 2 }],
            std::slice::from_ref(&proposal),
            "NTSC",
            "PAL",
        );
        assert!(common.ranges[0].eligible());
        assert_eq!(common.ranges[0].common_mode(), Some(true));
        assert_eq!(common.ranges[0].required_alignment, 8);
        assert_eq!(common.ranges[0].common_alignment(), Some(4));
        assert_eq!(common.ranges[0].split_suffix(), " align:4 common");
        let mut missing_align = common.ranges[0].clone();
        missing_align.members[0].target_common_align = None;
        assert!(!missing_align.eligible());
        let mut false_provenance = common.ranges[0].clone();
        false_provenance.members[0].target_common_align_basis = Some(CommonAlignBasis::TargetSplit);
        assert!(!false_provenance.eligible());
        let mut wrong_section = common.ranges[0].clone();
        wrong_section.section = ".data".into();
        assert!(!wrong_section.eligible());
        let mut over_aligned = common.ranges[0].clone();
        over_aligned.start += 8;
        over_aligned.end += 8;
        over_aligned.members[0].target_start += 8;
        over_aligned.members[0].target_end += 8;
        over_aligned.members[0].target_common_align = Some(16);
        assert_eq!(over_aligned.common_alignment(), None);
        assert!(over_aligned.split_suffix().is_empty());
        let common_path = directory.path().join("common-proposals.txt");
        crate::matching::proposals::write_unit_proposals(
            &typed_path::Utf8NativePathBuf::from(common_path.to_string_lossy().into_owned()),
            &common_target,
            std::slice::from_ref(&proposal),
            &common,
        )
        .unwrap();
        assert!(
            std::fs::read_to_string(common_path).unwrap().contains("end:0x00002008 align:4 common")
        );

        let mut conflicting = target("target", 0x2000, Some("unit.cpp"));
        let mut conflicting_symbol = conflicting.obj.symbols[0].clone();
        conflicting_symbol.flags = ObjSymbolFlagSet(ObjSymbolFlags::Common.into());
        conflicting.obj.symbols.replace(0, conflicting_symbol).unwrap();
        conflicting.obj.sections[0].name = ".bss".into();
        conflicting.obj.sections[0].kind = ObjSectionKind::Bss;
        let conflict = DataEvidenceReport::build(
            &source,
            &conflicting,
            &[DataMatch { source: 0, target: 0, evidence: 2 }],
            &[proposal],
            "NTSC",
            "PAL",
        );
        // A target split saying ordinary and a target symbol saying common
        // cannot support an automatic ownership claim.
        assert!(!conflict.ranges[0].eligible());
    }
}
