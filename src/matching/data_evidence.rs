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
use decomp_toolkit::{
    obj::{
        ObjDataKind, ObjInfo, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolKind,
        SymbolIndex,
    },
    util::elf::process_elf,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use typed_path::Utf8NativePath;

use crate::{
    analysis::{
        data_matching::DataMatch,
        matching::MatchTarget,
        object_evidence::{
            BuildFreshness, ObjectEvidence, ObjectStatus, ScanStatus, target_image_digest,
        },
        unit_matching::{UnitProposal, UnitTier, required_alignment},
    },
    project::analyze::with_working_directory,
};

pub const SCHEMA: u32 = 4;

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
    /// A whole ordinary BSS allocation proved by a clean target-version
    /// object. It never makes an individual inferred symbol size exact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled_ordinary_bss: Option<CompiledOrdinaryBss>,
    /// A compiler-generated pointer table placed after a held data member by
    /// the same function in source, a clean target-version object and retail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled_jump_table: Option<CompiledJumpTable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledOrdinaryBss {
    pub object_sha256: String,
    pub compiled_size: u32,
    pub section_align: u32,
    pub symbols: Vec<CompiledDataSymbol>,
    pub next_owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledDataSymbol {
    pub name: String,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledJumpTable {
    pub object_sha256: String,
    pub compiled_size: u32,
    pub table_offset: u32,
    pub function_name: String,
    pub entry_offsets: Vec<u32>,
    pub next_unit: String,
    pub next_name: String,
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
    pub fn ordinary_bss_proven(&self) -> bool {
        self.compiled_ordinary_bss.as_ref().is_some_and(|proof| proof.valid(self))
    }

    pub fn jump_table_proven(&self) -> bool {
        self.compiled_jump_table.as_ref().is_some_and(|proof| proof.valid(self))
    }

    /// Linker mode when every member agrees or an entire ordinary allocation
    /// has a compiled-layout certificate. A missing `common` flag alone never
    /// establishes ordinary BSS.
    pub fn common_mode(&self) -> Option<bool> {
        if self.ordinary_bss_proven() {
            return Some(false);
        }
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
    /// ordinary BSS range stays unannotated; discovery admits it only with a
    /// separate complete compiled-allocation certificate.
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
                || (member.target_size_basis == DataSizeBasis::Inferred
                    && !self.ordinary_bss_proven()
                    && !self.jump_table_proven())
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

impl CompiledOrdinaryBss {
    fn valid(&self, range: &DataRangeEvidence) -> bool {
        if range.section != ".bss"
            || range.start >= range.end
            || range.required_alignment == 0
            || !range.required_alignment.is_power_of_two()
            || self.object_sha256.len() != 64
            || !self.object_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.next_owner.is_empty()
            || self.next_owner == range.unit
            || self.section_align == 0
            || !self.section_align.is_power_of_two()
            || range.start % self.section_align != 0
            || self.symbols.is_empty()
            || range.members.len() < 2
            || range.members.iter().any(|member| {
                member.target_common.is_some()
                    || member.target_symbol_common
                    || member.target_owner.is_some()
            })
        {
            return false;
        }
        let Some(aligned) = self
            .compiled_size
            .checked_add(range.required_alignment - 1)
            .map(|size| size & !(range.required_alignment - 1))
        else {
            return false;
        };
        if aligned != range.end - range.start
            || self.compiled_size == 0
            || self.compiled_size > aligned
        {
            return false;
        }
        let mut cursor = 0;
        for symbol in &self.symbols {
            if symbol.name.is_empty() || symbol.start != cursor || symbol.end <= cursor {
                return false;
            }
            cursor = symbol.end;
        }
        if cursor != self.compiled_size {
            return false;
        }
        let mut named_anchors = BTreeSet::new();
        let mut target_indices = BTreeSet::new();
        let mut source_indices = BTreeSet::new();
        for member in &range.members {
            if !source_indices.insert(member.source_index)
                || !target_indices.insert(member.target_index)
            {
                return false;
            }
            let Some(offset) = member.target_start.checked_sub(range.start) else { return false };
            if !self.symbols.iter().any(|symbol| symbol.start == offset) {
                return false;
            }
            if !member.target_name.starts_with('@') {
                if !self
                    .symbols
                    .iter()
                    .any(|symbol| symbol.start == offset && symbol.name == member.target_name)
                {
                    return false;
                }
                if !named_anchors.insert(&member.target_name) {
                    return false;
                }
            }
        }
        named_anchors.len() >= 2
    }
}

impl CompiledJumpTable {
    fn valid(&self, range: &DataRangeEvidence) -> bool {
        let [held, table] = range.members.as_slice() else { return false };
        range.section == ".data"
            && range.start < range.end
            && self.object_sha256.len() == 64
            && self.object_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            && self.compiled_size == range.end - range.start
            && held.target_end.checked_sub(range.start) == Some(self.table_offset)
            && held.target_start == range.start
            && held.target_owner.as_deref() == Some(range.unit.as_str())
            && held.target_size_basis == DataSizeBasis::ExistingSplit
            && table.target_start == held.target_end
            && table.target_end == range.end
            && table.target_owner.is_none()
            && table.target_size_basis == DataSizeBasis::Inferred
            && !held.source_weak
            && !held.target_weak
            && !table.source_weak
            && !table.target_weak
            && held.source_wholly_owned
            && table.source_wholly_owned
            && self.entry_offsets.len() >= 8
            && self.entry_offsets.iter().collect::<BTreeSet<_>>().len() >= 3
            && self.entry_offsets.len().checked_mul(4)
                == table.target_end.checked_sub(table.target_start).map(|size| size as usize)
            && !self.function_name.is_empty()
            && !self.next_unit.is_empty()
            && self.next_unit != range.unit
            && !self.next_name.is_empty()
    }
}

fn compiled_bss_witness(
    source: &MatchTarget,
    target: &MatchTarget,
    range: &DataRangeEvidence,
    object: &ObjInfo,
    object_sha256: &str,
) -> Option<CompiledOrdinaryBss> {
    let first = range.members.first()?;
    let last = range.members.last()?;
    let source_first = &source.obj.symbols[first.source_index];
    let source_last = &source.obj.symbols[last.source_index];
    let source_section = source.obj.sections.get(source_first.section?)?;
    if source_section.name != ".bss" || source_last.section != source_first.section {
        return None;
    }
    let source_start = u32::try_from(source_first.address).ok()?;
    let (split_start, source_split) = source_section.splits.for_address(source_start)?;
    if source_split.unit != range.unit
        || source_split.common
        || split_start != source_start
        || source_last.address.checked_add(source_last.size)? != u64::from(source_split.end)
    {
        return None;
    }
    let target_section_index = target.obj.symbols[first.target_index].section?;
    let target_section = target.obj.sections.get(target_section_index)?;
    if target_section.name != ".bss"
        || target_section.kind != ObjSectionKind::Bss
        || range.members.iter().any(|member| {
            target.obj.symbols[member.target_index].section != Some(target_section_index)
        })
    {
        return None;
    }
    let (next_start, next_split) = target_section.splits.for_address(range.end)?;
    if next_start != range.end
        || next_split.unit == range.unit
        || next_split.common
        || next_split.autogenerated
        || !target.obj.symbols.iter().any(|(_, symbol)| {
            symbol.section == Some(target_section_index)
                && symbol.kind == ObjSymbolKind::Object
                && symbol.address == u64::from(range.end)
                && !symbol.flags.is_common()
                && !symbol.flags.is_weak()
        })
    {
        return None;
    }
    let target_members: BTreeSet<_> =
        range.members.iter().map(|member| member.target_index).collect();
    if target.obj.symbols.iter().any(|(index, symbol)| {
        symbol.section == Some(target_section_index)
            && symbol.kind == ObjSymbolKind::Object
            && symbol.address >= u64::from(range.start)
            && symbol.address < u64::from(range.end)
            && !target_members.contains(&index)
    }) {
        return None;
    }
    let mut sections = object
        .sections
        .iter()
        .filter(|(_, section)| section.name == ".bss" && section.kind == ObjSectionKind::Bss);
    let (section_index, section) = sections.next()?;
    if sections.next().is_some() {
        return None;
    }
    let compiled_size = u32::try_from(section.size).ok()?;
    let section_align = u32::try_from(section.align).ok()?;
    let mut symbols: Vec<CompiledDataSymbol> = object
        .symbols
        .iter()
        .filter(|(_, symbol)| {
            symbol.section == Some(section_index) && symbol.kind == ObjSymbolKind::Object
        })
        .map(|(_, symbol)| {
            Some(CompiledDataSymbol {
                name: symbol.name.clone(),
                start: u32::try_from(symbol.address.checked_sub(section.address)?).ok()?,
                end: u32::try_from(
                    symbol.address.checked_sub(section.address)?.checked_add(symbol.size)?,
                )
                .ok()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    if object.symbols.iter().any(|(_, symbol)| {
        symbol.section == Some(section_index)
            && symbol.kind == ObjSymbolKind::Object
            && (!symbol.size_known
                || symbol.size == 0
                || symbol.flags.is_weak()
                || symbol.flags.is_common())
    }) {
        return None;
    }
    symbols.sort_by_key(|symbol| (symbol.start, symbol.end));
    let witness = CompiledOrdinaryBss {
        object_sha256: object_sha256.to_string(),
        compiled_size,
        section_align,
        symbols,
        next_owner: next_split.unit.clone(),
    };
    witness.valid(range).then_some(witness)
}

fn table_function_and_offsets(
    image: &MatchTarget,
    table_index: SymbolIndex,
    unit: &str,
) -> Option<(String, Vec<u32>)> {
    let table = &image.obj.symbols[table_index];
    let section = image.obj.sections.get(table.section?)?;
    let bytes = section.symbol_data(table).ok()?;
    if bytes.len() < 32 || bytes.len() % 4 != 0 {
        return None;
    }
    let referring: Vec<_> = image
        .graph
        .nodes
        .iter()
        .filter(|node| node.data_refs().any(|reference| reference.target_symbol == table_index))
        .collect();
    let [node] = referring.as_slice() else { return None };
    let function = &image.obj.symbols[node.symbol];
    let code = image.obj.sections.get(node.section)?;
    let start = u32::try_from(function.address).ok()?;
    let end = function.address.checked_add(function.size)?;
    let (_, split) = code.splits.for_address(start)?;
    if code.kind != ObjSectionKind::Code
        || function.kind != ObjSymbolKind::Function
        || !function.size_known
        || function.flags.is_weak()
        || split.unit != unit
        || split.autogenerated
        || end > u64::from(split.end)
    {
        return None;
    }
    let offsets = bytes
        .chunks_exact(4)
        .map(|chunk| {
            let pointer = u32::from_be_bytes(chunk.try_into().ok()?);
            let offset = pointer.checked_sub(start)?;
            (offset % 4 == 0 && u64::from(pointer) < end).then_some(offset)
        })
        .collect::<Option<Vec<_>>>()?;
    Some((function.name.clone(), offsets))
}

fn compiled_jump_table_witness(
    source: &MatchTarget,
    target: &MatchTarget,
    range: &DataRangeEvidence,
    data_matches: &[DataMatch],
    object: &ObjInfo,
    object_sha256: &str,
) -> Option<CompiledJumpTable> {
    let [held, table] = range.members.as_slice() else { return None };
    if range.section != ".data"
        || held.target_owner.as_deref() != Some(range.unit.as_str())
        || table.target_owner.is_some()
        || table.target_size_basis != DataSizeBasis::Inferred
        || held.target_end != table.target_start
        || held.target_start != range.start
        || table.target_end != range.end
    {
        return None;
    }
    let source_first = &source.obj.symbols[held.source_index];
    let source_table = &source.obj.symbols[table.source_index];
    let source_section_index = source_first.section?;
    let source_section = source.obj.sections.get(source_section_index)?;
    let source_start = u32::try_from(source_first.address).ok()?;
    let (source_split_start, source_split) = source_section.splits.for_address(source_start)?;
    if source_section.name != ".data"
        || source_section.kind != ObjSectionKind::Data
        || source_first.kind != ObjSymbolKind::Object
        || source_table.kind != ObjSymbolKind::Object
        || source_table.section != Some(source_section_index)
        || source_split_start != source_start
        || source_split.unit != range.unit
        || source_split.common
        || source_first.address.checked_add(source_first.size)? != source_table.address
        || source_table.address.checked_add(source_table.size)? != u64::from(source_split.end)
        || source.obj.symbols.iter().any(|(index, symbol)| {
            symbol.section == Some(source_section_index)
                && symbol.kind == ObjSymbolKind::Object
                && symbol.address >= source_first.address
                && symbol.address < u64::from(source_split.end)
                && index != held.source_index
                && index != table.source_index
        })
    {
        return None;
    }
    let target_section_index = target.obj.symbols[held.target_index].section?;
    let target_section = target.obj.sections.get(target_section_index)?;
    let (held_start, held_split) = target_section.splits.for_address(range.start)?;
    let (next_source_start, next_source_split) =
        source_section.splits.for_address(source_split.end)?;
    let next_source_symbols: Vec<_> = source
        .obj
        .symbols
        .iter()
        .filter(|(_, symbol)| {
            symbol.section == Some(source_section_index)
                && symbol.kind == ObjSymbolKind::Object
                && symbol.address == u64::from(source_split.end)
                && symbol.size_known
                && symbol.size > 0
                && !symbol.flags.is_weak()
        })
        .collect();
    let next_target_symbols: Vec<_> = target
        .obj
        .symbols
        .iter()
        .filter(|(_, symbol)| {
            symbol.section == Some(target_section_index)
                && symbol.kind == ObjSymbolKind::Object
                && symbol.address == u64::from(range.end)
                && symbol.size_known
                && symbol.size > 0
                && !symbol.flags.is_weak()
        })
        .collect();
    let ([(next_source_index, next_source)], [(next_target_index, next_target)]) =
        (next_source_symbols.as_slice(), next_target_symbols.as_slice())
    else {
        return None;
    };
    if target_section.name != ".data"
        || target_section.kind != ObjSectionKind::Data
        || target.obj.symbols[table.target_index].section != Some(target_section_index)
        || held_start != range.start
        || held_split.end != held.target_end
        || held_split.unit != range.unit
        || held_split.common
        || next_source_start != source_split.end
        || next_source_split.unit == range.unit
        || next_source_split.autogenerated
        || next_source.name != next_target.name
        || !data_matches.iter().any(|pair| {
            pair.source == *next_source_index
                && pair.target == *next_target_index
                && pair.evidence >= 2
        })
        || target_section
            .splits
            .for_address(range.end)
            .is_some_and(|(_, split)| split.unit == range.unit)
        || target.obj.symbols.iter().any(|(index, symbol)| {
            symbol.section == Some(target_section_index)
                && symbol.kind == ObjSymbolKind::Object
                && symbol.address >= u64::from(range.start)
                && symbol.address < u64::from(range.end)
                && index != held.target_index
                && index != table.target_index
        })
    {
        return None;
    }
    let (source_function, source_offsets) =
        table_function_and_offsets(source, table.source_index, &range.unit)?;
    let (target_function, target_offsets) =
        table_function_and_offsets(target, table.target_index, &range.unit)?;
    if source_function != target_function
        || source_offsets != target_offsets
        || source_offsets.iter().collect::<BTreeSet<_>>().len() < 3
    {
        return None;
    }
    let mut sections = object
        .sections
        .iter()
        .filter(|(_, section)| section.name == ".data" && section.kind == ObjSectionKind::Data);
    let (section_index, section) = sections.next()?;
    if sections.next().is_some() || section.size != u64::from(range.end - range.start) {
        return None;
    }
    let mut symbols: Vec<_> = object
        .symbols
        .iter()
        .filter(|(_, symbol)| {
            symbol.section == Some(section_index) && symbol.kind == ObjSymbolKind::Object
        })
        .collect();
    symbols.sort_by_key(|(_, symbol)| symbol.address);
    let [(_, compiled_held), (_, compiled_table)] = symbols.as_slice() else { return None };
    let table_start = compiled_table.address.checked_sub(section.address)?;
    if compiled_held.name != source_first.name
        || compiled_held.name != target.obj.symbols[held.target_index].name
        || compiled_held.address != section.address
        || compiled_held.size != u64::from(held.target_end - held.target_start)
        || table_start != compiled_held.size
        || compiled_table.size != u64::from(table.target_end - table.target_start)
        || compiled_table.address.checked_add(compiled_table.size)?
            != section.address.checked_add(section.size)?
        || [compiled_held, compiled_table]
            .iter()
            .any(|symbol| !symbol.size_known || symbol.flags.is_weak() || symbol.flags.is_common())
    {
        return None;
    }
    let compiled_functions: Vec<_> = object
        .symbols
        .iter()
        .filter(|(_, symbol)| {
            symbol.kind == ObjSymbolKind::Function
                && symbol.name == source_function
                && !symbol.flags.is_weak()
                && symbol.size_known
        })
        .collect();
    let [(function_index, compiled_function)] = compiled_functions.as_slice() else {
        return None;
    };
    let compiled_start = u32::try_from(compiled_table.address).ok()?;
    let compiled_end =
        u32::try_from(compiled_table.address.checked_add(compiled_table.size)?).ok()?;
    if section.relocations.range(compiled_start..compiled_end).count() != source_offsets.len() {
        return None;
    }
    for (index, &offset) in source_offsets.iter().enumerate() {
        let address = compiled_start.checked_add(u32::try_from(index.checked_mul(4)?).ok()?)?;
        let relocation = section.relocations.at(address)?;
        if relocation.kind != ObjRelocKind::Absolute
            || relocation.target_symbol != *function_index
            || relocation.module.is_some()
            || relocation.addend != i64::from(offset)
            || u64::from(offset) >= compiled_function.size
        {
            return None;
        }
    }
    let witness = CompiledJumpTable {
        object_sha256: object_sha256.to_string(),
        compiled_size: u32::try_from(section.size).ok()?,
        table_offset: u32::try_from(table_start).ok()?,
        function_name: source_function,
        entry_offsets: source_offsets,
        next_unit: next_source_split.unit.clone(),
        next_name: next_source.name.clone(),
    };
    witness.valid(range).then_some(witness)
}

impl DataEvidenceReport {
    /// Corroborate complete BSS or jump-table allocations with the current,
    /// Ninja-clean target-version object. A guessed retail member size never
    /// becomes a size witness: only the complete section layout can qualify.
    pub fn add_compiled_allocations(
        &mut self,
        source: &MatchTarget,
        target: &MatchTarget,
        data_matches: &[DataMatch],
        objects: Option<&ObjectEvidence>,
        root: Option<&Path>,
    ) {
        let (Some(objects), Some(root)) = (objects, root) else { return };
        if objects.status != ScanStatus::Scanned
            || objects.target_image_sha256.as_deref() != Some(self.target_image_sha256.as_str())
        {
            return;
        }
        for range in &mut self.ranges {
            let ordinary_bss = range.section == ".bss"
                && range.members.len() >= 2
                && range.members.iter().all(|member| {
                    member.target_common.is_none()
                        && !member.target_symbol_common
                        && member.target_owner.is_none()
                });
            let jump_table = range.section == ".data" && range.members.len() == 2;
            if !ordinary_bss && !jump_table {
                continue;
            }
            let mut records = objects.objects.iter().filter(|record| record.unit == range.unit);
            let Some(record) = records.next() else { continue };
            if records.next().is_some() {
                continue;
            }
            if record.status != ObjectStatus::Available
                || record.build_freshness != BuildFreshness::Clean
                || record.sha256.is_none()
            {
                continue;
            }
            let path = root.join(&record.base_path);
            let Ok(bytes) = std::fs::read(&path) else { continue };
            if record.sha256.as_deref() != Some(format!("{:x}", Sha256::digest(&bytes)).as_str()) {
                continue;
            }
            let Ok(object) = with_working_directory(root, || {
                process_elf(Utf8NativePath::new(&record.base_path))
            }) else {
                continue;
            };
            if std::fs::read(&path).ok().as_deref() != Some(bytes.as_slice()) {
                continue;
            }
            if ordinary_bss {
                range.compiled_ordinary_bss = compiled_bss_witness(
                    source,
                    target,
                    range,
                    &object,
                    record.sha256.as_deref().unwrap(),
                );
            } else {
                range.compiled_jump_table = compiled_jump_table_witness(
                    source,
                    target,
                    range,
                    data_matches,
                    &object,
                    record.sha256.as_deref().unwrap(),
                );
            }
        }
    }

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
                compiled_ordinary_bss: None,
                compiled_jump_table: None,
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
            if range.compiled_ordinary_bss.is_some() && !range.ordinary_bss_proven() {
                bail!("Data evidence contains an invalid compiled BSS certificate");
            }
            if range.compiled_jump_table.is_some() && !range.jump_table_proven() {
                bail!("Data evidence contains an invalid compiled jump-table certificate");
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

    #[test]
    fn complete_compiled_bss_layout_certifies_a_range_not_guessed_member_sizes() {
        let member = |index, name: &str, start, end| DataMemberEvidence {
            source_index: index,
            target_index: index,
            source_name: name.into(),
            target_name: name.into(),
            target_start: start,
            target_end: end,
            source_extent_known: true,
            target_extent_known: true,
            target_size_basis: DataSizeBasis::Inferred,
            source_wholly_owned: true,
            source_weak: false,
            target_weak: false,
            target_symbol_common: false,
            target_common_align: None,
            target_common_align_basis: None,
            reference_positions: 2,
            target_owner: None,
            target_common: None,
        };
        let mut range = DataRangeEvidence {
            unit: "audio.cpp".into(),
            section: ".bss".into(),
            start: 0x2000,
            end: 0x20f0,
            tier: UnitTier::Candidate,
            reasons: vec![],
            required_alignment: 8,
            members: vec![
                member(0, "@454", 0x2000, 0x2030),
                member(1, "s_Players", 0x2030, 0x2094),
                member(2, "s_QueuedPlayers", 0x2094, 0x20f0),
            ],
            compiled_ordinary_bss: None,
            compiled_jump_table: None,
        };
        assert!(!range.eligible());
        range.compiled_ordinary_bss = Some(CompiledOrdinaryBss {
            object_sha256: "a".repeat(64),
            compiled_size: 0xec,
            section_align: 8,
            symbols: [
                ("@251", 0, 0x0c),
                ("@252", 0x0c, 0x18),
                ("@253", 0x18, 0x24),
                ("@255", 0x24, 0x30),
                ("s_Players", 0x30, 0x88),
                ("@257", 0x88, 0x94),
                ("s_QueuedPlayers", 0x94, 0xec),
            ]
            .into_iter()
            .map(|(name, start, end)| CompiledDataSymbol { name: name.into(), start, end })
            .collect(),
            next_owner: "another.cpp".into(),
        });
        assert!(range.eligible());
        assert_eq!(range.common_mode(), Some(false));
        assert_eq!(range.split_suffix(), "");
        assert_eq!(range.members[1].target_size_basis, DataSizeBasis::Inferred);

        let mut damaged = range.clone();
        damaged.compiled_ordinary_bss.as_mut().unwrap().symbols[5].start += 4;
        assert!(!damaged.eligible());
        let mut unbounded = range.clone();
        unbounded.compiled_ordinary_bss.as_mut().unwrap().next_owner = range.unit.clone();
        assert!(!unbounded.eligible());
        let mut repeated_anchor = range.clone();
        repeated_anchor.members[2].target_name = "s_Players".into();
        assert!(!repeated_anchor.eligible());
        let mut weak_anchor = range;
        weak_anchor.members[1].target_weak = true;
        assert!(!weak_anchor.eligible());
    }

    #[test]
    fn an_inferred_jump_table_needs_the_complete_compiled_allocation() {
        let member =
            |index, name: &str, start, end, owner: Option<&str>, basis| DataMemberEvidence {
                source_index: index,
                target_index: index,
                source_name: name.into(),
                target_name: name.into(),
                target_start: start,
                target_end: end,
                source_extent_known: true,
                target_extent_known: true,
                target_size_basis: basis,
                source_wholly_owned: true,
                source_weak: false,
                target_weak: false,
                target_symbol_common: false,
                target_common_align: None,
                target_common_align_basis: None,
                reference_positions: 2,
                target_owner: owner.map(str::to_owned),
                target_common: None,
            };
        let mut range = DataRangeEvidence {
            unit: "owner.cpp".into(),
            section: ".data".into(),
            start: 0x1000,
            end: 0x10f8,
            tier: UnitTier::Candidate,
            reasons: vec![],
            required_alignment: 4,
            members: vec![
                member(0, "vt", 0x1000, 0x106c, Some("owner.cpp"), DataSizeBasis::ExistingSplit),
                member(1, "table", 0x106c, 0x10f8, None, DataSizeBasis::Inferred),
            ],
            compiled_ordinary_bss: None,
            compiled_jump_table: None,
        };
        assert!(!range.eligible());
        range.compiled_jump_table = Some(CompiledJumpTable {
            object_sha256: "a".repeat(64),
            compiled_size: 0xf8,
            table_offset: 0x6c,
            function_name: "dispatch".into(),
            entry_offsets: (0..35).map(|index| (index % 7) * 4).collect(),
            next_unit: "next.cpp".into(),
            next_name: "next_vt".into(),
        });
        assert!(range.eligible());

        let mut incomplete = range.clone();
        incomplete.compiled_jump_table.as_mut().unwrap().entry_offsets.pop();
        assert!(!incomplete.eligible());
        let mut lost_prefix = range.clone();
        lost_prefix.members[0].target_owner = None;
        assert!(!lost_prefix.eligible());
        let mut same_next_owner = range;
        same_next_owner.compiled_jump_table.as_mut().unwrap().next_unit = "owner.cpp".into();
        assert!(!same_next_owner.eligible());
    }

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
