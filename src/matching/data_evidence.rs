//! Typed witnesses for the non-code ranges proposed by the matcher.
//!
//! `splits.txt` syntax is a useful review format, but it loses the symbol and
//! relocation evidence behind a range. Discovery reads this record as well as
//! the text proposal and only offers a range when both identify it exactly.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use anyhow::{Context, Result, bail};
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

pub const SCHEMA: u32 = 7;

/// The proposal reason for a range mapped by [`SourceLayoutBracket`].
const SOURCE_LAYOUT_REASON: &str = "whole source split mapped by a uniform anchor delta";

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

    /// The report for whatever version pair it records, for a caller that
    /// only has the reference.
    pub fn load_recorded(&self) -> Result<DataEvidenceReport> {
        let bytes = std::fs::read(&self.file)
            .with_context(|| format!("Failed to read data evidence {}", self.file))?;
        if self.schema != SCHEMA || format!("{:x}", Sha256::digest(&bytes)) != self.sha256 {
            bail!("Data evidence reference {} is stale or uses an unsupported schema", self.file);
        }
        let report: DataEvidenceReport = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed to parse data evidence {}", self.file))?;
        report.validate(&report.source, &report.target)?;
        Ok(report)
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
    /// The whole source split range, padding included, mapped onto the
    /// target by one anchor-bracketed delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_layout: Option<SourceLayoutBracket>,
}

/// Why a complete source split range may be claimed at a shifted address.
///
/// A split's interior layout is fixed by its translation unit. The nearest
/// unique named symbols on both sides of it, and every one between, moved by
/// the same delta, so the total size between the two brackets is unchanged.
/// That alone would allow one object to shrink while another grows, so the
/// brackets must lie within the neighbouring source splits, and every target
/// symbol between them must correspond to the source at the shifted address
/// (see [`LayoutIndex::map`]). Uniformly sized unnamed objects can still
/// shift between neighbours under those rules, and a build from extracted
/// objects cannot see a data boundary, so the content decides as well (see
/// [`LayoutInterior`]). The certificate records the source range, the
/// anchors and the source split's own attributes; the range it supports is
/// exactly the source range plus the delta, including the alignment padding a
/// member-by-member range omits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLayoutBracket {
    pub source_start: u32,
    pub source_end: u32,
    /// Target address minus source address.
    pub delta: i64,
    /// The last anchor at or before `source_start`.
    pub before: LayoutAnchor,
    /// The first anchor at or after `source_end`.
    pub after: LayoutAnchor,
    /// Every anchor strictly between the two brackets.
    pub inside: Vec<LayoutAnchor>,
    /// The source split's effective alignment.
    pub align: u32,
    /// Whether the source split states its alignment explicitly.
    pub explicit_align: bool,
    pub common: bool,
    /// What fixed the interior beyond the anchors.
    pub interior: LayoutInterior,
}

/// Anchors with equal deltas only show that the total size between them is
/// unchanged. Uniformly sized unnamed objects (a float pool, `lbl_` words)
/// can shift between neighbouring units without moving any anchor, and a
/// build from extracted objects cannot see that boundary. So the interior is
/// checked against content as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayoutInterior {
    /// Initialized data: the whole source split and the shifted target range
    /// hold the same bytes outside relocations, relocations agree in offset
    /// and kind, and real names of relocation targets agree.
    IdenticalBytes,
    /// BSS has no bytes: at least one member is the same named object in
    /// both versions, and every member paired by address alone has the same
    /// recorded size on both sides.
    NamedBssMember,
}

fn is_bss(section: &str) -> bool { matches!(section, ".bss" | ".sbss" | ".sbss2") }

/// One named symbol that occurs exactly once in each version, in the same
/// section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutAnchor {
    pub name: String,
    pub source: u32,
    pub target: u32,
}

impl LayoutAnchor {
    fn delta(&self) -> i64 { i64::from(self.target) - i64::from(self.source) }
}

/// A symbol as the source-layout mapping sees it. A loaded image and a
/// `symbols.txt` can both supply one, so the matcher and verify's link
/// feedback apply the same rule.
#[derive(Debug, Clone)]
pub struct LayoutSymbol {
    pub name: String,
    pub section: String,
    pub address: u32,
    /// A recorded size. dtk may have inferred it from the next symbol.
    pub size: Option<u32>,
}

/// The data symbols of a `symbols.txt`, for callers that have the project's
/// text rather than a loaded image.
pub fn layout_symbols(text: &str) -> Vec<LayoutSymbol> {
    text.lines()
        .filter_map(|line| {
            let symbol = crate::project::rename_sync::parse_line(line)?;
            if matches!(symbol.section.as_str(), ".text" | ".init") {
                return None;
            }
            let size = line.split_once("//").and_then(|(_, attributes)| {
                attributes
                    .split_whitespace()
                    .find_map(|attribute| attribute.strip_prefix("size:0x"))
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            });
            Some(LayoutSymbol {
                name: symbol.name,
                section: symbol.section,
                address: symbol.address,
                size: size.filter(|&size| size > 0),
            })
        })
        .collect()
}

/// A source range mapped onto the target. Positions index the symbol slices
/// the [`LayoutIndex`] was built from.
#[derive(Debug, Clone)]
pub struct LayoutMapping {
    pub delta: i64,
    pub start: u32,
    pub end: u32,
    pub before: LayoutAnchor,
    pub after: LayoutAnchor,
    pub inside: Vec<LayoutAnchor>,
    /// (source position, target position) for every target symbol inside.
    pub members: Vec<(usize, usize)>,
}

/// Anchors and per-section address orders of two symbol inventories.
pub struct LayoutIndex<'a> {
    source: &'a [LayoutSymbol],
    target: &'a [LayoutSymbol],
    anchors: HashMap<&'a str, Vec<LayoutAnchor>>,
    source_order: HashMap<&'a str, Vec<usize>>,
    target_order: HashMap<&'a str, Vec<usize>>,
}

/// A name that identifies the same object in both versions: not dtk's
/// address-derived placeholder, not a compiler label numbered per object, and
/// not a function-local static (`init$2667`), whose number is the compiler's.
fn anchor_name(name: &str) -> bool {
    crate::derive::objects::is_usable_source_name(name)
        && !crate::project::rename_sync::is_address_derived(name)
        && !name.rsplit_once('$').is_some_and(|(_, number)| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

impl<'a> LayoutIndex<'a> {
    pub fn new(source: &'a [LayoutSymbol], target: &'a [LayoutSymbol]) -> Self {
        fn by_name(symbols: &[LayoutSymbol]) -> HashMap<&str, Vec<usize>> {
            let mut names: HashMap<&str, Vec<usize>> = HashMap::new();
            for (position, symbol) in symbols.iter().enumerate() {
                names.entry(symbol.name.as_str()).or_default().push(position);
            }
            names
        }
        fn by_section(symbols: &[LayoutSymbol]) -> HashMap<&str, Vec<usize>> {
            let mut sections: HashMap<&str, Vec<usize>> = HashMap::new();
            for (position, symbol) in symbols.iter().enumerate() {
                sections.entry(symbol.section.as_str()).or_default().push(position);
            }
            for positions in sections.values_mut() {
                positions.sort_by_key(|&position| symbols[position].address);
            }
            sections
        }
        let target_names = by_name(target);
        let mut anchors: HashMap<&str, Vec<LayoutAnchor>> = HashMap::new();
        for (name, positions) in by_name(source) {
            let (Some(target_positions), [position]) =
                (target_names.get(name), positions.as_slice())
            else {
                continue;
            };
            let ([target_position], source_symbol) =
                (target_positions.as_slice(), &source[*position])
            else {
                continue;
            };
            let target_symbol = &target[*target_position];
            if anchor_name(name) && source_symbol.section == target_symbol.section {
                anchors.entry(source_symbol.section.as_str()).or_default().push(LayoutAnchor {
                    name: name.to_string(),
                    source: source_symbol.address,
                    target: target_symbol.address,
                });
            }
        }
        for list in anchors.values_mut() {
            list.sort_by_key(|anchor| anchor.source);
        }
        Self {
            source,
            target,
            anchors,
            source_order: by_section(source),
            target_order: by_section(target),
        }
    }

    /// Map `[start, end)` of a source section onto the target, or `None`
    /// when no single delta is established or something in the target does
    /// not correspond to the source layout.
    ///
    /// Both bracketing anchors must lie within `span`, normally the source
    /// split before this one through the split after it: equal deltas only
    /// show that the total size between two anchors is unchanged, so the
    /// stretch they bound is kept short. Every target symbol between the two
    /// anchors, not only inside the mapped range, must correspond to the
    /// source at the shifted address: a real name must be the source's name
    /// there or replace a dtk placeholder, and a placeholder or numbered label
    /// must start where a source symbol starts or lie inside a sized source
    /// object. A referenced address in source padding is a layout change.
    ///
    /// Overlap with existing target splits and the alignment of the result
    /// are the caller's to check, since only the caller knows the splits.
    pub fn map(
        &self,
        section: &str,
        start: u32,
        end: u32,
        span: (u32, u32),
    ) -> Option<LayoutMapping> {
        if start >= end {
            return None;
        }
        let anchors = self.anchors.get(section)?;
        let before = anchors.partition_point(|anchor| anchor.source <= start).checked_sub(1)?;
        let after = anchors.partition_point(|anchor| anchor.source < end);
        let bracket = anchors.get(before..=after)?;
        let (first, last) = (&bracket[0], &bracket[bracket.len() - 1]);
        let delta = first.delta();
        if first.source < span.0
            || last.source > span.1
            || bracket.iter().any(|anchor| anchor.delta() != delta)
        {
            return None;
        }
        let shift = |address: u32| u32::try_from(i64::from(address) + delta).ok();
        let (target_start, target_end) = (shift(start)?, shift(end)?);

        let source_order = self.source_order.get(section)?;
        let target_order = self.target_order.get(section)?;
        let source_from =
            |address: u32| source_order.partition_point(|&p| self.source[p].address < address);
        let bss = is_bss(section);
        let mut members = Vec::new();
        let mut named = false;
        let from = target_order.partition_point(|&p| self.target[p].address < first.target);
        for &position in &target_order[from..] {
            let symbol = &self.target[position];
            if symbol.address >= last.target {
                break;
            }
            let source_address = u32::try_from(i64::from(symbol.address) - delta).ok()?;
            let at = source_from(source_address);
            let candidates: Vec<usize> = source_order[at..]
                .iter()
                .copied()
                .take_while(|&p| self.source[p].address == source_address)
                .collect();
            let by_name = anchor_name(&symbol.name)
                .then(|| candidates.iter().copied().find(|&p| self.source[p].name == symbol.name))
                .flatten();
            let paired = if let Some(paired) = by_name {
                paired
            } else if anchor_name(&symbol.name) {
                candidates.iter().copied().find(|&p| placeholder(&self.source[p].name))?
            } else if let Some(&paired) = candidates.first() {
                paired
            } else {
                let container =
                    source_order[source_from(first.source)..at].iter().copied().find(|&p| {
                        let object = &self.source[p];
                        object.size.is_some_and(|size| {
                            u64::from(source_address) < u64::from(object.address) + u64::from(size)
                        })
                    });
                let container = container?;
                // Without bytes, the containing object must itself be in the
                // target at its shifted address, with the same recorded size.
                if bss {
                    let object = &self.source[container];
                    let shifted = u32::try_from(i64::from(object.address) + delta).ok()?;
                    let from = target_order.partition_point(|&p| self.target[p].address < shifted);
                    let held = target_order[from..]
                        .iter()
                        .take_while(|&&p| self.target[p].address == shifted)
                        .any(|&p| match (object.size, self.target[p].size) {
                            (Some(a), Some(b)) => a == b,
                            _ => true,
                        });
                    if !held {
                        return None;
                    }
                }
                continue;
            };
            // Without bytes, a BSS pair made by address alone must at least
            // agree on its recorded size.
            if bss
                && by_name.is_none()
                && let (Some(a), Some(b)) = (self.source[paired].size, symbol.size)
                && a != b
            {
                return None;
            }
            if (target_start..target_end).contains(&symbol.address) {
                named |= by_name.is_some();
                members.push((paired, position));
            }
        }
        if bss && !named {
            return None;
        }
        // An edge inside a target symbol would cut an object in two.
        let straddles = |edge: u32| {
            target_order.iter().any(|&p| {
                let symbol = &self.target[p];
                symbol.size.is_some_and(|size| {
                    symbol.address < edge
                        && u64::from(edge) < u64::from(symbol.address) + u64::from(size)
                })
            })
        };
        if members.is_empty() || straddles(target_start) || straddles(target_end) {
            return None;
        }
        Some(LayoutMapping {
            delta,
            start: target_start,
            end: target_end,
            before: first.clone(),
            after: last.clone(),
            inside: bracket[1..bracket.len() - 1].to_vec(),
            members,
        })
    }
}

/// dtk's name for an address nothing named yet. A real target name may
/// replace it; it never stands for a particular object.
fn placeholder(name: &str) -> bool {
    crate::derive::objects::is_derivable(name)
        || crate::project::rename_sync::is_address_derived(name)
}

/// Where the bracketing anchors of the source split at `index` may lie: from
/// the start of the split before it to the end of the split after it. The
/// first and last splits of a section are open towards the section's edge,
/// where no neighbour bounds them; the correspondence check still covers the
/// whole bracket. `splits` are the section's `splits.txt` ranges, sorted.
pub fn adjacent_span(splits: &[(u32, u32)], index: usize) -> (u32, u32) {
    let low = index.checked_sub(1).map_or(0, |previous| splits[previous].0);
    let high = splits.get(index + 1).map_or(u32::MAX, |next| next.1);
    (low, high)
}

impl SourceLayoutBracket {
    fn valid(&self, range: &DataRangeEvidence) -> bool {
        let shifted = |address: u32| i64::from(address) + self.delta;
        let anchors_agree = std::iter::once(&self.before)
            .chain(&self.inside)
            .chain(std::iter::once(&self.after))
            .all(|anchor| !anchor.name.is_empty() && anchor.delta() == self.delta);
        let ordered = std::iter::once(&self.before)
            .chain(&self.inside)
            .chain(std::iter::once(&self.after))
            .collect::<Vec<_>>()
            .windows(2)
            .all(|pair| pair[0].source <= pair[1].source);
        if self.source_start >= self.source_end
            || shifted(self.source_start) != i64::from(range.start)
            || shifted(self.source_end) != i64::from(range.end)
            || self.before.source > self.source_start
            || self.after.source < self.source_end
            || !anchors_agree
            || !ordered
            || !self.align.is_power_of_two()
            || range.required_alignment != self.align
            // The source edges were valid splits; a delta that preserves
            // their residue keeps them valid, and so do aligned edges.
            || (self.delta.rem_euclid(i64::from(self.align)) != 0
                && (range.start % self.align != 0 || range.end % self.align != 0))
            || range.start % 4 != 0
            || (self.common && !is_bss(&range.section))
            || range.members.is_empty()
        {
            return false;
        }
        let interior = match self.interior {
            LayoutInterior::IdenticalBytes => !is_bss(&range.section),
            LayoutInterior::NamedBssMember => {
                is_bss(&range.section)
                    && range.members.iter().any(|member| {
                        member.source_name == member.target_name && anchor_name(&member.source_name)
                    })
            }
        };
        if !interior {
            return false;
        }
        let mut previous = range.start;
        let mut sources = BTreeSet::new();
        for member in &range.members {
            if member.target_start < previous
                || member.target_end <= member.target_start
                || member.target_end > range.end
                || member.target_size_basis != DataSizeBasis::SourceLayoutBracketed
                || !member.source_extent_known
                || !member.target_extent_known
                || !member.source_wholly_owned
                // A weak member is admitted: the source split placed this
                // unit's copy at this offset and the target keeps the same
                // layout, while a copy left in a gap object duplicates it.
                // An absent flag says nothing about common linkage, but a
                // present one contradicts an ordinary source split.
                || (member.target_symbol_common && !self.common)
                || member.target_owner.as_ref().is_some_and(|owner| owner != &range.unit)
                || !sources.insert(member.source_index)
            {
                return false;
            }
            previous = member.target_start;
        }
        true
    }
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
    /// The target symbol's bytes, with relocated words masked, equal the
    /// paired source symbol's bytes over the source's own known size. Unlike a
    /// size guessed from the next symbol, that agreement is a content witness
    /// for both edges of the member.
    ByteIdentical,
    /// The member lies in a source split range that maps onto the target by
    /// one uniform address delta: named anchors bracket both edges and agree
    /// with every anchor between them, and every target symbol inside sits at
    /// a source symbol's address plus that delta. Its extent is the paired
    /// source symbol's, shifted. Only a valid [`SourceLayoutBracket`] on the
    /// enclosing range makes this a witness.
    SourceLayoutBracketed,
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

/// Smallest member whose bytes can witness its own extent. Shorter members
/// match too many unrelated objects.
const MIN_IDENTICAL_BYTES: u64 = 8;

/// Whether `target` holds exactly the bytes `source` does, so that the target's
/// extent (which dtk only guessed) can be read from the source's known size.
///
/// Words under a relocation are masked on both sides, since a pointer's value
/// legitimately differs between versions; what remains must be identical and
/// must not be one repeated byte, which would equal any zero-filled or
/// padding object. Relocation presence and kind have to agree at every
/// offset.
fn byte_identical(
    source_section: &ObjSection,
    source: &ObjSymbol,
    target_section: &ObjSection,
    target: &ObjSymbol,
) -> bool {
    let data_like = |section: &ObjSection| {
        matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
    };
    if !data_like(source_section)
        || !data_like(target_section)
        || !source.size_known
        || source.size < MIN_IDENTICAL_BYTES
        || target.size != source.size
    {
        return false;
    }
    let (Ok(source_bytes), Ok(target_bytes)) = (
        source_section.symbol_data(&ObjSymbol { size: source.size, ..source.clone() }),
        target_section.symbol_data(&ObjSymbol { size: source.size, ..target.clone() }),
    ) else {
        return false;
    };
    let relocations = |section: &ObjSection, symbol: &ObjSymbol| -> Vec<(u32, ObjRelocKind)> {
        let start = symbol.address as u32;
        section
            .relocations
            .range(start..start + source.size as u32)
            .map(|(address, reloc)| (address - start, reloc.kind))
            .collect()
    };
    let source_relocations = relocations(source_section, source);
    if source_relocations != relocations(target_section, target) {
        return false;
    }
    let mut masked = vec![false; source_bytes.len()];
    for &(offset, _) in &source_relocations {
        for slot in masked.iter_mut().skip(offset as usize).take(4) {
            *slot = true;
        }
    }
    let mut first = None;
    let mut varied = false;
    for (index, (&a, &b)) in source_bytes.iter().zip(target_bytes).enumerate() {
        if masked[index] {
            continue;
        }
        if a != b {
            return false;
        }
        match first {
            None => first = Some(a),
            Some(value) if value != a => varied = true,
            _ => {}
        }
    }
    varied
}

/// Whether `source_range` of the source section holds the same content as
/// the same length at `target_start` in the target, and nowhere else nearby.
///
/// Content is compared as [`content_at`] does. A match at the claimed delta
/// alone does not fix a boundary: a pool of equal constants or a table of
/// pointers into one object matches itself shifted by a word. So every other
/// word-aligned position whose range lies within `window` (the bracketing
/// anchors' target span, widened by two words on each side of the claimed
/// range) must fail to match. Data that repeats within that window is
/// refused.
fn range_identical(
    source: &MatchTarget,
    source_section: &ObjSection,
    (start, end): (u32, u32),
    target: &MatchTarget,
    target_section: &ObjSection,
    target_start: u32,
    window: (u32, u32),
) -> bool {
    let length = end - start;
    let at = |position: u32| {
        content_at(source, source_section, (start, end), target, target_section, position)
    };
    if at(target_start) != Some(true) {
        return false;
    }
    let low = window.0.min(target_start.saturating_sub(8));
    let high = window.1.max(target_start.saturating_add(length).saturating_add(8));
    let first = low + (target_start.wrapping_sub(low) % 4);
    let mut position = first;
    while position.checked_add(length).is_some_and(|end| end <= high) {
        if position != target_start && at(position).is_some() {
            return false;
        }
        position += 4;
    }
    true
}

/// Compares `source_range` with the same length at `target_start`: bytes
/// outside relocations must be identical, relocations must sit at the same
/// offsets with the same kinds, and where both relocation targets have a
/// real name, the names and the addends must agree. Relocations against a
/// dtk placeholder or a section symbol compare offset and kind only: their
/// addends are relative to a symbol whose own extent may differ between
/// versions. `None` is a mismatch; `Some(informative)` says whether
/// anything beyond masked words and one repeated byte was compared.
fn content_at(
    source: &MatchTarget,
    source_section: &ObjSection,
    (start, end): (u32, u32),
    target: &MatchTarget,
    target_section: &ObjSection,
    target_start: u32,
) -> Option<bool> {
    let data_like = |section: &ObjSection| {
        matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
    };
    let target_end = target_start.checked_add(end - start)?;
    if !data_like(source_section) || !data_like(target_section) {
        return None;
    }
    let source_bytes = source_section.data_range(start, end).ok()?;
    let target_bytes = target_section.data_range(target_start, target_end).ok()?;
    let source_relocations: Vec<_> = source_section.relocations.range(start..end).collect();
    let target_relocations: Vec<_> =
        target_section.relocations.range(target_start..target_end).collect();
    if source_relocations.len() != target_relocations.len() {
        return None;
    }
    let mut masked = vec![false; source_bytes.len()];
    let mut named_target = false;
    for (&(source_at, source_reloc), &(target_at, target_reloc)) in
        source_relocations.iter().zip(&target_relocations)
    {
        if source_at - start != target_at - target_start || source_reloc.kind != target_reloc.kind {
            return None;
        }
        let name = |image: &MatchTarget, reloc: &decomp_toolkit::obj::ObjReloc| {
            let name = &image.obj.symbols[reloc.target_symbol].name;
            anchor_name(name).then(|| name.clone())
        };
        if let (Some(a), Some(b)) = (name(source, source_reloc), name(target, target_reloc)) {
            if a != b || source_reloc.addend != target_reloc.addend {
                return None;
            }
            named_target = true;
        }
        for slot in masked.iter_mut().skip((source_at - start) as usize).take(4) {
            *slot = true;
        }
    }
    let mut first = None;
    let mut varied = false;
    for (index, (&a, &b)) in source_bytes.iter().zip(target_bytes).enumerate() {
        if masked[index] {
            continue;
        }
        if a != b {
            return None;
        }
        match first {
            None => first = Some(a),
            Some(value) if value != a => varied = true,
            _ => {}
        }
    }
    Some(varied || named_target)
}

fn identical_basis(
    basis: DataSizeBasis,
    source_symbol: &ObjSymbol,
    source: &MatchTarget,
    target_symbol: &ObjSymbol,
    target_section: &ObjSection,
) -> DataSizeBasis {
    if basis == DataSizeBasis::Inferred
        && source_symbol.section.and_then(|index| source.obj.sections.get(index)).is_some_and(
            |section| byte_identical(section, source_symbol, target_section, target_symbol),
        )
    {
        DataSizeBasis::ByteIdentical
    } else {
        basis
    }
}

impl DataRangeEvidence {
    pub fn ordinary_bss_proven(&self) -> bool {
        self.compiled_ordinary_bss.as_ref().is_some_and(|proof| proof.valid(self))
    }

    pub fn jump_table_proven(&self) -> bool {
        self.compiled_jump_table.as_ref().is_some_and(|proof| proof.valid(self))
    }

    pub fn source_layout_proven(&self) -> bool {
        self.source_layout.as_ref().is_some_and(|proof| proof.valid(self))
    }

    /// Linker mode when every member agrees or an entire ordinary allocation
    /// has a compiled-layout certificate. A missing `common` flag alone never
    /// establishes ordinary BSS. A source-layout certificate carries the
    /// source split's own mode.
    pub fn common_mode(&self) -> Option<bool> {
        if self.ordinary_bss_proven() {
            return Some(false);
        }
        if let Some(layout) = &self.source_layout {
            return self.source_layout_proven().then_some(layout.common);
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
        if let Some(layout) = &self.source_layout {
            return (self.start % layout.align == 0).then_some(layout.align);
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
        if let Some(layout) = self.source_layout.as_ref().filter(|_| self.source_layout_proven()) {
            // The source split's own attributes, as its line states them.
            let mut suffix = String::new();
            if layout.explicit_align || layout.common {
                suffix += &format!(" align:{}", layout.align);
            }
            if layout.common {
                suffix += " common";
            }
            return suffix;
        }
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
        if self.source_layout.is_some() {
            return self.source_layout_proven();
        }
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
                || member.target_size_basis == DataSizeBasis::SourceLayoutBracketed
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
            if range.members.len() > 1 && !member.target_name.starts_with('@') {
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
        if let [member] = range.members.as_slice() {
            // One zero-filled symbol has no distinctive bytes or second named
            // anchor. Its full allocation and next-unit seam need stronger
            // independent checks in compiled_bss_witness.
            self.symbols.len() == 1
                && self.compiled_size == range.end - range.start
                && member.target_size_basis == DataSizeBasis::Inferred
                && member.reference_positions >= 2
        } else {
            named_anchors.len() >= 2
        }
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
    if source_section.name != ".bss"
        || source_section.kind != ObjSectionKind::Bss
        || source_last.section != source_first.section
    {
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
    if range.members.len() == 1 {
        // The next split is already attributed in both versions. Require the
        // same unique, nonweak object at that seam before a singleton BSS
        // allocation can inherit its otherwise inferred right boundary.
        if source_first.flags.is_common()
            || source.obj.symbols.iter().any(|(index, symbol)| {
                symbol.section == source_first.section
                    && symbol.kind == ObjSymbolKind::Object
                    && symbol.address >= source_first.address
                    && symbol.address < u64::from(source_split.end)
                    && index != first.source_index
            })
        {
            return None;
        }
        let (next_source_start, next_source_split) =
            source_section.splits.for_address(source_split.end)?;
        let next_source: Vec<_> = source
            .obj
            .symbols
            .iter()
            .filter(|(_, symbol)| {
                symbol.section == source_first.section
                    && symbol.kind == ObjSymbolKind::Object
                    && symbol.address == u64::from(source_split.end)
                    && symbol.size_known
                    && symbol.size > 0
                    && !symbol.flags.is_weak()
                    && !symbol.flags.is_common()
            })
            .collect();
        let [(_, next_source)] = next_source.as_slice() else { return None };
        if next_source_start != source_split.end
            || source_split.autogenerated
            || source_split.skip
            || next_source_split.unit == range.unit
            || next_source_split.autogenerated
            || next_source_split.skip
            || next_source_split.common
            || next_source.name.is_empty()
        {
            return None;
        }
        let target_section_index = target.obj.symbols[first.target_index].section?;
        let target_section = target.obj.sections.get(target_section_index)?;
        let (next_target_start, next_target_split) =
            target_section.splits.for_address(range.end)?;
        let next_target: Vec<_> = target
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
                    && !symbol.flags.is_common()
            })
            .collect();
        let [(_, next_target)] = next_target.as_slice() else { return None };
        if next_target_start != range.end
            || next_source_split.unit != next_target_split.unit
            || next_target_split.skip
            || next_source.name != next_target.name
        {
            return None;
        }
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
                && !range.members.is_empty()
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
                    target_size_basis: identical_basis(
                        size_basis(target_symbol, section, split_exact),
                        source_symbol,
                        source,
                        target_symbol,
                        section,
                    ),
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
                source_layout: None,
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

    /// Map every source data split the target lacks onto the target by a
    /// uniform anchor delta, recording each one that maps cleanly as a whole
    /// range with a [`SourceLayoutBracket`], and a matching proposal so the
    /// text proposals name the same range.
    ///
    /// A range the matcher already proposed with the same bounds is
    /// strengthened in place unless its member record already proves the
    /// range and its BSS mode. Matcher ranges for the same unit and section
    /// that the layout range does not contain are dropped, unless one of them
    /// is eligible on its own record, in which case no layout range is added.
    /// Nothing here is applied: discovery still requires the range to fit
    /// beside the current splits, and the build to reproduce retail.
    pub fn add_source_layouts(
        &mut self,
        source: &MatchTarget,
        target: &MatchTarget,
        data_matches: &[DataMatch],
        proposals: &mut Vec<UnitProposal>,
    ) {
        let inventory = |image: &MatchTarget| -> (Vec<LayoutSymbol>, Vec<SymbolIndex>) {
            image
                .obj
                .symbols
                .iter()
                .filter_map(|(index, symbol)| {
                    let section = image.obj.sections.get(symbol.section?)?;
                    (section.kind != ObjSectionKind::Code
                        && !symbol.name.is_empty()
                        && symbol.kind != ObjSymbolKind::Section)
                        .then(|| {
                            Some((
                                LayoutSymbol {
                                    name: symbol.name.clone(),
                                    section: section.name.clone(),
                                    address: u32::try_from(symbol.address).ok()?,
                                    size: (symbol.size_known && symbol.size > 0)
                                        .then(|| u32::try_from(symbol.size).ok())
                                        .flatten(),
                                },
                                index,
                            ))
                        })
                        .flatten()
                })
                .unzip()
        };
        let (source_symbols, source_indices) = inventory(source);
        let (target_symbols, target_indices) = inventory(target);
        let index = LayoutIndex::new(&source_symbols, &target_symbols);
        let evidence: HashMap<(SymbolIndex, SymbolIndex), u32> =
            data_matches.iter().map(|pair| ((pair.source, pair.target), pair.evidence)).collect();

        for (source_section_index, source_section) in source.obj.sections.iter() {
            if source_section.kind == ObjSectionKind::Code {
                continue;
            }
            let Ok(Some((target_section_index, target_section))) =
                target.obj.sections.by_name(&source_section.name)
            else {
                continue;
            };
            // The ranges `splits.txt` states, as verify's link feedback reads
            // them, so both routes bound the same split by the same span.
            let mut bounds: Vec<(u32, u32)> = source_section
                .splits
                .iter()
                .filter(|(_, split)| !split.autogenerated)
                .map(|(start, split)| (start, split.end))
                .collect();
            bounds.sort_unstable();
            for (start, split) in source_section.splits.iter() {
                if split.autogenerated
                    || split.skip
                    || split.rename.is_some()
                    || target_section.splits.iter().any(|(_, other)| other.unit == split.unit)
                {
                    continue;
                }
                let Some(position) = bounds.iter().position(|&b| b == (start, split.end)) else {
                    continue;
                };
                let span = adjacent_span(&bounds, position);
                let Some(mapping) = index.map(&source_section.name, start, split.end, span) else {
                    continue;
                };
                if target_section
                    .splits
                    .iter()
                    .any(|(other, owner)| other < mapping.end && mapping.start < owner.end)
                {
                    continue;
                }
                let interior = if is_bss(&source_section.name) {
                    LayoutInterior::NamedBssMember
                } else if range_identical(
                    source,
                    source_section,
                    (start, split.end),
                    target,
                    target_section,
                    mapping.start,
                    (mapping.before.target, mapping.after.target),
                ) {
                    LayoutInterior::IdenticalBytes
                } else {
                    continue;
                };
                let align =
                    split.alignment(&source.obj, source_section_index, source_section, start);
                let mut members = Vec::new();
                for &(source_position, target_position) in &mapping.members {
                    let source_index = source_indices[source_position];
                    let target_index = target_indices[target_position];
                    let source_symbol = &source.obj.symbols[source_index];
                    let target_symbol = &target.obj.symbols[target_index];
                    let target_start = target_symbols[target_position].address;
                    let source_extent_known = source_symbol.size_known
                        && source_symbol.size > 0
                        && source_symbol.address + source_symbol.size <= u64::from(split.end);
                    let target_end = u32::try_from(
                        u64::from(target_start) + source_symbol.size.min(u64::from(u32::MAX)),
                    )
                    .unwrap_or(u32::MAX);
                    members.push(DataMemberEvidence {
                        source_index,
                        target_index,
                        source_name: source_symbol.name.clone(),
                        target_name: target_symbol.name.clone(),
                        target_start,
                        target_end,
                        source_extent_known,
                        target_extent_known: target_end <= mapping.end,
                        target_size_basis: DataSizeBasis::SourceLayoutBracketed,
                        source_wholly_owned: source_extent_known,
                        source_weak: source_symbol.flags.is_weak(),
                        target_weak: target_symbol.flags.is_weak(),
                        target_symbol_common: target_symbol.flags.is_common(),
                        target_common_align: target_symbol.align,
                        target_common_align_basis: (target_symbol.flags.is_common()
                            && target_symbol.align.is_some())
                        .then_some(CommonAlignBasis::TargetSymbol),
                        reference_positions: evidence
                            .get(&(source_index, target_index))
                            .copied()
                            .unwrap_or(0),
                        target_owner: None,
                        target_common: None,
                    });
                }
                let range = DataRangeEvidence {
                    unit: split.unit.clone(),
                    section: source_section.name.clone(),
                    start: mapping.start,
                    end: mapping.end,
                    tier: UnitTier::Candidate,
                    reasons: vec![SOURCE_LAYOUT_REASON.to_string()],
                    required_alignment: align,
                    members,
                    compiled_ordinary_bss: None,
                    compiled_jump_table: None,
                    source_layout: Some(SourceLayoutBracket {
                        source_start: start,
                        source_end: split.end,
                        delta: mapping.delta,
                        before: mapping.before,
                        after: mapping.after,
                        inside: mapping.inside,
                        align,
                        explicit_align: split.align.is_some(),
                        common: split.common,
                        interior,
                    }),
                };
                if !range.eligible() {
                    continue;
                }
                // A matcher range for this unit and section that the layout
                // range does not contain would be widened into a union that
                // neither record proves. One with a proof of its own wins and
                // the layout range is not offered; unproven ones are dropped.
                // Another layout range of the unit is a separate source split
                // and never conflicts. A contained matcher range whose line
                // would carry other attributes conflicts too: discovery
                // would keep it and drop the layout line.
                let suffix = range.split_suffix();
                let contained = |start: u32, end: u32| range.start <= start && end <= range.end;
                let conflicting = |existing: &DataRangeEvidence| {
                    existing.unit == range.unit
                        && existing.section == range.section
                        && existing.source_layout.is_none()
                        && (!contained(existing.start, existing.end)
                            || (existing.split_suffix() != suffix
                                && (existing.start, existing.end) != (range.start, range.end)))
                };
                if self.ranges.iter().any(|existing| conflicting(existing) && existing.eligible()) {
                    continue;
                }
                self.ranges.retain(|existing| !conflicting(existing));
                let ranges = &self.ranges;
                proposals.retain(|proposal| {
                    if proposal.unit != range.unit || proposal.section != target_section_index {
                        return true;
                    }
                    if (proposal.start, proposal.end) == (range.start, range.end) {
                        return true;
                    }
                    let proposed_suffix = ranges
                        .iter()
                        .find(|existing| {
                            (&existing.unit, &existing.section, existing.start, existing.end)
                                == (&range.unit, &range.section, proposal.start, proposal.end)
                        })
                        .map(DataRangeEvidence::split_suffix)
                        .unwrap_or_default();
                    contained(proposal.start, proposal.end) && proposed_suffix == suffix
                });
                let same = self.ranges.iter().position(|existing| {
                    (&existing.unit, &existing.section, existing.start, existing.end)
                        == (&range.unit, &range.section, range.start, range.end)
                });
                match same {
                    // A member record that already proves the range and, for
                    // BSS, its linker mode, needs no strengthening.
                    Some(position)
                        if self.ranges[position].eligible()
                            && (!matches!(range.section.as_str(), ".bss" | ".sbss" | ".sbss2")
                                || self.ranges[position].common_mode().is_some()) => {}
                    Some(position) => self.ranges[position] = range,
                    None => {
                        proposals.push(UnitProposal {
                            unit: range.unit.clone(),
                            section: target_section_index,
                            start: range.start,
                            end: range.end,
                            members: range.members.iter().map(|m| m.target_index).collect(),
                            tier: UnitTier::Candidate,
                            reasons: vec![SOURCE_LAYOUT_REASON],
                        });
                        self.ranges.push(range);
                    }
                }
            }
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
            if range.source_layout.is_some() && !range.source_layout_proven() {
                bail!("Data evidence contains an invalid source-layout certificate");
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
            source_layout: None,
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
    fn singleton_bss_requires_an_exact_complete_object_and_paired_references() {
        let member = DataMemberEvidence {
            source_index: 1,
            target_index: 2,
            source_name: "local$12".into(),
            target_name: "lbl_2000".into(),
            target_start: 0x2000,
            target_end: 0x2018,
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
            unit: "owner.cpp".into(),
            section: ".bss".into(),
            start: 0x2000,
            end: 0x2018,
            tier: UnitTier::Candidate,
            reasons: vec![],
            required_alignment: 8,
            members: vec![member],
            compiled_ordinary_bss: Some(CompiledOrdinaryBss {
                object_sha256: "a".repeat(64),
                compiled_size: 0x18,
                section_align: 8,
                symbols: vec![CompiledDataSymbol { name: "local$19".into(), start: 0, end: 0x18 }],
                next_owner: "next.cpp".into(),
            }),
            compiled_jump_table: None,
            source_layout: None,
        };
        assert!(range.eligible());
        range.members[0].reference_positions = 1;
        assert!(!range.eligible());
        range.members[0].reference_positions = 2;
        range.compiled_ordinary_bss.as_mut().unwrap().compiled_size = 0x14;
        assert!(!range.eligible());
    }

    #[test]
    fn singleton_bss_witness_needs_a_complete_source_and_the_same_next_owner() {
        fn image(start: u32, next_unit: &str, extra_source_symbol: bool) -> MatchTarget {
            let mut splits = ObjSplits::default();
            for (offset, size, unit) in [(0, 0x18, "owner.cpp"), (0x18, 0x20, next_unit)] {
                splits.push(start + offset, ObjSplit {
                    unit: unit.into(),
                    end: start + offset + size,
                    align: Some(8),
                    common: false,
                    autogenerated: false,
                    skip: false,
                    rename: None,
                });
            }
            let mut symbols = vec![
                ObjSymbol {
                    name: "local".into(),
                    address: u64::from(start),
                    section: Some(0),
                    size: 0x18,
                    size_known: true,
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                },
                ObjSymbol {
                    name: "next_variable".into(),
                    address: u64::from(start + 0x18),
                    section: Some(0),
                    size: 0x20,
                    size_known: true,
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                },
            ];
            if extra_source_symbol {
                symbols.push(ObjSymbol {
                    name: "unexpected".into(),
                    address: u64::from(start + 8),
                    section: Some(0),
                    size: 4,
                    size_known: true,
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                });
            }
            MatchTarget::new(
                "retail".into(),
                ObjInfo::new(
                    ObjKind::Executable,
                    ObjArchitecture::PowerPc,
                    "retail".into(),
                    symbols,
                    vec![ObjSection {
                        name: ".bss".into(),
                        kind: ObjSectionKind::Bss,
                        address: u64::from(start),
                        size: 0x38,
                        data: vec![],
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

        let source = image(0x3000, "next.cpp", false);
        let target = image(0x2000, "next.cpp", false);
        let object = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "compiled".into(),
            vec![ObjSymbol {
                name: "local$19".into(),
                address: 0,
                section: Some(0),
                size: 0x18,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            }],
            vec![ObjSection {
                name: ".bss".into(),
                kind: ObjSectionKind::Bss,
                address: 0,
                size: 0x18,
                data: vec![],
                align: 8,
                elf_index: 0,
                relocations: ObjRelocations::default(),
                virtual_address: None,
                file_offset: 0,
                section_known: true,
                splits: ObjSplits::default(),
            }],
        );
        let range = DataRangeEvidence {
            unit: "owner.cpp".into(),
            section: ".bss".into(),
            start: 0x2000,
            end: 0x2018,
            tier: UnitTier::Candidate,
            reasons: vec![],
            required_alignment: 8,
            members: vec![DataMemberEvidence {
                source_index: 0,
                target_index: 0,
                source_name: "local".into(),
                target_name: "local".into(),
                target_start: 0x2000,
                target_end: 0x2018,
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
            }],
            compiled_ordinary_bss: None,
            compiled_jump_table: None,
            source_layout: None,
        };
        let digest = "a".repeat(64);
        let witness = compiled_bss_witness(&source, &target, &range, &object, &digest).unwrap();
        assert_eq!(witness.next_owner, "next.cpp");
        assert!(
            compiled_bss_witness(
                &image(0x3000, "other.cpp", false),
                &target,
                &range,
                &object,
                &digest,
            )
            .is_none()
        );
        assert!(
            compiled_bss_witness(
                &image(0x3000, "next.cpp", true),
                &target,
                &range,
                &object,
                &digest,
            )
            .is_none()
        );
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
            source_layout: None,
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

    #[test]
    fn identical_bytes_witness_an_unknown_target_extent_but_zeros_and_differences_do_not() {
        let build = |source_data: [u8; 8], target_data: [u8; 8]| {
            let mut source = target("source", 0x1000, Some("unit.cpp"));
            source.obj.sections[0].data = source_data.to_vec();
            let mut guessed = target("target", 0x2000, None);
            guessed.obj.sections[0].data = target_data.to_vec();
            let mut symbol = guessed.obj.symbols[0].clone();
            symbol.data_kind = ObjDataKind::Unknown;
            guessed.obj.symbols.replace(0, symbol).unwrap();
            let proposal = UnitProposal {
                unit: "unit.cpp".into(),
                section: 0,
                start: 0x2000,
                end: 0x2008,
                members: vec![0],
                tier: UnitTier::Candidate,
                reasons: vec!["target is missing functions the source unit has"],
            };
            DataEvidenceReport::build(
                &source,
                &guessed,
                &[DataMatch { source: 0, target: 0, evidence: 2 }],
                std::slice::from_ref(&proposal),
                "NTSC",
                "PAL",
            )
        };
        let same = build([1, 2, 3, 4, 5, 6, 7, 8], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(same.ranges[0].members[0].target_size_basis, DataSizeBasis::ByteIdentical);
        assert!(same.ranges[0].eligible());
        let differs = build([1, 2, 3, 4, 5, 6, 7, 8], [1, 2, 3, 4, 5, 6, 7, 9]);
        assert_eq!(differs.ranges[0].members[0].target_size_basis, DataSizeBasis::Inferred);
        assert!(!differs.ranges[0].eligible());
        let zeros = build([0; 8], [0; 8]);
        assert_eq!(zeros.ranges[0].members[0].target_size_basis, DataSizeBasis::Inferred);
        assert!(!zeros.ranges[0].eligible());
    }

    /// A `.sbss` section holding `prev.cpp`, optionally `unit.cpp`, and
    /// `next.cpp`, at `base`. `names` overrides the symbols inside `unit.cpp`
    /// and `after` moves the right anchor.
    fn sbss_image(base: u32, unit_split: bool, names: [&str; 3], after: u32) -> MatchTarget {
        let mut splits = ObjSplits::default();
        let mut units = vec![("prev.cpp", 0, 8)];
        if unit_split {
            units.push(("unit.cpp", 8, 0x18));
        }
        units.push(("next.cpp", after, after + 8));
        for (unit, start, end) in units {
            splits.push(base + start, ObjSplit {
                unit: unit.into(),
                end: base + end,
                align: None,
                common: false,
                autogenerated: false,
                skip: false,
                rename: None,
            });
        }
        let symbol = |name: &str, offset: u32, size: u64| ObjSymbol {
            name: name.into(),
            address: u64::from(base + offset),
            section: Some(0),
            size,
            size_known: true,
            kind: ObjSymbolKind::Object,
            ..Default::default()
        };
        let symbols = vec![
            symbol("sPrevious", 0, 4),
            symbol(names[0], 8, 4),
            symbol(names[1], 0xc, 1),
            symbol(names[2], 0x10, 4),
            symbol("sNext", after, 4),
        ];
        MatchTarget::new(
            "image".into(),
            ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc,
                "image".into(),
                symbols,
                vec![ObjSection {
                    name: ".sbss".into(),
                    kind: ObjSectionKind::Bss,
                    address: u64::from(base),
                    size: 0x40,
                    data: vec![],
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

    fn layout_report(source: &MatchTarget, target: &MatchTarget) -> (DataEvidenceReport, usize) {
        let mut report = DataEvidenceReport::build(source, target, &[], &[], "NTSC", "JP");
        let mut proposals = Vec::new();
        report.add_source_layouts(source, target, &[], &mut proposals);
        (report, proposals.len())
    }

    #[test]
    fn a_whole_source_split_maps_by_one_bracketed_delta_including_padding() {
        let source = sbss_image(0x1000, true, ["sCount", "init$12", "lbl_00001010"], 0x18);
        let target = sbss_image(0x1100, false, ["sCount", "init$77", "lbl_00001110"], 0x18);
        let (report, proposed) = layout_report(&source, &target);
        report.validate("NTSC", "JP").unwrap();
        assert_eq!(proposed, 1);
        let [range] = report.ranges.as_slice() else { panic!("one range: {:?}", report.ranges) };
        assert_eq!((range.unit.as_str(), range.start, range.end), ("unit.cpp", 0x1108, 0x1118));
        assert!(range.eligible());
        assert_eq!(range.common_mode(), Some(false));
        assert_eq!(range.split_suffix(), "");
        assert_eq!(range.members.len(), 3);
        assert!(
            range
                .members
                .iter()
                .all(|member| member.target_size_basis == DataSizeBasis::SourceLayoutBracketed)
        );
        let layout = range.source_layout.as_ref().unwrap();
        assert_eq!((layout.delta, layout.before.name.as_str()), (0x100, "sCount"));
        assert_eq!(layout.after.name, "sNext");

        let mut shifted = range.clone();
        shifted.start += 4;
        shifted.end += 4;
        assert!(!shifted.eligible(), "the range must be the source range plus the delta");
        let mut disagreeing = range.clone();
        disagreeing.source_layout.as_mut().unwrap().after.target += 8;
        assert!(!disagreeing.eligible());
        let mut misaligned = range.clone();
        let certificate = misaligned.source_layout.as_mut().unwrap();
        certificate.delta += 4;
        certificate.before.target += 4;
        certificate.after.target += 4;
        misaligned.start += 4;
        misaligned.end += 4;
        misaligned.members.iter_mut().for_each(|member| {
            member.target_start += 4;
            member.target_end += 4;
        });
        assert!(!misaligned.eligible(), "a delta off the split alignment needs aligned edges");
        let mut weak = range.clone();
        weak.members[0].source_weak = true;
        weak.members[0].target_weak = true;
        assert!(weak.eligible(), "the source split placed this unit's weak copy here");
        let mut owned = range.clone();
        owned.members[1].target_owner = Some("other.cpp".into());
        assert!(!owned.eligible());
    }

    #[test]
    fn a_tampered_source_layout_certificate_is_not_eligible() {
        let source = sbss_image(0x1000, true, ["sCount", "init$12", "lbl_00001010"], 0x18);
        let target = sbss_image(0x1100, false, ["sCount", "init$77", "lbl_00001110"], 0x18);
        let (report, _) = layout_report(&source, &target);
        let range = &report.ranges[0];
        let layout = range.source_layout.as_ref().unwrap();
        let tampered = |change: &dyn Fn(&mut DataRangeEvidence)| {
            let mut copy = range.clone();
            change(&mut copy);
            copy.eligible()
        };
        // A left bracket past the split's start brackets nothing.
        assert!(!tampered(&|r| {
            let before = &mut r.source_layout.as_mut().unwrap().before;
            before.source += 4;
            before.target += 4;
        }));
        // Anchors listed out of address order.
        let early = LayoutAnchor {
            name: "sEarly".into(),
            source: layout.before.source - 8,
            target: layout.before.target - 8,
        };
        assert!(!tampered(&|r| r.source_layout.as_mut().unwrap().inside.push(early.clone())));
        // The range must carry the split's own alignment.
        assert!(!tampered(&|r| r.required_alignment *= 2));
        // Only BSS may be common.
        assert!(!tampered(&|r| {
            r.section = ".data".into();
            r.source_layout.as_mut().unwrap().common = true;
        }));
        // A BSS interior check does not certify initialized data.
        assert!(!tampered(&|r| r.section = ".data".into()));
        assert!(!tampered(&|r| {
            r.source_layout.as_mut().unwrap().interior = LayoutInterior::IdenticalBytes;
        }));
    }

    #[test]
    fn a_common_source_split_maps_with_its_attributes() {
        let mut source = sbss_image(0x1000, true, ["sCount", "init$12", "lbl_00001010"], 0x18);
        let target = sbss_image(0x1100, false, ["sCount", "init$77", "lbl_00001110"], 0x18);
        let section = source.obj.sections.get_mut(0).unwrap();
        let (_, split) = section.splits.iter_mut().find(|(_, s)| s.unit == "unit.cpp").unwrap();
        split.common = true;
        let (report, proposed) = layout_report(&source, &target);
        assert_eq!(proposed, 1);
        let range = &report.ranges[0];
        assert!(range.eligible());
        assert_eq!(range.common_mode(), Some(true));
        let align = range.source_layout.as_ref().unwrap().align;
        assert_eq!(range.split_suffix(), format!(" align:{align} common"));
    }

    #[test]
    fn a_source_layout_never_overlaps_another_units_target_split() {
        let source = sbss_image(0x1000, true, ["sCount", "init$12", "lbl_00001010"], 0x18);
        let mut target = sbss_image(0x1100, false, ["sCount", "init$77", "lbl_00001110"], 0x18);
        let section = target.obj.sections.get_mut(0).unwrap();
        section.splits.push(0x1110, ObjSplit {
            unit: "other.cpp".into(),
            end: 0x1114,
            align: None,
            common: false,
            autogenerated: false,
            skip: false,
            rename: None,
        });
        let (report, proposed) = layout_report(&source, &target);
        assert!(report.ranges.is_empty(), "{:?}", report.ranges);
        assert_eq!(proposed, 0);
    }

    /// One section at 0x1000 with the given symbols (name, offset, size),
    /// splits (unit, start, end) and bytes.
    fn pool_image(
        name: &str,
        kind: ObjSectionKind,
        symbols: &[(&str, u32, u64)],
        units: &[(&str, u32, u32)],
        data: Vec<u8>,
    ) -> MatchTarget {
        let base = 0x1000;
        let mut splits = ObjSplits::default();
        for &(unit, start, end) in units {
            splits.push(base + start, ObjSplit {
                unit: unit.into(),
                end: base + end,
                align: None,
                common: false,
                autogenerated: false,
                skip: false,
                rename: None,
            });
        }
        let symbols = symbols
            .iter()
            .map(|&(name, offset, size)| ObjSymbol {
                name: name.into(),
                address: u64::from(base + offset),
                section: Some(0),
                size,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            })
            .collect();
        MatchTarget::new(
            "image".into(),
            ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc,
                "image".into(),
                symbols,
                vec![ObjSection {
                    name: name.into(),
                    kind,
                    address: u64::from(base),
                    size: 0x20,
                    data,
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

    /// Eight distinct 4-byte constants.
    fn constants(values: [u8; 8]) -> Vec<u8> {
        values.iter().flat_map(|&value| [0x3f, value, 0, 0]).collect()
    }

    #[test]
    fn a_literal_pool_shifted_between_neighbours_is_refused_by_its_bytes() {
        // The previous unit's pool grew by one constant and this unit's
        // shrank by one: both anchors kept their addresses, and every target
        // label still starts where a source label starts.
        let source = pool_image(
            ".sdata2",
            ObjSectionKind::ReadOnlyData,
            &[
                ("sPrev", 0, 4),
                ("@1", 4, 4),
                ("@2", 8, 4),
                ("@3", 0xc, 4),
                ("@4", 0x10, 4),
                ("@5", 0x14, 4),
                ("sNext", 0x18, 4),
            ],
            &[("prev.cpp", 0, 0x10), ("unit.cpp", 0x10, 0x18), ("next.cpp", 0x18, 0x20)],
            constants([1, 2, 3, 4, 5, 6, 7, 8]),
        );
        let shifted = pool_image(
            ".sdata2",
            ObjSectionKind::ReadOnlyData,
            &[
                ("sPrev", 0, 4),
                ("@11", 4, 4),
                ("@12", 8, 4),
                ("@13", 0xc, 4),
                ("@14", 0x10, 4),
                ("@15", 0x14, 4),
                ("sNext", 0x18, 4),
            ],
            &[("next.cpp", 0x18, 0x20)],
            constants([1, 2, 3, 4, 9, 5, 7, 8]),
        );
        let unit = |report: DataEvidenceReport| -> Vec<DataRangeEvidence> {
            report.ranges.into_iter().filter(|range| range.unit == "unit.cpp").collect()
        };
        assert!(unit(layout_report(&source, &shifted).0).is_empty());
        // The same layout with the same constants is certified by its bytes.
        let same = pool_image(
            ".sdata2",
            ObjSectionKind::ReadOnlyData,
            &[
                ("sPrev", 0, 4),
                ("@11", 4, 4),
                ("@12", 8, 4),
                ("@13", 0xc, 4),
                ("@14", 0x10, 4),
                ("@15", 0x14, 4),
                ("sNext", 0x18, 4),
            ],
            &[("next.cpp", 0x18, 0x20)],
            constants([1, 2, 3, 4, 5, 6, 7, 8]),
        );
        let ranges = unit(layout_report(&source, &same).0);
        let [range] = ranges.as_slice() else { panic!("{ranges:?}") };
        assert_eq!((range.start, range.end), (0x1010, 0x1018));
        assert!(range.eligible());
        let layout = range.source_layout.as_ref().unwrap();
        assert_eq!(layout.interior, LayoutInterior::IdenticalBytes);
        // Zeros prove nothing about where a pool starts.
        let zeros = |symbols: &[(&str, u32, u64)], units: &[(&str, u32, u32)]| {
            pool_image(".sdata2", ObjSectionKind::ReadOnlyData, symbols, units, vec![0; 0x20])
        };
        let symbols = [("sPrev", 0, 4), ("@4", 0x10, 4), ("@5", 0x14, 4), ("sNext", 0x18, 4)];
        let ranges = unit(
            layout_report(
                &zeros(&symbols, &[
                    ("prev.cpp", 0, 0x10),
                    ("unit.cpp", 0x10, 0x18),
                    ("next.cpp", 0x18, 0x20),
                ]),
                &zeros(&symbols, &[("next.cpp", 0x18, 0x20)]),
            )
            .0,
        );
        assert!(ranges.is_empty(), "{ranges:?}");
    }

    fn unit_ranges(report: DataEvidenceReport) -> Vec<DataRangeEvidence> {
        report.ranges.into_iter().filter(|range| range.unit == "unit.cpp").collect()
    }

    const POOL: [(&str, u32, u64); 7] = [
        ("sPrev", 0, 4),
        ("@1", 4, 4),
        ("@2", 8, 4),
        ("@3", 0xc, 4),
        ("@4", 0x10, 4),
        ("@5", 0x14, 4),
        ("sNext", 0x18, 4),
    ];
    const POOL_UNITS: [(&str, u32, u32); 3] =
        [("prev.cpp", 0, 0x10), ("unit.cpp", 0x10, 0x18), ("next.cpp", 0x18, 0x20)];

    #[test]
    fn a_pool_of_equal_constants_matches_too_many_positions_to_be_certified() {
        // 1.0f everywhere in the pools: the bytes match at the claimed delta
        // and one word either side, so they do not fix the boundary.
        let mut values = [0x80; 8];
        values[0] = 1;
        values[6] = 2;
        let pool = |units: &[(&str, u32, u32)]| {
            pool_image(".sdata2", ObjSectionKind::ReadOnlyData, &POOL, units, constants(values))
        };
        let target = pool(&[("next.cpp", 0x18, 0x20)]);
        assert!(unit_ranges(layout_report(&pool(&POOL_UNITS), &target).0).is_empty());
    }

    #[test]
    fn a_pointer_table_needs_its_addends_and_a_unique_position() {
        // Every word points into sPrev; only the addends tell the entries apart.
        let table = |units: &[(&str, u32, u32)], addends: [i64; 5]| {
            let mut image =
                pool_image(".sdata", ObjSectionKind::Data, &POOL, units, constants([0; 8]));
            let section = image.obj.sections.get_mut(0).unwrap();
            for (index, addend) in addends.into_iter().enumerate() {
                section
                    .relocations
                    .insert(0x1004 + 4 * index as u32, decomp_toolkit::obj::ObjReloc {
                        kind: ObjRelocKind::Absolute,
                        target_symbol: 0,
                        addend,
                        module: None,
                    })
                    .unwrap();
            }
            image
        };
        let source = table(&POOL_UNITS, [0, 4, 8, 0xc, 0x10]);
        let target = |addends| table(&[("next.cpp", 0x18, 0x20)], addends);
        // The previous unit's table grew by an entry and this unit's shrank.
        let shifted = target([0, 4, 8, 0xc, 0xc]);
        assert!(unit_ranges(layout_report(&source, &shifted).0).is_empty());
        // The same table, with addends that differ word to word, is certified.
        let ranges = unit_ranges(layout_report(&source, &target([0, 4, 8, 0xc, 0x10])).0);
        let [range] = ranges.as_slice() else { panic!("{ranges:?}") };
        assert_eq!((range.start, range.end), (0x1010, 0x1018));
        // A table of equal entries matches at every word.
        let equal = table(&POOL_UNITS, [8; 5]);
        assert!(
            unit_ranges(layout_report(&equal, &table(&[("next.cpp", 0x18, 0x20)], [8; 5])).0)
                .is_empty()
        );
    }

    #[test]
    fn a_bss_layout_needs_a_named_member_and_equal_sizes() {
        let units = [("prev.cpp", 0, 0x10), ("unit.cpp", 0x10, 0x18), ("next.cpp", 0x18, 0x20)];
        let bss = |symbols: &[(&str, u32, u64)], units: &[(&str, u32, u32)]| {
            pool_image(".sbss", ObjSectionKind::Bss, symbols, units, Vec::new())
        };
        // Only placeholders inside: a shifted pool of words looks the same.
        let unnamed = bss(
            &[
                ("sPrev", 0, 4),
                ("lbl_00001010", 0x10, 4),
                ("lbl_00001014", 0x14, 4),
                ("sNext", 0x18, 4),
            ],
            &units,
        );
        let target = bss(
            &[
                ("sPrev", 0, 4),
                ("lbl_80001010", 0x10, 4),
                ("lbl_80001014", 0x14, 4),
                ("sNext", 0x18, 4),
            ],
            &[("next.cpp", 0x18, 0x20)],
        );
        let unit = |report: DataEvidenceReport| -> Vec<DataRangeEvidence> {
            report.ranges.into_iter().filter(|range| range.unit == "unit.cpp").collect()
        };
        assert!(unit(layout_report(&unnamed, &target).0).is_empty());
        // A member named alike in both versions fixes the interior.
        let named = bss(
            &[("sPrev", 0, 4), ("sUnit", 0x10, 4), ("lbl_00001014", 0x14, 4), ("sNext", 0x18, 4)],
            &units,
        );
        let named_target = bss(
            &[("sPrev", 0, 4), ("sUnit", 0x10, 4), ("lbl_80001014", 0x14, 4), ("sNext", 0x18, 4)],
            &[("next.cpp", 0x18, 0x20)],
        );
        let ranges = unit(layout_report(&named, &named_target).0);
        let [range] = ranges.as_slice() else { panic!("{ranges:?}") };
        assert!(range.eligible());
        assert_eq!(range.source_layout.as_ref().unwrap().interior, LayoutInterior::NamedBssMember);
        // A placeholder paired by address whose size changed is a layout change.
        let resized = bss(
            &[("sPrev", 0, 4), ("sUnit", 0x10, 4), ("lbl_80001014", 0x14, 2), ("sNext", 0x18, 4)],
            &[("next.cpp", 0x18, 0x20)],
        );
        assert!(unit(layout_report(&named, &resized).0).is_empty());
        // An interior reference needs its containing object in the target too.
        let orphan = bss(
            &[("sPrev", 0, 4), ("sUnit", 0x10, 4), ("lbl_80001016", 0x16, 2), ("sNext", 0x18, 4)],
            &[("next.cpp", 0x18, 0x20)],
        );
        assert!(unit(layout_report(&named, &orphan).0).is_empty());
        let contained = bss(
            &[
                ("sPrev", 0, 4),
                ("sUnit", 0x10, 4),
                ("lbl_80001014", 0x14, 4),
                ("lbl_80001016", 0x16, 2),
                ("sNext", 0x18, 4),
            ],
            &[("next.cpp", 0x18, 0x20)],
        );
        assert_eq!(unit(layout_report(&named, &contained).0).len(), 1);
    }

    #[test]
    fn a_units_second_layout_range_in_a_section_is_kept() {
        let symbols = [
            ("sPrev", 0, 4),
            ("sFirst", 8, 4),
            ("sMid", 0x10, 4),
            ("sSecond", 0x14, 4),
            ("sNext", 0x18, 4),
        ];
        let source = pool_image(
            ".sbss",
            ObjSectionKind::Bss,
            &symbols,
            &[
                ("prev.cpp", 0, 8),
                ("unit.cpp", 8, 0x10),
                ("mid.cpp", 0x10, 0x14),
                ("unit.cpp", 0x14, 0x18),
                ("next.cpp", 0x18, 0x20),
            ],
            Vec::new(),
        );
        let target = pool_image(
            ".sbss",
            ObjSectionKind::Bss,
            &symbols,
            &[("next.cpp", 0x18, 0x20)],
            Vec::new(),
        );
        let (report, _) = layout_report(&source, &target);
        let unit: Vec<(u32, u32)> = report
            .ranges
            .iter()
            .filter(|range| range.unit == "unit.cpp")
            .map(|range| (range.start, range.end))
            .collect();
        assert_eq!(unit, [(0x1008, 0x1010), (0x1014, 0x1018)]);
    }

    #[test]
    fn a_source_layout_needs_agreeing_anchors_and_a_corresponding_interior() {
        let source = sbss_image(0x1000, true, ["sCount", "init$12", "lbl_00001010"], 0x18);
        // The right anchor moved: something between the brackets changed size.
        let moved = sbss_image(0x1100, false, ["sCount", "init$12", "lbl_00001110"], 0x20);
        assert!(layout_report(&source, &moved).0.ranges.is_empty());
        // A real target name where the source has a different real name.
        let foreign = sbss_image(0x1100, false, ["sOther", "init$12", "lbl_00001110"], 0x18);
        assert!(layout_report(&source, &foreign).0.ranges.is_empty());
        // A real target name where the source only has a placeholder.
        let named = sbss_image(0x1100, false, ["sCount", "init$12", "sNamedLater"], 0x18);
        assert_eq!(layout_report(&source, &named).0.ranges.len(), 1);
        // The target already has a split for the unit there.
        let split = sbss_image(0x1100, true, ["sCount", "init$12", "lbl_00001110"], 0x18);
        assert!(layout_report(&source, &split).0.ranges.is_empty());
    }

    #[test]
    fn layout_mapping_keeps_both_edges_out_of_target_symbols() {
        let symbol = |name: &str, address: u32, size: Option<u32>| LayoutSymbol {
            name: name.into(),
            section: ".data".into(),
            address,
            size,
        };
        let source = [
            symbol("left", 0x100, Some(8)),
            symbol("held", 0x108, Some(8)),
            symbol("right", 0x110, Some(8)),
        ];
        let target = [
            symbol("left", 0x200, Some(8)),
            symbol("held", 0x208, Some(8)),
            symbol("right", 0x210, Some(8)),
        ];
        let span = (0x100, 0x118);
        let index = LayoutIndex::new(&source, &target);
        let mapping = index.map(".data", 0x108, 0x110, span).unwrap();
        assert_eq!((mapping.start, mapping.end, mapping.delta), (0x208, 0x210, 0x100));
        assert_eq!(mapping.members, [(1, 1)]);
        let straddling = [
            symbol("left", 0x200, Some(0xc)),
            symbol("held", 0x208, Some(8)),
            symbol("right", 0x210, Some(8)),
        ];
        assert!(LayoutIndex::new(&source, &straddling).map(".data", 0x108, 0x110, span).is_none());
        // Without an anchor at or after the end there is no right bracket.
        assert!(index.map(".data", 0x110, 0x118, span).is_none());
        // Anchors outside the adjacent splits bound too long a stretch.
        assert!(index.map(".data", 0x108, 0x110, (0x10c, 0x118)).is_none());
        assert!(index.map(".data", 0x108, 0x110, (0x100, 0x10c)).is_none());
    }

    fn data_symbol(name: &str, address: u32, size: Option<u32>) -> LayoutSymbol {
        LayoutSymbol { name: name.into(), section: ".data".into(), address, size }
    }

    #[test]
    fn a_target_reference_into_source_padding_is_a_layout_change() {
        let source = [
            data_symbol("left", 0x100, Some(4)),
            data_symbol("lbl_00000108", 0x108, Some(4)),
            data_symbol("right", 0x110, Some(8)),
        ];
        // 0x104..0x108 is padding in the source; the target references it.
        let padded = [
            data_symbol("left", 0x200, Some(4)),
            data_symbol("lbl_00000204", 0x204, Some(4)),
            data_symbol("lbl_00000208", 0x208, Some(4)),
            data_symbol("right", 0x210, Some(8)),
        ];
        let span = (0x100, 0x118);
        assert!(LayoutIndex::new(&source, &padded).map(".data", 0x108, 0x110, span).is_none());
        // Inside a sized source object it is an interior reference.
        let interior = [
            data_symbol("left", 0x200, Some(4)),
            data_symbol("lbl_00000208", 0x208, Some(4)),
            data_symbol("lbl_0000020A", 0x20a, None),
            data_symbol("right", 0x210, Some(8)),
        ];
        let mapping =
            LayoutIndex::new(&source, &interior).map(".data", 0x108, 0x110, span).unwrap();
        assert_eq!(mapping.members, [(1, 1)]);
        // A numbered label that starts where a source symbol starts pairs with it.
        let labelled = [
            data_symbol("left", 0x200, Some(4)),
            data_symbol("@123", 0x208, Some(4)),
            data_symbol("right", 0x210, Some(8)),
        ];
        let mapping =
            LayoutIndex::new(&source, &labelled).map(".data", 0x108, 0x110, span).unwrap();
        assert_eq!(mapping.members, [(1, 1)]);
    }

    #[test]
    fn the_whole_bracket_must_correspond_not_only_the_mapped_range() {
        let source = [
            data_symbol("left", 0x100, Some(4)),
            data_symbol("sOld", 0x104, Some(4)),
            data_symbol("lbl_00000108", 0x108, Some(4)),
            data_symbol("right", 0x110, Some(8)),
        ];
        let target = [
            data_symbol("left", 0x200, Some(4)),
            data_symbol("sNew", 0x204, Some(4)),
            data_symbol("lbl_00000208", 0x208, Some(4)),
            data_symbol("right", 0x210, Some(8)),
        ];
        let span = (0x100, 0x118);
        let index = LayoutIndex::new(&source, &target);
        assert!(
            index.map(".data", 0x108, 0x110, span).is_none(),
            "a different real name between the left anchor and the range"
        );
        let renamed = [
            data_symbol("left", 0x200, Some(4)),
            data_symbol("lbl_00000204", 0x204, Some(4)),
            data_symbol("lbl_00000208", 0x208, Some(4)),
            data_symbol("right", 0x210, Some(8)),
        ];
        let mapping = LayoutIndex::new(&source, &renamed).map(".data", 0x108, 0x110, span).unwrap();
        assert_eq!(mapping.members, [(2, 2)], "only symbols in the range are members");
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

        // A relative directory, so the reference has to make it absolute.
        // CARGO_TARGET_DIR may point elsewhere, so ./target need not exist yet.
        std::fs::create_dir_all("target").unwrap();
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
