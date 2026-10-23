//! Pairing the data two objects reference through function bodies that are
//! identical.
//!
//! A unit that is nearly done has a compiled source object whose functions
//! carry the same instructions as the target's, apart from the relocated
//! operands. Those operands then say exactly what the source symbols are in the
//! target: the n-th relocation of a source function and the n-th relocation of
//! its target twin name the same object, at the same offset into it. Nothing
//! about the data itself has to be guessed.
//!
//! From the pairs this module reads two things:
//!
//! - **Symbols.** A source symbol whose every reference lands on one target
//!   address, where no other source symbol does, has that address's symbol as
//!   its counterpart. Its name, size and section can name the target symbol.
//! - **Sections.** All references into one section of the source object share
//!   a single delta from the source offset to the target address exactly when
//!   the target kept the compiler's layout. Then the whole section occupies one
//!   contiguous target range, which is what a data split needs.
//!
//! The pairing is conservative by construction. A function is paired only when
//! its bytes agree with relocated fields masked and its relocations agree in
//! number, offset and kind. A symbol or section is dropped, with its reason
//! recorded, when its references disagree, when two source symbols claim one
//! target address, when sections, sizes or alignments cannot be the same
//! object, or when the initialized bytes differ.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use anyhow::{Result, ensure};
use objdiff_core::obj::{Object, RelocationFlags, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};

use crate::matching::data_evidence::LayoutSymbol;

/// The initialized contents of a DOL, by address.
///
/// Reading these is the only way to compare data the target object does not
/// contain: a unit that has no split for a section has no bytes of it either.
#[derive(Debug, Clone)]
pub struct DolImage {
    sections: Vec<(u32, Vec<u8>)>,
}

impl DolImage {
    pub fn read(path: &Path) -> Result<Self> { Self::parse(&std::fs::read(path)?) }

    /// The main executable of a project's version, wherever its `config.yml`
    /// keeps the original: beside the project, or under an object base.
    pub fn of_version(root: &Path, version: &str) -> Option<Self> {
        let config = crate::project::config::read_config(root, version).ok()?;
        let object = config.base.object.as_str();
        let beside = config.object_base.as_ref().map(|base| root.join(base.as_str()));
        [Some(root.to_path_buf()), beside]
            .into_iter()
            .flatten()
            .map(|base| base.join(object))
            .find(|path| path.is_file())
            .and_then(|path| Self::read(&path).ok())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 0x100, "DOL header is truncated");
        let word = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        let mut sections = Vec::new();
        for index in 0..18 {
            let (offset, address, size) =
                (word(4 * index), word(0x48 + 4 * index), word(0x90 + 4 * index));
            if size == 0 {
                continue;
            }
            let end = offset as usize + size as usize;
            ensure!(end <= bytes.len(), "DOL section {index} runs past the file");
            sections.push((address, bytes[offset as usize..end].to_vec()));
        }
        Ok(Self { sections })
    }

    /// `length` bytes at `address`, when one section holds them all.
    pub fn bytes(&self, address: u32, length: u32) -> Option<&[u8]> {
        let end = u64::from(address) + u64::from(length);
        self.sections.iter().find_map(|(start, data)| {
            let (start, section_end) = (u64::from(*start), u64::from(*start) + data.len() as u64);
            (u64::from(address) >= start && end <= section_end)
                .then(|| &data[(u64::from(address) - start) as usize..(end - start) as usize])
        })
    }
}

/// The target's data symbols, found by address or by name.
///
/// The target object names what it references only as far as `symbols.txt`
/// does, so this is the authority on the section, extent and name of the symbol
/// at an address.
pub struct TargetIndex<'a> {
    symbols: &'a [LayoutSymbol],
    by_address: BTreeMap<u32, Vec<usize>>,
    by_name: HashMap<&'a str, Vec<usize>>,
}

impl<'a> TargetIndex<'a> {
    pub fn new(symbols: &'a [LayoutSymbol]) -> Self {
        let mut by_address: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
        for (index, symbol) in symbols.iter().enumerate() {
            by_address.entry(symbol.address).or_default().push(index);
            by_name.entry(symbol.name.as_str()).or_default().push(index);
        }
        Self { symbols, by_address, by_name }
    }

    /// The one data symbol at `address`.
    pub fn at(&self, address: u32) -> Option<&'a LayoutSymbol> {
        match self.by_address.get(&address)?.as_slice() {
            [only] => Some(&self.symbols[*only]),
            _ => None,
        }
    }

    /// The address of the symbol an extracted object spells `name`. dtk
    /// appends `_<ADDRESS>` to a local name that two symbols share.
    fn address_of(&self, name: &str) -> Option<u32> {
        let unique = |candidates: &Vec<usize>| match candidates.as_slice() {
            [only] => Some(self.symbols[*only].address),
            _ => None,
        };
        if let Some(found) = self.by_name.get(name).and_then(unique) {
            return Some(found);
        }
        let (base, suffix) = name.rsplit_once('_')?;
        let address = u32::from_str_radix(suffix, 16).ok().filter(|_| suffix.len() == 8)?;
        let symbol = self.at(address)?;
        (symbol.name == base).then_some(address)
    }
}

/// What comparing a symbol's or a section's initialized bytes with the
/// target's showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BytesCheck {
    /// Equal, apart from the fields a relocation fills in.
    Equal,
    /// Uninitialized data, or an external symbol with no bytes of its own.
    NotApplicable,
    /// No target image was available to compare against.
    Unchecked,
}

/// A source symbol and the target symbol it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedSymbol {
    pub source: String,
    /// The source object's section, or `None` for a symbol it only references.
    pub source_section: Option<String>,
    pub target: String,
    pub target_section: String,
    pub target_address: u32,
    pub size: Option<u32>,
    pub references: usize,
    pub functions: usize,
    pub bytes: BytesCheck,
}

/// A section of the source object, and the contiguous target range it fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedSection {
    pub section: String,
    pub start: u32,
    /// `start` plus the source section's size, rounded up to its alignment.
    pub end: u32,
    pub source_size: u32,
    pub align: u32,
    pub references: usize,
    pub bytes: BytesCheck,
    /// The range is the extent of the individually paired symbols, because the
    /// section's references do not share one offset (a reordered pool).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reordered: bool,
}

/// A symbol or section the pairing declined, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejection {
    pub subject: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pairing {
    /// Source functions with a target twin whose bytes and relocations agree.
    pub functions: usize,
    pub symbols: Vec<PairedSymbol>,
    pub sections: Vec<PairedSection>,
    pub rejected: Vec<Rejection>,
}

/// One function's bytes with relocated fields cleared, and its relocations.
struct Body {
    name: String,
    bytes: Vec<u8>,
    relocations: Vec<Site>,
}

#[derive(Clone)]
struct Site {
    offset: u64,
    kind: u32,
    symbol: usize,
    addend: i64,
}

/// The bits of the word a relocation of this ELF kind fills in.
fn field_mask(kind: u32) -> Option<u32> {
    match kind {
        1 | 26 => Some(u32::MAX),        // ADDR32, REL32
        2 | 10 => Some(0x03FF_FFFC),     // ADDR24, REL24
        3..=6 => Some(0xFFFF),           // ADDR16 and its LO/HI/HA forms
        7..=9 | 11..=13 => Some(0xFFFC), // ADDR14, REL14 and their hinted forms
        109 => Some(0x001F_FFFF),        // EMB_SDA21
        _ => None,
    }
}

fn elf_kind(flags: RelocationFlags) -> Option<u32> {
    match flags {
        RelocationFlags::Elf(kind) => Some(kind),
        _ => None,
    }
}

/// `bytes` with every relocated field cleared. `base` is the offset of
/// `bytes[0]` in its section. Returns `None` for an unknown relocation kind.
fn cleared(bytes: &[u8], base: u64, sites: &[Site]) -> Option<Vec<u8>> {
    let mut out = bytes.to_vec();
    for site in sites {
        let mask = field_mask(site.kind)?;
        let at = (site.offset - base) as usize;
        if mask == u32::MAX {
            out.get_mut(at..at + 4)?.fill(0);
        } else {
            let word = at & !3;
            let current = u32::from_be_bytes(out.get(word..word + 4)?.try_into().ok()?);
            out[word..word + 4].copy_from_slice(&(current & !mask).to_be_bytes());
        }
    }
    Some(out)
}

fn bodies(object: &Object) -> Vec<Body> {
    let mut found = Vec::new();
    for symbol in &object.symbols {
        if symbol.kind != SymbolKind::Function || symbol.size == 0 {
            continue;
        }
        let Some(section) = symbol.section.and_then(|index| object.sections.get(index)) else {
            continue;
        };
        if section.kind != SectionKind::Code {
            continue;
        }
        let (start, end) = (symbol.address, symbol.address + symbol.size);
        let Some(raw) = section.data.get(start as usize..end as usize) else { continue };
        let sites: Option<Vec<Site>> = section
            .relocations
            .iter()
            .filter(|relocation| relocation.address >= start && relocation.address < end)
            // A NONE relocation fills nothing and says nothing about what the
            // function is: mwcc and dtk each emit them where the other does not.
            .filter(|relocation| elf_kind(relocation.flags) != Some(0))
            .map(|relocation| {
                Some(Site {
                    // mwcc places a 16-bit field two bytes into its instruction and
                    // dtk at its start, so the instruction identifies the site.
                    offset: relocation.address & !3,
                    kind: elf_kind(relocation.flags)?,
                    symbol: relocation.target_symbol,
                    addend: relocation.addend,
                })
            })
            .collect();
        let Some(mut sites) = sites else { continue };
        sites.sort_by_key(|site| site.offset);
        let Some(bytes) = cleared(raw, start, &sites) else { continue };
        for site in &mut sites {
            site.offset -= start;
        }
        found.push(Body { name: symbol.name.clone(), bytes, relocations: sites });
    }
    found
}

/// The signature two twins share: everything about a function except what its
/// relocations point at.
fn signature(body: &Body) -> (&[u8], Vec<(u64, u32)>) {
    (&body.bytes, body.relocations.iter().map(|site| (site.offset, site.kind)).collect())
}

/// Source and target functions that are the same function.
fn twins<'a>(source: &'a [Body], target: &'a [Body]) -> Vec<(&'a Body, &'a Body)> {
    let mut by_signature: HashMap<_, (Vec<&Body>, Vec<&Body>)> = HashMap::new();
    for body in source {
        by_signature.entry(signature(body)).or_default().0.push(body);
    }
    for body in target {
        by_signature.entry(signature(body)).or_default().1.push(body);
    }
    let mut pairs = Vec::new();
    for (_, (sources, targets)) in by_signature {
        match (sources.as_slice(), targets.as_slice()) {
            ([one], [other]) => pairs.push((*one, *other)),
            (sources, targets) => {
                // Interchangeable bodies are told apart only by name, and only
                // where each name is unique on both sides.
                for body in sources {
                    let same_name = |candidates: &[&Body]| {
                        candidates.iter().filter(|other| other.name == body.name).count()
                    };
                    if same_name(sources) == 1 && same_name(targets) == 1 {
                        let other = targets.iter().find(|other| other.name == body.name).unwrap();
                        pairs.push((*body, *other));
                    }
                }
            }
        }
    }
    pairs.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    pairs
}

/// What one reference says about a source symbol.
#[derive(Default)]
struct Evidence {
    /// Each distinct counterpart address, with how many references say so.
    bases: BTreeMap<i64, usize>,
    functions: BTreeSet<String>,
    references: usize,
}

/// The target address an extracted object's symbol stands for.
fn target_address(object: &Object, index: usize, targets: &TargetIndex) -> Option<u32> {
    let symbol = object.symbols.get(index)?;
    if let Some(address) = symbol.virtual_address.filter(|&address| address != 0) {
        return u32::try_from(address).ok();
    }
    if symbol.section.is_none() && symbol.address != 0 {
        return u32::try_from(symbol.address).ok();
    }
    targets.address_of(&symbol.name)
}

/// Whether a section name holds initialized data.
fn initialized(section: &str) -> bool { !matches!(section, ".bss" | ".sbss" | ".sbss2") }

/// Pairs what the functions of `source` and `target` reference.
///
/// `image`, when given, supplies the target's initialized bytes; without it
/// nothing is claimed to have been compared.
pub fn pair(
    source: &Object,
    target: &Object,
    targets: &TargetIndex,
    image: Option<&DolImage>,
) -> Pairing {
    let (source_bodies, target_bodies) = (bodies(source), bodies(target));
    let pairs = twins(&source_bodies, &target_bodies);
    let mut result = Pairing { functions: pairs.len(), ..Pairing::default() };

    let mut symbols: BTreeMap<usize, Evidence> = BTreeMap::new();
    // Per source section: each delta from a source offset to a target address,
    // and the target section names the references landed in.
    let mut sections: BTreeMap<usize, (BTreeMap<i64, usize>, BTreeSet<String>)> = BTreeMap::new();
    for (from, to) in pairs {
        for (source_site, target_site) in from.relocations.iter().zip(&to.relocations) {
            let Some(base) = target_address(target, target_site.symbol, targets) else { continue };

            let Some(landed) =
                u32::try_from(i64::from(base) + target_site.addend).ok().and_then(|address| {
                    // A reference lands inside a symbol, or on its first byte.
                    targets.at(address).or_else(|| targets.at(base))
                })
            else {
                continue;
            };
            let Some(source_symbol) = source.symbols.get(source_site.symbol) else { continue };
            let evidence = symbols.entry(source_site.symbol).or_default();
            evidence.references += 1;
            evidence.functions.insert(from.name.clone());
            *evidence
                .bases
                .entry(i64::from(base) + target_site.addend - source_site.addend)
                .or_default() += 1;
            if let Some(section) = source_symbol.section {
                let offset = source_symbol.address as i64 + source_site.addend;
                let entry = sections.entry(section).or_default();
                *entry.0.entry(i64::from(base) + target_site.addend - offset).or_default() += 1;
                entry.1.insert(landed.section.clone());
            }
        }
    }

    pair_symbols(source, target, targets, image, &symbols, &mut result);
    pair_sections(source, image, &sections, &mut result);
    result.symbols.sort_by_key(|a| a.target_address);
    result.sections.sort_by_key(|a| a.start);
    result
}

fn pair_symbols(
    source: &Object,
    _target: &Object,
    targets: &TargetIndex,
    image: Option<&DolImage>,
    symbols: &BTreeMap<usize, Evidence>,
    result: &mut Pairing,
) {
    // Candidate (source symbol, target base address) pairs, before the check
    // that no two source symbols share an address.
    let mut candidates: Vec<(usize, i64, &Evidence)> = Vec::new();
    for (&index, evidence) in symbols {
        let symbol = &source.symbols[index];
        if symbol.name.is_empty() || symbol.kind == SymbolKind::Section {
            continue;
        }
        match evidence.bases.len() {
            1 => candidates.push((index, *evidence.bases.keys().next().unwrap(), evidence)),
            _ => result.rejected.push(Rejection {
                subject: symbol.name.clone(),
                reason: format!(
                    "its references land at {} different target addresses",
                    evidence.bases.len()
                ),
            }),
        }
    }
    let mut claimed: BTreeMap<i64, usize> = BTreeMap::new();
    for (_, base, _) in &candidates {
        *claimed.entry(*base).or_default() += 1;
    }
    for (index, base, evidence) in candidates {
        let symbol = &source.symbols[index];
        let reject = |reason: String, result: &mut Pairing| {
            result.rejected.push(Rejection { subject: symbol.name.clone(), reason });
        };
        let Some(address) = u32::try_from(base).ok() else { continue };
        let Some(counterpart) = targets.at(address) else {
            // A reference into the middle of a larger object has no symbol of
            // its own to pair.
            continue;
        };
        if claimed[&base] > 1 {
            reject(format!("another source symbol also maps to {address:#010X}"), result);
            continue;
        }
        let section = symbol.section.and_then(|section| source.sections.get(section));
        if let Some(section) = section
            && section.name != counterpart.section
        {
            reject(
                format!(
                    "it is in {} but {} is in {}",
                    section.name, counterpart.name, counterpart.section
                ),
                result,
            );
            continue;
        }
        let size = (symbol.size > 0).then_some(symbol.size as u32);
        if let (Some(size), Some(known)) = (size, counterpart.size)
            && section.is_some()
            && !(size..=size.next_multiple_of(8)).contains(&known)
        {
            // symbols.txt may state a size padded to the next 8 bytes.
            reject(
                format!("its size {size:#x} differs from {}'s {known:#x}", counterpart.name),
                result,
            );
            continue;
        }
        if let Some(align) = symbol.align
            && address % align.get() != 0
        {
            reject(format!("{address:#010X} is not aligned to {}", align.get()), result);
            continue;
        }
        let bytes = match (section, size) {
            (Some(section), Some(size)) if section.kind == SectionKind::Data => {
                match check_bytes(source, section, symbol.address, size, address, image) {
                    Err(mismatch) => {
                        reject(mismatch, result);
                        continue;
                    }
                    Ok(check) => check,
                }
            }
            _ => BytesCheck::NotApplicable,
        };
        result.symbols.push(PairedSymbol {
            source: symbol.name.clone(),
            source_section: section.map(|section| section.name.clone()),
            target: counterpart.name.clone(),
            target_section: counterpart.section.clone(),
            target_address: address,
            size,
            references: evidence.references,
            functions: evidence.functions.len(),
            bytes,
        });
    }
}

/// Compares `size` bytes of a source section, from `offset`, with the target
/// image at `address`, ignoring every field a relocation fills in.
fn check_bytes(
    source: &Object,
    section: &objdiff_core::obj::Section,
    offset: u64,
    size: u32,
    address: u32,
    image: Option<&DolImage>,
) -> std::result::Result<BytesCheck, String> {
    let _ = source;
    let Some(image) = image else { return Ok(BytesCheck::Unchecked) };
    let Some(target) = image.bytes(address, size) else {
        return Err(format!("{address:#010X}..+{size:#x} is not initialized data of the target"));
    };
    let Some(ours) = section.data.get(offset as usize..offset as usize + size as usize) else {
        return Err("its bytes are outside the source section".into());
    };
    let relocated: Vec<(usize, usize)> = section
        .relocations
        .iter()
        .filter(|relocation| {
            relocation.address >= offset && relocation.address < offset + u64::from(size)
        })
        .map(|relocation| ((relocation.address - offset) as usize, 4))
        .collect();
    if equal_outside(ours, target, &relocated) {
        Ok(BytesCheck::Equal)
    } else {
        Err(format!("its bytes differ from the target's at {address:#010X}"))
    }
}

fn equal_outside(left: &[u8], right: &[u8], holes: &[(usize, usize)]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).enumerate().all(|(at, (a, b))| {
            a == b || holes.iter().any(|&(start, length)| at >= start && at < start + length)
        })
}

fn pair_sections(
    source: &Object,
    image: Option<&DolImage>,
    sections: &BTreeMap<usize, (BTreeMap<i64, usize>, BTreeSet<String>)>,
    result: &mut Pairing,
) {
    for (&index, (deltas, landed)) in sections {
        let section = &source.sections[index];
        if section.kind == SectionKind::Code || section.size == 0 {
            continue;
        }
        let reject = |reason: String, result: &mut Pairing| {
            result.rejected.push(Rejection { subject: section.name.clone(), reason });
        };
        if landed.iter().any(|name| *name != section.name) {
            reject(
                format!(
                    "its references land in {}",
                    landed.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                result,
            );
            continue;
        }
        if deltas.len() != 1 {
            match reordered(section, &result.symbols, image) {
                Ok(found) => result.sections.push(found),
                Err(why) => reject(
                    format!(
                        "its references use {} different offsets into the target and {why}",
                        deltas.len()
                    ),
                    result,
                ),
            }
            continue;
        }
        let (&delta, &references) = deltas.iter().next().unwrap();
        let (Ok(start), Ok(size)) = (u32::try_from(delta), u32::try_from(section.size)) else {
            continue;
        };
        let align = section.align.map_or(4, |align| align.get() as u32).max(4);
        if !align.is_power_of_two() || start % 4 != 0 {
            reject(format!("{start:#010X} is not aligned to 4"), result);
            continue;
        }
        let end = match end_of(&section.name, start, size, align, image) {
            Ok(end) => end,
            Err(why) => {
                reject(why, result);
                continue;
            }
        };
        let bytes = if !initialized(&section.name) {
            BytesCheck::NotApplicable
        } else if let Some(image) = image {
            let Some(target) = image.bytes(start, size) else {
                reject(
                    format!("{start:#010X}..+{size:#x} is not initialized data of the target"),
                    result,
                );
                continue;
            };
            let relocated: Vec<(usize, usize)> = section
                .relocations
                .iter()
                .map(|relocation| (relocation.address as usize, 4))
                .collect();
            let Some(ours) = section.data.get(..size as usize) else { continue };
            if !equal_outside(ours, target, &relocated) {
                reject(format!("its bytes differ from the target's at {start:#010X}"), result);
                continue;
            }
            BytesCheck::Equal
        } else {
            BytesCheck::Unchecked
        };
        result.sections.push(PairedSection {
            section: section.name.clone(),
            start,
            end,
            source_size: size,
            align,
            references,
            bytes,
            reordered: false,
        });
    }
}

/// Where a section of `size` bytes at `start` ends in the target.
///
/// A section ends at its alignment (the next split's data starts there) when
/// the bytes it would pad are zero, and otherwise at the next word, because
/// retail does not pad a section the following one begins right after. A start
/// that is not on the alignment keeps the word as its alignment.
fn end_of(
    name: &str,
    start: u32,
    size: u32,
    align: u32,
    image: Option<&DolImage>,
) -> std::result::Result<u32, String> {
    let align = if start % align == 0 { align } else { 4 };
    let last = start.saturating_add(size);
    let (padded, word) = (last.next_multiple_of(align), last.next_multiple_of(4));
    let Some(image) = image.filter(|_| initialized(name)) else { return Ok(padded) };
    let zero = |end: u32| {
        image.bytes(last, end - last).is_some_and(|bytes| bytes.iter().all(|&byte| byte == 0))
    };
    if zero(padded) {
        Ok(padded)
    } else if zero(word) {
        Ok(word)
    } else {
        Err(format!("the bytes after {last:#010X} are not padding"))
    }
}

/// The range a section fills when its constants moved independently of one
/// another, as a reordered literal pool does.
///
/// Each source symbol of the section that was paired individually (one to
/// one, same section kind, equal bytes where they can be read) gives one
/// target extent. The range starts at the lowest and must hold the section
/// from there: the paired extents may not span more than the section's own
/// size, and it ends where that size does. A constant nothing references can
/// sit before the first one paired, which only the link can show.
fn reordered(
    section: &objdiff_core::obj::Section,
    symbols: &[PairedSymbol],
    image: Option<&DolImage>,
) -> std::result::Result<PairedSection, String> {
    let ours: Vec<&PairedSymbol> = symbols
        .iter()
        .filter(|paired| {
            paired.source_section.as_deref() == Some(section.name.as_str()) && paired.size.is_some()
        })
        .collect();
    if ours.is_empty() {
        return Err("no symbol of it was paired individually".into());
    }
    let align = section.align.map_or(4, |align| align.get() as u32).max(4);
    if !align.is_power_of_two() {
        return Err(format!("its alignment {align} is not a power of two"));
    }
    let start = ours.iter().map(|paired| paired.target_address).min().unwrap();
    let used = ours
        .iter()
        .map(|paired| paired.target_address.saturating_add(paired.size.unwrap_or(0)))
        .max()
        .unwrap();
    let size = u32::try_from(section.size).map_err(|_| "it is too large".to_string())?;
    if start % 4 != 0 {
        return Err(format!("{start:#010X} is not aligned to 4"));
    }
    let end = end_of(&section.name, start, size, align, image)?;
    if used > end {
        return Err(format!(
            "its paired symbols span {start:#010X}..{used:#010X}, more than its {size:#x} bytes"
        ));
    }
    let bytes = if ours.iter().any(|paired| paired.bytes == BytesCheck::Unchecked) {
        BytesCheck::Unchecked
    } else if ours.iter().any(|paired| paired.bytes == BytesCheck::Equal) {
        BytesCheck::Equal
    } else {
        BytesCheck::NotApplicable
    };
    Ok(PairedSection {
        section: section.name.clone(),
        start,
        end,
        source_size: size,
        align,
        references: ours.iter().map(|paired| paired.references).sum(),
        bytes,
        reordered: true,
    })
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::{
        obj::{
            ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjRelocations, ObjSection,
            ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
        },
        util::elf::write_elf,
    };
    use objdiff_core::diff::{DiffObjConfig, DiffSide};

    use super::*;

    pub(crate) struct Sym {
        pub name: &'static str,
        pub section: Option<u32>,
        pub address: u64,
        pub size: u64,
        pub kind: ObjSymbolKind,
    }

    pub(crate) fn section(
        name: &str,
        kind: ObjSectionKind,
        data: Vec<u8>,
        size: u64,
    ) -> ObjSection {
        ObjSection {
            name: name.into(),
            kind,
            address: 0,
            size,
            data,
            align: 8,
            elf_index: 0,
            relocations: Default::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        }
    }

    pub(crate) fn reloc(kind: ObjRelocKind, symbol: u32, addend: i64) -> ObjReloc {
        ObjReloc { kind, target_symbol: symbol, addend, module: None }
    }

    pub(crate) fn object(
        sections: Vec<ObjSection>,
        symbols: &[Sym],
        relocations: Vec<(u32, u32, ObjReloc)>,
    ) -> Object {
        let mut sections = sections;
        for (section, address, reloc) in relocations {
            let mut existing: Vec<_> = sections[section as usize]
                .relocations
                .iter()
                .map(|(address, reloc)| (address, reloc.clone()))
                .collect();
            existing.push((address, reloc));
            sections[section as usize].relocations = ObjRelocations::new(existing).unwrap();
        }
        for (index, section) in sections.iter_mut().enumerate() {
            section.elf_index = index as u32 + 1;
        }
        let symbols = symbols
            .iter()
            .map(|symbol| ObjSymbol {
                name: symbol.name.into(),
                address: symbol.address,
                section: symbol.section,
                size: symbol.size,
                size_known: symbol.size > 0,
                kind: symbol.kind,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..Default::default()
            })
            .collect();
        let info = ObjInfo::new(
            ObjKind::Relocatable,
            ObjArchitecture::PowerPc,
            "test".into(),
            symbols,
            sections,
        );
        let bytes = write_elf(&info, true).unwrap();
        objdiff_core::obj::read::parse(&bytes, &DiffObjConfig::default(), DiffSide::Base).unwrap()
    }

    /// `lis r3, 0; addi r3, r3, 0; blr` referencing `symbol` twice.
    fn function() -> Vec<u8> {
        [0x3C60_0000u32, 0x3863_0000, 0x4E80_0020].into_iter().flat_map(u32::to_be_bytes).collect()
    }

    fn text() -> ObjSection { section(".text", ObjSectionKind::Code, function(), 12) }

    fn layout(name: &str, section: &str, address: u32, size: Option<u32>) -> LayoutSymbol {
        LayoutSymbol { name: name.into(), section: section.into(), address, size }
    }

    /// A source with `.sdata2` holding two floats and a function loading the
    /// second one; the target moved the section to 0x8042_1000.
    fn float_pair(target_pool: [u8; 8]) -> (Object, Object) {
        let source = object(
            vec![
                text(),
                section(".sdata2", ObjSectionKind::Data, vec![0x3F, 0x80, 0, 0, 0x40, 0, 0, 0], 8),
            ],
            &[
                Sym {
                    name: "Function",
                    section: Some(0),
                    address: 0,
                    size: 12,
                    kind: ObjSymbolKind::Function,
                },
                Sym {
                    name: "@41",
                    section: Some(1),
                    address: 0,
                    size: 4,
                    kind: ObjSymbolKind::Object,
                },
                Sym {
                    name: "@42",
                    section: Some(1),
                    address: 4,
                    size: 4,
                    kind: ObjSymbolKind::Object,
                },
            ],
            vec![
                (0, 0, reloc(ObjRelocKind::PpcAddr16Ha, 2, 0)),
                (0, 4, reloc(ObjRelocKind::PpcAddr16Lo, 2, 0)),
            ],
        );
        let _ = target_pool;
        let target = object(
            vec![text()],
            &[
                Sym {
                    name: "Function",
                    section: Some(0),
                    address: 0,
                    size: 12,
                    kind: ObjSymbolKind::Function,
                },
                Sym {
                    name: "@39",
                    section: None,
                    address: 0,
                    size: 0,
                    kind: ObjSymbolKind::Unknown,
                },
            ],
            vec![
                (0, 0, reloc(ObjRelocKind::PpcAddr16Ha, 1, 0)),
                (0, 4, reloc(ObjRelocKind::PpcAddr16Lo, 1, 0)),
            ],
        );
        (source, target)
    }

    fn image(pool: [u8; 8]) -> DolImage {
        let mut header = vec![0u8; 0x100];
        // One data section (index 7) at file offset 0x100.
        header[4 * 7..4 * 7 + 4].copy_from_slice(&0x100u32.to_be_bytes());
        header[0x48 + 4 * 7..0x48 + 4 * 7 + 4].copy_from_slice(&0x8042_1000u32.to_be_bytes());
        header[0x90 + 4 * 7..0x90 + 4 * 7 + 4].copy_from_slice(&8u32.to_be_bytes());
        header.extend_from_slice(&pool);
        DolImage::parse(&header).unwrap()
    }

    const POOL: [u8; 8] = [0x3F, 0x80, 0, 0, 0x40, 0, 0, 0];

    #[test]
    fn a_dol_image_serves_bytes_inside_one_section() {
        let image = image(POOL);
        assert_eq!(image.bytes(0x8042_1004, 4), Some(&POOL[4..]));
        assert_eq!(image.bytes(0x8042_1006, 4), None);
        assert_eq!(image.bytes(0x8000_0000, 4), None);
    }

    #[test]
    fn identical_functions_pair_the_constants_they_load() {
        let (source, target) = float_pair(POOL);
        let symbols = [
            layout("@39", ".sdata2", 0x8042_1004, Some(4)),
            layout("@38", ".sdata2", 0x8042_1000, Some(4)),
        ];
        let index = TargetIndex::new(&symbols);
        let pairing = pair(&source, &target, &index, Some(&image(POOL)));
        assert_eq!(pairing.functions, 1);
        assert_eq!(pairing.symbols.len(), 1, "{pairing:#?}");
        let symbol = &pairing.symbols[0];
        assert_eq!((symbol.source.as_str(), symbol.target.as_str()), ("@42", "@39"));
        assert_eq!(symbol.references, 2);
        assert_eq!(symbol.bytes, BytesCheck::Equal);
        // The section maps whole: `@42` is at offset 4, the target at 0x...1004.
        assert_eq!(pairing.sections.len(), 1, "{pairing:#?}");
        let section = &pairing.sections[0];
        assert_eq!(
            (section.section.as_str(), section.start, section.end),
            (".sdata2", 0x8042_1000, 0x8042_1008)
        );
        assert_eq!(section.bytes, BytesCheck::Equal);
    }

    #[test]
    fn differing_bytes_reject_the_pairing() {
        let (source, target) = float_pair(POOL);
        let symbols = [layout("@39", ".sdata2", 0x8042_1004, Some(4))];
        let index = TargetIndex::new(&symbols);
        let mut other = POOL;
        other[4] = 0x41;
        let pairing = pair(&source, &target, &index, Some(&image(other)));
        assert!(pairing.symbols.is_empty(), "{pairing:#?}");
        assert!(pairing.sections.is_empty(), "{pairing:#?}");
        assert_eq!(pairing.rejected.len(), 2, "{pairing:#?}");
    }

    #[test]
    fn without_an_image_nothing_is_claimed_compared() {
        let (source, target) = float_pair(POOL);
        let symbols = [layout("@39", ".sdata2", 0x8042_1004, Some(4))];
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), None);
        assert_eq!(pairing.symbols[0].bytes, BytesCheck::Unchecked);
        assert_eq!(pairing.sections[0].bytes, BytesCheck::Unchecked);
    }

    #[test]
    fn a_size_that_differs_rejects_the_symbol() {
        let (source, target) = float_pair(POOL);
        let symbols = [layout("@39", ".sdata2", 0x8042_1004, Some(0x10))];
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), None);
        assert!(pairing.symbols.is_empty(), "{pairing:#?}");
        assert!(pairing.rejected.iter().any(|r| r.reason.contains("size")), "{pairing:#?}");
    }

    #[test]
    fn a_section_mismatch_rejects_the_symbol() {
        let (source, target) = float_pair(POOL);
        let symbols = [layout("@39", ".rodata", 0x8042_1004, Some(4))];
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), None);
        assert!(pairing.symbols.is_empty(), "{pairing:#?}");
        assert!(pairing.sections.is_empty(), "{pairing:#?}");
    }

    #[test]
    fn a_function_whose_bytes_differ_pairs_nothing() {
        let (source, _) = float_pair(POOL);
        let mut code = function();
        code[8] = 0x4F;
        let target = object(
            vec![section(".text", ObjSectionKind::Code, code, 12)],
            &[
                Sym {
                    name: "Function",
                    section: Some(0),
                    address: 0,
                    size: 12,
                    kind: ObjSymbolKind::Function,
                },
                Sym {
                    name: "@39",
                    section: None,
                    address: 0,
                    size: 0,
                    kind: ObjSymbolKind::Unknown,
                },
            ],
            vec![
                (0, 0, reloc(ObjRelocKind::PpcAddr16Ha, 1, 0)),
                (0, 4, reloc(ObjRelocKind::PpcAddr16Lo, 1, 0)),
            ],
        );
        let symbols = [layout("@39", ".sdata2", 0x8042_1004, Some(4))];
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), None);
        assert_eq!(pairing.functions, 0);
        assert!(pairing.symbols.is_empty());
    }

    #[test]
    fn references_that_disagree_reject_the_symbol() {
        // The source loads `@42` twice; the target's two loads go to different
        // addresses.
        let source = object(
            vec![text(), section(".sdata2", ObjSectionKind::Data, vec![0; 8], 8)],
            &[
                Sym {
                    name: "Function",
                    section: Some(0),
                    address: 0,
                    size: 12,
                    kind: ObjSymbolKind::Function,
                },
                Sym {
                    name: "@42",
                    section: Some(1),
                    address: 4,
                    size: 4,
                    kind: ObjSymbolKind::Object,
                },
            ],
            vec![
                (0, 0, reloc(ObjRelocKind::PpcAddr16Ha, 1, 0)),
                (0, 4, reloc(ObjRelocKind::PpcAddr16Lo, 1, 0)),
            ],
        );
        let target = object(
            vec![text()],
            &[
                Sym {
                    name: "Function",
                    section: Some(0),
                    address: 0,
                    size: 12,
                    kind: ObjSymbolKind::Function,
                },
                Sym {
                    name: "lbl_80421004",
                    section: None,
                    address: 0,
                    size: 0,
                    kind: ObjSymbolKind::Unknown,
                },
                Sym {
                    name: "lbl_80421008",
                    section: None,
                    address: 0,
                    size: 0,
                    kind: ObjSymbolKind::Unknown,
                },
            ],
            vec![
                (0, 0, reloc(ObjRelocKind::PpcAddr16Ha, 1, 0)),
                (0, 4, reloc(ObjRelocKind::PpcAddr16Lo, 2, 0)),
            ],
        );
        let symbols = [
            layout("lbl_80421004", ".sdata2", 0x8042_1004, Some(4)),
            layout("lbl_80421008", ".sdata2", 0x8042_1008, Some(4)),
        ];
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), None);
        assert!(pairing.symbols.is_empty(), "{pairing:#?}");
        assert!(pairing.sections.is_empty(), "{pairing:#?}");
        assert!(pairing.rejected.iter().any(|r| r.subject == "@42"), "{pairing:#?}");
    }

    #[test]
    fn an_extracted_object_spells_a_shared_local_with_its_address() {
        let symbols = [
            layout("@39", ".sdata2", 0x8042_1688, Some(4)),
            layout("@39", ".sdata2", 0x8042_1700, Some(4)),
            layout("lbl_80421800", ".sdata2", 0x8042_1800, Some(4)),
        ];
        let index = TargetIndex::new(&symbols);
        assert_eq!(index.address_of("@39_80421688"), Some(0x8042_1688));
        assert_eq!(index.address_of("@39"), None);
        assert_eq!(index.address_of("lbl_80421800"), Some(0x8042_1800));
        assert_eq!(index.address_of("@40_80421688"), None);
    }

    /// Two functions each loading one float of a two-float pool, which the
    /// target stores in the opposite order: `first` and `second` are the
    /// target addresses of the source's `@41` and `@42`.
    fn reordered_pool(first: u32, second: u32) -> (Object, Object) {
        let function = |name: &'static str, at: u64| Sym {
            name,
            section: Some(0),
            address: at,
            size: 12,
            kind: ObjSymbolKind::Function,
        };
        let code = |load: u32| {
            let words = [0x3C60_0000u32, load, 0x4E80_0020];
            words.into_iter().flat_map(u32::to_be_bytes).collect::<Vec<u8>>()
        };
        let both = || {
            let mut bytes = code(0xC022_0000);
            bytes.extend(code(0xC042_0000));
            bytes
        };
        let source = object(
            vec![
                section(".text", ObjSectionKind::Code, both(), 24),
                section(".sdata2", ObjSectionKind::Data, POOL.to_vec(), 8),
            ],
            &[
                function("First", 0),
                function("Second", 12),
                Sym {
                    name: "@41",
                    section: Some(1),
                    address: 0,
                    size: 4,
                    kind: ObjSymbolKind::Object,
                },
                Sym {
                    name: "@42",
                    section: Some(1),
                    address: 4,
                    size: 4,
                    kind: ObjSymbolKind::Object,
                },
            ],
            vec![
                (0, 0, reloc(ObjRelocKind::PpcAddr16Ha, 2, 0)),
                (0, 4, reloc(ObjRelocKind::PpcAddr16Lo, 2, 0)),
                (0, 12, reloc(ObjRelocKind::PpcAddr16Ha, 3, 0)),
                (0, 16, reloc(ObjRelocKind::PpcAddr16Lo, 3, 0)),
            ],
        );
        let name =
            |address: u32| -> &'static str { Box::leak(format!("lbl_{address:08X}").into()) };
        let placeholder = |address: u32| Sym {
            name: name(address),
            section: None,
            address: 0,
            size: 0,
            kind: ObjSymbolKind::Unknown,
        };
        let target = object(
            vec![section(".text", ObjSectionKind::Code, both(), 24)],
            &[
                function("First", 0),
                function("Second", 12),
                placeholder(first),
                placeholder(second),
            ],
            vec![
                (0, 0, reloc(ObjRelocKind::PpcAddr16Ha, 2, 0)),
                (0, 4, reloc(ObjRelocKind::PpcAddr16Lo, 2, 0)),
                (0, 12, reloc(ObjRelocKind::PpcAddr16Ha, 3, 0)),
                (0, 16, reloc(ObjRelocKind::PpcAddr16Lo, 3, 0)),
            ],
        );
        (source, target)
    }

    #[test]
    fn a_reordered_pool_is_bounded_by_the_constants_paired_one_by_one() {
        let (source, target) = reordered_pool(0x8042_1004, 0x8042_1000);
        let symbols = [
            layout("lbl_80421004", ".sdata2", 0x8042_1004, Some(4)),
            layout("lbl_80421000", ".sdata2", 0x8042_1000, Some(4)),
        ];
        // The target holds the same two floats in the opposite order.
        let swapped = [POOL[4], POOL[5], POOL[6], POOL[7], POOL[0], POOL[1], POOL[2], POOL[3]];
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), Some(&image(swapped)));
        assert_eq!(pairing.functions, 2, "{pairing:#?}");
        assert_eq!(pairing.symbols.len(), 2, "{pairing:#?}");
        assert_eq!(pairing.sections.len(), 1, "{pairing:#?}");
        let section = &pairing.sections[0];
        assert_eq!((section.start, section.end), (0x8042_1000, 0x8042_1008));
        assert!(section.reordered);
        assert_eq!(section.bytes, BytesCheck::Equal);
    }

    #[test]
    fn a_reordered_pool_whose_constants_differ_gets_no_range() {
        let (source, target) = reordered_pool(0x8042_1004, 0x8042_1000);
        let symbols = [
            layout("lbl_80421004", ".sdata2", 0x8042_1004, Some(4)),
            layout("lbl_80421000", ".sdata2", 0x8042_1000, Some(4)),
        ];
        // The bytes are in source order, so neither constant is where it was
        // paired.
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), Some(&image(POOL)));
        assert!(pairing.symbols.is_empty(), "{pairing:#?}");
        assert!(pairing.sections.is_empty(), "{pairing:#?}");
    }

    #[test]
    fn a_reordered_pool_spread_wider_than_the_section_gets_no_range() {
        let (source, target) = reordered_pool(0x8042_1010, 0x8042_1000);
        let symbols = [
            layout("lbl_80421010", ".sdata2", 0x8042_1010, Some(4)),
            layout("lbl_80421000", ".sdata2", 0x8042_1000, Some(4)),
        ];
        let pairing = pair(&source, &target, &TargetIndex::new(&symbols), None);
        assert_eq!(pairing.symbols.len(), 2, "{pairing:#?}");
        assert!(pairing.sections.is_empty(), "{pairing:#?}");
        assert!(pairing.rejected.iter().any(|r| r.reason.contains("span")), "{pairing:#?}");
    }
}
