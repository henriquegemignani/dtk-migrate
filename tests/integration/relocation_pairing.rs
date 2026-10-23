//! Naming data and bounding data sections through identical function bodies.
//!
//! The objects are written as real ELF files and read back the way the stages
//! read them: a compiled source object, and an object extracted from the
//! target whose references to data outside the unit are bare names.

use decomp_toolkit::{
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjRelocations, ObjSection,
        ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    },
    util::elf::write_elf,
};
use dtk_migrate::{
    derive::{
        objects::Compiled,
        propose::{Proposal, Tier, by_data_relocations},
    },
    matching::{
        data_evidence::LayoutSymbol,
        relocation_pairing::{BytesCheck, DolImage, TargetIndex, pair},
    },
};
use objdiff_core::diff::DiffSide;

struct Sym(&'static str, Option<u32>, u64, u64, ObjSymbolKind);

fn section(name: &str, kind: ObjSectionKind, data: Vec<u8>) -> ObjSection {
    ObjSection {
        name: name.into(),
        kind,
        address: 0,
        size: data.len() as u64,
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

/// An object with one `.text` function (`lis`, `lfs`/`lwz`, `blr`) whose two
/// relocations name the symbols at `references`, plus the given data sections.
fn object(
    side: DiffSide,
    mut data: Vec<ObjSection>,
    symbols: &[Sym],
    references: [u32; 2],
    code: u32,
) -> Compiled {
    let words = [0x3C60_0000u32, code, 0x4E80_0020];
    let mut text = section(
        ".text",
        ObjSectionKind::Code,
        words.into_iter().flat_map(u32::to_be_bytes).collect(),
    );
    text.relocations = ObjRelocations::new(vec![
        (0, ObjReloc {
            kind: ObjRelocKind::PpcAddr16Ha,
            target_symbol: references[0],
            addend: 0,
            module: None,
        }),
        (4, ObjReloc {
            kind: ObjRelocKind::PpcAddr16Lo,
            target_symbol: references[1],
            addend: 0,
            module: None,
        }),
    ])
    .unwrap();
    let mut sections = vec![text];
    sections.append(&mut data);
    for (index, section) in sections.iter_mut().enumerate() {
        section.elf_index = index as u32 + 1;
    }
    let symbols = std::iter::once(Sym("Function", Some(0), 0, 12, ObjSymbolKind::Function))
        .chain(symbols.iter().map(|s| Sym(s.0, s.1, s.2, s.3, s.4)))
        .map(|Sym(name, section, address, size, kind)| ObjSymbol {
            name: name.into(),
            address,
            section,
            size,
            size_known: size > 0,
            kind,
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
    Compiled::parse(&write_elf(&info, true).unwrap(), side).unwrap()
}

fn layout(name: &str, section: &str, address: u32, size: u32) -> LayoutSymbol {
    LayoutSymbol { name: name.into(), section: section.into(), address, size: Some(size) }
}

/// A DOL with `.sdata2` bytes at 0x80421000.
fn image(pool: &[u8]) -> DolImage {
    let mut file = vec![0u8; 0x100];
    let set = |file: &mut Vec<u8>, at: usize, value: u32| {
        file[at..at + 4].copy_from_slice(&value.to_be_bytes())
    };
    set(&mut file, 4 * 7, 0x100);
    set(&mut file, 0x48 + 4 * 7, 0x8042_1000);
    set(&mut file, 0x90 + 4 * 7, pool.len() as u32);
    file.extend_from_slice(pool);
    DolImage::parse(&file).unwrap()
}

const POOL: [u8; 8] = [0x3F, 0x80, 0, 0, 0x40, 0, 0, 0];

/// Source: a named float `kScale` loaded by `Function`. Target: the same
/// function loading `lbl_80421004`, a constant inside a section no split holds.
fn constant(source_name: &'static str) -> (Compiled, Compiled) {
    let source = object(
        DiffSide::Base,
        vec![section(".sdata2", ObjSectionKind::Data, POOL.to_vec())],
        &[Sym(source_name, Some(1), 4, 4, ObjSymbolKind::Object)],
        [1, 1],
        0xC022_0000,
    );
    let target = object(
        DiffSide::Target,
        vec![],
        &[Sym("lbl_80421004", None, 0, 0, ObjSymbolKind::Unknown)],
        [1, 1],
        0xC022_0000,
    );
    (source, target)
}

fn named(proposals: &[Proposal]) -> Vec<(&str, &str)> {
    proposals.iter().map(|p| (p.old.as_str(), p.new.as_str())).collect()
}

#[test]
fn a_constant_loaded_by_an_identical_function_names_its_placeholder() {
    let (source, target) = constant("kScale");
    let symbols = [layout("lbl_80421004", ".sdata2", 0x8042_1004, 4)];
    let index = TargetIndex::new(&symbols);
    let proposals = by_data_relocations("Unit.o", &target, &source, &index, Some(&image(&POOL)));
    assert_eq!(named(&proposals), [("lbl_80421004", "kScale")]);
    assert_eq!(proposals[0].method, "data-relocation");
    assert_eq!(proposals[0].tier, Tier::Confident);
}

#[test]
fn a_compiler_literal_name_is_never_proposed() {
    let (source, target) = constant("@41");
    let symbols = [layout("lbl_80421004", ".sdata2", 0x8042_1004, 4)];
    let proposals = by_data_relocations(
        "Unit.o",
        &target,
        &source,
        &TargetIndex::new(&symbols),
        Some(&image(&POOL)),
    );
    assert!(proposals.is_empty(), "{proposals:?}");
}

#[test]
fn a_target_name_that_is_not_a_placeholder_is_not_renamed() {
    let (source, _) = constant("kScale");
    let target = object(
        DiffSide::Target,
        vec![],
        &[Sym("kOther", None, 0, 0, ObjSymbolKind::Unknown)],
        [1, 1],
        0xC022_0000,
    );
    let symbols = [layout("kOther", ".sdata2", 0x8042_1004, 4)];
    let proposals = by_data_relocations(
        "Unit.o",
        &target,
        &source,
        &TargetIndex::new(&symbols),
        Some(&image(&POOL)),
    );
    assert!(proposals.is_empty(), "{proposals:?}");
}

#[test]
fn different_bytes_withdraw_the_name() {
    let (source, target) = constant("kScale");
    let symbols = [layout("lbl_80421004", ".sdata2", 0x8042_1004, 4)];
    let mut other = POOL;
    other[4] = 0x41;
    let proposals = by_data_relocations(
        "Unit.o",
        &target,
        &source,
        &TargetIndex::new(&symbols),
        Some(&image(&other)),
    );
    assert!(proposals.is_empty(), "{proposals:?}");
}

#[test]
fn an_external_global_is_named_without_any_bytes_to_compare() {
    // `gCounter` is defined elsewhere: the source only references it.
    let source = object(
        DiffSide::Base,
        vec![],
        &[Sym("gCounter", None, 0, 0, ObjSymbolKind::Unknown)],
        [1, 1],
        0x8003_0000,
    );
    let target = object(
        DiffSide::Target,
        vec![],
        &[Sym("lbl_8041D000", None, 0, 0, ObjSymbolKind::Unknown)],
        [1, 1],
        0x8003_0000,
    );
    let symbols = [layout("lbl_8041D000", ".sbss", 0x8041_D000, 4)];
    let proposals =
        by_data_relocations("Unit.o", &target, &source, &TargetIndex::new(&symbols), None);
    assert_eq!(named(&proposals), [("lbl_8041D000", "gCounter")]);
    // Two references from one function and nothing to compare is one signal.
    assert_eq!(proposals[0].tier, Tier::Probable);
}

#[test]
fn a_function_with_different_instructions_names_nothing() {
    let (source, _) = constant("kScale");
    let target = object(
        DiffSide::Target,
        vec![],
        &[Sym("lbl_80421004", None, 0, 0, ObjSymbolKind::Unknown)],
        [1, 1],
        0xC042_0000,
    );
    let symbols = [layout("lbl_80421004", ".sdata2", 0x8042_1004, 4)];
    let proposals = by_data_relocations(
        "Unit.o",
        &target,
        &source,
        &TargetIndex::new(&symbols),
        Some(&image(&POOL)),
    );
    assert!(proposals.is_empty(), "{proposals:?}");
}

#[test]
fn a_section_whose_references_share_one_delta_gets_a_range() {
    let (source, target) = constant("kScale");
    let symbols = [layout("lbl_80421004", ".sdata2", 0x8042_1004, 4)];
    let pairing =
        pair(&source.object, &target.object, &TargetIndex::new(&symbols), Some(&image(&POOL)));
    assert_eq!(pairing.sections.len(), 1, "{pairing:#?}");
    let section = &pairing.sections[0];
    assert_eq!((section.start, section.end), (0x8042_1000, 0x8042_1008));
    assert_eq!(section.bytes, BytesCheck::Equal);
}
