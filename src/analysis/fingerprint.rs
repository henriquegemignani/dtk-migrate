use std::collections::BTreeSet;

use decomp_toolkit::{
    analysis::vm::is_load_store_op,
    obj::{ObjInfo, ObjSectionKind},
};
use ppc750cl::{Argument, GPR, Ins, Opcode};
use xxhash_rust::xxh3::Xxh3;

use crate::analysis::callgraph::{CallGraph, FunctionNode};

/// Shortest run of printable bytes considered a usable string anchor.
const MIN_STRING_LEN: usize = 6;
/// Longest string prefix retained. Anchors are about identity, not content.
const MAX_STRING_LEN: usize = 128;

/// Build-invariant description of a single function.
#[derive(Debug, Clone)]
pub struct Fingerprint {
    /// Hash of the function's instructions with relocation-affected bits cleared.
    ///
    /// Two functions sharing this hash are byte-identical once the linker's
    /// address patching is factored out, which across builds of the same source
    /// is strong evidence they were compiled from the same code.
    pub exact_hash: u64,
    /// Hash of the opcode sequence alone, ignoring every operand.
    ///
    /// Survives register allocation and immediate changes, so it still groups
    /// functions whose bodies shifted slightly between versions.
    pub opcode_hash: u64,
    pub instruction_count: u32,
    pub call_count: u32,
    pub data_ref_count: u32,
    /// Distinct string literals referenced by the function, sorted and deduplicated.
    pub strings: Vec<String>,
}

impl Fingerprint {
    /// Whether two functions are similar enough to be worth scoring at all.
    ///
    /// Cheap rejection keeps candidate generation from degenerating into an
    /// all-pairs comparison across two 16k-function binaries.
    pub fn plausible_match(&self, other: &Fingerprint) -> bool {
        let (a, b) = (self.instruction_count, other.instruction_count);
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        // Allow generous drift for tiny functions, tighten as they grow.
        hi <= lo.saturating_mul(2).max(lo + 8)
    }

    /// Similarity in `0.0..=1.0`, used to rank competing candidates.
    pub fn similarity(&self, other: &Fingerprint) -> f32 {
        if self.exact_hash == other.exact_hash {
            return 1.0;
        }
        let mut score = 0.0;
        if self.opcode_hash == other.opcode_hash {
            score += 0.5;
        }
        score += 0.2 * ratio(self.instruction_count, other.instruction_count);
        score += 0.15 * ratio(self.call_count, other.call_count);
        score += 0.15 * ratio(self.data_ref_count, other.data_ref_count);
        score.min(1.0)
    }
}

/// Ratio of the smaller value to the larger, treating `0`/`0` as identical.
fn ratio(a: u32, b: u32) -> f32 {
    if a == b {
        return 1.0;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    lo as f32 / hi as f32
}

/// Computes a [`Fingerprint`] for every node in a call graph.
///
/// The returned vector is indexed by `NodeIndex`.
pub fn fingerprint_all(obj: &ObjInfo, graph: &CallGraph) -> Vec<Fingerprint> {
    graph.nodes.iter().map(|node| fingerprint(obj, node)).collect()
}

pub fn fingerprint(obj: &ObjInfo, node: &FunctionNode) -> Fingerprint {
    let mut exact = Xxh3::new();
    let mut opcodes = Xxh3::new();
    let body = normalized_body(obj, node);
    for chunk in body.chunks_exact(4) {
        let code = u32::from_be_bytes(chunk.try_into().unwrap());
        exact.update(chunk);
        opcodes.update(&(Ins::new(code).op as u32).to_be_bytes());
    }

    Fingerprint {
        exact_hash: exact.digest(),
        opcode_hash: opcodes.digest(),
        instruction_count: body.len() as u32 / 4,
        call_count: node.calls().count() as u32,
        data_ref_count: node.data_refs().count() as u32,
        strings: referenced_strings(obj, node),
    }
}

/// A function's instruction bytes with every relocation-owned field cleared.
///
/// This is also used to confirm equality after a hash lookup. Returning the
/// bytes keeps hash collisions from becoming coverage evidence.
pub fn normalized_body(obj: &ObjInfo, node: &FunctionNode) -> Vec<u8> {
    let Some(section) = obj.sections.get(node.section) else { return Vec::new() };
    let start = (node.address as u64 - section.address) as usize;
    let end = (start + node.size as usize).min(section.data.len());
    let mut body = Vec::with_capacity(end.saturating_sub(start));
    for (index, chunk) in section.data[start.min(end)..end].chunks_exact(4).enumerate() {
        let address = node.address + (index * 4) as u32;
        let mut code = u32::from_be_bytes(chunk.try_into().unwrap());
        if let Some(reloc) = section.relocations.at(address) {
            code &= !reloc.kind.value_mask();
        }
        body.extend_from_slice(&code.to_be_bytes());
    }
    body
}

/// One instruction whose immediate addresses storage relative to the method's
/// `this` pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThisRelativeAccess {
    /// Byte offset of the instruction within the function.
    pub instruction_offset: u32,
    /// Effective byte offset from `this`, including any preceding `addi` chain.
    pub object_offset: i32,
}

/// A function body with proven `this`-relative immediates cleared in addition
/// to ordinary relocation fields.
///
/// This is deliberately separate from [`normalized_body`]. Exact-body matches
/// retain their strict meaning, while this representation can detect code that
/// only changed because a base class inserted or removed fields.
#[derive(Debug, Clone)]
pub struct LayoutShiftBody {
    pub bytes: Vec<u8>,
    pub accesses: Vec<ThisRelativeAccess>,
    pub hash: u64,
}

/// Builds a conservative layout-shift representation for a C++ instance
/// method. Register `r3` is the incoming `this` pointer. Provenance is carried
/// through register copies and `addi`; any other definition discards it.
///
/// The scan is intentionally conservative rather than a full CFG dataflow.
/// Seeing a definition on either branch drops provenance for later linear
/// instructions, which can lose evidence but cannot manufacture a member
/// access. Calls invalidate volatile registers and preserve nonvolatile ones.
pub fn layout_shift_body(obj: &ObjInfo, node: &FunctionNode) -> LayoutShiftBody {
    let body = normalized_body(obj, node);
    let mut registers = [None; 32];
    registers[3] = Some(0i32);
    let mut bytes = Vec::with_capacity(body.len());
    let mut accesses = Vec::new();

    for (index, chunk) in body.chunks_exact(4).enumerate() {
        let mut code = u32::from_be_bytes(chunk.try_into().unwrap());
        let ins = Ins::new(code);
        let instruction_offset = (index * 4) as u32;

        let copied_this = if ins.op == Opcode::Or && ins.field_rs() == ins.field_rb() {
            registers[ins.field_rs() as usize]
        } else {
            None
        };
        let adjusted_this = if ins.op == Opcode::Addi && ins.field_ra() != 0 {
            registers[ins.field_ra() as usize]
                .map(|base| base.wrapping_add(ins.field_simm() as i32))
        } else {
            None
        };

        if is_load_store_op(ins.op) && ins.field_ra() != 0 {
            if let Some(base) = registers[ins.field_ra() as usize] {
                accesses.push(ThisRelativeAccess {
                    instruction_offset,
                    object_offset: base.wrapping_add(ins.field_simm() as i32),
                });
                code &= !0xFFFF;
            }
        } else if let Some(object_offset) = adjusted_this {
            accesses.push(ThisRelativeAccess { instruction_offset, object_offset });
            code &= !0xFFFF;
        }

        for argument in ins.defs() {
            if let Argument::GPR(GPR(register)) = argument {
                registers[register as usize] = None;
            }
        }
        if ins.op == Opcode::Or && ins.field_rs() == ins.field_rb() {
            registers[ins.field_ra() as usize] = copied_this;
        } else if ins.op == Opcode::Addi {
            registers[ins.field_rd() as usize] = adjusted_this;
        }

        if matches!(ins.op, Opcode::B | Opcode::Bc | Opcode::Bcctr | Opcode::Bclr) && ins.field_lk()
        {
            for register in registers.iter_mut().take(13) {
                *register = None;
            }
        }
        bytes.extend_from_slice(&code.to_be_bytes());
    }

    let hash = xxhash_rust::xxh3::xxh3_64(&bytes);
    LayoutShiftBody { bytes, accesses, hash }
}

/// Collects string literals reachable through the function's data references.
///
/// String contents are among the few things that survive both recompilation and
/// porting to another game built on the same codebase, which makes them the
/// strongest single anchor available for cross-version matching.
fn referenced_strings(obj: &ObjInfo, node: &FunctionNode) -> Vec<String> {
    // Hi/Lo relocation pairs both point at the same literal, so collect target
    // addresses first and read each one once.
    let mut addresses = BTreeSet::new();
    for reference in node.data_refs() {
        let symbol = &obj.symbols[reference.target_symbol];
        let Some(section_index) = symbol.section else { continue };
        let Some(section) = obj.sections.get(section_index) else { continue };
        if !matches!(section.kind, ObjSectionKind::ReadOnlyData | ObjSectionKind::Data) {
            continue;
        }
        addresses.insert((section_index, symbol.address as i64 + reference.addend));
    }

    let mut strings = BTreeSet::new();
    for (section_index, address) in addresses {
        let Some(section) = obj.sections.get(section_index) else { continue };
        let offset = address - section.address as i64;
        if offset < 0 || offset as usize >= section.data.len() {
            continue;
        }
        if let Some(string) = read_string(&section.data[offset as usize..]) {
            strings.insert(string);
        }
    }
    strings.into_iter().collect()
}

/// Reads a printable string, or `None` if the bytes don't look like one.
///
/// A literal that runs past [`MAX_STRING_LEN`] is truncated to its prefix rather
/// than discarded. Assert messages and `__FILE__` paths are the longest literals
/// in a binary and also the most distinctive, so dropping them would forfeit the
/// best anchors available.
fn read_string(data: &[u8]) -> Option<String> {
    let window = &data[..data.len().min(MAX_STRING_LEN)];
    let end = window.iter().position(|&b| b == 0).unwrap_or(window.len());
    if end < MIN_STRING_LEN {
        return None;
    }
    let bytes = &window[..end];
    if !bytes.iter().all(|&b| matches!(b, b' '..=b'~' | b'\t' | b'\n' | b'\r')) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocKind, ObjRelocations, ObjSection,
        ObjSectionKind, ObjSplits, ObjSymbol, ObjSymbolKind,
    };

    use super::*;

    fn function_object(words: &[u32]) -> ObjInfo {
        let data: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "test".to_string(),
            vec![ObjSymbol {
                name: "Method__5ClassFv".to_string(),
                address: 0x1000,
                section: Some(0),
                size: data.len() as u64,
                size_known: true,
                kind: ObjSymbolKind::Function,
                ..Default::default()
            }],
            vec![ObjSection {
                name: ".text".to_string(),
                kind: ObjSectionKind::Code,
                address: 0x1000,
                size: data.len() as u64,
                data,
                align: 4,
                elf_index: 0,
                relocations: ObjRelocations::default(),
                virtual_address: None,
                file_offset: 0,
                section_known: true,
                splits: ObjSplits::default(),
            }],
        )
    }

    fn layout(words: &[u32]) -> LayoutShiftBody {
        let object = function_object(words);
        let graph = CallGraph::build(&object);
        layout_shift_body(&object, graph.node(0))
    }

    #[test]
    fn masking_clears_exactly_the_relocated_bits() {
        // The whole approach rests on these masks: clearing them must leave the
        // opcode and register fields of the instruction untouched.
        let bl = 0x4800_0000u32 | 0x0012_3456 & 0x3FFFFFC;
        assert_eq!(bl & !ObjRelocKind::PpcRel24.value_mask(), 0x4800_0000);

        let lis = 0x3C60_0000u32 | 0x8045; // lis r3, 0x8045
        assert_eq!(lis & !ObjRelocKind::PpcAddr16Ha.value_mask(), 0x3C60_0000);

        // An absolute relocation consumes the entire word.
        assert_eq!(0xDEAD_BEEFu32 & !ObjRelocKind::Absolute.value_mask(), 0);
    }

    #[test]
    fn layout_shift_masks_only_proven_this_relative_offsets() {
        let source = layout(&[
            0x7C7F_1B78, // mr r31,r3
            0x809F_0158, // lwz r4,0x158(r31)
            0x38BF_0160, // addi r5,r31,0x160
            0x9805_0008, // stb r0,8(r5), effective this+0x168
            0x80C1_0008, // lwz r6,8(r1), stack access
            0x4E80_0020, // blr
        ]);
        let target =
            layout(&[0x7C7F_1B78, 0x809F_0168, 0x38BF_0170, 0x9805_0008, 0x80C1_0008, 0x4E80_0020]);
        assert_eq!(source.bytes, target.bytes);
        assert_eq!(source.accesses, vec![
            ThisRelativeAccess { instruction_offset: 4, object_offset: 0x158 },
            ThisRelativeAccess { instruction_offset: 8, object_offset: 0x160 },
            ThisRelativeAccess { instruction_offset: 12, object_offset: 0x168 },
        ]);
        assert_eq!(
            target.accesses.iter().map(|access| access.object_offset).collect::<Vec<_>>(),
            vec![0x168, 0x170, 0x178]
        );
    }

    #[test]
    fn layout_shift_keeps_stack_offsets_distinct() {
        let source = layout(&[0x8061_0008, 0x4E80_0020]);
        let target = layout(&[0x8061_0018, 0x4E80_0020]);
        assert_ne!(source.bytes, target.bytes);
        assert!(source.accesses.is_empty());
        assert!(target.accesses.is_empty());
    }

    #[test]
    fn reads_a_plain_c_string() {
        assert_eq!(read_string(b"CStateManager.cpp\0rest").as_deref(), Some("CStateManager.cpp"));
    }

    #[test]
    fn rejects_strings_below_the_minimum_length() {
        assert_eq!(read_string(b"abc\0"), None);
        assert_eq!(read_string(b"abc"), None, "short and unterminated");
    }

    #[test]
    fn truncates_long_literals_rather_than_discarding_them() {
        // Assert messages and __FILE__ paths run past the window and are exactly
        // the anchors worth keeping.
        let mut data = "a".repeat(MAX_STRING_LEN + 40).into_bytes();
        data.push(0);
        let read = read_string(&data).expect("a long literal is still an anchor");
        assert_eq!(read.len(), MAX_STRING_LEN);
    }

    #[test]
    fn an_unterminated_run_still_reads_as_a_string() {
        assert_eq!(read_string(b"no terminator here").as_deref(), Some("no terminator here"));
    }

    #[test]
    fn rejects_binary_data_masquerading_as_a_string() {
        assert_eq!(read_string(b"ab\x01\x02\x03\x04cd\0"), None);
    }

    fn fp(instruction_count: u32, call_count: u32) -> Fingerprint {
        Fingerprint {
            exact_hash: 1,
            opcode_hash: 2,
            instruction_count,
            call_count,
            data_ref_count: 0,
            strings: Vec::new(),
        }
    }

    #[test]
    fn plausible_match_tolerates_growth_in_small_functions() {
        // Small functions swing proportionally more between builds.
        assert!(fp(4, 0).plausible_match(&fp(10, 0)));
        assert!(fp(100, 0).plausible_match(&fp(150, 0)));
        assert!(!fp(10, 0).plausible_match(&fp(100, 0)));
    }

    #[test]
    fn plausible_match_is_symmetric() {
        for (a, b) in [(4u32, 10u32), (10, 100), (50, 60)] {
            assert_eq!(fp(a, 0).plausible_match(&fp(b, 0)), fp(b, 0).plausible_match(&fp(a, 0)));
        }
    }

    #[test]
    fn identical_encodings_score_perfectly() {
        let a = fp(20, 3);
        assert_eq!(a.similarity(&a), 1.0);
    }

    #[test]
    fn similarity_falls_off_with_divergence() {
        let mut near = fp(20, 3);
        near.exact_hash = 99;
        let mut far = fp(60, 12);
        far.exact_hash = 99;
        far.opcode_hash = 98;
        let base = fp(20, 3);
        assert!(base.similarity(&near) > base.similarity(&far));
        assert!(base.similarity(&far) >= 0.0 && base.similarity(&near) <= 1.0);
    }
}
