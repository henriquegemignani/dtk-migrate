//! Naming placeholder functions from compiled units that have no split.
//!
//! Every other method here compares a compiled object with the object that
//! was extracted from the target for the same unit, so a unit the target has
//! no split for contributes nothing. This one compares such a unit's functions
//! with every placeholder function in the target binary instead.
//!
//! An exact body match is rare across versions, but the *shape* of a function
//! survives: its opcodes, in order, with every operand and relocation ignored.
//! Each body is reduced to its opcode sequence, cut into overlapping runs of
//! four, and two bodies are compared by the overlap of those sets (Jaccard).
//! The comparison is deliberately coarse and so is only trusted when the best
//! pairing is high and clearly ahead of the runner-up, and when both sides
//! agree: a name that lands on two targets, or a target that two names want,
//! is dropped. The thresholds were calibrated against names the target
//! already carried, where this agrees about 99.7% of the time.
//!
//! A weak function appears in every object that uses it, so ownership is not
//! read from where a name was found. The proposals say which object defined
//! the name, and the build decides whether the result links.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use anyhow::Result;
use objdiff_core::{
    diff::{DiffObjConfig, DiffSide},
    obj::{SectionKind, SymbolFlag, SymbolKind},
};
use rayon::prelude::*;

use crate::{
    derive::{
        objects::{is_derivable, is_usable_source_name},
        propose::{Proposal, Tier},
        unit_key,
    },
    matching::relocation_pairing::DolImage,
    project::rename_sync,
};

/// Instructions in a shingle.
const SHINGLE: usize = 4;
/// How far two bodies' lengths may differ, as a ratio, before they are not
/// compared.
const LENGTH_LOW: f64 = 0.6;
const LENGTH_HIGH: f64 = 1.6;
/// The overlap the best pairing needs, and the lead it needs over the next
/// distinct name.
const MIN_SIMILARITY: f64 = 0.6;
const MIN_MARGIN: f64 = 0.1;
/// Bodies shorter than this have too few shingles to say anything.
const MIN_INSTRUCTIONS: usize = 8;

/// The method name carried by every proposal made here.
pub const METHOD: &str = "body-shape";

/// One token per instruction: the opcode, and the extended opcode where the
/// primary one is only a group. Branch link bits stay, since a call and a jump
/// are different shapes.
fn token(word: u32) -> u32 {
    let primary = word >> 26;
    match primary {
        // Integer, floating-point and paired-single groups.
        4 => (primary << 16) | (word & 0x3F),
        19 | 31 => (primary << 16) | ((word >> 1) & 0x3FF),
        59 => (primary << 16) | ((word >> 1) & 0x1F),
        63 => (primary << 16) | ((word >> 1) & 0x3FF),
        // Branches: the link bit separates calls from jumps.
        16 | 18 => (primary << 16) | (word & 1),
        _ => primary << 16,
    }
}

/// The set of opcode shingles in a function body.
fn shingles(code: &[u8]) -> Option<(Vec<u64>, usize)> {
    let tokens: Vec<u32> = code
        .chunks_exact(4)
        .map(|chunk| token(u32::from_be_bytes(chunk.try_into().unwrap())))
        .collect();
    if tokens.len() < MIN_INSTRUCTIONS {
        return None;
    }
    let mut set: Vec<u64> = tokens
        .windows(SHINGLE)
        .map(|window| {
            window.iter().fold(0xcbf29ce484222325u64, |hash, &token| {
                (hash ^ u64::from(token)).wrapping_mul(0x100000001b3)
            })
        })
        .collect();
    set.sort_unstable();
    set.dedup();
    Some((set, tokens.len()))
}

fn jaccard(a: &[u64], b: &[u64]) -> f64 {
    let (mut i, mut j, mut shared) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                shared += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let union = a.len() + b.len() - shared;
    if union == 0 { 0.0 } else { shared as f64 / union as f64 }
}

/// A compiled function reduced to its shape.
#[derive(Debug, Clone)]
pub struct Shape {
    pub name: String,
    pub unit: String,
    pub weak: bool,
    shingles: Vec<u64>,
    length: usize,
}

impl Shape {
    pub fn new(name: &str, unit: &str, weak: bool, code: &[u8]) -> Option<Self> {
        let (shingles, length) = shingles(code)?;
        Some(Self { name: name.into(), unit: unit.into(), weak, shingles, length })
    }
}

/// The functions of one compiled object, as shapes.
pub fn read_shapes(path: &Path, unit: &str) -> Result<Vec<Shape>> {
    let object = objdiff_core::obj::read::read(path, &DiffObjConfig::default(), DiffSide::Base)?;
    let mut shapes = Vec::new();
    for symbol in &object.symbols {
        if symbol.kind != SymbolKind::Function || symbol.size == 0 {
            continue;
        }
        if !is_usable_source_name(&symbol.name) {
            continue;
        }
        let Some(section) = symbol.section.and_then(|index| object.sections.get(index)) else {
            continue;
        };
        if section.kind != SectionKind::Code {
            continue;
        }
        let start = symbol.address.saturating_sub(section.address) as usize;
        let Some(code) = section.data.get(start..start + symbol.size as usize) else { continue };
        if let Some(shape) =
            Shape::new(&symbol.name, unit, symbol.flags.contains(SymbolFlag::Weak), code)
        {
            shapes.push(shape);
        }
    }
    Ok(shapes)
}

/// A placeholder function in the target binary, as a shape.
#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    shape: Shape,
}

/// The placeholder functions of a symbols file whose bytes the image holds.
pub fn target_shapes(symbols: &str, image: &DolImage) -> Vec<Target> {
    symbols
        .lines()
        .filter_map(|line| {
            let symbol = rename_sync::parse_line(line)?;
            if !matches!(symbol.section.as_str(), ".text" | ".init") || !is_derivable(&symbol.name)
            {
                return None;
            }
            let attributes = line.split_once("//")?.1;
            if !attributes.split_whitespace().any(|a| a == "type:function") {
                return None;
            }
            let size = attributes
                .split_whitespace()
                .find_map(|a| a.strip_prefix("size:0x"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())?;
            let code = image.bytes(symbol.address, size)?;
            let shape = Shape::new(&symbol.name, "", false, code)?;
            Some(Target { name: symbol.name, shape })
        })
        .collect()
}

/// How a name was found, kept so a wrong one can be traced.
#[derive(Debug, Clone)]
pub struct Pairing {
    pub target: String,
    pub name: String,
    pub unit: String,
    pub similarity: f64,
    pub margin: f64,
}

/// Collapses shapes by name. A name defined several times is kept only when
/// every definition has the same shape neighbourhood, otherwise it is dropped:
/// it could be any of them and the target has one.
fn collapse(shapes: Vec<Shape>) -> Vec<Shape> {
    let mut by_name: BTreeMap<String, Vec<Shape>> = BTreeMap::new();
    for shape in shapes {
        by_name.entry(shape.name.clone()).or_default().push(shape);
    }
    by_name
        .into_values()
        .filter_map(|mut group| {
            let first = group.remove(0);
            group
                .iter()
                .all(|other| jaccard(&first.shingles, &other.shingles) >= 0.9)
                .then_some(first)
        })
        .collect()
}

/// Pairs each target with the one name its shape supports.
pub fn pair(shapes: Vec<Shape>, targets: &[Target]) -> Vec<Pairing> {
    let sources = collapse(shapes);
    let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
    for (at, source) in sources.iter().enumerate() {
        for &shingle in &source.shingles {
            index.entry(shingle).or_default().push(at);
        }
    }

    let found: Vec<Pairing> = targets
        .par_iter()
        .filter_map(|target| {
            let mut seen: BTreeSet<usize> = BTreeSet::new();
            for shingle in &target.shape.shingles {
                if let Some(list) = index.get(shingle) {
                    seen.extend(list);
                }
            }
            let mut scored: Vec<(f64, usize)> = seen
                .into_iter()
                .filter(|&at| {
                    let ratio = sources[at].length as f64 / target.shape.length as f64;
                    (LENGTH_LOW..=LENGTH_HIGH).contains(&ratio)
                })
                .map(|at| (jaccard(&target.shape.shingles, &sources[at].shingles), at))
                .collect();
            scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
            let &(best, at) = scored.first()?;
            let runner_up = scored.get(1).map_or(0.0, |entry| entry.0);
            let margin = best - runner_up;
            (best >= MIN_SIMILARITY && margin >= MIN_MARGIN).then(|| Pairing {
                target: target.name.clone(),
                name: sources[at].name.clone(),
                unit: sources[at].unit.clone(),
                similarity: best,
                margin,
            })
        })
        .collect();

    // A name two targets want is as likely to be either, or neither.
    let mut wanted: HashMap<&str, usize> = HashMap::new();
    for pairing in &found {
        *wanted.entry(pairing.name.as_str()).or_default() += 1;
    }
    let mut kept: Vec<Pairing> =
        found.iter().filter(|pairing| wanted[pairing.name.as_str()] == 1).cloned().collect();
    kept.sort_by(|a, b| a.target.cmp(&b.target));
    kept
}

/// The proposals for every source object that has no extracted counterpart.
///
/// `skipped` holds the unit keys that other methods already compare.
pub fn propose(
    objects: &[(String, std::path::PathBuf)],
    symbols: &str,
    image: &DolImage,
) -> Result<Vec<Proposal>> {
    let shapes: Vec<Shape> = objects
        .par_iter()
        .filter_map(|(unit, path)| read_shapes(path, unit).ok())
        .flatten()
        .collect();
    let targets = target_shapes(symbols, image);
    Ok(pair(shapes, &targets)
        .into_iter()
        .map(|pairing| {
            let mut proposal = Proposal::new(
                &pairing.target,
                &pairing.name,
                &unit_key(&pairing.unit),
                METHOD,
                Tier::Probable,
            );
            proposal.signal = Some(format!("shape {:.2}", pairing.similarity));
            proposal.percent = Some((pairing.similarity * 100.0) as f32);
            proposal.margin = Some((pairing.margin * 100.0) as f32);
            proposal
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` distinct but plausible instruction words: lwz, stw, addi, ...
    fn body(opcodes: &[u32]) -> Vec<u8> {
        opcodes.iter().flat_map(|op| (op << 26).to_be_bytes()).collect()
    }

    #[test]
    fn operands_do_not_change_a_shape() {
        let a = [0x8001_0008u32; 12].iter().flat_map(|w| w.to_be_bytes()).collect::<Vec<_>>();
        let b = [0x8061_0010u32; 12].iter().flat_map(|w| w.to_be_bytes()).collect::<Vec<_>>();
        assert_eq!(shingles(&a), shingles(&b));
    }

    #[test]
    fn a_call_and_a_jump_are_different_tokens() {
        assert_ne!(token(0x4800_0001), token(0x4800_0000));
    }

    #[test]
    fn a_body_too_short_has_no_shape() {
        assert!(shingles(&body(&[32, 36, 14])).is_none());
    }

    #[test]
    fn only_a_clear_winner_is_paired() {
        let near = body(&[32, 36, 14, 15, 32, 36, 14, 15, 24, 25, 32, 36, 14, 18]);
        let far = body(&[10, 11, 12, 13, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50]);
        let source = vec![
            Shape::new("Near", "a.o", false, &near).unwrap(),
            Shape::new("Far", "b.o", false, &far).unwrap(),
        ];
        let target = Target {
            name: "fn_80000000".into(),
            shape: Shape::new("fn_80000000", "", false, &near).unwrap(),
        };
        let paired = pair(source, &[target]);
        assert_eq!(paired.len(), 1);
        assert_eq!(paired[0].name, "Near");
    }

    #[test]
    fn a_name_wanted_twice_is_dropped() {
        let one = body(&[32, 36, 14, 15, 32, 36, 14, 15, 24, 25, 32, 36, 14, 18]);
        let source = vec![Shape::new("Only", "a.o", false, &one).unwrap()];
        let targets: Vec<Target> = ["fn_1", "fn_2"]
            .iter()
            .map(|name| Target {
                name: (*name).into(),
                shape: Shape::new(name, "", false, &one).unwrap(),
            })
            .collect();
        assert!(pair(source, &targets).is_empty());
    }

    #[test]
    fn differing_weak_copies_are_not_a_name() {
        let a = body(&[32, 36, 14, 15, 32, 36, 14, 15, 24, 25, 32, 36, 14, 18]);
        let b = body(&[10, 11, 12, 13, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50]);
        let shapes = vec![
            Shape::new("Copy", "a.o", true, &a).unwrap(),
            Shape::new("Copy", "b.o", true, &b).unwrap(),
        ];
        assert!(collapse(shapes).is_empty());
    }
}
