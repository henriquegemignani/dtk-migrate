//! Reading the two compiled objects a unit has.
//!
//! Every method in this module compares a unit's *compiled source object* with
//! the object *extracted from the target binary*. Both already exist after a
//! normal build, so the whole of symbol derivation costs a few seconds and no
//! compilation of its own.
//!
//! What the pair gives that a cross-version binary comparison cannot: the
//! source object states what the unit is supposed to contain. Every comparison
//! therefore stays inside one translation unit and rests on names the build
//! already agrees on.

use std::path::Path;

use anyhow::{Context, Result};
use objdiff_core::{
    diff::{DiffObjConfig, DiffSide},
    obj::{Object, SectionKind, SymbolKind},
};

/// One function in an object, with the calls it makes.
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
    /// The symbols this function references, in address order.
    pub relocations: Vec<Reference>,
}

/// One relocation inside a function: what it points at, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub offset: u64,
    /// The relocation kind, as the architecture numbers it. Two references only
    /// correspond if they are the same kind.
    pub kind: u32,
    pub target: String,
}

/// An object and the `.text` functions in it, in address order.
pub struct Compiled {
    pub object: Object,
    pub functions: Vec<Function>,
}

impl Compiled {
    /// `side` says which half of a comparison this object is: the extracted
    /// original is the target, the compiled source is the base.
    pub fn read(path: &Path, side: DiffSide) -> Result<Self> {
        let config = DiffObjConfig::default();
        let object = objdiff_core::obj::read::read(path, &config, side)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let functions = functions_of(&object);
        Ok(Self { object, functions })
    }

    pub fn function(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|function| function.name == name)
    }
}

/// The code symbols of an object, each with the references inside it.
fn functions_of(object: &Object) -> Vec<Function> {
    let mut found: Vec<Function> = Vec::new();
    for symbol in &object.symbols {
        if symbol.kind != SymbolKind::Function || symbol.size == 0 {
            continue;
        }
        let Some(index) = symbol.section else { continue };
        let Some(section) = object.sections.get(index) else { continue };
        if section.kind != SectionKind::Code {
            continue;
        }
        let start = symbol.address;
        let end = start + symbol.size;
        let mut relocations: Vec<Reference> = section
            .relocations
            .iter()
            .filter(|relocation| relocation.address >= start && relocation.address < end)
            .filter_map(|relocation| {
                Some(Reference {
                    offset: relocation.address - start,
                    kind: relocation_kind(relocation.flags),
                    target: object.symbols.get(relocation.target_symbol)?.name.clone(),
                })
            })
            .collect();
        relocations.sort_by_key(|reference| reference.offset);
        found.push(Function {
            name: symbol.name.clone(),
            address: start,
            size: symbol.size,
            relocations,
        });
    }
    found.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name)));
    found
}

/// A relocation kind as one number, whatever the architecture calls it.
///
/// Only equality matters here: two references correspond when they are the same
/// kind of reference, and what that kind means is the architecture's business.
fn relocation_kind(flags: objdiff_core::obj::RelocationFlags) -> u32 {
    match flags {
        objdiff_core::obj::RelocationFlags::Elf(kind) => kind,
        other => {
            // Anything not ELF is folded into one bucket rather than silently
            // comparing equal to an ELF kind of the same number.
            let _ = other;
            u32::MAX
        }
    }
}

/// dtk's own convention for a symbol it invented because nothing claims that
/// address yet — not a real name from any source file.
const AUTO_PREFIXES: [&str; 6] = ["lbl_", "fn_", "jumptable_", "gap_", "pad_", "dtor_"];

/// True for a target name that is a placeholder rather than a real name.
pub fn is_derivable(name: &str) -> bool {
    AUTO_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// True for a source name worth copying onto a target symbol.
///
/// CodeWarrior's own local labels (`@468`, `@stringBase0`) are numbered per
/// object and carry no meaning across a comparison, and a placeholder is by
/// definition not a name, so neither may ever be proposed.
pub fn is_usable_source_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('@') && !is_derivable(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_name_is_derivable_and_a_real_one_is_not() {
        assert!(is_derivable("fn_8030DA80"));
        assert!(is_derivable("lbl_80400000"));
        assert!(!is_derivable("GetTextureElement__20CParticleDataFactory"));
    }

    #[test]
    fn a_compiler_local_label_is_never_a_usable_source_name() {
        assert!(!is_usable_source_name("@468"));
        assert!(!is_usable_source_name("@stringBase0"));
        assert!(!is_usable_source_name("fn_8030DA80"));
        assert!(!is_usable_source_name(""));
        assert!(is_usable_source_name("CPlayer::Update"));
    }
}
