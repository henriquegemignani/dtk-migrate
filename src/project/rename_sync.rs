//! Carries symbol renames made in one version's `symbols.txt` over to another
//! version's.
//!
//! A version that is being decompiled keeps getting its symbols renamed:
//! better names for ones already named, or names for ones that had none. A
//! second version that was migrated from it earlier still carries the old
//! names. Re-running a migration would eventually rename them, but only
//! through function matching and a build for every candidate; a rename that
//! the source already made is a much stronger statement than a match, and it
//! can be applied directly.
//!
//! A rename is a source symbol at the same section and address whose name
//! differs between two revisions. It applies in the target to the symbol that
//! currently holds the old name. Comparing the endpoints of a commit range,
//! rather than replaying each commit, collapses `A -> B -> C` into `A -> C`
//! and cancels `A -> B -> A`.
//!
//! This module has no notion of git or the filesystem: it takes the text of
//! symbols files and says what to rename and what it could not.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::project::symbols::{Renames, symbol_name};

/// A symbol as written in a symbols file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolLine {
    pub name: String,
    pub section: String,
    pub address: u32,
    pub local: bool,
}

/// Where a symbol lives. REL modules have their own symbols files, so within
/// one file a section and address identify the place.
type Place = (String, u32);

/// One rename the source made between two revisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRename {
    pub old: String,
    pub new: String,
    pub section: String,
    pub address: u32,
    /// Whether the renamed symbol is `scope:local` at the newer revision.
    pub local: bool,
}

/// Parses one line of a symbols file: `name = .section:0xADDR; // attributes`.
pub fn parse_line(line: &str) -> Option<SymbolLine> {
    let name = symbol_name(line)?;
    let rest = line[name.len()..].trim_start().strip_prefix('=')?.trim_start();
    let (place, attributes) = rest.split_once(';')?;
    let (section, address) = place.trim().split_once(':')?;
    let address = u32::from_str_radix(address.trim().strip_prefix("0x")?, 16).ok()?;
    let local = attributes
        .split_once("//")
        .is_some_and(|(_, attributes)| attributes.split_whitespace().any(|a| a == "scope:local"));
    Some(SymbolLine { name: name.to_string(), section: section.to_string(), address, local })
}

fn by_place(text: &str) -> BTreeMap<Place, Vec<SymbolLine>> {
    let mut places: BTreeMap<Place, Vec<SymbolLine>> = BTreeMap::new();
    for symbol in text.lines().filter_map(parse_line) {
        places.entry((symbol.section.clone(), symbol.address)).or_default().push(symbol);
    }
    places
}

/// What differs between two revisions of the source's symbols.
#[derive(Debug, Default)]
pub struct SourceChanges {
    pub renames: Vec<SourceRename>,
    /// Places that hold several symbols at one of the revisions (a label and
    /// an object, say) and whose names changed. Which name became which is a
    /// guess, so none is made.
    pub ambiguous: Vec<(String, u32)>,
}

/// Finds the symbols renamed in place between `old` and `new`.
///
/// Only a place holding exactly one symbol at both revisions is paired.
/// Symbols that appear or disappear are not renames: a new symbol has nothing
/// in the target to rename, and a removed one is not this tool's to delete.
pub fn source_renames(old: &str, new: &str) -> SourceChanges {
    let (old, new) = (by_place(old), by_place(new));
    let mut changes = SourceChanges::default();
    for (place, before) in &old {
        let Some(after) = new.get(place) else { continue };
        let names = |symbols: &[SymbolLine]| -> BTreeSet<String> {
            symbols.iter().map(|s| s.name.clone()).collect()
        };
        if names(before) == names(after) {
            continue;
        }
        match (before.as_slice(), after.as_slice()) {
            ([before], [after]) => changes.renames.push(SourceRename {
                old: before.name.clone(),
                new: after.name.clone(),
                section: place.0.clone(),
                address: place.1,
                local: after.local,
            }),
            _ => changes.ambiguous.push(place.clone()),
        }
    }
    changes
}

/// Why a source rename was not turned into a target rename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skipped {
    /// The target already holds the new name: nothing to do.
    AlreadyApplied(SourceRename),
    /// The target has no symbol with the old name. It was never carried over
    /// (still `fn_XXXX`), or it was renamed since. A migration run names it
    /// from the current source.
    NotInTarget(SourceRename),
    /// The old name is held by several target symbols (local duplicates), so
    /// the name does not identify one of them.
    AmbiguousInTarget(SourceRename),
    /// Another source rename wants the same new name for a different old name,
    /// so applying either would collide.
    DuplicateNewName(SourceRename),
    /// The old name is derived from an address (`lbl_8041E6E8`, `fn_80003100`).
    /// Each version derives it from its own addresses, so another version's
    /// symbol of that name is a coincidence, not the same symbol.
    AddressDerived(SourceRename),
}

impl Skipped {
    pub fn rename(&self) -> &SourceRename {
        match self {
            Self::AlreadyApplied(r)
            | Self::NotInTarget(r)
            | Self::AmbiguousInTarget(r)
            | Self::DuplicateNewName(r)
            | Self::AddressDerived(r) => r,
        }
    }
}

#[derive(Debug, Default)]
pub struct SyncPlan {
    pub renames: Renames,
    pub applied: Vec<SourceRename>,
    pub skipped: Vec<Skipped>,
    pub ambiguous_places: Vec<(String, u32)>,
}

/// Whether a name is one dtk generates from the symbol's address, such as
/// `lbl_8041E6E8`, `fn_80003100` or `__dt__800057EC`.
pub fn is_address_derived(name: &str) -> bool {
    let Some((stem, address)) = name
        .len()
        .checked_sub(8)
        .and_then(|at| name.is_char_boundary(at).then(|| name.split_at(at)))
    else {
        return false;
    };
    stem.ends_with('_')
        && stem.len() > 1
        && address.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

/// Resolves source renames against the target's current names.
pub fn plan(changes: SourceChanges, target: &str) -> Result<SyncPlan> {
    let mut held: BTreeMap<String, usize> = BTreeMap::new();
    for symbol in target.lines().filter_map(parse_line) {
        *held.entry(symbol.name).or_default() += 1;
    }
    let mut wanted: BTreeMap<&str, usize> = BTreeMap::new();
    for rename in &changes.renames {
        *wanted.entry(rename.new.as_str()).or_default() += 1;
    }

    let mut result = SyncPlan { ambiguous_places: changes.ambiguous.clone(), ..Default::default() };
    for rename in &changes.renames {
        let count = |name: &str| held.get(name).copied().unwrap_or(0);
        let skip = if is_address_derived(&rename.old) {
            Some(Skipped::AddressDerived(rename.clone()))
        } else if wanted[rename.new.as_str()] > 1 {
            Some(Skipped::DuplicateNewName(rename.clone()))
        } else if count(&rename.new) > 0 && count(&rename.old) == 0 {
            Some(Skipped::AlreadyApplied(rename.clone()))
        } else if count(&rename.old) == 0 {
            Some(Skipped::NotInTarget(rename.clone()))
        } else if count(&rename.old) > 1 {
            Some(Skipped::AmbiguousInTarget(rename.clone()))
        } else {
            None
        };
        match skip {
            Some(skip) => result.skipped.push(skip),
            None => {
                result.renames.add(&rename.old, &rename.new, rename.local)?;
                result.applied.push(rename.clone());
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::symbols::render_renames;

    const BEFORE: &str = "\
fn_80000000 = .text:0x80000000; // type:function size:0x10
OldName = .text:0x80000010; // type:function size:0x10
Stable = .text:0x80000020; // type:function size:0x10
lbl_80001000 = .data:0x80001000; // type:object size:0x8
";
    const AFTER: &str = "\
Named = .text:0x80000000; // type:function size:0x10
NewName = .text:0x80000010; // type:function size:0x10 scope:local
Stable = .text:0x80000020; // type:function size:0x10
lbl_80001000 = .data:0x80001000; // type:object size:0x8
Added = .text:0x80000030; // type:function size:0x10
";

    #[test]
    fn lines_parse_their_place_and_scope() {
        let line = parse_line("A = .text:0x8000ABCD; // type:function scope:local").unwrap();
        assert_eq!((line.section.as_str(), line.address, line.local), (".text", 0x8000ABCD, true));
        assert!(parse_line("// comment").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn only_symbols_renamed_in_place_are_renames() {
        let changes = source_renames(BEFORE, AFTER);
        let pairs: Vec<_> =
            changes.renames.iter().map(|r| (r.old.as_str(), r.new.as_str(), r.local)).collect();
        assert_eq!(pairs, [("fn_80000000", "Named", false), ("OldName", "NewName", true)]);
        assert!(changes.ambiguous.is_empty());
    }

    #[test]
    fn a_rename_applies_to_the_target_symbol_holding_the_old_name() {
        let target = "\
OldName = .text:0x80100010; // type:function size:0x10
Stable = .text:0x80100020; // type:function size:0x10
";
        let plan = plan(source_renames(BEFORE, AFTER), target).unwrap();
        assert_eq!(plan.applied.len(), 1);
        assert!(
            matches!(plan.skipped.as_slice(), [Skipped::AddressDerived(r)] if r.new == "Named")
        );
        let (text, report) = render_renames(target, &plan.renames);
        assert_eq!(report.applied, 1);
        assert!(
            text.contains("NewName = .text:0x80100010; // type:function size:0x10 scope:local")
        );
    }

    #[test]
    fn a_rename_the_target_already_has_is_not_applied_twice() {
        let target = "NewName = .text:0x80100010; // type:function size:0x10\n";
        let plan = plan(source_renames(BEFORE, AFTER), target).unwrap();
        assert!(plan.applied.is_empty());
        assert!(plan.skipped.iter().any(|s| matches!(s, Skipped::AlreadyApplied(_))));
    }

    #[test]
    fn a_name_held_twice_in_the_target_does_not_identify_a_symbol() {
        let target = "\
OldName = .text:0x80100010; // type:function size:0x10 scope:local
OldName = .text:0x80100050; // type:function size:0x10 scope:local
";
        let plan = plan(source_renames(BEFORE, AFTER), target).unwrap();
        assert!(plan.applied.is_empty());
        assert!(plan.skipped.iter().any(|s| matches!(s, Skipped::AmbiguousInTarget(_))));
    }

    #[test]
    fn two_renames_to_one_name_are_both_refused() {
        let before = "A = .text:0x1; // x\nB = .text:0x2; // x\n";
        let after = "C = .text:0x1; // x\nC = .text:0x2; // x\n";
        let target = "A = .text:0x9; // x\nB = .text:0xA; // x\n";
        let plan = plan(source_renames(before, after), target).unwrap();
        assert!(plan.applied.is_empty());
        assert_eq!(plan.skipped.len(), 2);
    }

    #[test]
    fn a_name_derived_from_an_address_does_not_identify_a_target_symbol() {
        assert!(is_address_derived("lbl_8041E6E8"));
        assert!(is_address_derived("fn_80003100"));
        assert!(is_address_derived("__dt__800057EC"));
        assert!(!is_address_derived("skCosX2"));
        assert!(!is_address_derived("lbl_"));
        let before = "lbl_8041E6E8 = .sdata2:0x8041E6E8; // x
";
        let after = "skCosX2 = .sdata2:0x8041E6E8; // x
";
        // The target's own lbl_8041E6E8 is at an unrelated place.
        let target = "lbl_8041E6E8 = .sdata2:0x8041E6E8; // x
";
        let plan = plan(source_renames(before, after), target).unwrap();
        assert!(plan.applied.is_empty());
        assert!(matches!(plan.skipped.as_slice(), [Skipped::AddressDerived(_)]));
    }

    #[test]
    fn a_swap_is_applied_whole() {
        let before = "A = .text:0x1; // x\nB = .text:0x2; // x\n";
        let after = "B = .text:0x1; // x\nA = .text:0x2; // x\n";
        let target = "A = .text:0x11; // x\nB = .text:0x12; // x\n";
        let plan = plan(source_renames(before, after), target).unwrap();
        let (text, report) = render_renames(target, &plan.renames);
        assert_eq!(report.applied, 2, "{text}");
        assert!(text.starts_with("B = .text:0x11"));
    }

    #[test]
    fn a_place_with_several_symbols_is_reported_not_guessed() {
        let before = "@3 = .data:0x10; // x\n...data.0 = .data:0x10; // x\n";
        let after = "@3 = .data:0x10; // x\nOther = .data:0x10; // x\n";
        let changes = source_renames(before, after);
        assert!(changes.renames.is_empty());
        assert_eq!(changes.ambiguous, [(".data".to_string(), 0x10)]);
    }
}
