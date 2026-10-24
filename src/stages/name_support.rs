//! Ownership claimed from names alone.
//!
//! The ownership model discover normally uses needs independent attribution,
//! which on a version whose compiled source does not match the binary is
//! mostly unavailable. This is a weaker claim, opt-in, and labelled as such:
//! a proposed code range belongs to a unit when most of the functions that
//! unit's compiled object defines strongly are the very functions the target
//! symbols file names inside that range.
//!
//! A weak definition is never counted. It is repeated in every object that
//! uses it, so finding it in a range says nothing about who owns the range.
//! The claim is not self-validating; the build and retail hash check decide
//! whether it holds.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::project::rename_sync;

/// What a range's names say about its owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameSupport {
    /// Strong function definitions in the unit's compiled object.
    pub strong_functions: u32,
    /// Of those, how many are named inside the proposed range.
    pub members: u32,
    /// Every function the symbols file places inside the range.
    pub span_functions: u32,
}

impl NameSupport {
    /// Two named members is the least that is not a coincidence, and at least
    /// half of the unit's own functions must be there. A range holding far
    /// more functions than the unit defines has swallowed its neighbours.
    pub fn permits(&self) -> bool {
        self.members >= 2
            && self.members * 2 >= self.strong_functions
            && self.span_functions <= self.strong_functions.saturating_mul(2)
    }
}

/// Counts what `symbols` names inside the `.text` ranges.
pub fn assess(symbols: &str, strong: &BTreeSet<String>, ranges: &[(u32, u32)]) -> NameSupport {
    let (mut members, mut span) = (0u32, 0u32);
    for line in symbols.lines() {
        let Some(symbol) = rename_sync::parse_line(line) else { continue };
        if symbol.section != ".text" {
            continue;
        }
        let is_function = line.split_once("//").is_some_and(|(_, attributes)| {
            attributes.split_whitespace().any(|a| a == "type:function")
        });
        let address = symbol.address;
        if !is_function || !ranges.iter().any(|&(start, end)| address >= start && address < end) {
            continue;
        }
        span += 1;
        if strong.contains(&symbol.name) {
            members += 1;
        }
    }
    NameSupport { strong_functions: strong.len() as u32, members, span_functions: span }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbols() -> String {
        [
            "Alpha__1AFv = .text:0x80000000; // type:function size:0x10",
            "Beta__1AFv = .text:0x80000010; // type:function size:0x10",
            "fn_80000020 = .text:0x80000020; // type:function size:0x10",
            "lbl_80000030 = .data:0x80000030; // size:0x4",
        ]
        .join("\n")
    }

    fn strong(names: &[&str]) -> BTreeSet<String> { names.iter().map(|n| n.to_string()).collect() }

    #[test]
    fn named_members_inside_the_range_support_it() {
        let found = assess(&symbols(), &strong(&["Alpha__1AFv", "Beta__1AFv"]), &[(
            0x8000_0000,
            0x8000_0030,
        )]);
        assert_eq!((found.members, found.span_functions), (2, 3));
        assert!(found.permits());
    }

    #[test]
    fn a_single_member_is_not_enough() {
        let found = assess(&symbols(), &strong(&["Alpha__1AFv", "Gamma__1AFv"]), &[(
            0x8000_0000,
            0x8000_0010,
        )]);
        assert!(!found.permits());
    }

    #[test]
    fn data_symbols_and_outside_functions_are_not_counted() {
        let found = assess(&symbols(), &strong(&["Alpha__1AFv"]), &[(0x8000_0000, 0x8000_0010)]);
        assert_eq!(found.span_functions, 1);
    }

    #[test]
    fn a_range_swallowing_neighbours_is_refused() {
        let support = NameSupport { strong_functions: 2, members: 2, span_functions: 5 };
        assert!(!support.permits());
    }
}
