//! Hiding a version's split ownership, so the coverage policy can be scored on
//! a version that already has the answers.
//!
//! Calibration asks the policy for boundaries the project already knows, which
//! is only a question if the answer is out of reach. The answer lives in the
//! target's own splits, and the neighbour-based evidence reads those straight
//! off the analysed object — so blanking the owner's name on the way out is not
//! enough. The generators would still be bounding their gaps with the very
//! boundaries they are being asked to find.
//!
//! The hiding therefore happens to the object itself, before any analysis runs.
//! Every reader then agrees about what is known, because there is nothing left
//! to disagree about. What a scenario leaves behind is a state a migration could
//! really be in, and [`Masked::hidden`] names the units actually being asked.

use std::collections::{BTreeMap, BTreeSet};

use clap::ValueEnum;
use decomp_toolkit::obj::{ObjInfo, ObjSectionKind, ObjSymbolKind, SectionIndex};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// How much of the target's split ownership to hide.
///
/// Every scenario but [`Scenario::Nothing`] describes a distinct way real splits
/// are wrong, so that recovering from each can be measured on its own rather
/// than averaged into one number.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    /// Nothing is hidden. What a real migration run uses.
    #[default]
    Nothing,
    /// Every unit's splits removed: the state a version begins a migration in.
    Everything,
    /// Alternating units removed, so each hidden unit keeps both neighbours.
    /// The case the neighbour-bounded generators are built for.
    IsolatedUnit,
    /// Runs of three units removed together, with a visible unit either side,
    /// so one window has to account for more than one missing unit.
    ConsecutiveUnits,
    /// Alternating units keep their start and lose their last function: a split
    /// that is present, and short.
    TruncatedSplits,
    /// Alternating units hand their last function to the unit after them, so
    /// ownership is wrong rather than missing.
    ///
    /// The function moved is whichever one happens to sit last, which is not
    /// the same thing as a helper: a real shared or indirectly referenced
    /// helper needs the compiled source object to identify, and until that
    /// evidence exists this measures recovery from a misplaced *tail*. Read the
    /// result as that, not as helper-ownership recovery.
    MisplacedHelper,
}

impl Scenario {
    /// Every scenario that hides something, in the order a report lists them.
    pub const HIDING: [Scenario; 5] = [
        Scenario::Everything,
        Scenario::IsolatedUnit,
        Scenario::ConsecutiveUnits,
        Scenario::TruncatedSplits,
        Scenario::MisplacedHelper,
    ];

    /// Whether the scenario promises every hidden run a visible unit at both
    /// ends. [`Scenario::Everything`] promises nothing — there is no anchor left
    /// anywhere, and that is the point of it.
    pub fn promises_anchors(self) -> bool {
        !matches!(self, Scenario::Nothing | Scenario::Everything)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scenario::Nothing => "nothing",
            Scenario::Everything => "everything",
            Scenario::IsolatedUnit => "isolated-unit",
            Scenario::ConsecutiveUnits => "consecutive-units",
            Scenario::TruncatedSplits => "truncated-splits",
            Scenario::MisplacedHelper => "misplaced-helper",
        }
    }
}

/// What a scenario did, and to whom.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Masked {
    pub scenario: Scenario,
    /// The units under test: those whose true extent the analysis can no longer
    /// read off the target. A unit a scenario selected but could not alter —
    /// nothing to truncate, no neighbour to hand a function to — is not here,
    /// because its answer was never hidden.
    pub hidden: BTreeSet<String>,
    /// The splits left standing, in the form the alternatives builder reads.
    /// Empty under [`Scenario::Nothing`], where the project's own file says the
    /// same thing and says it better.
    pub visible: IndexMap<String, Vec<String>>,
}

impl Masked {
    /// Whether any ownership was hidden at all.
    pub fn hides_anything(&self) -> bool { self.scenario != Scenario::Nothing }
}

/// Applies a scenario to an analysed target, in place.
pub fn apply(obj: &mut ObjInfo, scenario: Scenario) -> Masked {
    if scenario == Scenario::Nothing {
        return Masked::default();
    }
    let selected = select(obj, scenario);
    let hidden = match scenario {
        Scenario::Nothing => BTreeSet::new(),
        Scenario::Everything | Scenario::IsolatedUnit | Scenario::ConsecutiveUnits => {
            remove(obj, &selected)
        }
        Scenario::TruncatedSplits => truncate(obj, &selected),
        Scenario::MisplacedHelper => misplace(obj, &selected),
    };
    Masked { scenario, hidden, visible: visible_blocks(obj) }
}

/// The units a scenario touches, with every neighbour it promises left visible.
///
/// Windows are built inside one section at a time. Two units adjacent in `.text`
/// are not adjacent in `.init`, and a window laid across the seam between the
/// two sections would promise an anchor that is not next to anything — which
/// would quietly mix bounded recovery failures in with unbounded ones, and the
/// point of these scenarios is to keep those apart.
///
/// A unit another section needs as an anchor is then dropped from the selection,
/// so the promise holds in every section rather than on average.
fn select(obj: &ObjInfo, scenario: Scenario) -> BTreeSet<String> {
    let orders = code_orders(obj);
    let mut chosen: BTreeSet<String> = BTreeSet::new();
    let mut anchors: BTreeSet<String> = BTreeSet::new();
    for order in &orders {
        for (hide, keep) in windows(scenario, order.len()) {
            chosen.extend(hide.into_iter().map(|at| order[at].clone()));
            anchors.extend(keep.into_iter().map(|at| order[at].clone()));
        }
    }
    let mut hidden: BTreeSet<String> = chosen.difference(&anchors).cloned().collect();
    if scenario.promises_anchors() {
        enforce_anchors(&orders, &mut hidden);
    }
    hidden
}

/// The units of each code section, in address order, first appearance only.
fn code_orders(obj: &ObjInfo) -> Vec<Vec<String>> {
    let generated = autogenerated(obj);
    let mut orders = Vec::new();
    for (_, section) in obj.sections.iter() {
        if section.kind != ObjSectionKind::Code {
            continue;
        }
        let mut order: Vec<String> = Vec::new();
        for (_, split) in section.splits.iter() {
            if !generated.contains(split.unit.as_str()) && !order.contains(&split.unit) {
                order.push(split.unit.clone());
            }
        }
        orders.push(order);
    }
    orders
}

/// Unhides whatever it takes for every run of hidden units to be closed by a
/// visible unit at both ends, in every code section.
///
/// The windows alone cannot promise this. A section too short to hold a window
/// contributes no anchors, so a unit chosen by some *other* section's window can
/// be hidden there with nothing beside it — a `.text` of five units and an
/// `.init` holding only the one being hidden leaves `.init` with no splits at
/// all. That is an unbounded gap reported as a bounded one, which is the one
/// thing these scenarios exist to keep apart.
fn enforce_anchors(orders: &[Vec<String>], hidden: &mut BTreeSet<String>) {
    // Unhiding a unit can only ever give another run the anchor it was missing,
    // so this shrinks monotonically and settles.
    loop {
        let mut freed: BTreeSet<String> = BTreeSet::new();
        for order in orders {
            let mut at = 0;
            while at < order.len() {
                if !hidden.contains(&order[at]) {
                    at += 1;
                    continue;
                }
                let start = at;
                while at < order.len() && hidden.contains(&order[at]) {
                    at += 1;
                }
                if start == 0 {
                    freed.insert(order[start].clone());
                }
                if at == order.len() {
                    freed.insert(order[at - 1].clone());
                }
            }
        }
        if freed.is_empty() {
            return;
        }
        hidden.retain(|unit| !freed.contains(unit));
    }
}

/// One scenario's windows over a section holding `len` units, as the positions
/// to hide and the positions that must stay visible to bound them.
fn windows(scenario: Scenario, len: usize) -> Vec<(Vec<usize>, Vec<usize>)> {
    match scenario {
        Scenario::Nothing => Vec::new(),
        // No anchors to promise: nothing is left to bound a gap with.
        Scenario::Everything => vec![((0..len).collect(), Vec::new())],
        // Every other unit, each with the neighbour on both sides.
        Scenario::IsolatedUnit | Scenario::TruncatedSplits | Scenario::MisplacedHelper => (1..len
            .saturating_sub(1))
            .step_by(2)
            .map(|at| (vec![at], vec![at - 1, at + 1]))
            .collect(),
        // Runs of three, spaced so that one visible unit closes each run and
        // opens the next. A section too short to close a run gets none.
        Scenario::ConsecutiveUnits => (1..len.saturating_sub(3))
            .step_by(5)
            .map(|at| (vec![at, at + 1, at + 2], vec![at - 1, at + 3]))
            .collect(),
    }
}

/// Drops every split of the named units, in every section. A unit's data goes
/// with its code: half a unit is not a state a migration ever starts from.
fn remove(obj: &mut ObjInfo, units: &BTreeSet<String>) -> BTreeSet<String> {
    let mut removed = BTreeSet::new();
    for (_, section) in obj.sections.iter_mut() {
        let addresses: BTreeSet<u32> = section.splits.iter().map(|(address, _)| address).collect();
        for address in addresses {
            let Some(splits) = section.splits.remove(address) else { continue };
            for split in splits {
                if units.contains(&split.unit) {
                    removed.insert(split.unit.clone());
                } else {
                    section.splits.push(address, split);
                }
            }
        }
    }
    removed
}

/// Cuts each unit's last function out of its own split, leaving a range that
/// starts right and stops short — the shape the matcher leaves behind when it
/// runs out of functions it can place.
fn truncate(obj: &mut ObjInfo, units: &BTreeSet<String>) -> BTreeSet<String> {
    let mut truncated = BTreeSet::new();
    for (index, address, _, last, unit) in tails(obj, units) {
        set_end(obj, index, address, &unit, last);
        truncated.insert(unit);
    }
    truncated
}

/// Hands each unit's last function to the unit that follows it, so its boundary
/// is wrong rather than missing.
fn misplace(obj: &mut ObjInfo, units: &BTreeSet<String>) -> BTreeSet<String> {
    let mut moved = BTreeSet::new();
    for (index, address, boundary, last, unit) in tails(obj, units) {
        let Some(section) = obj.sections.get_mut(index) else { continue };
        // Only a unit starting exactly where this one ends can take it.
        let Some(neighbour) = section.splits.remove(boundary) else { continue };
        for split in neighbour {
            section.splits.push(last, split);
        }
        set_end(obj, index, address, &unit, last);
        moved.insert(unit);
    }
    moved
}

/// Each selected unit's code split whose last function can be taken off it, as
/// `(section, split start, split end, last function address, unit)`.
///
/// A unit split across two code sections is listed twice, and a unit whose split
/// holds a single function is not listed at all: cutting that one would leave an
/// empty range rather than a short one.
fn tails(obj: &ObjInfo, units: &BTreeSet<String>) -> Vec<(SectionIndex, u32, u32, u32, String)> {
    let mut found = Vec::new();
    for (index, section, address, split) in obj.sections.all_splits() {
        if section.kind != ObjSectionKind::Code || split.end == 0 || !units.contains(&split.unit) {
            continue;
        }
        let Some(last) = last_function(obj, index, address, split.end) else { continue };
        if last > address {
            found.push((index, address, split.end, last, split.unit.clone()));
        }
    }
    found
}

/// Where the last function inside a range begins.
fn last_function(obj: &ObjInfo, section: SectionIndex, start: u32, end: u32) -> Option<u32> {
    obj.symbols
        .for_section_range(section, start..end)
        .filter(|(_, symbol)| symbol.kind == ObjSymbolKind::Function && symbol.size > 0)
        .map(|(_, symbol)| symbol.address as u32)
        .next_back()
}

fn set_end(obj: &mut ObjInfo, section: SectionIndex, address: u32, unit: &str, end: u32) {
    let Some(section) = obj.sections.get_mut(section) else { return };
    for (at, split) in section.splits.iter_mut() {
        if at == address && split.unit == unit {
            split.end = end;
        }
    }
}

/// The splits still standing, as `splits.txt` lines.
fn visible_blocks(obj: &ObjInfo) -> IndexMap<String, Vec<String>> {
    let generated = autogenerated(obj);
    let mut blocks: IndexMap<String, Vec<String>> = IndexMap::new();
    for (_, section, address, split) in obj.sections.all_splits() {
        if generated.contains(split.unit.as_str()) {
            continue;
        }
        blocks.entry(split.unit.clone()).or_default().push(format!(
            "\t{:11} start:0x{address:08X} end:0x{:08X}",
            section.name,
            split_end(split.end, section.address + section.size)
        ));
    }
    blocks
}

/// Every unit's true extent per section, for a scorer that needs the answer a
/// scenario is about to hide.
pub fn true_extents(obj: &ObjInfo) -> BTreeMap<String, Vec<(String, u32, u32)>> {
    let mut result: BTreeMap<String, Vec<(String, u32, u32)>> = BTreeMap::new();
    for (_, section, address, split) in obj.sections.all_splits() {
        let end = split_end(split.end, section.address + section.size);
        result.entry(split.unit.clone()).or_default().push((section.name.clone(), address, end));
    }
    result
}

/// A split's end, resolving the zero that means "to the end of the section".
fn split_end(end: u32, section_end: u64) -> u32 { if end == 0 { section_end as u32 } else { end } }

/// The units dtk generated as placeholders, in one pass.
///
/// `ObjInfo::is_unit_autogenerated` walks every split in the object, so asking
/// it once per split turns a whole-object scan quadratic.
fn autogenerated(obj: &ObjInfo) -> BTreeSet<&str> {
    let mut explicit: BTreeSet<&str> = BTreeSet::new();
    let mut generated: BTreeSet<&str> = BTreeSet::new();
    for (_, _, _, split) in obj.sections.all_splits() {
        if split.autogenerated { &mut generated } else { &mut explicit }.insert(&split.unit);
    }
    generated.difference(&explicit).copied().collect()
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::obj::{
        ObjArchitecture, ObjKind, ObjRelocations, ObjSection, ObjSplit, ObjSplits, ObjSymbol,
    };

    use super::*;

    /// `.text` holds eight units end to end; `.init` holds three of them again
    /// in a different order, so that adjacency in one section says nothing about
    /// adjacency in the other.
    const TEXT: [&str; 8] = ["a.c", "b.c", "c.c", "d.c", "e.c", "f.c", "g.c", "h.c"];
    const INIT: [&str; 3] = ["h.c", "a.c", "e.c"];

    fn code_section(name: &str, index: SectionIndex, base: u32, units: &[&str]) -> ObjSection {
        let mut splits = ObjSplits::default();
        for (at, unit) in units.iter().enumerate() {
            let start = base + at as u32 * 0x100;
            splits.push(start, ObjSplit {
                unit: (*unit).to_string(),
                end: start + 0x100,
                align: None,
                common: false,
                autogenerated: false,
                skip: false,
                rename: None,
            });
        }
        let size = units.len() as u64 * 0x100;
        ObjSection {
            name: name.to_string(),
            kind: ObjSectionKind::Code,
            address: u64::from(base),
            size,
            data: vec![0; size as usize],
            align: 4,
            elf_index: index,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits,
        }
    }

    /// Two functions of 0x80 in every 0x100 unit, so each split has a tail that
    /// can be taken off it.
    fn functions(section: SectionIndex, base: u32, units: usize) -> Vec<ObjSymbol> {
        (0..units as u32)
            .flat_map(|unit| (0..2u32).map(move |half| base + unit * 0x100 + half * 0x80))
            .map(|address| ObjSymbol {
                name: format!("fn_{address:X}"),
                address: u64::from(address),
                section: Some(section),
                size: 0x80,
                size_known: true,
                kind: ObjSymbolKind::Function,
                ..Default::default()
            })
            .collect()
    }

    fn object() -> ObjInfo {
        let mut symbols = functions(0, 0, TEXT.len());
        symbols.extend(functions(1, 0x1000, INIT.len()));
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "target".to_string(),
            symbols,
            vec![code_section(".text", 0, 0, &TEXT), code_section(".init", 1, 0x1000, &INIT)],
        )
    }

    fn names(units: &[&str]) -> BTreeSet<String> {
        units.iter().map(|unit| (*unit).to_string()).collect()
    }

    /// One unit's extent in one section, if it still has one.
    fn extent(obj: &ObjInfo, section: &str, unit: &str) -> Option<(u32, u32)> {
        obj.sections
            .all_splits()
            .find(|(_, s, _, split)| s.name == section && split.unit == unit)
            .map(|(_, _, address, split)| (address, split.end))
    }

    /// Every unit still visible in a section, in address order.
    fn order(obj: &ObjInfo, section: &str) -> Vec<String> {
        obj.sections
            .all_splits()
            .filter(|(_, s, _, _)| s.name == section)
            .map(|(_, _, _, split)| split.unit.clone())
            .collect()
    }

    /// Asserts that every run of hidden units is closed by a visible unit at
    /// both ends, in every section it appears in.
    ///
    /// A run is bounded as a run, not unit by unit: the middle of three
    /// consecutive hidden units has no visible neighbour and is not supposed to.
    /// What must hold is that the gap itself has an anchor either side, which is
    /// the whole promise these scenarios make — and the reason their results can
    /// be read as bounded recovery rather than a mix of bounded and unbounded.
    fn assert_bounded(before: &ObjInfo, after: &ObjInfo, hidden: &BTreeSet<String>) {
        for section in [".text", ".init"] {
            let original = order(before, section);
            let remaining = order(after, section);
            let mut at = 0;
            while at < original.len() {
                if !hidden.contains(&original[at]) {
                    at += 1;
                    continue;
                }
                let start = at;
                while at < original.len() && hidden.contains(&original[at]) {
                    at += 1;
                }
                let run = &original[start..at];
                let left = start.checked_sub(1).map(|before| &original[before]);
                let right = original.get(at);
                assert!(
                    left.is_some_and(|name| remaining.contains(name)),
                    "the run {run:?} has no visible left anchor in {section}"
                );
                assert!(
                    right.is_some_and(|name| remaining.contains(name)),
                    "the run {run:?} has no visible right anchor in {section}"
                );
            }
        }
    }

    #[test]
    fn hiding_everything_leaves_no_split_to_read() {
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::Everything);
        assert_eq!(masked.hidden.len(), TEXT.len());
        assert_eq!(obj.sections.all_splits().count(), 0);
        assert!(masked.visible.is_empty());
    }

    #[test]
    fn an_isolated_unit_keeps_both_its_neighbours_visible() {
        let before = object();
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::IsolatedUnit);
        assert_eq!(masked.hidden, names(&["b.c", "d.c", "f.c"]));
        assert_bounded(&before, &obj, &masked.hidden);
    }

    #[test]
    fn the_last_unit_in_a_section_is_never_hidden() {
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::IsolatedUnit);
        // It has no right neighbour, so hiding it would be an unbounded gap
        // reported as a bounded one.
        assert!(!masked.hidden.contains("h.c"));
        assert_eq!(extent(&obj, ".text", "h.c"), Some((0x700, 0x800)));
    }

    #[test]
    fn a_unit_another_section_needs_as_an_anchor_stays_visible() {
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::IsolatedUnit);
        // `.init` lists a.c between h.c and e.c, so its own window would hide
        // it — but `.text` needs it to bound b.c, and the promise wins.
        assert!(!masked.hidden.contains("a.c"));
        assert_eq!(extent(&obj, ".init", "a.c"), Some((0x1100, 0x1200)));
    }

    #[test]
    fn consecutive_units_hide_a_run_bounded_on_both_sides() {
        let before = object();
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::ConsecutiveUnits);
        assert_eq!(masked.hidden, names(&["b.c", "c.c", "d.c"]));
        assert_eq!(extent(&obj, ".text", "a.c"), Some((0x000, 0x100)));
        assert_eq!(extent(&obj, ".text", "e.c"), Some((0x400, 0x500)));
        assert_bounded(&before, &obj, &masked.hidden);
    }

    /// A secondary section holding a single unit, which is the one the primary
    /// section's window wants to hide.
    fn lone_secondary() -> ObjInfo {
        let text = ["a.c", "b.c", "c.c", "d.c", "e.c"];
        let mut symbols = functions(0, 0, text.len());
        symbols.extend(functions(1, 0x1000, 1));
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "target".to_string(),
            symbols,
            vec![code_section(".text", 0, 0, &text), code_section(".init", 1, 0x1000, &["b.c"])],
        )
    }

    #[test]
    fn a_section_too_short_for_a_window_still_keeps_its_anchors() {
        let before = lone_secondary();
        let mut obj = lone_secondary();
        let masked = apply(&mut obj, Scenario::IsolatedUnit);
        // `.text` would hide b.c and d.c; b.c is the whole of `.init`, so
        // hiding it would leave that section with nothing to bound a gap with.
        assert!(!masked.hidden.contains("b.c"));
        assert_eq!(masked.hidden, names(&["d.c"]));
        assert_bounded(&before, &obj, &masked.hidden);
    }

    #[test]
    fn a_short_secondary_section_survives_the_consecutive_scenario_too() {
        let before = lone_secondary();
        let mut obj = lone_secondary();
        let masked = apply(&mut obj, Scenario::ConsecutiveUnits);
        // `.text` has five units, so its one run is b.c, c.c, d.c — but b.c
        // alone fills `.init`, and a run cannot be closed there.
        assert!(!masked.hidden.contains("b.c"));
        assert_bounded(&before, &obj, &masked.hidden);
    }

    #[test]
    fn a_section_too_short_to_close_a_run_contributes_none() {
        // `.init` has three units, so a run of three cannot be bounded there.
        assert!(windows(Scenario::ConsecutiveUnits, INIT.len()).is_empty());
        assert!(windows(Scenario::ConsecutiveUnits, 4).is_empty());
        assert_eq!(windows(Scenario::ConsecutiveUnits, 5), vec![(vec![1, 2, 3], vec![0, 4])]);
    }

    #[test]
    fn a_truncated_split_keeps_its_start_and_loses_its_last_function() {
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::TruncatedSplits);
        assert_eq!(masked.hidden, names(&["b.c", "d.c", "f.c"]));
        assert_eq!(extent(&obj, ".text", "b.c"), Some((0x100, 0x180)));
        // Untouched units keep the whole of theirs.
        assert_eq!(extent(&obj, ".text", "a.c"), Some((0x000, 0x100)));
        assert_eq!(extent(&obj, ".text", "c.c"), Some((0x200, 0x300)));
    }

    #[test]
    fn a_misplaced_tail_lands_in_the_next_unit_rather_than_nowhere() {
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::MisplacedHelper);
        assert_eq!(masked.hidden, names(&["b.c", "d.c", "f.c"]));
        assert_eq!(extent(&obj, ".text", "b.c"), Some((0x100, 0x180)));
        // The function b.c lost is inside c.c now, not unowned.
        assert_eq!(extent(&obj, ".text", "c.c"), Some((0x180, 0x300)));
        // And no unit is both robbed and robbing, which would move both of its
        // boundaries at once.
        assert_eq!(extent(&obj, ".text", "e.c"), Some((0x380, 0x500)));
    }

    #[test]
    fn masking_nothing_touches_nothing() {
        let mut obj = object();
        let masked = apply(&mut obj, Scenario::Nothing);
        assert!(masked.hidden.is_empty());
        assert_eq!(obj.sections.all_splits().count(), TEXT.len() + INIT.len());
    }

    #[test]
    fn the_true_extents_survive_for_the_scorer() {
        let obj = object();
        let extents = true_extents(&obj);
        assert_eq!(extents["b.c"], vec![(".text".to_string(), 0x100, 0x200)]);
        assert_eq!(extents["a.c"], vec![
            (".text".to_string(), 0x000, 0x100),
            (".init".to_string(), 0x1100, 0x1200),
        ]);
    }
}
