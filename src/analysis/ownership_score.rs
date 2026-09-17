//! Scoring split ownership against a version that already has the answers.
//!
//! Two different questions share this arithmetic, and they must share it
//! literally rather than by resemblance:
//!
//! * **Calibration** hides part of a finished version's ownership and asks
//!   whether the policy puts it back.
//! * **The historical benchmark** replays a real migration against a later
//!   revision of the same project and asks what it actually recovered.
//!
//! Two scorers would drift, and a drift here is invisible: both would still
//! produce plausible numbers, and the numbers would stop meaning the same
//! thing. So the vocabulary — what *exact* means, when a range is somebody
//! else's, how bytes are attributed — lives here once.
//!
//! Nothing in this module is an input to inference. It reads answers a
//! migration is not allowed to see, which is the whole reason it is kept out of
//! [`crate::stages`] and out of the rest of [`crate::analysis`]'s call graph.
//! A test in `tests/historical_recall.rs` enforces that separation, because the
//! failure it prevents — an oracle quietly reaching the matcher — produces a
//! benchmark that reports excellent results and means nothing.
//!
//! # What is measured apart
//!
//! Addresses, not totals. A body that swaps `0x100..0x200` for `0x200..0x300`
//! keeps its byte count exactly and has given up every address it owned, so
//! everything here is computed as interval set algebra per section and only
//! then summed. That is also why gaining and losing are separate numbers
//! rather than one signed difference: a change that takes 0x80 correct bytes
//! and returns 0x80 different correct bytes is not a change that did nothing.
//!
//! Semantics and formatting are also apart. Two bodies own the same ground when
//! their merged intervals agree; whether they are written the same way, with the
//! same `align:` and `common` attributes, is a second question with its own
//! answer.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::{
    analysis::coverage::TargetFunction,
    project::splits::{Range, parse_attributes, parse_range},
    stages::{coverage::alternatives::parse_address, discover::CODE_SECTIONS},
};

/// Unit name to its `splits.txt` entry lines, as every reader of a split file
/// already holds them.
pub type Blocks = IndexMap<String, Vec<String>>;

/// Which sections a measurement counts.
///
/// Reported separately rather than chosen once, because they answer different
/// questions: an alternative only ever claims code, so scoring coverage over
/// everything would read a unit's untouched `.data` as permanently missed —
/// while a benchmark that only ever counted code would score
/// `CStreamAudioManager` as a complete recovery when it dropped a `.bss` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// `.text` and `.init` only.
    Code,
    /// Every section a split file names.
    Everything,
}

impl Scope {
    pub fn includes(self, section: &str) -> bool {
        match self {
            Scope::Code => CODE_SECTIONS.contains(&section),
            Scope::Everything => true,
        }
    }
}

/// One `splits.txt` entry: a range and whatever its line carried after it.
///
/// The attributes belong to the *entry*, not to the section. Ten of Prime's
/// units hold two `.bss` ranges of which only the second is `align:4 common` —
/// ordinary BSS and common BSS — so pooling attributes per section could not
/// say which range was which, and rendering such a body back out would put
/// `common` on both.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Entry {
    #[serde(flatten)]
    pub range: Range,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub attributes: BTreeSet<String>,
}

/// Everything one unit owns, in a form two revisions can be compared in.
///
/// Structure and ownership are different questions asked of the same value.
/// [`Body::entries`] is what the file says, entry by entry;
/// [`Body::intervals`] merges those into the ground the unit actually holds.
/// Two bodies can agree on the second and differ on the first, and which of
/// those happened is usually the interesting part.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// Every entry, ordered by section and address, so that a file writing the
    /// same ranges in another order compares equal.
    pub entries: Vec<Entry>,
}

impl Body {
    /// Reads one unit's body out of a parsed split file.
    pub fn of(blocks: &Blocks, unit: &str) -> Self {
        let lines = blocks.get(unit).map(Vec::as_slice).unwrap_or_default();
        Self::new(
            lines
                .iter()
                .filter_map(|line| {
                    Some(Entry { range: parse_range(line)?, attributes: parse_attributes(line) })
                })
                .collect(),
        )
    }

    pub fn new(mut entries: Vec<Entry>) -> Self {
        entries.sort();
        Self { entries }
    }

    /// The same body with everything outside `scope` dropped.
    pub fn within(&self, scope: Scope) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|entry| scope.includes(&entry.range.section))
                .cloned()
                .collect(),
        }
    }

    /// The ground this body holds, with touching ranges joined.
    pub fn intervals(&self) -> Vec<Range> {
        merged(self.entries.iter().map(|entry| entry.range.clone()).collect())
    }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn bytes(&self) -> u32 { total(&self.intervals()) }

    /// Whether these two own precisely the same ground, however it is written.
    pub fn same_ownership(&self, other: &Self) -> bool { self.intervals() == other.intervals() }

    /// Whether they are also written the same way, entry for entry, with the
    /// same attributes on each.
    pub fn same_structure(&self, other: &Self) -> bool { self.entries == other.entries }

    /// The body written back as `splits.txt` lines.
    ///
    /// The exact inverse of [`Body::of`], attributes included and on the right
    /// range, so a manifest can be reduced to split files and read back without
    /// the round trip changing what it says.
    pub fn render(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| {
                let mut line = format!(
                    "\t{:11} start:0x{:08X} end:0x{:08X}",
                    entry.range.section, entry.range.start, entry.range.end
                );
                for attribute in &entry.attributes {
                    line.push(' ');
                    line.push_str(attribute);
                }
                line
            })
            .collect()
    }
}

/// Every unit's answer, indexed so a question about one address is cheap.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Oracle {
    bodies: BTreeMap<String, Body>,
}

impl Oracle {
    pub fn of(blocks: &Blocks) -> Self {
        Self { bodies: blocks.keys().map(|name| (name.clone(), Body::of(blocks, name))).collect() }
    }

    pub fn units(&self) -> impl Iterator<Item = &String> { self.bodies.keys() }

    pub fn body(&self, unit: &str) -> Body { self.bodies.get(unit).cloned().unwrap_or_default() }

    pub fn places(&self, unit: &str) -> bool {
        self.bodies.get(unit).is_some_and(|body| !body.is_empty())
    }

    /// Everything the oracle gives to somebody other than `unit`.
    ///
    /// Merged across owners, because for the question "is this ground somebody
    /// else's?" it does not matter which somebody.
    pub fn foreign(&self, unit: &str, scope: Scope) -> Vec<Range> {
        merged(
            self.bodies
                .iter()
                .filter(|(name, _)| name.as_str() != unit)
                .flat_map(|(_, body)| body.within(scope).intervals())
                .collect(),
        )
    }

    /// Everything the oracle gives to anybody at all.
    pub fn claimed(&self, scope: Scope) -> Vec<Range> {
        merged(self.bodies.values().flat_map(|body| body.within(scope).intervals()).collect())
    }

    /// Who owns one address, or `None` when nobody does — or when two units
    /// both claim it, which is no more usable an answer than none.
    pub fn owner_at(&self, section: &str, address: u32) -> Option<&str> {
        let mut found = self.bodies.iter().filter(|(_, body)| {
            body.entries.iter().any(|entry| {
                entry.range.section == section
                    && entry.range.start <= address
                    && address < entry.range.end
            })
        });
        let (name, _) = found.next()?;
        found.next().is_none().then_some(name.as_str())
    }
}

/// How a single proposed range stands against the oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Both boundaries reproduced: this unit's range, and nothing else.
    Exact,
    /// Overlaps this unit and stops short of, or runs past, a boundary.
    Partial,
    /// Claims ground the oracle gives to another unit.
    Incorrect,
    /// The oracle has nothing to say here.
    Unknown,
}

/// What became of the unit as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Exact,
    Partial,
    Incorrect,
    /// Landed somewhere the oracle does not place this unit or any other.
    Unowned,
    /// Nothing was proposed at all.
    Abstained,
    /// Something was proposed and the application refused it, which is not the
    /// same as proposing nothing.
    Refused,
}

/// How well a translation unit was *identified*, whatever became of the
/// proposal afterwards.
///
/// Kept apart from boundaries and from application on purpose: a unit can be
/// recognised with confidence, have one edge still unresolved, and have no
/// change that the build will accept. Collapsing those into one disposition is
/// what made a run report `unknown-failure` for a unit whose proposed range was
/// exactly right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Identification {
    /// Nothing put this unit anywhere.
    Absent,
    /// One explanation, not independently corroborated.
    Tentative,
    /// Independent evidence agrees on one explanation.
    Corroborated,
    /// Several explanations, none decisive.
    Ambiguous,
}

/// How far a proposal got before something stopped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Application {
    /// The stage never offered this unit a candidate.
    NotOffered,
    /// Offered, and the run ended before it was tried.
    NotAttempted,
    /// Refused before a build: the change itself was not applicable.
    PreflightRefused,
    /// Built, and the build or its gates rejected the result.
    BuildRefused,
    Accepted,
    /// Accepted, then replaced by a later, larger claim on the same unit.
    Superseded,
}

/// Whether the unit's own source was proved to link and match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    NotAttempted,
    Failed,
    Verified,
}

/// How the body selected by a stage compares with the oracle, independently
/// of whether it was later published or superseded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionQuality {
    /// No ownership-producing selection was recorded.
    NoChange,
    Exact,
    Partial,
    Incorrect,
    /// The selected body lands only in ground the oracle does not assign.
    Unknown,
}

/// Classifies one complete replacement body selected for `unit`.
pub fn selection_quality(
    unit: &str,
    oracle: &Oracle,
    selected: Option<&Body>,
    scope: Scope,
) -> SelectionQuality {
    let Some(selected) = selected else { return SelectionQuality::NoChange };
    let selected = selected.within(scope);
    let truth = oracle.body(unit).within(scope);
    let measured = ledger(unit, oracle, &Body::default(), &selected, scope);
    if selected.same_ownership(&truth) {
        SelectionQuality::Exact
    } else if measured.newly_wrong_bytes > 0 {
        SelectionQuality::Incorrect
    } else if measured.attributed_bytes > 0 {
        SelectionQuality::Partial
    } else {
        SelectionQuality::Unknown
    }
}

/// What a change did to one unit's ownership, in bytes, against the oracle.
///
/// Every field is an interval measurement, so a body that trades ground reports
/// the trade rather than a net of zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// What the oracle gives this unit.
    pub oracle_bytes: u32,
    /// Of that, what it held before the change.
    pub retained_bytes: u32,
    /// Of that, what it holds after.
    pub attributed_bytes: u32,
    /// Correct ground the change won.
    pub gained_bytes: u32,
    /// Correct ground the change gave up.
    pub lost_bytes: u32,
    /// Oracle ground it still does not hold.
    pub missed_bytes: u32,
    /// Another unit's ground it held before. Not this change's doing, and not
    /// hidden either.
    pub wrong_before_bytes: u32,
    /// Another unit's ground it holds after.
    pub wrong_after_bytes: u32,
    /// Of that, what the change itself took.
    pub newly_wrong_bytes: u32,
    /// Ground it holds that the oracle gives to nobody. Not an error: the
    /// oracle simply has not split it.
    pub unknown_bytes: u32,
}

/// Measures one unit's before and after against the oracle.
pub fn ledger(unit: &str, oracle: &Oracle, before: &Body, after: &Body, scope: Scope) -> Ledger {
    let truth = oracle.body(unit).within(scope).intervals();
    let foreign = oracle.foreign(unit, scope);
    let claimed = oracle.claimed(scope);
    let before = before.within(scope).intervals();
    let after = after.within(scope).intervals();

    let correct_before = intersect(&truth, &before);
    let correct_after = intersect(&truth, &after);
    let wrong_before = intersect(&foreign, &before);
    let wrong_after = intersect(&foreign, &after);

    Ledger {
        oracle_bytes: total(&truth),
        retained_bytes: total(&correct_before),
        attributed_bytes: total(&correct_after),
        gained_bytes: total(&difference(&correct_after, &correct_before)),
        lost_bytes: total(&difference(&correct_before, &correct_after)),
        missed_bytes: total(&difference(&truth, &after)),
        wrong_before_bytes: total(&wrong_before),
        wrong_after_bytes: total(&wrong_after),
        newly_wrong_bytes: total(&difference(&wrong_after, &wrong_before)),
        unknown_bytes: total(&difference(&after, &claimed)),
    }
}

/// The unit-level verdict a ledger and a body imply.
///
/// `Incorrect` outranks everything: a change that reaches into another unit is
/// a mistake whatever else it also got right. Only ground the change *added*
/// counts against it, so a unit that came in holding somebody else's bytes is
/// not blamed for them — but it is not called exact either, which is why the
/// comparison is against the oracle's body rather than against the ledger's
/// totals.
pub fn outcome(ledger: &Ledger, truth: &Body, after: &Body, changed: bool) -> Outcome {
    if !changed {
        return Outcome::Abstained;
    }
    if ledger.newly_wrong_bytes > 0 {
        Outcome::Incorrect
    } else if after.same_ownership(truth) {
        Outcome::Exact
    } else if ledger.attributed_bytes > 0 {
        Outcome::Partial
    } else {
        Outcome::Unowned
    }
}

/// Whether the oracle gives one proposed range to the unit that claims it, to
/// someone else, or to nobody.
///
/// A range contained in the unit's own is *not* the same answer as the unit's
/// own: it is the right neighbourhood with at least one boundary still
/// unresolved, and a measurement that conflates the two cannot see the search
/// stopping early.
pub fn range_state(unit: &str, section: &str, start: u32, end: u32, oracle: &Oracle) -> State {
    let own = oracle.body(unit).intervals();
    if own.iter().any(|range| range.section == section && range.start == start && range.end == end)
    {
        return State::Exact;
    }
    // Wrong ownership outranks partial credit.
    let foreign = oracle.foreign(unit, Scope::Everything);
    if foreign
        .iter()
        .any(|range| range.section == section && start < range.end && range.start < end)
    {
        return State::Incorrect;
    }
    if own.iter().any(|range| {
        range.section == section && overlap((start, end), (range.start, range.end)) > 0
    }) {
        return State::Partial;
    }
    // Unowned ground is not a wrong answer: the oracle simply has nothing to say
    // there, and counting it as an error would punish a policy for covering what
    // nobody has split yet.
    State::Unknown
}

/// What a transaction did to a unit other than the one it was about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerEffect {
    pub unit: String,
    /// Correctly owned ground this unit gave up.
    pub lost_bytes: u32,
    /// Ground it took on that the oracle gives to someone else.
    pub wrong_bytes: u32,
    /// Whether it is left owning precisely what the oracle says it should.
    pub exact: bool,
}

/// Scores one of a transaction's neighbours.
///
/// A transaction is only as good as its worst part. Scoring the candidate alone
/// would let a range look recovered while the unit beside it was quietly cut
/// into the wrong shape.
pub fn owner_effect(
    owner: &str,
    oracle: &Oracle,
    before: &Blocks,
    after: &Blocks,
    scope: Scope,
) -> OwnerEffect {
    let held = Body::of(before, owner);
    let left = Body::of(after, owner);
    let measured = ledger(owner, oracle, &held, &left, scope);
    OwnerEffect {
        unit: owner.to_string(),
        lost_bytes: measured.lost_bytes,
        wrong_bytes: measured.newly_wrong_bytes,
        exact: left.within(scope).same_ownership(&oracle.body(owner).within(scope)),
    }
}

/// Who the oracle says owns each function in the target's layout.
pub fn ownership_at_layout(
    layout: &[TargetFunction],
    oracle: &Oracle,
) -> BTreeMap<(String, String), Option<String>> {
    layout
        .iter()
        .map(|item| {
            let address = parse_address(&item.address).unwrap_or(0);
            let owner = oracle.owner_at(&item.section, address).map(str::to_string);
            ((item.section.clone(), item.address.clone()), owner)
        })
        .collect()
}

// --- interval algebra -------------------------------------------------------

/// How much of `a` and `b` is the same ground.
pub fn overlap(a: (u32, u32), b: (u32, u32)) -> u32 { a.1.min(b.1).saturating_sub(a.0.max(b.0)) }

/// One range per run of touching or overlapping ranges, so that a split and the
/// proposal that continues it read as the one range they would become.
pub fn merged(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_by(|a, b| a.section.cmp(&b.section).then(a.start.cmp(&b.start)));
    let mut result: Vec<Range> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match result.last_mut() {
            Some(last) if last.section == range.section && range.start <= last.end => {
                last.end = last.end.max(range.end);
            }
            _ => result.push(range),
        }
    }
    result
}

/// How many bytes a set of ranges covers.
pub fn total(ranges: &[Range]) -> u32 { ranges.iter().map(Range::size).sum() }

fn by_section(ranges: &[Range]) -> BTreeMap<&str, Vec<(u32, u32)>> {
    let mut found: BTreeMap<&str, Vec<(u32, u32)>> = BTreeMap::new();
    for range in ranges {
        found.entry(range.section.as_str()).or_default().push((range.start, range.end));
    }
    found
}

fn rebuild(sections: BTreeMap<&str, Vec<(u32, u32)>>) -> Vec<Range> {
    merged(
        sections
            .into_iter()
            .flat_map(|(section, ranges)| {
                ranges.into_iter().map(move |(start, end)| Range {
                    section: section.to_string(),
                    start,
                    end,
                })
            })
            .filter(|range| range.end > range.start)
            .collect(),
    )
}

/// The ground both sets hold.
pub fn intersect(a: &[Range], b: &[Range]) -> Vec<Range> {
    let other = by_section(b);
    let mut found: BTreeMap<&str, Vec<(u32, u32)>> = BTreeMap::new();
    for (section, ranges) in by_section(a) {
        let Some(against) = other.get(section) else { continue };
        let mut kept = Vec::new();
        for &(start, end) in &ranges {
            for &(other_start, other_end) in against {
                let (low, high) = (start.max(other_start), end.min(other_end));
                if low < high {
                    kept.push((low, high));
                }
            }
        }
        found.insert(section, kept);
    }
    rebuild(found)
}

/// The ground `a` holds and `b` does not.
pub fn difference(a: &[Range], b: &[Range]) -> Vec<Range> {
    let other = by_section(b);
    let mut found: BTreeMap<&str, Vec<(u32, u32)>> = BTreeMap::new();
    for (section, ranges) in by_section(a) {
        let empty = Vec::new();
        let against = other.get(section).unwrap_or(&empty);
        let mut kept = Vec::new();
        for &(start, end) in &ranges {
            let mut at = start;
            for &(other_start, other_end) in against.iter().filter(|(s, e)| *s < end && *e > start)
            {
                if other_start > at {
                    kept.push((at, other_start));
                }
                at = at.max(other_end);
            }
            if at < end {
                kept.push((at, end));
            }
        }
        found.insert(section, kept);
    }
    rebuild(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(section: &str, start: u32, end: u32) -> String {
        format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
    }

    fn blocks(entries: &[(&str, &str, u32, u32)]) -> Blocks {
        let mut map: Blocks = IndexMap::new();
        for (name, section, start, end) in entries {
            map.entry((*name).to_string()).or_default().push(line(section, *start, *end));
        }
        map
    }

    fn code(entries: &[(&str, u32, u32)]) -> Blocks {
        blocks(&entries.iter().map(|(n, s, e)| (*n, ".text", *s, *e)).collect::<Vec<_>>())
    }

    fn body(entries: &[(&str, u32, u32)]) -> Body {
        Body::new(
            entries
                .iter()
                .map(|(section, start, end)| Entry {
                    range: Range { section: (*section).to_string(), start: *start, end: *end },
                    attributes: BTreeSet::new(),
                })
                .collect(),
        )
    }

    #[test]
    fn reproducing_both_boundaries_is_exact() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000)]));
        assert_eq!(range_state("a.cpp", ".text", 0x1000, 0x2000, &oracle), State::Exact);
    }

    #[test]
    fn a_fragment_inside_the_right_unit_is_partial_rather_than_correct() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000)]));
        assert_eq!(range_state("a.cpp", ".text", 0x1100, 0x1200, &oracle), State::Partial);
    }

    #[test]
    fn a_range_overlapping_another_unit_is_incorrect() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]));
        assert_eq!(range_state("a.cpp", ".text", 0x1F00, 0x2100, &oracle), State::Incorrect);
    }

    #[test]
    fn overrunning_into_unowned_ground_still_counts_as_partial() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000)]));
        assert_eq!(range_state("a.cpp", ".text", 0x1000, 0x2400, &oracle), State::Partial);
    }

    #[test]
    fn a_range_nobody_owns_is_unknown_rather_than_wrong() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000)]));
        assert_eq!(range_state("a.cpp", ".text", 0x5000, 0x5100, &oracle), State::Unknown);
    }

    #[test]
    fn a_range_in_another_section_does_not_collide() {
        let oracle = Oracle::of(&code(&[("b.cpp", 0x1000, 0x2000)]));
        assert_eq!(range_state("a.cpp", ".data", 0x1100, 0x1200, &oracle), State::Unknown);
    }

    #[test]
    fn overlap_measures_shared_ground_only() {
        assert_eq!(overlap((0x100, 0x200), (0x180, 0x300)), 0x80);
        assert_eq!(overlap((0x100, 0x200), (0x200, 0x300)), 0);
        assert_eq!(overlap((0x100, 0x200), (0x000, 0x080)), 0);
    }

    #[test]
    fn a_split_and_the_proposal_continuing_it_merge_into_one_range() {
        assert_eq!(body(&[(".text", 0x100, 0x180), (".text", 0x180, 0x200)]).intervals().len(), 1);
        assert_eq!(body(&[(".text", 0x100, 0x180), (".text", 0x190, 0x200)]).intervals().len(), 2);
        assert_eq!(body(&[(".text", 0x100, 0x200), (".init", 0x100, 0x200)]).intervals().len(), 2);
        // Merging is for ownership only. The entries stay as the file wrote
        // them, so the two-line form is still two entries.
        assert_eq!(body(&[(".text", 0x100, 0x180), (".text", 0x180, 0x200)]).entries.len(), 2);
    }

    #[test]
    fn attributes_belong_to_the_range_that_carried_them() {
        // The real shape, from `MetroidPrime/CAnimData.cpp`: ordinary BSS and
        // common BSS in the same section, only the second one flagged. Pooling
        // them per section cannot say which is which, and anything writing the
        // body back out would mark both `common`.
        let mut map: Blocks = IndexMap::new();
        map.insert("a.cpp".to_string(), vec![
            "\t.bss        start:0x803E3050 end:0x803E3090".to_string(),
            "\t.bss        start:0x8042C6A0 end:0x8042F4A4 align:4 common".to_string(),
        ]);
        let found = Body::of(&map, "a.cpp");
        assert_eq!(found.entries.len(), 2, "two ranges, not one merged span");
        assert!(found.entries[0].attributes.is_empty());
        assert_eq!(
            found.entries[1].attributes,
            BTreeSet::from(["align:4".to_string(), "common".to_string()])
        );

        // Moving the flag to the other range keeps every address and is a
        // different block.
        let mut moved: Blocks = IndexMap::new();
        moved.insert("a.cpp".to_string(), vec![
            "\t.bss        start:0x803E3050 end:0x803E3090 align:4 common".to_string(),
            "\t.bss        start:0x8042C6A0 end:0x8042F4A4".to_string(),
        ]);
        let other = Body::of(&moved, "a.cpp");
        assert!(found.same_ownership(&other));
        assert!(!found.same_structure(&other), "which range is common is part of the answer");
    }

    #[test]
    fn a_body_written_back_out_as_split_lines_is_the_same_body() {
        let mut map: Blocks = IndexMap::new();
        map.insert("a.cpp".to_string(), vec![
            "\t.bss        start:0x803E3050 end:0x803E3090".to_string(),
            "\t.bss        start:0x8042C6A0 end:0x8042F4A4 align:4 common".to_string(),
            "\t.text       start:0x80001000 end:0x80001100".to_string(),
        ]);
        let original = Body::of(&map, "a.cpp");
        let mut round: Blocks = IndexMap::new();
        round.insert("a.cpp".to_string(), original.render());
        assert!(original.same_structure(&Body::of(&round, "a.cpp")), "{:?}", original.render());
    }

    #[test]
    fn two_lines_and_one_merged_line_are_the_same_ownership() {
        let mut split: Blocks = IndexMap::new();
        split.insert("a.cpp".to_string(), vec![
            line(".text", 0x1000, 0x1800),
            line(".text", 0x1800, 0x2000),
        ]);
        let whole = code(&[("a.cpp", 0x1000, 0x2000)]);
        assert!(Body::of(&split, "a.cpp").same_ownership(&Body::of(&whole, "a.cpp")));
    }

    #[test]
    fn a_swap_of_equal_size_reports_both_the_gain_and_the_loss() {
        // The same number of bytes, none of them the same bytes. A net measure
        // would call this no change at all.
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x1200)]));
        let before = body(&[(".text", 0x1000, 0x1100)]);
        let after = body(&[(".text", 0x1100, 0x1200)]);
        let found = ledger("a.cpp", &oracle, &before, &after, Scope::Code);
        assert_eq!(found.gained_bytes, 0x100);
        assert_eq!(found.lost_bytes, 0x100);
        assert_eq!(found.attributed_bytes, 0x100);
        assert_eq!(found.missed_bytes, 0x100);
    }

    #[test]
    fn ground_the_unit_came_in_holding_wrongly_is_not_charged_to_the_change() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]));
        let before = body(&[(".text", 0x1F00, 0x2080)]);
        let after = body(&[(".text", 0x1F00, 0x2080)]);
        let found = ledger("a.cpp", &oracle, &before, &after, Scope::Code);
        assert_eq!(found.wrong_before_bytes, 0x80);
        assert_eq!(found.wrong_after_bytes, 0x80);
        assert_eq!(found.newly_wrong_bytes, 0, "the change did not put it there");
        // But it is still visible in the final state.
        assert_eq!(found.wrong_after_bytes, 0x80);
    }

    #[test]
    fn taking_a_neighbours_ground_is_newly_wrong() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]));
        let found = ledger(
            "a.cpp",
            &oracle,
            &Body::default(),
            &body(&[(".text", 0x1000, 0x2100)]),
            Scope::Code,
        );
        assert_eq!(found.newly_wrong_bytes, 0x100);
        assert_eq!(found.attributed_bytes, 0x1000);
        assert_eq!(found.unknown_bytes, 0);
    }

    #[test]
    fn ground_nobody_owns_is_counted_apart_from_ground_somebody_else_owns() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000)]));
        let found = ledger(
            "a.cpp",
            &oracle,
            &Body::default(),
            &body(&[(".text", 0x1000, 0x2100)]),
            Scope::Code,
        );
        assert_eq!(found.newly_wrong_bytes, 0);
        assert_eq!(found.unknown_bytes, 0x100);
    }

    #[test]
    fn code_and_everything_are_measured_apart() {
        let mut map: Blocks = IndexMap::new();
        map.insert("a.cpp".to_string(), vec![
            line(".text", 0x1000, 0x1100),
            line(".bss", 0x8000, 0x8100),
        ]);
        let oracle = Oracle::of(&map);
        let after = body(&[(".text", 0x1000, 0x1100)]);
        // Code alone calls this a complete recovery; the whole body does not.
        // CStreamAudioManager is exactly this shape.
        let by_code = ledger("a.cpp", &oracle, &Body::default(), &after, Scope::Code);
        assert_eq!(by_code.missed_bytes, 0);
        let by_all = ledger("a.cpp", &oracle, &Body::default(), &after, Scope::Everything);
        assert_eq!(by_all.missed_bytes, 0x100);
    }

    #[test]
    fn an_address_two_units_both_claim_has_no_usable_owner() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x1800, 0x2200)]));
        assert_eq!(oracle.owner_at(".text", 0x1200), Some("a.cpp"));
        assert_eq!(oracle.owner_at(".text", 0x1900), None);
        assert_eq!(oracle.owner_at(".text", 0x9000), None);
    }

    #[test]
    fn an_unchanged_unit_is_an_abstention_however_good_its_ownership_is() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000)]));
        let held = body(&[(".text", 0x1000, 0x2000)]);
        let found = ledger("a.cpp", &oracle, &held, &held, Scope::Code);
        assert_eq!(outcome(&found, &oracle.body("a.cpp"), &held, false), Outcome::Abstained);
        assert_eq!(outcome(&found, &oracle.body("a.cpp"), &held, true), Outcome::Exact);
    }

    #[test]
    fn selected_body_quality_is_independent_of_publication() {
        let oracle = Oracle::of(&code(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]));
        assert_eq!(
            selection_quality("a.cpp", &oracle, None, Scope::Code),
            SelectionQuality::NoChange
        );
        assert_eq!(
            selection_quality(
                "a.cpp",
                &oracle,
                Some(&body(&[(".text", 0x1000, 0x2000)])),
                Scope::Code,
            ),
            SelectionQuality::Exact
        );
        assert_eq!(
            selection_quality(
                "a.cpp",
                &oracle,
                Some(&body(&[(".text", 0x1000, 0x1800)])),
                Scope::Code,
            ),
            SelectionQuality::Partial
        );
        assert_eq!(
            selection_quality(
                "a.cpp",
                &oracle,
                Some(&body(&[(".text", 0x1000, 0x2100)])),
                Scope::Code,
            ),
            SelectionQuality::Incorrect
        );
        assert_eq!(
            selection_quality(
                "a.cpp",
                &oracle,
                Some(&body(&[(".text", 0x5000, 0x5100)])),
                Scope::Code,
            ),
            SelectionQuality::Unknown
        );
    }
}
