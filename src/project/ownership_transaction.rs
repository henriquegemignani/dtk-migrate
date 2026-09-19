//! One change to split ownership, however many units it touches.
//!
//! A boundary between two units is one fact, so moving it is one change: the
//! unit that gains and the unit that gives way are written together or not at
//! all. Earlier versions expressed that as a single candidate body plus a
//! narrowing-only revision of one neighbour, which cannot say "swap these two
//! ranges", "extend three units at once" or "correct this edge without growing
//! anything". A transaction can.
//!
//! What it carries is deliberately complete:
//!
//! - every affected unit's **exact before-state** and **complete after-body**,
//!   so applying it never has to merge anything and a stale world is detected
//!   rather than patched;
//! - the read set: every other unit whose ranges touch the ones being changed,
//!   with the body it had when the evidence was gathered, because a boundary
//!   inferred against a neighbour is only valid while that neighbour stands;
//! - the **transfers** — which addresses leave which unit for which other —
//!   derived from the bodies and checked against them, so a unit can never lose
//!   ground without the transaction saying who receives it;
//! - the evidence and policy it was derived under, and a stable identity over
//!   all of the above.
//!
//! [`OwnershipTransaction::apply`] is the one way any of this reaches a split
//! map. Calibration, worker trials, integration and publication all go through
//! it, and it builds and checks the whole resulting map before replacing the
//! caller's, so a refusal leaves nothing half-applied.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    analysis::coverage::RequiredExtract,
    build::context::ValidationError,
    project::{
        link_order::cyclic_units,
        splits::{Splits, parse_attributes, parse_range},
    },
};

/// Bumped when the stored shape or meaning of a transaction changes.
pub const TRANSACTION_SCHEMA: u32 = 1;

/// The module every split address in a `splits.txt` belongs to. Explicit so
/// that later REL support cannot alias two identical section addresses.
pub const MODULE: &str = "main";

pub type Blocks = IndexMap<String, Vec<String>>;

/// A unit the transaction writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberChange {
    pub unit: String,
    /// Exactly what the unit must hold for the transaction to apply. `None`
    /// means the unit has no block at all, which is different from an empty
    /// one.
    pub before: Option<Vec<String>>,
    /// The complete replacement body. Anything absent from it is ground the
    /// unit stops owning, and has to appear in a transfer.
    pub after: Vec<String>,
}

/// A unit the transaction only reads: its ranges touch the ones being changed,
/// so the evidence depended on it staying exactly as it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitState {
    pub unit: String,
    pub body: Option<Vec<String>>,
}

/// Addresses whose owner changes. `None` is "nobody".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Transfer {
    pub module: String,
    pub section: String,
    pub start: String,
    pub end: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

impl Transfer {
    pub fn range(&self) -> (u32, u32) { (parse_hex(&self.start), parse_hex(&self.end)) }

    pub fn bytes(&self) -> u32 {
        let (start, end) = self.range();
        end.saturating_sub(start)
    }
}

/// Ground a transaction gives up to nobody, and why. A shrink is a legitimate
/// correction only when something says the ground was never the unit's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Release {
    pub module: String,
    pub section: String,
    pub start: String,
    pub end: String,
    pub reason: String,
}

/// The provenance a transaction is derived under, supplied by whoever builds
/// it and bound into its identity.
#[derive(Debug, Clone, Default)]
pub struct Provenance {
    /// A digest naming the policy that produced the change.
    pub policy: String,
    /// The content-addressed observation report the evidence came from.
    pub observation_sha256: String,
    /// References to the evidence: kinds, support groups, attribution ids.
    pub evidence: Vec<String>,
    pub required_extracts: Vec<RequiredExtract>,
    pub releases: Vec<Release>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwnershipTransaction {
    pub schema: u32,
    /// SHA-256 over everything below, so two runs, a worker and the
    /// coordinator agree on which change was proved.
    pub id: String,
    pub policy: String,
    pub observation_sha256: String,
    pub evidence: Vec<String>,
    /// Sorted by unit; the explicit write set.
    pub members: Vec<MemberChange>,
    /// Sorted by unit; the read set beyond the members.
    pub reads: Vec<UnitState>,
    /// Derived from `members`, stored so a reader need not re-derive it, and
    /// checked against them whenever the transaction is used.
    pub transfers: Vec<Transfer>,
    pub releases: Vec<Release>,
    pub required_extracts: Vec<RequiredExtract>,
}

fn refused(message: impl std::fmt::Display) -> anyhow::Error {
    ValidationError(format!("transaction refused: {message}")).into()
}

fn stale(message: impl std::fmt::Display) -> anyhow::Error {
    ValidationError(format!("stale precondition: {message}")).into()
}

fn parse_hex(text: &str) -> u32 {
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    u32::from_str_radix(digits, 16).unwrap_or(0)
}

fn hex(value: u32) -> String { format!("0x{value:08X}") }

/// Every parsed range in a body, as (section, start, end).
fn ranges(lines: &[String]) -> Vec<(String, u32, u32)> {
    lines
        .iter()
        .filter_map(|line| parse_range(line))
        .map(|range| (range.section, range.start, range.end))
        .collect()
}

impl OwnershipTransaction {
    /// Derives a transaction from the state it will be applied to and the
    /// complete bodies it writes.
    ///
    /// Unchanged bodies are not members. Nothing is judged here beyond what
    /// the derivation itself needs; [`Self::preview`] decides whether the
    /// change is allowed.
    pub fn build(
        blocks: &Blocks,
        changes: impl IntoIterator<Item = (String, Vec<String>)>,
        provenance: Provenance,
    ) -> Result<Self> {
        let mut members: BTreeMap<String, MemberChange> = BTreeMap::new();
        for (unit, after) in changes {
            let before = blocks.get(&unit).cloned();
            if before.as_ref() == Some(&after) {
                continue;
            }
            let change = MemberChange { unit: unit.clone(), before, after };
            if members.insert(unit.clone(), change).is_some() {
                bail!(refused(format!("{unit} is written twice")));
            }
        }
        if members.is_empty() {
            bail!(refused("it changes nothing"));
        }
        let members: Vec<MemberChange> = members.into_values().collect();
        let transfers = transfers_of(&members)?;
        let reads = neighbours(blocks, &members);

        let mut evidence = provenance.evidence;
        evidence.sort();
        evidence.dedup();
        let mut releases = provenance.releases;
        releases.sort();
        let mut transaction = Self {
            schema: TRANSACTION_SCHEMA,
            id: String::new(),
            policy: provenance.policy,
            observation_sha256: provenance.observation_sha256,
            evidence,
            members,
            reads,
            transfers,
            releases,
            required_extracts: provenance.required_extracts,
        };
        transaction.id = transaction.identity();
        Ok(transaction)
    }

    fn identity(&self) -> String {
        let canonical = serde_json::to_vec(&(
            self.schema,
            &self.policy,
            &self.observation_sha256,
            &self.evidence,
            &self.members,
            &self.reads,
            &self.transfers,
            &self.releases,
            &self.required_extracts,
        ))
        .unwrap_or_default();
        format!("{:x}", Sha256::digest(canonical))
    }

    /// Identity of the work a trial would repeat. The full transaction id
    /// binds the complete observation report for publication; that report can
    /// change when an unrelated unit lands. Retrying the same before/after
    /// bodies and the same read dependencies solely for that global digest
    /// would waste a build. A changed relevant neighbour or changed evidence
    /// still changes this key.
    pub fn retry_key(&self) -> String {
        let canonical = serde_json::to_vec(&(
            self.schema,
            &self.policy,
            &self.evidence,
            &self.members,
            &self.reads,
            &self.transfers,
            &self.releases,
            &self.required_extracts,
        ))
        .unwrap_or_default();
        format!("{:x}", Sha256::digest(canonical))
    }

    pub fn member(&self, unit: &str) -> Option<&MemberChange> {
        self.members.iter().find(|member| member.unit == unit)
    }

    /// The units this transaction writes.
    pub fn writes(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|member| member.unit.as_str())
    }

    /// Everything this transaction's validity depends on: what it writes and
    /// what it only reads.
    pub fn touched(&self) -> impl Iterator<Item = &str> {
        self.writes().chain(self.reads.iter().map(|read| read.unit.as_str()))
    }

    /// Bytes `unit` newly owns.
    pub fn gained_bytes(&self, unit: &str) -> u32 {
        self.transfers.iter().filter(|t| t.to.as_deref() == Some(unit)).map(Transfer::bytes).sum()
    }

    /// Bytes `unit` stops owning.
    pub fn lost_bytes(&self, unit: &str) -> u32 {
        self.transfers.iter().filter(|t| t.from.as_deref() == Some(unit)).map(Transfer::bytes).sum()
    }

    /// Owned bytes after minus owned bytes before, across every member. Zero
    /// for a pure boundary move, which is still a change worth making.
    pub fn net_bytes(&self) -> i64 {
        self.transfers
            .iter()
            .map(|transfer| match (&transfer.from, &transfer.to) {
                (None, Some(_)) => i64::from(transfer.bytes()),
                (Some(_), None) => -i64::from(transfer.bytes()),
                _ => 0,
            })
            .sum()
    }

    /// Units that receive ground.
    pub fn receivers(&self) -> BTreeSet<&str> {
        self.transfers.iter().filter_map(|transfer| transfer.to.as_deref()).collect()
    }

    /// Checks that the transaction is internally what it claims to be,
    /// independently of any split map: its identity, that its transfers are
    /// exactly what its bodies imply, that every release is declared and
    /// explained, and that it keeps the split attributes of what it retains.
    pub fn validate(&self) -> Result<()> {
        if self.schema != TRANSACTION_SCHEMA {
            bail!(refused(format!(
                "schema {} is not the {TRANSACTION_SCHEMA} this build understands",
                self.schema
            )));
        }
        if self.id != self.identity() {
            bail!(refused(format!("{} does not match its contents", self.id)));
        }
        if self.members.is_empty() {
            bail!(refused("it has no members"));
        }
        if !self.members.windows(2).all(|pair| pair[0].unit < pair[1].unit) {
            bail!(refused("members are not in canonical order"));
        }
        if !self.reads.windows(2).all(|pair| pair[0].unit < pair[1].unit)
            || self.reads.iter().any(|read| self.member(&read.unit).is_some())
        {
            bail!(refused("read set is not canonical"));
        }
        if self.evidence.is_empty() {
            bail!(refused("it cites no evidence"));
        }
        for member in &self.members {
            if member.after.is_empty() {
                bail!(refused(format!("{} would lose its whole block", member.unit)));
            }
            if member.before.as_ref() == Some(&member.after) {
                bail!(refused(format!("{} is listed but unchanged", member.unit)));
            }
            preserves_attributes(member)?;
        }
        if transfers_of(&self.members)? != self.transfers {
            bail!(refused("its transfers do not match its bodies"));
        }
        let released: Vec<(&str, &str, &str, &str)> = self
            .transfers
            .iter()
            .filter(|transfer| transfer.to.is_none())
            .map(|t| (t.module.as_str(), t.section.as_str(), t.start.as_str(), t.end.as_str()))
            .collect();
        let declared: Vec<(&str, &str, &str, &str)> = self
            .releases
            .iter()
            .map(|r| (r.module.as_str(), r.section.as_str(), r.start.as_str(), r.end.as_str()))
            .collect();
        if released != declared {
            let unexplained = self
                .transfers
                .iter()
                .find(|t| {
                    t.to.is_none()
                        && !declared.contains(&(
                            t.module.as_str(),
                            t.section.as_str(),
                            t.start.as_str(),
                            t.end.as_str(),
                        ))
                })
                .map(|t| {
                    format!(
                        "{} would lose {} {}..{} with nothing receiving it",
                        t.from.as_deref().unwrap_or("?"),
                        t.section,
                        t.start,
                        t.end
                    )
                })
                .unwrap_or_else(|| "its declared releases do not match what it gives up".into());
            bail!(refused(unexplained));
        }
        if self.releases.iter().any(|release| release.reason.trim().is_empty()) {
            bail!(refused("a release does not say why"));
        }
        Ok(())
    }

    /// Confirms `blocks` is still the world this transaction was derived in.
    pub fn check_preconditions(&self, blocks: &Blocks) -> Result<()> {
        for member in &self.members {
            if blocks.get(&member.unit) != member.before.as_ref() {
                bail!(stale(format!("{} changed since transaction {}", member.unit, self.id)));
            }
        }
        for read in &self.reads {
            if blocks.get(&read.unit) != read.body.as_ref() {
                bail!(stale(format!(
                    "neighbour {} changed since transaction {}",
                    read.unit, self.id
                )));
            }
        }
        // Ground taken from nobody must still be nobody's. A unit already
        // there when the transaction was derived is in the read set, and its
        // overlap is a refusal of the change itself; one that arrived since
        // makes the change stale.
        let known: BTreeSet<&str> = self.touched().collect();
        for transfer in self.transfers.iter().filter(|transfer| transfer.from.is_none()) {
            let (start, end) = transfer.range();
            if let Some(owner) = owner_overlapping(blocks, &known, &transfer.section, start, end) {
                bail!(stale(format!(
                    "{} {}..{} is now owned by {owner}",
                    transfer.section, transfer.start, transfer.end
                )));
            }
        }
        Ok(())
    }

    /// The complete split map this transaction would produce from `blocks`,
    /// checked, without touching `blocks`.
    pub fn preview(&self, blocks: &Blocks) -> Result<Blocks> {
        self.validate()?;
        self.check_preconditions(blocks)?;

        let mut next = blocks.clone();
        let mut new_units = Vec::new();
        for member in &self.members {
            if member.before.is_none() {
                new_units.push(member.unit.clone());
            }
            next.insert(member.unit.clone(), member.after.clone());
        }
        let mut splits = Splits { header: String::new(), blocks: next };
        splits.place_new_units(&new_units)?;
        let next = splits.blocks;

        // No member may overlap another unit, or itself. Everything outside
        // the members is untouched by construction.
        let writers: BTreeSet<&str> = self.writes().collect();
        for member in &self.members {
            let own = ranges(&member.after);
            for (index, (section, start, end)) in own.iter().enumerate() {
                if own[index + 1..].iter().any(|(s, a, b)| s == section && a < end && start < b) {
                    bail!(refused(format!("{} would overlap itself in {section}", member.unit)));
                }
                if let Some(owner) = owner_overlapping(&next, &writers, section, *start, *end) {
                    bail!(refused(format!(
                        "{} would overlap {owner} in {section} {}..{}",
                        member.unit,
                        hex(*start),
                        hex(*end)
                    )));
                }
            }
        }
        // Members are disjoint from one another as well; `transfers_of`
        // refuses an after-state where two of them claim one address.

        let after_cycles = cyclic_units(&next);
        if !after_cycles.is_empty() {
            let introduced: Vec<String> =
                after_cycles.difference(&cyclic_units(blocks)).cloned().collect();
            if !introduced.is_empty() {
                bail!(refused(format!("it would create a link-order cycle among {introduced:?}")));
            }
        }
        Ok(next)
    }

    /// Applies the transaction to `blocks`, all of it or none of it.
    pub fn apply(&self, blocks: &mut Blocks) -> Result<()> {
        *blocks = self.preview(blocks)?;
        Ok(())
    }

    /// Confirms `blocks` holds exactly what this transaction wrote.
    pub fn check_applied(&self, blocks: &Blocks) -> Result<()> {
        self.validate()?;
        for member in &self.members {
            if blocks.get(&member.unit) != Some(&member.after) {
                bail!(ValidationError(format!(
                    "{} changed after transaction {} was applied",
                    member.unit, self.id
                )));
            }
        }
        Ok(())
    }

    /// Puts back what this transaction replaced, after confirming it is what
    /// currently stands. Used to walk an accepted history backwards.
    pub fn undo(&self, blocks: &mut Blocks) -> Result<()> {
        self.check_applied(blocks)?;
        for member in &self.members {
            match &member.before {
                Some(before) => {
                    blocks.insert(member.unit.clone(), before.clone());
                }
                None => {
                    blocks.shift_remove(&member.unit);
                }
            }
        }
        Ok(())
    }
}

/// Which unit other than `excluded` claims any of `section` `start..end`.
fn owner_overlapping(
    blocks: &Blocks,
    excluded: &BTreeSet<&str>,
    section: &str,
    start: u32,
    end: u32,
) -> Option<String> {
    blocks
        .iter()
        .filter(|(name, _)| !excluded.contains(name.as_str()))
        .find(|(_, lines)| {
            ranges(lines).iter().any(|(s, a, b)| s == section && *a < end && start < *b)
        })
        .map(|(name, _)| name.clone())
}

/// Every non-member unit whose ranges overlap or abut a member's, before or
/// after.
fn neighbours(blocks: &Blocks, members: &[MemberChange]) -> Vec<UnitState> {
    let writers: BTreeSet<&str> = members.iter().map(|member| member.unit.as_str()).collect();
    let touched: Vec<(String, u32, u32)> = members
        .iter()
        .flat_map(|member| member.before.iter().flatten().chain(&member.after))
        .filter_map(|line| parse_range(line))
        .map(|range| (range.section, range.start, range.end))
        .collect();
    blocks
        .iter()
        .filter(|(name, _)| !writers.contains(name.as_str()))
        .filter(|(_, lines)| {
            ranges(lines).iter().any(|(section, start, end)| {
                touched.iter().any(|(s, a, b)| s == section && start <= b && a <= end)
            })
        })
        .map(|(name, lines)| {
            (name.clone(), UnitState { unit: name.clone(), body: Some(lines.clone()) })
        })
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

/// Which addresses change owner among the members, in canonical order.
///
/// Only members can gain or lose, so this needs nothing but their bodies. Two
/// members claiming one address on the same side of the change is refused:
/// before, it means the world was already inconsistent; after, it would make
/// it so.
fn transfers_of(members: &[MemberChange]) -> Result<Vec<Transfer>> {
    type Owned<'a> = BTreeMap<String, Vec<(u32, u32, &'a str)>>;
    let mut before: Owned = BTreeMap::new();
    let mut after: Owned = BTreeMap::new();
    for member in members {
        for (side, lines) in [
            (&mut before, member.before.as_deref().unwrap_or_default()),
            (&mut after, &member.after),
        ] {
            for (section, start, end) in ranges(lines) {
                if end <= start {
                    bail!(refused(format!("{} has an empty or inverted range", member.unit)));
                }
                side.entry(section).or_default().push((start, end, member.unit.as_str()));
            }
        }
    }
    for (label, side) in [("before", &mut before), ("after", &mut after)] {
        for (section, list) in side.iter_mut() {
            list.sort();
            if let Some(pair) = list.windows(2).find(|pair| pair[0].1 > pair[1].0) {
                bail!(refused(format!(
                    "{} and {} overlap in {section} {label} the change",
                    pair[0].2, pair[1].2
                )));
            }
        }
    }

    let sections: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let owner = |list: Option<&Vec<(u32, u32, &str)>>, start: u32, end: u32| {
        list.into_iter()
            .flatten()
            .find(|(a, b, _)| *a <= start && end <= *b)
            .map(|(_, _, unit)| unit.to_string())
    };
    let mut transfers: Vec<Transfer> = Vec::new();
    for section in sections {
        let old = before.get(section);
        let new = after.get(section);
        let mut points: Vec<u32> = old
            .into_iter()
            .chain(new)
            .flatten()
            .flat_map(|(start, end, _)| [*start, *end])
            .collect();
        points.sort_unstable();
        points.dedup();
        for pair in points.windows(2) {
            let (start, end) = (pair[0], pair[1]);
            let from = owner(old, start, end);
            let to = owner(new, start, end);
            if from == to {
                continue;
            }
            match transfers.last_mut() {
                Some(last)
                    if &last.section == section
                        && parse_hex(&last.end) == start
                        && last.from == from
                        && last.to == to =>
                {
                    last.end = hex(end);
                }
                _ => transfers.push(Transfer {
                    module: MODULE.to_string(),
                    section: section.clone(),
                    start: hex(start),
                    end: hex(end),
                    from,
                    to,
                }),
            }
        }
    }
    Ok(transfers)
}

/// A retained or resized range keeps the split attributes it had, and lines
/// this code does not understand survive verbatim.
///
/// `common`, `align:` and friends change what a block means to dtk without
/// moving a single address, so a transaction that dropped them would be a
/// different change from the one its transfers describe.
fn preserves_attributes(member: &MemberChange) -> Result<()> {
    let Some(before) = &member.before else { return Ok(()) };
    let mut opaque: BTreeMap<&str, usize> = BTreeMap::new();
    for line in before.iter().filter(|line| parse_range(line).is_none()) {
        *opaque.entry(line.as_str()).or_default() += 1;
    }
    for line in member.after.iter().filter(|line| parse_range(line).is_none()) {
        if let Some(count) = opaque.get_mut(line.as_str()) {
            *count = count.saturating_sub(1);
        }
    }
    if opaque.values().any(|count| *count > 0) {
        bail!(refused(format!(
            "{} would lose a line it does not describe as a range",
            member.unit
        )));
    }

    let old: Vec<(String, u32, u32, BTreeSet<String>)> = before
        .iter()
        .filter_map(|line| {
            parse_range(line).map(|r| (r.section, r.start, r.end, parse_attributes(line)))
        })
        .collect();
    for line in &member.after {
        let Some(range) = parse_range(line) else { continue };
        let attributes = parse_attributes(line);
        let overlapped: BTreeSet<&BTreeSet<String>> = old
            .iter()
            .filter(|(section, start, end, _)| {
                *section == range.section && *start < range.end && range.start < *end
            })
            .map(|(_, _, _, attributes)| attributes)
            .collect();
        if overlapped.len() > 1 || overlapped.iter().any(|kept| **kept != attributes) {
            bail!(refused(format!(
                "{} would change the attributes of its {} range",
                member.unit, range.section
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(section: &str, start: u32, end: u32) -> String {
        format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
    }

    fn text(start: u32, end: u32) -> String { line(".text", start, end) }

    fn blocks(entries: &[(&str, &[String])]) -> Blocks {
        entries.iter().map(|(name, lines)| ((*name).to_string(), lines.to_vec())).collect()
    }

    fn provenance() -> Provenance {
        Provenance {
            policy: "test-policy".into(),
            observation_sha256: "observations".into(),
            evidence: vec!["exact-body".into()],
            ..Default::default()
        }
    }

    fn build(world: &Blocks, changes: &[(&str, Vec<String>)]) -> OwnershipTransaction {
        OwnershipTransaction::build(
            world,
            changes.iter().map(|(unit, after)| ((*unit).to_string(), after.clone())),
            provenance(),
        )
        .unwrap()
    }

    #[test]
    fn a_new_unit_gains_unowned_ground() {
        let world = blocks(&[("b.cpp", &[text(0x200, 0x300)])]);
        let transaction = build(&world, &[("a.cpp", vec![text(0x100, 0x200)])]);
        assert_eq!(transaction.transfers, vec![Transfer {
            module: "main".into(),
            section: ".text".into(),
            start: hex(0x100),
            end: hex(0x200),
            from: None,
            to: Some("a.cpp".into()),
        }]);
        // b.cpp's range abuts the claim, so its position is part of what the
        // change assumed.
        assert_eq!(transaction.reads, vec![UnitState {
            unit: "b.cpp".into(),
            body: Some(vec![text(0x200, 0x300)])
        }]);
        let mut applied = world.clone();
        transaction.apply(&mut applied).unwrap();
        // A new unit goes where its address puts it, not at the end.
        assert_eq!(applied.keys().collect::<Vec<_>>(), ["a.cpp", "b.cpp"]);
        assert_eq!(transaction.net_bytes(), 0x100);
    }

    #[test]
    fn an_equal_size_boundary_correction_is_a_change() {
        // The edge between a.cpp and b.cpp moves; nobody's total changes in
        // aggregate, and it is still exactly the change the evidence asked for.
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)]), ("b.cpp", &[text(0x200, 0x400)])]);
        let transaction = build(&world, &[
            ("a.cpp", vec![text(0x100, 0x280)]),
            ("b.cpp", vec![text(0x280, 0x400)]),
        ]);
        assert_eq!(transaction.net_bytes(), 0);
        assert_eq!(transaction.gained_bytes("a.cpp"), 0x80);
        assert_eq!(transaction.lost_bytes("b.cpp"), 0x80);
        let mut applied = world.clone();
        transaction.apply(&mut applied).unwrap();
        assert_eq!(applied["a.cpp"], [text(0x100, 0x280)]);
        assert_eq!(applied["b.cpp"], [text(0x280, 0x400)]);
    }

    #[test]
    fn a_swap_of_two_ranges_is_one_transaction() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)]), ("b.cpp", &[text(0x200, 0x300)])]);
        let transaction = build(&world, &[
            ("a.cpp", vec![text(0x200, 0x300)]),
            ("b.cpp", vec![text(0x100, 0x200)]),
        ]);
        assert_eq!(transaction.transfers.len(), 2);
        let mut applied = world.clone();
        transaction.apply(&mut applied).unwrap();
        assert_eq!(applied["a.cpp"], [text(0x200, 0x300)]);
        assert_eq!(applied["b.cpp"], [text(0x100, 0x200)]);
    }

    #[test]
    fn ground_given_up_to_nobody_is_refused_unless_declared() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200), line(".rodata", 0x800, 0x840)])]);
        let transaction = build(&world, &[("a.cpp", vec![text(0x100, 0x300)])]);
        let error = transaction.preview(&world).unwrap_err().to_string();
        assert!(error.contains("a.cpp would lose .rodata"), "{error}");

        let mut declared = provenance();
        declared.releases = vec![Release {
            module: "main".into(),
            section: ".rodata".into(),
            start: hex(0x800),
            end: hex(0x840),
            reason: "the data belongs to a later unit".into(),
        }];
        let explained = OwnershipTransaction::build(
            &world,
            [("a.cpp".to_string(), vec![text(0x100, 0x300)])],
            declared,
        )
        .unwrap();
        explained.preview(&world).unwrap();
    }

    #[test]
    fn a_body_moving_a_range_keeping_its_size_is_refused() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)])]);
        let moved = build(&world, &[("a.cpp", vec![text(0x200, 0x300)])]);
        let error = moved.preview(&world).unwrap_err().to_string();
        assert!(error.contains("0x00000100..0x00000200"), "{error}");
    }

    #[test]
    fn claiming_a_non_members_ground_is_refused_before_any_build() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)]), ("b.cpp", &[text(0x200, 0x300)])]);
        let grabbing = build(&world, &[("a.cpp", vec![text(0x100, 0x280)])]);
        let error = grabbing.preview(&world).unwrap_err().to_string();
        assert!(error.contains("a.cpp would overlap b.cpp"), "{error}");
    }

    #[test]
    fn ground_claimed_by_a_newcomer_makes_the_transaction_stale() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)])]);
        let extension = build(&world, &[("a.cpp", vec![text(0x100, 0x400)])]);
        let mut later = world.clone();
        later.insert("c.cpp".into(), vec![text(0x300, 0x380)]);
        let error = extension.preview(&later).unwrap_err().to_string();
        assert!(error.contains("stale precondition"), "{error}");
        assert!(error.contains("now owned by c.cpp"), "{error}");
    }

    #[test]
    fn a_refusal_leaves_every_owner_untouched() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)]), ("b.cpp", &[text(0x200, 0x300)])]);
        let transaction = build(&world, &[
            ("a.cpp", vec![text(0x100, 0x280)]),
            ("b.cpp", vec![text(0x280, 0x300)]),
        ]);
        let mut moved = world.clone();
        moved["b.cpp"] = vec![text(0x200, 0x380)];
        let before = moved.clone();
        let error = transaction.apply(&mut moved).unwrap_err().to_string();
        assert!(error.contains("stale precondition"), "{error}");
        assert_eq!(moved, before);
    }

    #[test]
    fn a_changed_neighbour_makes_the_transaction_stale() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)]), ("b.cpp", &[text(0x200, 0x300)])]);
        let extension = build(&world, &[("a.cpp", vec![text(0x80, 0x200)])]);
        assert_eq!(extension.reads.len(), 1);
        let mut later = world.clone();
        later["b.cpp"] = vec![text(0x200, 0x380)];
        let error = extension.preview(&later).unwrap_err().to_string();
        assert!(error.contains("neighbour b.cpp changed"), "{error}");
    }

    #[test]
    fn a_tampered_transaction_is_refused() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)])]);
        let mut transaction = build(&world, &[("a.cpp", vec![text(0x100, 0x300)])]);
        transaction.members[0].after = vec![text(0x100, 0x400)];
        let error = transaction.preview(&world).unwrap_err().to_string();
        assert!(error.contains("does not match its contents"), "{error}");

        // Forging a consistent identity does not help: the transfers still
        // have to be the ones the bodies imply.
        transaction.id = transaction.identity();
        let error = transaction.preview(&world).unwrap_err().to_string();
        assert!(error.contains("transfers do not match"), "{error}");
    }

    #[test]
    fn identity_is_stable_and_covers_every_input() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)])]);
        let one = build(&world, &[("a.cpp", vec![text(0x100, 0x300)])]);
        let same = build(&world, &[("a.cpp", vec![text(0x100, 0x300)])]);
        assert_eq!(one.id, same.id);
        assert_eq!(one.id.len(), 64);

        let mut elsewhere = provenance();
        elsewhere.observation_sha256 = "other observations".into();
        let other = OwnershipTransaction::build(
            &world,
            [("a.cpp".to_string(), vec![text(0x100, 0x300)])],
            elsewhere,
        )
        .unwrap();
        assert_ne!(one.id, other.id);

        let moved_world =
            blocks(&[("a.cpp", &[text(0x100, 0x200)]), ("c.cpp", &[text(0x300, 0x400)])]);
        let with_neighbour = build(&moved_world, &[("a.cpp", vec![text(0x100, 0x300)])]);
        assert_ne!(one.id, with_neighbour.id, "the read set is part of the before-state");
    }

    #[test]
    fn retry_key_changes_only_when_relevant_state_or_evidence_changes() {
        let original = blocks(&[
            ("a.cpp", &[text(0x100, 0x200)]),
            ("b.cpp", &[text(0x300, 0x400)]),
            ("c.cpp", &[text(0x700, 0x800)]),
        ]);
        let proposal = |world: &Blocks, provenance| {
            OwnershipTransaction::build(
                world,
                [("a.cpp".to_string(), vec![text(0x100, 0x300)])],
                provenance,
            )
            .unwrap()
        };
        let one = proposal(&original, provenance());
        let mut new_report = provenance();
        new_report.observation_sha256 = "a report updated by c.cpp".into();
        let report_only = proposal(&original, new_report);
        assert_ne!(one.id, report_only.id);
        assert_eq!(one.retry_key(), report_only.retry_key());

        let unrelated = blocks(&[
            ("a.cpp", &[text(0x100, 0x200)]),
            ("b.cpp", &[text(0x300, 0x400)]),
            ("c.cpp", &[text(0x800, 0x900)]),
        ]);
        assert_eq!(one.retry_key(), proposal(&unrelated, provenance()).retry_key());

        let repaired = blocks(&[
            ("a.cpp", &[text(0x100, 0x200)]),
            ("b.cpp", &[text(0x300, 0x500)]),
            ("c.cpp", &[text(0x700, 0x800)]),
        ]);
        assert_ne!(one.retry_key(), proposal(&repaired, provenance()).retry_key());
    }

    #[test]
    fn retained_ranges_keep_their_attributes() {
        let world = blocks(&[("a.cpp", &[
            format!("{} align:16", text(0x100, 0x200)),
            "\t// a comment dtk keeps".to_string(),
        ])]);
        let dropped = build(&world, &[("a.cpp", vec![text(0x100, 0x300)])]);
        let error = dropped.preview(&world).unwrap_err().to_string();
        assert!(error.contains("lose a line"), "{error}");

        let dropped = build(&world, &[("a.cpp", vec![
            text(0x100, 0x300),
            "\t// a comment dtk keeps".to_string(),
        ])]);
        let error = dropped.preview(&world).unwrap_err().to_string();
        assert!(error.contains("attributes"), "{error}");

        let kept = build(&world, &[("a.cpp", vec![
            format!("{} align:16", text(0x100, 0x300)),
            "\t// a comment dtk keeps".to_string(),
        ])]);
        kept.preview(&world).unwrap();
    }

    #[test]
    fn a_new_link_order_cycle_is_refused() {
        // a.cpp precedes b.cpp in .text, so a.cpp's data must precede b.cpp's
        // too: placing it after leaves no order that satisfies both.
        let world = blocks(&[
            ("a.cpp", &[text(0x100, 0x200)]),
            ("b.cpp", &[text(0x200, 0x300), line(".data", 0x800, 0x810)]),
        ]);
        let ordered =
            build(&world, &[("a.cpp", vec![text(0x100, 0x200), line(".data", 0x700, 0x710)])]);
        ordered.preview(&world).unwrap();
        let cyclic =
            build(&world, &[("a.cpp", vec![text(0x100, 0x200), line(".data", 0x900, 0x910)])]);
        let error = cyclic.preview(&world).unwrap_err().to_string();
        assert!(error.contains("link-order cycle"), "{error}");
    }

    #[test]
    fn a_cycle_that_was_already_there_does_not_block_an_unrelated_change() {
        let world = blocks(&[
            ("a.cpp", &[text(0x100, 0x200), line(".data", 0x900, 0x910)]),
            ("b.cpp", &[text(0x200, 0x300), line(".data", 0x800, 0x810)]),
            ("c.cpp", &[text(0x400, 0x500)]),
        ]);
        let unrelated = build(&world, &[("c.cpp", vec![text(0x400, 0x580)])]);
        unrelated.preview(&world).unwrap();
    }

    #[test]
    fn undo_walks_an_applied_history_backwards() {
        let world = blocks(&[("b.cpp", &[text(0x200, 0x300)])]);
        let first = build(&world, &[("a.cpp", vec![text(0x100, 0x200)])]);
        let mut state = world.clone();
        first.apply(&mut state).unwrap();
        let second = build(&state, &[
            ("a.cpp", vec![text(0x100, 0x280)]),
            ("b.cpp", vec![text(0x280, 0x300)]),
        ]);
        second.apply(&mut state).unwrap();

        // Out of order is caught: the first transaction's bodies are no
        // longer what stands.
        assert!(first.clone().undo(&mut state.clone()).is_err());
        second.undo(&mut state).unwrap();
        first.undo(&mut state).unwrap();
        assert_eq!(state, world);
    }

    #[test]
    fn removing_a_block_entirely_is_refused() {
        let world = blocks(&[("a.cpp", &[text(0x100, 0x200)])]);
        let transaction = build(&world, &[("a.cpp", vec![])]);
        let error = transaction.preview(&world).unwrap_err().to_string();
        assert!(error.contains("whole block"), "{error}");
    }
}
