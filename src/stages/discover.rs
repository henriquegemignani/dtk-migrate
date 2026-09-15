//! Discovering useful split boundaries by measured compiler progress.
//!
//! A split says "this range of the target belongs to that source file". Getting
//! one right lets the comparison pair up functions that were already correct
//! and simply unattributed, so matched code goes up without a line of source
//! changing. Getting one wrong costs a build and is undone.
//!
//! The gate is a measured gain: a code candidate is kept only if the unit's own
//! matched code went up and no other unit's went down. The retail hash is also
//! required, but it proves something narrower than it looks — it says the split
//! is internally consistent, not that the candidate's source is right, because
//! a unit `configure.py` has not enabled still links from its extracted
//! original. That distinction is what [`super::verify`] exists to settle.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::{
    build::context::{BuildContext, is_trial_failure},
    project::{
        link_order::cyclic_units,
        report::Report,
        splits::{Splits, parse_range},
        transaction::Owned,
    },
    stages::{Candidate, Event, Outcome, Prepared, Selections, Stage},
};

pub struct Discover;

const VALIDATION: &str =
    "objdiff matched code; retail hash checks split integrity, not candidate source linkage";

/// Sections whose ranges a code candidate may claim.
const CODE_SECTIONS: [&str; 2] = [".text", ".init"];

/// What a discovery candidate proposes: a complete replacement body for a unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub lines: Vec<String>,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Code,
    Data,
}

fn format_range(section: &str, start: u32, end: u32) -> String {
    format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
}

fn ranges_in(lines: &[String], section: &str) -> Vec<(u32, u32)> {
    lines
        .iter()
        .filter_map(|line| parse_range(line))
        .filter(|range| range.section == section)
        .map(|range| (range.start, range.end))
        .collect()
}

/// Ranges every unit other than `name` already claims in `section`.
fn occupied(
    existing: &IndexMap<String, Vec<String>>,
    name: &str,
    section: &str,
) -> Vec<(u32, u32)> {
    existing
        .iter()
        .filter(|(other, _)| other.as_str() != name)
        .flat_map(|(_, lines)| ranges_in(lines, section))
        .collect()
}

/// Merges a unit's proposed and existing ranges in one section into one span.
///
/// Returns `None` when there is nothing to change, or when the span would
/// overlap a range another unit already owns.
fn merged_span(
    proposed: &[(u32, u32)],
    current: &[(u32, u32)],
    taken: &[(u32, u32)],
) -> Option<(u32, u32)> {
    let start = proposed.iter().chain(current).map(|r| r.0).min()?;
    let end = proposed.iter().chain(current).map(|r| r.1).max()?;
    if current == [(start, end)] {
        return None;
    }
    if taken.iter().any(|&(a, b)| start < b && a < end) {
        return None;
    }
    Some((start, end))
}

/// Proposals that widen or create a unit's code range.
///
/// Gaps inside the proposed span are kept rather than trimmed: the compiler
/// comparison is what tests ownership, and a partial code split can expose many
/// matching functions even when the rest of the translation unit is unfinished
/// or genuinely differs between versions. A span is never allowed to cross into
/// a range another established unit owns.
pub fn code_proposals(
    proposals: &IndexMap<String, Vec<String>>,
    existing: &IndexMap<String, Vec<String>>,
) -> Vec<(String, Vec<String>)> {
    let mut result: Vec<(String, Vec<String>)> = Vec::new();
    for (name, lines) in proposals {
        let sections: BTreeSet<String> = lines
            .iter()
            .filter_map(|line| parse_range(line))
            .filter(|range| CODE_SECTIONS.contains(&range.section.as_str()))
            .map(|range| range.section)
            .collect();
        if sections.is_empty() {
            continue;
        }
        let mut body: Vec<String> = existing.get(name).cloned().unwrap_or_default();
        for section in &sections {
            let proposed = ranges_in(lines, section);
            let current = ranges_in(&body, section);
            let taken = occupied(existing, name, section);
            let Some((start, end)) = merged_span(&proposed, &current, &taken) else { continue };
            body.retain(|line| parse_range(line).is_none_or(|r| &r.section != section));
            body.push(format_range(section, start, end));
        }
        if !body.is_empty() && Some(&body) != existing.get(name) {
            result.push((name.clone(), body));
        }
    }
    // Most code first: the biggest measurable gain per build.
    result.sort_by_key(|(_, body)| {
        let bytes: i64 = body
            .iter()
            .filter_map(|line| parse_range(line))
            .filter(|range| CODE_SECTIONS.contains(&range.section.as_str()))
            .map(|range| i64::from(range.end) - i64::from(range.start))
            .sum();
        -bytes
    });
    result
}

/// True when this unit emits no code at all in the source version.
///
/// Such a unit can never be reached by a code pass: there is no `.text` to
/// anchor on. Its data can still be proposed by symbol name, so it is the one
/// case where a data proposal may create a target unit outright. This asks the
/// *source* split rather than the proposal, because a proposal missing `.text`
/// usually means the matcher could not place the code — which is the case this
/// rule exists to reject.
fn data_only_in_source(source: &IndexMap<String, Vec<String>>, name: &str) -> bool {
    source.get(name).is_some_and(|body| {
        !body.is_empty()
            && !body
                .iter()
                .filter_map(|line| parse_range(line))
                .any(|range| CODE_SECTIONS.contains(&range.section.as_str()))
    })
}

/// How many bytes a unit's body claims in one section, if it claims any.
fn section_size(body: Option<&Vec<String>>, section: &str) -> Option<u32> {
    let ranges = ranges_in(body?, section);
    let start = ranges.iter().map(|r| r.0).min()?;
    let end = ranges.iter().map(|r| r.1).max()?;
    Some(end - start)
}

/// Grows a proposed range over an unowned remainder that would strand a symbol.
///
/// The matcher ends a proposed range at the last symbol it could match, so an
/// unmatched symbol sitting immediately after lands in a remainder nothing
/// owns. Nothing emits it, and the unit's own code still references it, so the
/// link fails on an undefined symbol — `musyx/runtime/synth.c` lost its whole
/// data migration to a four-byte tail of exactly this shape.
///
/// Claiming that remainder needs evidence it belongs here, so the growth is
/// bounded twice: never into the next owner's range, and never past the size
/// the same unit has in the source version.
fn extended_end(
    start: u32,
    end: u32,
    taken: &[(u32, u32)],
    source_body: Option<&Vec<String>>,
    section: &str,
) -> u32 {
    let Some(expected) = section_size(source_body, section) else { return end };
    if end - start >= expected {
        return end;
    }
    let mut limit = start + expected;
    if let Some(next) = taken.iter().map(|r| r.0).filter(|&a| a >= end).min() {
        limit = limit.min(next);
    }
    end.max(limit)
}

/// Proposals that extend an established unit with its non-code sections.
///
/// The matcher proposes a range for every section by symbol-name
/// correspondence, but [`code_proposals`] only ever acts on code. A unit whose
/// code is already split and matched can still be missing its `.rodata`,
/// `.bss`, `.sdata` or `.sbss`: the symbols are already correctly named, the
/// range was already proposed, nothing ever claimed it, it was simply never
/// carried over.
pub fn data_proposals(
    proposals: &IndexMap<String, Vec<String>>,
    existing: &IndexMap<String, Vec<String>>,
    source: &IndexMap<String, Vec<String>>,
) -> Vec<(String, Vec<String>)> {
    let mut names: Vec<String> = existing.keys().cloned().collect();
    names.extend(
        proposals
            .keys()
            .filter(|name| !existing.contains_key(*name) && data_only_in_source(source, name))
            .cloned(),
    );

    let mut result: Vec<(String, Vec<String>)> = Vec::new();
    for name in names {
        let body = existing.get(&name).cloned().unwrap_or_default();
        let Some(lines) = proposals.get(&name) else { continue };
        let sections: BTreeSet<String> = lines
            .iter()
            .filter_map(|line| parse_range(line))
            .filter(|range| !CODE_SECTIONS.contains(&range.section.as_str()))
            .map(|range| range.section)
            .collect();
        if sections.is_empty() {
            continue;
        }
        let mut new_body = body.clone();
        for section in &sections {
            let proposed = ranges_in(lines, section);
            let current = ranges_in(&new_body, section);
            let taken = occupied(existing, &name, section);
            let Some((start, mut end)) = merged_span(&proposed, &current, &taken) else {
                continue;
            };
            end = extended_end(start, end, &taken, source.get(&name), section);
            new_body.retain(|line| parse_range(line).is_none_or(|r| &r.section != section));
            new_body.push(format_range(section, start, end));
        }
        if new_body != body {
            result.push((name, new_body));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Whether any unit's matched code went down.
fn regresses(before: &Report, after: &Report) -> bool {
    let new = after.by_source_name();
    before.by_source_name().iter().any(|(name, unit)| {
        new.get(name).map(|u| u.matched_code()).unwrap_or(0) < unit.matched_code()
    })
}

fn matched(report: &Report, name: &str) -> u64 {
    report.by_source_name().get(name).map(|u| u.matched_code()).unwrap_or(0)
}

impl Stage for Discover {
    fn name(&self) -> &'static str { "discover" }

    fn prepare(&self, ctx: &BuildContext, limit: Option<usize>) -> Result<Prepared> {
        std::fs::create_dir_all(&ctx.output)?;
        let splits_path = ctx.root.join("config").join(&ctx.target).join("splits.txt");
        let symbols_path = splits_path.with_file_name("symbols.txt");

        let starting = ctx.build(None)?;
        let mut symbols = Owned::take(&symbols_path)?;
        let mut events: Vec<Event> = Vec::new();

        let proposals_path = ctx.output.join("proposals.txt");
        let renames_path = ctx.output.join("renames.txt");
        let mut request = crate::matching::Request::new(
            config_path(ctx, &ctx.source),
            config_path(ctx, &ctx.target),
        );
        request.outputs = crate::matching::Outputs {
            splits: Some(proposals_path.clone()),
            renames: Some(renames_path.clone()),
            report: Some(ctx.output.join("matches.json")),
            ..Default::default()
        };
        crate::matching::run(&request)?;

        // Confident renames are applied once, up front: `dtk match` anchors its
        // proposals on symbol names, so a name established here widens what
        // every later candidate can be. The batch is kept only if it builds and
        // costs no existing unit its matched code.
        let reason = match apply_renames(ctx, &mut symbols, &renames_path, &starting) {
            Ok(None) => None,
            Ok(Some(reason)) => Some(reason),
            Err(error) if is_trial_failure(&error) => Some(format!("{error:#}")),
            Err(error) => return Err(error),
        };
        if let Some(reason) = reason {
            symbols.restore()?;
            events.push(Event::new("", "rename-batch-reverted").because(reason));
        }
        symbols.commit();

        let baseline = ctx.build(None)?;
        let blocks = Splits::read(&splits_path)?.blocks;
        let proposals = Splits::read(&proposals_path)?.blocks;
        let source_blocks =
            Splits::read(&ctx.root.join("config").join(&ctx.source).join("splits.txt"))?.blocks;

        let mut candidates: Vec<Candidate> = code_proposals(&proposals, &blocks)
            .into_iter()
            .map(|(name, lines)| candidate(name, lines, Kind::Code))
            .collect::<Result<_>>()?;
        if let Some(limit) = limit {
            candidates.truncate(limit);
        }

        // One unit must never yield two candidates. Each kind carries a complete
        // replacement body, so whichever landed second would revert the other's
        // sections. Code keeps the slot because it has to prove a matched-code
        // gain, which the data pass deliberately skips; the unit's data is
        // proposed again by the next run.
        let staged: BTreeSet<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        let mut data: Vec<Candidate> = data_proposals(&proposals, &blocks, &source_blocks)
            .into_iter()
            .filter(|(name, _)| !staged.contains(name.as_str()))
            .map(|(name, lines)| candidate(name, lines, Kind::Data))
            .collect::<Result<_>>()?;
        if let Some(limit) = limit {
            data.truncate(limit);
        }
        candidates.extend(data);

        let mut extra = serde_json::Map::new();
        extra.insert("starting".into(), serde_json::to_value(&starting)?);
        Ok(Prepared { candidates, baseline, events, extra })
    }

    fn evaluate(
        &self,
        ctx: &BuildContext,
        _prepared: &Prepared,
        candidates: &[Candidate],
        _preferred: &Selections,
    ) -> Result<Outcome> {
        let names: BTreeSet<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        if names.len() != candidates.len() {
            bail!("Duplicate discovery candidate names");
        }
        let splits_path = ctx.root.join("config").join(&ctx.target).join("splits.txt");
        let mut owned = Owned::take(&splits_path)?;
        let mut splits = Splits::parse(&String::from_utf8(owned.original().to_vec())?)?;

        let mut state =
            Trials { report: ctx.build(None)?, accepted: BTreeSet::new(), events: Vec::new() };
        let baseline_cycles = cyclic_units(&splits.blocks);
        if !candidates.is_empty() {
            let mut queue = vec![candidates.to_vec()];
            while let Some(batch) = queue.pop() {
                let retry = state.trial(ctx, &mut owned, &mut splits, &batch, &baseline_cycles)?;
                match retry {
                    Retry::Done => {}
                    Retry::Split(halves) => queue.extend(halves.into_iter().rev()),
                }
            }
        }
        write(&mut owned, &splits)?;
        let final_report = ctx.build(None)?;
        if regresses(&state.report, &final_report) {
            bail!("Final discovery report regressed after validation");
        }
        owned.commit();

        let accepted: Vec<Candidate> =
            candidates.iter().filter(|c| state.accepted.contains(&c.name)).cloned().collect();
        let deferred: Vec<Candidate> =
            candidates.iter().filter(|c| !state.accepted.contains(&c.name)).cloned().collect();
        Ok(Outcome {
            accepted,
            deferred,
            events: state.events,
            report: final_report,
            validation: VALIDATION.to_string(),
            selections: Selections::new(),
        })
    }

    fn validate(
        &self,
        ctx: &BuildContext,
        _accepted: &[Candidate],
        _prepared: &Prepared,
        _selections: &Selections,
    ) -> Result<Report> {
        ctx.build(None)
    }
}

/// A version's project configuration, as the matcher wants it.
pub fn config_path(ctx: &BuildContext, version: &str) -> typed_path::Utf8NativePathBuf {
    let path = ctx.root.join("config").join(version).join("config.yml");
    typed_path::Utf8NativePathBuf::from(path.to_string_lossy().into_owned())
}

fn candidate(name: String, lines: Vec<String>, kind: Kind) -> Result<Candidate> {
    Ok(Candidate { evidence: serde_json::to_value(Proposal { lines, kind })?, name })
}

fn proposal_of(candidate: &Candidate) -> Result<Proposal> {
    serde_json::from_value(candidate.evidence.clone())
        .with_context(|| format!("Missing split proposal for {}", candidate.name))
}

fn write(owned: &mut Owned, splits: &Splits) -> Result<()> {
    owned.write(splits.render().as_bytes())
}

/// Applies the matcher's confident renames, returning why they were reverted.
fn apply_renames(
    ctx: &BuildContext,
    symbols: &mut Owned,
    renames: &std::path::Path,
    starting: &Report,
) -> Result<Option<String>> {
    let text = std::fs::read_to_string(renames).unwrap_or_default();
    if text.lines().all(|line| line.trim().is_empty() || line.trim_start().starts_with('#')) {
        return Ok(None);
    }
    let rename_set = crate::project::symbols::Renames::parse(&text)?;
    let current = String::from_utf8(std::fs::read(symbols.path())?)?;
    let (renamed, _) = crate::project::symbols::render_renames(&current, &rename_set);
    symbols.write(renamed.as_bytes())?;
    let after = ctx.build(None)?;
    Ok(regresses(starting, &after).then(|| "regressed existing matched code".to_string()))
}

enum Retry {
    Done,
    Split(Vec<Vec<Candidate>>),
}

struct Trials {
    report: Report,
    accepted: BTreeSet<String>,
    events: Vec<Event>,
}

impl Trials {
    fn trial(
        &mut self,
        ctx: &BuildContext,
        owned: &mut Owned,
        splits: &mut Splits,
        batch: &[Candidate],
        baseline_cycles: &BTreeSet<String>,
    ) -> Result<Retry> {
        if batch.is_empty() {
            return Ok(Retry::Done);
        }
        let mut staged = splits.clone();
        let mut new_names: Vec<String> = Vec::new();
        for candidate in batch {
            let proposal = proposal_of(candidate)?;
            if !staged.blocks.contains_key(&candidate.name) {
                new_names.push(candidate.name.clone());
            }
            staged.blocks.insert(candidate.name.clone(), proposal.lines);
        }

        // dtk rejects a cyclic link order before compiling anything, so a batch
        // that implies one can be bisected without paying for a build. Only a
        // cycle this batch introduces counts: candidates drag otherwise-fine
        // units into a component with them, and an input that was already
        // cyclic is the caller's problem, not this batch's.
        let introduced: BTreeSet<String> =
            cyclic_units(&staged.blocks).difference(baseline_cycles).cloned().collect();
        if batch.iter().any(|c| introduced.contains(&c.name)) {
            return Ok(self.reject(owned, splits, batch, "link-order-cycle")?);
        }

        staged.place_new_units(&new_names)?;
        write(owned, &staged)?;
        let tested = match ctx.trial_build() {
            Ok(report) => report,
            Err(error) if is_trial_failure(&error) => {
                return Ok(self.reject(owned, splits, batch, "build-conflict")?);
            }
            Err(error) => return Err(error),
        };

        // A data candidate only extends an already-matched unit's data ranges;
        // it never moves the matched-code count, so the gain test does not apply
        // to it. It still passes the build and retail check above and the
        // regression check below.
        let (keep, dropped): (Vec<&Candidate>, Vec<&Candidate>) =
            batch.iter().partition(|candidate| {
                proposal_of(candidate).map(|p| p.kind).unwrap_or(Kind::Code) == Kind::Data
                    || matched(&tested, &candidate.name) > matched(&self.report, &candidate.name)
            });
        if !dropped.is_empty() {
            self.events.extend(dropped.iter().map(|c| Event::new(&c.name, "no-matched-code-gain")));
            write(owned, splits)?;
            let keep: Vec<Candidate> = keep.into_iter().cloned().collect();
            return Ok(if keep.is_empty() { Retry::Done } else { Retry::Split(vec![keep]) });
        }
        if regresses(&self.report, &tested) {
            return Ok(self.reject(owned, splits, batch, "regresses-existing-code")?);
        }

        for candidate in batch {
            let gain = matched(&tested, &candidate.name) as i64
                - matched(&self.report, &candidate.name) as i64;
            self.events.push(
                Event::new(&candidate.name, "accepted").because(format!("{gain} code bytes")),
            );
            let proposal = proposal_of(candidate)?;
            let is_new = !splits.blocks.contains_key(&candidate.name);
            splits.blocks.insert(candidate.name.clone(), proposal.lines);
            if is_new {
                splits.place_new_units(std::slice::from_ref(&candidate.name))?;
            }
            self.accepted.insert(candidate.name.clone());
        }
        self.report = tested;
        Ok(Retry::Done)
    }

    /// Puts the accepted state back, then halves the batch or records a single
    /// candidate's rejection.
    fn reject(
        &mut self,
        owned: &mut Owned,
        splits: &Splits,
        batch: &[Candidate],
        status: &str,
    ) -> Result<Retry> {
        write(owned, splits)?;
        if batch.len() > 1 {
            let middle = batch.len() / 2;
            return Ok(Retry::Split(vec![batch[..middle].to_vec(), batch[middle..].to_vec()]));
        }
        self.events.push(Event::new(&batch[0].name, status));
        Ok(Retry::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(entries: &[(&str, &[&str])]) -> IndexMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(name, lines)| {
                ((*name).to_string(), lines.iter().map(|l| (*l).to_string()).collect())
            })
            .collect()
    }

    fn text(start: u32, end: u32) -> String { format_range(".text", start, end) }
    fn data(start: u32, end: u32) -> String { format_range(".data", start, end) }

    #[test]
    fn a_new_code_unit_is_proposed_whole() {
        let proposals = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = code_proposals(&proposals, &IndexMap::new());
        assert_eq!(result, vec![("a.cpp".to_string(), vec![text(0x100, 0x200)])]);
    }

    #[test]
    fn an_existing_unit_is_widened_to_cover_both_ranges() {
        let proposals = blocks(&[("a.cpp", &[&text(0x300, 0x400)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = code_proposals(&proposals, &existing);
        // The gap in the middle is kept: the comparison tests ownership.
        assert_eq!(result[0].1, vec![text(0x100, 0x400)]);
    }

    #[test]
    fn a_span_that_would_cross_another_unit_is_dropped() {
        let proposals = blocks(&[("a.cpp", &[&text(0x300, 0x400)])]);
        let existing =
            blocks(&[("a.cpp", &[&text(0x100, 0x200)]), ("b.cpp", &[&text(0x250, 0x280)])]);
        assert!(code_proposals(&proposals, &existing).is_empty());
    }

    #[test]
    fn a_unit_already_covering_the_span_proposes_nothing() {
        let proposals = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        assert!(code_proposals(&proposals, &existing).is_empty());
    }

    #[test]
    fn a_data_only_proposal_is_not_a_code_candidate() {
        let proposals = blocks(&[("a.cpp", &[&data(0x100, 0x200)])]);
        assert!(code_proposals(&proposals, &IndexMap::new()).is_empty());
    }

    #[test]
    fn candidates_are_ordered_by_how_much_code_they_claim() {
        let proposals =
            blocks(&[("small.cpp", &[&text(0x100, 0x110)]), ("big.cpp", &[&text(0x200, 0x400)])]);
        let result = code_proposals(&proposals, &IndexMap::new());
        assert_eq!(result[0].0, "big.cpp");
    }

    #[test]
    fn data_extends_an_established_unit_without_touching_its_code() {
        let proposals = blocks(&[("a.cpp", &[&text(0x100, 0x200), &data(0x900, 0xA00)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = data_proposals(&proposals, &existing, &IndexMap::new());
        assert_eq!(result[0].1, vec![text(0x100, 0x200), data(0x900, 0xA00)]);
    }

    #[test]
    fn data_never_creates_a_unit_that_has_code_in_the_source_version() {
        let proposals = blocks(&[("new.cpp", &[&data(0x900, 0xA00)])]);
        let source = blocks(&[("new.cpp", &[&text(0x100, 0x200), &data(0x900, 0xA00)])]);
        assert!(data_proposals(&proposals, &IndexMap::new(), &source).is_empty());
    }

    #[test]
    fn data_may_create_a_unit_that_emits_no_code_at_all() {
        // No .text exists to anchor on, so no code pass could ever place it.
        let proposals = blocks(&[("table.cpp", &[&data(0x900, 0xA00)])]);
        let source = blocks(&[("table.cpp", &[&data(0x900, 0xA00)])]);
        let result = data_proposals(&proposals, &IndexMap::new(), &source);
        assert_eq!(result[0].0, "table.cpp");
    }

    #[test]
    fn a_range_grows_over_a_remainder_that_would_strand_a_symbol() {
        // synth.c: the proposal stops at the last matched symbol and leaves a
        // four-byte tail nothing owns, which fails the link.
        let proposals = blocks(&[("synth.c", &[&data(0x900, 0x9FC)])]);
        let existing = blocks(&[("synth.c", &[&text(0x100, 0x200)])]);
        let source = blocks(&[("synth.c", &[&data(0x800, 0x900)])]);
        let result = data_proposals(&proposals, &existing, &source);
        assert!(result[0].1.contains(&data(0x900, 0xA00)), "{:?}", result[0].1);
    }

    #[test]
    fn growth_stops_at_the_next_owner() {
        let proposals = blocks(&[("a.cpp", &[&data(0x900, 0x9FC)])]);
        let existing =
            blocks(&[("a.cpp", &[&text(0x100, 0x200)]), ("b.cpp", &[&data(0x9FE, 0xB00)])]);
        let source = blocks(&[("a.cpp", &[&data(0x800, 0x900)])]);
        let result = data_proposals(&proposals, &existing, &source);
        assert!(result[0].1.contains(&data(0x900, 0x9FE)), "{:?}", result[0].1);
    }

    #[test]
    fn growth_never_exceeds_the_size_the_source_version_has() {
        let proposals = blocks(&[("a.cpp", &[&data(0x900, 0x9FC)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        // The source unit is smaller than the proposal, so nothing is added.
        let source = blocks(&[("a.cpp", &[&data(0x800, 0x810)])]);
        let result = data_proposals(&proposals, &existing, &source);
        assert!(result[0].1.contains(&data(0x900, 0x9FC)), "{:?}", result[0].1);
    }

    #[test]
    fn a_unit_with_no_source_body_is_not_grown() {
        let proposals = blocks(&[("a.cpp", &[&data(0x900, 0x9FC)])]);
        let existing = blocks(&[("a.cpp", &[&text(0x100, 0x200)])]);
        let result = data_proposals(&proposals, &existing, &IndexMap::new());
        assert!(result[0].1.contains(&data(0x900, 0x9FC)), "{:?}", result[0].1);
    }
}
