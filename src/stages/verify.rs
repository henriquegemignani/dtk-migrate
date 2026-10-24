//! Enabling whole source files, once their compiled objects are shown to link
//! and produce retail bytes.
//!
//! This is the only stage whose acceptance means "this file's source is
//! correct". The others move boundaries and names around, which improves what a
//! comparison can see without ever compiling the candidate into the shipped
//! binary.
//!
//! What makes it a proof and not a coincidence is that both halves are checked.
//! A retail hash on its own proves nothing here: `tools/project.py` links the
//! *extracted original* object for any file `configure.py` has not enabled, so
//! a build can pass its checksum while the candidate's source was never
//! compiled into it. That is the circularity the earlier tool fell into. So
//! every accepted unit must also appear, by its compiled object path, in the
//! actual Ninja input list of the artifact it belongs to.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::{
    build::context::{BuildContext, ValidationError, is_trial_failure},
    derive::objects::Compiled,
    matching::{
        data_evidence::{LayoutIndex, LayoutSymbol, adjacent_span, layout_symbols},
        relocation_pairing::{DolImage, PairedSection, Pairing, TargetIndex},
    },
    project::{
        configure_py::Configure,
        link_order::cyclic_units,
        report::{ObjdiffConfig, ObjdiffUnit, Report, strip_source_root},
        splits::{Splits, entry_line, entry_suffix, parse_attributes, parse_range},
        transaction::Owned,
    },
    stages::{
        Applied, Candidate, DataSeam, Event, MutationScope, Outcome, Prepared, Selections, Stage,
        bisect_pretested_groups,
        refusal::{Kind, LinkerDiagnosticKind, Refusal},
    },
};

pub struct Verify;

/// What acceptance in this stage establishes.
const VALIDATION: &str = "compiled-link-inputs-and-retail-bytes";

/// Link feedback rounds for one unit. Each round adds the data ranges the
/// previous link named and costs one more link.
const FEEDBACK_ROUNDS: usize = 3;

/// The `Applied` id of data ranges added from link feedback.
const DATA_FEEDBACK: &str = "data-split-feedback";

/// The target data ranges link feedback added for a unit that then linked
/// from source and matched retail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFeedback {
    /// The unit's name in `splits.txt`, which can differ from its source name.
    pub split_unit: String,
    /// The `splits.txt` lines added to that unit. Not `lines`: benchmark
    /// reads a record's `lines` as a coverage body.
    pub data_lines: Vec<String>,
    /// The source sections whose ranges came from relocation pairing, with
    /// what was compared. Empty for ranges the linker's own diagnostics named.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pairing: Vec<PairedSection>,
}

impl Stage for Verify {
    fn name(&self) -> &'static str { "verify" }

    fn scopes(&self, candidate: &Candidate) -> Result<BTreeSet<MutationScope>> {
        Ok(BTreeSet::from([MutationScope::UnitLink(candidate.name.clone())]))
    }

    fn prepare(&self, ctx: &BuildContext, limit: Option<usize>) -> Result<Prepared> {
        if limit == Some(0) {
            bail!("limit must be positive");
        }
        let path = ctx.root.join("configure.py");
        let mut owned = Owned::take(&path)?;
        let text = String::from_utf8(owned.original().to_vec())?;
        let configure = Configure::parse(&text)?;

        // Fold any legacy override block into ordinary statuses before
        // measuring, so the baseline reflects what the project really enables.
        let migrated: BTreeMap<String, Vec<String>> = configure
            .legacy_blocks()
            .iter()
            .map(|block| (block.version.clone(), block.names.iter().cloned().collect()))
            .collect();
        let rendered = configure.render(&ctx.target, &BTreeSet::new())?;
        owned.write(rendered.as_bytes())?;

        let migrated_configure = Configure::parse(&rendered)?;
        let mut unsplit = Vec::new();
        let baseline = validate(
            ctx,
            &migrated_configure.configured_names(&ctx.target),
            false,
            Some(&mut unsplit),
        )?;
        owned.check()?;

        let units = baseline.by_source_name();
        let mut candidates: Vec<(&str, u64)> = units
            .iter()
            .filter(|(_, unit)| unit.metadata.complete != Some(true))
            .filter(|(_, unit)| unit.matched_code() > 0)
            .filter(|(_, unit)| unit.matches_on_content())
            .map(|(name, unit)| (*name, unit.matched_code()))
            .collect();
        // Biggest first: the most matched code per build, and a batch that fails
        // costs less to bisect when its members are not interchangeable.
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

        // Candidates come from the build report, which says nothing about how an
        // object is declared. Dropping the ones whose declaration cannot be
        // rewritten costs those units; leaving them in costs whichever batch
        // they land in, after that batch has already done its builds.
        let blocked = migrated_configure.unrewritable_names();
        let mut events: Vec<Event> = candidates
            .iter()
            .filter_map(|(name, _)| blocked.get(*name).map(|kind| (name, kind)))
            .map(|(name, kind)| {
                Event::new(*name, "skipped").because(format!("{kind} cannot be widened safely"))
            })
            .collect();
        events.extend(unsplit.iter().map(|name| {
            Event::new(name, "configured-without-split").because(format!(
                "MatchingFor({0}) but {0} has no split for it, so nothing is compiled or linked",
                ctx.target
            ))
        }));

        let mut chosen: Vec<Candidate> = candidates
            .into_iter()
            .filter(|(name, _)| !blocked.contains_key(*name))
            .map(|(name, _)| Candidate::new(name))
            .collect();
        if let Some(limit) = limit {
            chosen.truncate(limit);
        }

        let mut extra = serde_json::Map::new();
        extra.insert("migrated_legacy".into(), serde_json::to_value(&migrated)?);
        // The rendered configuration is the baseline every trial renders from.
        owned.commit();
        Ok(Prepared { candidates: chosen, baseline, events, extra, permitted: Default::default() })
    }

    fn evaluate(
        &self,
        ctx: &BuildContext,
        prepared: &Prepared,
        candidates: &[Candidate],
        _preferred: &Selections,
    ) -> Result<Outcome> {
        self.evaluate_with_negative(ctx, prepared, candidates, &BTreeMap::new(), &BTreeMap::new())
    }

    fn integrate_pretested(
        &self,
        ctx: &BuildContext,
        prepared: &Prepared,
        candidates: &[Candidate],
        _preferred: &Selections,
        negative: &BTreeMap<String, Event>,
        negative_groups: &BTreeMap<Vec<String>, Vec<Event>>,
    ) -> Result<Outcome> {
        self.evaluate_with_negative(ctx, prepared, candidates, negative, negative_groups)
    }

    fn validate(
        &self,
        ctx: &BuildContext,
        accepted: &[Candidate],
        _prepared: &Prepared,
        _selections: &Selections,
        applied: &[Applied],
    ) -> Result<Report> {
        // Data ranges link feedback added are part of what was proved. The
        // project being validated must still hold every one of them.
        let feedback: Vec<&Applied> =
            applied.iter().filter(|entry| entry.id == DATA_FEEDBACK).collect();
        if !feedback.is_empty() {
            let path = ctx.root.join("config").join(&ctx.target).join("splits.txt");
            check_feedback(&feedback, accepted, &Splits::read(&path)?.blocks)?;
        }
        let text = std::fs::read_to_string(ctx.root.join("configure.py"))?;
        let mut names = Configure::parse(&text)?.configured_names(&ctx.target);
        names.extend(accepted.iter().map(|c| c.name.clone()));
        validate(ctx, &names, false, None)
    }
}

/// Requires every unit with link feedback to be accepted and its target
/// split to still hold each line feedback added.
fn check_feedback(
    feedback: &[&Applied],
    accepted: &[Candidate],
    blocks: &IndexMap<String, Vec<String>>,
) -> Result<()> {
    for entry in feedback {
        let feedback: DataFeedback = serde_json::from_value(entry.record.clone())?;
        let body = blocks.get(&feedback.split_unit).map(Vec::as_slice).unwrap_or_default();
        if !accepted.iter().any(|candidate| candidate.name == entry.unit)
            || feedback.data_lines.iter().any(|line| !body.contains(line))
        {
            bail!("Link feedback data ranges for {} changed after verification", entry.unit);
        }
    }
    Ok(())
}

impl Verify {
    fn evaluate_with_negative(
        &self,
        ctx: &BuildContext,
        prepared: &Prepared,
        candidates: &[Candidate],
        negative: &BTreeMap<String, Event>,
        negative_groups: &BTreeMap<Vec<String>, Vec<Event>>,
    ) -> Result<Outcome> {
        let path = ctx.root.join("configure.py");
        let mut owned = Owned::take(&path)?;
        let text = String::from_utf8(owned.original().to_vec())?;
        let configure = Configure::parse(&text)?;

        // Preflight before writing anything: a name this file cannot express
        // should fail now, not after the batch has done its builds.
        let requested: BTreeSet<String> = candidates.iter().map(|c| c.name.clone()).collect();
        configure.render(&ctx.target, &requested)?;
        let baseline_names = configure.configured_names(&ctx.target);

        let write = |owned: &mut Owned, names: &BTreeSet<String>| -> Result<()> {
            owned.write(configure.render(&ctx.target, names)?.as_bytes())
        };

        let mut feedback = LinkFeedback::new(prepared);
        let (accepted, deferred, mut events) = bisect_pretested_groups(
            candidates,
            "failed-source-link-or-hash",
            "retail-hash-verified-source",
            negative,
            negative_groups,
            |already, batch| {
                let proposed: BTreeSet<String> =
                    already.iter().chain(batch).map(|c| c.name.clone()).collect();
                write(&mut owned, &proposed)?;
                let mut checked = baseline_names.clone();
                checked.extend(proposed.iter().cloned());
                feedback.stage(ctx, batch)?;
                let outcome = match validate(ctx, &checked, true, None) {
                    Ok(_) => {
                        feedback.keep();
                        Ok(())
                    }
                    // Only an isolated unit's failure says which unit the
                    // linker's diagnostics are about.
                    Err(error) if batch.len() == 1 && is_trial_failure(&error) => {
                        feedback.retry(ctx, &batch[0].name, &checked, error)
                    }
                    Err(error) => {
                        feedback.discard()?;
                        Err(error)
                    }
                };
                if outcome.is_err() {
                    // Put the file back to the accepted set before the next
                    // trial, so a failure never leaks into the one after it.
                    let kept: BTreeSet<String> = already.iter().map(|c| c.name.clone()).collect();
                    write(&mut owned, &kept)?;
                }
                outcome
            },
        )?;

        let kept: BTreeSet<String> = accepted.iter().map(|c| c.name.clone()).collect();
        write(&mut owned, &kept)?;
        let (applied, feedback_events, splits) = feedback.finish(&kept)?;
        // A worker's accepted candidate carries the ranges it needed, so that
        // integration can stage them with the candidate rather than refuse the
        // union and rediscover them one unit at a time. A candidate accepted
        // without feedback carries nothing, even if it arrived with ranges.
        let mut accepted = accepted;
        for candidate in &mut accepted {
            candidate.evidence = applied
                .iter()
                .find(|entry| entry.unit == candidate.name)
                .map_or(serde_json::Value::Null, |entry| entry.record.clone());
        }
        events.extend(feedback_events);
        let mut checked = baseline_names;
        checked.extend(kept);
        let report = validate(ctx, &checked, false, None)?;
        owned.check()?;
        if let Some(splits) = splits {
            splits.check()?;
            splits.commit();
        }
        owned.commit();
        Ok(Outcome {
            tried: Default::default(),
            accepted,
            deferred,
            events,
            report,
            validation: VALIDATION.to_string(),
            applied,
            selections: Selections::new(),
        })
    }
}

/// Feeds a source-link refusal's duplicate data symbols back as data splits.
///
/// When a unit's data stays in an unsplit gap object, linking the unit from
/// source defines that data twice: `multiply-defined: 'S' in unit.o,
/// Previously defined in auto_NN_ADDR_sec.o`. If the unit's source split for
/// that section holds S, the unit's target range is the source split mapped
/// by its anchor-bracketed delta (see [`LayoutIndex`]), or else S's own
/// extent. The unit is linked again with those ranges added, and kept only if
/// that link passes the same input and retail checks as any other trial.
struct LinkFeedback {
    permitted: crate::stages::Permitted,
    /// Loaded on the first refusal that might be fed back. `None` inside
    /// when the target has no `splits.txt` to extend.
    loaded: Option<Option<Loaded>>,
    added: BTreeMap<String, DataFeedback>,
    /// Lines staged for the batch under trial, from candidates a worker
    /// already proved with feedback. Nothing here is kept until that batch
    /// passes its trial.
    pending: Option<(Splits, BTreeMap<String, DataFeedback>)>,
    events: Vec<Event>,
}

struct Loaded {
    splits: Owned,
    /// The target splits as accepted so far, feedback included.
    accepted: Splits,
    baseline_cycles: BTreeSet<String>,
    inputs: FeedbackInputs,
}

/// What feedback reads from both versions.
struct FeedbackInputs {
    source_symbols: Vec<LayoutSymbol>,
    target_symbols: Vec<LayoutSymbol>,
    source_blocks: IndexMap<String, Vec<String>>,
    /// Verify's source name to the unit's `splits.txt` name, DOL units only.
    split_units: BTreeMap<String, String>,
    /// Jump-table seams an earlier stage certified.
    seams: Vec<DataSeam>,
    /// Verify's source name to the unit's compiled source object and the
    /// object extracted from the target, DOL units only.
    objects: BTreeMap<String, (std::path::PathBuf, std::path::PathBuf)>,
    /// The target's initialized bytes, when its DOL can be read.
    image: Option<DolImage>,
}

impl Loaded {
    fn read(ctx: &BuildContext, permitted: &crate::stages::Permitted) -> Result<Option<Self>> {
        let config = |version: &str| ctx.root.join("config").join(version);
        let path = config(&ctx.target).join("splits.txt");
        if !path.is_file() {
            return Ok(None);
        }
        let read = |path: std::path::PathBuf| {
            std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))
        };
        let splits = Owned::take(&path)?;
        let accepted = Splits::parse(&String::from_utf8(splits.original().to_vec())?)?;
        let objdiff = ObjdiffConfig::read(&ctx.root.join("objdiff.json"))?;
        let objects = objdiff
            .units
            .iter()
            .filter_map(|unit| {
                let name = strip_source_root(unit.metadata.source_path.as_deref()?);
                let (base, target) = (unit.base_path.as_deref()?, unit.target_path.as_deref()?);
                if module_of(target, &ctx.target).is_some() {
                    return None;
                }
                Some((name.to_string(), (ctx.root.join(base), ctx.root.join(target))))
            })
            .collect();
        let image = DolImage::of_version(&ctx.root, &ctx.target);
        let split_units = objdiff
            .units
            .iter()
            .filter_map(|unit| {
                let name = strip_source_root(unit.metadata.source_path.as_deref()?);
                let target_path = unit.target_path.as_deref()?.replace('\\', "/");
                if module_of(&target_path, &ctx.target).is_some() {
                    return None;
                }
                let stem = target_path.split_once("/obj/")?.1.strip_suffix(".o")?;
                let matching: Vec<&String> = accepted
                    .blocks
                    .keys()
                    .filter(|key| {
                        key.rsplit_once('.').map_or(key.as_str(), |(stem, _)| stem) == stem
                    })
                    .collect();
                // `x.c` and `x.cpp` share an object stem; the source path's
                // extension decides, and an unresolved tie maps to nothing.
                let split = match matching.as_slice() {
                    [only] => *only,
                    several => {
                        let extension = name.rsplit_once('.').map(|(_, extension)| extension);
                        let mut exact = several.iter().filter(|key| {
                            key.rsplit_once('.').map(|(_, extension)| extension) == extension
                        });
                        match (exact.next(), exact.next()) {
                            (Some(key), None) => *key,
                            _ => return None,
                        }
                    }
                };
                Some((name.to_string(), split.clone()))
            })
            .collect();
        let inputs = FeedbackInputs {
            source_symbols: layout_symbols(&read(config(&ctx.source).join("symbols.txt"))?),
            target_symbols: layout_symbols(&read(config(&ctx.target).join("symbols.txt"))?),
            source_blocks: Splits::read(&config(&ctx.source).join("splits.txt"))?.blocks,
            split_units,
            seams: permitted.jump_table_seams.iter().cloned().collect(),
            objects,
            image,
        };
        Ok(Some(Self { baseline_cycles: cyclic_units(&accepted.blocks), splits, accepted, inputs }))
    }

    /// The splits name of a unit whose data this stage may still change.
    fn writable(&self, permitted: &crate::stages::Permitted, name: &str) -> Option<String> {
        // Coverage and discovery recheck the exact bodies they certified, so
        // a unit an earlier stage changed keeps its body.
        let split_unit = self.inputs.split_units.get(name)?;
        (!permitted.reserved.contains(split_unit)
            && !permitted.reserved_data.contains(split_unit)
            && self.accepted.blocks.contains_key(split_unit))
        .then(|| split_unit.clone())
    }

    /// Puts the splits file back to the accepted state.
    fn restore(&mut self, any_accepted: bool) -> Result<()> {
        if any_accepted {
            self.splits.write(self.accepted.render().as_bytes())
        } else {
            self.splits.restore()
        }
    }
}

impl LinkFeedback {
    fn new(prepared: &Prepared) -> Self {
        Self {
            permitted: prepared.permitted.clone(),
            loaded: None,
            added: BTreeMap::new(),
            pending: None,
            events: Vec::new(),
        }
    }

    fn load(&mut self, ctx: &BuildContext) -> Result<Option<&mut Loaded>> {
        if self.loaded.is_none() {
            self.loaded = Some(Loaded::read(ctx, &self.permitted)?);
        }
        Ok(self.loaded.as_mut().and_then(Option::as_mut))
    }

    fn loaded(&mut self) -> &mut Loaded {
        self.loaded.as_mut().and_then(Option::as_mut).expect("link feedback inputs are loaded")
    }

    /// Stages the ranges a worker's trial of these candidates needed. A line
    /// that no longer fits beside the accepted splits is left out, and the
    /// unit then goes through feedback again if its link is refused.
    fn stage(&mut self, ctx: &BuildContext, batch: &[Candidate]) -> Result<()> {
        let carried: Vec<(&str, DataFeedback)> = batch
            .iter()
            .filter_map(|candidate| {
                let feedback = serde_json::from_value(candidate.evidence.clone()).ok()?;
                Some((candidate.name.as_str(), feedback))
            })
            .collect();
        if carried.is_empty() || self.load(ctx)?.is_none() {
            return Ok(());
        }
        let loaded = self.loaded.as_ref().and_then(Option::as_ref).unwrap();
        let carried = carried
            .into_iter()
            .filter(|(name, feedback)| {
                loaded.writable(&self.permitted, name).as_ref() == Some(&feedback.split_unit)
            })
            .collect();
        let (staged, lines) =
            stage_lines(&loaded.accepted, &loaded.baseline_cycles, &loaded.inputs.seams, carried);
        if !lines.is_empty() {
            self.loaded().splits.write(staged.render().as_bytes())?;
            self.pending = Some((staged, lines));
        }
        Ok(())
    }

    /// The batch passed: its staged lines are now accepted.
    fn keep(&mut self) {
        if let Some((staged, lines)) = self.pending.take() {
            self.loaded().accepted = staged;
            self.added.extend(lines);
        }
    }

    /// The batch failed: its staged lines are withdrawn.
    fn discard(&mut self) -> Result<()> {
        if self.pending.take().is_some() {
            let any_accepted = !self.added.is_empty();
            self.loaded().restore(any_accepted)?;
        }
        Ok(())
    }

    /// Retries one refused unit with the data ranges its link named, at most
    /// [`FEEDBACK_ROUNDS`] times, on top of any ranges staged for it. Returns
    /// the last refusal if none passes.
    fn retry(
        &mut self,
        ctx: &BuildContext,
        name: &str,
        checked: &BTreeSet<String>,
        mut error: anyhow::Error,
    ) -> Result<()> {
        let pending = self.pending.take();
        let any_accepted = !self.added.is_empty();
        let split_unit = if !feedable(&Refusal::from_error(&error)) {
            None
        } else if self.load(ctx)?.is_some() {
            let loaded = self.loaded.as_ref().and_then(Option::as_ref).unwrap();
            loaded.writable(&self.permitted, name)
        } else {
            None
        };
        let Some(split_unit) = split_unit else {
            if pending.is_some() {
                self.loaded().restore(any_accepted)?;
            }
            return Err(error);
        };
        let (mut staged, mut lines, mut pairing) = match pending {
            Some((staged, mut carried)) => {
                let carried = carried.remove(name);
                let (lines, pairing) =
                    carried.map(|feedback| (feedback.data_lines, feedback.pairing)).unzip();
                (staged, lines.unwrap_or_default(), pairing.unwrap_or_default())
            }
            None => (self.loaded().accepted.clone(), Vec::new(), Vec::new()),
        };
        for round in 1..=FEEDBACK_ROUNDS {
            let refusal = Refusal::from_error(&error);
            let inputs = &self.loaded().inputs;
            let mut derived = derive_ranges(inputs, &split_unit, &staged.blocks, &refusal);
            if derived.is_empty() {
                derived = derive_paired_ranges(inputs, name, &split_unit, &staged.blocks, &refusal);
            }
            if derived.is_empty() {
                break;
            }
            let body = staged.blocks.get_mut(&split_unit).unwrap();
            for range in &derived {
                insert_line(body, range.line.clone());
            }
            let reasons =
                derived.iter().map(|range| range.reason.as_str()).collect::<Vec<_>>().join("; ");
            if cyclic_units(&staged.blocks)
                .difference(&self.loaded().baseline_cycles)
                .next()
                .is_some()
            {
                self.events.push(Event::new(name, DATA_FEEDBACK).because(format!(
                    "round {round}: not linked, the ranges would make the link order cyclic: {reasons}"
                )));
                break;
            }
            self.events.push(
                Event::new(name, DATA_FEEDBACK)
                    .because(format!("round {round}: linking again with {reasons}")),
            );
            let loaded = self.loaded();
            pairing.extend(derived.iter().filter_map(|range| range.paired.clone()));
            lines.extend(derived.into_iter().map(|range| range.line));
            loaded.splits.write(staged.render().as_bytes())?;
            match validate(ctx, checked, true, None) {
                Ok(_) => {
                    loaded.accepted = staged;
                    self.added.insert(name.to_string(), DataFeedback {
                        split_unit,
                        data_lines: lines,
                        pairing,
                    });
                    return Ok(());
                }
                Err(next) if is_trial_failure(&next) => error = next,
                Err(next) => {
                    loaded.restore(any_accepted)?;
                    return Err(next);
                }
            }
        }
        self.loaded().restore(any_accepted)?;
        Err(error)
    }

    /// The feedback of units that stayed accepted, and the splits file as
    /// they left it, still uncommitted: the caller commits it only once the
    /// final validation passes, and dropping it restores the original.
    fn finish(self, kept: &BTreeSet<String>) -> Result<(Vec<Applied>, Vec<Event>, Option<Owned>)> {
        if self.added.keys().any(|name| !kept.contains(name)) {
            bail!("Link feedback was recorded for a unit verification did not keep");
        }
        let splits = self.loaded.flatten().map(|loaded| loaded.splits);
        let applied = self
            .added
            .into_iter()
            .map(|(unit, feedback)| {
                Ok(Applied {
                    unit,
                    id: DATA_FEEDBACK.to_string(),
                    units: vec![feedback.split_unit.clone()],
                    record: serde_json::to_value(feedback)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok((applied, self.events, splits))
    }
}

/// Adds each unit's carried lines to `accepted` when all of them still fit
/// beside the splits and add no link-order cycle; a unit whose lines do not
/// is left out whole.
fn stage_lines(
    accepted: &Splits,
    baseline_cycles: &BTreeSet<String>,
    seams: &[DataSeam],
    carried: Vec<(&str, DataFeedback)>,
) -> (Splits, BTreeMap<String, DataFeedback>) {
    let mut staged = accepted.clone();
    let mut lines = BTreeMap::new();
    for (name, feedback) in carried {
        if !staged.blocks.contains_key(&feedback.split_unit) {
            continue;
        }
        let mut trial = staged.clone();
        let fits = feedback.data_lines.iter().all(|line| {
            let Some(range) = parse_range(line) else { return false };
            let body = &trial.blocks[&feedback.split_unit];
            let free =
                trial.blocks.values().flatten().filter_map(|l| parse_range(l)).all(|other| {
                    other.section != range.section
                        || other.end <= range.start
                        || range.end <= other.start
                }) && keeps_seams(seams, &feedback.split_unit, &range.section, range.start, |at| {
                    starts_at(body, &range.section, at)
                });
            if free {
                insert_line(trial.blocks.get_mut(&feedback.split_unit).unwrap(), line.clone());
            }
            free
        });
        if fits && cyclic_units(&trial.blocks).difference(baseline_cycles).next().is_none() {
            staged = trial;
            lines.insert(name.to_string(), feedback);
        }
    }
    (staged, lines)
}

/// Whether `lines` hold a range of `section` starting at `address`.
fn starts_at(lines: &[String], section: &str, address: u32) -> bool {
    lines
        .iter()
        .filter_map(|line| parse_range(line))
        .any(|range| range.section == section && range.start == address)
}

/// Whether a new range of `unit` starting at `start` keeps every certified
/// jump-table seam of its section, as discovery rechecks them at publication:
/// only the expected unit may start at a seam, and once that unit has a range
/// in the section, one of its ranges must start there. `unit_starts_at` says
/// whether the unit already has a range starting at an address.
fn keeps_seams(
    seams: &[DataSeam],
    unit: &str,
    section: &str,
    start: u32,
    unit_starts_at: impl Fn(u32) -> bool,
) -> bool {
    seams.iter().filter(|seam| seam.section == section).all(|seam| {
        if start == seam.address {
            unit == seam.next_unit
        } else {
            unit != seam.next_unit || unit_starts_at(seam.address)
        }
    })
}

/// A target data range derived from one link refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivedRange {
    section: String,
    start: u32,
    end: u32,
    line: String,
    reason: String,
    /// The range is one symbol's own extent rather than a mapped source split.
    own_extent: bool,
    /// The relocation pairing the range came from.
    paired: Option<PairedSection>,
}

/// `auto_09_8041BEB8_sdata.o` names a gap object: the section `.sdata` and
/// the address the unsplit gap starts at.
fn gap_object(name: &str) -> Option<(String, u32)> {
    let stem = name.strip_prefix("auto_")?.strip_suffix(".o")?;
    let (_, rest) = stem.split_once('_')?;
    let (address, section) = rest.split_once('_')?;
    Some((format!(".{section}"), u32::from_str_radix(address, 16).ok()?))
}

/// Whether a symbol the linker printed (demangled for C++) is this
/// `symbols.txt` name.
///
/// Whitespace is ignored: mwld may wrap a long name inside a token, and a
/// rejoined message cannot tell that break from a real space such as the one
/// after a comma in a template argument list.
fn linker_spelling(printed: &str, name: &str) -> bool {
    let squeezed = |text: &str| text.split_whitespace().collect::<String>();
    let printed = squeezed(printed);
    printed == squeezed(name)
        || objdiff_core::diff::Demangler::Codewarrior
            .demangle(name)
            .is_some_and(|demangled| squeezed(&demangled) == printed)
}

/// A path's file name without its extension: `Kyoto/CFoo.cpp` and `CFoo.o`
/// are both `CFoo`.
fn file_stem(path: &str) -> &str {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

/// The target ranges a refusal's gap duplicates imply for `unit`.
///
/// Only duplicates the linker reports in this unit's own object count. Each
/// range lies inside the gap the linker named, overlaps no existing split,
/// and is backed by one of the unit's own source splits of that section
/// holding the symbol: that whole split mapped by its anchor-bracketed delta
/// (see [`LayoutIndex`]) when the mapping fits the gap and keeps the split's
/// alignment, or else the symbol's own extent. Every duplicate of the refusal
/// is derived in one round, and adjacent own extents become one range.
fn derive_ranges(
    inputs: &FeedbackInputs,
    unit: &str,
    target_blocks: &IndexMap<String, Vec<String>>,
    refusal: &Refusal,
) -> Vec<DerivedRange> {
    let index = LayoutIndex::new(&inputs.source_symbols, &inputs.target_symbols);
    let mut derived: Vec<DerivedRange> = Vec::new();
    for diagnostic in &refusal.linker {
        let (Some(object), Some(gap)) =
            (diagnostic.object.as_deref(), diagnostic.previously_defined_in.as_deref())
        else {
            continue;
        };
        let Some((section, gap_start)) = gap_object(gap) else { continue };
        if diagnostic.kind != LinkerDiagnosticKind::MultiplyDefined
            || file_stem(object) != file_stem(unit)
        {
            continue;
        }
        let occupied: Vec<(u32, u32)> = target_blocks
            .values()
            .flatten()
            .filter_map(|line| parse_range(line))
            .filter(|range| range.section == section)
            .map(|range| (range.start, range.end))
            .collect();
        // The gap runs from where the linker says it starts to the next split.
        let gap_end = occupied.iter().map(|&(start, _)| start).filter(|&s| s > gap_start).min();
        let in_gap =
            |address: u32| address >= gap_start && gap_end.is_none_or(|gap_end| address < gap_end);
        let Some(symbol) = inputs
            .target_symbols
            .iter()
            .filter(|symbol| {
                symbol.section == section
                    && in_gap(symbol.address)
                    && linker_spelling(&diagnostic.symbol, &symbol.name)
            })
            .min_by_key(|symbol| symbol.address)
        else {
            continue;
        };
        if derived.iter().any(|range| {
            range.section == section && (range.start..range.end).contains(&symbol.address)
        }) {
            continue;
        }
        let body = target_blocks.get(unit).map(Vec::as_slice).unwrap_or_default();
        let fits = |start: u32, end: u32| {
            start % 4 == 0
                && start < end
                && in_gap(start)
                && gap_end.is_none_or(|gap_end| end <= gap_end)
                && !occupied.iter().any(|&(a, b)| start < b && a < end)
                && !derived.iter().any(|r| r.section == section && start < r.end && r.start < end)
                && keeps_seams(&inputs.seams, unit, &section, start, |at| {
                    starts_at(body, &section, at)
                        || derived.iter().any(|r| r.section == section && r.start == at)
                })
        };
        let mut bounds: Vec<(u32, u32)> = inputs
            .source_blocks
            .values()
            .flatten()
            .filter_map(|line| parse_range(line))
            .filter(|range| range.section == section)
            .map(|range| (range.start, range.end))
            .collect();
        bounds.sort_unstable();
        let source_lines = inputs
            .source_blocks
            .get(unit)
            .into_iter()
            .flatten()
            .filter(|line| parse_range(line).is_some_and(|range| range.section == section));
        for source_line in source_lines {
            let source = parse_range(source_line).unwrap();
            let Some(position) = bounds.iter().position(|&b| b == (source.start, source.end))
            else {
                continue;
            };
            // Initialized data needs its bytes compared before a layout
            // mapping can stand for the whole split (see `LayoutInterior`),
            // and `symbols.txt` has none: only BSS is mapped here.
            let mapping = matches!(section.as_str(), ".bss" | ".sbss" | ".sbss2")
                .then(|| {
                    index.map(&section, source.start, source.end, adjacent_span(&bounds, position))
                })
                .flatten();
            // The source split must hold the same object: by name, or as the
            // source symbol the mapping pairs with it.
            let by_name = inputs.source_symbols.iter().any(|candidate| {
                candidate.section == section
                    && (source.start..source.end).contains(&candidate.address)
                    && candidate.name == symbol.name
            });
            let paired = mapping.as_ref().is_some_and(|mapping| {
                mapping
                    .members
                    .iter()
                    .any(|&(_, target)| inputs.target_symbols[target].address == symbol.address)
            });
            if !by_name && !paired {
                continue;
            }
            let suffix = entry_suffix(source_line);
            let stated = parse_attributes(source_line)
                .iter()
                .find_map(|attribute| attribute.strip_prefix("align:")?.parse::<u32>().ok())
                .filter(|align| align.is_power_of_two());
            // As for a source-layout certificate: a delta that keeps the
            // split's alignment residue keeps its edges valid, and so do
            // aligned edges. Without a stated alignment, dtk's section default
            // stands in for the split's effective one; a member aligned beyond
            // it is not visible in `symbols.txt` sizes, and the build decides.
            let split_align = stated.unwrap_or(match section.as_str() {
                ".ctors" | ".dtors" | "extab" | "extabindex" => 4,
                _ => 8,
            });
            let mapped = mapping.filter(|mapping| {
                (mapping.start..mapping.end).contains(&symbol.address)
                    && (mapping.delta.rem_euclid(i64::from(split_align)) == 0
                        || (mapping.start % split_align == 0 && mapping.end % split_align == 0))
                    && fits(mapping.start, mapping.end)
            });
            let align = stated.unwrap_or(4).max(4);
            let (start, end, how, own_extent) = if let Some(mapping) = mapped {
                (
                    mapping.start,
                    mapping.end,
                    format!(
                        "the source split shifted by {:#x} between {} and {}",
                        mapping.delta, mapping.before.name, mapping.after.name
                    ),
                    false,
                )
            } else {
                let Some(size) = symbol.size else { break };
                let end = symbol.address.saturating_add(size).next_multiple_of(align);
                if !fits(symbol.address, end) {
                    break;
                }
                (symbol.address, end, format!("{}'s own extent", symbol.name), true)
            };
            derived.push(DerivedRange {
                line: entry_line(&section, start, end, &suffix),
                reason: format!(
                    "{section} {start:#010X}..{end:#010X} from {how}, for '{}' previously defined in {gap}",
                    diagnostic.symbol
                ),
                section: section.clone(),
                start,
                end,
                own_extent,
                paired: None,
            });
            break;
        }
    }
    coalesce(derived)
}

/// Whether a refusal is one that data ranges might cure: a duplicate left in
/// an unsplit gap, or a checksum that no longer matches because a section the
/// source object has sits in the gap beside the original.
fn feedable(refusal: &Refusal) -> bool {
    refusal.gap_duplicates().next().is_some() || refusal.kind == Kind::RetailMismatch
}

/// The sections whose target range relocation pairing may propose.
const PAIRED_SECTIONS: [&str; 7] =
    [".rodata", ".data", ".sdata", ".sdata2", ".bss", ".sbss", ".sbss2"];

/// The target ranges the unit's identical functions imply for sections it has
/// no range of, when its link produced the wrong bytes.
///
/// The compiled source object and the object extracted from the target are
/// read again here, as the failed link left them. Every function whose bytes
/// agree pairs each of its relocations with its twin's, and a source section
/// whose references all share one delta from its own offsets to target
/// addresses fills a single range there (see [`Pairing`]). Where the target's
/// bytes could be read they are equal to the source's.
fn derive_paired_ranges(
    inputs: &FeedbackInputs,
    name: &str,
    unit: &str,
    target_blocks: &IndexMap<String, Vec<String>>,
    refusal: &Refusal,
) -> Vec<DerivedRange> {
    if refusal.kind != Kind::RetailMismatch {
        return Vec::new();
    }
    let Some((base, target)) = inputs.objects.get(name) else { return Vec::new() };
    let (Ok(source), Ok(target)) = (
        Compiled::read(base, objdiff_core::diff::DiffSide::Base),
        Compiled::read(target, objdiff_core::diff::DiffSide::Target),
    ) else {
        return Vec::new();
    };
    let index = TargetIndex::new(&inputs.target_symbols);
    let pairing = crate::matching::relocation_pairing::pair(
        &source.object,
        &target.object,
        &index,
        inputs.image.as_ref(),
    );
    ranges_from_pairing(inputs, unit, target_blocks, &pairing)
}

fn ranges_from_pairing(
    inputs: &FeedbackInputs,
    unit: &str,
    target_blocks: &IndexMap<String, Vec<String>>,
    pairing: &Pairing,
) -> Vec<DerivedRange> {
    let body = target_blocks.get(unit).map(Vec::as_slice).unwrap_or_default();
    let occupied: Vec<_> = target_blocks
        .values()
        .flatten()
        .filter_map(|line| parse_range(line))
        .map(|range| (range.section, range.start, range.end))
        .collect();
    let mut derived: Vec<DerivedRange> = Vec::new();
    for paired in &pairing.sections {
        let section = paired.section.as_str();
        if !PAIRED_SECTIONS.contains(&section)
            || body.iter().filter_map(|line| parse_range(line)).any(|r| r.section == section)
        {
            continue;
        }
        let (start, end) = (paired.start, paired.end);
        let free = start % 4 == 0
            && start < end
            && !occupied.iter().any(|(s, a, b)| s == section && start < *b && *a < end)
            && keeps_seams(&inputs.seams, unit, section, start, |at| starts_at(body, section, at));
        if !free {
            continue;
        }
        let suffix = inputs
            .source_blocks
            .get(unit)
            .into_iter()
            .flatten()
            .find(|line| parse_range(line).is_some_and(|range| range.section == section))
            .map(|line| entry_suffix(line))
            .unwrap_or_default();
        let bytes = serde_json::to_value(paired.bytes)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_default();
        derived.push(DerivedRange {
            line: entry_line(section, start, end, &suffix),
            reason: format!(
                "{section} {start:#010X}..{end:#010X} paired through the relocations of {} \
                 identical functions ({} references, bytes {bytes}{})",
                pairing.functions,
                paired.references,
                if paired.reordered { ", constants paired one by one" } else { "" },
            ),
            section: section.to_string(),
            start,
            end,
            own_extent: false,
            paired: Some(paired.clone()),
        });
    }
    derived
}

/// Joins own-extent ranges that touch and share their attributes, so a unit
/// whose duplicates are adjacent objects gets one range per run of them.
fn coalesce(mut derived: Vec<DerivedRange>) -> Vec<DerivedRange> {
    derived.sort_by(|a, b| (&a.section, a.start).cmp(&(&b.section, b.start)));
    let mut joined: Vec<DerivedRange> = Vec::new();
    for range in derived {
        if let Some(last) = joined.last_mut()
            && last.own_extent
            && range.own_extent
            && last.section == range.section
            && last.end == range.start
            && entry_suffix(&last.line) == entry_suffix(&range.line)
        {
            last.end = range.end;
            last.line = entry_line(&last.section, last.start, last.end, &entry_suffix(&range.line));
            last.reason = format!("{}; {}", last.reason, range.reason);
            continue;
        }
        joined.push(range);
    }
    joined
}

/// The order dtk writes a unit's sections in. Others follow, in name order.
const SECTION_ORDER: [&str; 13] = [
    ".init",
    "extab",
    "extabindex",
    ".text",
    ".ctors",
    ".dtors",
    ".rodata",
    ".data",
    ".bss",
    ".sdata",
    ".sbss",
    ".sdata2",
    ".sbss2",
];

/// Adds a line among the unit's ranges of the same section in address order,
/// or else before the first range of a later section in dtk's order.
fn insert_line(body: &mut Vec<String>, line: String) {
    let rank = |section: &str| {
        SECTION_ORDER
            .iter()
            .position(|known| *known == section)
            .map_or((SECTION_ORDER.len(), section.to_string()), |index| (index, String::new()))
    };
    let Some(range) = parse_range(&line) else {
        body.push(line);
        return;
    };
    let same = |current: &String| parse_range(current).filter(|c| c.section == range.section);
    let at = body
        .iter()
        .position(|current| same(current).is_some_and(|c| c.start > range.start))
        .or_else(|| body.iter().rposition(|current| same(current).is_some()).map(|index| index + 1))
        .or_else(|| {
            body.iter().position(|current| {
                parse_range(current).is_some_and(|c| rank(&c.section) > rank(&range.section))
            })
        })
        .unwrap_or(body.len());
    body.insert(at, line);
}

/// Builds, then requires every named unit to be a real input to a real link.
///
/// `record`, when given, collects configured units this version has no split
/// for. Such a unit is declared `MatchingFor(<target>)` but appears in neither
/// the report nor `objdiff.json`, because dtk emits no rule for a unit it cannot
/// place — so nothing is compiled and nothing is linked. That is vacuous rather
/// than wrong (the units it happens to are empty ones, whose split in the source
/// version is a zero-length range), and it is a standing property of the
/// configuration rather than anything a candidate did. Failing the whole stage
/// on it would block work that has nothing to do with it.
pub fn validate(
    ctx: &BuildContext,
    names: &BTreeSet<String>,
    trial: bool,
    mut record: Option<&mut Vec<String>>,
) -> Result<Report> {
    let report = if trial { ctx.trial_build()? } else { ctx.build(None)? };
    let units = report.by_source_name();

    let objdiff = ObjdiffConfig::read(&ctx.root.join("objdiff.json"))?;
    let mut comparison: BTreeMap<&str, &ObjdiffUnit> = BTreeMap::new();
    for unit in &objdiff.units {
        let Some(source) = unit.metadata.source_path.as_deref() else { continue };
        let name = strip_source_root(source);
        if !names.contains(name) {
            continue;
        }
        if comparison.insert(name, unit).is_some() {
            bail!(ValidationError(format!("Ambiguous objdiff source unit: {name}")));
        }
    }

    let mut linked: BTreeMap<Option<String>, BTreeSet<String>> = BTreeMap::new();
    for name in names {
        let unit = comparison.get(name.as_str()).copied();
        if unit.is_none() && !units.contains_key(name.as_str()) {
            // No split for this version, so there is no object and no link to
            // check. Anything with a split reaches the checks below.
            if let Some(record) = record.as_mut() {
                record.push(name.clone());
            }
            continue;
        }
        let target_path = unit.and_then(|u| u.target_path.as_deref()).unwrap_or_default();
        let module = module_of(target_path, &ctx.target);

        // dtk's report covers the DOL; a REL's units are absent from it
        // entirely, so their completeness is a question it cannot answer. The
        // link check below is the half that actually tests "configured to link
        // from source", and it works for every module.
        if module.is_none()
            && units.get(name.as_str()).and_then(|u| u.metadata.complete) != Some(true)
        {
            bail!(ValidationError(format!("{name} was not configured to link from source")));
        }

        if !linked.contains_key(&module) {
            linked.insert(module.clone(), link_inputs(ctx, module.as_deref())?);
        }
        let object = unit.and_then(|u| u.base_path.as_deref()).unwrap_or_default();
        let artifact = match &module {
            None => "main.elf".to_string(),
            Some(module) => format!("{module}.plf"),
        };
        if object.is_empty() || !linked[&module].contains(&normalize(ctx, object)) {
            bail!(ValidationError(format!(
                "{name}'s compiled object is not an input to {artifact}"
            )));
        }
    }
    Ok(report)
}

/// The objects a module's link actually consumes, as Ninja reports them.
fn link_inputs(ctx: &BuildContext, module: Option<&str>) -> Result<BTreeSet<String>> {
    let artifact = match module {
        None => format!(
            "build/{}/{}",
            ctx.target,
            crate::project::config::dol_elf_name(&ctx.root, &ctx.target)
        ),
        Some(module) => format!("build/{}/{module}/{module}.plf", ctx.target),
    };
    let args = vec!["-t".to_string(), "inputs".to_string(), artifact.clone()];
    let output = ctx
        .run(&ctx.tools.ninja.clone(), &args, true, None)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("Failed to list the inputs of {artifact}"))?;
    Ok(output.lines().filter(|line| !line.trim().is_empty()).map(|p| normalize(ctx, p)).collect())
}

/// One spelling for a path, so a Ninja listing and an objdiff entry compare.
fn normalize(ctx: &BuildContext, path: &str) -> String {
    let joined = ctx.root.join(path.replace('\\', "/"));
    let text = joined.to_string_lossy().replace('\\', "/");
    // Collapse the `a/./b` and `a/b/../c` forms Ninja and objdiff each produce
    // in their own way, then case-fold where the filesystem does.
    let mut parts: Vec<&str> = Vec::new();
    for part in text.split('/') {
        match part {
            "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if cfg!(windows) { joined.to_lowercase() } else { joined }
}

/// The REL module a compiled object belongs to, or `None` for the DOL.
///
/// dtk puts a module's extracted objects under `build/<version>/<module>/obj/`
/// and the DOL's directly under `build/<version>/obj/`, so the path says which
/// link an object is destined for. A unit configured with
/// `MatchingFor(<version>)` may live in either, and the two are validated
/// against different artifacts.
pub fn module_of(target_path: &str, version: &str) -> Option<String> {
    let normalized = target_path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
    let index = parts.iter().position(|part| *part == version)?;
    let after = &parts[index + 1..];
    match after {
        [first, _rest @ ..] if after.len() > 1 && *first != "obj" => Some((*first).to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_under_the_version_root_belongs_to_the_dol() {
        assert_eq!(module_of("build/GM8P01_00/obj/MetroidPrime/main.o", "GM8P01_00"), None);
    }

    #[test]
    fn an_object_under_a_module_directory_names_that_module() {
        assert_eq!(
            module_of("build/GM8P01_00/NESPALemuP/obj/NESemu/emu.o", "GM8P01_00"),
            Some("NESPALemuP".to_string())
        );
    }

    #[test]
    fn a_windows_path_reads_the_same_as_a_posix_one() {
        assert_eq!(
            module_of("build\\GM8P01_00\\NESPALemuP\\obj\\emu.o", "GM8P01_00"),
            Some("NESPALemuP".to_string())
        );
    }

    #[test]
    fn a_path_that_does_not_mention_the_version_has_no_module() {
        assert_eq!(module_of("build/GM8E01_00/obj/main.o", "GM8P01_00"), None);
        assert_eq!(module_of("", "GM8P01_00"), None);
    }

    #[test]
    fn a_bare_version_directory_has_no_module() {
        assert_eq!(module_of("build/GM8P01_00/main.dol", "GM8P01_00"), None);
    }

    use crate::stages::refusal::{Kind, LinkerDiagnostic, LinkerDiagnosticKind};

    fn symbol(name: &str, address: u32, size: u32) -> LayoutSymbol {
        LayoutSymbol { name: name.into(), section: ".sbss".into(), address, size: Some(size) }
    }

    fn blocks(entries: &[(&str, &[(u32, u32)])]) -> IndexMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(unit, ranges)| {
                let mut lines = vec![entry_line(".text", 0x100, 0x200, "")];
                lines
                    .extend(ranges.iter().map(|&(start, end)| entry_line(".sbss", start, end, "")));
                ((*unit).to_string(), lines)
            })
            .collect()
    }

    /// `seq.c` holds two `.sbss` objects in the source; the target moved the
    /// section by 0x100 and has not split them, so they sit in a gap object.
    fn inputs(next_target: u32) -> FeedbackInputs {
        FeedbackInputs {
            source_symbols: vec![
                symbol("sPrevious", 0x1000, 4),
                symbol("seqFreeRoot", 0x1008, 4),
                symbol("seqPausedRoot", 0x100c, 4),
                symbol("sNext", 0x1018, 4),
            ],
            target_symbols: vec![
                symbol("sPrevious", 0x1100, 4),
                symbol("seqFreeRoot", 0x1108, 4),
                symbol("seqPausedRoot", 0x110c, 4),
                symbol("sNext", next_target, 4),
            ],
            source_blocks: blocks(&[
                ("prev.c", &[(0x1000, 0x1008)]),
                ("seq.c", &[(0x1008, 0x1018)]),
                ("next.c", &[(0x1018, 0x1020)]),
            ]),
            split_units: BTreeMap::new(),
            seams: Vec::new(),
            objects: BTreeMap::new(),
            image: None,
        }
    }

    fn duplicate(symbol: &str, gap: &str) -> Refusal {
        Refusal {
            kind: Kind::DuplicateSymbol,
            affected: Vec::new(),
            linker: vec![LinkerDiagnostic {
                kind: LinkerDiagnosticKind::MultiplyDefined,
                symbol: symbol.into(),
                object: Some("seq.o".into()),
                referenced_from: None,
                previously_defined_in: Some(gap.into()),
            }],
            command: None,
        }
    }

    #[test]
    fn a_gap_object_names_its_section_and_start() {
        assert_eq!(gap_object("auto_09_8041BEB8_sdata.o"), Some((".sdata".into(), 0x8041BEB8)));
        assert_eq!(gap_object("auto_11_80421AB8_sdata2.o"), Some((".sdata2".into(), 0x80421AB8)));
        assert_eq!(gap_object("THPDec.o"), None);
    }

    #[test]
    fn the_linker_spells_a_member_demangled() {
        assert!(linker_spelling(
            "CDolphinController::skTypeUnknown",
            "skTypeUnknown__18CDolphinController"
        ));
        assert!(linker_spelling("seqFreeRoot", "seqFreeRoot"));
        // A wrap inside the name rejoins with a space.
        assert!(linker_spelling(
            "CDolphinController::skType Unknown",
            "skTypeUnknown__18CDolphinController"
        ));
        assert!(!linker_spelling("seqFreeRoot", "seqPausedRoot"));
    }

    #[test]
    fn a_gap_duplicate_becomes_the_bracketed_source_split() {
        let target = blocks(&[
            ("prev.c", &[(0x1100, 0x1108)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1118, 0x1120)]),
        ]);
        let refusal = duplicate("seqFreeRoot", "auto_10_00001108_sbss.o");
        let derived = derive_ranges(&inputs(0x1118), "seq.c", &target, &refusal);
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(derived[0].line, entry_line(".sbss", 0x1108, 0x1118, ""));
        assert!(
            derived[0].reason.contains("between seqFreeRoot and sNext"),
            "{}",
            derived[0].reason
        );

        // Without a source split for the section there is nothing to feed back.
        assert!(derive_ranges(&inputs(0x1118), "other.c", &target, &refusal).is_empty());
        // A gap object of another section does not hold this symbol.
        let elsewhere = duplicate("seqFreeRoot", "auto_10_00001108_sdata.o");
        assert!(derive_ranges(&inputs(0x1118), "seq.c", &target, &elsewhere).is_empty());
    }

    #[test]
    fn without_a_uniform_delta_feedback_claims_only_the_symbol() {
        // The right anchor moved, so the whole source split cannot be mapped.
        let target = blocks(&[
            ("prev.c", &[(0x1100, 0x1108)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1120, 0x1128)]),
        ]);
        let refusal = duplicate("seqFreeRoot", "auto_10_00001108_sbss.o");
        let derived = derive_ranges(&inputs(0x1120), "seq.c", &target, &refusal);
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(derived[0].line, entry_line(".sbss", 0x1108, 0x110c, ""));
        // A range that would overlap an existing split is never proposed.
        let crowded = blocks(&[
            ("prev.c", &[(0x1100, 0x110a)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1120, 0x1128)]),
        ]);
        assert!(derive_ranges(&inputs(0x1120), "seq.c", &crowded, &refusal).is_empty());
    }

    #[test]
    fn only_a_duplicate_in_the_units_own_object_is_fed_back() {
        let target = blocks(&[
            ("prev.c", &[(0x1100, 0x1108)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1118, 0x1120)]),
        ]);
        let mut refusal = duplicate("seqFreeRoot", "auto_10_00001108_sbss.o");
        refusal.linker[0].object = Some("other.o".into());
        assert!(derive_ranges(&inputs(0x1118), "seq.c", &target, &refusal).is_empty());
        assert_eq!(file_stem("musyx/runtime/seq.c"), file_stem("seq.o"));
    }

    #[test]
    fn every_duplicate_of_a_refusal_is_derived_at_once_and_adjacent_extents_join() {
        // The right anchor moved, so each symbol is claimed by its own extent.
        let target = blocks(&[
            ("prev.c", &[(0x1100, 0x1108)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1120, 0x1128)]),
        ]);
        let mut refusal = duplicate("seqFreeRoot", "auto_10_00001108_sbss.o");
        let mut second = refusal.linker[0].clone();
        second.symbol = "seqPausedRoot".into();
        refusal.linker.push(second);
        let derived = derive_ranges(&inputs(0x1120), "seq.c", &target, &refusal);
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(derived[0].line, entry_line(".sbss", 0x1108, 0x1110, ""));
        assert!(derived[0].reason.contains("seqPausedRoot"), "{}", derived[0].reason);
    }

    #[test]
    fn a_mapping_that_starts_before_the_gap_falls_back_to_the_symbols_extent() {
        // prev.c already ends inside the mapped range's start, so the mapped
        // split does not fit; the symbol's own extent still does.
        let inputs = inputs(0x1118);
        let target = blocks(&[
            ("prev.c", &[(0x1100, 0x1104)]),
            ("mid.c", &[(0x1104, 0x1108)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1118, 0x1120)]),
        ]);
        // The gap the linker names starts after the symbol the mapping
        // would begin with.
        let refusal = duplicate("seqPausedRoot", "auto_10_0000110C_sbss.o");
        let derived = derive_ranges(&inputs, "seq.c", &target, &refusal);
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(derived[0].line, entry_line(".sbss", 0x110c, 0x1110, ""));
        assert!(derived[0].reason.contains("own extent"), "{}", derived[0].reason);
    }

    #[test]
    fn the_gap_ends_at_the_next_target_split() {
        // A target symbol of the same spelling past the gap is not the one.
        let mut inputs = inputs(0x1120);
        inputs.target_symbols.push(symbol("seqLater", 0x1130, 4));
        inputs.source_symbols.push(symbol("seqLater", 0x1010, 4));
        let target = blocks(&[
            ("prev.c", &[(0x1100, 0x1108)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1120, 0x1128)]),
        ]);
        let refusal = duplicate("seqLater", "auto_10_00001108_sbss.o");
        assert!(derive_ranges(&inputs, "seq.c", &target, &refusal).is_empty());
    }

    fn feedback_entry(unit: &str, split_unit: &str, lines: &[String]) -> Applied {
        Applied {
            unit: unit.into(),
            id: DATA_FEEDBACK.into(),
            units: vec![split_unit.into()],
            record: serde_json::to_value(DataFeedback {
                split_unit: split_unit.into(),
                data_lines: lines.to_vec(),
                pairing: Vec::new(),
            })
            .unwrap(),
        }
    }

    #[test]
    fn validation_requires_every_fed_back_line() {
        let added = entry_line(".sbss", 0x1108, 0x1118, "");
        let entry = feedback_entry("seq.c", "seq.c", std::slice::from_ref(&added));
        let accepted = [Candidate::new("seq.c")];
        let mut present = blocks(&[("seq.c", &[])]);
        present.get_mut("seq.c").unwrap().push(added.clone());
        check_feedback(&[&entry], &accepted, &present).unwrap();
        let missing = blocks(&[("seq.c", &[])]);
        assert!(check_feedback(&[&entry], &accepted, &missing).is_err());
        assert!(check_feedback(&[&entry], &[], &present).is_err(), "the unit was not accepted");
    }

    #[test]
    fn a_carried_line_that_no_longer_fits_is_left_out_whole() {
        let accepted = Splits {
            header: String::new(),
            blocks: IndexMap::from([
                ("seq.c".to_string(), vec![entry_line(".text", 0x100, 0x200, "")]),
                ("other.c".to_string(), vec![
                    entry_line(".text", 0x200, 0x300, ""),
                    entry_line(".sbss", 0x1110, 0x1120, ""),
                ]),
            ]),
        };
        let fits = DataFeedback {
            split_unit: "seq.c".into(),
            data_lines: vec![entry_line(".sbss", 0x1100, 0x1108, "")],
            pairing: Vec::new(),
        };
        let (staged, lines) = stage_lines(&accepted, &cyclic_units(&accepted.blocks), &[], vec![(
            "seq.c",
            fits.clone(),
        )]);
        assert_eq!(lines.len(), 1);
        assert!(staged.blocks["seq.c"].contains(&fits.data_lines[0]));
        let crowded = DataFeedback {
            split_unit: "seq.c".into(),
            data_lines: vec![
                entry_line(".sbss", 0x1100, 0x1108, ""),
                entry_line(".sbss", 0x1108, 0x1118, ""),
            ],
            pairing: Vec::new(),
        };
        let (staged, lines) =
            stage_lines(&accepted, &cyclic_units(&accepted.blocks), &[], vec![("seq.c", crowded)]);
        assert!(lines.is_empty());
        assert_eq!(staged.blocks, accepted.blocks, "nothing of the unit is staged");
    }

    #[test]
    fn a_feedback_line_follows_the_units_ranges_of_its_section() {
        let mut body =
            vec![entry_line(".text", 0x100, 0x200, ""), entry_line(".data", 0x300, 0x310, "")];
        insert_line(&mut body, entry_line(".text", 0x200, 0x210, ""));
        insert_line(&mut body, entry_line(".sbss", 0x400, 0x408, ""));
        // A new section goes where dtk writes it, not at the end.
        insert_line(&mut body, entry_line(".rodata", 0x280, 0x290, ""));
        insert_line(&mut body, entry_line(".sdata", 0x380, 0x388, ""));
        insert_line(&mut body, entry_line(".unusual", 0x500, 0x508, ""));
        insert_line(&mut body, entry_line(".text", 0x80, 0x100, ""));
        assert_eq!(body, [
            entry_line(".text", 0x80, 0x100, ""),
            entry_line(".text", 0x100, 0x200, ""),
            entry_line(".text", 0x200, 0x210, ""),
            entry_line(".rodata", 0x280, 0x290, ""),
            entry_line(".data", 0x300, 0x310, ""),
            entry_line(".sdata", 0x380, 0x388, ""),
            entry_line(".sbss", 0x400, 0x408, ""),
            entry_line(".unusual", 0x500, 0x508, ""),
        ]);
    }

    fn seam(address: u32, next_unit: &str) -> DataSeam {
        DataSeam { section: ".sbss".into(), address, next_unit: next_unit.into() }
    }

    #[test]
    fn feedback_never_starts_another_unit_at_a_certified_jump_table_seam() {
        let target = blocks(&[
            ("prev.c", &[(0x1100, 0x1108)]),
            ("seq.c", &[]),
            ("next.c", &[(0x1118, 0x1120)]),
        ]);
        let refusal = duplicate("seqFreeRoot", "auto_10_00001108_sbss.o");
        let mut inputs = inputs(0x1118);
        // prev.c's jump table ends at 0x1108 and another unit continues there.
        inputs.seams = vec![seam(0x1108, "other.c")];
        assert!(derive_ranges(&inputs, "seq.c", &target, &refusal).is_empty());
        // The expected unit may.
        inputs.seams = vec![seam(0x1108, "seq.c")];
        assert_eq!(derive_ranges(&inputs, "seq.c", &target, &refusal).len(), 1);
        // The expected unit must start at its seam before claiming elsewhere.
        inputs.seams = vec![seam(0x1104, "seq.c")];
        assert!(derive_ranges(&inputs, "seq.c", &target, &refusal).is_empty());
    }

    #[test]
    fn a_carried_line_at_another_units_seam_is_not_staged() {
        let accepted = Splits {
            header: String::new(),
            blocks: IndexMap::from([("seq.c".to_string(), vec![entry_line(
                ".text", 0x100, 0x200, "",
            )])]),
        };
        let carried = DataFeedback {
            split_unit: "seq.c".into(),
            data_lines: vec![entry_line(".sbss", 0x1108, 0x1118, "")],
            pairing: Vec::new(),
        };
        let baseline = cyclic_units(&accepted.blocks);
        let (_, lines) = stage_lines(&accepted, &baseline, &[seam(0x1108, "other.c")], vec![(
            "seq.c",
            carried.clone(),
        )]);
        assert!(lines.is_empty());
        let (_, lines) =
            stage_lines(&accepted, &baseline, &[seam(0x1108, "seq.c")], vec![("seq.c", carried)]);
        assert_eq!(lines.len(), 1);
    }

    fn paired(section: &str, start: u32, end: u32) -> PairedSection {
        PairedSection {
            section: section.into(),
            start,
            end,
            source_size: end - start,
            align: 8,
            references: 3,
            bytes: crate::matching::relocation_pairing::BytesCheck::Equal,
            reordered: false,
        }
    }

    fn pairing(sections: Vec<PairedSection>) -> Pairing {
        Pairing { functions: 4, sections, ..Pairing::default() }
    }

    #[test]
    fn a_paired_section_the_unit_lacks_becomes_its_range() {
        let target = blocks(&[("seq.c", &[]), ("next.c", &[(0x1200, 0x1208)])]);
        let found = ranges_from_pairing(
            &inputs(0x1100),
            "seq.c",
            &target,
            &pairing(vec![paired(".sdata2", 0x8042_1000, 0x8042_1010)]),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, entry_line(".sdata2", 0x8042_1000, 0x8042_1010, ""));
        assert!(found[0].reason.contains("4 identical functions"), "{}", found[0].reason);
        assert_eq!(found[0].paired.as_ref().map(|p| p.references), Some(3));
    }

    #[test]
    fn a_section_the_unit_already_has_is_left_alone() {
        let mut target = blocks(&[("seq.c", &[])]);
        target.get_mut("seq.c").unwrap().push(entry_line(".sdata2", 0x8042_2000, 0x8042_2010, ""));
        let found = ranges_from_pairing(
            &inputs(0x1100),
            "seq.c",
            &target,
            &pairing(vec![paired(".sdata2", 0x8042_1000, 0x8042_1010)]),
        );
        assert!(found.is_empty());
    }

    #[test]
    fn a_paired_range_overlapping_another_unit_is_not_proposed() {
        let mut target = blocks(&[("seq.c", &[]), ("next.c", &[])]);
        target.get_mut("next.c").unwrap().push(entry_line(".sdata2", 0x8042_1008, 0x8042_1020, ""));
        let found = ranges_from_pairing(
            &inputs(0x1100),
            "seq.c",
            &target,
            &pairing(vec![paired(".sdata2", 0x8042_1000, 0x8042_1010)]),
        );
        assert!(found.is_empty());
        // The same section in another section name is free.
        let found = ranges_from_pairing(
            &inputs(0x1100),
            "seq.c",
            &target,
            &pairing(vec![paired(".rodata", 0x8042_1000, 0x8042_1010)]),
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn only_data_sections_are_paired_into_ranges() {
        let target = blocks(&[("seq.c", &[])]);
        let found = ranges_from_pairing(
            &inputs(0x1100),
            "seq.c",
            &target,
            &pairing(vec![paired(".ctors", 0x8042_1000, 0x8042_1010)]),
        );
        assert!(found.is_empty());
    }

    #[test]
    fn a_range_keeps_the_source_splits_attributes() {
        let mut inputs = inputs(0x1100);
        inputs
            .source_blocks
            .get_mut("seq.c")
            .unwrap()
            .push(entry_line(".sdata2", 0x2000, 0x2010, "align:8"));
        let target = blocks(&[("seq.c", &[])]);
        let found = ranges_from_pairing(
            &inputs,
            "seq.c",
            &target,
            &pairing(vec![paired(".sdata2", 0x8042_1000, 0x8042_1010)]),
        );
        assert_eq!(found[0].line, entry_line(".sdata2", 0x8042_1000, 0x8042_1010, "align:8"));
    }

    #[test]
    fn a_retail_mismatch_is_fed_back_and_an_unrelated_failure_is_not() {
        let refusal =
            |kind| Refusal { kind, affected: Vec::new(), linker: Vec::new(), command: None };
        assert!(feedable(&refusal(Kind::RetailMismatch)));
        assert!(!feedable(&refusal(Kind::UndefinedSymbol)));
        assert!(!feedable(&refusal(Kind::SourceCompileError)));
    }
}
