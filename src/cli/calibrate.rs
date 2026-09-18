//! `dtk-migrate calibrate` — scoring the coverage policy against a version that
//! already has the answers.
//!
//! The policy decides which target ranges a source unit may claim. On a version
//! whose splits are already correct, that decision can be checked: hide part of
//! what the target knows, build the same alternatives a migration would, and
//! compare each one against the splits the project already has.
//!
//! The hiding is what makes it a test rather than a tautology, and it happens
//! to the analysed object rather than to the report — see [`crate::analysis::mask`].
//! A run therefore costs one full match per scenario, which is the price of
//! each scenario being a separate question.
//!
//! Three things are measured apart, because they fail apart:
//!
//! * **Boundary recovery.** Once the first choice is applied, does the unit own
//!   exactly the code ranges the oracle gives it — every section, both ends? A
//!   fragment sitting inside the right unit is not a recovered boundary, and
//!   neither is one of two sections coming out right. Counting either as one
//!   hides exactly the weakness worth finding.
//! * **Bytes.** How much of the unit would reach the right owner, how much
//!   nobody claims even then, how much went somewhere the oracle gives to
//!   someone else. Measured on what the unit would *own*, not on the proposal
//!   alone: a unit whose truncated split still holds most of itself has not
//!   missed the whole of itself.
//! * **Abstention.** A unit that produced nothing is in the denominator. A
//!   policy that answers rarely and correctly and a policy that answers often
//!   and correctly are not the same policy, and only the denominator says so.
//!
//! Units are split into a calibration half and a held-out half by a hash of the
//! name, so a policy tuned against the first can be reported against the second.
//! An incorrect assignment in either fails the command: the policy is supposed
//! to abstain, not guess.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    analysis::{
        coverage::{CoverageReport, CoverageUnit},
        mask::Scenario,
        ownership_score::{
            Blocks, Body, Oracle, Outcome, OwnerEffect, Scope, State, owner_effect,
            ownership_at_layout, range_state,
        },
    },
    matching,
    project::splits::Splits,
    stages::coverage::{
        EVIDENCE_SCHEMA, POLICY_VERSION,
        alternatives::{self, Alternative, parse_address},
        apply_alternative, offers_candidate,
    },
};

/// Calibration judges code only: an alternative never claims anything else, so
/// scoring a unit's data would read as permanently missed ground no policy was
/// ever asked about.
const SCOPE: Scope = Scope::Code;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The dtk-template project to read.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    /// The version whose progress is being carried over.
    #[arg(long)]
    pub source: String,
    /// The already-named version to score against.
    #[arg(long)]
    pub target: String,
    /// Which scenarios to run, repeatable. Every hiding scenario by default,
    /// each of which costs one full match.
    #[arg(long, value_enum)]
    pub scenario: Vec<Scenario>,
    /// A saved pre-change splits file to use as the oracle.
    ///
    /// Pass this when the target has already received the proposals being
    /// evaluated, so calibration cannot score its own output as an answer.
    #[arg(long)]
    pub oracle_splits: Option<PathBuf>,
    /// Where to write the result.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// One unit the policy got wrong, named.
///
/// A count alone cannot tell "the same known error is still there" from "that
/// one was fixed and a different one appeared", which is the only question
/// worth asking of an error total between two runs.
#[derive(Debug, Serialize)]
struct Fault {
    unit: String,
    partition: String,
    /// Which measures objected, in the order they are reported.
    kinds: Vec<&'static str>,
}

/// Everything wrong in one scenario, by name.
fn faults(records: &[Record]) -> Vec<Fault> {
    records
        .iter()
        .filter_map(|record| {
            let mut kinds = Vec::new();
            if record.outcome == Outcome::Incorrect {
                kinds.push("ownership");
            }
            if record.alternatives.iter().any(|range| range.state == State::Incorrect) {
                kinds.push("alternative");
            }
            if record.anchors.iter().any(|anchor| anchor.state == State::Incorrect) {
                kinds.push("anchor");
            }
            if record.owner_effects.iter().any(|effect| effect.lost_bytes > 0) {
                kinds.push("neighbour-lost");
            }
            if record.owner_effects.iter().any(|effect| effect.wrong_bytes > 0) {
                kinds.push("neighbour-wrong");
            }
            (!kinds.is_empty()).then(|| Fault {
                unit: record.name.clone(),
                partition: record.partition.clone(),
                kinds,
            })
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct ScoredRange {
    id: String,
    evidence: String,
    state: State,
}

#[derive(Debug, Serialize)]
struct ScoredAnchor {
    address: String,
    evidence: String,
    state: State,
}

#[derive(Debug, Serialize)]
struct Record {
    name: String,
    partition: String,
    outcome: Outcome,
    /// Whether the coverage stage would offer this unit a candidate at all. It
    /// only considers units with no block whatsoever, so a unit left holding a
    /// short or wrong split is skipped however good the evidence for fixing it
    /// — which is worth seeing next to the outcome, not buried in it.
    /// Whether the coverage stage would hand this unit to a trial, decided by
    /// the stage's own rule. Since Step 2 that is "it has an alternative left
    /// to try", not "it has no block" — a short split is now refinable, so
    /// nothing is excluded for being represented.
    offered: bool,
    /// Why the application refused the first choice, when it did.
    refused: Option<String>,
    /// Why nothing was proposed, in one word, when nothing was.
    disposition: String,
    selected_alternative: Option<Alternative>,
    /// The unit's code bytes, as the oracle has them.
    oracle_bytes: u32,
    /// Of those, the ones the unit already held before the proposal — a
    /// truncated split still owns most of itself.
    retained_bytes: u32,
    /// Of those, the ones the unit would hold once the first choice is applied.
    attributed_bytes: u32,
    /// Of those, the ones still unowned afterwards.
    missed_bytes: u32,
    /// Bytes the unit would hold that the oracle gives to another unit.
    wrong_bytes: u32,
    /// What the same transaction did to the neighbours it revises.
    owner_effects: Vec<OwnerEffect>,
    alternatives: Vec<ScoredRange>,
    anchors: Vec<ScoredAnchor>,
}

#[derive(Debug, Default, Serialize)]
struct Measures {
    /// Every unit the scenario hid and the oracle places, including the ones
    /// that produced nothing. Without those the accuracy of a policy that
    /// almost never answers is meaningless.
    units: usize,
    boundaries_exact: usize,
    boundaries_partial: usize,
    boundaries_incorrect: usize,
    boundaries_unowned: usize,
    abstained: usize,
    /// Proposals the application threw out, which are neither an answer nor an
    /// abstention.
    refused: usize,
    /// Neighbours revised by an accepted transaction, and what it cost them.
    owners_revised: usize,
    owners_left_exact: usize,
    owner_lost_bytes: u32,
    owner_wrong_bytes: u32,
    oracle_bytes: u32,
    retained_bytes: u32,
    attributed_bytes: u32,
    missed_bytes: u32,
    wrong_bytes: u32,
    ranges: usize,
    ranges_exact: usize,
    ranges_partial: usize,
    ranges_incorrect: usize,
    ranges_unknown: usize,
    anchors: usize,
    anchors_correct: usize,
    anchors_incorrect: usize,
    anchors_unknown: usize,
}

/// Splits units into two halves by a hash of the name, so a policy tuned on one
/// can be reported against the other.
fn partition(name: &str) -> &'static str {
    if Sha256::digest(name.as_bytes())[0] < 128 { "calibration" } else { "held-out" }
}

pub fn run(args: Args) -> Result<()> {
    let root = std::path::absolute(&args.project_root)?;
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| root.join("build").join(&args.target).join("coverage-calibration"));
    std::fs::create_dir_all(&output)?;

    let scenarios = match args.scenario.as_slice() {
        [] => Scenario::HIDING.to_vec(),
        chosen if chosen.contains(&Scenario::Nothing) => {
            bail!("Calibration needs a scenario that hides something; `nothing` hides nothing")
        }
        chosen => chosen.to_vec(),
    };

    let oracle_path = args
        .oracle_splits
        .clone()
        .unwrap_or_else(|| root.join("config").join(&args.target).join("splits.txt"));
    let oracle = Oracle::of(&Splits::read(&oracle_path)?.blocks);
    let source_blocks =
        Splits::read(&root.join("config").join(&args.source).join("splits.txt"))?.blocks;

    let mut all: BTreeMap<String, BTreeMap<String, Measures>> = BTreeMap::new();
    let mut faulty: BTreeMap<String, Vec<Fault>> = BTreeMap::new();
    for scenario in scenarios {
        let directory = output.join(scenario.as_str());
        std::fs::create_dir_all(&directory)?;
        let masked = evidence(&root, &args, &directory.join("evidence.json"), scenario)?;
        if masked.mask.scenario != scenario || masked.mask.hidden.is_empty() {
            bail!("Scenario {} hid nothing in {}", scenario.as_str(), args.target);
        }

        // The layout is the target's own functions, which masking does not
        // move; the oracle supplies the owners it no longer carries.
        let owners = ownership_at_layout(&masked.target_layout, &oracle);
        let records = score_all(&masked, &oracle, &source_blocks, &owners)?;
        let measures = summarize(&records);
        let wrong = faults(&records);

        let result = serde_json::json!({
            "schema": 4,
            "policy": masked.policy,
            "source": args.source,
            "target": args.target,
            "scenario": scenario.as_str(),
            "hidden_units": masked.mask.hidden.len(),
            "oracle_splits": oracle_path.display().to_string(),
            "partition": "sha256-first-byte-less-than-128",
            "incorrect": wrong,
            "records": records,
            "measures": measures,
        });
        std::fs::write(directory.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
        all.insert(scenario.as_str().to_string(), measures);
        faulty.insert(scenario.as_str().to_string(), wrong);
    }

    std::fs::write(output.join("result.md"), markdown(&all, &faulty))?;
    println!("{}", serde_json::to_string_pretty(&all)?);
    println!("\nEvidence: {}", output.display());
    let named: BTreeSet<&str> =
        faulty.values().flatten().map(|fault| fault.unit.as_str()).collect();
    if !named.is_empty() {
        bail!(
            "The coverage policy assigned ownership incorrectly for {}: {}. See {}",
            named.len(),
            named.into_iter().collect::<Vec<_>>().join(", "),
            output.display()
        );
    }
    Ok(())
}

/// Generates one coverage report with the named scenario's ownership hidden.
///
/// The target's symbol names are ignored whatever the scenario, because a
/// migration never has them: what varies here is only what is known about who
/// owns what.
fn evidence(root: &Path, args: &Args, path: &Path, scenario: Scenario) -> Result<CoverageReport> {
    let config = |version: &str| {
        typed_path::Utf8NativePathBuf::from(
            root.join("config").join(version).join("config.yml").to_string_lossy().into_owned(),
        )
    };
    let mut request = matching::Request::new(config(&args.source), config(&args.target));
    request.validate = true;
    request.mask = scenario;
    request.outputs.coverage = Some(path.to_path_buf());
    matching::run(&request)?;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let report: CoverageReport =
        serde_json::from_str(&text).context("Failed to parse the coverage evidence")?;
    if report.schema != EVIDENCE_SCHEMA || report.policy.version != POLICY_VERSION {
        bail!("The coverage evidence is not the schema or policy this tool understands");
    }
    Ok(report)
}

/// One record per unit the scenario hid, whether or not anything was proposed
/// for it.
fn score_all(
    masked: &CoverageReport,
    oracle: &Oracle,
    source_blocks: &Blocks,
    owners: &BTreeMap<(String, String), Option<String>>,
) -> Result<Vec<Record>> {
    let by_name: BTreeMap<String, &CoverageUnit> =
        masked.source_units.iter().map(|unit| (unit.name.clone(), unit)).collect();

    // Only units the oracle places and the scenario actually hid are being
    // asked anything.
    let mut asked: Vec<&CoverageUnit> = masked
        .source_units
        .iter()
        .filter(|unit| !unit.autogenerated)
        .filter(|unit| oracle.places(&unit.name) && masked.mask.hidden.contains(&unit.name))
        .collect();
    asked.sort_by(|a, b| a.name.cmp(&b.name));

    let expected: BTreeSet<String> =
        masked.source_units.iter().map(|unit| unit.name.clone()).collect();
    let observations = crate::analysis::ownership::ObservationIndex::load(
        masked.identifications.clone(),
        &masked.source,
        &masked.target,
        &expected,
    )?;
    Ok(asked
        .into_iter()
        .map(|unit| {
            // The splits the scenario left standing, which is what a migration
            // would have had in hand at this point.
            let found = alternatives::build(
                unit,
                &masked.mask.visible,
                &by_name,
                source_blocks,
                &observations,
            );
            score(unit, found, oracle, &masked.mask.visible, owners)
        })
        .collect())
}

fn score(
    unit: &CoverageUnit,
    found: Vec<Alternative>,
    oracle: &Oracle,
    visible: &Blocks,
    owners: &BTreeMap<(String, String), Option<String>>,
) -> Record {
    let name = unit.name.as_str();
    let mut scored = Vec::new();
    // One anchor can appear in several alternatives of the same kind; it should
    // be scored once.
    let mut unique: BTreeMap<(String, String, String), String> = BTreeMap::new();
    for alternative in &found {
        let start = parse_address(&alternative.start).unwrap_or(0);
        let end = parse_address(&alternative.end).unwrap_or(0);
        scored.push(ScoredRange {
            id: alternative.id.clone(),
            evidence: alternative.evidence.clone(),
            state: range_state(name, &alternative.section, start, end, oracle),
        });
        for anchor in &alternative.anchors {
            let section = anchor.get("section").and_then(|v| v.as_str()).unwrap_or_default();
            let address = anchor.get("target_address").and_then(|v| v.as_str()).unwrap_or_default();
            unique.insert(
                (alternative.evidence.clone(), section.to_string(), address.to_string()),
                address.to_string(),
            );
        }
    }
    let anchors = unique
        .into_iter()
        .map(|((evidence, section, address), _)| ScoredAnchor {
            state: match owners.get(&(section, address.clone())) {
                Some(Some(owner)) if owner == name => State::Exact,
                Some(Some(_)) => State::Incorrect,
                _ => State::Unknown,
            },
            address,
            evidence,
        })
        .collect();

    // What the unit would own once the first choice is applied — applied for
    // real, through the same code a trial uses. Modelling it as "the split it
    // has, plus the range proposed" would credit a tail-only proposal with
    // keeping a prefix that the application actually overwrites.
    //
    // Abstaining leaves the world alone, which is why a unit that proposes
    // nothing still owns whatever split the scenario left it.
    let selected = found.first();
    let mut blocks = visible.clone();
    let mut refused = None;
    if let Some(alternative) = selected {
        // A refused application is its own answer, and not the same answer as
        // abstaining: the policy did propose something, and the trial threw it
        // out. Scoring the unchanged world here would report the proposal as
        // having quietly succeeded at claiming nothing.
        if let Err(error) = apply_alternative(&mut blocks, name, alternative) {
            refused = Some(format!("{error:#}"));
            blocks = visible.clone();
        }
    }
    let before = Body::of(visible, name);
    let after = Body::of(&blocks, name);
    let measured = crate::analysis::ownership_score::ledger(name, oracle, &before, &after, SCOPE);

    // The outcome is about the unit, not about one of its ranges. A unit with
    // code in both `.init` and `.text` is not recovered because one of the two
    // came out right; per-range exactness is reported separately, below.
    let outcome = match selected {
        None => Outcome::Abstained,
        Some(_) if refused.is_some() => Outcome::Refused,
        _ => crate::analysis::ownership_score::outcome(
            &measured,
            &oracle.body(name).within(SCOPE),
            &after.within(SCOPE),
            true,
        ),
    };

    // An alternative that revises its neighbours is one transaction, and a
    // transaction is only as good as its worst part. Scoring the candidate
    // alone would let a range look recovered while the unit beside it was
    // quietly cut into the wrong shape.
    let owner_effects = selected
        .map(|alternative| {
            alternative
                .transaction
                .writes()
                .filter(|owner| *owner != name)
                .map(|owner| owner_effect(owner, oracle, visible, &blocks, SCOPE))
                .collect()
        })
        .unwrap_or_default();

    Record {
        name: name.to_string(),
        partition: partition(name).to_string(),
        outcome,
        offered: offers_candidate(&found),
        refused,
        disposition: alternatives::disposition(unit, &found, visible.contains_key(name)),
        oracle_bytes: measured.oracle_bytes,
        retained_bytes: measured.retained_bytes,
        attributed_bytes: measured.attributed_bytes,
        missed_bytes: measured.missed_bytes,
        wrong_bytes: measured.newly_wrong_bytes,
        owner_effects,
        selected_alternative: selected.cloned(),
        alternatives: scored,
        anchors,
    }
}

/// Measures per half of the population, and within each half, split by whether
/// the coverage stage would actually hand the unit to a trial.
///
/// The split is by the stage's own eligibility rule rather than a copy of it,
/// so that a change of rule cannot leave calibration measuring a population the
/// pipeline no longer has. Since represented units became refinable the
/// not-offered rows are exactly the abstentions: nothing is ruled out for
/// already holding a block.
fn summarize(records: &[Record]) -> BTreeMap<String, Measures> {
    let mut result = BTreeMap::new();
    for partition in ["calibration", "held-out"] {
        for (reach, offered) in [("offered", true), ("not-offered", false)] {
            let rows: Vec<&Record> = records
                .iter()
                .filter(|r| r.partition == partition && r.offered == offered)
                .collect();
            if rows.is_empty() {
                continue;
            }
            result.insert(format!("{partition}/{reach}"), measure(&rows));
        }
    }
    result
}

fn measure(rows: &[&Record]) -> Measures {
    let ranges: Vec<&ScoredRange> = rows.iter().flat_map(|r| &r.alternatives).collect();
    let anchors: Vec<&ScoredAnchor> = rows.iter().flat_map(|r| &r.anchors).collect();
    let effects: Vec<&OwnerEffect> = rows.iter().flat_map(|r| &r.owner_effects).collect();
    let outcomes = |state: Outcome| rows.iter().filter(|row| row.outcome == state).count();
    let count =
        |list: &[&ScoredRange], state: State| list.iter().filter(|r| r.state == state).count();
    let count_anchors =
        |list: &[&ScoredAnchor], state: State| list.iter().filter(|r| r.state == state).count();
    let bytes = |pick: fn(&Record) -> u32| rows.iter().map(|row| pick(row)).sum();
    Measures {
        units: rows.len(),
        boundaries_exact: outcomes(Outcome::Exact),
        boundaries_partial: outcomes(Outcome::Partial),
        boundaries_incorrect: outcomes(Outcome::Incorrect),
        boundaries_unowned: outcomes(Outcome::Unowned),
        abstained: outcomes(Outcome::Abstained),
        refused: outcomes(Outcome::Refused),
        owners_revised: effects.len(),
        owners_left_exact: effects.iter().filter(|effect| effect.exact).count(),
        owner_lost_bytes: effects.iter().map(|effect| effect.lost_bytes).sum(),
        owner_wrong_bytes: effects.iter().map(|effect| effect.wrong_bytes).sum(),
        oracle_bytes: bytes(|row| row.oracle_bytes),
        retained_bytes: bytes(|row| row.retained_bytes),
        attributed_bytes: bytes(|row| row.attributed_bytes),
        missed_bytes: bytes(|row| row.missed_bytes),
        wrong_bytes: bytes(|row| row.wrong_bytes),
        ranges: ranges.len(),
        ranges_exact: count(&ranges, State::Exact),
        ranges_partial: count(&ranges, State::Partial),
        ranges_incorrect: count(&ranges, State::Incorrect),
        ranges_unknown: count(&ranges, State::Unknown),
        anchors: anchors.len(),
        anchors_correct: count_anchors(&anchors, State::Exact),
        anchors_incorrect: count_anchors(&anchors, State::Incorrect),
        anchors_unknown: count_anchors(&anchors, State::Unknown),
    }
}

fn markdown(
    all: &BTreeMap<String, BTreeMap<String, Measures>>,
    faulty: &BTreeMap<String, Vec<Fault>>,
) -> String {
    let mut lines = vec![
        "# Coverage calibration".to_string(),
        String::new(),
        "Every unit a scenario hid is counted, including the ones that produced no candidate: a \
         policy that answers rarely and correctly is not the same as one that answers often and \
         correctly, and only the denominator says which this is."
            .to_string(),
        String::new(),
        "Judged on what each unit would own once its first choice is applied. *Exact* means that \
         is precisely the oracle's code ranges for it, in every section. *Partial* overlaps the \
         right unit with at least one boundary unresolved — the right neighbourhood, not a \
         recovered boundary. *Wrong* claims ground the oracle gives to another unit. *Unowned* \
         lands where the oracle says nothing, which is not an error."
            .to_string(),
        String::new(),
        "## Boundary recovery".to_string(),
        String::new(),
        "*Offered* rows are units the coverage stage would hand to a trial, decided by the \
         stage's own eligibility rule rather than a copy of it. Since represented units became \
         refinable, the *not-offered* rows are exactly the abstentions — nothing is ruled out \
         merely for already holding a block."
            .to_string(),
        String::new(),
        "| Scenario | Population | Units | Exact | Partial | Wrong | Unowned | Abstained | \
         Refused |"
            .to_string(),
        "|---|---|---:|---:|---:|---:|---:|---:|---:|".to_string(),
    ];
    for (scenario, by_partition) in all {
        for (name, value) in by_partition {
            lines.push(format!(
                "| {scenario} | {name} | {} | {} | {} | {} | {} | {} | {} |",
                value.units,
                value.boundaries_exact,
                value.boundaries_partial,
                value.boundaries_incorrect,
                value.boundaries_unowned,
                value.abstained,
                value.refused
            ));
        }
    }

    lines.extend([
        String::new(),
        "## Bytes".to_string(),
        String::new(),
        "Code bytes only, since code is all an alternative ever claims. *Retained* is what the \
         unit still owned before the proposal, so *attributed* minus *retained* is what the \
         policy actually won; *missed* is what nobody owns even after applying it."
            .to_string(),
        String::new(),
        "| Scenario | Population | Oracle | Retained | Attributed | Missed | Wrong |".to_string(),
        "|---|---|---:|---:|---:|---:|---:|".to_string(),
    ]);
    for (scenario, by_partition) in all {
        for (name, value) in by_partition {
            lines.push(format!(
                "| {scenario} | {name} | {} | {} | {} | {} | {} |",
                value.oracle_bytes,
                value.retained_bytes,
                value.attributed_bytes,
                value.missed_bytes,
                value.wrong_bytes
            ));
        }
    }

    lines.extend([
        String::new(),
        "## Revised neighbours".to_string(),
        String::new(),
        "An alternative that shrinks the unit beside it is one transaction, and is only as good \
         as its worst part. Any lost or wrongly taken byte here fails the run."
            .to_string(),
        String::new(),
        "| Scenario | Population | Revised | Left exact | Lost bytes | Wrong bytes |".to_string(),
        "|---|---|---:|---:|---:|---:|".to_string(),
    ]);
    for (scenario, by_partition) in all {
        for (name, value) in by_partition.iter().filter(|(_, m)| m.owners_revised > 0) {
            lines.push(format!(
                "| {scenario} | {name} | {} | {} | {} | {} |",
                value.owners_revised,
                value.owners_left_exact,
                value.owner_lost_bytes,
                value.owner_wrong_bytes
            ));
        }
    }

    lines.extend([
        String::new(),
        "## Incorrect assignments".to_string(),
        String::new(),
        "Named, not counted. A total that has not moved says nothing about whether the same \
         error is still here or a different one took its place, and only one of those is \
         progress."
            .to_string(),
        String::new(),
        "| Scenario | Unit | Partition | Objecting measures |".to_string(),
        "|---|---|---|---|".to_string(),
    ]);
    let mut any = false;
    for (scenario, found) in faulty {
        for fault in found {
            any = true;
            lines.push(format!(
                "| {scenario} | {} | {} | {} |",
                fault.unit,
                fault.partition,
                fault.kinds.join(", ")
            ));
        }
    }
    if !any {
        lines.push("| — | none | — | — |".to_string());
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;

    /// The interval arithmetic these tests rest on lives in
    /// [`crate::analysis::ownership_score`] and is tested there. What is tested
    /// here is the part calibration owns: applying a unit's first choice for
    /// real and reporting what that did.
    fn blocks(entries: &[(&str, u32, u32)]) -> Blocks {
        let mut map: Blocks = IndexMap::new();
        for (name, start, end) in entries {
            map.entry((*name).to_string())
                .or_default()
                .push(format!("\t{:11} start:0x{start:08X} end:0x{end:08X}", ".text"));
        }
        map
    }

    #[test]
    fn the_partition_is_stable_and_splits_the_population() {
        assert_eq!(partition("a.cpp"), partition("a.cpp"));
        let names: Vec<String> = (0..200).map(|i| format!("unit{i}.cpp")).collect();
        let calibration = names.iter().filter(|n| partition(n) == "calibration").count();
        assert!((40..160).contains(&calibration), "{calibration} of 200");
    }

    /// A unit carrying no evidence of its own: these tests score the ranges
    /// handed to [`score`], not the generators that found them.
    fn unit(name: &str, code_bytes: u64) -> CoverageUnit {
        CoverageUnit {
            name: name.to_string(),
            code_bytes,
            autogenerated: false,
            source_functions: 0,
            no_exact_target_body: 0,
            name_only_candidates: 0,
            ambiguous_exact_bodies: 0,
            anchors: Vec::new(),
            layout_shift_candidates: 0,
            layout_shift_anchors: Vec::new(),
            boundary_sequences: Vec::new(),
            adjacent_owner_transitions: Vec::new(),
            required_extracts: Vec::new(),
        }
    }

    fn line(section: &str, start: u32, end: u32) -> String {
        format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
    }

    /// A neighbour narrowed in the same transaction: its name, the range the
    /// proposal believed it held, and the range it keeps.
    type Narrowing = (&'static str, (u32, u32), (u32, u32));

    /// A proposal, before it is derived against the world it is scored in.
    ///
    /// The body is the part that matters: applying an alternative writes
    /// exactly `section start..end` for the unit, so a real one carrying a
    /// single range is a unit claiming a single range and nothing else.
    struct Claim {
        section: &'static str,
        start: u32,
        end: u32,
        neighbour: Option<Narrowing>,
    }

    fn alternative(section: &'static str, start: u32, end: u32) -> Claim {
        Claim { section, start, end, neighbour: None }
    }

    /// Derives each claim's transaction the way generation would: against
    /// the world the proposal was made in, which for a neighbour revision is
    /// whatever range the proposal believed that neighbour held.
    fn derive(name: &str, claims: Vec<Claim>, visible: &Blocks) -> Vec<Alternative> {
        claims
            .into_iter()
            .map(|claim| {
                let mut world = visible.clone();
                let mut others = Vec::new();
                if let Some((owner, original, revised)) = claim.neighbour {
                    world.insert(owner.to_string(), vec![line(".text", original.0, original.1)]);
                    others.push((owner.to_string(), vec![line(".text", revised.0, revised.1)]));
                }
                Alternative::uncertified(
                    name,
                    (claim.section, claim.start, claim.end),
                    vec![line(claim.section, claim.start, claim.end)],
                    others,
                    &world,
                )
                .unwrap()
            })
            .collect()
    }

    /// An oracle placing one unit in two code sections.
    fn two_sections() -> Blocks {
        let mut oracle: Blocks = IndexMap::new();
        oracle.insert("a.cpp".to_string(), vec![
            "\t.init        start:0x00001000 end:0x00001100".to_string(),
            "\t.text        start:0x00002000 end:0x00002400".to_string(),
        ]);
        oracle
    }

    fn scored(name: &str, found: Vec<Claim>, oracle: &Blocks, visible: &Blocks) -> Record {
        let found = derive(name, found, visible);
        score(&unit(name, 0), found, &Oracle::of(oracle), visible, &BTreeMap::new())
    }

    /// A unit whose evidence produced nothing, holding a split the scenario cut
    /// short: the bytes it still owns are not missing.
    fn truncated(found: Vec<Claim>) -> Record {
        let oracle = blocks(&[("CCollidableSphere.cpp", 0x1000, 0x2400)]);
        let visible = blocks(&[("CCollidableSphere.cpp", 0x1000, 0x2380)]);
        let found = derive("CCollidableSphere.cpp", found, &visible);
        score(
            &unit("CCollidableSphere.cpp", 0x1400),
            found,
            &Oracle::of(&oracle),
            &visible,
            &BTreeMap::new(),
        )
    }

    #[test]
    fn a_truncated_split_that_abstains_misses_only_what_was_cut() {
        let record = truncated(Vec::new());
        assert_eq!(record.outcome, Outcome::Abstained);
        assert_eq!(record.oracle_bytes, 0x1400);
        // The retained split still owns all but the tail, so reporting the
        // whole unit as missed would blame the policy for bytes nobody lost.
        assert_eq!(record.retained_bytes, 0x1380);
        assert_eq!(record.attributed_bytes, 0x1380);
        assert_eq!(record.missed_bytes, 0x80);
        assert_eq!(record.wrong_bytes, 0);
    }

    #[test]
    fn a_tail_only_body_is_refused_rather_than_dropping_the_prefix() {
        // Applying an alternative replaces the unit's body, so a body naming
        // only the missing tail would hand back the 0x1380 bytes the unit
        // already had. The generator no longer builds one; the application
        // refuses it regardless, which is the guarantee worth having.
        let record = truncated(vec![alternative(".text", 0x2380, 0x2400)]);
        assert_eq!(record.outcome, Outcome::Refused);
        // And nothing moved: the unit still holds what it came in with.
        assert_eq!(record.retained_bytes, 0x1380);
        assert_eq!(record.attributed_bytes, 0x1380);
        assert_eq!(record.missed_bytes, 0x80);
    }

    #[test]
    fn a_proposal_carrying_the_whole_unit_recovers_it() {
        let record = truncated(vec![alternative(".text", 0x1000, 0x2400)]);
        assert_eq!(record.outcome, Outcome::Exact);
        assert_eq!(record.attributed_bytes, 0x1400);
        assert_eq!(record.missed_bytes, 0);
    }

    #[test]
    fn holding_a_block_no_longer_decides_whether_a_unit_is_offered() {
        // A unit with an alternative is offered whether or not it already holds
        // a split — that is the Step 2 rule, and calibration reads it from the
        // stage rather than keeping its own copy.
        assert!(truncated(vec![alternative(".text", 0x1000, 0x2400)]).offered);
        // With nothing to try, it is not offered and not measured as an answer.
        assert!(!truncated(Vec::new()).offered);
        assert_eq!(truncated(Vec::new()).outcome, Outcome::Abstained);
    }

    #[test]
    fn getting_one_of_two_code_sections_right_is_not_an_exact_recovery() {
        let found = vec![alternative(".init", 0x1000, 0x1100)];
        let record = scored("a.cpp", found, &two_sections(), &IndexMap::new());
        // `.init` is precisely right and `.text` is missing entirely, which
        // leaves most of the unit unrecovered — the old measure called this
        // exact, because it only ever looked at the first range.
        assert_eq!(record.outcome, Outcome::Partial);
        assert_eq!(record.attributed_bytes, 0x100);
        assert_eq!(record.missed_bytes, 0x400);
    }

    #[test]
    fn a_body_omitting_a_section_the_unit_held_is_refused() {
        // A `.text` body that forgets the unit's `.init` split would cost it
        // that section outright, so the application will not have it.
        let mut visible: Blocks = IndexMap::new();
        visible.insert("a.cpp".to_string(), vec![
            "\t.init        start:0x00001000 end:0x00001100".to_string(),
        ]);
        let found = vec![alternative(".text", 0x2000, 0x2400)];
        let record = scored("a.cpp", found, &two_sections(), &visible);
        assert_eq!(record.outcome, Outcome::Refused);
        assert_eq!(record.retained_bytes, 0x100);
        assert_eq!(record.attributed_bytes, 0x100);
    }

    #[test]
    fn a_unit_with_two_ranges_in_one_section_needs_both() {
        let mut oracle: Blocks = IndexMap::new();
        oracle.insert("a.cpp".to_string(), vec![
            "\t.text        start:0x00002000 end:0x00002400".to_string(),
            "\t.text        start:0x00003000 end:0x00003200".to_string(),
        ]);
        let found = vec![alternative(".text", 0x2000, 0x2400)];
        let record = scored("a.cpp", found, &oracle, &IndexMap::new());
        assert_eq!(record.outcome, Outcome::Partial);
        assert_eq!(record.oracle_bytes, 0x600);
        assert_eq!(record.attributed_bytes, 0x400);
        assert_eq!(record.missed_bytes, 0x200);
    }

    #[test]
    fn a_unit_is_blamed_only_for_ground_its_proposal_adds() {
        // The split the unit came in with reaches into its neighbour. The
        // policy did not put it there and proposed nothing, so it is not
        // answerable for those bytes.
        let oracle = blocks(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]);
        let visible = blocks(&[("a.cpp", 0x1F00, 0x2080)]);
        let record = scored("a.cpp", Vec::new(), &oracle, &visible);
        assert_eq!(record.wrong_bytes, 0);
        assert_eq!(record.outcome, Outcome::Abstained);
    }

    /// The same alternative, but shrinking a neighbour to make room.
    fn with_revision(
        mut claim: Claim,
        unit: &'static str,
        original: (u32, u32),
        revised: (u32, u32),
    ) -> Claim {
        claim.neighbour = Some((unit, original, revised));
        claim
    }

    #[test]
    fn a_refused_application_is_recorded_rather_than_scored_as_unchanged() {
        // The revision names a range b.cpp does not have, so the application
        // throws the whole transaction out.
        let oracle = blocks(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]);
        let visible = blocks(&[("b.cpp", 0x2000, 0x3000)]);
        let found = vec![with_revision(
            alternative(".text", 0x1000, 0x2000),
            "b.cpp",
            (0, 0x99),
            (0, 0x50),
        )];
        let record = scored("a.cpp", found, &oracle, &visible);
        assert_eq!(record.outcome, Outcome::Refused);
        assert!(record.refused.is_some());
        // Nothing moved, so nothing is credited — least of all the range the
        // refused proposal named.
        assert_eq!(record.attributed_bytes, 0);
        assert!(record.owner_effects.iter().all(|effect| effect.lost_bytes == 0));
    }

    #[test]
    fn a_revised_neighbour_is_scored_alongside_the_candidate() {
        // b.cpp really starts at 0x2000, and the transaction takes 0x100 of it
        // for a.cpp — ground the oracle says is b.cpp's.
        let oracle = blocks(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]);
        let visible = blocks(&[("b.cpp", 0x2000, 0x3000)]);
        let found = vec![with_revision(
            alternative(".text", 0x1000, 0x2100),
            "b.cpp",
            (0x2000, 0x3000),
            (0x2100, 0x3000),
        )];
        let record = scored("a.cpp", found, &oracle, &visible);
        let [effect] = &record.owner_effects[..] else { panic!("{:?}", record.owner_effects) };
        assert_eq!(effect.unit, "b.cpp");
        assert_eq!(effect.lost_bytes, 0x100);
        assert!(!effect.exact);
        // And the candidate is independently wrong for having taken it.
        assert_eq!(record.outcome, Outcome::Incorrect);
    }

    #[test]
    fn claiming_a_neighbours_ground_is_incorrect_whatever_else_it_gets_right() {
        let oracle = blocks(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]);
        let found = vec![alternative(".text", 0x1000, 0x2100)];
        let record = scored("a.cpp", found, &oracle, &IndexMap::new());
        assert_eq!(record.outcome, Outcome::Incorrect);
        assert_eq!(record.attributed_bytes, 0x1000);
        assert_eq!(record.wrong_bytes, 0x100);
    }
}
