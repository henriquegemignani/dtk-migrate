//! What a real migration actually recovered, measured against a later revision
//! of the same project.
//!
//! Every other test here asks whether the code does what it was written to do.
//! This one asks whether what it was written to do is worth doing. In July a
//! migration ran against Metroid Prime at `b65ad2a6`, from `GM8E01_00` to
//! `GM8P01_00`; it completed all four stages and published a retail-identical
//! DOL. Months of decompilation later, `ca286f45` says what the answers were.
//! Thirty-five translation units became source-linked in between, and those are
//! the question.
//!
//! The numbers below are what the tool did on the day. They are pinned so that
//! a change to the policy has to move them on purpose, in a diff somebody reads.
//! **They are not targets that have been met.** One unit of twenty-seven was
//! recovered exactly and three already-correct units were damaged; the plan this
//! fixture was built for exists to change both, and this test is how that change
//! will be believed.
//!
//! # The fixture
//!
//! `tests/fixtures/ownership/` holds the two revisions' `splits.txt`, the file
//! the run published, and which units each revision linked from source. Primary
//! data in the form the project writes it — not a saved copy of this scorer's
//! output, which would agree with itself forever. The manifest is rebuilt from
//! it here through the same function `benchmark prepare` uses.
//!
//! Splits in full, all 805 units, not just the interesting ones: whether a
//! claimed range belongs to somebody else is a question about the whole address
//! space, and a fixture missing the other 770 units would quietly reclassify
//! theft as unclaimed ground.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use dtk_migrate::{
    analysis::ownership_score::{Outcome, Scope},
    cli::benchmark::{
        Linkage, Manifest, Revision, RunFacts, Score, UnitScore, build_manifest, score,
    },
    project::splits::Splits,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Provenance {
    baseline_revision: String,
    baseline_splits_sha256: String,
    baseline_expected_retail_sha1: String,
    baseline_verified_dol_sha1: Option<String>,
    oracle_revision: String,
    oracle_splits_sha256: String,
    oracle_expected_retail_sha1: String,
    oracle_verified_dol_sha1: Option<String>,
    run_published_dol_sha1: String,
}

fn fixture(name: &str) -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ownership").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn manifest() -> Manifest {
    let linkage: Linkage = serde_json::from_str(&fixture("linkage.json")).unwrap();
    let provenance: Provenance = serde_json::from_str(&fixture("provenance.json")).unwrap();
    build_manifest(
        "GM8E01_00",
        "GM8P01_00",
        Revision {
            id: provenance.baseline_revision,
            splits_sha256: provenance.baseline_splits_sha256,
            configure_sha256: None,
            expected_retail_sha1: provenance.baseline_expected_retail_sha1,
            verified_dol_sha1: provenance.baseline_verified_dol_sha1,
        },
        &fixture("baseline.splits.txt"),
        Revision {
            id: provenance.oracle_revision,
            splits_sha256: provenance.oracle_splits_sha256,
            configure_sha256: None,
            expected_retail_sha1: provenance.oracle_expected_retail_sha1,
            verified_dol_sha1: provenance.oracle_verified_dol_sha1,
        },
        &fixture("oracle.splits.txt"),
        &linkage,
    )
    .expect("the fixture should describe a recall set")
}

/// The run reduced to what it changed. The stage evidence it also wrote runs to
/// megabytes and says nothing about ownership, so it is not committed; the
/// fields that need it — proposal recall, per-stage application — are exercised
/// by unit tests and by the opt-in run below.
fn run_facts() -> RunFacts {
    let provenance: Provenance = serde_json::from_str(&fixture("provenance.json")).unwrap();
    RunFacts::from_splits(
        fixture("run-id.txt").trim(),
        "GM8E01_00",
        "GM8P01_00",
        Splits::parse(&fixture("baseline.splits.txt")).unwrap().blocks,
        Splits::parse(&fixture("published.splits.txt")).unwrap().blocks,
    )
    .with_baseline_splits_sha256(provenance.baseline_splits_sha256)
    .with_published_dol_sha1(provenance.run_published_dol_sha1)
}

fn scored() -> Score { score(&manifest(), &run_facts()) }

fn by_name(result: &Score) -> BTreeMap<&str, &UnitScore> {
    result.units.iter().map(|row| (row.unit.as_str(), row)).collect()
}

#[test]
fn the_recall_set_is_the_thirty_five_units_the_later_work_proved() {
    let manifest = manifest();
    assert_eq!(manifest.recall_set.len(), 35, "{:?}", manifest.recall_set);
    // Derived from the two `configure.py` files, not from the splits: a unit
    // whose split moved is not necessarily a unit anyone proved.
    assert!(manifest.recall_set.contains(&"GuiSys/CGuiTableGroup.cpp".to_string()));
    assert!(
        manifest.units.len() > 700,
        "the oracle must be complete to answer about foreign ground"
    );
}

#[test]
fn the_run_started_where_the_fixture_says_it_did() {
    let result = scored();
    assert!(result.baseline_agrees, "the fixture's baseline is not the one the run was given");
    assert_eq!(result.published_retail_agrees, Some(true));
    assert_eq!(result.target, "GM8P01_00");
}

#[test]
fn the_published_outcome_for_the_twenty_seven_changed_units_is_one_exact_in_twenty_seven() {
    // The population the original analysis reported, reproduced field by field.
    // Twenty-seven of the thirty-five needed at least one section moved.
    let result = scored();
    let population = &result.populations["recall-changed/full"];
    assert_eq!(population.units, 27);
    assert_eq!(population.exact, 1, "only CGuiTableGroup came out whole");
    assert_eq!(population.partial + population.wrong, 8);
    assert_eq!(population.partial, 3);
    assert_eq!(population.wrong, 5);
    assert_eq!(population.unchanged, 18, "eighteen were never touched at all");
}

#[test]
fn the_published_outcome_for_the_twenty_five_changed_text_ranges_is_two_exact() {
    // The same run judged on code alone, which is a different population and a
    // different answer — two exact rather than one, because
    // CStreamAudioManager's `.text` is right and its `.bss` is missing.
    let result = scored();
    let population = &result.populations["recall-changed-code/code"];
    assert_eq!(population.units, 25);
    assert_eq!(population.exact, 2);
    assert_eq!(population.partial + population.wrong, 6);
    assert_eq!(population.unchanged, 17);
}

#[test]
fn a_unit_can_have_its_code_exactly_right_and_still_be_incomplete() {
    // CStreamAudioManager is the reason code and the whole body are scored
    // apart. Reporting only code would call this a finished recovery.
    let result = scored();
    let row = by_name(&result)["Kyoto/Audio/CStreamAudioManager.cpp"];
    assert_eq!(row.code_outcome, Outcome::Exact);
    assert_eq!(row.full_outcome, Outcome::Partial);
    assert!(row.code_exact && !row.full_exact);
    assert!(row.full.missed_bytes > 0, "the later .bss range is still unowned");
    assert_eq!(row.code.newly_wrong_bytes, 0, "nothing was taken from anyone");
}

#[test]
fn stopping_short_and_taking_a_neighbours_ground_are_not_the_same_failure() {
    // The distinction the whole benchmark turns on. CameraPitchVolume stopped
    // inside its own unit: incomplete, and safe. Platform reached past its
    // start into functions that strongly match CScriptSound: it claimed ground
    // that is not its, and the retail hash cannot see the difference because
    // both units are still linked from their extracted originals.
    let result = scored();
    let rows = by_name(&result);

    let short = rows["MetroidPrime/ScriptObjects/CScriptCameraPitchVolume.cpp"];
    assert_eq!(short.code_outcome, Outcome::Partial);
    assert_eq!(short.code.newly_wrong_bytes, 0);
    assert!(!short.regressed);

    let thief = rows["MetroidPrime/ScriptObjects/CScriptPlatform.cpp"];
    assert_eq!(thief.code_outcome, Outcome::Incorrect);
    assert_eq!(
        thief.code.newly_wrong_bytes, 0x2B4,
        "the accepted range starts 0x2B4 bytes before the one the later work established"
    );
    assert!(thief.regressed);
}

#[test]
fn the_three_already_correct_units_the_run_damaged_are_named() {
    // Controls: units the two revisions already agree about, which the run had
    // no business changing. Every one of them should come out unchanged. Three
    // did not, and a total alone could not tell "still the same three" from
    // "three different ones", so they are named.
    let result = scored();
    let controls = &result.populations["control/full"];
    assert_eq!(controls.regressed, 3, "{:?}", result.regressions);

    let damaged: BTreeSet<&str> = result
        .units
        .iter()
        .filter(|row| row.regressed && !row.needed_change && result.regressions.contains(&row.unit))
        .map(|row| row.unit.as_str())
        .collect();
    assert_eq!(
        damaged,
        BTreeSet::from([
            "GuiSys/CGuiCamera.cpp",
            "Kyoto/CFrameDelayedKiller.cpp",
            "MetroidPrime/Player/CPlayerState.cpp",
        ])
    );
    // Each took ground from somebody rather than merely running past the last
    // split, which is what makes them damage rather than an unsupported claim.
    for name in &damaged {
        assert!(by_name(&result)[name].full.newly_wrong_bytes > 0, "{name}");
    }
}

#[test]
fn every_unit_the_run_damaged_is_named_and_none_is_only_a_total() {
    let result = scored();
    // Eight against answers a build proved. This is the number the plan exists
    // to drive to zero; it is pinned so that driving it down is visible and
    // driving it up is a failing test rather than a footnote.
    assert_eq!(result.regressions.len(), 8, "{:?}", result.regressions);
    assert!(result.regressions.contains(&"MetroidPrime/ScriptObjects/CScriptPlatform.cpp".into()));
    // And seven more against oracle splits nothing has verified, reported
    // separately because an unverified split is not firm enough ground to fail
    // a run over.
    assert!(!result.unverified_regressions.is_empty());
    assert!(
        result.unverified_regressions.iter().all(|name| !result.regressions.contains(name)),
        "a unit belongs to one list or the other"
    );
}

#[test]
fn a_unit_whose_two_revisions_agree_and_which_nothing_touched_is_not_scored_as_a_miss() {
    // Most of the project is this: the run left it alone, correctly. If these
    // counted as misses the recall number would be dominated by units nobody
    // asked about.
    let result = scored();
    let controls = &result.populations["control/full"];
    assert!(controls.units > 400);
    // The five verdicts partition the population. `regressed` is not one of
    // them: it is a second question asked of the same units, which is why a
    // damaged control is counted in both `wrong` and `regressed`.
    assert_eq!(
        controls.units,
        controls.exact + controls.partial + controls.wrong + controls.unowned + controls.unchanged
    );
    assert!(controls.unchanged > 400, "{controls:?}");
}

#[test]
fn a_unit_with_several_ranges_in_one_section_is_compared_as_a_set() {
    // Prime's splits put some units in two `.text` ranges and `.bss` blocks
    // carrying `common`. Merging by min-start and max-end would swallow the
    // gap between them, so the manifest keeps the set and compares sets.
    let manifest = manifest();
    let multi: Vec<&String> = manifest
        .units
        .iter()
        .filter(|(_, truth)| {
            let mut per_section: BTreeMap<&str, usize> = BTreeMap::new();
            for entry in &truth.oracle.entries {
                *per_section.entry(entry.range.section.as_str()).or_default() += 1;
            }
            per_section.values().any(|count| *count > 1)
        })
        .map(|(name, _)| name)
        .collect();
    // Ten of them, every one an ordinary `.bss` range plus a common-BSS one.
    // Merging by min-start and max-end would swallow the gap between the two
    // and hand the unit an allocation it does not own.
    assert_eq!(multi.len(), 10, "{multi:?}");

    let common: Vec<&String> = manifest
        .units
        .iter()
        .filter(|(_, truth)| {
            truth.oracle.entries.iter().any(|entry| entry.attributes.contains("common"))
        })
        .map(|(name, _)| name)
        .collect();
    assert!(!common.is_empty(), "the fixture should contain BSS blocks carrying `common`");
    // And a body that keeps the addresses but drops the attribute is the same
    // ownership and a different block.
    let truth = &manifest.units[common[0]].oracle;
    let stripped = dtk_migrate::analysis::ownership_score::Body::new(
        truth
            .entries
            .iter()
            .cloned()
            .map(|mut entry| {
                entry.attributes.clear();
                entry
            })
            .collect(),
    );
    assert!(truth.same_ownership(&stripped));
    assert!(!truth.same_structure(&stripped));
}

#[test]
fn the_score_does_not_depend_on_where_the_oracle_is_kept() {
    // The weakest form of the guarantee that matters, and the cheapest to
    // check: scoring is a pure function of the manifest and the run. Anything
    // that made inference sensitive to the oracle would have to make this vary.
    let first = scored();
    let second = score(&manifest(), &run_facts());
    assert_eq!(serde_json::to_string(&first).unwrap(), serde_json::to_string(&second).unwrap());
}

#[test]
fn nothing_that_decides_anything_can_reach_the_oracle() {
    // The strong form. A benchmark whose oracle leaked into the matcher would
    // report excellent results and mean nothing, and no amount of care while
    // writing a policy prevents that later. What prevents it is the oracle
    // never being reachable from the modules that decide: the scorer and the
    // benchmark command are not `use`d by analysis, matching or any stage.
    //
    // Checked against the source tree rather than the type system because Rust
    // has no way to say "this module may not be imported by those".
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders: Vec<String> = Vec::new();
    for directory in ["analysis", "matching", "stages"] {
        walk(&root.join(directory), &mut |path: &PathBuf| {
            // The scorer itself lives under `analysis` and is allowed to know
            // its own name.
            if path.ends_with("ownership_score.rs") {
                return;
            }
            let text = std::fs::read_to_string(path).unwrap_or_default();
            for (number, line) in text.lines().enumerate() {
                // Declaring the module is how it exists at all; the question is
                // whether anything *uses* it.
                if line.trim_start().starts_with("pub mod ") {
                    continue;
                }
                for forbidden in ["ownership_score", "cli::benchmark"] {
                    if line.contains(forbidden) {
                        offenders.push(format!(
                            "{}:{} names {forbidden}",
                            path.display(),
                            number + 1
                        ));
                    }
                }
            }
        });
    }
    assert!(
        offenders.is_empty(),
        "the oracle must not be reachable from anything that decides: {offenders:#?}"
    );
}

fn walk(directory: &PathBuf, visit: &mut impl FnMut(&PathBuf)) {
    let Ok(entries) = std::fs::read_dir(directory) else { return };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, visit);
        } else if path.extension().is_some_and(|e| e == "rs") {
            visit(&path);
        }
    }
}

/// The whole run, including the evidence the fixture does not carry.
///
/// Point `DTK_MIGRATE_BENCHMARK_RUN` at the run directory to check the parts
/// that need its stage records — proposal recall, per-stage application,
/// verification. Without it this passes trivially, since there is nothing to
/// read.
#[test]
fn the_saved_run_agrees_with_the_fixture_distilled_from_it() {
    let Some(directory) = std::env::var_os("DTK_MIGRATE_BENCHMARK_RUN").map(PathBuf::from) else {
        eprintln!("skipped: set DTK_MIGRATE_BENCHMARK_RUN to the saved run directory");
        return;
    };
    let facts = dtk_migrate::cli::benchmark::read_run(&directory).expect("unreadable run");
    let manifest = manifest();
    let full = score(&manifest, &facts);
    let reduced = scored();

    assert!(full.baseline_agrees);
    assert_eq!(full.published_retail_agrees, Some(true));
    assert!(
        !full.proposal_history_complete,
        "the schema-1 run cannot reconstruct coordinator-only rediscovery rounds"
    );
    for key in ["recall-changed/full", "recall-changed-code/code", "control/full"] {
        let (a, b) = (&full.populations[key], &reduced.populations[key]);
        assert_eq!((a.units, a.exact, a.partial, a.wrong), (b.units, b.exact, b.partial, b.wrong));
        assert_eq!(a.regressed, b.regressed, "{key}");
    }
    assert_eq!(full.regressions, reduced.regressions);

    // And the parts only the full run can answer. Seven units had code-exact
    // proposals, but only four had the complete body. Of those four one was
    // selected and three were refused by builds. None is a ranking failure:
    // the run never selected a different body from the same decision that held
    // an exact alternative.
    let code = &full.populations["recall/code"];
    let whole = &full.populations["recall/full"];
    assert_eq!(code.proposal_recall, 7, "{code:?}");
    assert_eq!(code.selected_exact, 2, "{code:?}");
    assert_eq!(whole.proposal_recall, 4, "{whole:?}");
    assert_eq!(whole.selected_exact, 1, "{whole:?}");
    assert_eq!(code.ranking_failures, 0, "{code:?}");
    assert_eq!(whole.ranking_failures, 0, "{whole:?}");

    let rows = by_name(&full);
    let widget_verify = rows["GuiSys/CGuiWidget.cpp"]
        .stage_trace
        .iter()
        .find(|trace| trace.stage == "verify")
        .expect("CGuiWidget should have been handed to verification");
    assert_eq!(
        widget_verify.application,
        dtk_migrate::analysis::ownership_score::Application::BuildRefused
    );
    assert_eq!(widget_verify.reason.as_deref(), Some("ninja failed: exit status 1"));
    assert_eq!(
        rows["GuiSys/CGuiPane.cpp"].application,
        dtk_migrate::analysis::ownership_score::Application::BuildRefused
    );
    for name in ["Kyoto/Text/CColorOverrideInstruction.cpp", "Kyoto/Text/CPopStateInstruction.cpp"]
    {
        assert_eq!(
            rows[name].application,
            dtk_migrate::analysis::ownership_score::Application::BuildRefused,
            "{name}"
        );
    }
    assert_eq!(
        reduced.populations["recall/full"].proposal_recall, 0,
        "the fixture has no evidence"
    );
}

/// Kept honest: the fixture is the primary files, not this scorer's own output.
#[test]
fn the_fixture_is_readable_project_data_rather_than_a_saved_verdict() {
    let provenance: Provenance = serde_json::from_str(&fixture("provenance.json")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(fixture("baseline.splits.txt").as_bytes())),
        provenance.baseline_splits_sha256
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(fixture("oracle.splits.txt").as_bytes())),
        provenance.oracle_splits_sha256
    );
    let baseline = Splits::parse(&fixture("baseline.splits.txt")).unwrap();
    let oracle = Splits::parse(&fixture("oracle.splits.txt")).unwrap();
    let published = Splits::parse(&fixture("published.splits.txt")).unwrap();
    assert!(baseline.blocks.len() > 700);
    assert!(oracle.blocks.len() >= baseline.blocks.len());
    assert!(published.blocks.len() >= baseline.blocks.len());
    // The scorer's own conclusions are nowhere in it.
    for name in ["baseline.splits.txt", "oracle.splits.txt", "published.splits.txt"] {
        let text = fixture(name);
        assert!(!text.contains("regressed"), "{name} should carry no verdicts");
        assert!(!text.contains("newly_wrong"), "{name} should carry no verdicts");
    }
    let scopes = [Scope::Code, Scope::Everything];
    assert!(scopes.iter().any(|scope| scope.includes(".text")));
    assert!(!Scope::Code.includes(".bss") && Scope::Everything.includes(".bss"));
}
