//! The cascade: accepting one unit's range is what makes the next unit's
//! evidence exist.
//!
//! This is the behaviour the coverage stage was rebuilt around, and it cannot be
//! seen from either end alone. A unit test can show that `build` produces an
//! alternative from evidence; a run against a real project shows a number
//! changing. Neither shows that accepting A is what *caused* B to become
//! eligible, that B's freshly generated proposal survives worker integration and
//! publication, or that A can then be extended again without losing what it
//! already owned.
//!
//! The evidence is injected rather than derived, because deriving it needs two
//! analysable binaries and nothing else here does. Everything the stage decides
//! — the trials, the ownership gates, batching, publication, resume — is the
//! real thing.
//!
//! Built in steps, each of which must hold before the next means anything:
//!
//! 1. The injected evidence offers exactly `A.cpp` and nothing else.
//! 2. Once `A.cpp` holds a block, it offers `B.cpp`.
//! 3. Once both hold blocks, it offers `A.cpp` again, extended.
//!
//! Only then is it worth running the coordinator over it, since a cascade test
//! that silently proposes nothing looks exactly like one that works.
//!
//! # The coordinator run
//!
//! The rest of the file drives the real pipeline over that evidence in the
//! miniature dtk-template project from [`common`]: preparation, worker batches
//! in their own workspaces, integration, rediscovery between rounds,
//! publication, and resume. `DTK_MIGRATE_EVIDENCE_DIR` holds `0.json`,
//! `1.json`, `2.json` — the three worlds above, serialized from
//! [`evidence_for`].

mod common;

use std::collections::BTreeMap;

use common::{Blocks, Fixture, Layout, describe, line, names};
use dtk_migrate::{
    analysis::{
        coverage::CoverageReport,
        coverage_fixture::{anchor, report, unit, withheld},
    },
    stages::coverage::alternatives,
};
use indexmap::IndexMap;

/// Where each unit's code sits in the fixture's target, and what the evidence
/// says about it at each stage of the cascade.
///
/// `A.cpp` owns 0x1000..0x1200 in the end, but its evidence arrives in two
/// instalments: the first half is matched immediately, the second only once
/// `B.cpp` beside it has a boundary to be bounded by.
const A_FIRST: (u32, u32) = (0x8000_1000, 0x8000_1100);
const A_REST: (u32, u32) = (0x8000_1100, 0x8000_1200);
const B_RANGE: (u32, u32) = (0x8000_1200, 0x8000_1300);

fn blocks(entries: &[(&str, u32, u32)]) -> Blocks {
    let mut map: Blocks = IndexMap::new();
    for (name, start, end) in entries {
        map.entry((*name).to_string()).or_default().push(line(".text", *start, *end));
    }
    map
}

/// The evidence the fixture's provider hands over when the target's splits name
/// `named` units.
///
/// This is the whole of the cascade's logic, and it is deliberately blunt: the
/// point is not that the rule is clever but that the evidence *changes* when
/// ownership does, which is what the coordinator has to notice.
///
/// Both units and all three anchors are in every report, at the same sizes
/// throughout. What a round changes is only whether an anchor qualifies. That
/// distinction is the point: the source is a fixed body of code being
/// progressively explained, so a summary reporting more source in round two
/// than round one would be reporting a bug. If the units appeared as their
/// evidence did, every such bug would look like correct behaviour here.
fn evidence_for(named: usize) -> CoverageReport {
    let a_one = anchor("A_one", A_FIRST.0, A_FIRST.1);
    let a_two = anchor("A_two", A_REST.0, A_REST.1);
    let b_one = anchor("B_one", B_RANGE.0, B_RANGE.1);
    let units = match named {
        // Nothing owns anything yet, so nothing else has a boundary to be
        // bounded by: only A.cpp's first half is placeable.
        0 => vec![
            unit("A.cpp", vec![a_one, withheld(a_two, "no following boundary")]),
            unit("B.cpp", vec![withheld(b_one, "no preceding boundary")]),
        ],
        // A.cpp has landed, which is what gives B.cpp its lower bound.
        1 => vec![
            unit("A.cpp", vec![a_one, withheld(a_two, "no following boundary")]),
            unit("B.cpp", vec![b_one]),
        ],
        // Both hold blocks, so A.cpp's tail is bounded on both sides at last.
        _ => vec![unit("A.cpp", vec![a_one, a_two]), unit("B.cpp", vec![b_one])],
    };
    report("NTSC", "PAL", units)
}

/// Every unit the policy would offer a candidate for, given what is owned.
fn offered(named: usize, owned: &Blocks) -> BTreeMap<String, Vec<String>> {
    let evidence = evidence_for(named);
    let expected = evidence.source_units.iter().map(|unit| unit.name.clone()).collect();
    let observations = dtk_migrate::analysis::ownership::ObservationIndex::load(
        evidence.identifications.clone(),
        &evidence.source,
        &evidence.target,
        &expected,
    )
    .unwrap();
    let by_name: BTreeMap<String, &dtk_migrate::analysis::coverage::CoverageUnit> =
        evidence.source_units.iter().map(|u| (u.name.clone(), u)).collect();
    evidence
        .source_units
        .iter()
        .filter_map(|source| {
            let found =
                alternatives::build(source, owned, &by_name, &IndexMap::new(), &observations);
            found.first().map(|first| (source.name.clone(), first.lines.clone()))
        })
        .collect()
}

#[test]
fn before_anything_lands_only_a_is_offered() {
    let found = offered(0, &IndexMap::new());
    assert_eq!(found.keys().collect::<Vec<_>>(), ["A.cpp"], "{found:#?}");
    assert_eq!(found["A.cpp"], [line(".text", A_FIRST.0, A_FIRST.1)]);
}

#[test]
fn accepting_a_is_what_makes_b_eligible() {
    let owned = blocks(&[("A.cpp", A_FIRST.0, A_FIRST.1)]);
    // The same world, but with A.cpp's block in it.
    let before = offered(0, &IndexMap::new());
    let after = offered(1, &owned);

    assert!(!before.contains_key("B.cpp"), "B.cpp had no evidence before A.cpp landed");
    assert_eq!(after.keys().collect::<Vec<_>>(), ["B.cpp"], "{after:#?}");
    assert_eq!(after["B.cpp"], [line(".text", B_RANGE.0, B_RANGE.1)]);
    // And A.cpp is not offered again for ground it already holds.
    assert!(!after.contains_key("A.cpp"));
}

#[test]
fn accepting_b_is_what_lets_a_be_extended() {
    let owned = blocks(&[("A.cpp", A_FIRST.0, A_FIRST.1), ("B.cpp", B_RANGE.0, B_RANGE.1)]);
    let found = offered(2, &owned);

    assert_eq!(found.keys().collect::<Vec<_>>(), ["A.cpp"], "{found:#?}");
    // One enlarged range, not the tail alone: the body an alternative writes
    // replaces the block, so a tail-only body would drop the half A.cpp has.
    assert_eq!(found["A.cpp"], [line(".text", A_FIRST.0, A_REST.1)]);
}

#[test]
fn the_cascade_settles_once_everything_is_owned() {
    // The end state: nothing further is offered, so a coordinator looping on
    // rediscovery has a reason to stop that is not the round limit.
    let owned = blocks(&[("A.cpp", A_FIRST.0, A_REST.1), ("B.cpp", B_RANGE.0, B_RANGE.1)]);
    assert!(offered(2, &owned).is_empty());
}

// ---------------------------------------------------------------------------
// The project fixture the coordinator runs against.
// ---------------------------------------------------------------------------

/// The source version's splits, at its own addresses and its own sizes.
///
/// Only `stunted_splits` reads these — the cascade's alternatives come from
/// anchors, not from the source layout — but a unit whose source counterpart is
/// missing is audited differently, so the fixture supplies both.
fn source_splits(include_unlinked: bool) -> String {
    let mut splits = format!(
        "{}A.cpp:
{}

B.cpp:
{}
",
        common::SPLITS_HEADER,
        line(".text", 0x8000_0400, 0x8000_0600),
        line(".text", 0x8000_0600, 0x8000_0700)
    );
    if include_unlinked {
        splits.push_str(&format!(
            "
Unlinked.cpp:
{}
",
            line(".text", 0x8000_2000, 0x8000_2100)
        ));
    }
    splits
}

/// The project over `worlds`, linking only `A.cpp` and `B.cpp`.
fn build_fixture(worlds: &[CoverageReport]) -> Option<Fixture> {
    let include_unlinked = worlds
        .first()
        .is_some_and(|world| world.source_units.iter().any(|unit| unit.name == "Unlinked.cpp"));
    common::build(&Layout {
        units: vec!["A.cpp".into(), "B.cpp".into()],
        source_splits: source_splits(include_unlinked),
        // The target owns nothing yet. Everything it ends up owning, the run
        // put there. Written in exactly the form the writer renders — a file
        // that is merely equivalent would be rewritten the first time a stage
        // saves it, and a test asking whether a no-op run left the project
        // alone would be reading its own formatting back.
        target_splits: format!(
            "{}
",
            common::SPLITS_HEADER.trim_end()
        ),
        worlds: worlds.iter().cloned().map(Some).collect(),
        discover: None,
    })
}

/// The three worlds of the cascade, as files.
fn cascade_worlds() -> Vec<CoverageReport> { (0..=2).map(evidence_for).collect() }

/// The same units, with nothing the policy will believe about any of them.
fn nothing_believable() -> Vec<CoverageReport> {
    let units = || {
        vec![
            unit("A.cpp", vec![
                withheld(anchor("A_one", A_FIRST.0, A_FIRST.1), "no boundary either side"),
                withheld(anchor("A_two", A_REST.0, A_REST.1), "no boundary either side"),
            ]),
            unit("B.cpp", vec![withheld(
                anchor("B_one", B_RANGE.0, B_RANGE.1),
                "no boundary either side",
            )]),
        ]
    };
    (0..=2).map(|_| report("NTSC", "PAL", units())).collect()
}

/// Evidence for a unit the project does not link from an extracted object.
///
/// The proposal is perfectly well-formed and the build succeeds; what fails is
/// the check that the range was proved about the extracted original rather than
/// about compiled source. That is a rejection the stage is supposed to make, so
/// it is the honest way to produce a run whose every candidate is refused.
fn only_an_unlinked_unit() -> Vec<CoverageReport> {
    let units = || {
        vec![
            unit("A.cpp", vec![
                withheld(anchor("A_one", A_FIRST.0, A_FIRST.1), "no boundary either side"),
                withheld(anchor("A_two", A_REST.0, A_REST.1), "no boundary either side"),
            ]),
            unit("B.cpp", vec![withheld(
                anchor("B_one", B_RANGE.0, B_RANGE.1),
                "no boundary either side",
            )]),
            unit("Unlinked.cpp", vec![anchor("U_one", 0x8000_2000, 0x8000_2100)]),
        ]
    };
    (0..=3).map(|_| report("NTSC", "PAL", units())).collect()
}

fn independent_worlds() -> Vec<CoverageReport> {
    let units = || {
        vec![
            unit("A.cpp", vec![anchor("A_one", A_FIRST.0, A_FIRST.1)]),
            unit("B.cpp", vec![anchor("B_one", B_RANGE.0, B_RANGE.1)]),
        ]
    };
    (0..=2).map(|_| report("NTSC", "PAL", units())).collect()
}

fn independent_fixture(units: &[&str]) -> Option<Fixture> {
    let source_splits = format!(
        "{}{}",
        common::SPLITS_HEADER,
        units
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let start = 0x8000_4000 + (i as u32) * 0x200;
                format!("{name}:\n{}\n\n", line(".text", start, start + 0x100))
            })
            .collect::<String>()
    );
    let worlds = (0..=units.len())
        .map(|_| {
            report(
                "NTSC",
                "PAL",
                units
                    .iter()
                    .enumerate()
                    .map(|(i, name)| {
                        let start = 0x8000_1000 + (i as u32) * 0x200;
                        unit(name, vec![anchor(&format!("member_{i}"), start, start + 0x100)])
                    })
                    .collect(),
            )
        })
        .map(Some)
        .collect();
    common::build(&Layout {
        units: units.iter().map(|name| (*name).to_string()).collect(),
        source_splits,
        target_splits: format!("{}\n", common::SPLITS_HEADER.trim_end()),
        worlds,
        discover: None,
    })
}

#[test]
fn a_worker_proves_independent_first_choices_in_one_build() {
    let units = ["A.cpp", "B.cpp", "C.cpp", "D.cpp", "E.cpp"];
    let Some(fixture) = independent_fixture(&units) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };

    // Five candidates, one worker and a batch ceiling of two produces at
    // least one multi-candidate batch under the normal queue-sizing policy.
    let output = fixture.migrate_with_settings("1", "2", &[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");
    let job = fixture.json(&format!("{stage}/jobs/00000/result.json"));
    assert_eq!(names(&job["accepted"]).len(), 2, "{job:#}");
    assert!(job["events"].as_array().unwrap().iter().any(|event| {
        event["status"] == "selection-union-validated"
            && event["reason"].as_str().is_some_and(|reason| reason.starts_with("2 selections"))
    }));
    let result = fixture.json(&format!("{stage}/result.json"));
    assert_eq!(names(&result["accepted"]).len(), 5, "{result:#}");
}

#[test]
fn the_coordinator_sends_failed_union_halves_to_different_lanes() {
    let units = ["A.cpp", "B.cpp", "C.cpp", "D.cpp", "E.cpp", "F.cpp", "G.cpp", "H.cpp", "I.cpp"];
    let Some(fixture) = independent_fixture(&units) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate_with_settings("2", "40", &[], &[
        "DTK_MIGRATE_FIXTURE_REJECT_WORKER_COMBINATION",
        "A.cpp,B.cpp",
    ]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let trials = format!("build/dtk-migrate/runs/{id}/coverage/jobs/00000/trials");
    let left = fixture.read(&format!("{trials}/root-L/lane.txt"));
    let right = fixture.read(&format!("{trials}/root-R/lane.txt"));
    assert!(!left.is_empty() && !right.is_empty(), "missing split trial lane records");
    assert_ne!(left, right, "the coordinator should use both idle build lanes");
    let job = fixture.json(&format!("build/dtk-migrate/runs/{id}/coverage/jobs/00000/result.json"));
    assert_eq!(names(&job["accepted"]).len(), 2, "{job:#}");
}

#[test]
fn the_coordinator_follows_the_cascade_it_was_never_told_about() {
    let Some(fixture) = build_fixture(&cascade_worlds()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    // Preparation saw one candidate, because at that point one is all the
    // evidence supported.
    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    assert_eq!(names(&prepared["candidates"]), ["A.cpp"], "{prepared:#}");

    // And the run finished holding two. B.cpp was never prepared, never
    // batched, and never handed to a worker: the only way it can be here is
    // that accepting A.cpp made its evidence exist.
    let result = fixture.json(&format!("{stage}/result.json"));
    let mut accepted = names(&result["accepted"]);
    accepted.sort();
    assert_eq!(accepted, ["A.cpp", "B.cpp"], "{result:#}");
    assert!(names(&result["deferred"]).is_empty(), "{result:#}");

    // Each acceptance in the order the rounds reached it: the worker's A.cpp,
    // integration re-proving it, B.cpp once A.cpp had landed, then A.cpp again
    // extended into the gap B.cpp's boundary opened up.
    let taken: Vec<String> = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["status"] == "accepted")
        .map(|event| event["unit"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(taken, ["A.cpp", "A.cpp", "B.cpp", "A.cpp"], "{result:#}");

    // The final accepted entry intentionally keeps only A's last, extended
    // proposal. Audits still need the worker's earlier half-range to measure
    // proposal recall, so both candidate versions are retained separately.
    let a_bodies: Vec<Vec<&str>> = result["offered"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|candidate| candidate["name"] == "A.cpp")
        .flat_map(|candidate| candidate["evidence"]["alternatives"].as_array().unwrap())
        .map(|alternative| {
            alternative["lines"]
                .as_array()
                .unwrap()
                .iter()
                .map(|line| line.as_str().unwrap())
                .collect()
        })
        .collect();
    let first = line(".text", A_FIRST.0, A_FIRST.1);
    let complete = line(".text", A_FIRST.0, A_REST.1);
    assert!(a_bodies.contains(&vec![first.as_str()]));
    assert!(a_bodies.contains(&vec![complete.as_str()]));

    // Twice, and no more: the third look found nothing, which is why the run
    // stopped for a reason rather than on the round budget.
    let rediscovered = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["status"] == "rediscovered")
        .count();
    assert_eq!(rediscovered, 2, "{result:#}");
    assert_eq!(result["retry"]["regenerated"], 2, "{result:#}");
    assert_eq!(result["retry"]["budget_exhausted"], 0, "{result:#}");
    assert!(result["retry"]["attempted"].as_u64().unwrap() >= 4, "{result:#}");
    assert!(
        !result["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["status"] == "rediscovery-limit-reached"),
        "{result:#}"
    );
}

#[test]
fn what_the_cascade_settled_on_is_what_gets_published() {
    let Some(fixture) = build_fixture(&cascade_worlds()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    // The exact ranges, in the owner's checkout. A.cpp holds one merged range
    // rather than two fragments, because an alternative replaces a block whole.
    let published = fixture.published_splits();
    assert_eq!(published.keys().collect::<Vec<_>>(), ["A.cpp", "B.cpp"], "{published:#?}");
    assert_eq!(published["A.cpp"], [line(".text", A_FIRST.0, A_REST.1)]);
    assert_eq!(published["B.cpp"], [line(".text", B_RANGE.0, B_RANGE.1)]);

    // Two translation units gained a home, neither of them a refinement of
    // ground the project already had, and the gain is measured against where
    // the stage started rather than against the round before it.
    let summary = fixture.json(&format!("{stage}/coverage.json"));
    assert_eq!(summary["source_units"], 2);
    assert_eq!(summary["baseline_represented"], 0);
    assert_eq!(summary["final_represented"], 2);
    assert_eq!(summary["newly_supported_units"], 2);
    assert_eq!(summary["refined_units"], 0, "A.cpp was extended, but it started with nothing");
    assert_eq!(
        summary["newly_assigned_code_bytes"],
        A_REST.1 - A_FIRST.0 + (B_RANGE.1 - B_RANGE.0),
        "{summary:#}"
    );

    // The proposal and the selection have to be a pair. A.cpp was accepted
    // twice, and the id recorded has to name an alternative of the proposal
    // that is stored beside it — the extended one, not the half-range the
    // worker proved.
    let result = fixture.json(&format!("{stage}/result.json"));
    let stored = result["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["name"] == "A.cpp")
        .expect("A.cpp should be accepted");
    let chosen = result["selections"]["A.cpp"].as_str().expect("A.cpp should have a selection");
    let alternative = stored["evidence"]["alternatives"]
        .as_array()
        .unwrap()
        .iter()
        .find(|alternative| alternative["id"] == chosen)
        .unwrap_or_else(|| panic!("the stored proposal does not contain {chosen}: {result:#}"));
    let lines: Vec<&str> =
        alternative["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect();
    assert_eq!(lines, [line(".text", A_FIRST.0, A_REST.1)]);
    assert_eq!(summary["selected"]["A.cpp"]["id"], chosen);

    let journal = fixture.json(&format!("build/dtk-migrate/runs/{id}/publication.json"));
    assert_eq!(journal["status"], "published", "{journal:#}");
    let changed: Vec<&String> = journal["changes"].as_object().unwrap().keys().collect();
    assert_eq!(changed, ["config/PAL/splits.txt"], "only the splits should have moved");
}

#[test]
fn a_run_interrupted_after_its_workers_finished_does_not_repeat_their_builds() {
    let Some(fixture) = build_fixture(&cascade_worlds()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let interrupted = fixture.migrate(&[], &["DTK_MIGRATE_FIXTURE_ABORT", "1"]);
    assert!(!interrupted.status.success(), "{}", describe(&interrupted));
    let id = fixture.run_id();

    // The workers got as far as proving A.cpp and writing it down.
    let job = fixture.json(&format!("build/dtk-migrate/runs/{id}/coverage/jobs/00000/result.json"));
    assert_eq!(names(&job["accepted"]), ["A.cpp"], "{job:#}");
    let before = fixture.worker_builds(&id);
    assert!(!before.is_empty(), "the workers should have built something");
    assert_eq!(fixture.published_splits().len(), 0, "nothing should have been published yet");

    let resumed = fixture.resume(&id);
    assert!(resumed.status.success(), "{}", describe(&resumed));
    assert!(
        String::from_utf8_lossy(&resumed.stderr).contains("reused from a previous run"),
        "{}",
        describe(&resumed)
    );
    assert_eq!(
        fixture.worker_builds(&id),
        before,
        "a resumed run should reuse the worker results, not rebuild them"
    );

    // And the resumed half finished the cascade the interrupted half started.
    let published = fixture.published_splits();
    assert_eq!(published["A.cpp"], [line(".text", A_FIRST.0, A_REST.1)]);
    assert_eq!(published["B.cpp"], [line(".text", B_RANGE.0, B_RANGE.1)]);
}

#[test]
fn a_stage_with_nothing_to_offer_finishes_instead_of_failing() {
    let Some(fixture) = build_fixture(&nothing_believable()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let output = fixture.migrate(&[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    assert!(names(&prepared["candidates"]).is_empty(), "{prepared:#}");

    // A successful result with nothing in it, and a baseline that was measured
    // rather than assumed: the stage still built the project and recorded what
    // it found, which is what makes "no progress" a claim and not a gap.
    let result = fixture.json(&format!("{stage}/result.json"));
    assert!(names(&result["accepted"]).is_empty(), "{result:#}");
    assert!(names(&result["deferred"]).is_empty(), "{result:#}");
    assert_eq!(result["final_measures"], result["baseline"], "{result:#}");
    assert!(result["dol_sha1"].as_str().is_some_and(|hash| !hash.is_empty()), "{result:#}");
    assert_eq!(fixture.read("config/PAL/splits.txt"), before, "the project should be untouched");

    let journal = fixture.json(&format!("build/dtk-migrate/runs/{id}/publication.json"));
    assert_eq!(journal["status"], "published", "{journal:#}");
    assert!(journal["changes"].as_object().unwrap().is_empty(), "{journal:#}");
}

#[test]
fn a_stage_whose_every_candidate_is_refused_finishes_with_them_deferred() {
    let Some(fixture) = build_fixture(&only_an_unlinked_unit()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let output = fixture.migrate(&[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    assert_eq!(names(&prepared["candidates"]), ["Unlinked.cpp"], "{prepared:#}");

    // Refused, and deferred rather than condemned — and the run that contains
    // that refusal is a successful run.
    let result = fixture.json(&format!("{stage}/result.json"));
    assert!(names(&result["accepted"]).is_empty(), "{result:#}");
    assert_eq!(names(&result["deferred"]), ["Unlinked.cpp"], "{result:#}");
    assert!(result["retry"]["attempted"].as_u64().unwrap() >= 1, "{result:#}");
    let rejection = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["unit"] == "Unlinked.cpp" && event["status"] == "rejected")
        .unwrap_or_else(|| panic!("no recorded reason for the refusal: {result:#}"));
    assert!(
        rejection["reason"].as_str().unwrap().contains("source-linkage-violation"),
        "{rejection:#}"
    );
    assert_eq!(result["final_measures"], result["baseline"], "{result:#}");
    assert_eq!(fixture.read("config/PAL/splits.txt"), before, "a refusal leaves nothing behind");

    let summary = fixture.json(&format!("{stage}/coverage.json"));
    assert_eq!(summary["newly_supported_units"], 0);
    assert_eq!(summary["newly_assigned_code_bytes"], 0);
    assert_eq!(summary["dispositions"]["Unlinked.cpp"], "build-failure");
}

#[test]
fn a_failed_worker_union_is_bisected_without_replaying_every_selection() {
    let Some(fixture) = build_fixture(&independent_worlds()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[], &["DTK_MIGRATE_FIXTURE_REJECT_COMBINATION", "A.cpp,B.cpp"]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    // Each candidate passed in its own worker. Their union is the only state
    // the fixture rejects, so integration must keep the ordered left half and
    // isolate the right half rather than abandoning or replaying both.
    for job in ["00000", "00001"] {
        let result = fixture.json(&format!("{stage}/jobs/{job}/result.json"));
        assert_eq!(names(&result["accepted"]).len(), 1, "{result:#}");
        assert!(names(&result["deferred"]).is_empty(), "{result:#}");
    }
    let result = fixture.json(&format!("{stage}/result.json"));
    assert_eq!(names(&result["accepted"]), ["A.cpp"], "{result:#}");
    assert_eq!(names(&result["deferred"]), ["B.cpp"], "{result:#}");

    let published = fixture.published_splits();
    assert_eq!(published.keys().collect::<Vec<_>>(), ["A.cpp"], "{published:#?}");
    assert_eq!(published["A.cpp"], [line(".text", A_FIRST.0, A_FIRST.1)]);

    // The full union, the passing half and the failing leaf are visible in the
    // integration log. A serial fallback would repeat both candidates after
    // the failed union and therefore require another successful B build.
    let log = fixture.read(&format!("{stage}/integration-evidence/build.log"));
    assert!(log.contains("fixture: rejected combined ownership"), "{log}");
    assert!(
        result["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| { event["unit"] == "B.cpp" && event["status"] == "rejected" }),
        "{result:#}"
    );
}
