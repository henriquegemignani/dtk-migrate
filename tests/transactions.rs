//! Atomic ownership transactions, through the real coordinator.
//!
//! A candidate whose code occupies the head of its neighbour's split can only
//! be placed by moving the boundary between them: the candidate gains exactly
//! what the neighbour gives up. That is one change to two units, and every
//! part of the pipeline has to treat it as one — the worker that proves it,
//! the scheduler that decides which lane sees it, integration, a later
//! refinement that supersedes it for the candidate while its effect on the
//! neighbour stands, publication, resume, and `--only`.
//!
//! The target, in address order:
//!
//! | unit | before the run | after |
//! |---|---|---|
//! | `P.cpp` | `0x1000..0x1100` | unchanged |
//! | `A.cpp` | nothing | `.text 0x1100..0x1300`, then `.init 0x0100..0x0180` |
//! | `B.cpp` | `0x1100..0x1500` (too wide) | `0x1300..0x1500` |
//! | `Q.cpp` | nothing | `0x1500..0x1600` |
//!
//! `Q.cpp` claims ground that touches `B.cpp`, so a transaction for either one
//! depends on the other's neighbour. They must be decided in one lane.

mod common;

use common::{Blocks, Fixture, Layout, describe, line, names};
use dtk_migrate::analysis::{
    coverage::CoverageReport,
    coverage_fixture::{anchor, next_prefix_transition, owned_by, report, run, unit, withheld},
};

const P: (u32, u32) = (0x8000_1000, 0x8000_1100);
const CLAIM: (u32, u32) = (0x8000_1100, 0x8000_1300);
const B_ORIGINAL: (u32, u32) = (0x8000_1100, 0x8000_1500);
const B_KEPT: (u32, u32) = (0x8000_1300, 0x8000_1500);
const A_INIT: (u32, u32) = (0x8000_0100, 0x8000_0180);
const Q: (u32, u32) = (0x8000_1500, 0x8000_1600);

/// What the matcher says when the target names `named` units.
///
/// The adjacent-owner transition is offered in every world: once `A.cpp` has
/// taken the head of `B.cpp`, the neighbour no longer holds the range the
/// transition names, and the policy drops it on its own. `A.cpp`'s `.init`
/// function only becomes believable once `A.cpp` holds a block — the later
/// refinement that supersedes the joint transaction for `A.cpp`.
fn evidence_for(named: usize) -> CoverageReport {
    let a_text = owned_by(run("A_text", CLAIM.0, CLAIM.1, 0x40), "B.cpp");
    let b = owned_by(run("B", B_KEPT.0, B_KEPT.1, 0x80), "B.cpp");
    let mut a_init = anchor("A_init", A_INIT.0, A_INIT.1);
    a_init.section = ".init".into();
    if named < 3 {
        a_init = withheld(a_init, "no block to extend yet");
    }
    let mut a = unit("A.cpp", a_text.iter().cloned().chain([a_init]).collect());
    a.adjacent_owner_transitions =
        vec![next_prefix_transition("P.cpp", "B.cpp", CLAIM, B_ORIGINAL, &a_text, &b)];
    report("NTSC", "PAL", vec![
        unit("P.cpp", run("P", P.0, P.1, 0x100)),
        a,
        unit("B.cpp", b),
        unit("Q.cpp", run("Q", Q.0, Q.1, 0x80)),
    ])
}

fn blocks(entries: &[(&str, &[String])]) -> Blocks {
    entries.iter().map(|(name, lines)| ((*name).to_string(), lines.to_vec())).collect()
}

fn fixture() -> Option<Fixture> {
    let source = blocks(&[
        ("P.cpp", &[line(".text", 0x8000_0400, 0x8000_0500)]),
        ("A.cpp", &[
            line(".init", 0x8000_0000, 0x8000_0080),
            line(".text", 0x8000_0500, 0x8000_0700),
        ]),
        ("B.cpp", &[line(".text", 0x8000_0700, 0x8000_0900)]),
        ("Q.cpp", &[line(".text", 0x8000_0900, 0x8000_0A00)]),
    ]);
    let target = baseline_target();
    common::build(&Layout {
        units: ["P.cpp", "A.cpp", "B.cpp", "Q.cpp"].map(String::from).to_vec(),
        source_splits: common::render(&source),
        target_splits: common::render(&target),
        worlds: (0..=4).map(|named| (named >= 2).then(|| evidence_for(named))).collect(),
    })
}

fn baseline_target() -> Blocks {
    blocks(&[
        ("P.cpp", &[line(".text", P.0, P.1)]),
        ("B.cpp", &[line(".text", B_ORIGINAL.0, B_ORIGINAL.1)]),
    ])
}

fn expected_final() -> Blocks {
    blocks(&[
        ("P.cpp", &[line(".text", P.0, P.1)]),
        ("A.cpp", &[line(".text", CLAIM.0, CLAIM.1), line(".init", A_INIT.0, A_INIT.1)]),
        ("B.cpp", &[line(".text", B_KEPT.0, B_KEPT.1)]),
        ("Q.cpp", &[line(".text", Q.0, Q.1)]),
    ])
}

fn units_of(entry: &serde_json::Value) -> Vec<&str> {
    entry["units"].as_array().unwrap().iter().map(|u| u.as_str().unwrap()).collect()
}

#[test]
fn a_candidate_and_the_neighbour_it_narrows_are_published_as_one_transaction() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    // Both units moved, and nothing else did. P.cpp is where it was, B.cpp
    // gave up exactly what A.cpp took, and A.cpp's later `.init` refinement
    // did not undo the narrowing it was not part of.
    let published = fixture.published_splits();
    let mut expected = expected_final();
    for name in published.keys() {
        assert_eq!(published[name], expected.shift_remove(name).unwrap_or_default(), "{name}");
    }
    assert!(expected.is_empty(), "missing from the published splits: {expected:#?}");

    // The history integration applied: the joint transaction first, and a
    // later one for A.cpp alone that supersedes it for A.cpp. The selection is
    // the last of them, and the whole chain is what publication replayed.
    let result = fixture.json(&format!("{stage}/result.json"));
    let applied = result["applied"].as_array().unwrap();
    let for_a: Vec<&serde_json::Value> =
        applied.iter().filter(|entry| entry["unit"] == "A.cpp").collect();
    assert_eq!(for_a.len(), 2, "{result:#}");
    assert_eq!(units_of(for_a[0]), ["A.cpp", "B.cpp"]);
    assert_eq!(units_of(for_a[1]), ["A.cpp"]);
    assert_eq!(result["selections"]["A.cpp"], for_a[1]["id"]);
    // B.cpp was changed only as A.cpp's neighbour, and belongs to this stage
    // for the rest of the run all the same.
    assert!(!names(&result["accepted"]).contains(&"B.cpp".to_string()));

    let summary = fixture.json(&format!("{stage}/coverage.json"));
    let joint = summary["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|transaction| transaction["members"].as_array().unwrap().len() == 2)
        .unwrap_or_else(|| panic!("no two-unit transaction reported: {summary:#}"));
    assert_eq!(joint["candidate"], "A.cpp");
    assert_eq!(joint["net_bytes"], 0, "a boundary moved; nothing was newly owned");
    assert_eq!(joint["superseded"], true);
    assert_eq!(summary["dispositions"]["B.cpp"], "revised-by-transaction");
    assert_eq!(summary["dispositions"]["A.cpp"], "accepted");

    // A.cpp and Q.cpp both depend on B.cpp, so one lane decided both, one
    // after the other: which of them was decided first cannot depend on which
    // of two lanes happened to finish first.
    let jobs = std::fs::read_dir(fixture.root.join(format!("{stage}/jobs"))).unwrap().count();
    assert_eq!(jobs, 1, "conflicting candidates were split across lanes");
    let job = fixture.json(&format!("{stage}/jobs/00000/job.json"));
    let mut batched = names(&job["candidates"]);
    batched.sort();
    assert_eq!(batched, ["A.cpp", "Q.cpp"], "{job:#}");

    let journal = fixture.json(&format!("build/dtk-migrate/runs/{id}/publication.json"));
    assert_eq!(journal["status"], "published", "{journal:#}");
    let changed: Vec<&String> = journal["changes"].as_object().unwrap().keys().collect();
    assert_eq!(changed, ["config/PAL/splits.txt"]);
}

#[test]
fn a_resumed_run_publishes_the_same_transactions_without_rebuilding_its_workers() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let interrupted = fixture.migrate(&[], &["DTK_MIGRATE_FIXTURE_ABORT", "1"]);
    assert!(!interrupted.status.success(), "{}", describe(&interrupted));
    assert_eq!(fixture.read("config/PAL/splits.txt"), before, "nothing published yet");
    let id = fixture.run_id();
    let builds = fixture.worker_builds(&id);
    assert!(!builds.is_empty(), "the workers should have built something");

    let resumed = fixture.resume(&id);
    assert!(resumed.status.success(), "{}", describe(&resumed));
    assert_eq!(fixture.worker_builds(&id), builds, "worker results should be reused");
    let published = fixture.published_splits();
    for (name, body) in expected_final() {
        assert_eq!(published.get(&name), Some(&body), "{name}");
    }
}

#[test]
fn only_refuses_a_transaction_that_would_change_a_unit_outside_it() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let output = fixture.migrate(&["--only", "A.cpp"], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    // A.cpp cannot be placed without narrowing B.cpp, which this run was told
    // to leave alone. Taking A.cpp's half of the change would be a different
    // change — one that overlaps B.cpp — so neither half happens, and the
    // report says which unit it would have needed. Naming B.cpp as well is how
    // a focused run permits it; see the next test.
    let result = fixture.json(&format!("{stage}/result.json"));
    assert!(names(&result["accepted"]).is_empty(), "{result:#}");
    assert_eq!(names(&result["deferred"]), ["A.cpp"], "{result:#}");
    let refusal = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["unit"] == "A.cpp" && event["status"] == "rejected")
        .unwrap_or_else(|| panic!("no recorded refusal: {result:#}"));
    let reason = refusal["reason"].as_str().unwrap();
    assert!(reason.starts_with("dependency-not-permitted"), "{reason}");
    assert!(reason.contains("B.cpp"), "{reason}");
    assert_eq!(fixture.read("config/PAL/splits.txt"), before, "the project should be untouched");

    let summary = fixture.json(&format!("{stage}/coverage.json"));
    assert_eq!(summary["dispositions"]["A.cpp"], "dependency-not-permitted");
    assert_eq!(summary["eligible_excluded_by_only"], serde_json::json!(["Q.cpp"]));
}

#[test]
fn naming_the_neighbour_with_only_permits_the_whole_transaction() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    // B.cpp is not a candidate of its own. Naming it permits A.cpp's change to
    // write it; it does not make it something to evaluate.
    let output = fixture.migrate(&["--only", "A.cpp", "--only", "B.cpp"], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    assert_eq!(names(&prepared["candidates"]), ["A.cpp"], "{prepared:#}");

    let published = fixture.published_splits();
    let expected = expected_final();
    for name in ["P.cpp", "A.cpp", "B.cpp"] {
        assert_eq!(published.get(name), expected.get(name), "{name}");
    }
    // Q.cpp was neither requested nor needed, so it is untouched and reported.
    assert!(!published.contains_key("Q.cpp"), "{published:#?}");
    let summary = fixture.json(&format!("{stage}/coverage.json"));
    assert_eq!(summary["eligible_excluded_by_only"], serde_json::json!(["Q.cpp"]));
}

#[test]
fn only_a_neighbour_without_its_candidate_is_refused() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let output = fixture.migrate(&["--only", "B.cpp"], &[]);
    assert!(!output.status.success(), "{}", describe(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("B.cpp"), "{}", describe(&output));
    assert_eq!(fixture.read("config/PAL/splits.txt"), before);
}

#[test]
fn the_benchmark_credits_a_neighbour_with_the_transaction_that_wrote_it() {
    use dtk_migrate::{
        analysis::ownership_score::Application,
        cli::benchmark::{Linkage, Revision, build_manifest, read_run, score},
    };
    use sha2::{Digest, Sha256};

    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();

    // The oracle is the state the run should reach. B.cpp is never a
    // candidate; everything the scorer knows about it comes from A.cpp's
    // transaction.
    let baseline = common::render(&baseline_target());
    let revision = |id: &str, splits: &str| Revision {
        id: id.into(),
        splits_sha256: format!("{:x}", Sha256::digest(splits.as_bytes())),
        configure_sha256: None,
        expected_retail_sha1: "0".repeat(40),
        verified_dol_sha1: None,
    };
    let oracle = common::render(&expected_final());
    let manifest = build_manifest(
        "NTSC",
        "PAL",
        revision("baseline", &baseline),
        &baseline,
        revision("oracle", &oracle),
        &oracle,
        &Linkage {
            baseline: Default::default(),
            oracle: ["A.cpp", "B.cpp", "Q.cpp"].map(String::from).into(),
            verified_oracle: Default::default(),
        },
    )
    .unwrap();
    let facts = read_run(&fixture.root.join(format!("build/dtk-migrate/runs/{id}"))).unwrap();
    let result = score(&manifest, &facts);
    let row = |name: &str| result.units.iter().find(|unit| unit.unit == name).unwrap();

    let neighbour = row("B.cpp");
    assert_eq!(neighbour.application, Application::Accepted, "{neighbour:#?}");
    assert!(neighbour.code_recall.proposed && neighbour.code_recall.selected, "{neighbour:#?}");
    assert!(!neighbour.code_recall.ranking_failure);
    // Credited to the joint transaction, which a later refinement superseded
    // for A.cpp but not for B.cpp.
    let summary = fixture.json(&format!("build/dtk-migrate/runs/{id}/coverage/result.json"));
    let joint = summary["applied"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["units"].as_array().unwrap().len() == 2)
        .unwrap();
    assert_eq!(neighbour.selected.as_deref(), joint["id"].as_str());

    let candidate = row("A.cpp");
    assert_eq!(candidate.application, Application::Accepted);
    assert!(candidate.code_recall.selected && candidate.full_recall.selected, "{candidate:#?}");
    assert_eq!(
        candidate.selected.as_ref(),
        summary["selections"]["A.cpp"].as_str().map(String::from).as_ref()
    );
}

#[test]
fn only_is_resolved_across_every_stage_of_the_run() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    // Coverage changes and reserves both units; verification, the next stage,
    // has no candidate for either. That is a request already satisfied, not a
    // mistaken one.
    let output =
        fixture.migrate(&["--stages", "verify", "--only", "A.cpp", "--only", "B.cpp"], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let run = fixture.json(&format!("build/dtk-migrate/runs/{id}/run.json"));
    assert_eq!(run["stages"], serde_json::json!(["coverage", "verify"]));
    let published = fixture.published_splits();
    let expected = expected_final();
    for name in ["A.cpp", "B.cpp"] {
        assert_eq!(published.get(name), expected.get(name), "{name}");
    }
}

#[test]
fn a_name_no_stage_involves_stops_the_run_before_publication() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let output = fixture.migrate(
        &["--stages", "verify", "--only", "A.cpp", "--only", "B.cpp", "--only", "nowhere.cpp"],
        &[],
    );
    assert!(!output.status.success(), "{}", describe(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("nowhere.cpp") && stderr.contains("nothing was published"), "{stderr}");
    assert_eq!(fixture.read("config/PAL/splits.txt"), before);
}
