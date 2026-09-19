//! A three-unit run through preparation, workers, integration and publication.

mod common;

use common::{Blocks, Layout, describe, line, names};
use dtk_migrate::analysis::coverage_fixture::{anchor, owned_by, report, unit};

const A: (u32, u32) = (0x8000_1000, 0x8000_1100);
const B: (u32, u32) = (0x8000_1100, 0x8000_1200);
const C: (u32, u32) = (0x8000_1200, 0x8000_1300);

fn evidence(settled: bool) -> dtk_migrate::analysis::coverage::CoverageReport {
    let a = anchor("a", A.0, A.1);
    let b = owned_by(vec![anchor("b", B.0, B.1)], "B.cpp");
    let c = owned_by(vec![anchor("c", C.0, C.1)], if settled { "C.cpp" } else { "B.cpp" });
    report("NTSC", "PAL", vec![unit("A.cpp", vec![a]), unit("B.cpp", b), unit("C.cpp", c)])
}

fn blocks(items: &[(&str, Vec<String>)]) -> Blocks {
    items.iter().map(|(name, lines)| ((*name).to_string(), lines.clone())).collect()
}

#[test]
fn a_decisive_run_publishes_one_three_unit_transaction() {
    let source = blocks(&[
        ("A.cpp", vec![line(".text", 0x8000_0400, 0x8000_0500)]),
        ("B.cpp", vec![line(".text", 0x8000_0500, 0x8000_0600)]),
        ("C.cpp", vec![line(".text", 0x8000_0600, 0x8000_0700)]),
    ]);
    let target = blocks(&[("B.cpp", vec![line(".text", B.0, C.1)])]);
    let Some(fixture) = common::build(&Layout {
        units: ["A.cpp", "B.cpp", "C.cpp"].map(str::to_string).to_vec(),
        source_splits: common::render(&source),
        target_splits: common::render(&target),
        worlds: vec![None, Some(evidence(false)), None, Some(evidence(true))],
    }) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");
    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    let candidate = prepared["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["name"] == "A.cpp")
        .unwrap();
    assert!(
        candidate["evidence"]["alternatives"].as_array().unwrap().iter().any(|alternative| {
            alternative["evidence"] == "joint-unit-run"
                && alternative["transaction"]["members"].as_array().unwrap().len() == 3
        }),
        "{candidate:#}"
    );
    let result = fixture.json(&format!("{stage}/result.json"));
    assert!(
        result["applied"].as_array().unwrap().iter().any(|entry| {
            entry["unit"] == "A.cpp"
                && entry["units"] == serde_json::json!(["A.cpp", "B.cpp", "C.cpp"])
        }),
        "{result:#}"
    );
    let published = fixture.published_splits();
    assert_eq!(published["A.cpp"], vec![line(".text", A.0, A.1)]);
    assert_eq!(published["B.cpp"], vec![line(".text", B.0, B.1)]);
    assert_eq!(published["C.cpp"], vec![line(".text", C.0, C.1)]);
    assert!(names(&result["accepted"]).contains(&"A.cpp".to_string()));
}
