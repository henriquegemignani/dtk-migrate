mod common;

use common::{Blocks, Layout, describe, line};

#[test]
fn rejected_verify_subtrees_are_pretested_without_serial_leaf_builds() {
    let units: Vec<String> = std::iter::once("A.cpp".to_string())
        .chain((0..16).map(|i| format!("R{i:02}.cpp")))
        .collect();
    let blocks: Blocks = units
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let start = 0x8000_1000 + (i as u32) * 0x200;
            (name.clone(), vec![line(".text", start, start + 0x100)])
        })
        .collect();
    let splits = common::render(&blocks);
    let Some(fixture) = common::build(&Layout {
        units: units.clone(),
        source_splits: splits.clone(),
        target_splits: splits,
        worlds: vec![None],
        discover: None,
    }) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let refused = units[1..].join(",");
    let output = fixture.migrate_stages_with_settings("verify", "4", "1", &[], &[
        "DTK_MIGRATE_FIXTURE_REJECT_SOURCE",
        &refused,
    ]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let result = fixture.json(&format!("build/dtk-migrate/runs/{id}/verify/result.json"));
    let accepted: Vec<&str> = result["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect();
    assert_eq!(accepted, ["A.cpp"], "{result:#}");
    assert_eq!(result["deferred"].as_array().unwrap().len(), 16, "{result:#}");
    assert!(describe(&output).contains("verify: 4 of 4 bisection subtrees refused"));
    for i in 0..4 {
        let job = fixture
            .json(&format!("build/dtk-migrate/runs/{id}/verify/pretests-1/{i:05}/result.json"));
        assert!(job["accepted"].as_array().unwrap().is_empty(), "{job:#}");
        assert_eq!(job["deferred"].as_array().unwrap().len(), 4, "{job:#}");
    }
}
