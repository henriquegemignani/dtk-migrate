mod common;

use common::{Blocks, DiscoverEvidence, Layout, describe, line};
use dtk_migrate::{
    analysis::coverage_fixture::{anchor, report, unit},
    matching::data_evidence::{DataEvidenceReport, SCHEMA},
};

#[test]
fn rejected_discovery_subtrees_are_pretested_without_serial_leaf_builds() {
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
    let code = common::render(&blocks);
    let ownership = report(
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
    );
    let Some(fixture) = common::build(&Layout {
        units: units.clone(),
        source_splits: code.clone(),
        target_splits: common::render(&Blocks::new()),
        worlds: vec![Some(ownership)],
        discover: Some(DiscoverEvidence {
            proposals: code,
            data: DataEvidenceReport {
                schema: SCHEMA,
                source: "NTSC".into(),
                target: "PAL".into(),
                source_image_sha256: "0".repeat(64),
                target_image_sha256: "1".repeat(64),
                ranges: Vec::new(),
            },
        }),
    }) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let refused = units[1..].join(",");
    let output = fixture.migrate_stages_with_settings("discover", "4", "1", &[], &[
        "DTK_MIGRATE_FIXTURE_REJECT_SPLIT",
        &refused,
        "DTK_MIGRATE_FIXTURE_MATCH_SPLITS",
        "1",
    ]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let result = fixture.json(&format!("build/dtk-migrate/runs/{id}/discover/result.json"));
    let accepted: Vec<&str> = result["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect();
    assert_eq!(accepted, ["A.cpp"], "{result:#}");
    assert_eq!(result["deferred"].as_array().unwrap().len(), 16, "{result:#}");
    assert!(describe(&output).contains("discover: 4 of 4 bisection subtrees refused"));
}
