//! Code ownership, independently witnessed data, and source linkage on one TU.

mod common;

use common::{Blocks, DiscoverEvidence, Layout, describe, line};
use dtk_migrate::{
    analysis::{
        coverage_fixture::{report, run, unit},
        unit_matching::UnitTier,
    },
    matching::data_evidence::{
        CommonAlignBasis, DataEvidenceReport, DataMemberEvidence, DataRangeEvidence, DataSizeBasis,
        SCHEMA,
    },
    project::splits::Splits,
};

const CODE: (u32, u32) = (0x8000_1000, 0x8000_1200);
const BSS_ONE: (u32, u32) = (0x8000_2000, 0x8000_2004);
const BSS_TWO: (u32, u32) = (0x8000_2100, 0x8000_2108);
const HEADER: &str =
    "Sections:\n\t.text       type:code align:4\n\t.bss        type:bss align:4\n\n";

fn bss(start: u32, end: u32) -> String { format!("{} align:4 common", line(".bss", start, end)) }

fn render(blocks: Blocks) -> String { Splits { header: HEADER.into(), blocks }.render() }

fn data_range(start: u32, end: u32, index: u32) -> DataRangeEvidence {
    DataRangeEvidence {
        unit: "A.cpp".into(),
        section: ".bss".into(),
        start,
        end,
        tier: UnitTier::Candidate,
        reasons: vec!["other data is still unresolved".into()],
        required_alignment: 4,
        members: vec![DataMemberEvidence {
            source_index: index,
            target_index: index,
            source_name: format!("source_bss_{index}"),
            target_name: format!("target_bss_{index}"),
            target_start: start,
            target_end: end,
            source_extent_known: true,
            target_extent_known: true,
            target_size_basis: DataSizeBasis::FixedWidth,
            source_wholly_owned: true,
            source_weak: false,
            target_weak: false,
            target_symbol_common: true,
            target_common_align: Some(4),
            target_common_align_basis: Some(CommonAlignBasis::TargetSymbol),
            reference_positions: 2,
            target_owner: None,
            target_common: None,
        }],
        compiled_ordinary_bss: None,
    }
}

fn fixture() -> Option<common::Fixture> {
    let source = Blocks::from([("A.cpp".into(), vec![
        line(".text", 0x8000_0400, 0x8000_0600),
        bss(0x8000_3000, 0x8000_3004),
        bss(0x8000_3100, 0x8000_3108),
    ])]);
    let proposals = Blocks::from([("A.cpp".into(), vec![
        bss(BSS_ONE.0, BSS_ONE.1),
        bss(BSS_TWO.0, BSS_TWO.1),
    ])]);
    let world = report("NTSC", "PAL", vec![unit("A.cpp", run("A", CODE.0, CODE.1, 0x100))]);
    common::build(&Layout {
        units: vec!["A.cpp".into()],
        source_splits: render(source),
        target_splits: render(Blocks::new()),
        worlds: vec![Some(world.clone()), Some(world)],
        discover: Some(DiscoverEvidence {
            proposals: render(proposals),
            data: DataEvidenceReport {
                schema: SCHEMA,
                source: "NTSC".into(),
                target: "PAL".into(),
                source_image_sha256: "0".repeat(64),
                target_image_sha256: "1".repeat(64),
                ranges: vec![
                    data_range(BSS_ONE.0, BSS_ONE.1, 0),
                    data_range(BSS_TWO.0, BSS_TWO.1, 1),
                ],
            },
        }),
    })
}

#[test]
fn focused_discovery_does_not_publish_global_matcher_renames() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let symbols = "fn_80001000 = .text:0x80001000; // type:function size:0x20\n";
    std::fs::write(fixture.root.join("config/PAL/symbols.txt"), symbols).unwrap();
    std::fs::write(fixture.evidence.join("discover-renames.txt"), "fn_80001000 = RenamedFn\n")
        .unwrap();

    let output = fixture.migrate(&["--stages", "coverage,discover", "--only", "A.cpp"], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    assert_eq!(fixture.read("config/PAL/symbols.txt"), symbols);
    let id = fixture.run_id();
    let prepared = fixture.json(&format!("build/dtk-migrate/runs/{id}/discover/prepared.json"));
    assert!(
        prepared["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["status"] == "rename-batch-skipped-by-only"),
        "{prepared:#}"
    );
}

#[test]
fn unfocused_discovery_still_applies_confident_matcher_renames() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    std::fs::write(
        fixture.root.join("config/PAL/symbols.txt"),
        "fn_80001000 = .text:0x80001000; // type:function size:0x20\n",
    )
    .unwrap();
    std::fs::write(fixture.evidence.join("discover-renames.txt"), "fn_80001000 = RenamedFn\n")
        .unwrap();

    let output = fixture.migrate(&["--stages", "coverage,discover"], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    assert!(fixture.read("config/PAL/symbols.txt").contains("RenamedFn = .text:0x80001000"));
}

#[test]
fn coverage_data_and_verify_publish_one_composed_body() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&["--stages", "discover,verify"], &[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let final_blocks = fixture.published_splits();
    assert_eq!(final_blocks["A.cpp"], [
        line(".text", CODE.0, CODE.1),
        bss(BSS_ONE.0, BSS_ONE.1),
        bss(BSS_TWO.0, BSS_TWO.1),
    ]);
    for stage in ["coverage", "discover", "verify"] {
        let result = fixture.json(&format!("build/dtk-migrate/runs/{id}/{stage}/result.json"));
        assert_eq!(result["accepted"][0]["name"], "A.cpp", "{stage}: {result:#}");
    }
    let publication = fixture.json(&format!("build/dtk-migrate/runs/{id}/publication.json"));
    assert_eq!(publication["status"], "published", "{publication:#}");
    assert!(publication["final_certificates_sha256"].as_str().is_some());
    let graph = fixture.json(&format!("build/dtk-migrate/runs/{id}/final-certificates.json"));
    assert_eq!(graph["schema"], 1);
    assert_eq!(
        graph["units"]["A.cpp"]["body"],
        serde_json::json!([
            line(".text", CODE.0, CODE.1),
            bss(BSS_ONE.0, BSS_ONE.1),
            bss(BSS_TWO.0, BSS_TWO.1),
        ])
    );
    assert_eq!(graph["units"]["A.cpp"]["discovery"]["kind"], "data");
    assert_eq!(graph["units"]["A.cpp"]["verified_source_link"], true);
    assert_eq!(graph["units"]["A.cpp"]["coverage_transactions"].as_array().unwrap().len(), 1);
}

#[test]
fn interruption_before_data_completion_resumes_with_the_same_final_certificates() {
    let Some(fixture) = fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let original = fixture.read("config/PAL/splits.txt");
    let interrupted = fixture
        .migrate(&["--stages", "discover,verify"], &["DTK_MIGRATE_FIXTURE_ABORT_DISCOVER", "1"]);
    assert!(!interrupted.status.success(), "{}", describe(&interrupted));
    assert_eq!(fixture.read("config/PAL/splits.txt"), original);
    let id = fixture.run_id();
    let coverage_path = format!("build/dtk-migrate/runs/{id}/coverage/result.json");
    let coverage_result = fixture.json(&coverage_path);
    assert_eq!(coverage_result["accepted"][0]["name"], "A.cpp");

    let resumed = fixture.resume(&id);
    assert!(resumed.status.success(), "{}", describe(&resumed));
    let resumed_coverage = fixture.json(&coverage_path);
    for field in ["accepted", "applied", "selections"] {
        assert_eq!(
            resumed_coverage[field], coverage_result[field],
            "resume changed coverage's {field} certificate"
        );
    }
    assert_eq!(fixture.published_splits()["A.cpp"], [
        line(".text", CODE.0, CODE.1),
        bss(BSS_ONE.0, BSS_ONE.1),
        bss(BSS_TWO.0, BSS_TWO.1),
    ]);
    let publication = fixture.json(&format!("build/dtk-migrate/runs/{id}/publication.json"));
    assert_eq!(publication["status"], "published", "{publication:#}");
}
