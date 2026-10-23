use crate::{
    common,
    common::{Blocks, Fixture, Layout, describe, line},
};

/// `.sbss` of `P.cpp`, `A.cpp` and `N.cpp`, and the same three in `.sdata`
/// 0x1000 higher.
fn symbols(base: u32) -> String {
    let sbss = [("sPrevious", 0), ("seqFreeRoot", 8), ("seqPausedRoot", 0xc), ("sNext", 0x18)];
    let sdata = [("sDataPrevious", 0x1000), ("sDataA", 0x1008), ("sDataNext", 0x1010)];
    sbss.iter()
        .map(|(name, offset)| (name, ".sbss", offset))
        .chain(sdata.iter().map(|(name, offset)| (name, ".sdata", offset)))
        .map(|(name, section, offset)| {
            format!("{name} = {section}:0x{:08X}; // type:object size:0x4\n", base + offset)
        })
        .collect()
}

fn text(index: u32) -> String {
    line(".text", 0x8000_1000 + index * 0x100, 0x8000_1100 + index * 0x100)
}

fn sbss(start: u32, end: u32) -> String { line(".sbss", start, end) }

fn sdata(start: u32, end: u32) -> String { line(".sdata", start, end) }

fn blocks(entries: Vec<(&str, Vec<String>)>) -> Blocks {
    entries.into_iter().map(|(name, lines)| (name.to_string(), lines)).collect()
}

/// `A.cpp` holds `.sbss` and `.sdata` in the source; the target moved both by
/// 0x100 and split neither for it.
fn fixture() -> Option<Fixture> {
    let source = blocks(vec![
        ("P.cpp", vec![text(0), sbss(0x8000_2000, 0x8000_2008), sdata(0x8000_3000, 0x8000_3008)]),
        ("A.cpp", vec![text(1), sbss(0x8000_2008, 0x8000_2018), sdata(0x8000_3008, 0x8000_3010)]),
        ("N.cpp", vec![text(2), sbss(0x8000_2018, 0x8000_2020), sdata(0x8000_3010, 0x8000_3018)]),
    ]);
    let target = blocks(vec![
        ("P.cpp", vec![text(0), sbss(0x8000_2100, 0x8000_2108), sdata(0x8000_3100, 0x8000_3108)]),
        ("A.cpp", vec![text(1)]),
        ("N.cpp", vec![text(2), sbss(0x8000_2118, 0x8000_2120), sdata(0x8000_3110, 0x8000_3118)]),
    ]);
    let Some(fixture) = common::build(&Layout {
        units: vec!["P.cpp".into(), "A.cpp".into(), "N.cpp".into()],
        source_splits: common::render(&source),
        target_splits: common::render(&target),
        worlds: vec![None],
        discover: None,
    }) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return None;
    };
    std::fs::write(fixture.root.join("config/NTSC/symbols.txt"), symbols(0x8000_2000)).unwrap();
    std::fs::write(fixture.root.join("config/PAL/symbols.txt"), symbols(0x8000_2100)).unwrap();
    Some(fixture)
}

const SBSS_DUPLICATE: &str = "A.cpp,seqFreeRoot,auto_05_80002108_sbss.o,.sbss";
const SDATA_DUPLICATE: &str = "A.cpp,sDataA,auto_04_80003108_sdata.o,.sdata";

fn verify(fixture: &Fixture, env: &[&str]) -> serde_json::Value {
    let output = fixture.migrate_stages_with_settings("verify", "1", "4", &[], env);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    fixture.json(&format!("build/dtk-migrate/runs/{id}/verify/result.json"))
}

fn feedback_events(result: &serde_json::Value) -> Vec<&serde_json::Value> {
    result["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["status"] == "data-split-feedback")
        .collect()
}

fn accepts(result: &serde_json::Value, name: &str) -> bool {
    common::names(&result["accepted"]).iter().any(|accepted| accepted == name)
}

/// A unit whose `.sbss` the target never split is refused as
/// `multiply-defined`. Verify maps its source split onto the target, links it
/// again with that range, and keeps the range only because that link passes.
#[test]
fn a_gap_duplicate_is_fed_back_as_the_units_data_split() {
    let Some(fixture) = fixture() else { return };
    let result = verify(&fixture, &["DTK_MIGRATE_FIXTURE_GAP_DUPLICATE", SBSS_DUPLICATE]);
    assert!(accepts(&result, "A.cpp"), "{result:#}");
    let applied = result["applied"].as_array().unwrap();
    assert_eq!(applied.len(), 1, "{result:#}");
    assert_eq!(applied[0]["unit"], "A.cpp");
    assert_eq!(applied[0]["id"], "data-split-feedback");
    let added = sbss(0x8000_2108, 0x8000_2118);
    assert_eq!(applied[0]["record"]["data_lines"], serde_json::json!([added]));
    let feedback = feedback_events(&result);
    // The worker found the range; integration staged it with the candidate it
    // carried instead of refusing the union and feeding it back again.
    assert_eq!(feedback.len(), 1, "{result:#}");
    assert_eq!(feedback[0]["unit"], "A.cpp");
    assert!(
        feedback[0]["reason"].as_str().unwrap().contains("between seqFreeRoot and sNext"),
        "{result:#}"
    );
    assert_eq!(fixture.published_splits()["A.cpp"], [text(1), added]);
}

/// Each link names the next duplicate; every round adds its range.
#[test]
fn feedback_continues_over_several_rounds() {
    let Some(fixture) = fixture() else { return };
    let duplicates = format!("{SBSS_DUPLICATE};{SDATA_DUPLICATE}");
    let result = verify(&fixture, &["DTK_MIGRATE_FIXTURE_GAP_DUPLICATE", &duplicates]);
    assert!(accepts(&result, "A.cpp"), "{result:#}");
    let added_sbss = sbss(0x8000_2108, 0x8000_2118);
    // Initialized data is never mapped from `symbols.txt` alone, so the
    // `.sdata` duplicate is claimed by its own extent.
    let added_sdata = sdata(0x8000_3108, 0x8000_310c);
    let applied = result["applied"].as_array().unwrap();
    assert_eq!(applied.len(), 1, "{result:#}");
    assert_eq!(applied[0]["record"]["data_lines"], serde_json::json!([added_sbss, added_sdata]));
    let rounds: Vec<&str> =
        feedback_events(&result).iter().map(|event| event["reason"].as_str().unwrap()).collect();
    assert_eq!(rounds.len(), 2, "{result:#}");
    assert!(rounds[0].starts_with("round 1: linking again"), "{rounds:?}");
    assert!(rounds[1].starts_with("round 2: linking again"), "{rounds:?}");
    // dtk's section order: `.sdata` before `.sbss`.
    assert_eq!(fixture.published_splits()["A.cpp"], [text(1), added_sdata, added_sbss]);
}

/// A derived range that still does not link is withdrawn: the unit stays
/// refused, nothing is recorded, and the target splits are as they were.
#[test]
fn a_fed_back_range_whose_link_still_fails_is_withdrawn() {
    let Some(fixture) = fixture() else { return };
    let before = fixture.published_splits();
    let result = verify(&fixture, &[
        "DTK_MIGRATE_FIXTURE_GAP_DUPLICATE",
        SBSS_DUPLICATE,
        "DTK_MIGRATE_FIXTURE_REJECT_SECTION",
        "A.cpp,.sbss",
    ]);
    assert!(!accepts(&result, "A.cpp"), "{result:#}");
    assert!(result["applied"].as_array().unwrap().is_empty(), "{result:#}");
    assert!(!feedback_events(&result).is_empty(), "{result:#}");
    assert_eq!(fixture.published_splits(), before);
    assert_eq!(fixture.published_splits()["A.cpp"], [text(1)]);
}

/// A worker proved A.cpp with a fed-back range, but integration's combined
/// batch fails. The staged range is withdrawn with the batch, and comes back
/// only with the trial that keeps A.cpp.
#[test]
fn a_failed_batch_withdraws_the_ranges_staged_for_it() {
    let Some(fixture) = fixture() else { return };
    let result = verify(&fixture, &[
        "DTK_MIGRATE_FIXTURE_GAP_DUPLICATE",
        SBSS_DUPLICATE,
        "DTK_MIGRATE_FIXTURE_REJECT_LINKED_COMBINATION",
        "A.cpp,N.cpp",
    ]);
    assert!(accepts(&result, "A.cpp") && accepts(&result, "P.cpp"), "{result:#}");
    assert!(!accepts(&result, "N.cpp"), "{result:#}");
    // Only the worker's round: integration staged the carried line for the
    // failed batch and again for A.cpp's own trial, without feeding it back.
    assert_eq!(feedback_events(&result).len(), 1, "{result:#}");
    let applied = result["applied"].as_array().unwrap();
    assert_eq!(applied.len(), 1, "{result:#}");
    assert_eq!(applied[0]["unit"], "A.cpp");
    let added = sbss(0x8000_2108, 0x8000_2118);
    let published = fixture.published_splits();
    assert_eq!(published["A.cpp"], [text(1), added]);
    assert_eq!(published["N.cpp"][0], text(2));
}

/// Without a source split holding the symbol, nothing is fed back and the
/// unit stays refused.
#[test]
fn a_duplicate_the_source_unit_does_not_hold_is_not_fed_back() {
    let units = blocks(vec![("A.cpp", vec![line(".text", 0x8000_1000, 0x8000_1100)])]);
    let Some(fixture) = common::build(&Layout {
        units: vec!["A.cpp".into()],
        source_splits: common::render(&units),
        target_splits: common::render(&units),
        worlds: vec![None],
        discover: None,
    }) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    std::fs::write(fixture.root.join("config/NTSC/symbols.txt"), symbols(0x8000_2000)).unwrap();
    std::fs::write(fixture.root.join("config/PAL/symbols.txt"), symbols(0x8000_2100)).unwrap();
    let result = verify(&fixture, &["DTK_MIGRATE_FIXTURE_GAP_DUPLICATE", SBSS_DUPLICATE]);
    assert!(common::names(&result["accepted"]).is_empty(), "{result:#}");
    let refused = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["status"] == "failed-source-link-or-hash")
        .unwrap_or_else(|| panic!("{result:#}"));
    assert_eq!(refused["refusal"]["kind"], "duplicate-symbol");
    assert_eq!(refused["refusal"]["linker"][0]["symbol"], "seqFreeRoot");
    assert_eq!(fixture.published_splits()["A.cpp"], units["A.cpp"]);
}
