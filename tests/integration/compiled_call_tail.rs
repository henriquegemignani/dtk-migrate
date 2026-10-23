//! Opt-in checks against the frozen historical NTSC-to-PAL identification.

use std::collections::BTreeMap;

use dtk_migrate::{
    analysis::{
        coverage_fixture::unit,
        ownership::{IdentificationReport, ObservationIndex},
    },
    stages::coverage::alternatives,
};
use indexmap::IndexMap;

fn frozen() -> Option<IdentificationReport> {
    let path = std::env::var_os("DTK_MIGRATE_HISTORICAL_COMPLETE_REPORT")?;
    Some(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
}

fn load(report: IdentificationReport) -> ObservationIndex {
    let source = report.source.clone();
    let target = report.target.clone();
    ObservationIndex::load_self_contained(report, &source, &target).unwrap()
}

#[test]
fn the_changed_cimage_tail_has_one_call_linked_placement() {
    let Some(report) = frozen() else { return };
    let index = load(report);
    let tails: Vec<_> = index
        .compiled_call_linked_tails()
        .iter()
        .filter(|tail| tail.unit == "Kyoto/Text/CImageInstruction.cpp")
        .collect();
    assert_eq!(tails.len(), 1);
    assert_eq!(tails[0].target_caller, "0x80342F60");
    assert_eq!(tails[0].target_tail, "0x80343078");

    let candidate = unit("Kyoto/Text/CImageInstruction.cpp", vec![]);
    let units = BTreeMap::from([(candidate.name.clone(), &candidate)]);
    let source = IndexMap::from([(candidate.name.clone(), vec![
        "\t.text start:0x80359718 end:0x80359AEC".into(),
    ])]);
    let target = IndexMap::from([(candidate.name.clone(), vec![
        "\t.text start:0x80342E3C end:0x80342F60".into(),
    ])]);
    let alternatives = alternatives::build(&candidate, &target, &units, &source, &index);
    let offered = alternatives.first().expect("the complete call-linked tail must be offered");
    assert_eq!(offered.evidence, "compiled-call-linked-tail");
    assert_eq!(offered.end, "0x803430D4");
    assert_eq!(offered.ownership.new_compiled_call_linked_tail_members, 1);
    assert_eq!(offered.ownership.new_unresolved, 0);

    let truncated_source = IndexMap::from([(candidate.name.clone(), vec![
        "\t.text start:0x8035983C end:0x80359AEC".into(),
    ])]);
    let alternatives = alternatives::build(&candidate, &target, &units, &truncated_source, &index);
    assert!(!alternatives.iter().any(|item| item.evidence == "compiled-call-linked-tail"));
}

#[test]
fn all_three_call_relationships_are_required() {
    let Some(mut report) = frozen() else { return };
    let tail =
        report.target_functions.iter_mut().find(|item| item.address == "0x80343078").unwrap();
    tail.callers.clear();
    assert!(
        !load(report.clone())
            .compiled_call_linked_tails()
            .iter()
            .any(|item| item.unit == "Kyoto/Text/CImageInstruction.cpp")
    );

    let tail =
        report.target_functions.iter_mut().find(|item| item.address == "0x80343078").unwrap();
    tail.callers.push(dtk_migrate::analysis::ownership::CallerReference {
        section: ".text".into(),
        address: "0x80342F60".into(),
    });
    let source_tail =
        report.source_functions.iter_mut().find(|item| item.address == "0x803599F4").unwrap();
    source_tail.callers.clear();
    assert!(
        !load(report.clone())
            .compiled_call_linked_tails()
            .iter()
            .any(|item| item.unit == "Kyoto/Text/CImageInstruction.cpp")
    );
    let source_tail =
        report.source_functions.iter_mut().find(|item| item.address == "0x803599F4").unwrap();
    source_tail.callers.push(dtk_migrate::analysis::ownership::CallerReference {
        section: ".text".into(),
        address: "0x8035983C".into(),
    });
    let object = report
        .object_evidence
        .as_mut()
        .unwrap()
        .objects
        .iter_mut()
        .find(|item| item.unit == "Kyoto/Text/CImageInstruction.cpp")
        .unwrap();
    let caller = object
        .functions
        .iter_mut()
        .find(|item| item.name.starts_with("Invoke__17CImageInstruction"))
        .unwrap();
    caller.references.retain(|reference| reference.target != "CalculateHeight__13CFontImageDefCFv");
    assert!(
        !load(report)
            .compiled_call_linked_tails()
            .iter()
            .any(|item| item.unit == "Kyoto/Text/CImageInstruction.cpp")
    );
}

#[test]
fn a_guessed_caller_extent_cannot_place_the_tail() {
    let Some(report) = frozen() else { return };
    let mut guessed = report.clone();
    guessed
        .target_functions
        .iter_mut()
        .find(|item| item.address == "0x80342F60")
        .unwrap()
        .extent_known = false;
    assert!(
        !load(guessed)
            .compiled_call_linked_tails()
            .iter()
            .any(|item| { item.unit == "Kyoto/Text/CImageInstruction.cpp" })
    );
}
