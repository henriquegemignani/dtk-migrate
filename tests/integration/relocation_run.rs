//! Opt-in regression against the frozen historical NTSC-to-PAL identification.
//! The ordinary suite does not require retail binaries or this saved report.

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
fn the_gui_factory_run_is_placed_by_order_and_shared_vtable_relocations() {
    let Some(report) = frozen() else { return };
    let index = load(report);
    assert_eq!(index.relocation_linked_runs().len(), 1);
    let matches: Vec<_> = index
        .relocation_linked_runs()
        .iter()
        .filter(|run| run.unit == "GuiSys/CGuiFactories.cpp")
        .collect();
    assert_eq!(matches.len(), 1);
    let run = matches[0];
    assert_eq!((&*run.start, &*run.end), ("0x802ADCD8", "0x802AE178"));
    assert_eq!(run.inserted, "0x802ADF70");
    assert_eq!(run.target_vtable, "0x803D4608");
    let after = BTreeMap::from([(".text".into(), vec![(0x802ADCD8, 0x802AE178)])]);
    let assessment = index.assess("GuiSys/CGuiFactories.cpp", "main", &BTreeMap::new(), &after);
    assert_eq!(assessment.independent_members, 1);
    assert_eq!(assessment.new_relocation_linked_run_members, 5);
    assert!(assessment.permits_automatic_claim());
}

#[test]
fn a_broken_vtable_relation_cannot_place_the_same_run() {
    let Some(mut report) = frozen() else { return };
    let raw =
        report.unattributed_references.iter_mut().find(|raw| raw.address == "0x802AE0DC").unwrap();
    raw.references.retain(|reference| !(reference.offset == 88 && reference.kind == "PpcAddr16Lo"));
    let index = load(report);
    assert!(
        !index.relocation_linked_runs().iter().any(|run| run.unit == "GuiSys/CGuiFactories.cpp")
    );
}

#[test]
fn the_code_claim_requires_its_source_vtable_and_live_target_bounds() {
    let Some(report) = frozen() else { return };
    let index = load(report);
    let candidate = unit("GuiSys/CGuiFactories.cpp", vec![]);
    let units = BTreeMap::from([(candidate.name.clone(), &candidate)]);
    let source = IndexMap::from([(candidate.name.clone(), vec![
        "\t.text start:0x802C1BCC end:0x802C202C".into(),
        "\t.data start:0x803EC7B8 end:0x803EC7C8".into(),
    ])]);
    let target = IndexMap::from([
        ("GuiSys/CGuiCompoundWidget.cpp".into(), vec![
            "\t.text start:0x802ADB04 end:0x802ADCD8".into(),
        ]),
        ("GuiSys/CGuiFeeHelper.cpp".into(), vec!["\t.text start:0x802AE178 end:0x802AE290".into()]),
    ]);
    let offered = |source: &IndexMap<String, Vec<String>>,
                   target: &IndexMap<String, Vec<String>>| {
        alternatives::build(&candidate, target, &units, source, &index)
            .into_iter()
            .any(|alternative| alternative.evidence == "relocation-linked-run")
    };
    assert!(offered(&source, &target));

    let mut missing_source_data = source.clone();
    missing_source_data.get_mut(&candidate.name).unwrap().pop();
    assert!(!offered(&missing_source_data, &target));

    let mut foreign_target_data = target.clone();
    foreign_target_data
        .get_mut("GuiSys/CGuiCompoundWidget.cpp")
        .unwrap()
        .push("\t.data start:0x803D4608 end:0x803D4618".into());
    assert!(!offered(&source, &foreign_target_data));

    let mut moved_bound = target.clone();
    moved_bound.get_mut("GuiSys/CGuiFeeHelper.cpp").unwrap()[0] =
        "\t.text start:0x802AE180 end:0x802AE290".into();
    assert!(!offered(&source, &moved_bound));
}
