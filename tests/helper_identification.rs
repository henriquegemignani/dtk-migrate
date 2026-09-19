//! Opt-in check against a read-only historical NTSC-to-PAL match report.
//!
//! Generate it with `dtk-migrate match --identifications` from the frozen
//! b65ad2a6 configs, then set `DTK_MIGRATE_HELPER_REPORT` to its path. The
//! ordinary suite uses small typed fixtures and needs no retail binaries.

use std::path::PathBuf;

use dtk_migrate::analysis::{
    helpers::HelperSignal,
    ownership::{IdentificationReport, ObservationIndex},
};

#[test]
fn historical_orphan_and_widget_helper_survive_canonical_loading() {
    let Some(path) = std::env::var_os("DTK_MIGRATE_HELPER_REPORT").map(PathBuf::from) else {
        eprintln!("skipped: set DTK_MIGRATE_HELPER_REPORT to a frozen identification report");
        return;
    };
    let report: IdentificationReport =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let source = report.source.clone();
    let target = report.target.clone();
    let index = ObservationIndex::load_self_contained(report, &source, &target).unwrap();
    assert_eq!(index.report().helper_families.len(), 1_315);
    assert_eq!(index.report().unresolved_target_clusters.len(), 23);
    let orphan = index
        .report()
        .unresolved_target_clusters
        .iter()
        .find(|item| item.start == "0x80356EDC")
        .expect("the historical CTime address run has no source unit in this revision");
    assert_eq!(orphan.left.current_owner, "Kyoto/CFrameDelayedKiller.cpp");
    assert_eq!(orphan.right.current_owner, "dolphin/ai.c");
    assert!(orphan.members.len() >= 2);
    let widget =
        index.report().helper_families.iter().find(|family| {
            family.target_occurrences.iter().any(|item| item.address == "0x802AF844")
        });
    let widget = widget.expect("HeadWidget's small type-ID function must retain body evidence");
    assert!(widget.source_definitions.iter().any(|item| item.unit == "GuiSys/CGuiHeadWidget.cpp"));
    let initializer = index
        .report()
        .helper_families
        .iter()
        .find(|family| family.target_occurrences.iter().any(|item| item.address == "0x80145158"))
        .expect("the opaque PAL occurrence must retain its source initializer name");
    assert!(initializer.signals.contains(&HelperSignal::StaticInitializerName));
    assert!(
        initializer.source_definitions.iter().any(|item| item.name == "__sinit_CPowerBomb_cpp")
    );
}
