//! Opt-in smoke test for compiled-source corroboration against a real project.

use std::{collections::BTreeSet, path::PathBuf};

use dtk_migrate::analysis::{
    object_evidence::{ObjectStatus, ScanStatus, inspect},
    ownership::{IdentificationReport, ObservationIndex},
};

#[test]
fn compiled_widget_body_is_available_without_assigning_its_retail_owner() {
    let (Some(root), Some(report_path)) = (
        std::env::var_os("DTK_MIGRATE_OBJECT_ROOT").map(PathBuf::from),
        std::env::var_os("DTK_MIGRATE_HELPER_REPORT").map(PathBuf::from),
    ) else {
        eprintln!("skipped: set DTK_MIGRATE_OBJECT_ROOT and DTK_MIGRATE_HELPER_REPORT");
        return;
    };
    let report: IdentificationReport =
        serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
    let hash = report
        .target_functions
        .iter()
        .find(|function| function.address == "0x802AF844")
        .unwrap()
        .normalized_body_sha256
        .as_ref()
        .unwrap()
        .clone();
    let unit = "GuiSys/CGuiHeadWidget.cpp".to_string();
    let original_directory = std::env::current_dir().unwrap();
    let evidence =
        inspect(&root, "GM8P01_00", &BTreeSet::from([unit.clone()]), &BTreeSet::from([hash]));
    assert_eq!(std::env::current_dir().unwrap(), original_directory);
    assert_eq!(evidence.status, ScanStatus::Scanned);
    assert_eq!(evidence.objects.len(), 1);
    assert_eq!(evidence.objects[0].status, ObjectStatus::Available);
    assert!(
        evidence.definitions.iter().any(
            |definition| definition.unit == unit && definition.name.contains("GetWidgetTypeID")
        )
    );
}

#[test]
fn sparse_historical_objects_remain_optional_and_canonical() {
    let Some(path) = std::env::var_os("DTK_MIGRATE_OBJECT_REPORT").map(PathBuf::from) else {
        eprintln!("skipped: set DTK_MIGRATE_OBJECT_REPORT to a frozen object-evidence report");
        return;
    };
    let report: IdentificationReport =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let source = report.source.clone();
    let target = report.target.clone();
    let index = ObservationIndex::load_self_contained(report, &source, &target).unwrap();
    let evidence = index.report().object_evidence.as_ref().unwrap();
    assert_eq!(evidence.status, ScanStatus::Scanned);
    assert!(evidence.objects.iter().any(|record| {
        record.unit == "GuiSys/CGuiHeadWidget.cpp" && record.status == ObjectStatus::Available
    }));
    assert!(evidence.objects.iter().any(|record| record.status == ObjectStatus::Missing));
    assert!(!evidence.unmapped_units.is_empty());
    for (address, unit) in [
        ("0x802AF844", "GuiSys/CGuiHeadWidget.cpp"),
        ("0x802AF548", "GuiSys/CGuiGroup.cpp"),
        ("0x802B2374", "GuiSys/CGuiTableGroup.cpp"),
        ("0x80145158", "MetroidPrime/Weapons/CPowerBomb.cpp"),
    ] {
        let family = index
            .report()
            .helper_families
            .iter()
            .find(|family| family.target_occurrences.iter().any(|item| item.address == address))
            .unwrap();
        assert!(family.compiled_definitions.iter().any(|definition| definition.unit == unit));
    }
}
