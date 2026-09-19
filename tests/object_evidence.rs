//! Opt-in smoke test for compiled-source corroboration against a real project.

use std::{collections::BTreeSet, path::PathBuf, time::Instant};

use dtk_migrate::{
    analysis::{
        matching::MatchTarget,
        object_evidence::{
            BuildFreshness, ObjectStatus, ScanStatus, capture_target_references,
            emitted_owner_resolutions, inspect, order_matches, relocation_matches,
            relocation_placements, target_image_digest,
        },
        ownership::{IDENTIFICATION_SCHEMA, IdentificationReport, ObservationIndex},
    },
    project::analyze::load_analyzed,
};
use typed_path::Utf8NativePath;

#[test]
fn historical_pal_get_generator_desc_is_distinguished_without_a_source_fix() {
    let Some(path) = std::env::var_os("DTK_MIGRATE_HISTORICAL_COMPLETE_REPORT") else {
        eprintln!("skipped: set DTK_MIGRATE_HISTORICAL_COMPLETE_REPORT");
        return;
    };
    let report: IdentificationReport =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let canonical =
        ObservationIndex::load_self_contained(report.clone(), &report.source, &report.target)
            .unwrap();
    let evidence = report.object_evidence.as_ref().unwrap();
    assert_eq!(evidence.unscanned_configured_units, 10);
    assert_eq!(evidence.unmapped_units.len(), 23);
    let units = report.units.iter().map(|item| item.unit.clone()).collect();
    let placements = relocation_placements(evidence, &units, &report.target_functions);
    assert_eq!(
        canonical.report().object_evidence.as_ref().unwrap().relocation_placements,
        placements
    );
    let electric = placements.iter().find(|item| item.target_address == "0x803485F4").unwrap();
    assert_eq!(electric.unit, "Kyoto/Particles/CParticleElectricDataFactory.cpp");
    assert_eq!(
        electric.object_sha256,
        "0fd8081879b9034ba454b26a6cec11313468dd2eec3c19114947e0bf60257180"
    );
    assert_eq!(electric.distinctive_offset, 32);
    assert_eq!(
        electric.endpoint_body_sha256,
        "3835b7ca0b44643b318fe7fba33724ee362bae3ac318096aa4256df7252e4f49"
    );
    assert_eq!(electric.excluded_competitors.len(), 2);
    assert_eq!(
        electric
            .excluded_competitors
            .iter()
            .map(|item| (item.unit.as_str(), item.target_address.as_str()))
            .collect::<Vec<_>>(),
        [
            ("Kyoto/Particles/CParticleSwooshDataFactory.cpp", "0x803188A8"),
            ("Weapons/CProjectileWeaponDataFactory.cpp", "0x8029E2BC"),
        ]
    );
    assert!(!electric.inventory_complete);
    assert!(evidence.emitted_owners.is_empty());
}

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
    assert!(!evidence.objects[0].functions.is_empty());
    assert!(
        evidence.definitions.iter().any(
            |definition| definition.unit == unit && definition.name.contains("GetWidgetTypeID")
        )
    );
}

#[test]
fn frozen_sparse_objects_expose_immediate_order_without_assigning_an_owner() {
    let (Some(root), Some(report_path)) = (
        std::env::var_os("DTK_MIGRATE_FROZEN_OBJECT_ROOT").map(PathBuf::from),
        std::env::var_os("DTK_MIGRATE_OBJECT_REPORT").map(PathBuf::from),
    ) else {
        eprintln!("skipped: set DTK_MIGRATE_FROZEN_OBJECT_ROOT and DTK_MIGRATE_OBJECT_REPORT");
        return;
    };
    let report: IdentificationReport =
        serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
    let saved = report.object_evidence.as_ref().unwrap();
    let expected: Vec<_> =
        saved.objects.iter().filter(|record| record.status == ObjectStatus::Available).collect();
    let units = expected.iter().map(|record| record.unit.clone()).collect();
    let hashes = report
        .target_functions
        .iter()
        .filter(|function| function.current_owner.is_none() || function.owner_autogenerated)
        .filter_map(|function| function.normalized_body_sha256.clone())
        .collect();
    let mut evidence = inspect(&root, "GM8P01_00", &units, &hashes);
    assert_eq!(evidence.status, ScanStatus::Scanned);
    for record in expected {
        let scanned = evidence.objects.iter().find(|item| item.unit == record.unit).unwrap();
        assert_eq!(scanned.status, ObjectStatus::Available);
        assert_eq!(scanned.sha256, record.sha256);
    }
    evidence.canonicalize(&units, &hashes, true).unwrap();
    let matches = order_matches(&evidence, &report.target_functions, &report.attributions);
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().any(|item| {
        item.unit == "GuiSys/CGuiHeadWidget.cpp"
            && item.target_address == "0x802AF844"
            && item.before.as_ref().is_some_and(|before| before.target_address == "0x802AF7E4")
    }));
    assert!(matches.iter().any(|item| {
        item.unit == "MetroidPrime/Weapons/CPowerBomb.cpp"
            && item.target_address == "0x80144E10"
            && item.before.as_ref().is_some_and(|before| before.target_address == "0x80144DA0")
    }));
    assert!(matches.iter().all(|item| {
        !item.before.as_ref().is_some_and(|before| before.independently_attributed)
            && !item.after.as_ref().is_some_and(|after| after.independently_attributed)
    }));
    let source_units = report.units.iter().map(|unit| unit.unit.clone()).collect();
    assert!(
        emitted_owner_resolutions(
            &evidence,
            &source_units,
            &report.source_functions,
            &report.target_functions,
            &report.attributions,
        )
        .is_empty()
    );
}

#[test]
fn frozen_sparse_objects_correlate_references_without_assigning_an_owner() {
    let (Some(root), Some(report_path), Some(config_path)) = (
        std::env::var_os("DTK_MIGRATE_FROZEN_OBJECT_ROOT").map(PathBuf::from),
        std::env::var_os("DTK_MIGRATE_OBJECT_REPORT").map(PathBuf::from),
        std::env::var_os("DTK_MIGRATE_TARGET_CONFIG").map(PathBuf::from),
    ) else {
        eprintln!("skipped: set frozen object root, report and target config");
        return;
    };
    let mut report: IdentificationReport =
        serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
    let expected: Vec<_> = report
        .object_evidence
        .as_ref()
        .unwrap()
        .objects
        .iter()
        .filter(|record| record.status == ObjectStatus::Available)
        .collect();
    let units = expected.iter().map(|record| record.unit.clone()).collect();
    let hashes = report
        .target_functions
        .iter()
        .filter_map(|function| function.normalized_body_sha256.clone())
        .collect();
    let mut evidence = inspect(&root, "GM8P01_00", &units, &hashes);
    evidence.canonicalize(&units, &hashes, true).unwrap();
    assert!(evidence.build_graph_sha256.is_some());
    for record in expected {
        let scanned = evidence.objects.iter().find(|item| item.unit == record.unit).unwrap();
        assert_eq!(scanned.sha256, record.sha256);
        assert_eq!(scanned.build_freshness, BuildFreshness::Clean);
        assert!(scanned.compiler.is_some());
        assert!(scanned.c_flags.is_some());
        assert!(scanned.c_flags_sha256.is_some());
    }
    let config = Utf8NativePath::new(config_path.to_str().unwrap());
    let (_, obj) = load_analyzed(config, None, "--target-root").unwrap();
    let target = MatchTarget::new(config.to_string(), obj);
    evidence.target_image_sha256 = Some(target_image_digest(&target));
    evidence.target_references =
        capture_target_references(&target, &report.target_functions, &evidence.definitions);
    evidence.canonicalize_target_references(&report.target_functions).unwrap();
    let matches = relocation_matches(&evidence, &report.target_functions, &report.attributions);
    assert_eq!(matches.len(), 8);
    assert!(matches.iter().any(|item| {
        item.unit == "GuiSys/CGuiGroup.cpp"
            && item.target_address == "0x802AD3DC"
            && item.correlated.iter().any(|reference| {
                reference.compiled_target == "__vt__9CGuiGroup"
                    && reference.basis
                        == dtk_migrate::analysis::object_evidence::ReferenceBasis::NamedSymbol
            })
    }));
    assert!(matches.iter().any(|item| {
        item.unit == "GuiSys/CGuiHeadWidget.cpp" && item.target_address == "0x802ADC9C"
    }));
    assert!(matches.iter().any(|item| {
        item.unit == "MetroidPrime/Weapons/CPowerBomb.cpp" && item.target_address == "0x8003B8B0"
    }));
    evidence.relocation_matches = matches.clone();
    evidence.relocation_matches[0].unit = "forged.cpp".into();
    report.schema = IDENTIFICATION_SCHEMA;
    report.object_evidence = Some(evidence);
    let source = report.source.clone();
    let target_name = report.target.clone();
    let index = ObservationIndex::load_self_contained(report, &source, &target_name).unwrap();
    assert_eq!(index.report().object_evidence.as_ref().unwrap().relocation_matches, matches);
    let saved = serde_json::to_vec(index.report()).unwrap();
    let reloaded = ObservationIndex::load_self_contained(
        serde_json::from_slice(&saved).unwrap(),
        &source,
        &target_name,
    )
    .unwrap();
    assert_eq!(reloaded.digest(), index.digest());
}

#[test]
fn a_full_object_inventory_remains_canonical_and_binary_only_fallback_exists() {
    let (Some(root), Some(report_path), Some(config_path)) = (
        std::env::var_os("DTK_MIGRATE_FULL_OBJECT_ROOT").map(PathBuf::from),
        std::env::var_os("DTK_MIGRATE_HELPER_REPORT").map(PathBuf::from),
        std::env::var_os("DTK_MIGRATE_TARGET_CONFIG").map(PathBuf::from),
    ) else {
        eprintln!("skipped: set full object root, helper report and target config");
        return;
    };
    let mut report: IdentificationReport =
        serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
    let mut binary_only_report = report.clone();
    binary_only_report.object_evidence = None;
    let units = report.units.iter().map(|unit| unit.unit.clone()).collect();
    let hashes = report
        .target_functions
        .iter()
        .filter_map(|function| function.normalized_body_sha256.clone())
        .collect();
    let mut evidence = inspect(&root, "GM8P01_00", &units, &hashes);
    assert_eq!(evidence.status, ScanStatus::Scanned);
    evidence.canonicalize(&units, &hashes, true).unwrap();
    let available =
        evidence.objects.iter().filter(|record| record.status == ObjectStatus::Available).count();
    let clean = evidence
        .objects
        .iter()
        .filter(|record| record.build_freshness == BuildFreshness::Clean)
        .count();
    let functions: usize = evidence.objects.iter().map(|record| record.functions.len()).sum();
    let matches = order_matches(&evidence, &report.target_functions, &report.attributions);
    let independent = matches
        .iter()
        .filter(|item| {
            item.before.as_ref().is_some_and(|before| before.independently_attributed)
                || item.after.as_ref().is_some_and(|after| after.independently_attributed)
        })
        .count();
    eprintln!(
        "available={available} ninja_clean={clean} functions={functions} definitions={} order_matches={} independent={} bytes={}",
        evidence.definitions.len(),
        matches.len(),
        independent,
        serde_json::to_vec(&evidence).unwrap().len(),
    );
    assert!(available > 100);
    assert!(functions > available);
    evidence.order_matches = matches;
    let config = Utf8NativePath::new(config_path.to_str().unwrap());
    let (_, obj) = load_analyzed(config, None, "--target-root").unwrap();
    let target = MatchTarget::new(config.to_string(), obj);
    evidence.target_image_sha256 = Some(target_image_digest(&target));
    evidence.target_references =
        capture_target_references(&target, &report.target_functions, &evidence.definitions);
    evidence.canonicalize_target_references(&report.target_functions).unwrap();
    let placed = emitted_owner_resolutions(
        &evidence,
        &units,
        &report.source_functions,
        &report.target_functions,
        &report.attributions,
    );
    eprintln!(
        "object owner placements={} unscanned_configured={} unmapped_source_units={}",
        placed.len(),
        evidence.unscanned_configured_units,
        evidence.unmapped_units.len(),
    );
    if evidence.unscanned_configured_units != 0 || !evidence.unmapped_units.is_empty() {
        assert!(placed.is_empty());
    }
    let first_correlation = Instant::now();
    evidence.relocation_matches =
        relocation_matches(&evidence, &report.target_functions, &report.attributions);
    let first_elapsed = first_correlation.elapsed();
    let cached_correlation = Instant::now();
    let cached = relocation_matches(&evidence, &report.target_functions, &report.attributions);
    let cached_elapsed = cached_correlation.elapsed();
    assert_eq!(cached, evidence.relocation_matches);
    eprintln!(
        "target reference functions={} discriminating relocation matches={} first={first_elapsed:?} cached={cached_elapsed:?}",
        evidence.target_references.len(),
        evidence.relocation_matches.len(),
    );
    report.schema = IDENTIFICATION_SCHEMA;
    binary_only_report.schema = report.schema;
    report.object_evidence = Some(evidence);
    let source = report.source.clone();
    let target = report.target.clone();
    let binary_only =
        ObservationIndex::load_self_contained(binary_only_report, &source, &target).unwrap();
    let first = ObservationIndex::load_self_contained(report, &source, &target).unwrap();
    assert_eq!(
        serde_json::to_value(&first.report().attributions).unwrap(),
        serde_json::to_value(&binary_only.report().attributions).unwrap(),
    );
    let saved = serde_json::to_vec(first.report()).unwrap();
    let reloaded = ObservationIndex::load_self_contained(
        serde_json::from_slice(&saved).unwrap(),
        &source,
        &target,
    )
    .unwrap();
    assert_eq!(reloaded.digest(), first.digest());
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
