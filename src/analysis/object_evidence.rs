//! Optional compiled-source evidence for helper families.
//!
//! A compiled definition proves that this *version's source object* contains a
//! body. It does not prove that the linker selected that object or that its
//! function supplied a particular target occurrence. Object paths come from
//! objdiff's `base_path`; `target_path` is the extracted retail object and is
//! deliberately not used as compiled-source evidence.

use std::{
    collections::BTreeSet,
    io::ErrorKind,
    path::{Component, Path},
};

use anyhow::{Result, bail};
use decomp_toolkit::util::elf::process_elf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use typed_path::Utf8NativePath;

use crate::{
    analysis::{callgraph::CallGraph, helpers::body_digest},
    project::report::ObjdiffConfig,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanStatus {
    Scanned,
    MissingObjdiff,
    UnreadableObjdiff,
    InvalidObjdiff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectStatus {
    Available,
    Missing,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub unit: String,
    pub base_path: String,
    pub status: ObjectStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledDefinition {
    pub unit: String,
    pub name: String,
    pub section: String,
    /// Addresses are relative to the compiled ELF section, not retail VAs.
    pub address: String,
    pub end: String,
    pub normalized_body_sha256: String,
    pub weak: bool,
    pub object_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectEvidence {
    pub status: ScanStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objdiff_sha256: Option<String>,
    pub objects: Vec<ObjectRecord>,
    /// Source units without a compiled-object mapping in objdiff.json.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmapped_units: Vec<String>,
    pub definitions: Vec<CompiledDefinition>,
}

impl ObjectEvidence {
    fn unavailable(status: ScanStatus) -> Self {
        Self {
            status,
            objdiff_sha256: None,
            objects: Vec::new(),
            unmapped_units: Vec::new(),
            definitions: Vec::new(),
        }
    }

    pub fn canonicalize(
        &mut self,
        units: &BTreeSet<String>,
        target_hashes: &BTreeSet<String>,
    ) -> Result<()> {
        if (self.status == ScanStatus::Scanned) != self.objdiff_sha256.is_some()
            || self.objdiff_sha256.as_deref().is_some_and(|hash| !valid_digest(hash))
        {
            bail!("Compiled-object evidence has invalid objdiff provenance");
        }
        if self.status != ScanStatus::Scanned
            && (!self.objects.is_empty()
                || !self.definitions.is_empty()
                || !self.unmapped_units.is_empty())
        {
            bail!("Unavailable compiled-object channel contains observations");
        }
        let mut seen = BTreeSet::new();
        let mut available = BTreeSet::new();
        for record in &self.objects {
            let status_and_hash_valid = match record.status {
                ObjectStatus::Available => record.sha256.is_some(),
                ObjectStatus::Missing => record.sha256.is_none(),
                ObjectStatus::Unreadable => true,
            };
            if !units.contains(&record.unit)
                || !safe_relative(&record.base_path)
                || !seen.insert((&record.unit, &record.base_path))
                || record.sha256.as_deref().is_some_and(|hash| !valid_digest(hash))
                || !status_and_hash_valid
            {
                bail!("Compiled-object evidence has an invalid object record");
            }
            if record.status == ObjectStatus::Available {
                available.insert((&record.unit, record.sha256.as_deref().unwrap()));
            }
        }
        let mut definitions = BTreeSet::new();
        for definition in &self.definitions {
            let start = parse_hex(&definition.address);
            let end = parse_hex(&definition.end);
            if !units.contains(&definition.unit)
                || definition.name.is_empty()
                || definition.section.is_empty()
                || !valid_digest(&definition.normalized_body_sha256)
                || !valid_digest(&definition.object_sha256)
                || !target_hashes.contains(&definition.normalized_body_sha256)
                || !available.contains(&(&definition.unit, definition.object_sha256.as_str()))
                || !matches!((start, end), (Some(start), Some(end)) if end > start)
                || !definitions.insert((
                    &definition.unit,
                    &definition.section,
                    &definition.address,
                    &definition.name,
                    &definition.object_sha256,
                ))
            {
                bail!("Compiled-object evidence has an invalid function definition");
            }
        }
        self.objects.sort_by(|a, b| (&a.unit, &a.base_path).cmp(&(&b.unit, &b.base_path)));
        if self.status == ScanStatus::Scanned {
            let mapped: BTreeSet<&str> =
                self.objects.iter().map(|item| item.unit.as_str()).collect();
            self.unmapped_units =
                units.iter().filter(|unit| !mapped.contains(unit.as_str())).cloned().collect();
        }
        self.definitions.sort_by(|a, b| {
            (&a.unit, &a.section, &a.address, &a.name, &a.object_sha256).cmp(&(
                &b.unit,
                &b.section,
                &b.address,
                &b.name,
                &b.object_sha256,
            ))
        });
        Ok(())
    }
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(':')
        && !path.starts_with('\\')
        && Path::new(path).components().all(|component| matches!(component, Component::Normal(_)))
}

fn hex(value: u32) -> String { format!("0x{value:08X}") }

fn parse_hex(value: &str) -> Option<u32> { u32::from_str_radix(value.strip_prefix("0x")?, 16).ok() }

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Scan existing compiled source objects. Missing files and unreadable objects
/// are recorded as unavailable; neither blocks binary-only identification.
/// Only functions matching a known target body digest are retained, so a
/// complete scan does not duplicate the whole compiled-object symbol table.
pub fn inspect(
    root: &Path,
    units: &BTreeSet<String>,
    target_hashes: &BTreeSet<String>,
) -> ObjectEvidence {
    let config_path = root.join("objdiff.json");
    let config_bytes = match std::fs::read(&config_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ObjectEvidence::unavailable(if error.kind() == ErrorKind::NotFound {
                ScanStatus::MissingObjdiff
            } else {
                ScanStatus::UnreadableObjdiff
            });
        }
    };
    let Ok(config) = serde_json::from_slice::<ObjdiffConfig>(&config_bytes) else {
        return ObjectEvidence::unavailable(ScanStatus::InvalidObjdiff);
    };
    let mut evidence = ObjectEvidence {
        status: ScanStatus::Scanned,
        objdiff_sha256: Some(format!("{:x}", Sha256::digest(config_bytes))),
        objects: Vec::new(),
        unmapped_units: Vec::new(),
        definitions: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for entry in config.units {
        if entry.metadata.module_id != 0 {
            continue;
        }
        let Some(unit) = ObjdiffConfig::source_name_of(&entry) else { continue };
        if !units.contains(unit) {
            continue;
        }
        let Some(base_path) = entry.base_path.as_deref() else { continue };
        // An objdiff path outside this checkout cannot be attributed to this
        // build. Leave its unit unmapped rather than emitting a record that
        // canonical loading would have to reject.
        if !safe_relative(base_path) {
            continue;
        }
        if !seen.insert((unit.to_string(), base_path.to_string())) {
            continue;
        }
        let mut record = ObjectRecord {
            unit: unit.to_string(),
            base_path: base_path.to_string(),
            status: ObjectStatus::Unreadable,
            sha256: None,
        };
        let path = root.join(base_path);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                if error.kind() == ErrorKind::NotFound {
                    record.status = ObjectStatus::Missing;
                }
                evidence.objects.push(record);
                continue;
            }
        };
        let digest = format!("{:x}", Sha256::digest(&bytes));
        record.sha256 = Some(digest.clone());
        let Some(path_text) = path.to_str() else {
            evidence.objects.push(record);
            continue;
        };
        let Ok(obj) = process_elf(Utf8NativePath::new(path_text)) else {
            evidence.objects.push(record);
            continue;
        };
        record.status = ObjectStatus::Available;
        for (_, function) in CallGraph::build(&obj).iter() {
            let Some(body_hash) = body_digest(&obj, function) else { continue };
            if !target_hashes.contains(&body_hash) {
                continue;
            }
            let Some(end) = function.address.checked_add(function.size) else { continue };
            evidence.definitions.push(CompiledDefinition {
                unit: unit.to_string(),
                name: obj.symbols[function.symbol].name.clone(),
                section: obj.sections[function.section].name.clone(),
                address: hex(function.address),
                end: hex(end),
                normalized_body_sha256: body_hash,
                weak: obj.symbols[function.symbol].flags.is_weak(),
                object_sha256: digest.clone(),
            });
        }
        evidence.objects.push(record);
    }
    evidence.objects.sort_by(|a, b| (&a.unit, &a.base_path).cmp(&(&b.unit, &b.base_path)));
    let mapped: BTreeSet<&str> = evidence.objects.iter().map(|item| item.unit.as_str()).collect();
    evidence.unmapped_units =
        units.iter().filter(|unit| !mapped.contains(unit.as_str())).cloned().collect();
    evidence.definitions.sort_by(|a, b| {
        (&a.unit, &a.section, &a.address, &a.name, &a.object_sha256).cmp(&(
            &b.unit,
            &b.section,
            &b.address,
            &b.name,
            &b.object_sha256,
        ))
    });
    evidence.definitions.dedup_by(|a, b| {
        (&a.unit, &a.section, &a.address, &a.name, &a.object_sha256)
            == (&b.unit, &b.section, &b.address, &b.name, &b.object_sha256)
    });
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_objdiff_is_an_unavailable_channel() {
        let root = tempfile::tempdir().unwrap();
        let evidence = inspect(root.path(), &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(evidence.status, ScanStatus::MissingObjdiff);
        assert!(evidence.definitions.is_empty());
    }

    #[test]
    fn paths_cannot_escape_the_selected_project_root() {
        assert!(safe_relative("build/PAL/src/A.o"));
        assert!(!safe_relative("../elsewhere/A.o"));
        assert!(!safe_relative("C:/elsewhere/A.o"));
    }

    #[test]
    fn a_compiled_definition_must_bind_to_an_available_object_and_target_body() {
        let object_hash = "a".repeat(64);
        let body_hash = "b".repeat(64);
        let mut evidence = ObjectEvidence {
            status: ScanStatus::Scanned,
            objdiff_sha256: Some("c".repeat(64)),
            objects: vec![ObjectRecord {
                unit: "A.cpp".into(),
                base_path: "build/PAL/src/A.o".into(),
                status: ObjectStatus::Available,
                sha256: Some(object_hash.clone()),
            }],
            unmapped_units: Vec::new(),
            definitions: vec![CompiledDefinition {
                unit: "A.cpp".into(),
                name: "helper".into(),
                section: ".text".into(),
                address: "0x00000000".into(),
                end: "0x00000020".into(),
                normalized_body_sha256: body_hash.clone(),
                weak: true,
                object_sha256: object_hash,
            }],
        };
        let units = BTreeSet::from(["A.cpp".into(), "B.cpp".into()]);
        let targets = BTreeSet::from([body_hash]);
        evidence.canonicalize(&units, &targets).unwrap();
        assert_eq!(evidence.unmapped_units, ["B.cpp"]);
        evidence.objects[0].status = ObjectStatus::Missing;
        assert!(evidence.canonicalize(&units, &targets).is_err());
    }
}
