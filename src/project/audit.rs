//! Read-only audits of splits that already exist.
//!
//! Every stage looks at proposals; this looks at what is already there, which
//! is the blind spot they share. A unit that owns *some* range counts as
//! represented, so coverage skips it and discovery only ever extends what is
//! there. A badly wrong range is therefore worse than no range at all, because
//! nothing will look for the right one while it stands.
//!
//! Nothing here is acted on. Removing a fragment is only safe when the unit's
//! true range is separately determinable, which these cannot decide.

use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::project::{
    config::{self, DOL_NAME},
    splits::{Splits, parse_range},
};

/// A unit that genuinely shrank between versions keeps the same order of
/// magnitude. Everything observed below half was a misattributed fragment, and
/// the population thins out well before that, so the threshold does not sit on
/// a gradient.
pub const STUNTED_RATIO: f64 = 0.5;

/// A target split far smaller than the same unit's source split.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stunted {
    pub unit: String,
    pub section: String,
    pub claimed_bytes: u64,
    pub expected_bytes: u64,
    pub ratio: f64,
    /// Which module it was found in, when auditing more than the DOL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// The source-version module it was judged against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub against: Option<String>,
}

/// A module the target has not begun splitting, but the source has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsplitModule {
    pub module: String,
    pub against: String,
    pub source_units: usize,
    pub source_code_bytes: u64,
    /// Whether the version compiles any source for it at all.
    pub built: bool,
}

/// A unit one version links into a different module than the other does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocatedUnit {
    pub unit: String,
    pub source_module: String,
    pub target_module: String,
}

/// Total bytes a unit's body claims in one section.
pub fn section_bytes(body: Option<&Vec<String>>, section: &str) -> u64 {
    body.map(|lines| {
        lines
            .iter()
            .filter_map(|line| parse_range(line))
            .filter(|range| range.section == section)
            .map(|range| u64::from(range.end - range.start))
            .sum()
    })
    .unwrap_or(0)
}

/// Units whose target split claims far less than the same unit's source split.
///
/// The usual cause is a range built on a symbol that several source objects
/// define: a weak symbol, a template instantiation, an inline destructor. The
/// two versions' linkers resolve it to different units, so matching the name
/// proved nothing about ownership, and the range landed wherever the other
/// version happened to put that one function.
///
/// Compared against the source version's *split* rather than its compiled
/// object. An object also contains inline functions that never reach the
/// binary, which makes correct splits look stunted — `dolphin/mtx/mtx44.c`
/// claims 5% of its object and 100% of its source split.
pub fn stunted_splits(
    target: &IndexMap<String, Vec<String>>,
    source: &IndexMap<String, Vec<String>>,
    section: &str,
    ratio: f64,
) -> Vec<Stunted> {
    let mut found: Vec<Stunted> = target
        .iter()
        .filter_map(|(unit, body)| {
            let claimed = section_bytes(Some(body), section);
            let expected = section_bytes(source.get(unit), section);
            if claimed == 0 || expected == 0 || claimed as f64 >= expected as f64 * ratio {
                return None;
            }
            Some(Stunted {
                unit: unit.clone(),
                section: section.to_string(),
                claimed_bytes: claimed,
                expected_bytes: expected,
                ratio: claimed as f64 / expected as f64,
                module: None,
                against: None,
            })
        })
        .collect();
    found.sort_by(|a, b| a.ratio.total_cmp(&b.ratio).then_with(|| a.unit.cmp(&b.unit)));
    found
}

/// Parsed split blocks for one module, or empty when it has no splits file.
pub fn read_blocks(path: &Path) -> Result<IndexMap<String, Vec<String>>> {
    if !path.is_file() {
        return Ok(IndexMap::new());
    }
    Ok(Splits::read(path)?.blocks)
}

/// Parsed split blocks for one version's module, the DOL by default.
pub fn load_blocks(
    root: &Path,
    version: &str,
    module: &str,
) -> Result<IndexMap<String, Vec<String>>> {
    read_blocks(&config::find(root, version, module)?.splits)
}

/// Every stunted split across every module, each judged against its
/// counterpart.
///
/// Modules pair by position because their names differ across regions, so each
/// result records both names rather than assuming one.
pub fn audit_modules(
    root: &Path,
    source: &str,
    target: &str,
    section: &str,
) -> Result<Vec<Stunted>> {
    let mut found = Vec::new();
    for (target_module, source_module) in config::pair(root, source, target)? {
        let Some(source_module) = source_module else { continue };
        for mut entry in stunted_splits(
            &read_blocks(&target_module.splits)?,
            &read_blocks(&source_module.splits)?,
            section,
            STUNTED_RATIO,
        ) {
            entry.module = Some(target_module.name.clone());
            entry.against = Some(source_module.name.clone());
            found.push(entry);
        }
    }
    found.sort_by(|a, b| a.ratio.total_cmp(&b.ratio).then_with(|| a.unit.cmp(&b.unit)));
    Ok(found)
}

/// Modules the target has not begun splitting, but the source has.
///
/// A module with no unit splits at all is invisible to every stage: it never
/// appears as a candidate, and nothing reports it as missing. Metroid Prime's
/// PAL NES emulator sits here — its splits file holds only a section header.
pub fn unsplit_modules(root: &Path, source: &str, target: &str) -> Result<Vec<UnsplitModule>> {
    let mut found = Vec::new();
    for (target_module, source_module) in config::pair(root, source, target)? {
        let Some(source_module) = source_module else { continue };
        let target_blocks = read_blocks(&target_module.splits)?;
        let source_blocks = read_blocks(&source_module.splits)?;
        if !target_blocks.is_empty() || source_blocks.is_empty() {
            continue;
        }
        found.push(UnsplitModule {
            module: target_module.name.clone(),
            against: source_module.name.clone(),
            source_units: source_blocks.len(),
            source_code_bytes: source_blocks
                .values()
                .map(|body| section_bytes(Some(body), ".text"))
                .sum(),
            built: target_module.sources().is_dir(),
        });
    }
    Ok(found)
}

/// Units one version links into a different module than the other does.
///
/// A translation unit can move between the DOL and a REL between releases,
/// which makes it look missing in one module and unexplained in another.
/// Reported rather than acted on: whether the move is real or an artefact of
/// one side being unsplit cannot be told from splits alone.
pub fn relocated_units(root: &Path, source: &str, target: &str) -> Result<Vec<RelocatedUnit>> {
    let owners = |version: &str| -> Result<BTreeMap<String, String>> {
        let mut found = BTreeMap::new();
        for module in config::modules(root, version)? {
            for unit in read_blocks(&module.splits)?.keys() {
                found.insert(unit.clone(), module.name.clone());
            }
        }
        Ok(found)
    };
    let source_owners = owners(source)?;
    let target_owners = owners(target)?;
    let mut found: Vec<RelocatedUnit> = target_owners
        .into_iter()
        .filter_map(|(unit, module)| {
            let from = source_owners.get(&unit)?;
            ((from == DOL_NAME) != (module == DOL_NAME)).then(|| RelocatedUnit {
                unit,
                source_module: from.clone(),
                target_module: module,
            })
        })
        .collect();
    found.sort_by(|a, b| a.unit.cmp(&b.unit));
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(entries: &[(&str, u32, u32)]) -> IndexMap<String, Vec<String>> {
        let mut map: IndexMap<String, Vec<String>> = IndexMap::new();
        for (name, start, end) in entries {
            map.entry((*name).to_string())
                .or_default()
                .push(format!("\t{:11} start:0x{start:08X} end:0x{end:08X}", ".text"));
        }
        map
    }

    #[test]
    fn a_unit_claiming_far_less_than_its_source_split_is_stunted() {
        let target = blocks(&[("a.cpp", 0x1000, 0x1010)]);
        let source = blocks(&[("a.cpp", 0x2000, 0x2400)]);
        let found = stunted_splits(&target, &source, ".text", STUNTED_RATIO);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].claimed_bytes, 0x10);
        assert_eq!(found[0].expected_bytes, 0x400);
    }

    #[test]
    fn a_unit_that_merely_shrank_is_not_stunted() {
        let target = blocks(&[("a.cpp", 0x1000, 0x1380)]);
        let source = blocks(&[("a.cpp", 0x2000, 0x2400)]);
        assert!(stunted_splits(&target, &source, ".text", STUNTED_RATIO).is_empty());
    }

    #[test]
    fn a_unit_the_source_version_does_not_split_is_not_judged() {
        let target = blocks(&[("a.cpp", 0x1000, 0x1010)]);
        assert!(stunted_splits(&target, &IndexMap::new(), ".text", STUNTED_RATIO).is_empty());
    }

    #[test]
    fn the_worst_ratio_is_reported_first() {
        let target = blocks(&[("bad.cpp", 0x1000, 0x1004), ("less.cpp", 0x3000, 0x3100)]);
        let source = blocks(&[("bad.cpp", 0x2000, 0x2400), ("less.cpp", 0x4000, 0x4400)]);
        let found = stunted_splits(&target, &source, ".text", STUNTED_RATIO);
        assert_eq!(found[0].unit, "bad.cpp");
    }

    #[test]
    fn several_ranges_in_one_section_are_added_up() {
        let target = blocks(&[("a.cpp", 0x1000, 0x1010), ("a.cpp", 0x1100, 0x1110)]);
        assert_eq!(section_bytes(target.get("a.cpp"), ".text"), 0x20);
    }
}
