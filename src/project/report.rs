//! The two JSON files a build leaves behind: the objdiff progress report and
//! the objdiff project configuration.
//!
//! Only the fields the stages actually read are modelled. Everything else is
//! carried through untouched, because these files are generated on every build
//! and nothing here ever writes one.
//!
//! The three measurements they carry are easy to confuse and mean different
//! things:
//!
//! - `matched_code` is a comparison result — bytes in functions objdiff calls
//!   matching. It says nothing about whether the source compiles.
//! - `complete_code` is a build *setting*: bytes in units `configure.py`
//!   enables. It is not a byte comparison.
//! - `fuzzy_match_percent` on a section is a comparison result too, and an
//!   empty section's score is about our symbol annotations rather than about
//!   any bytes in the binary.

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// `configure.py`'s `src_dir` overrides.
///
/// Most units live under the default `src/`, but SDK-derived modules override
/// it. `report.json`'s `metadata.source_path` carries this prefix while
/// `splits.txt` and the match proposals never do. Get this wrong and every
/// SDK-sourced candidate (`dolphin/*`, `musyx/*`, `runtime/*`) silently looks
/// absent from the rebuilt report even when it built and matched perfectly.
const SOURCE_ROOTS: [&str; 3] = ["extern/musyx/src/", "extern/sdk/", "src/"];

/// The unit name the rest of the tool uses, given a report's `source_path`.
pub fn strip_source_root(path: &str) -> &str {
    SOURCE_ROOTS.iter().find_map(|root| path.strip_prefix(root)).unwrap_or(path)
}

/// `build/<version>/report.json`, as written by `objdiff-cli report generate`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Report {
    #[serde(default)]
    pub measures: Measures,
    #[serde(default)]
    pub units: Vec<Unit>,
    /// Everything else the report carries, kept so a round-trip is lossless.
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Measures {
    /// Bytes in functions the comparison calls matching. A number in a string
    /// in some versions of the format, so read leniently.
    #[serde(default, deserialize_with = "lenient_u64")]
    pub matched_code: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub total_code: u64,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub complete_code: u64,
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Unit {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub measures: Measures,
    #[serde(default)]
    pub metadata: UnitMetadata,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UnitMetadata {
    #[serde(default)]
    pub source_path: Option<String>,
    /// Whether `configure.py` enables this unit's compiled object. A build
    /// setting, not a measurement.
    #[serde(default)]
    pub complete: Option<bool>,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub module_id: u64,
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Section {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub fuzzy_match_percent: f32,
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

/// Sections that hold no bytes.
///
/// They exist as a name, an address and a size, so a fuzzy match percent over
/// one of them scores our symbol annotations rather than anything in the binary.
/// dtk sizes a symbol to the gap before the next one, which is how `GXMisc.c`'s
/// `FinishQueue` came to be 0xC in PAL and 0x8 in NTSC — one guessed size, a 75%
/// section score, and a unit whose code is a byte-identical match was never
/// offered as a candidate at all.
pub const EMPTY_SECTIONS: [&str; 3] = [".bss", ".sbss", ".sbss2"];

impl Unit {
    /// The unit name the rest of the tool uses, or `None` for a unit with no
    /// source file.
    pub fn source_name(&self) -> Option<&str> {
        self.metadata.source_path.as_deref().filter(|p| !p.is_empty()).map(strip_source_root)
    }

    pub fn matched_code(&self) -> u64 { self.measures.matched_code }

    /// True when every section that actually holds bytes is a full match.
    ///
    /// A unit with nothing but empty sections answers false: there is no
    /// evidence either way, and this is the gate that decides what is worth a
    /// build.
    pub fn matches_on_content(&self) -> bool {
        let mut sections =
            self.sections.iter().filter(|s| !EMPTY_SECTIONS.contains(&s.name.as_str())).peekable();
        sections.peek().is_some() && sections.all(|s| s.fuzzy_match_percent == 100.0)
    }
}

impl Report {
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("Failed to parse {}", path.display()))
    }

    /// Units that belong to the DOL and have a source file, keyed by unit name.
    ///
    /// A REL's units carry a non-zero `module_id`; the stages that gate on a DOL
    /// build cannot say anything about them.
    pub fn by_source_name(&self) -> BTreeMap<&str, &Unit> {
        self.units
            .iter()
            .filter(|unit| unit.metadata.module_id == 0)
            .filter_map(|unit| Some((unit.source_name()?, unit)))
            .collect()
    }
}

/// `objdiff.json`, the comparison configuration the build generates.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObjdiffConfig {
    #[serde(default)]
    pub units: Vec<ObjdiffUnit>,
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObjdiffUnit {
    #[serde(default)]
    pub name: String,
    /// The object extracted from the shipped binary.
    #[serde(default)]
    pub target_path: Option<String>,
    /// The object compiled from source.
    #[serde(default)]
    pub base_path: Option<String>,
    #[serde(default)]
    pub metadata: UnitMetadata,
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

impl ObjdiffConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("Failed to parse {}", path.display()))
    }

    pub fn source_name_of(unit: &ObjdiffUnit) -> Option<&str> {
        unit.metadata.source_path.as_deref().filter(|p| !p.is_empty()).map(strip_source_root)
    }
}

/// Reads a number that the format sometimes writes as a JSON string.
fn lenient_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where D: serde::Deserializer<'de> {
    use serde::de::Error;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => Ok(number.as_u64().unwrap_or(0)),
        serde_json::Value::String(text) => text.parse().map_err(D::Error::custom),
        serde_json::Value::Null => Ok(0),
        other => Err(D::Error::custom(format!("expected a number, found {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(sections: &[(&str, f32)]) -> Unit {
        serde_json::from_value(serde_json::json!({
            "name": "u",
            "sections": sections
                .iter()
                .map(|(name, percent)| serde_json::json!({"name": name, "fuzzy_match_percent": percent}))
                .collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    #[test]
    fn a_source_root_prefix_is_stripped_from_a_unit_name() {
        assert_eq!(strip_source_root("src/MetroidPrime/main.cpp"), "MetroidPrime/main.cpp");
        assert_eq!(strip_source_root("extern/sdk/dolphin/gx/GXMisc.c"), "dolphin/gx/GXMisc.c");
        assert_eq!(strip_source_root("extern/musyx/src/runtime/synth.c"), "runtime/synth.c");
    }

    #[test]
    fn a_path_under_no_known_root_is_left_alone() {
        assert_eq!(strip_source_root("asm/whatever.s"), "asm/whatever.s");
    }

    #[test]
    fn every_content_section_matching_qualifies() {
        assert!(unit(&[(".text", 100.0), (".data", 100.0)]).matches_on_content());
    }

    #[test]
    fn a_content_section_short_of_a_full_match_does_not() {
        assert!(!unit(&[(".text", 100.0), (".data", 99.0)]).matches_on_content());
    }

    #[test]
    fn an_empty_section_cannot_disqualify_a_matching_unit() {
        // GXMisc.c: .text is a byte-identical match, .sbss scores 75% because one
        // symbol there carries a size dtk guessed from the gap to the next one.
        assert!(unit(&[(".text", 100.0), (".sbss", 75.0)]).matches_on_content());
        for name in EMPTY_SECTIONS {
            assert!(unit(&[(".text", 100.0), (name, 0.0)]).matches_on_content(), "{name}");
        }
    }

    #[test]
    fn a_unit_of_nothing_but_empty_sections_is_not_evidence() {
        assert!(!unit(&[(".bss", 100.0)]).matches_on_content());
        assert!(!unit(&[]).matches_on_content());
    }

    #[test]
    fn a_measure_written_as_a_string_still_reads_as_a_number() {
        let report: Report = serde_json::from_str(
            r#"{"measures": {"matched_code": "1234", "complete_code": 56}, "units": []}"#,
        )
        .unwrap();
        assert_eq!(report.measures.matched_code, 1234);
        assert_eq!(report.measures.complete_code, 56);
    }

    #[test]
    fn units_are_keyed_by_source_name_and_rel_units_are_left_out() {
        let report: Report = serde_json::from_str(
            r#"{"units": [
                {"name": "a", "metadata": {"source_path": "src/a.cpp"}},
                {"name": "b", "metadata": {"source_path": "src/b.cpp", "module_id": 3}},
                {"name": "c", "metadata": {}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(report.by_source_name().into_keys().collect::<Vec<&str>>(), ["a.cpp"]);
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let text = r#"{"measures":{"matched_code":1},"units":[],"version":"3.7.0"}"#;
        let report: Report = serde_json::from_str(text).unwrap();
        let back = serde_json::to_value(&report).unwrap();
        assert_eq!(back["version"], "3.7.0");
    }
}
