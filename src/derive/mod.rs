//! Deriving target symbol names by comparing a unit's two compiled objects.
//!
//! For every unit that has both a compiled source object and an object
//! extracted from the target binary, four methods propose names. Both objects
//! already exist after a normal build, so this costs a few seconds and no
//! compilation of its own.
//!
//! This is a different signal from cross-version matching, which compares two
//! versions of the same binary and so is limited to whatever survived between
//! them. Here the source object states what the unit is *supposed* to contain,
//! which keeps every comparison inside one translation unit and rests it on
//! names the build already agrees on.
//!
//! Nothing is written without being asked. A proposal is dropped unless every
//! unit with an opinion agrees, the symbol exists, and the new name is not
//! already taken at another address.

pub mod body;
pub mod objects;
pub mod ordering;
pub mod propose;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use anyhow::{Context, Result, bail};
use objdiff_core::diff::DiffSide;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    derive::{
        objects::{Compiled, is_usable_source_name},
        propose::{Limits, Proposal, Tier},
    },
    project::{
        config::{self, DOL_NAME},
        splits::{Splits, parse_range},
    },
};

static SYMBOL_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\S+) = (\.\w+):0x([0-9A-Fa-f]+);").unwrap());
static SYMBOL_SIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\S+) = \.\w+:0x[0-9A-Fa-f]+;.*\bsize:0x([0-9A-Fa-f]+)").unwrap()
});

/// Where a symbol lives, which is what decides whether a rename is applicable.
pub type Placement = (String, u64);

/// Name to `(section, address)` for every symbol in a symbols file.
pub fn load_symbols(path: &Path) -> Result<BTreeMap<String, Placement>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let captures = SYMBOL_LINE.captures(line.trim())?;
            let address = u64::from_str_radix(captures.get(3)?.as_str(), 16).ok()?;
            Some((
                captures.get(1)?.as_str().to_string(),
                (captures.get(2)?.as_str().to_string(), address),
            ))
        })
        .collect())
}

/// Name to size for every sized symbol in a symbols file.
pub fn load_symbol_sizes(path: &Path) -> BTreeMap<String, u64> {
    let Ok(text) = std::fs::read_to_string(path) else { return BTreeMap::new() };
    text.lines()
        .filter_map(|line| {
            let captures = SYMBOL_SIZE.captures(line.trim())?;
            let size = u64::from_str_radix(captures.get(2)?.as_str(), 16).ok()?;
            Some((captures.get(1)?.as_str().to_string(), size))
        })
        .collect()
}

/// A unit's identity, independent of whether it is named `.c`, `.cpp` or `.o`.
pub fn unit_key(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    match normalized.rfind('.') {
        Some(index) if !normalized[index..].contains('/') => normalized[..index].to_string(),
        _ => normalized,
    }
}

/// Answers which unit's split contains an address, by section and address.
pub struct Owners {
    spans: Vec<(String, u32, u32, String)>,
}

impl Owners {
    pub fn read(root: &Path, version: &str, module: &str) -> Result<Self> {
        let splits = Splits::read(&config::find(root, version, module)?.splits)?;
        let spans = splits
            .blocks
            .iter()
            .flat_map(|(name, lines)| lines.iter().map(move |line| (name, line)))
            .filter_map(|(name, line)| {
                let range = parse_range(line)?;
                Some((range.section, range.start, range.end, unit_key(name)))
            })
            .collect();
        Ok(Self { spans })
    }

    pub fn at(&self, section: &str, address: u64) -> Option<&str> {
        self.spans
            .iter()
            .find(|(span_section, start, end, _)| {
                span_section == section && u64::from(*start) <= address && address < u64::from(*end)
            })
            .map(|(_, _, _, name)| name.as_str())
    }
}

/// Why a proposal was not kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejected {
    pub old: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub defined_in: Vec<String>,
}

/// A misplaced name, and the rename it is standing in the way of.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correction {
    pub unit: String,
    pub address_named: String,
    pub should_be: String,
    pub contested: bool,
    pub reference_size: Option<u64>,
    pub percent: Option<f32>,
    pub own_percent: Option<f32>,
    pub carried_size: Option<u64>,
    pub namesake_size: Option<u64>,
    /// Which renames are waiting for this name to be freed.
    pub frees_name_for: Vec<String>,
}

/// Everything one derivation run concluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub units: usize,
    pub proposed: usize,
    pub accepted: BTreeMap<String, Proposal>,
    pub rejected: Vec<Rejected>,
    pub failures: Vec<Failure>,
    pub corrections: Vec<Correction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub unit: String,
    pub error: String,
}

/// Keeps only unambiguous renames that a symbols file can actually apply.
pub fn resolve(
    proposals: &[Proposal],
    symbols: &BTreeMap<String, Placement>,
    defined_by: &BTreeMap<String, BTreeSet<String>>,
    owners: Option<&Owners>,
) -> (BTreeMap<String, Proposal>, Vec<Rejected>) {
    let mut by_old: BTreeMap<&str, Vec<&Proposal>> = BTreeMap::new();
    for proposal in proposals {
        by_old.entry(proposal.old.as_str()).or_default().push(proposal);
    }

    let mut accepted: BTreeMap<String, Proposal> = BTreeMap::new();
    let mut rejected: Vec<Rejected> = Vec::new();

    for (old, group) in by_old {
        // Where two methods disagree, the one that observed the function wins.
        let best = group.iter().map(|p| p.strength()).max().unwrap_or(0);
        let group: Vec<&&Proposal> = group.iter().filter(|p| p.strength() == best).collect();
        let names: BTreeSet<&str> = group.iter().map(|p| p.new.as_str()).collect();
        if names.len() > 1 {
            rejected.push(Rejected {
                old: old.to_string(),
                reason: "units disagree".into(),
                new: None,
                names: names.into_iter().map(String::from).collect(),
                defined_in: Vec::new(),
            });
            continue;
        }
        let new = names.into_iter().next().unwrap_or_default().to_string();
        let Some(placement) = symbols.get(old) else {
            rejected.push(Rejected {
                old: old.to_string(),
                reason: "not in symbols file".into(),
                new: Some(new),
                names: Vec::new(),
                defined_in: Vec::new(),
            });
            continue;
        };
        // Renaming onto a name that already exists elsewhere would put two
        // symbols with one name in the file, which silently breaks whichever
        // reference resolves to the wrong address.
        if symbols.get(&new).is_some_and(|other| other != placement) {
            rejected.push(Rejected {
                old: old.to_string(),
                reason: "name already taken".into(),
                new: Some(new),
                names: Vec::new(),
                defined_in: Vec::new(),
            });
            continue;
        }
        // A name a source object defines is exported by that unit's compiled
        // object whenever the unit is linked from source. Giving the same name
        // to an address outside that unit puts it in two linked objects, and
        // the linker rejects that outright — the one failure here that is loud
        // rather than silent, so it is worth refusing up front. The symbols
        // file cannot answer this: it describes the extracted objects, and the
        // competing definition comes from the compiler.
        if let (Some(owners), Some(claimants)) = (owners, defined_by.get(&new)) {
            let here = owners.at(&placement.0, placement.1);
            if !here.is_some_and(|unit| claimants.contains(unit)) {
                rejected.push(Rejected {
                    old: old.to_string(),
                    reason: "name defined by another unit's source".into(),
                    new: Some(new),
                    names: Vec::new(),
                    defined_in: claimants.iter().take(3).cloned().collect(),
                });
                continue;
            }
        }
        let mut chosen = group
            .iter()
            .min_by_key(|p| p.tier)
            .map(|p| (**p).clone())
            .unwrap_or_else(|| (*group[0]).clone());
        chosen.new = new;
        chosen.units =
            group.iter().map(|p| p.unit.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        accepted.insert(old.to_string(), chosen);
    }

    // Two addresses claiming one name is the same collision seen from the other
    // side, and neither claim is more credible than the other.
    let mut by_new: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (old, proposal) in &accepted {
        by_new.entry(proposal.new.clone()).or_default().push(old.clone());
    }
    for (new, olds) in by_new {
        if olds.len() > 1 {
            for old in olds {
                accepted.remove(&old);
                rejected.push(Rejected {
                    old,
                    reason: "name claimed by several symbols".into(),
                    new: Some(new.clone()),
                    names: Vec::new(),
                    defined_in: Vec::new(),
                });
            }
        }
    }
    rejected.sort_by(|a, b| a.old.cmp(&b.old).then_with(|| a.reason.cmp(&b.reason)));
    (accepted, rejected)
}

/// Units that have both a compiled source object and an extracted one.
pub fn unit_objects(
    root: &Path,
    version: &str,
    module: &str,
) -> Result<Vec<(String, PathBuf, PathBuf)>> {
    let selected = config::find(root, version, module)?;
    let (source_root, target_root) = (selected.sources(), selected.extracted());
    if !source_root.is_dir() {
        // A REL the version does not build has an `obj/` but never a `src/`, so
        // there is nothing to compare against and the reason is worth naming.
        let extra = if selected.is_dol {
            String::new()
        } else {
            format!("; {version} may not build the '{module}' module")
        };
        bail!("No compiled source objects under {}{extra}", source_root.display());
    }
    let mut units = Vec::new();
    for entry in walkdir::WalkDir::new(&source_root).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() || entry.path().extension().is_none_or(|e| e != "o") {
            continue;
        }
        let relative = entry.path().strip_prefix(&source_root)?;
        let target = target_root.join(relative);
        if target.is_file() {
            units.push((
                relative.to_string_lossy().replace('\\', "/"),
                entry.path().to_path_buf(),
                target,
            ));
        }
    }
    Ok(units)
}

/// Everything one unit's object pair implies.
fn one_unit(
    entry: &(String, PathBuf, PathBuf),
    limits: &Limits,
    reference: Option<&BTreeMap<String, u64>>,
) -> (Vec<Proposal>, Option<Failure>, String, BTreeSet<String>) {
    let (unit, source_path, target_path) = entry;
    let read = || -> Result<(Compiled, Compiled)> {
        Ok((
            Compiled::read(source_path, DiffSide::Base)?,
            Compiled::read(target_path, DiffSide::Target)?,
        ))
    };
    let (source, target) = match read() {
        Ok(pair) => pair,
        Err(error) => {
            return (
                Vec::new(),
                Some(Failure { unit: unit.clone(), error: format!("{error:#}") }),
                unit_key(unit),
                BTreeSet::new(),
            );
        }
    };

    let mut found = propose::positional(&source, &target, unit);
    match propose::by_body(unit, &target, &source, limits) {
        Ok(more) => found.extend(more),
        Err(error) => {
            return (
                found,
                Some(Failure { unit: unit.clone(), error: format!("{error:#}") }),
                unit_key(unit),
                BTreeSet::new(),
            );
        }
    }
    if let Ok(more) = propose::misplaced(unit, &target, &source, limits, reference) {
        found.extend(more);
    }

    let defines: BTreeSet<String> = source
        .functions
        .iter()
        .filter(|f| is_usable_source_name(&f.name))
        .map(|f| f.name.clone())
        .collect();
    (found, None, unit_key(unit), defines)
}

/// What a derivation run was asked to do.
#[derive(Debug, Clone)]
pub struct Request {
    pub root: PathBuf,
    pub version: String,
    pub module: String,
    pub only: Vec<String>,
    pub limit: Option<usize>,
    pub limits: Limits,
    /// Another version's symbols, used to tell a misplaced name apart from a
    /// unit whose source has not been matched yet.
    pub reference: Option<String>,
}

impl Request {
    pub fn new(root: PathBuf, version: String) -> Self {
        Self {
            root,
            version,
            module: DOL_NAME.to_string(),
            only: Vec::new(),
            limit: None,
            limits: Limits::default(),
            reference: None,
        }
    }
}

/// Collects, reconciles and reports every rename the object pairs imply.
pub fn derive(request: &Request) -> Result<Report> {
    let mut units = unit_objects(&request.root, &request.version, &request.module)?;
    if !request.only.is_empty() {
        let wanted: BTreeSet<&str> = request.only.iter().map(String::as_str).collect();
        units.retain(|(name, _, _)| {
            wanted.contains(name.as_str()) || wanted.contains(unit_key(name).as_str())
        });
    }
    if let Some(limit) = request.limit {
        units.truncate(limit);
    }

    let reference = request
        .reference
        .as_ref()
        .map(|version| {
            Ok::<_, anyhow::Error>(load_symbol_sizes(
                &config::find(&request.root, version, &request.module)?.symbols,
            ))
        })
        .transpose()?;

    // Each unit is independent, and the work is arithmetic over two small
    // objects, so this parallelises cleanly.
    let results: Vec<(Vec<Proposal>, Option<Failure>, String, BTreeSet<String>)> = units
        .par_iter()
        .map(|entry| one_unit(entry, &request.limits, reference.as_ref()))
        .collect();

    let mut proposals = Vec::new();
    let mut failures = Vec::new();
    let mut defined_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (found, failure, key, defines) in results {
        proposals.extend(found);
        if let Some(failure) = failure {
            failures.push(failure);
        }
        for name in defines {
            defined_by.entry(name).or_default().insert(key.clone());
        }
    }

    let module = config::find(&request.root, &request.version, &request.module)?;
    let symbols = load_symbols(&module.symbols)?;
    let owners = Owners::read(&request.root, &request.version, &request.module)?;
    let (accepted, rejected) = resolve(&proposals, &symbols, &defined_by, Some(&owners));
    let corrections = corrections(&accepted, &rejected);

    Ok(Report {
        units: units.len(),
        proposed: proposals.len(),
        accepted,
        rejected,
        failures,
        corrections,
    })
}

/// Misplaced names, and the rename each one is standing in the way of.
///
/// A correction is deliberately reported and applied on its own rather than
/// paired with the rename it unblocks. Freeing a name cannot collide with
/// anything — the name it moves to is unused — so it is safe whatever else
/// lands, including when a run bisects a failing batch and separates the two
/// halves. Applying both at once is the case that is not safe: half a swap puts
/// one name on two addresses. The blocked rename is simply proposed again by the
/// next run, once the name it wants is free.
pub fn corrections(
    accepted: &BTreeMap<String, Proposal>,
    rejected: &[Rejected],
) -> Vec<Correction> {
    let mut blocked: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for entry in rejected.iter().filter(|entry| entry.reason == "name already taken") {
        if let Some(new) = &entry.new {
            blocked.entry(new.as_str()).or_default().push(entry.old.clone());
        }
    }
    accepted
        .iter()
        .filter(|(_, proposal)| proposal.method == "misplaced-name")
        .map(|(old, proposal)| {
            let mut frees = blocked.get(old.as_str()).cloned().unwrap_or_default();
            frees.sort();
            Correction {
                unit: proposal.unit.clone(),
                address_named: old.clone(),
                should_be: proposal.new.clone(),
                contested: proposal.contested.unwrap_or(false),
                reference_size: proposal.reference_size,
                percent: proposal.percent,
                own_percent: proposal.own_percent,
                carried_size: proposal.carried_size,
                namesake_size: proposal.namesake_size,
                frees_name_for: frees,
            }
        })
        .collect()
}

/// Renders the rename file `symbols rename` consumes.
pub fn render_renames(accepted: &BTreeMap<String, Proposal>, tier: Tier) -> String {
    let mut lines: Vec<(&str, &str)> = accepted
        .iter()
        .filter(|(_, proposal)| proposal.tier <= tier)
        .map(|(old, proposal)| (proposal.new.as_str(), old.as_str()))
        .collect();
    lines.sort();
    let mut text: String = lines.iter().map(|(new, old)| format!("{old} = {new}\n")).collect();
    if text.is_empty() {
        text.push_str("");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(old: &str, new: &str, unit: &str, method: &str, tier: Tier) -> Proposal {
        let mut value = Proposal {
            old: old.into(),
            new: new.into(),
            unit: unit.into(),
            method: method.into(),
            tier,
            signal: None,
            percent: None,
            margin: None,
            candidates: None,
            exact: None,
            anchors: None,
            functions: None,
            off_spine: None,
            chosen_percent: None,
            contested: None,
            reference_size: None,
            own_percent: None,
            carried_size: None,
            namesake_size: None,
            replacement_size: None,
            units: Vec::new(),
        };
        value.units.push(unit.into());
        value
    }

    fn symbols(entries: &[(&str, u64)]) -> BTreeMap<String, Placement> {
        entries
            .iter()
            .map(|(name, address)| ((*name).to_string(), (".text".to_string(), *address)))
            .collect()
    }

    #[test]
    fn one_agreed_rename_is_accepted() {
        let proposals = [proposal("fn_1", "Real", "a.cpp", "body-match", Tier::Confident)];
        let (accepted, rejected) =
            resolve(&proposals, &symbols(&[("fn_1", 0x1000)]), &BTreeMap::new(), None);
        assert_eq!(accepted["fn_1"].new, "Real");
        assert!(rejected.is_empty());
    }

    #[test]
    fn two_units_naming_one_symbol_differently_settle_nothing() {
        let proposals = [
            proposal("fn_1", "Real", "a.cpp", "body-match", Tier::Confident),
            proposal("fn_1", "Other", "b.cpp", "body-match", Tier::Confident),
        ];
        let (accepted, rejected) =
            resolve(&proposals, &symbols(&[("fn_1", 0x1000)]), &BTreeMap::new(), None);
        assert!(accepted.is_empty());
        assert_eq!(rejected[0].reason, "units disagree");
    }

    #[test]
    fn a_body_comparison_outranks_a_position_that_disagrees() {
        let proposals = [
            proposal("fn_1", "FromBody", "a.cpp", "body-match", Tier::Probable),
            proposal("fn_1", "FromPosition", "a.cpp", "function-position", Tier::Probable),
        ];
        let (accepted, _) =
            resolve(&proposals, &symbols(&[("fn_1", 0x1000)]), &BTreeMap::new(), None);
        assert_eq!(accepted["fn_1"].new, "FromBody");
    }

    #[test]
    fn a_symbol_the_file_does_not_have_cannot_be_renamed() {
        let proposals = [proposal("fn_1", "Real", "a.cpp", "body-match", Tier::Confident)];
        let (accepted, rejected) = resolve(&proposals, &BTreeMap::new(), &BTreeMap::new(), None);
        assert!(accepted.is_empty());
        assert_eq!(rejected[0].reason, "not in symbols file");
    }

    #[test]
    fn a_name_another_address_already_holds_is_refused() {
        let proposals = [proposal("fn_1", "Taken", "a.cpp", "body-match", Tier::Confident)];
        let (accepted, rejected) = resolve(
            &proposals,
            &symbols(&[("fn_1", 0x1000), ("Taken", 0x2000)]),
            &BTreeMap::new(),
            None,
        );
        assert!(accepted.is_empty());
        assert_eq!(rejected[0].reason, "name already taken");
    }

    #[test]
    fn two_symbols_claiming_one_name_cancel_each_other() {
        let proposals = [
            proposal("fn_1", "Real", "a.cpp", "body-match", Tier::Confident),
            proposal("fn_2", "Real", "b.cpp", "body-match", Tier::Confident),
        ];
        let (accepted, rejected) = resolve(
            &proposals,
            &symbols(&[("fn_1", 0x1000), ("fn_2", 0x2000)]),
            &BTreeMap::new(),
            None,
        );
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 2);
        assert!(rejected.iter().all(|r| r.reason == "name claimed by several symbols"));
    }

    #[test]
    fn the_strongest_tier_among_agreeing_proposals_is_kept() {
        let proposals = [
            proposal("fn_1", "Real", "a.cpp", "body-match", Tier::Probable),
            proposal("fn_1", "Real", "b.cpp", "call-site", Tier::Confident),
        ];
        let (accepted, _) =
            resolve(&proposals, &symbols(&[("fn_1", 0x1000)]), &BTreeMap::new(), None);
        assert_eq!(accepted["fn_1"].tier, Tier::Confident);
        assert_eq!(accepted["fn_1"].units, ["a.cpp", "b.cpp"]);
    }

    #[test]
    fn a_unit_identity_ignores_the_file_extension() {
        assert_eq!(unit_key("MetroidPrime/main.cpp"), "MetroidPrime/main");
        assert_eq!(unit_key("MetroidPrime/main.o"), "MetroidPrime/main");
        assert_eq!(unit_key("dolphin\\gx\\GXMisc.c"), "dolphin/gx/GXMisc");
    }

    #[test]
    fn a_rename_file_lists_the_kept_tiers_only() {
        let accepted = BTreeMap::from([
            ("fn_1".to_string(), proposal("fn_1", "Sure", "a.cpp", "body-match", Tier::Confident)),
            ("fn_2".to_string(), proposal("fn_2", "Maybe", "a.cpp", "body-match", Tier::Candidate)),
        ]);
        assert_eq!(render_renames(&accepted, Tier::Confident), "fn_1 = Sure\n");
        let both = render_renames(&accepted, Tier::Candidate);
        assert!(both.contains("fn_1 = Sure"), "{both}");
        assert!(both.contains("fn_2 = Maybe"), "{both}");
    }

    #[test]
    fn a_correction_names_the_rename_it_unblocks() {
        let accepted = BTreeMap::from([(
            "BuildBoidNearList".to_string(),
            proposal(
                "BuildBoidNearList",
                "OldBuildBoidNearList",
                "CFishCloud.cpp",
                "misplaced-name",
                Tier::Confident,
            ),
        )]);
        let rejected = vec![Rejected {
            old: "fn_8001A330".into(),
            reason: "name already taken".into(),
            new: Some("BuildBoidNearList".into()),
            names: Vec::new(),
            defined_in: Vec::new(),
        }];
        let found = corrections(&accepted, &rejected);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].should_be, "OldBuildBoidNearList");
        assert_eq!(found[0].frees_name_for, ["fn_8001A330"]);
    }

    #[test]
    fn a_name_another_units_source_defines_is_refused() {
        let proposals = [proposal("fn_1", "TheirFunction", "a.cpp", "body-match", Tier::Confident)];
        let defined_by =
            BTreeMap::from([("TheirFunction".to_string(), BTreeSet::from(["b".to_string()]))]);
        let owners = Owners { spans: vec![(".text".into(), 0x1000, 0x2000, "a".into())] };
        let (accepted, rejected) =
            resolve(&proposals, &symbols(&[("fn_1", 0x1000)]), &defined_by, Some(&owners));
        assert!(accepted.is_empty());
        assert_eq!(rejected[0].reason, "name defined by another unit's source");
        assert_eq!(rejected[0].defined_in, ["b"]);
    }

    #[test]
    fn a_name_the_owning_units_own_source_defines_is_allowed() {
        let proposals = [proposal("fn_1", "OurFunction", "a.cpp", "body-match", Tier::Confident)];
        let defined_by =
            BTreeMap::from([("OurFunction".to_string(), BTreeSet::from(["a".to_string()]))]);
        let owners = Owners { spans: vec![(".text".into(), 0x1000, 0x2000, "a".into())] };
        let (accepted, _) =
            resolve(&proposals, &symbols(&[("fn_1", 0x1000)]), &defined_by, Some(&owners));
        assert_eq!(accepted["fn_1"].new, "OurFunction");
    }

    #[test]
    fn an_address_finds_its_owning_unit() {
        let owners = Owners {
            spans: vec![
                (".text".into(), 0x1000, 0x2000, "a".into()),
                (".text".into(), 0x2000, 0x3000, "b".into()),
            ],
        };
        assert_eq!(owners.at(".text", 0x1500), Some("a"));
        assert_eq!(owners.at(".text", 0x2000), Some("b"));
        assert_eq!(owners.at(".text", 0x9000), None);
        assert_eq!(owners.at(".data", 0x1500), None);
    }
}
