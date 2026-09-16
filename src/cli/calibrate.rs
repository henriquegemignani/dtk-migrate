//! `dtk-migrate calibrate` — scoring the coverage policy against a version that
//! already has the answers.
//!
//! The policy decides which target ranges a source unit may claim. On a version
//! whose splits are already correct, that decision can be checked: generate the
//! evidence with the target's names and ownership hidden, build the same
//! alternatives a migration would, and compare each one against the splits the
//! project already has.
//!
//! The hiding is what makes it a test rather than a tautology. With ownership
//! visible, the policy would be reading the answer it is being asked for.
//!
//! Units are split into a calibration half and a held-out half by a hash of the
//! name, so a policy tuned against the first can be reported against the second.
//! An incorrect assignment in either fails the command: the policy is supposed
//! to abstain, not guess.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use indexmap::IndexMap;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    analysis::coverage::CoverageReport,
    matching,
    project::splits::{Splits, parse_range},
    stages::coverage::{
        EVIDENCE_SCHEMA, POLICY_VERSION,
        alternatives::{self, Alternative, parse_address},
    },
};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The dtk-template project to read.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    /// The version whose progress is being carried over.
    #[arg(long)]
    pub source: String,
    /// The already-named version to score against.
    #[arg(long)]
    pub target: String,
    /// A saved pre-change splits file to use as the oracle.
    ///
    /// Pass this when the target has already received the proposals being
    /// evaluated, so calibration cannot score its own output as an answer.
    #[arg(long)]
    pub oracle_splits: Option<PathBuf>,
    /// Where to write the result.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Whether a proposed range agrees with the oracle, contradicts it, or falls
/// where the oracle says nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum State {
    Correct,
    Incorrect,
    Unknown,
}

#[derive(Debug, Serialize)]
struct ScoredRange {
    id: String,
    evidence: String,
    state: State,
}

#[derive(Debug, Serialize)]
struct ScoredAnchor {
    address: String,
    evidence: String,
    state: State,
}

#[derive(Debug, Serialize)]
struct Record {
    name: String,
    partition: String,
    selected_alternative: Alternative,
    alternatives: Vec<ScoredRange>,
    anchors: Vec<ScoredAnchor>,
}

#[derive(Debug, Default, Serialize)]
struct Measures {
    tus: usize,
    ranges: usize,
    ranges_correct: usize,
    ranges_incorrect: usize,
    ranges_unknown: usize,
    anchors: usize,
    anchors_correct: usize,
    anchors_incorrect: usize,
    anchors_unknown: usize,
    /// Bytes the first-choice alternative would have assigned correctly.
    represented_bytes: u32,
}

/// Splits units into two halves by a hash of the name, so a policy tuned on one
/// can be reported against the other.
fn partition(name: &str) -> &'static str {
    if Sha256::digest(name.as_bytes())[0] < 128 { "calibration" } else { "held-out" }
}

type Blocks = IndexMap<String, Vec<String>>;

/// Whether the oracle puts this range inside the unit that claims it.
fn range_state(name: &str, section: &str, start: u32, end: u32, oracle: &Blocks) -> State {
    let own_contains = oracle
        .get(name)
        .into_iter()
        .flatten()
        .filter_map(|line| parse_range(line))
        .any(|range| range.section == section && range.start <= start && end <= range.end);
    if own_contains {
        return State::Correct;
    }
    let overlaps_other = oracle
        .iter()
        .filter(|(other, _)| other.as_str() != name)
        .flat_map(|(_, lines)| lines)
        .filter_map(|line| parse_range(line))
        .any(|range| range.section == section && start < range.end && range.start < end);
    // Unowned ground is not a wrong answer: the oracle simply has nothing to
    // say there, and counting it as an error would punish the policy for
    // covering what nobody has split yet.
    if overlaps_other { State::Incorrect } else { State::Unknown }
}

/// Who the oracle says owns each function in the target's layout.
fn ownership_at_layout(
    layout: &[crate::analysis::coverage::TargetFunction],
    oracle: &Blocks,
) -> BTreeMap<(String, String), Option<String>> {
    let parsed: Vec<(&str, crate::project::splits::Range)> = oracle
        .iter()
        .flat_map(|(name, lines)| lines.iter().map(move |line| (name.as_str(), line)))
        .filter_map(|(name, line)| Some((name, parse_range(line)?)))
        .collect();

    layout
        .iter()
        .map(|item| {
            let address = parse_address(&item.address).unwrap_or(0);
            let owners: Vec<&str> = parsed
                .iter()
                .filter(|(_, range)| {
                    range.section == item.section && range.start <= address && address < range.end
                })
                .map(|(name, _)| *name)
                .collect();
            // Two owners means the oracle contradicts itself here, which is no
            // more usable than no owner at all.
            let owner = (owners.len() == 1).then(|| owners[0].to_string());
            ((item.section.clone(), item.address.clone()), owner)
        })
        .collect()
}

pub fn run(args: Args) -> Result<()> {
    let root = std::path::absolute(&args.project_root)?;
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| root.join("build").join(&args.target).join("coverage-calibration"));
    std::fs::create_dir_all(&output)?;

    let masked = evidence(&root, &args, &output.join("masked-evidence.json"), true)?;
    let oracle_evidence = evidence(&root, &args, &output.join("oracle-evidence.json"), false)?;
    for value in [&masked, &oracle_evidence] {
        if value.schema != EVIDENCE_SCHEMA || value.policy.version != POLICY_VERSION {
            bail!("The coverage evidence is not the schema or policy this tool understands");
        }
    }
    if !masked.target_ownership_masked || oracle_evidence.target_ownership_masked {
        bail!("Calibration needs one masked and one unmasked evidence report");
    }

    let oracle_path = args
        .oracle_splits
        .clone()
        .unwrap_or_else(|| root.join("config").join(&args.target).join("splits.txt"));
    let oracle = Splits::read(&oracle_path)?.blocks;
    let owners = ownership_at_layout(&oracle_evidence.target_layout, &oracle);

    // Only units the oracle actually places can be scored.
    let mut candidates: Vec<(String, Vec<Alternative>)> = masked
        .source_units
        .iter()
        .filter(|unit| !unit.autogenerated && oracle.contains_key(&unit.name))
        .filter_map(|unit| {
            let found =
                alternatives::build(unit, &IndexMap::new(), &BTreeMap::new(), &IndexMap::new());
            (!found.is_empty()).then(|| (unit.name.clone(), found))
        })
        .collect();
    candidates.sort_by(|a, b| {
        let widest = |list: &Vec<Alternative>| list.iter().map(|x| x.covered_bytes).max();
        widest(&b.1).cmp(&widest(&a.1)).then_with(|| a.0.cmp(&b.0))
    });

    let records: Vec<Record> =
        candidates.into_iter().map(|(name, found)| score(&name, found, &oracle, &owners)).collect();
    let measures = summarize(&records);

    let result = serde_json::json!({
        "schema": 3,
        "policy": masked.policy,
        "source": args.source,
        "target": args.target,
        "oracle_splits": oracle_path.display().to_string(),
        "partition": "sha256-first-byte-less-than-128",
        "records": records,
        "measures": measures,
    });
    std::fs::write(output.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
    std::fs::write(output.join("result.md"), markdown(&masked.policy.version, &measures))?;

    println!("{}", serde_json::to_string_pretty(&measures)?);
    if measures.values().any(|m| m.ranges_incorrect > 0 || m.anchors_incorrect > 0) {
        bail!("The coverage policy assigned ownership incorrectly; see {}", output.display());
    }
    println!("\nEvidence: {}", output.display());
    Ok(())
}

/// Generates one coverage report, with the target's names and ownership hidden
/// or not.
fn evidence(root: &Path, args: &Args, path: &Path, mask: bool) -> Result<CoverageReport> {
    let config = |version: &str| {
        typed_path::Utf8NativePathBuf::from(
            root.join("config").join(version).join("config.yml").to_string_lossy().into_owned(),
        )
    };
    let mut request = matching::Request::new(config(&args.source), config(&args.target));
    request.validate = mask;
    request.outputs.coverage = Some(path.to_path_buf());
    matching::run(&request)?;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&text).context("Failed to parse the coverage evidence")
}

fn score(
    name: &str,
    found: Vec<Alternative>,
    oracle: &Blocks,
    owners: &BTreeMap<(String, String), Option<String>>,
) -> Record {
    let mut scored = Vec::new();
    // One anchor can appear in several alternatives of the same kind; it should
    // be scored once.
    let mut unique: BTreeMap<(String, String, String), String> = BTreeMap::new();
    for alternative in &found {
        let start = parse_address(&alternative.start).unwrap_or(0);
        let end = parse_address(&alternative.end).unwrap_or(0);
        scored.push(ScoredRange {
            id: alternative.id.clone(),
            evidence: alternative.evidence.clone(),
            state: range_state(name, &alternative.section, start, end, oracle),
        });
        for anchor in &alternative.anchors {
            let section = anchor.get("section").and_then(|v| v.as_str()).unwrap_or_default();
            let address = anchor.get("target_address").and_then(|v| v.as_str()).unwrap_or_default();
            unique.insert(
                (alternative.evidence.clone(), section.to_string(), address.to_string()),
                address.to_string(),
            );
        }
    }
    let anchors = unique
        .into_iter()
        .map(|((evidence, section, address), _)| ScoredAnchor {
            state: match owners.get(&(section, address.clone())) {
                Some(Some(owner)) if owner == name => State::Correct,
                Some(Some(_)) => State::Incorrect,
                _ => State::Unknown,
            },
            address,
            evidence,
        })
        .collect();

    Record {
        name: name.to_string(),
        partition: partition(name).to_string(),
        selected_alternative: found[0].clone(),
        alternatives: scored,
        anchors,
    }
}

fn summarize(records: &[Record]) -> BTreeMap<String, Measures> {
    let mut result = BTreeMap::new();
    for partition in ["calibration", "held-out"] {
        let rows: Vec<&Record> = records.iter().filter(|r| r.partition == partition).collect();
        let ranges: Vec<&ScoredRange> = rows.iter().flat_map(|r| &r.alternatives).collect();
        let anchors: Vec<&ScoredAnchor> = rows.iter().flat_map(|r| &r.anchors).collect();
        let count =
            |list: &[&ScoredRange], state: State| list.iter().filter(|r| r.state == state).count();
        let count_anchors =
            |list: &[&ScoredAnchor], state: State| list.iter().filter(|r| r.state == state).count();
        result.insert(partition.to_string(), Measures {
            tus: rows.len(),
            ranges: ranges.len(),
            ranges_correct: count(&ranges, State::Correct),
            ranges_incorrect: count(&ranges, State::Incorrect),
            ranges_unknown: count(&ranges, State::Unknown),
            anchors: anchors.len(),
            anchors_correct: count_anchors(&anchors, State::Correct),
            anchors_incorrect: count_anchors(&anchors, State::Incorrect),
            anchors_unknown: count_anchors(&anchors, State::Unknown),
            represented_bytes: rows
                .iter()
                .filter(|row| row.alternatives.first().is_some_and(|a| a.state == State::Correct))
                .map(|row| row.selected_alternative.covered_bytes)
                .sum(),
        });
    }
    result
}

fn markdown(policy: &u32, measures: &BTreeMap<String, Measures>) -> String {
    let mut lines = vec![
        "# Coverage calibration".to_string(),
        String::new(),
        format!("Policy version: {policy}"),
        String::new(),
        "An incorrect range or anchor means the policy claimed ground the oracle gives to \
         another unit. Unknown means the oracle has nothing to say there, which is not an error."
            .to_string(),
        String::new(),
        "| Partition | TUs | Ranges | Correct | Unknown | Incorrect | Anchors correct | Unknown \
         | Incorrect | Bytes |"
            .to_string(),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|".to_string(),
    ];
    for (name, value) in measures {
        lines.push(format!(
            "| {name} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            value.tus,
            value.ranges,
            value.ranges_correct,
            value.ranges_unknown,
            value.ranges_incorrect,
            value.anchors_correct,
            value.anchors_unknown,
            value.anchors_incorrect,
            value.represented_bytes
        ));
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(entries: &[(&str, u32, u32)]) -> Blocks {
        let mut map: Blocks = IndexMap::new();
        for (name, start, end) in entries {
            map.entry((*name).to_string())
                .or_default()
                .push(format!("\t{:11} start:0x{start:08X} end:0x{end:08X}", ".text"));
        }
        map
    }

    #[test]
    fn a_range_inside_the_units_own_split_is_correct() {
        let oracle = blocks(&[("a.cpp", 0x1000, 0x2000)]);
        assert_eq!(range_state("a.cpp", ".text", 0x1100, 0x1200, &oracle), State::Correct);
    }

    #[test]
    fn a_range_overlapping_another_unit_is_incorrect() {
        let oracle = blocks(&[("a.cpp", 0x1000, 0x2000), ("b.cpp", 0x2000, 0x3000)]);
        assert_eq!(range_state("a.cpp", ".text", 0x1F00, 0x2100, &oracle), State::Incorrect);
    }

    #[test]
    fn a_range_nobody_owns_is_unknown_rather_than_wrong() {
        let oracle = blocks(&[("a.cpp", 0x1000, 0x2000)]);
        assert_eq!(range_state("a.cpp", ".text", 0x5000, 0x5100, &oracle), State::Unknown);
    }

    #[test]
    fn a_range_in_another_section_does_not_collide() {
        let oracle = blocks(&[("b.cpp", 0x1000, 0x2000)]);
        assert_eq!(range_state("a.cpp", ".data", 0x1100, 0x1200, &oracle), State::Unknown);
    }

    #[test]
    fn the_partition_is_stable_and_splits_the_population() {
        assert_eq!(partition("a.cpp"), partition("a.cpp"));
        let names: Vec<String> = (0..200).map(|i| format!("unit{i}.cpp")).collect();
        let calibration = names.iter().filter(|n| partition(n) == "calibration").count();
        assert!((40..160).contains(&calibration), "{calibration} of 200");
    }
}
