//! `dtk-migrate benchmark` — scoring a finished migration against a later
//! revision that has the answers.
//!
//! Calibration hides part of a version's ownership and asks whether the policy
//! puts it back. That is a fair question and a synthetic one: the hidden
//! neighbourhood is otherwise intact, and the evidence is generated in the same
//! process that scores it. This asks the other question. A real migration was
//! run against a real project at a real revision, months of decompilation later
//! someone established what the answers actually were, and the two can be
//! compared.
//!
//! Two operations, both read-only:
//!
//! * **`prepare`** builds a manifest from two immutable revisions — what each
//!   translation unit owned before, what it owns in the oracle, and which units
//!   became source-linked in between.
//! * **`score`** reads a completed run directory and measures it against that
//!   manifest.
//!
//! # Why the manifest cannot be read out of the checkout
//!
//! The benchmark project was *published to*: the migration rewrote its
//! `splits.txt`, `symbols.txt` and `configure.py`. Its working tree is
//! therefore the run's own output, not the baseline the run started from, and a
//! scorer that read it would be grading the answer against itself. So the
//! manifest comes from Git blobs, or from files saved before the run, and
//! scoring re-checks that the run really started where the manifest says.
//!
//! # Why this is a separate command
//!
//! The oracle is a later revision of the same project. Nothing that decides
//! anything — the matcher, the policy, a stage, a worker — may see it, and the
//! only durable way to guarantee that is for the oracle never to be reachable
//! from those modules at all. `tests/historical_recall.rs` asserts that
//! separation against the source tree, because a benchmark whose oracle leaked
//! into inference reports excellent results and means nothing.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    analysis::ownership_score::{
        Application, Blocks, Body, Identification, Ledger, Oracle, Outcome, Scope, Verification,
        ledger, outcome,
    },
    project::{
        configure_py::{Configure, Status},
        splits::Splits,
    },
};

/// Bumped when the manifest's meaning changes. The historical run's own schema
/// is frozen — see [`legacy`] — so this versions only what `prepare` writes.
pub const MANIFEST_SCHEMA: u32 = 2;
pub const SCORE_SCHEMA: u32 = 2;

#[derive(ClapArgs, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub command: Operation,
}

#[derive(Subcommand, Debug)]
pub enum Operation {
    /// Build an oracle manifest from two immutable revisions.
    Prepare(PrepareArgs),
    /// Score a completed run directory against a manifest.
    Score(ScoreArgs),
}

#[derive(ClapArgs, Debug)]
pub struct PrepareArgs {
    /// The project the two revisions live in. Only read from, and only through
    /// `git show`, so its working tree may be anything.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    /// The revision the migration started from.
    #[arg(long)]
    pub baseline: String,
    /// The later revision that supplies the answers.
    #[arg(long)]
    pub oracle: String,
    /// The version being migrated from, for the record.
    #[arg(long)]
    pub source: String,
    /// The version being migrated to. Its `splits.txt` is the thing compared.
    #[arg(long)]
    pub target: String,
    /// A saved baseline `splits.txt`, instead of reading the blob.
    #[arg(long)]
    pub baseline_splits: Option<PathBuf>,
    /// A saved oracle `splits.txt`, instead of reading the blob.
    #[arg(long)]
    pub oracle_splits: Option<PathBuf>,
    #[arg(long)]
    pub baseline_configure: Option<PathBuf>,
    #[arg(long)]
    pub oracle_configure: Option<PathBuf>,
    #[arg(long)]
    pub output: PathBuf,
    /// Also write the two revisions' split files and their linkage, small
    /// enough and plain enough to commit as a regression fixture.
    #[arg(long)]
    pub fixture: Option<PathBuf>,
}

#[derive(ClapArgs, Debug)]
pub struct ScoreArgs {
    #[arg(long)]
    pub manifest: PathBuf,
    /// A completed run directory, the one holding `run.json`.
    #[arg(long)]
    pub run: PathBuf,
    /// Where to write `score.json` and `score.md`. Defaults to beside the run.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Also write a reduced manifest and observation pair, small enough to
    /// commit as a regression fixture.
    #[arg(long)]
    pub fixture: Option<PathBuf>,
}

// --- the manifest -----------------------------------------------------------

/// How much a unit's oracle split is worth as an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    /// The oracle revision links this unit from its own source, so a build that
    /// reproduced retail proved the split. This is the only kind of answer
    /// worth failing a run over.
    SourceLinked,
    /// The oracle has a split for it that nothing has verified. Usually right,
    /// occasionally a leftover guess — reported, never used as a verdict.
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    /// A Git revision, or the path of the saved file that stood in for one.
    pub id: String,
    pub splits_sha256: String,
    #[serde(default)]
    pub configure_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitTruth {
    /// What the unit owned at the baseline revision.
    pub baseline: Body,
    /// What the oracle says it owns.
    pub oracle: Body,
    pub baseline_linked: bool,
    pub oracle_linked: bool,
    pub trust: Trust,
    /// Whether the two revisions disagree about its ownership at all.
    pub changed: bool,
    /// Whether they disagree about its code specifically.
    pub changed_code: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub source: String,
    pub target: String,
    pub baseline: Revision,
    pub oracle: Revision,
    /// Units the oracle revision links from source and the baseline did not.
    /// The population a recall number is about.
    pub recall_set: Vec<String>,
    pub units: BTreeMap<String, UnitTruth>,
}

impl Manifest {
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let manifest: Self = serde_json::from_str(&text)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        if manifest.schema != MANIFEST_SCHEMA {
            bail!(
                "Manifest is schema {} and this tool writes {MANIFEST_SCHEMA}; rebuild it with \
                 `benchmark prepare` rather than reading it as if the fields still meant the same",
                manifest.schema
            );
        }
        Ok(manifest)
    }

    fn oracle(&self) -> Oracle {
        let mut blocks: Blocks = IndexMap::new();
        for (name, truth) in &self.units {
            blocks.insert(name.clone(), truth.oracle.render());
        }
        Oracle::of(&blocks)
    }

    fn baseline_blocks(&self) -> Blocks {
        self.units
            .iter()
            .filter(|(_, truth)| !truth.baseline.is_empty())
            .map(|(name, truth)| (name.clone(), truth.baseline.render()))
            .collect()
    }
}

fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

/// Reads one path at one revision, without touching the working tree.
fn blob(root: &Path, revision: &str, path: &str) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["show", &format!("{revision}:{path}")])
        .output()
        .with_context(|| format!("Failed to run git in {}", root.display()))?;
    if !output.status.success() {
        bail!(
            "git show {revision}:{path} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("Blob is not UTF-8")
}

/// Either a saved file or a blob, so a manifest can be built from a checkout
/// whose history is gone.
fn source_text(
    root: &Path,
    revision: &str,
    path: &str,
    saved: Option<&PathBuf>,
) -> Result<(String, String)> {
    match saved {
        Some(file) => {
            let text = std::fs::read_to_string(file)
                .with_context(|| format!("Failed to read {}", file.display()))?;
            Ok((file.display().to_string(), text))
        }
        None => Ok((revision.to_string(), blob(root, revision, path)?)),
    }
}

/// Which units each revision links from source, for the target version.
///
/// Derived from `configure.py`, and saved separately so a fixture can carry it
/// without carrying two copies of a 200 KB Python file whose other 99% has
/// nothing to do with ownership.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Linkage {
    pub baseline: BTreeSet<String>,
    pub oracle: BTreeSet<String>,
}

/// Builds a manifest from the two revisions' splits and their linkage.
///
/// Shared by `prepare` and by the regression fixture, so a committed fixture is
/// scored by the same code that produced the numbers it pins.
pub fn build_manifest(
    source: &str,
    target: &str,
    baseline: Revision,
    baseline_splits: &str,
    oracle: Revision,
    oracle_splits: &str,
    linkage: &Linkage,
) -> Result<Manifest> {
    let before = Splits::parse(baseline_splits)?.blocks;
    let after = Splits::parse(oracle_splits)?.blocks;

    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut units = BTreeMap::new();
    for name in names {
        let baseline_body = Body::of(&before, name);
        let oracle_body = Body::of(&after, name);
        let changed = !baseline_body.same_structure(&oracle_body);
        let changed_code =
            !baseline_body.within(Scope::Code).same_ownership(&oracle_body.within(Scope::Code));
        let oracle_links = linkage.oracle.contains(name);
        units.insert(name.clone(), UnitTruth {
            baseline: baseline_body,
            oracle: oracle_body,
            baseline_linked: linkage.baseline.contains(name),
            oracle_linked: oracle_links,
            trust: if oracle_links { Trust::SourceLinked } else { Trust::Unverified },
            changed,
            changed_code,
        });
    }

    // The recall set is about units the later work *proved*, in the target
    // version. A unit linked for some other version says nothing here.
    let recall_set: Vec<String> = linkage
        .oracle
        .difference(&linkage.baseline)
        .filter(|name| units.contains_key(*name))
        .cloned()
        .collect();
    if recall_set.is_empty() {
        bail!(
            "No unit became source-linked for {target} between these revisions, so there is \
             nothing to measure recall against"
        );
    }

    Ok(Manifest {
        schema: MANIFEST_SCHEMA,
        source: source.to_string(),
        target: target.to_string(),
        baseline,
        oracle,
        recall_set,
        units,
    })
}

/// Which units a `configure.py` links from source for one version.
pub fn linked(text: &str, version: &str) -> Result<BTreeSet<String>> {
    let configure = Configure::parse(text)?;
    Ok(configure
        .declarations()
        .iter()
        .filter(|declaration| match &declaration.status {
            Status::Universal => true,
            Status::For(versions) => versions.iter().any(|v| v == version),
            Status::None | Status::Unrewritable(_) => false,
        })
        .map(|declaration| declaration.name.clone())
        .collect())
}

pub fn prepare(args: &PrepareArgs) -> Result<()> {
    let root = std::path::absolute(&args.project_root)?;
    let splits_path = format!("config/{}/splits.txt", args.target);

    let (baseline_id, baseline_splits) =
        source_text(&root, &args.baseline, &splits_path, args.baseline_splits.as_ref())?;
    let (oracle_id, oracle_splits) =
        source_text(&root, &args.oracle, &splits_path, args.oracle_splits.as_ref())?;
    let (_, baseline_configure) =
        source_text(&root, &args.baseline, "configure.py", args.baseline_configure.as_ref())?;
    let (_, oracle_configure) =
        source_text(&root, &args.oracle, "configure.py", args.oracle_configure.as_ref())?;

    let linkage = Linkage {
        baseline: linked(&baseline_configure, &args.target)?,
        oracle: linked(&oracle_configure, &args.target)?,
    };
    let manifest = build_manifest(
        &args.source,
        &args.target,
        Revision {
            id: baseline_id,
            splits_sha256: digest(baseline_splits.as_bytes()),
            configure_sha256: Some(digest(baseline_configure.as_bytes())),
        },
        &baseline_splits,
        Revision {
            id: oracle_id,
            splits_sha256: digest(oracle_splits.as_bytes()),
            configure_sha256: Some(digest(oracle_configure.as_bytes())),
        },
        &oracle_splits,
        &linkage,
    )?;
    write_json(&args.output, &manifest)?;
    if let Some(directory) = &args.fixture {
        write_oracle_fixture(directory, &manifest, &baseline_splits, &oracle_splits, &linkage)?;
    }
    println!(
        "{} units, {} newly linked for {}. Manifest: {}",
        manifest.units.len(),
        manifest.recall_set.len(),
        args.target,
        args.output.display()
    );
    Ok(())
}

// --- reading a finished run -------------------------------------------------

/// A read-only adapter for the run schema the historical benchmark was produced
/// with.
///
/// Deliberately not [`crate::run::StageResult`]. That type will keep changing;
/// the run being scored will not, and a scorer that followed the live type
/// would either stop parsing the historical evidence or, worse, keep parsing it
/// while reading new meanings into old fields.
mod legacy {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    pub struct Summary {
        #[serde(default)]
        pub id: String,
        #[serde(default)]
        pub source: String,
        #[serde(default)]
        pub target: String,
        #[serde(default)]
        pub stages: BTreeMap<String, Stage>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct Stage {
        #[serde(default)]
        pub accepted: Vec<Candidate>,
        #[serde(default)]
        pub deferred: Vec<Candidate>,
        #[serde(default)]
        pub selections: BTreeMap<String, String>,
        #[serde(default)]
        pub events: Vec<Event>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Candidate {
        pub name: String,
        #[serde(default)]
        pub evidence: serde_json::Value,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Event {
        #[serde(default)]
        pub unit: String,
        #[serde(default)]
        pub status: String,
        #[serde(default)]
        pub reason: Option<String>,
    }

    /// `run.json`: what the run froze before it did anything.
    ///
    /// `owner.manifest` is a SHA-256 per project input, taken before the first
    /// worker started. It is the only record of where a run began that survives
    /// a run which then changed nothing.
    #[derive(Debug, Clone, Deserialize)]
    pub struct Record {
        #[serde(default)]
        pub source: String,
        #[serde(default)]
        pub target: String,
        #[serde(default)]
        pub owner: Owner,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct Owner {
        #[serde(default)]
        pub manifest: BTreeMap<String, String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Journal {
        #[serde(default)]
        pub status: String,
        #[serde(default)]
        pub changes: BTreeMap<String, Change>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Change {
        #[serde(default)]
        pub before: Option<String>,
        #[serde(default)]
        pub after: Option<String>,
    }
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        bail!("Journal entry is not valid hex");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("Journal entry is not valid hex"))
        .collect()
}

/// The order stages run in, which is also the order a later acceptance
/// supersedes an earlier one.
const STAGES: [&str; 4] = ["derive", "coverage", "discover", "verify"];

/// Everything the scorer reads out of a finished run.
pub struct RunFacts {
    pub id: String,
    pub source: String,
    pub target: String,
    /// The target splits as the run found them, out of the publication journal.
    pub before: Blocks,
    /// And as it left them.
    pub after: Blocks,
    pub published: bool,
    /// Digest of the target split file before the run started. This is the only
    /// baseline evidence available when publication had no split-file change.
    baseline_splits_sha256: Option<String>,
    /// No journal entry means the run left the split file untouched. In that
    /// case scoring uses the manifest baseline after proving it by digest.
    use_manifest_baseline: bool,
    stages: BTreeMap<String, legacy::Stage>,
}

impl RunFacts {
    /// A run reduced to its split bodies, for a fixture that cannot carry the
    /// megabytes of evidence the original wrote.
    pub fn from_splits(
        id: &str,
        source: &str,
        target: &str,
        before: Blocks,
        after: Blocks,
    ) -> Self {
        Self {
            id: id.to_string(),
            source: source.to_string(),
            target: target.to_string(),
            before,
            after,
            published: true,
            baseline_splits_sha256: None,
            use_manifest_baseline: false,
            stages: BTreeMap::new(),
        }
    }
}

pub fn read_run(run: &Path) -> Result<RunFacts> {
    let summary: legacy::Summary = read_json(&run.join("result.json"))?;
    let record: legacy::Record = read_json(&run.join("run.json"))?;
    let journal: legacy::Journal = read_json(&run.join("publication.json"))?;
    if !record.source.is_empty() && record.source != summary.source {
        bail!("run.json names source {} but result.json names {}", record.source, summary.source);
    }
    if !record.target.is_empty() && record.target != summary.target {
        bail!("run.json names target {} but result.json names {}", record.target, summary.target);
    }
    let target = if summary.target.is_empty() {
        bail!("The run's result.json does not name a target version")
    } else {
        summary.target.clone()
    };

    let key = format!("config/{target}/splits.txt");
    let baseline_splits_sha256 = record.owner.manifest.get(&key).cloned();
    let change = journal.changes.get(&key);
    let text = |side: Option<&String>| -> Result<Option<Blocks>> {
        match side {
            Some(hex) => {
                let bytes = unhex(hex)?;
                Ok(Some(Splits::parse(&String::from_utf8(bytes)?)?.blocks))
            }
            None => Ok(None),
        }
    };
    let before = text(change.and_then(|c| c.before.as_ref()))?;
    let after = text(change.and_then(|c| c.after.as_ref()))?;
    // A run that changed no splits published the baseline unchanged, which is a
    // real outcome and not a missing one.
    let (before, after, use_manifest_baseline) = match (before, after) {
        (Some(before), Some(after)) => (before, after, false),
        (Some(before), None) => (before.clone(), before, false),
        (None, None) => (IndexMap::new(), IndexMap::new(), true),
        (None, Some(_)) => {
            bail!("Publication records an after-image for {key} without a before-image")
        }
    };

    Ok(RunFacts {
        id: summary.id,
        source: summary.source,
        target,
        before,
        after,
        published: journal.status == "published",
        baseline_splits_sha256,
        use_manifest_baseline,
        stages: summary.stages,
    })
}

/// Every complete replacement body any stage proposed for a unit.
///
/// Both stages express a proposal the same way — a `lines` array that replaces
/// the unit's block outright — so this walks the recorded evidence for them
/// rather than knowing each stage's evidence type. That also means a stage
/// added later is measured without this having to be taught about it.
fn proposed_bodies(evidence: &serde_json::Value) -> Vec<Vec<String>> {
    let mut found = Vec::new();
    collect(evidence, &mut found);
    return found;

    fn collect(value: &serde_json::Value, into: &mut Vec<Vec<String>>) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Array(lines)) = map.get("lines") {
                    let body: Vec<String> =
                        lines.iter().filter_map(|l| l.as_str().map(str::to_string)).collect();
                    if !body.is_empty() {
                        into.push(body);
                    }
                }
                for (key, item) in map {
                    if key != "lines" {
                        collect(item, into);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| collect(item, into)),
            _ => {}
        }
    }
}

// --- scoring ----------------------------------------------------------------

/// What the run found for a unit, and what it did with what it found.
///
/// Three separate facts, because the gap between the first and the last has
/// several possible causes and only one of them is a ranking problem. A run
/// that proposed the right body and never got to try it failed at scheduling; a
/// run that tried it and the build refused it failed at application; a run that
/// had it, chose something else, and was wrong failed at ranking. `proposed`
/// alone cannot tell those apart, so it is not asked to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recall {
    /// Some body the run proposed is exactly the oracle's answer.
    pub proposed: bool,
    /// The run proved a body, and it is exactly the oracle's answer.
    pub selected: bool,
    /// An exact proposal existed, a different one was selected, and the one
    /// selected was not exact. The only shape that is actually a ranking
    /// failure.
    pub ranking_failure: bool,
}

fn recall_for(name: &str, truth: &Body, found: &Trace, scope: Scope) -> Recall {
    let wanted = truth.within(scope);
    let exact = |lines: &Vec<String>| {
        let mut one: Blocks = IndexMap::new();
        one.insert(name.to_string(), lines.clone());
        Body::of(&one, name).within(scope).same_ownership(&wanted)
    };
    let proposed = found.proposed.iter().any(exact);
    let selected = found.selected.as_ref().is_some_and(exact);
    Recall {
        proposed,
        selected,
        ranking_failure: proposed
            && !selected
            && found.selected.as_ref().is_some_and(|chosen| {
                found.selected_stage_proposed.iter().any(|other| other != chosen && exact(other))
            }),
    }
}

/// What one stage did with one unit, and what it said about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageTrace {
    pub stage: String,
    pub application: Application,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitScore {
    pub unit: String,
    pub trust: Trust,
    pub in_recall_set: bool,
    /// Whether the two revisions disagree about this unit at all. A unit the
    /// oracle agrees with the baseline about is a control, not a target.
    pub needed_change: bool,
    pub needed_code_change: bool,
    pub identification: Identification,
    /// Why the identification says what it says, named rather than scored.
    pub identification_evidence: Vec<String>,
    /// What the run found and what it did with it, judged on code alone and on
    /// the whole body. Separately, because they disagree: seven of the recall
    /// set had a code-exact proposal and only four had a full-body one, and a
    /// single boolean reported against both populations claimed the larger
    /// number in both.
    pub code_recall: Recall,
    pub full_recall: Recall,
    pub proposals: usize,
    pub application: Application,
    pub stage_trace: Vec<StageTrace>,
    /// Which alternative the accepting stage recorded proving. A unit accepted
    /// with no selection beside it is a run that cannot say what it proved,
    /// which is worth seeing even though the oracle has no opinion about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<String>,
    pub verification: Verification,
    /// The verdict on what it ended up owning: exact, partial, wrong, unowned,
    /// or unchanged.
    pub code_outcome: Outcome,
    pub full_outcome: Outcome,
    pub code: Ledger,
    pub full: Ledger,
    /// Whether it ends up owning precisely the oracle's ground, and whether it
    /// also writes it the same way.
    pub code_exact: bool,
    pub full_exact: bool,
    pub structure_exact: bool,
    /// The run took ground the oracle gives to someone else, or gave up ground
    /// the unit correctly held. The most important number in the whole report,
    /// and the one that must reach zero.
    ///
    /// Deliberately *not* "it stopped agreeing with the oracle". A unit that
    /// keeps all of its own ground and runs a little past the last split into
    /// territory nobody has claimed has not damaged anything — the oracle has
    /// no opinion there, and scoring it as damage would report 160 units of
    /// harm in a run that did none.
    pub regressed: bool,
    /// It came in agreeing with the oracle exactly and does not any more. A
    /// superset of [`Self::regressed`]: the difference is a claim nothing
    /// supports rather than a claim that is wrong.
    pub lost_exactness: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Population {
    pub units: usize,
    pub exact: usize,
    pub partial: usize,
    pub wrong: usize,
    pub unowned: usize,
    pub unchanged: usize,
    /// Units for which some proposal was exactly right *in this population's
    /// scope*. A code population reports code recall and a full-body population
    /// reports full-body recall; they are different numbers.
    pub proposal_recall: usize,
    /// Of those, the ones where the run proved the right body.
    pub selected_exact: usize,
    /// And the ones where it had the right body, proved a different one, and
    /// that one was wrong.
    pub ranking_failures: usize,
    pub regressed: usize,
    pub lost_exactness: usize,
    pub gained_bytes: u32,
    pub lost_bytes: u32,
    pub newly_wrong_bytes: u32,
    pub wrong_after_bytes: u32,
    pub missed_bytes: u32,
    pub unknown_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Score {
    pub schema: u32,
    pub run: String,
    pub source: String,
    pub target: String,
    pub baseline_revision: String,
    pub oracle_revision: String,
    /// Whether the run really started from the manifest's baseline. A `false`
    /// here makes every number below meaningless, so it is recorded rather than
    /// assumed.
    pub baseline_agrees: bool,
    pub published: bool,
    pub populations: BTreeMap<String, Population>,
    /// Units the run damaged, by name, and only ones whose oracle answer a
    /// build actually proved. A count cannot tell "the same three" from "three
    /// different ones", and an unverified oracle split is not firm enough
    /// ground to call anything a regression from.
    pub regressions: Vec<String>,
    /// The same measure over units whose oracle answer nothing has verified.
    /// Reported, never fatal.
    pub unverified_regressions: Vec<String>,
    pub units: Vec<UnitScore>,
}

fn population(rows: &[&UnitScore], scope: Scope) -> Population {
    let pick = |row: &UnitScore| if scope == Scope::Code { row.code } else { row.full };
    let recall = |row: &UnitScore, scope: Scope| {
        if scope == Scope::Code { row.code_recall } else { row.full_recall }
    };
    let verdict =
        |row: &UnitScore| if scope == Scope::Code { row.code_outcome } else { row.full_outcome };
    let count = |state: Outcome| rows.iter().filter(|row| verdict(row) == state).count();
    Population {
        units: rows.len(),
        exact: count(Outcome::Exact),
        partial: count(Outcome::Partial),
        wrong: count(Outcome::Incorrect),
        unowned: count(Outcome::Unowned),
        unchanged: count(Outcome::Abstained),
        proposal_recall: rows.iter().filter(|row| recall(row, scope).proposed).count(),
        selected_exact: rows.iter().filter(|row| recall(row, scope).selected).count(),
        ranking_failures: rows.iter().filter(|row| recall(row, scope).ranking_failure).count(),
        regressed: rows.iter().filter(|row| row.regressed).count(),
        lost_exactness: rows.iter().filter(|row| row.lost_exactness).count(),
        gained_bytes: rows.iter().map(|row| pick(row).gained_bytes).sum(),
        lost_bytes: rows.iter().map(|row| pick(row).lost_bytes).sum(),
        newly_wrong_bytes: rows.iter().map(|row| pick(row).newly_wrong_bytes).sum(),
        wrong_after_bytes: rows.iter().map(|row| pick(row).wrong_after_bytes).sum(),
        missed_bytes: rows.iter().map(|row| pick(row).missed_bytes).sum(),
        unknown_bytes: rows.iter().map(|row| pick(row).unknown_bytes).sum(),
    }
}

/// Scores one finished run against one manifest. Pure: the same inputs give the
/// same answer wherever either of them is stored.
pub fn score(manifest: &Manifest, run: &RunFacts) -> Score {
    let oracle = manifest.oracle();
    // A changed split file carries its before-image in the journal. A no-op run
    // carries only the starting file's digest in run.json, so use the manifest
    // body only after that digest proves it is the same baseline.
    let manifest_baseline = manifest.baseline_blocks();
    let baseline_agrees = if run.use_manifest_baseline {
        !manifest.baseline.splits_sha256.is_empty()
            && run.baseline_splits_sha256.as_deref()
                == Some(manifest.baseline.splits_sha256.as_str())
    } else {
        manifest
            .units
            .iter()
            .all(|(name, truth)| Body::of(&run.before, name).same_structure(&truth.baseline))
    };
    let before = if run.use_manifest_baseline { &manifest_baseline } else { &run.before };
    let after = if run.use_manifest_baseline { &manifest_baseline } else { &run.after };

    let mut units: Vec<UnitScore> = manifest
        .units
        .iter()
        .map(|(name, truth)| {
            let held = Body::of(before, name);
            let left = Body::of(after, name);
            let code = ledger(name, &oracle, &held, &left, Scope::Code);
            let full = ledger(name, &oracle, &held, &left, Scope::Everything);
            let changed_code = !held.within(Scope::Code).same_ownership(&left.within(Scope::Code));
            let changed_full = !held.same_structure(&left);

            let found = trace(name, run);
            UnitScore {
                unit: name.clone(),
                trust: truth.trust,
                in_recall_set: manifest.recall_set.contains(name),
                needed_change: truth.changed,
                needed_code_change: truth.changed_code,
                identification: identify(found.proposed.len(), &found.proposed),
                identification_evidence: evidence_names(name, run),
                code_recall: recall_for(name, &truth.oracle, &found, Scope::Code),
                full_recall: recall_for(name, &truth.oracle, &found, Scope::Everything),
                proposals: found.proposed.len(),
                application: found.application,
                stage_trace: found.traces,
                selected: found.selection_id,
                verification: verification(name, run),
                code_outcome: outcome(
                    &code,
                    &truth.oracle.within(Scope::Code),
                    &left.within(Scope::Code),
                    changed_code,
                ),
                full_outcome: outcome(&full, &truth.oracle, &left, changed_full),
                code,
                full,
                code_exact: left
                    .within(Scope::Code)
                    .same_ownership(&truth.oracle.within(Scope::Code)),
                full_exact: left.same_ownership(&truth.oracle),
                structure_exact: left.same_structure(&truth.oracle),
                // Judged on the whole body, because a run that kept the code and
                // dropped a `.bss` range has still broken a unit that was
                // correct.
                regressed: full.lost_bytes > 0 || full.newly_wrong_bytes > 0,
                lost_exactness: held.same_structure(&truth.oracle)
                    && !left.same_structure(&truth.oracle),
                refusal: found.refusal,
            }
        })
        .collect();
    units.sort_by(|a, b| a.unit.cmp(&b.unit));

    let recall: Vec<&UnitScore> = units.iter().filter(|row| row.in_recall_set).collect();
    let changed: Vec<&UnitScore> = recall.iter().copied().filter(|row| row.needed_change).collect();
    let changed_code: Vec<&UnitScore> =
        recall.iter().copied().filter(|row| row.needed_code_change).collect();
    // Everything whose answer a build actually proved.
    let safety: Vec<&UnitScore> =
        units.iter().filter(|row| row.trust == Trust::SourceLinked).collect();
    // Of those, the ones the two revisions already agree about. The run had
    // nothing to do here and every one of them should come out unchanged, which
    // makes this the population a recall improvement is most likely to break.
    let controls: Vec<&UnitScore> =
        safety.iter().copied().filter(|row| !row.needed_change).collect();

    let mut populations = BTreeMap::new();
    populations.insert("recall/full".into(), population(&recall, Scope::Everything));
    populations.insert("recall/code".into(), population(&recall, Scope::Code));
    populations.insert("recall-changed/full".into(), population(&changed, Scope::Everything));
    populations.insert("recall-changed-code/code".into(), population(&changed_code, Scope::Code));
    populations.insert("source-linked/full".into(), population(&safety, Scope::Everything));
    populations.insert("control/full".into(), population(&controls, Scope::Everything));

    Score {
        schema: SCORE_SCHEMA,
        run: run.id.clone(),
        source: run.source.clone(),
        target: run.target.clone(),
        baseline_revision: manifest.baseline.id.clone(),
        oracle_revision: manifest.oracle.id.clone(),
        baseline_agrees,
        published: run.published,
        regressions: units
            .iter()
            .filter(|row| row.regressed && row.trust == Trust::SourceLinked)
            .map(|row| row.unit.clone())
            .collect(),
        unverified_regressions: units
            .iter()
            .filter(|row| row.regressed && row.trust != Trust::SourceLinked)
            .map(|row| row.unit.clone())
            .collect(),
        populations,
        units,
    }
}

/// Why one stage refused a candidate, in that stage's own words.
///
/// Each stage has its own frozen vocabulary, and only coverage ever wrote
/// `rejected`. Reading every stage as if it did meant discovery's
/// `build-conflict` and verification's `failed-source-link-or-hash` were
/// silently invisible, so a unit with two recorded verification failures came
/// out as never attempted.
///
/// Frozen on purpose: these are the statuses the run being scored actually
/// wrote. A stage that changes its vocabulary later gets an entry of its own
/// rather than quietly reclassifying this run's history.
fn refusal_kind(stage: &str, status: &str) -> Option<Application> {
    match (stage, status) {
        // A cyclic link order is found in the split file, before anything is
        // compiled; everything else here is something a build said.
        ("discover", "link-order-cycle") => Some(Application::PreflightRefused),
        ("discover", "build-conflict" | "no-matched-code-gain" | "regresses-existing-code") => {
            Some(Application::BuildRefused)
        }
        ("verify", "failed-source-link-or-hash") => Some(Application::BuildRefused),
        ("derive", "name-conflict" | "regresses-existing-code") => Some(Application::BuildRefused),
        // Coverage says only `rejected`, and its reason text says whether the
        // change was refused before a build or by one.
        ("coverage", "rejected") => Some(Application::BuildRefused),
        _ => None,
    }
}

/// Coverage refusals that happened before a build, told apart by reason text
/// because coverage records one status for both.
fn is_preflight(reason: &str) -> bool {
    let text = reason.to_lowercase();
    text.contains("with nothing saying it should")
        || text.contains("no longer has its exact evidenced")
        || text.contains("not uniquely revisable")
        || text.contains("malformed adjacent-owner revision")
        || text.contains("duplicate adjacent-owner revision")
}

/// Everything one stage did with one unit.
struct StageOutcome {
    application: Application,
    reason: Option<String>,
    /// Every complete body this stage proposed for the unit.
    proposed: Vec<Vec<String>>,
    /// The one it proved, when it proved one.
    selected: Option<Vec<String>>,
    selection_id: Option<String>,
}

/// What one stage did with one unit, read in that stage's own vocabulary.
fn stage_outcome(stage: &str, facts: &legacy::Stage, name: &str) -> Option<StageOutcome> {
    let accepted = facts.accepted.iter().find(|c| c.name == name);
    let deferred = facts.deferred.iter().find(|c| c.name == name);
    let candidate = accepted.or(deferred)?;
    let proposed = proposed_bodies(&candidate.evidence);

    let refused = facts
        .events
        .iter()
        .filter(|event| event.unit == name)
        .filter_map(|event| {
            let kind = refusal_kind(stage, &event.status)?;
            let reason = event.reason.clone().or_else(|| Some(event.status.clone()));
            Some((kind, reason))
        })
        .next_back();

    let application = match (accepted.is_some(), &refused) {
        (true, _) => Application::Accepted,
        (false, Some((Application::BuildRefused, reason)))
            if reason.as_deref().is_some_and(is_preflight) =>
        {
            Application::PreflightRefused
        }
        (false, Some((kind, _))) => *kind,
        (false, None) => Application::NotAttempted,
    };

    let selection_id = facts.selections.get(name).cloned();
    let selected =
        accepted.and_then(|candidate| selected_body(&candidate.evidence, selection_id.as_deref()));
    Some(StageOutcome {
        application,
        reason: refused.and_then(|(_, reason)| reason),
        proposed,
        selected,
        selection_id,
    })
}

/// The one body a stage proved, rather than any body it considered.
///
/// Coverage records which alternative it proved by id; discovery has a single
/// proposal, so accepting it is selecting it. Guessing from the proposal list
/// would make a ranking failure indistinguishable from a stage that only ever
/// had one option.
fn selected_body(evidence: &serde_json::Value, id: Option<&str>) -> Option<Vec<String>> {
    if let (Some(id), Some(alternatives)) =
        (id, evidence.get("alternatives").and_then(|v| v.as_array()))
    {
        let chosen = alternatives.iter().find(|a| a.get("id").and_then(|v| v.as_str()) == Some(id));
        return chosen.and_then(|a| lines_of(a.get("lines")?));
    }
    // A stage whose candidate is one complete body.
    evidence.get("lines").and_then(lines_of)
}

fn lines_of(value: &serde_json::Value) -> Option<Vec<String>> {
    let found: Vec<String> =
        value.as_array()?.iter().filter_map(|l| l.as_str().map(str::to_string)).collect();
    (!found.is_empty()).then_some(found)
}

/// How far the run got with one unit, and every stage's part in it.
///
/// Stages are visited in execution order, never in whatever order a map
/// iterates: which stage decided last is the whole question, and `coverage`
/// sorts before `discover` and `verify` by accident of the alphabet.
fn trace(name: &str, run: &RunFacts) -> Trace {
    let mut traces = Vec::new();
    let mut proposed: Vec<Vec<String>> = Vec::new();
    let mut selected = None;
    let mut selected_stage_proposed = Vec::new();
    let mut selection_id = None;
    let mut refusal = None;

    for stage in STAGES {
        // Derivation's candidates are symbol names, not units; it has no
        // opinion about ownership and is not asked for one.
        if stage == "derive" {
            continue;
        }
        let Some(facts) = run.stages.get(stage) else { continue };
        let Some(outcome) = stage_outcome(stage, facts, name) else { continue };
        proposed.extend(outcome.proposed.iter().cloned());
        if outcome.application == Application::Accepted && outcome.selected.is_some() {
            // The last ownership-producing stage to accept is the one whose
            // body survives. Verification accepts the same body and has no
            // split proposal of its own, so it deliberately does not replace
            // this record.
            selected = outcome.selected.clone();
            selected_stage_proposed = outcome.proposed.clone();
            selection_id = outcome.selection_id.clone();
        } else if refusal.is_none() {
            refusal = outcome.reason.clone();
        }
        traces.push(StageTrace {
            stage: stage.to_string(),
            application: outcome.application,
            reason: outcome.reason,
        });
    }

    // The last stage to accept decides, and an earlier acceptance it replaced
    // is superseded rather than simply accepted.
    let application = match traces.iter().rposition(|t| t.application == Application::Accepted) {
        Some(index) => {
            for earlier in &mut traces[..index] {
                if earlier.application == Application::Accepted {
                    earlier.application = Application::Superseded;
                }
            }
            Application::Accepted
        }
        None => traces.iter().map(|t| t.application).next_back().unwrap_or(Application::NotOffered),
    };
    Trace {
        application,
        traces,
        refusal,
        proposed,
        selected,
        selected_stage_proposed,
        selection_id,
    }
}

struct Trace {
    application: Application,
    traces: Vec<StageTrace>,
    refusal: Option<String>,
    proposed: Vec<Vec<String>>,
    selected: Option<Vec<String>>,
    selected_stage_proposed: Vec<Vec<String>>,
    selection_id: Option<String>,
}

/// What the run believed about this unit, named rather than scored.
fn evidence_names(name: &str, run: &RunFacts) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for facts in run.stages.values() {
        for candidate in facts.accepted.iter().chain(&facts.deferred) {
            if candidate.name != name {
                continue;
            }
            collect_evidence(&candidate.evidence, &mut found);
        }
    }
    found.into_iter().collect()
}

fn collect_evidence(value: &serde_json::Value, into: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for key in ["evidence", "kind", "method"] {
                if let Some(serde_json::Value::String(text)) = map.get(key) {
                    into.insert(text.clone());
                }
            }
            map.values().for_each(|item| collect_evidence(item, into));
        }
        serde_json::Value::Array(items) => {
            items.iter().for_each(|item| collect_evidence(item, into))
        }
        _ => {}
    }
}

/// What the run's own record supports saying about identification.
///
/// Deliberately conservative, and deliberately incomplete: telling a
/// corroborated identification from a merely plausible one needs the typed
/// attribution records the current evidence does not carry. Until it does, a
/// unit with one explanation is `tentative` and one with several materially
/// different explanations is `ambiguous`. Nothing here is reported as
/// `corroborated`, because nothing here can honestly establish it.
fn identify(proposals: usize, bodies: &[Vec<String>]) -> Identification {
    let distinct: BTreeSet<&Vec<String>> = bodies.iter().collect();
    match (proposals, distinct.len()) {
        (0, _) => Identification::Absent,
        (_, 0 | 1) => Identification::Tentative,
        _ => Identification::Ambiguous,
    }
}

fn verification(name: &str, run: &RunFacts) -> Verification {
    let Some(verify) = run.stages.get("verify") else { return Verification::NotAttempted };
    if verify.accepted.iter().any(|c| c.name == name) {
        Verification::Verified
    } else if verify.deferred.iter().any(|c| c.name == name) {
        Verification::Failed
    } else {
        Verification::NotAttempted
    }
}

// --- the command itself -----------------------------------------------------

pub fn run(args: Args) -> Result<()> {
    match args.command {
        Operation::Prepare(args) => prepare(&args),
        Operation::Score(args) => score_command(&args),
    }
}

fn score_command(args: &ScoreArgs) -> Result<()> {
    let manifest = Manifest::read(&args.manifest)?;
    let facts = read_run(&args.run)?;
    if facts.source != manifest.source {
        bail!(
            "The run migrated from {} and the manifest describes {}",
            facts.source,
            manifest.source
        );
    }
    if facts.target != manifest.target {
        bail!(
            "The run migrated to {} and the manifest describes {}",
            facts.target,
            manifest.target
        );
    }
    let result = score(&manifest, &facts);
    let output = args.output.clone().unwrap_or_else(|| args.run.join("benchmark"));
    std::fs::create_dir_all(&output)?;
    write_json(&output.join("score.json"), &result)?;
    std::fs::write(output.join("score.md"), markdown(&result))?;
    if let Some(directory) = &args.fixture {
        write_run_fixture(directory, &facts)?;
    }

    println!("{}", serde_json::to_string_pretty(&result.populations)?);
    if !result.baseline_agrees {
        println!(
            "\nWarning: the run did not start from this manifest's baseline, so these numbers \
             describe two different projects."
        );
    }
    if !result.regressions.is_empty() {
        println!("\nRegressed: {}", result.regressions.join(", "));
    }
    println!("\nEvidence: {}", output.display());
    Ok(())
}

/// Writes the files a committed regression test needs.
///
/// The primary data, in the form the project itself writes it, rather than a
/// distillation: three split files and the linkage the two revisions declared.
/// Anyone can read them, `git diff` says something useful about them, and a test
/// that builds its manifest from them is exercising the same code path
/// `prepare` does rather than a saved copy of that code's output.
///
/// All of every split file, not only the interesting units. Whether a range is
/// somebody else's is a question about the whole address space, so a manifest
/// missing 350 units would quietly reclassify theft as unclaimed ground.
fn write_oracle_fixture(
    directory: &Path,
    manifest: &Manifest,
    baseline_splits: &str,
    oracle_splits: &str,
    linkage: &Linkage,
) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    std::fs::write(directory.join("baseline.splits.txt"), baseline_splits)?;
    std::fs::write(directory.join("oracle.splits.txt"), oracle_splits)?;
    write_json(&directory.join("linkage.json"), linkage)?;
    write_json(
        &directory.join("provenance.json"),
        &serde_json::json!({
            "source": manifest.source,
            "target": manifest.target,
            "baseline_revision": manifest.baseline.id,
            "baseline_splits_sha256": manifest.baseline.splits_sha256,
            "oracle_revision": manifest.oracle.id,
            "oracle_splits_sha256": manifest.oracle.splits_sha256,
        }),
    )?;
    println!("Fixture: {}", directory.display());
    Ok(())
}

/// What the run left behind, beside the oracle files `prepare` wrote.
fn write_run_fixture(directory: &Path, facts: &RunFacts) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    std::fs::write(directory.join("published.splits.txt"), render_splits(&facts.after))?;
    std::fs::write(directory.join("run-id.txt"), format!("{}\n", facts.id))?;
    println!("Fixture: {}", directory.display());
    Ok(())
}

/// Split blocks written back out as a file a test can read with [`Splits`].
fn render_splits(blocks: &Blocks) -> String {
    let mut text = String::from("Sections:\n\n");
    for (name, lines) in blocks {
        text.push_str(name);
        text.push_str(":\n");
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        text.push('\n');
    }
    text
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Failed to parse {}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("Failed to write {}", path.display()))
}

fn markdown(score: &Score) -> String {
    let mut lines = vec![
        format!("# Historical recall: run {}", score.run),
        String::new(),
        format!(
            "Baseline `{}` against oracle `{}`, target {}.",
            score.baseline_revision, score.oracle_revision, score.target
        ),
        String::new(),
    ];
    if !score.baseline_agrees {
        lines.push(
            "**The run did not start from this manifest's baseline.** Everything below compares \
             two different projects."
                .to_string(),
        );
        lines.push(String::new());
    }
    lines.extend([
        "*Exact* means the unit ends up owning precisely the oracle's ground. *Partial* overlaps \
         it with a boundary unresolved. *Wrong* holds ground the oracle gives to someone else. \
         *Unchanged* is a unit the run left alone, which for a control is the right answer and \
         for a target is a miss."
            .to_string(),
        String::new(),
        "| Population | Units | Exact | Partial | Wrong | Unowned | Unchanged | Proposed exact | \
         Selected exact | Ranking failures | Damaged | No longer exact |"
            .to_string(),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|".to_string(),
    ]);
    for (name, value) in &score.populations {
        lines.push(format!(
            "| {name} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            value.units,
            value.exact,
            value.partial,
            value.wrong,
            value.unowned,
            value.unchanged,
            value.proposal_recall,
            value.selected_exact,
            value.ranking_failures,
            value.regressed,
            value.lost_exactness
        ));
    }

    lines.extend([
        String::new(),
        "## Bytes".to_string(),
        String::new(),
        "*Gained* and *lost* are both measured, because a body that trades ground for ground of \
         the same size has not done nothing. *Newly wrong* is what the run itself took from \
         somebody else; *wrong after* includes what the baseline already had."
            .to_string(),
        String::new(),
        "| Population | Gained | Lost | Newly wrong | Wrong after | Missed | No oracle answer |"
            .to_string(),
        "|---|---:|---:|---:|---:|---:|---:|".to_string(),
    ]);
    for (name, value) in &score.populations {
        lines.push(format!(
            "| {name} | {} | {} | {} | {} | {} | {} |",
            value.gained_bytes,
            value.lost_bytes,
            value.newly_wrong_bytes,
            value.wrong_after_bytes,
            value.missed_bytes,
            value.unknown_bytes
        ));
    }

    lines.extend([
        String::new(),
        "## Regressions".to_string(),
        String::new(),
        "Units the run took ground from, or took ground from someone else for, where a build \
         proved the oracle's answer. Named, because a total that has not moved says nothing about \
         whether these are the same ones. This list must be empty."
            .to_string(),
        String::new(),
    ]);
    if score.regressions.is_empty() {
        lines.push("None.".to_string());
    } else {
        lines.extend(score.regressions.iter().map(|name| format!("- `{name}`")));
    }
    if !score.unverified_regressions.is_empty() {
        lines.extend([
            String::new(),
            format!(
                "{} more against oracle splits nothing has verified, which are reported rather \
                 than counted: {}.",
                score.unverified_regressions.len(),
                score.unverified_regressions.join(", ")
            ),
        ]);
    }

    lines.extend([
        String::new(),
        "## Recall set".to_string(),
        String::new(),
        "| Unit | Code | Full | Identification | Code recall | Full recall | Application | Verification |"
            .to_string(),
        "|---|---|---|---|---|---|---|---|".to_string(),
    ]);
    for row in score.units.iter().filter(|row| row.in_recall_set) {
        lines.push(format!(
            "| `{}` | {:?} | {:?} | {:?} | {} | {} | {:?} | {:?} |",
            row.unit,
            row.code_outcome,
            row.full_outcome,
            row.identification,
            recall_label(row.code_recall),
            recall_label(row.full_recall),
            row.application,
            row.verification
        ));
    }
    lines.join("\n") + "\n"
}

fn recall_label(recall: Recall) -> &'static str {
    if recall.ranking_failure {
        "ranking-failure"
    } else if recall.selected {
        "selected"
    } else if recall.proposed {
        "proposed"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(entries: &[(&str, u32, u32)]) -> Body {
        let mut blocks: Blocks = IndexMap::new();
        blocks.insert(
            "u".to_string(),
            entries
                .iter()
                .map(|(section, start, end)| {
                    format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
                })
                .collect(),
        );
        Body::of(&blocks, "u")
    }

    #[test]
    fn a_body_survives_being_written_back_out_as_split_lines() {
        let mut blocks: Blocks = IndexMap::new();
        blocks.insert("u".to_string(), vec![
            "\t.text       start:0x80001000 end:0x80001100".to_string(),
            "\t.bss        start:0x80400000 end:0x80400010".to_string(),
            "\t.bss        start:0x80410000 end:0x80410010 align:4 common".to_string(),
        ]);
        let original = Body::of(&blocks, "u");
        let mut round: Blocks = IndexMap::new();
        round.insert("u".to_string(), original.render());
        assert!(original.same_structure(&Body::of(&round, "u")), "{:?}", original.render());
    }

    #[test]
    fn a_proposal_is_found_wherever_a_stage_happens_to_nest_it() {
        // Discovery puts `lines` at the top; coverage nests it under each
        // alternative. One walk finds both, so a stage added later is measured
        // without this being taught about it.
        let discovery = serde_json::json!({ "kind": "code", "lines": ["a", "b"] });
        assert_eq!(proposed_bodies(&discovery), vec![vec!["a".to_string(), "b".to_string()]]);
        let coverage = serde_json::json!({
            "alternatives": [{ "lines": ["x"] }, { "lines": ["y", "z"] }],
        });
        assert_eq!(proposed_bodies(&coverage).len(), 2);
        assert!(proposed_bodies(&serde_json::json!({ "lines": [] })).is_empty());
    }

    #[test]
    fn a_preflight_refusal_is_told_apart_from_a_build_refusal() {
        assert!(is_preflight(
            "CFoo.cpp would lose .text 0x1000..0x2000 with nothing saying it should"
        ));
        assert!(!is_preflight("retail-mismatch: Retail DOL bytes differ"));
    }

    #[test]
    fn each_legacy_stage_uses_the_statuses_it_actually_wrote() {
        let candidate = legacy::Candidate {
            name: "u.cpp".into(),
            evidence: serde_json::json!({ "lines": ["\t.text start:0x00001000 end:0x00002000"] }),
        };
        let mut stage = legacy::Stage {
            deferred: vec![candidate.clone()],
            events: vec![legacy::Event {
                unit: "u.cpp".into(),
                status: "failed-source-link-or-hash".into(),
                reason: Some("ninja failed".into()),
            }],
            ..Default::default()
        };
        let verify = stage_outcome("verify", &stage, "u.cpp").unwrap();
        assert_eq!(verify.application, Application::BuildRefused);
        assert_eq!(verify.reason.as_deref(), Some("ninja failed"));

        stage.events[0].status = "link-order-cycle".into();
        stage.events[0].reason = None;
        let discover = stage_outcome("discover", &stage, "u.cpp").unwrap();
        assert_eq!(discover.application, Application::PreflightRefused);
        assert_eq!(discover.reason.as_deref(), Some("link-order-cycle"));
    }

    #[test]
    fn an_exact_proposal_from_an_earlier_stage_is_not_a_ranking_failure() {
        let exact = vec!["\t.text       start:0x00001000 end:0x00002000".to_string()];
        let wrong = vec!["\t.text       start:0x00001000 end:0x00001800".to_string()];
        let truth = body(&[(".text", 0x1000, 0x2000)]);
        let mut trace = Trace {
            application: Application::Accepted,
            traces: Vec::new(),
            refusal: None,
            proposed: vec![exact.clone(), wrong.clone()],
            selected: Some(wrong.clone()),
            selected_stage_proposed: vec![wrong],
            selection_id: None,
        };
        let across_stages = recall_for("u", &truth, &trace, Scope::Code);
        assert!(across_stages.proposed);
        assert!(!across_stages.ranking_failure);

        trace.selected_stage_proposed.push(exact);
        assert!(recall_for("u", &truth, &trace, Scope::Code).ranking_failure);
    }

    #[test]
    fn linkage_is_read_for_one_version_at_a_time() {
        let text = "VERSIONS = [\n    \"A\",\n    \"B\",\n]\n\
                    objects = [\n\
                    \x20   Object(MatchingFor(\"A\"), \"only_a.cpp\"),\n\
                    \x20   Object(Matching, \"both.cpp\"),\n\
                    \x20   Object(NonMatching, \"neither.cpp\"),\n]\n";
        assert_eq!(
            linked(text, "A").unwrap(),
            BTreeSet::from(["only_a.cpp".to_string(), "both.cpp".to_string()])
        );
        assert_eq!(linked(text, "B").unwrap(), BTreeSet::from(["both.cpp".to_string()]));
    }

    fn manifest(units: &[(&str, Body, Body, bool)]) -> Manifest {
        Manifest {
            schema: MANIFEST_SCHEMA,
            source: "NTSC".into(),
            target: "PAL".into(),
            baseline: Revision {
                id: "base".into(),
                splits_sha256: String::new(),
                configure_sha256: None,
            },
            oracle: Revision {
                id: "oracle".into(),
                splits_sha256: String::new(),
                configure_sha256: None,
            },
            recall_set: units
                .iter()
                .filter(|(_, _, _, recall)| *recall)
                .map(|(name, ..)| (*name).to_string())
                .collect(),
            units: units
                .iter()
                .map(|(name, baseline, oracle, recall)| {
                    ((*name).to_string(), UnitTruth {
                        changed: !baseline.same_structure(oracle),
                        changed_code: !baseline
                            .within(Scope::Code)
                            .same_ownership(&oracle.within(Scope::Code)),
                        baseline: baseline.clone(),
                        oracle: oracle.clone(),
                        baseline_linked: false,
                        oracle_linked: *recall,
                        trust: if *recall { Trust::SourceLinked } else { Trust::Unverified },
                    })
                })
                .collect(),
        }
    }

    fn facts(before: Blocks, after: Blocks) -> RunFacts {
        RunFacts::from_splits("test", "NTSC", "PAL", before, after)
    }

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
    fn a_unit_that_was_right_and_takes_a_neighbours_ground_is_named() {
        // CGuiCamera's shape: the baseline already agreed with the oracle, and
        // the run moved it into the unit next door. No byte total notices this
        // on its own — the run gained ground, on paper — so it is its own
        // verdict, and the verdict names the unit.
        let mine = body(&[(".text", 0x1000, 0x2000)]);
        let theirs = body(&[(".text", 0x2000, 0x3000)]);
        let manifest = manifest(&[
            ("mine.cpp", mine.clone(), mine, true),
            ("theirs.cpp", theirs.clone(), theirs, true),
        ]);
        let run = facts(
            blocks(&[("mine.cpp", 0x1000, 0x2000), ("theirs.cpp", 0x2000, 0x3000)]),
            blocks(&[("mine.cpp", 0x1000, 0x2100), ("theirs.cpp", 0x2100, 0x3000)]),
        );
        let result = score(&manifest, &run);
        assert_eq!(result.regressions, ["mine.cpp", "theirs.cpp"]);
        // One took, the other lost. Both are damage and both are named.
        let by_name: BTreeMap<&str, &UnitScore> =
            result.units.iter().map(|row| (row.unit.as_str(), row)).collect();
        assert_eq!(by_name["mine.cpp"].full.newly_wrong_bytes, 0x100);
        assert_eq!(by_name["theirs.cpp"].full.lost_bytes, 0x100);
    }

    #[test]
    fn running_past_the_last_split_into_unclaimed_ground_is_not_damage() {
        // CActor's shape, and the reason a regression is defined as taking or
        // losing ground rather than as any disagreement: the unit keeps every
        // byte the oracle gives it and runs 0x100 past the end into territory
        // nobody has split. The oracle has no opinion there. Counting it as
        // damage reported 160 broken units in a run that broke none.
        let truth = body(&[(".text", 0x1000, 0x2000)]);
        let manifest = manifest(&[("a.cpp", truth.clone(), truth, true)]);
        let run = facts(blocks(&[("a.cpp", 0x1000, 0x2000)]), blocks(&[("a.cpp", 0x1000, 0x2100)]));
        let result = score(&manifest, &run);
        assert!(result.regressions.is_empty());
        assert!(!result.units[0].regressed);
        // Still visible, because an unsupported claim is worth seeing.
        assert!(result.units[0].lost_exactness);
        assert_eq!(result.units[0].full.unknown_bytes, 0x100);
    }

    #[test]
    fn damage_against_an_unverified_oracle_split_is_reported_apart() {
        // Nothing has proved this unit's later split, so it is not firm enough
        // ground to fail a run over — but hiding it would be worse.
        let mine = body(&[(".text", 0x1000, 0x2000)]);
        let theirs = body(&[(".text", 0x2000, 0x3000)]);
        let manifest = manifest(&[
            ("mine.cpp", mine.clone(), mine, false),
            ("theirs.cpp", theirs.clone(), theirs, false),
        ]);
        let run = facts(
            blocks(&[("mine.cpp", 0x1000, 0x2000), ("theirs.cpp", 0x2000, 0x3000)]),
            blocks(&[("mine.cpp", 0x1000, 0x2100), ("theirs.cpp", 0x2100, 0x3000)]),
        );
        let result = score(&manifest, &run);
        assert!(result.regressions.is_empty());
        assert_eq!(result.unverified_regressions, ["mine.cpp", "theirs.cpp"]);
    }

    #[test]
    fn a_truncated_recovery_and_a_theft_are_different_answers() {
        // Two ways to be not-exact that must never be counted together: one
        // stopped short inside its own unit, the other reached into its
        // neighbour. CameraPitchVolume and CScriptPlatform respectively.
        let manifest = manifest(&[
            ("short.cpp", Body::default(), body(&[(".text", 0x1000, 0x2000)]), true),
            ("thief.cpp", Body::default(), body(&[(".text", 0x3000, 0x4000)]), true),
            (
                "victim.cpp",
                body(&[(".text", 0x2000, 0x3000)]),
                body(&[(".text", 0x2000, 0x3000)]),
                false,
            ),
        ]);
        let run = facts(
            blocks(&[("victim.cpp", 0x2000, 0x3000)]),
            blocks(&[
                ("short.cpp", 0x1000, 0x1800),
                ("victim.cpp", 0x2000, 0x3000),
                ("thief.cpp", 0x2C00, 0x4000),
            ]),
        );
        let result = score(&manifest, &run);
        let by_name: BTreeMap<&str, &UnitScore> =
            result.units.iter().map(|row| (row.unit.as_str(), row)).collect();
        assert_eq!(by_name["short.cpp"].code_outcome, Outcome::Partial);
        assert_eq!(by_name["short.cpp"].code.newly_wrong_bytes, 0);
        assert_eq!(by_name["thief.cpp"].code_outcome, Outcome::Incorrect);
        assert_eq!(by_name["thief.cpp"].code.newly_wrong_bytes, 0x400);
        assert_eq!(result.populations["recall/code"].partial, 1);
        assert_eq!(result.populations["recall/code"].wrong, 1);
    }

    #[test]
    fn code_and_data_are_scored_apart_for_the_same_unit() {
        // CStreamAudioManager: the exact `.text` range and a missing `.bss`
        // one. Counting only code calls this a complete recovery.
        let oracle = body(&[(".text", 0x1000, 0x2000), (".bss", 0x8000, 0x8100)]);
        let manifest = manifest(&[("a.cpp", Body::default(), oracle, true)]);
        let run = facts(IndexMap::new(), blocks(&[("a.cpp", 0x1000, 0x2000)]));
        let result = score(&manifest, &run);
        assert_eq!(result.units[0].code_outcome, Outcome::Exact);
        assert_eq!(result.units[0].full_outcome, Outcome::Partial);
        assert!(result.units[0].code_exact);
        assert!(!result.units[0].full_exact);
        assert_eq!(result.units[0].full.missed_bytes, 0x100);
    }

    #[test]
    fn a_run_that_did_not_start_from_the_manifests_baseline_says_so() {
        let truth = body(&[(".text", 0x1000, 0x2000)]);
        let manifest = manifest(&[("a.cpp", truth.clone(), truth, false)]);
        let run = facts(blocks(&[("a.cpp", 0x1000, 0x1400)]), blocks(&[("a.cpp", 0x1000, 0x2000)]));
        assert!(!score(&manifest, &run).baseline_agrees);
    }

    #[test]
    fn a_noop_run_proves_its_unpublished_baseline_by_digest() {
        let truth = body(&[(".text", 0x1000, 0x2000)]);
        let mut manifest = manifest(&[("a.cpp", truth.clone(), truth, false)]);
        manifest.baseline.splits_sha256 = "known-baseline".into();
        let mut run = facts(IndexMap::new(), IndexMap::new());
        run.use_manifest_baseline = true;
        run.baseline_splits_sha256 = Some("known-baseline".into());
        assert!(score(&manifest, &run).baseline_agrees);

        run.baseline_splits_sha256 = Some("different-baseline".into());
        assert!(!score(&manifest, &run).baseline_agrees);
    }
}
