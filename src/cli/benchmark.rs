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
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::{
    analysis::{
        ownership::{
            FunctionAttribution, IdentificationBasis, IdentificationConfidence,
            IdentificationReport, UnitIdentification,
        },
        ownership_score::{
            Application, Blocks, Body, Identification, Ledger, Oracle, Outcome, Scope,
            SelectionQuality, Verification, ledger, outcome, selection_quality,
        },
    },
    project::{
        configure_py::Configure,
        splits::{Range, Splits},
    },
};

/// Bumped when the manifest's meaning changes. The historical run's own schema
/// is frozen — see [`legacy`] — so this versions only what `prepare` writes.
pub const MANIFEST_SCHEMA: u32 = 4;
pub const SCORE_SCHEMA: u32 = 5;
/// Coverage summaries before schema 10 do not contain the typed identification
/// inventory. Keep this explicit here so the historical adapter cannot silently
/// reinterpret a future coverage schema merely because some fields deserialize.
const TYPED_IDENTIFICATION_COVERAGE_SCHEMA: u32 = 10;
const REFERENCED_IDENTIFICATION_COVERAGE_SCHEMA: u32 = 11;

#[derive(ClapArgs, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub command: Operation,
}

#[derive(Subcommand, Debug)]
pub enum Operation {
    /// Build an oracle manifest from two immutable revisions.
    Prepare(Box<PrepareArgs>),
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
    /// A saved baseline `config.yml`, instead of reading the Git blob.
    #[arg(long)]
    pub baseline_config: Option<PathBuf>,
    /// A saved oracle `config.yml`, instead of reading the Git blob.
    #[arg(long)]
    pub oracle_config: Option<PathBuf>,
    /// A baseline DOL whose SHA-1 is checked against the revision's declared
    /// retail hash. This proves the artifact's bytes, not its linker inputs.
    #[arg(long)]
    pub baseline_dol: Option<PathBuf>,
    /// An oracle DOL whose SHA-1 is checked against the revision's declared
    /// retail hash. This proves the artifact's bytes, not its linker inputs.
    #[arg(long)]
    pub oracle_dol: Option<PathBuf>,
    /// A completed migration run at the oracle revision whose `verify` stage
    /// proved compiled link inputs and retail bytes. Only units covered by this
    /// proof are trusted as source-linked oracle answers.
    #[arg(long, conflicts_with = "oracle_dol")]
    pub oracle_verification_run: Option<PathBuf>,
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
    /// Retail target hash declared by this revision's `config.yml`.
    pub expected_retail_sha1: String,
    /// SHA-1 of a supplied DOL checked against `expected_retail_sha1`. This says
    /// nothing about which objects were linked into it; source-link trust also
    /// requires an explicit verified-linkage set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_dol_sha1: Option<String>,
}

impl Revision {
    fn retail_verified(&self) -> bool {
        valid_sha1(&self.expected_retail_sha1)
            && self
                .verified_dol_sha1
                .as_deref()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&self.expected_retail_sha1))
    }
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
        validate_revision("baseline", &manifest.baseline)?;
        validate_revision("oracle", &manifest.oracle)?;
        if manifest.units.values().any(|unit| unit.trust == Trust::SourceLinked) {
            if !manifest.oracle.retail_verified() {
                bail!("Manifest marks source-linked oracle units as trusted without a retail DOL")
            }
            if manifest
                .units
                .values()
                .any(|unit| unit.trust == Trust::SourceLinked && !unit.oracle_linked)
            {
                bail!("Manifest trusts a unit the oracle does not declare source-linked")
            }
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

fn valid_sha1(hash: &str) -> bool {
    hash.len() == 40 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_revision(label: &str, revision: &Revision) -> Result<()> {
    if !valid_sha1(&revision.expected_retail_sha1) {
        bail!("The {label} revision does not declare a valid retail SHA-1")
    }
    if revision.verified_dol_sha1.is_some() && !revision.retail_verified() {
        bail!("The {label} revision's verified DOL does not match its declared retail SHA-1")
    }
    Ok(())
}

fn file_sha1(path: &Path) -> Result<String> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(format!("{:x}", Sha1::digest(bytes)))
}

fn retail_sha1(config: &str) -> Result<String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(config).context("Failed to parse config.yml")?;
    value
        .get("hash")
        .and_then(serde_yaml::Value::as_str)
        .map(str::to_string)
        .filter(|hash| valid_sha1(hash))
        .context("config.yml does not declare a 40-digit hexadecimal target `hash`")
}

fn verified_dol(path: Option<&PathBuf>, expected: &str, revision: &str) -> Result<Option<String>> {
    let Some(path) = path else { return Ok(None) };
    let actual = file_sha1(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!(
            "The DOL supplied for {revision} has SHA-1 {actual}, but its config.yml declares \
             {expected}"
        )
    }
    Ok(Some(actual))
}

/// Reads one path at one revision, without touching the working tree.
fn blob(root: &Path, revision: &str, path: &str) -> Result<String> {
    String::from_utf8(blob_bytes(root, revision, path)?).context("Blob is not UTF-8")
}

fn blob_bytes(root: &Path, revision: &str, path: &str) -> Result<Vec<u8>> {
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
    Ok(output.stdout)
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
    /// Oracle declarations whose compiled objects a completed verification run
    /// proved were real linker inputs while reproducing retail bytes.
    #[serde(default)]
    pub verified_oracle: BTreeSet<String>,
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
    validate_revision("baseline", &baseline)?;
    validate_revision("oracle", &oracle)?;
    if !baseline.expected_retail_sha1.eq_ignore_ascii_case(&oracle.expected_retail_sha1) {
        bail!(
            "The revisions disagree about the retail target: {} versus {}",
            baseline.expected_retail_sha1,
            oracle.expected_retail_sha1
        )
    }
    if !linkage.verified_oracle.is_subset(&linkage.oracle) {
        bail!("Verified oracle linkage names units the oracle does not declare source-linked")
    }
    if !linkage.verified_oracle.is_empty() && !oracle.retail_verified() {
        bail!("Verified oracle linkage requires a retail-identical oracle DOL")
    }
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
            trust: if linkage.verified_oracle.contains(name) && oracle.retail_verified() {
                Trust::SourceLinked
            } else {
                Trust::Unverified
            },
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
    Ok(Configure::parse(text)?.configured_names(version))
}

#[derive(Debug)]
struct OracleVerification {
    dol_sha1: String,
    units: BTreeSet<String>,
}

fn supported_run_schema(schema: u32) -> bool { matches!(schema, 1..=4) }

const REVISION_BOUND_RUN_SCHEMA: u32 = 3;

struct OracleInputs<'a> {
    target: &'a str,
    configure: &'a str,
    splits: &'a str,
    config: &'a str,
    expected_dol_sha1: &'a str,
    declared: &'a BTreeSet<String>,
    commit: &'a str,
}

/// Reads the durable result of the pipeline's verification stage. Unlike a DOL
/// path, this binds retail bytes to the exact project inputs the run froze and
/// to the stage that checked every configured unit against Ninja's real link
/// inputs.
fn oracle_verification(run: &Path, oracle: &OracleInputs<'_>) -> Result<OracleVerification> {
    let summary: legacy::Summary = read_json(&run.join("result.json"))?;
    let record: legacy::Record = read_json(&run.join("run.json"))?;
    let journal: legacy::Journal = read_json(&run.join("publication.json"))?;
    validate_run_schemas(summary.schema, record.schema)?;
    if record.schema < REVISION_BOUND_RUN_SCHEMA {
        bail!(
            "Oracle linkage proof requires run schema {REVISION_BOUND_RUN_SCHEMA}, which records \
             revision-bound repository provenance"
        )
    }
    if summary.id != record.id {
        bail!("Oracle verification result and run record have different run IDs")
    }
    if summary.source != record.source {
        bail!("Oracle verification result and run record have different source versions")
    }
    if summary.target != oracle.target || record.target != oracle.target {
        bail!("Oracle verification run targets a different version than {}", oracle.target)
    }
    if record.stages != ["verify"] {
        bail!("Oracle linkage proof must come from a verify-only run")
    }
    let repository = record
        .repository
        .as_ref()
        .context("Oracle verification run did not record its Git revision")?;
    if !repository.clean {
        bail!("Oracle verification run started from a dirty Git checkout")
    }
    if !repository.head.eq_ignore_ascii_case(oracle.commit) {
        bail!("Oracle verification run was not built from oracle revision {}", oracle.commit)
    }
    if journal.status != "published" {
        bail!("Oracle verification run was not published")
    }

    let expected_inputs = [
        ("configure.py".to_string(), digest(oracle.configure.as_bytes())),
        (format!("config/{}/splits.txt", oracle.target), digest(oracle.splits.as_bytes())),
        (format!("config/{}/config.yml", oracle.target), digest(oracle.config.as_bytes())),
    ];
    for (path, expected) in expected_inputs {
        if record.owner.manifest.get(&path) != Some(&expected) {
            bail!("Oracle verification run did not freeze the manifest's exact {path}")
        }
    }

    let stage = summary
        .stages
        .get("verify")
        .context("Oracle verification run has no verify-stage result")?;
    if stage.validation != "compiled-link-inputs-and-retail-bytes" {
        bail!("Oracle verification stage did not certify compiled linker inputs")
    }
    if !stage.dol_sha1.eq_ignore_ascii_case(oracle.expected_dol_sha1)
        || !summary.published_dol_sha1.eq_ignore_ascii_case(oracle.expected_dol_sha1)
    {
        bail!("Oracle verification run did not publish the declared retail DOL")
    }
    let prepared: legacy::StoredPreparation = read_json(&run.join("verify/prepared.json"))?;
    let unlinked: BTreeSet<&str> = prepared
        .prepared
        .events
        .iter()
        .filter(|event| event.status == "configured-without-split")
        .map(|event| event.unit.as_str())
        .collect();
    let units =
        oracle.declared.iter().filter(|name| !unlinked.contains(name.as_str())).cloned().collect();
    Ok(OracleVerification { dol_sha1: stage.dol_sha1.clone(), units })
}

fn resolve_revision(root: &Path, revision: &str) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", &format!("{revision}^{{commit}}")])
        .output()
        .with_context(|| format!("Failed to resolve oracle revision {revision}"))?;
    if !output.status.success() {
        bail!("Cannot resolve oracle revision {revision}")
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn validate_run_schemas(summary: u32, record: u32) -> Result<()> {
    if summary != record {
        bail!("Run schema differs between result.json ({summary}) and run.json ({record})")
    }
    if !supported_run_schema(summary) {
        bail!("Run schema {summary} is unsupported; this scorer accepts only schemas 1 to 4")
    }
    Ok(())
}

pub fn prepare(args: &PrepareArgs) -> Result<()> {
    let root = std::path::absolute(&args.project_root)?;
    let splits_path = format!("config/{}/splits.txt", args.target);
    let config_path = format!("config/{}/config.yml", args.target);

    let (baseline_id, baseline_splits) =
        source_text(&root, &args.baseline, &splits_path, args.baseline_splits.as_ref())?;
    let (oracle_id, oracle_splits) =
        source_text(&root, &args.oracle, &splits_path, args.oracle_splits.as_ref())?;
    let (_, baseline_configure) =
        source_text(&root, &args.baseline, "configure.py", args.baseline_configure.as_ref())?;
    let (_, oracle_configure) =
        source_text(&root, &args.oracle, "configure.py", args.oracle_configure.as_ref())?;
    let (_, baseline_config) =
        source_text(&root, &args.baseline, &config_path, args.baseline_config.as_ref())?;
    let (_, oracle_config) =
        source_text(&root, &args.oracle, &config_path, args.oracle_config.as_ref())?;
    let baseline_retail = retail_sha1(&baseline_config)?;
    let oracle_retail = retail_sha1(&oracle_config)?;

    let baseline_linked = linked(&baseline_configure, &args.target)?;
    let oracle_linked = linked(&oracle_configure, &args.target)?;
    let oracle_commit = if args.oracle_verification_run.is_some() {
        Some(resolve_revision(&root, &args.oracle)?)
    } else {
        None
    };
    let verification = args
        .oracle_verification_run
        .as_deref()
        .map(|run| {
            oracle_verification(run, &OracleInputs {
                target: &args.target,
                configure: &oracle_configure,
                splits: &oracle_splits,
                config: &oracle_config,
                expected_dol_sha1: &oracle_retail,
                declared: &oracle_linked,
                commit: oracle_commit.as_deref().expect("verification implies a resolved oracle"),
            })
        })
        .transpose()?;
    let linkage = Linkage {
        baseline: baseline_linked,
        oracle: oracle_linked,
        verified_oracle: verification.as_ref().map(|proof| proof.units.clone()).unwrap_or_default(),
    };
    let manifest = build_manifest(
        &args.source,
        &args.target,
        Revision {
            id: baseline_id,
            splits_sha256: digest(baseline_splits.as_bytes()),
            configure_sha256: Some(digest(baseline_configure.as_bytes())),
            expected_retail_sha1: baseline_retail.clone(),
            verified_dol_sha1: verified_dol(
                args.baseline_dol.as_ref(),
                &baseline_retail,
                &args.baseline,
            )?,
        },
        &baseline_splits,
        Revision {
            id: oracle_id,
            splits_sha256: digest(oracle_splits.as_bytes()),
            configure_sha256: Some(digest(oracle_configure.as_bytes())),
            expected_retail_sha1: oracle_retail.clone(),
            verified_dol_sha1: match verification {
                Some(proof) => Some(proof.dol_sha1),
                None => verified_dol(args.oracle_dol.as_ref(), &oracle_retail, &args.oracle)?,
            },
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
        pub schema: u32,
        pub id: String,
        pub source: String,
        pub target: String,
        #[serde(default)]
        pub stages: BTreeMap<String, Stage>,
        #[serde(default)]
        pub published_dol_sha1: String,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct Stage {
        /// Present in schema-2+ runs. Older runs retain only the final candidate
        /// per unit and can provide a lower bound by way of prepared/jobs data.
        #[serde(default)]
        pub offered: Option<Vec<Candidate>>,
        #[serde(default)]
        pub accepted: Vec<Candidate>,
        #[serde(default)]
        pub deferred: Vec<Candidate>,
        #[serde(default)]
        pub selections: BTreeMap<String, String>,
        #[serde(default)]
        pub events: Vec<Event>,
        #[serde(default)]
        pub validation: String,
        #[serde(default)]
        pub dol_sha1: String,
        /// Schema 4: every ownership transaction integration applied, in
        /// order, including ones a later refinement superseded. Absent — and
        /// empty — in older runs.
        #[serde(default)]
        pub applied: Vec<Applied>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct Applied {
        #[serde(default)]
        pub id: String,
        /// Every unit it wrote, the candidate's neighbours included.
        #[serde(default)]
        pub units: Vec<String>,
        #[serde(default)]
        pub record: serde_json::Value,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Candidate {
        pub name: String,
        #[serde(default)]
        pub evidence: serde_json::Value,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct StoredPreparation {
        #[serde(flatten)]
        #[serde(default)]
        pub prepared: Prepared,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct Prepared {
        #[serde(default)]
        pub candidates: Vec<Candidate>,
        #[serde(default)]
        pub events: Vec<Event>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct JobResult {
        #[serde(default)]
        pub accepted: Vec<Candidate>,
        #[serde(default)]
        pub deferred: Vec<Candidate>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Event {
        #[serde(default)]
        pub unit: String,
        #[serde(default)]
        pub status: String,
        #[serde(default)]
        pub reason: Option<String>,
        /// Schema 4: the alternative (transaction) the event concerns.
        #[serde(default)]
        pub alternative: Option<String>,
    }

    /// `run.json`: what the run froze before it did anything.
    ///
    /// `owner.manifest` is a SHA-256 per project input, taken before the first
    /// worker started. It is the only record of where a run began that survives
    /// a run which then changed nothing.
    #[derive(Debug, Clone, Deserialize)]
    pub struct Record {
        pub schema: u32,
        pub id: String,
        pub source: String,
        pub target: String,
        pub stages: Vec<String>,
        #[serde(default)]
        pub repository: Option<RepositoryState>,
        #[serde(default)]
        pub owner: Owner,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RepositoryState {
        pub head: String,
        pub clean: bool,
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
        pub before_sha256: Option<String>,
        #[serde(default)]
        pub after_sha256: Option<String>,
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
    published_dol_sha1: Option<String>,
    /// True only when every stage carried the schema-2 candidate history. Old
    /// worker and preparation artifacts improve recall, but cannot reconstruct
    /// coordinator-only intermediate rediscovery rounds.
    pub proposal_history_complete: bool,
    /// Digest of the target split file before the run started. This is the only
    /// baseline evidence available when publication had no split-file change.
    baseline_splits_sha256: Option<String>,
    /// No journal entry means the run left the split file untouched. In that
    /// case scoring uses the manifest baseline after proving it by digest.
    use_manifest_baseline: bool,
    /// Reduced fixtures contain parsed primary data rather than the original
    /// byte-for-byte file. Real run directories must always prove by digest.
    allow_structural_baseline: bool,
    stages: BTreeMap<String, legacy::Stage>,
    identifications: BTreeMap<String, UnitIdentification>,
    attributions: BTreeMap<String, FunctionAttribution>,
}

#[derive(Deserialize)]
struct CoverageArtifact {
    schema: u32,
    #[serde(default)]
    // Schema 10 embedded the complete IdentificationReport here. Schema 11
    // keeps a compact Vec<UnitIdentification> for human-readable coverage
    // output and points at the complete, content-addressed report through
    // `observation`. Delay decoding until the schema has selected which
    // meaning applies, or serde will try to read schema 11's array as the old
    // report before `referenced_identifications` can follow the reference.
    identifications: Option<serde_json::Value>,
    #[serde(default)]
    observation: Option<crate::analysis::ownership::ObservationReference>,
}

fn typed_identifications(
    coverage: CoverageArtifact,
    source: &str,
    target: &str,
) -> Result<(BTreeMap<String, UnitIdentification>, BTreeMap<String, FunctionAttribution>)> {
    let Some(report) = coverage.identifications else {
        if coverage.schema >= TYPED_IDENTIFICATION_COVERAGE_SCHEMA {
            bail!(
                "Coverage summary schema {} is missing its typed identification inventory",
                coverage.schema
            );
        }
        return Ok((BTreeMap::new(), BTreeMap::new()));
    };
    if coverage.schema != TYPED_IDENTIFICATION_COVERAGE_SCHEMA {
        bail!(
            "Coverage summary schema {} contains typed identifications, but the benchmark understands them only in schema {TYPED_IDENTIFICATION_COVERAGE_SCHEMA}",
            coverage.schema
        );
    }
    let report: IdentificationReport = serde_json::from_value(report)
        .context("Coverage summary schema 10 has an invalid typed identification inventory")?;
    if report.schema != 1 {
        bail!(
            "Coverage summary has identification schema {}, but schema {TYPED_IDENTIFICATION_COVERAGE_SCHEMA} requires identification schema 1",
            report.schema
        );
    }
    if report.source != source || report.target != target {
        bail!("Coverage summary's identification source/target does not match the run");
    }
    let mut identifications = BTreeMap::new();
    for identification in report.units {
        let name = identification.unit.clone();
        if identifications.insert(name.clone(), identification).is_some() {
            bail!("Coverage summary contains duplicate identification for {name}");
        }
    }
    let mut attributions = BTreeMap::new();
    for attribution in report.attributions {
        let id = attribution.id.clone();
        if !identifications.contains_key(&attribution.source.unit) {
            bail!("Coverage summary attributes {id} to an unknown source unit");
        }
        if attributions.insert(id.clone(), attribution).is_some() {
            bail!("Coverage summary contains duplicate attribution {id}");
        }
    }
    for identification in identifications.values() {
        for id in identification.evidence.iter().chain(&identification.unresolved_helpers).chain(
            identification.candidates.iter().flat_map(|candidate| &candidate.attribution_ids),
        ) {
            let Some(attribution) = attributions.get(id) else {
                bail!(
                    "Identification for {} refers to unknown attribution {id}",
                    identification.unit
                )
            };
            if attribution.source.unit != identification.unit {
                bail!(
                    "Identification for {} refers to attribution {id} owned by {}",
                    identification.unit,
                    attribution.source.unit
                );
            }
        }
        for id in identification.candidates.iter().flat_map(|candidate| {
            [
                candidate.left_target_edge.adjacent_attribution_id.as_ref(),
                candidate.right_target_edge.adjacent_attribution_id.as_ref(),
            ]
            .into_iter()
            .flatten()
        }) {
            if !attributions.contains_key(id) {
                bail!(
                    "Identification for {} refers to unknown adjacent attribution {id}",
                    identification.unit
                );
            }
        }
    }
    Ok((identifications, attributions))
}

fn referenced_identifications(
    coverage: CoverageArtifact,
    coverage_dir: &Path,
    source: &str,
    target: &str,
) -> Result<(BTreeMap<String, UnitIdentification>, BTreeMap<String, FunctionAttribution>)> {
    if coverage.schema == TYPED_IDENTIFICATION_COVERAGE_SCHEMA {
        return typed_identifications(coverage, source, target);
    }
    if coverage.schema != REFERENCED_IDENTIFICATION_COVERAGE_SCHEMA {
        if coverage.schema > REFERENCED_IDENTIFICATION_COVERAGE_SCHEMA {
            bail!("Coverage summary schema {} is newer than the benchmark", coverage.schema);
        }
        return Ok((BTreeMap::new(), BTreeMap::new()));
    }
    let reference = coverage.observation.ok_or_else(|| {
        anyhow::anyhow!("Coverage summary schema 11 is missing its ownership observation reference")
    })?;
    if !crate::analysis::ownership::identification_schema_supported(reference.schema) {
        bail!("Coverage observation uses unsupported identification schema {}", reference.schema);
    }
    let relative = Path::new(&reference.file);
    if relative.is_absolute()
        || relative.components().any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("Coverage observation path must stay inside the coverage artifact directory");
    }
    let report: IdentificationReport = read_json(&coverage_dir.join(relative))?;
    let index =
        crate::analysis::ownership::ObservationIndex::load_self_contained(report, source, target)?;
    index
        .verify_reference(&reference)
        .context("Coverage observation does not match coverage.json")?;
    let mut identifications = BTreeMap::new();
    for item in &index.report().units {
        identifications.insert(item.unit.clone(), item.clone());
    }
    let mut attributions = BTreeMap::new();
    for item in &index.report().attributions {
        attributions.insert(item.id.clone(), item.clone());
    }
    Ok((identifications, attributions))
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
            published_dol_sha1: None,
            // A reduced fixture deliberately omits stage evidence. Even when
            // the source run retained every proposal, this representation
            // cannot make an exhaustive proposal-recall claim.
            proposal_history_complete: false,
            baseline_splits_sha256: None,
            use_manifest_baseline: false,
            allow_structural_baseline: true,
            stages: BTreeMap::new(),
            identifications: BTreeMap::new(),
            attributions: BTreeMap::new(),
        }
    }

    /// Adds the retail digest carried by a reduced fixture whose full
    /// `result.json` is intentionally not committed.
    pub fn with_published_dol_sha1(mut self, sha1: impl Into<String>) -> Self {
        self.published_dol_sha1 = Some(sha1.into());
        self
    }

    /// Pins a reduced fixture to the exact baseline file it was distilled from.
    pub fn with_baseline_splits_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.baseline_splits_sha256 = Some(sha256.into());
        self.allow_structural_baseline = false;
        self
    }
}

pub fn read_run(run: &Path) -> Result<RunFacts> {
    let mut summary: legacy::Summary = read_json(&run.join("result.json"))?;
    let record: legacy::Record = read_json(&run.join("run.json"))?;
    let journal: legacy::Journal = read_json(&run.join("publication.json"))?;
    validate_run_schemas(summary.schema, record.schema)?;
    if record.id != summary.id {
        bail!("run.json names run {} but result.json names {}", record.id, summary.id)
    }
    if journal.status != "published" {
        bail!(
            "The run's publication status is `{}`; only a completed, published run can be scored",
            journal.status
        )
    }
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
    if let Some(change) = change
        && change.before_sha256.as_ref() != baseline_splits_sha256.as_ref()
    {
        bail!("Publication's before-image digest for {key} disagrees with run.json")
    }
    let text =
        |side: Option<&String>, expected: Option<&String>, label: &str| -> Result<Option<Blocks>> {
            match side {
                Some(hex) => {
                    let bytes = unhex(hex)?;
                    if expected.is_none_or(|expected| digest(&bytes) != *expected) {
                        bail!("Publication's {label}-image bytes for {key} do not match its digest")
                    }
                    Ok(Some(Splits::parse(&String::from_utf8(bytes)?)?.blocks))
                }
                None => Ok(None),
            }
        };
    let before = text(
        change.and_then(|c| c.before.as_ref()),
        change.and_then(|c| c.before_sha256.as_ref()),
        "before",
    )?;
    let after = text(
        change.and_then(|c| c.after.as_ref()),
        change.and_then(|c| c.after_sha256.as_ref()),
        "after",
    )?;
    // A run that changed no splits published the baseline unchanged, which is a
    // real outcome and not a missing one.
    let (before, after, use_manifest_baseline) = match (before, after) {
        (Some(before), Some(after)) => (before, after, false),
        (Some(_), None) => {
            bail!("Publication deleted {key}; there is no final split state to score")
        }
        (None, None) => (IndexMap::new(), IndexMap::new(), true),
        (None, Some(_)) => {
            bail!("Publication records an after-image for {key} without a before-image")
        }
    };

    let proposal_history_complete = summary
        .stages
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "coverage" | "discover"))
        .all(|(_, stage)| stage.offered.is_some());
    for (name, stage) in &mut summary.stages {
        if stage.offered.is_some() {
            continue;
        }
        let mut recovered = Vec::new();
        let prepared = run.join(name).join("prepared.json");
        if prepared.is_file() {
            let stored: legacy::StoredPreparation = read_json(&prepared)?;
            recovered.extend(stored.prepared.candidates);
        }
        let jobs = run.join(name).join("jobs");
        if jobs.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(&jobs)?.filter_map(Result::ok).collect();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let result = entry.path().join("result.json");
                if !result.is_file() {
                    continue;
                }
                let job: legacy::JobResult = read_json(&result)?;
                recovered.extend(job.accepted);
                recovered.extend(job.deferred);
            }
        }
        recovered.extend(stage.accepted.iter().cloned());
        recovered.extend(stage.deferred.iter().cloned());
        deduplicate_candidates(&mut recovered);
        stage.offered = Some(recovered);
    }

    let artifact = run.join("coverage").join("coverage.json");
    let (identifications, attributions) = if artifact.is_file() {
        referenced_identifications(
            read_json(&artifact)?,
            artifact.parent().expect("coverage.json has a parent"),
            &summary.source,
            &target,
        )?
    } else {
        (BTreeMap::new(), BTreeMap::new())
    };

    Ok(RunFacts {
        id: summary.id,
        source: summary.source,
        target,
        before,
        after,
        published: journal.status == "published",
        published_dol_sha1: (!summary.published_dol_sha1.is_empty())
            .then_some(summary.published_dol_sha1),
        proposal_history_complete,
        baseline_splits_sha256,
        use_manifest_baseline,
        allow_structural_baseline: false,
        stages: summary.stages,
        identifications,
        attributions,
    })
}

fn deduplicate_candidates(candidates: &mut Vec<legacy::Candidate>) {
    let mut distinct = Vec::new();
    for candidate in std::mem::take(candidates) {
        if !distinct.iter().any(|seen: &legacy::Candidate| {
            seen.name == candidate.name && seen.evidence == candidate.evidence
        }) {
            distinct.push(candidate);
        }
    }
    *candidates = distinct;
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

fn body_from_lines(name: &str, lines: &[String]) -> Body {
    let mut one: Blocks = IndexMap::new();
    one.insert(name.to_string(), lines.to_vec());
    Body::of(&one, name)
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
    /// Complete target range sets carried by the recorded proposals. Keeping
    /// these in the score makes an identification auditable without reopening
    /// a multi-megabyte run directory.
    pub candidate_target_intervals: Vec<Vec<Range>>,
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
    pub code_selection: SelectionQuality,
    pub full_selection: SelectionQuality,
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
    /// Whether the run's published DOL matches the retail hash declared by the
    /// immutable revisions. `None` is used only by reduced in-memory fixtures.
    pub published_retail_agrees: Option<bool>,
    /// False for legacy runs whose coordinator did not persist intermediate
    /// rediscovery proposals. Their proposal-recall totals are lower bounds.
    pub proposal_history_complete: bool,
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
    let baseline_agrees = if let Some(recorded) = &run.baseline_splits_sha256 {
        !manifest.baseline.splits_sha256.is_empty() && recorded == &manifest.baseline.splits_sha256
    } else if run.allow_structural_baseline {
        manifest
            .units
            .iter()
            .all(|(name, truth)| Body::of(&run.before, name).same_structure(&truth.baseline))
    } else {
        false
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
            let typed_identification = run.identifications.get(name);
            let selected_body = found.selected.as_ref().map(|lines| body_from_lines(name, lines));
            let mut candidate_target_intervals =
                typed_identification.map(typed_candidate_intervals).unwrap_or_default();
            candidate_target_intervals.extend(
                found.proposed.iter().map(|lines| body_from_lines(name, lines).intervals()),
            );
            candidate_target_intervals.sort();
            candidate_target_intervals.dedup();
            UnitScore {
                unit: name.clone(),
                trust: truth.trust,
                in_recall_set: manifest.recall_set.contains(name),
                needed_change: truth.changed,
                needed_code_change: truth.changed_code,
                identification: typed_identification.map_or_else(
                    || identify(found.proposed.len(), &found.proposed),
                    |identification| score_identification(identification.confidence),
                ),
                identification_evidence: typed_identification.map_or_else(
                    || evidence_names(name, run),
                    |identification| {
                        typed_identification_evidence(identification, &run.attributions)
                    },
                ),
                candidate_target_intervals,
                code_recall: recall_for(name, &truth.oracle, &found, Scope::Code),
                full_recall: recall_for(name, &truth.oracle, &found, Scope::Everything),
                proposals: found.proposed.len(),
                application: found.application,
                stage_trace: found.traces,
                selected: found.selection_id,
                code_selection: selection_quality(
                    name,
                    &oracle,
                    selected_body.as_ref(),
                    Scope::Code,
                ),
                full_selection: selection_quality(
                    name,
                    &oracle,
                    selected_body.as_ref(),
                    Scope::Everything,
                ),
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
        published_retail_agrees: run.published_dol_sha1.as_ref().map(|actual| {
            actual.eq_ignore_ascii_case(&manifest.baseline.expected_retail_sha1)
                && actual.eq_ignore_ascii_case(&manifest.oracle.expected_retail_sha1)
        }),
        proposal_history_complete: run.proposal_history_complete,
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
///
/// The first group is what run schemas 1–3 wrote and must keep meaning what it
/// meant; the second is how atomic ownership transactions (schema 4) phrase a
/// change refused before anything was built.
fn is_preflight(reason: &str) -> bool {
    let text = reason.to_lowercase();
    text.contains("stale precondition")
        || text.contains("transaction refused")
        || text.contains("which this run does not permit")
        || text.contains("with nothing saying it should")
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
///
/// Before run schema 4 a unit's only record is its own candidate. From schema
/// 4 a coverage transaction may also write units that are not candidates at all
/// — the neighbour an adjacent-owner transition narrows — and a later
/// transaction may write a unit after its own selection. So a unit is also
/// credited with every body another candidate's transaction proposed for it,
/// and what it finally holds is whatever the last applied transaction to write
/// it left there, whichever candidate carried that transaction.
fn stage_outcome(stage: &str, facts: &legacy::Stage, name: &str) -> Option<StageOutcome> {
    let accepted = facts.accepted.iter().find(|c| c.name == name);
    let deferred = facts.deferred.iter().find(|c| c.name == name);
    let offered: Vec<&legacy::Candidate> =
        facts.offered.iter().flatten().filter(|candidate| candidate.name == name).collect();
    let own = accepted.or(deferred).or_else(|| offered.last().copied());
    let writers: Vec<&legacy::Candidate> = facts
        .offered
        .iter()
        .flatten()
        .chain(&facts.accepted)
        .chain(&facts.deferred)
        .filter(|candidate| {
            candidate.name != name && !member_bodies(&candidate.evidence, name).is_empty()
        })
        .collect();
    let last_write = facts.applied.iter().rev().find(|entry| entry.units.iter().any(|u| u == name));
    if own.is_none() && writers.is_empty() && last_write.is_none() {
        return None;
    }

    let mut proposed: Vec<Vec<String>> =
        offered.into_iter().flat_map(|candidate| proposed_bodies(&candidate.evidence)).collect();
    if proposed.is_empty()
        && let Some(own) = own
    {
        proposed = proposed_bodies(&own.evidence);
    }
    // The same neighbour body is carried by every recorded version of the
    // proposing candidate; it is one proposal, not several.
    let mut borrowed: Vec<Vec<String>> = Vec::new();
    for body in writers.iter().flat_map(|candidate| member_bodies(&candidate.evidence, name)) {
        if !proposed.contains(&body) && !borrowed.contains(&body) {
            borrowed.push(body);
        }
    }
    proposed.extend(borrowed);

    // Refusals are recorded against the candidate that carried a change. A
    // unit with no candidate of its own was refused only when the transaction
    // actually attempted would have written it: a candidate's other
    // alternatives may leave it alone, and an event that does not say which
    // alternative it was about cannot be attributed to a neighbour at all.
    let concerns = |event: &legacy::Event| match own {
        Some(_) => event.unit == name,
        None => event.alternative.as_deref().is_some_and(|id| {
            writers.iter().any(|candidate| {
                candidate.name == event.unit && alternative_writes(&candidate.evidence, id, name)
            })
        }),
    };
    let refused = facts
        .events
        .iter()
        .filter(|event| concerns(event))
        .filter_map(|event| {
            let kind = refusal_kind(stage, &event.status)?;
            let reason = event.reason.clone().or_else(|| Some(event.status.clone()));
            Some((kind, reason))
        })
        .next_back();

    let application = match (accepted.is_some() || last_write.is_some(), &refused) {
        (true, _) => Application::Accepted,
        (false, Some((Application::BuildRefused, reason)))
            if reason.as_deref().is_some_and(is_preflight) =>
        {
            Application::PreflightRefused
        }
        (false, Some((kind, _))) => *kind,
        (false, None) => Application::NotAttempted,
    };

    let (selected, selection_id) = match last_write {
        Some(entry) => (applied_body(entry, name), Some(entry.id.clone())),
        None => {
            let selection_id = facts.selections.get(name).cloned();
            let selected = accepted
                .and_then(|candidate| selected_body(&candidate.evidence, selection_id.as_deref()));
            (selected, selection_id)
        }
    };
    Some(StageOutcome {
        application,
        reason: refused.and_then(|(_, reason)| reason),
        proposed,
        selected,
        selection_id,
    })
}

/// The complete bodies a candidate's transactions would give `unit`, which
/// need not be the candidate. Kept apart from [`proposed_bodies`] on purpose:
/// transaction members are stored under `after`, never `lines`, so a
/// neighbour's body is never mistaken for the candidate's own.
fn member_bodies(evidence: &serde_json::Value, unit: &str) -> Vec<Vec<String>> {
    evidence
        .get("alternatives")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|alternative| alternative.get("transaction")?.get("members")?.as_array())
        .flatten()
        .filter(|member| member.get("unit").and_then(|v| v.as_str()) == Some(unit))
        .filter_map(|member| lines_of(member.get("after")?))
        .collect()
}

/// Whether the alternative `id` in a candidate's evidence writes `unit`.
fn alternative_writes(evidence: &serde_json::Value, id: &str, unit: &str) -> bool {
    evidence
        .get("alternatives")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter(|alternative| alternative.get("id").and_then(|v| v.as_str()) == Some(id))
        .filter_map(|alternative| alternative.get("transaction")?.get("members")?.as_array())
        .flatten()
        .any(|member| member.get("unit").and_then(|v| v.as_str()) == Some(unit))
}

/// What an applied transaction wrote for `unit`.
fn applied_body(entry: &legacy::Applied, unit: &str) -> Option<Vec<String>> {
    entry
        .record
        .get("alternative")?
        .get("transaction")?
        .get("members")?
        .as_array()?
        .iter()
        .find(|member| member.get("unit").and_then(|v| v.as_str()) == Some(unit))
        .and_then(|member| lines_of(member.get("after")?))
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
        for candidate in
            facts.offered.iter().flatten().chain(&facts.accepted).chain(&facts.deferred)
        {
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

fn score_identification(confidence: IdentificationConfidence) -> Identification {
    match confidence {
        IdentificationConfidence::Absent => Identification::Absent,
        IdentificationConfidence::Tentative => Identification::Tentative,
        IdentificationConfidence::Corroborated => Identification::Corroborated,
        IdentificationConfidence::Ambiguous => Identification::Ambiguous,
    }
}

fn typed_identification_evidence(
    identification: &UnitIdentification,
    attributions: &BTreeMap<String, FunctionAttribution>,
) -> Vec<String> {
    let mut evidence: BTreeSet<String> = identification.evidence.iter().cloned().collect();
    let basis = match identification.basis {
        IdentificationBasis::None => "none",
        IdentificationBasis::NamesOnly => "names-only",
        IdentificationBasis::Binary => "binary",
        IdentificationBasis::Mixed => "mixed",
    };
    evidence.insert(format!("basis:{basis}"));
    evidence.insert(format!("binary-functions:{}", identification.binary_functions));
    evidence.insert(format!(
        "independent-functions:{}",
        identification.independently_supported_functions
    ));
    for id in &identification.evidence {
        let Some(attribution) = attributions.get(id) else { continue };
        evidence.insert(format!("{id}:method:{}", attribution.method.as_str()));
        evidence
            .extend(attribution.evidence.iter().map(|item| format!("{id}:evidence:{}", item.kind)));
    }
    evidence
        .extend(identification.boundary_blockers.iter().map(|reason| format!("boundary:{reason}")));
    evidence.extend(
        identification.application_blockers.iter().map(|reason| format!("application:{reason}")),
    );
    evidence.into_iter().collect()
}

fn parse_hex_address(value: &str) -> Option<u32> {
    u32::from_str_radix(value.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

fn typed_candidate_intervals(identification: &UnitIdentification) -> Vec<Vec<Range>> {
    identification
        .candidates
        .iter()
        .filter_map(|candidate| {
            Some(vec![Range {
                section: candidate.section.clone(),
                start: parse_hex_address(&candidate.start)?,
                end: parse_hex_address(&candidate.end)?,
            }])
        })
        .collect()
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
    println!("{}", serde_json::to_string_pretty(&result.populations)?);
    if !result.baseline_agrees {
        bail!(
            "The run did not start from this manifest's exact baseline; diagnostic output was \
             written to {}, but it is not a valid benchmark",
            output.display()
        );
    }
    if result.published_retail_agrees != Some(true) {
        bail!(
            "The run does not carry a published DOL matching the manifest's retail hash; \
             diagnostic output was written to {}, but it is not a valid benchmark",
            output.display()
        );
    }
    if let Some(directory) = &args.fixture {
        write_run_fixture(directory, &facts, &manifest)?;
    }
    if !result.proposal_history_complete {
        println!(
            "\nWarning: this legacy run did not retain coordinator proposal history; proposed-exact \
             counts are lower bounds."
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
            "baseline_expected_retail_sha1": manifest.baseline.expected_retail_sha1,
            "baseline_verified_dol_sha1": manifest.baseline.verified_dol_sha1,
            "oracle_revision": manifest.oracle.id,
            "oracle_splits_sha256": manifest.oracle.splits_sha256,
            "oracle_expected_retail_sha1": manifest.oracle.expected_retail_sha1,
            "oracle_verified_dol_sha1": manifest.oracle.verified_dol_sha1,
        }),
    )?;
    println!("Fixture: {}", directory.display());
    Ok(())
}

/// What the run left behind, beside the oracle files `prepare` wrote.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunFixtureProvenance {
    pub schema: u32,
    pub run_id: String,
    pub source: String,
    pub target: String,
    pub baseline_splits_sha256: String,
    pub published_splits_sha256: String,
    pub published_dol_sha1: String,
    pub source_proposal_history_complete: bool,
}

fn write_run_fixture(directory: &Path, facts: &RunFacts, manifest: &Manifest) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    let published = if facts.use_manifest_baseline {
        render_splits(&manifest.baseline_blocks())
    } else {
        render_splits(&facts.after)
    };
    std::fs::write(directory.join("published.splits.txt"), &published)?;
    std::fs::write(directory.join("run-id.txt"), format!("{}\n", facts.id))?;
    write_json(&directory.join("run-provenance.json"), &RunFixtureProvenance {
        schema: 1,
        run_id: facts.id.clone(),
        source: facts.source.clone(),
        target: facts.target.clone(),
        baseline_splits_sha256: facts
            .baseline_splits_sha256
            .clone()
            .context("Run fixture has no frozen baseline split digest")?,
        published_splits_sha256: digest(published.as_bytes()),
        published_dol_sha1: facts
            .published_dol_sha1
            .clone()
            .context("Run fixture has no published DOL digest")?,
        source_proposal_history_complete: facts.proposal_history_complete,
    })?;
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
    if score.published_retail_agrees == Some(false) {
        lines.push(
            "**The published DOL does not match the retail hash recorded by the manifest.**"
                .to_string(),
        );
        lines.push(String::new());
    } else if score.published_retail_agrees.is_none() {
        lines.push(
            "**The run carries no published DOL digest, so retail equality is unverified.**"
                .to_string(),
        );
        lines.push(String::new());
    }
    if !score.proposal_history_complete {
        lines.push(
            "**Proposal history is incomplete.** Proposed-exact totals are lower bounds because \
             this legacy run did not retain coordinator rediscovery rounds."
                .to_string(),
        );
        lines.push(String::new());
    }
    lines.extend([
        "*Exact* means the unit ends up owning precisely the oracle's ground. *Partial* overlaps \
         it with a boundary unresolved. *Wrong* means the run newly added ground the oracle gives \
         to someone else; retained wrong ground remains visible in the byte ledger. \
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
        "| Unit | Code | Full | Identification | Code recall | Full recall | Code selection | Full selection | Application | Verification |"
            .to_string(),
        "|---|---|---|---|---|---|---|---|---|---|".to_string(),
    ]);
    for row in score.units.iter().filter(|row| row.in_recall_set) {
        lines.push(format!(
            "| `{}` | {:?} | {:?} | {:?} | {} | {} | {:?} | {:?} | {:?} | {:?} |",
            row.unit,
            row.code_outcome,
            row.full_outcome,
            row.identification,
            recall_label(row.code_recall),
            recall_label(row.full_recall),
            row.code_selection,
            row.full_selection,
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

    const TEST_RETAIL: &str = "0000000000000000000000000000000000000000";

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
    fn typed_identification_replaces_proposal_count_guessing() {
        use crate::analysis::ownership::{CandidateSequence, EdgeEvidence};

        let mut identification = UnitIdentification::absent("u.cpp", 2);
        identification.confidence = IdentificationConfidence::Corroborated;
        identification.basis = IdentificationBasis::Mixed;
        identification.evidence = vec!["attribution-1".into(), "attribution-2".into()];
        identification.boundary_blockers = vec!["right edge unresolved".into()];
        identification.candidates.push(CandidateSequence {
            module: "main".into(),
            source_section: ".text".into(),
            section: ".text".into(),
            start: "0x80001000".into(),
            end: "0x80001200".into(),
            attribution_ids: identification.evidence.clone(),
            matched_members: 2,
            target_functions_in_envelope: 2,
            contiguous_target_members: true,
            left_source_edge_observed: true,
            right_source_edge_observed: true,
            left_target_edge: EdgeEvidence {
                supported: true,
                reason: "neighbor".into(),
                adjacent_attribution_id: None,
            },
            right_target_edge: EdgeEvidence {
                supported: false,
                reason: "unknown".into(),
                adjacent_attribution_id: None,
            },
            unexplained_target_members: Vec::new(),
            current_owners: Vec::new(),
        });

        assert_eq!(score_identification(identification.confidence), Identification::Corroborated);
        assert!(
            typed_identification_evidence(&identification, &BTreeMap::new())
                .contains(&"boundary:right edge unresolved".to_string())
        );
        assert_eq!(typed_candidate_intervals(&identification), vec![vec![Range {
            section: ".text".into(),
            start: 0x80001000,
            end: 0x80001200
        }]]);
    }

    #[test]
    fn typed_identifications_are_bound_to_the_coverage_schema_that_defined_them() {
        let identification = UnitIdentification::absent("u.cpp", 0);
        let error = typed_identifications(
            CoverageArtifact {
                schema: TYPED_IDENTIFICATION_COVERAGE_SCHEMA - 1,
                identifications: Some(
                    serde_json::to_value(IdentificationReport {
                        schema: 1,
                        source: "NTSC".into(),
                        target: "PAL".into(),
                        attributions: Vec::new(),
                        source_functions: Vec::new(),
                        target_functions: Vec::new(),
                        helper_families: Vec::new(),
                        unresolved_target_clusters: Vec::new(),
                        helper_tail_hypotheses: Vec::new(),
                        object_evidence: None,
                        units: vec![identification.clone()],
                    })
                    .unwrap(),
                ),
                observation: None,
            },
            "NTSC",
            "PAL",
        )
        .unwrap_err();
        assert!(error.to_string().contains("typed identifications"), "{error}");

        assert!(
            typed_identifications(
                CoverageArtifact {
                    schema: TYPED_IDENTIFICATION_COVERAGE_SCHEMA - 1,
                    identifications: None,
                    observation: None,
                },
                "NTSC",
                "PAL"
            )
            .unwrap()
            .0
            .is_empty(),
            "legacy summaries without the new field stay readable"
        );
        let error = typed_identifications(
            CoverageArtifact {
                schema: TYPED_IDENTIFICATION_COVERAGE_SCHEMA,
                identifications: None,
                observation: None,
            },
            "NTSC",
            "PAL",
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing its typed identification"), "{error}");
        assert_eq!(
            typed_identifications(
                CoverageArtifact {
                    schema: TYPED_IDENTIFICATION_COVERAGE_SCHEMA,
                    identifications: Some(
                        serde_json::to_value(IdentificationReport {
                            schema: 1,
                            source: "NTSC".into(),
                            target: "PAL".into(),
                            attributions: Vec::new(),
                            source_functions: Vec::new(),
                            target_functions: Vec::new(),
                            helper_families: Vec::new(),
                            unresolved_target_clusters: Vec::new(),
                            helper_tail_hypotheses: Vec::new(),
                            object_evidence: None,
                            units: vec![identification],
                        })
                        .unwrap()
                    ),
                    observation: None,
                },
                "NTSC",
                "PAL"
            )
            .unwrap()
            .0
            .len(),
            1
        );
    }

    #[test]
    fn referenced_coverage_can_keep_its_compact_identification_list() {
        let artifact: CoverageArtifact = serde_json::from_value(serde_json::json!({
            "schema": REFERENCED_IDENTIFICATION_COVERAGE_SCHEMA,
            "identifications": [{ "unit": "u.cpp" }],
            "observation": {
                "schema": crate::analysis::ownership::IDENTIFICATION_SCHEMA,
                "sha256": "digest",
                "file": "preparation/ownership-digest.json"
            }
        }))
        .unwrap();

        assert_eq!(artifact.schema, REFERENCED_IDENTIFICATION_COVERAGE_SCHEMA);
        assert!(artifact.identifications.unwrap().is_array());
        assert!(artifact.observation.is_some());
    }

    #[test]
    fn a_preflight_refusal_is_told_apart_from_a_build_refusal() {
        assert!(is_preflight(
            "CFoo.cpp would lose .text 0x1000..0x2000 with nothing saying it should"
        ));
        for transactional in [
            "stale-precondition: stale precondition: neighbour CBar.cpp changed since transaction x",
            "ownership-preflight: transaction refused: CFoo.cpp would overlap CBar.cpp",
            "dependency-not-permitted: CFoo.cpp requires changing CBar.cpp, which this run does \
             not permit",
        ] {
            assert!(is_preflight(transactional), "{transactional}");
        }
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
                alternative: None,
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
    fn proposal_recall_reads_every_recorded_candidate_version() {
        let exact = legacy::Candidate {
            name: "u.cpp".into(),
            evidence: serde_json::json!({
                "alternatives": [{
                    "id": "early-exact",
                    "lines": ["\t.text       start:0x00001000 end:0x00002000"]
                }]
            }),
        };
        let final_partial = legacy::Candidate {
            name: "u.cpp".into(),
            evidence: serde_json::json!({
                "alternatives": [{
                    "id": "later-partial",
                    "lines": ["\t.text       start:0x00001000 end:0x00001800"]
                }]
            }),
        };
        let stage = legacy::Stage {
            offered: Some(vec![exact, final_partial.clone()]),
            accepted: vec![final_partial],
            selections: BTreeMap::from([("u.cpp".into(), "later-partial".into())]),
            ..Default::default()
        };
        let found = stage_outcome("coverage", &stage, "u.cpp").unwrap();
        assert_eq!(found.proposed.len(), 2);
        assert!(found.proposed.iter().any(|body| body[0].contains("end:0x00002000")));
    }

    /// A coverage alternative whose transaction writes `members`, the first of
    /// which is the candidate.
    fn joint(id: &str, members: &[(&str, &str)]) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "lines": [members[0].1],
            "transaction": {
                "id": id,
                "members": members
                    .iter()
                    .map(|(unit, line)| serde_json::json!({ "unit": unit, "after": [line] }))
                    .collect::<Vec<_>>(),
            },
        })
    }

    fn applied(alternative: &serde_json::Value) -> legacy::Applied {
        legacy::Applied {
            id: alternative["id"].as_str().unwrap().into(),
            units: alternative["transaction"]["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["unit"].as_str().unwrap().to_string())
                .collect(),
            record: serde_json::json!({ "alternative": alternative }),
        }
    }

    const A_TEXT: &str = "\t.text       start:0x00001100 end:0x00001300";
    const A_INIT: &str = "\t.init       start:0x00000100 end:0x00000180";
    const B_KEPT: &str = "\t.text       start:0x00001300 end:0x00001500";

    #[test]
    fn a_neighbour_written_only_by_another_candidates_transaction_is_attributed() {
        let together = joint("joint", &[("A.cpp", A_TEXT), ("B.cpp", B_KEPT)]);
        // A later refinement for A.cpp alone supersedes the joint transaction
        // for A.cpp; B.cpp still holds what the joint one wrote.
        let refined = serde_json::json!({
            "id": "refined",
            "lines": [A_TEXT, A_INIT],
            "transaction": {
                "id": "refined",
                "members": [{ "unit": "A.cpp", "after": [A_TEXT, A_INIT] }],
            },
        });
        let first = legacy::Candidate {
            name: "A.cpp".into(),
            evidence: serde_json::json!({ "alternatives": [together.clone()] }),
        };
        let last = legacy::Candidate {
            name: "A.cpp".into(),
            evidence: serde_json::json!({ "alternatives": [refined.clone()] }),
        };
        let stage = legacy::Stage {
            offered: Some(vec![first, last.clone()]),
            accepted: vec![last],
            selections: BTreeMap::from([("A.cpp".into(), "refined".into())]),
            applied: vec![applied(&together), applied(&refined)],
            ..Default::default()
        };

        let neighbour = stage_outcome("coverage", &stage, "B.cpp").expect("B.cpp was written");
        assert_eq!(neighbour.application, Application::Accepted);
        assert_eq!(neighbour.selected, Some(vec![B_KEPT.to_string()]));
        assert_eq!(neighbour.selection_id.as_deref(), Some("joint"));
        assert_eq!(neighbour.proposed, [vec![B_KEPT.to_string()]]);

        let candidate = stage_outcome("coverage", &stage, "A.cpp").unwrap();
        assert_eq!(candidate.selected, Some(vec![A_TEXT.to_string(), A_INIT.to_string()]));
        assert_eq!(candidate.selection_id.as_deref(), Some("refined"));
        // The candidate's own bodies only: B.cpp's never counts as A.cpp's.
        assert_eq!(candidate.proposed.len(), 2);
    }

    #[test]
    fn a_later_transaction_decides_a_selected_units_final_body() {
        // C.cpp's transaction narrows A.cpp after A.cpp's own selection.
        let own = joint("own", &[("A.cpp", A_TEXT)]);
        let narrowed = "\t.text       start:0x00001100 end:0x00001200";
        let later = joint("later", &[
            ("C.cpp", "\t.text       start:0x00001200 end:0x00001300"),
            ("A.cpp", narrowed),
        ]);
        let a = legacy::Candidate {
            name: "A.cpp".into(),
            evidence: serde_json::json!({ "alternatives": [own.clone()] }),
        };
        let c = legacy::Candidate {
            name: "C.cpp".into(),
            evidence: serde_json::json!({ "alternatives": [later.clone()] }),
        };
        let stage = legacy::Stage {
            offered: Some(vec![a.clone(), c.clone()]),
            accepted: vec![a, c],
            selections: BTreeMap::from([
                ("A.cpp".into(), "own".into()),
                ("C.cpp".into(), "later".into()),
            ]),
            applied: vec![applied(&own), applied(&later)],
            ..Default::default()
        };
        let found = stage_outcome("coverage", &stage, "A.cpp").unwrap();
        assert_eq!(found.selected, Some(vec![narrowed.to_string()]));
        assert_eq!(found.selection_id.as_deref(), Some("later"));
        assert!(found.proposed.contains(&vec![narrowed.to_string()]));
    }

    #[test]
    fn a_neighbour_of_a_refused_transaction_carries_the_refusal() {
        let together = joint("joint", &[("A.cpp", A_TEXT), ("B.cpp", B_KEPT)]);
        let stage = legacy::Stage {
            deferred: vec![legacy::Candidate {
                name: "A.cpp".into(),
                evidence: serde_json::json!({ "alternatives": [together] }),
            }],
            events: vec![legacy::Event {
                unit: "A.cpp".into(),
                status: "rejected".into(),
                reason: Some(
                    "dependency-not-permitted: A.cpp requires changing B.cpp, which this run \
                     does not permit"
                        .into(),
                ),
                alternative: Some("joint".into()),
            }],
            ..Default::default()
        };
        let neighbour = stage_outcome("coverage", &stage, "B.cpp").unwrap();
        assert_eq!(neighbour.application, Application::PreflightRefused);
        assert_eq!(neighbour.selected, None);
        assert_eq!(neighbour.proposed, [vec![B_KEPT.to_string()]]);
        // A unit nothing proposed anything for is still not offered.
        assert!(stage_outcome("coverage", &stage, "Q.cpp").is_none());
    }

    #[test]
    fn a_neighbour_is_not_refused_by_an_alternative_that_would_not_have_written_it() {
        // A.cpp's first alternative writes only A.cpp and is refused; its
        // second, also A.cpp-only, is accepted; a third that would have
        // narrowed B.cpp was never tried.
        let alone = joint("alone", &[("A.cpp", A_TEXT)]);
        let smaller =
            joint("smaller", &[("A.cpp", "\t.text       start:0x00001100 end:0x00001200")]);
        let together = joint("joint", &[("A.cpp", A_TEXT), ("B.cpp", B_KEPT)]);
        let a = legacy::Candidate {
            name: "A.cpp".into(),
            evidence: serde_json::json!({ "alternatives": [alone, smaller.clone(), together] }),
        };
        let refusal = |alternative: Option<&str>| legacy::Event {
            unit: "A.cpp".into(),
            status: "rejected".into(),
            reason: Some("build-timeout: timed out after 120s".into()),
            alternative: alternative.map(str::to_string),
        };
        let mut stage = legacy::Stage {
            offered: Some(vec![a.clone()]),
            accepted: vec![a],
            selections: BTreeMap::from([("A.cpp".into(), "smaller".into())]),
            events: vec![refusal(Some("alone"))],
            applied: vec![applied(&smaller)],
            ..Default::default()
        };
        let neighbour = stage_outcome("coverage", &stage, "B.cpp").unwrap();
        assert_eq!(neighbour.application, Application::NotAttempted);
        assert_eq!(neighbour.proposed, [vec![B_KEPT.to_string()]], "still proposed");

        // An event that does not name its alternative is not evidence about
        // the neighbour either.
        stage.events = vec![refusal(None)];
        let neighbour = stage_outcome("coverage", &stage, "B.cpp").unwrap();
        assert_eq!(neighbour.application, Application::NotAttempted);

        // The joint alternative being refused is.
        stage.events = vec![refusal(Some("joint"))];
        let neighbour = stage_outcome("coverage", &stage, "B.cpp").unwrap();
        assert_eq!(neighbour.application, Application::BuildRefused);
    }

    #[test]
    fn legacy_preparation_reads_the_flattened_on_disk_shape() {
        let stored: legacy::StoredPreparation = serde_json::from_value(serde_json::json!({
            "candidates": [{ "name": "u.cpp", "evidence": { "lines": ["body"] } }],
            "events": [{ "unit": "empty.cpp", "status": "configured-without-split" }],
            "source_fingerprint": "fingerprint"
        }))
        .unwrap();
        assert_eq!(stored.prepared.candidates.len(), 1);
        assert_eq!(stored.prepared.events.len(), 1);
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
                    \x20   Object(NonMatching, \"legacy_b.cpp\"),\n]\n\n\
                    # BEGIN AUTOMATED SOURCE VERIFICATION\n\
                    # Version: B\n\
                    if config.version == \"B\":\n\
                    \x20   _verified_source_units = {\"legacy_b.cpp\"}\n\
                    \x20   for _verified_lib in config.libs:\n\
                    \x20       for _verified_obj in _verified_lib['objects']:\n\
                    \x20           if _verified_obj.name in _verified_source_units:\n\
                    \x20               _verified_obj.completed = True\n\
                    # END AUTOMATED SOURCE VERIFICATION\n";
        assert_eq!(
            linked(text, "A").unwrap(),
            BTreeSet::from(["only_a.cpp".to_string(), "both.cpp".to_string()])
        );
        assert_eq!(
            linked(text, "B").unwrap(),
            BTreeSet::from(["both.cpp".to_string(), "legacy_b.cpp".to_string()])
        );
    }

    #[test]
    fn configuring_source_does_not_make_an_unverified_oracle_trusted() {
        let splits = "Sections:\n\na.cpp:\n\t.text start:0x00001000 end:0x00002000\n";
        let revision = |id: &str, verified: bool| Revision {
            id: id.into(),
            splits_sha256: "splits".into(),
            configure_sha256: Some("configure".into()),
            expected_retail_sha1: TEST_RETAIL.into(),
            verified_dol_sha1: verified.then(|| TEST_RETAIL.into()),
        };
        let mut linkage = Linkage {
            baseline: BTreeSet::new(),
            oracle: BTreeSet::from(["a.cpp".to_string()]),
            verified_oracle: BTreeSet::new(),
        };
        let unverified = build_manifest(
            "NTSC",
            "PAL",
            revision("base", true),
            splits,
            revision("oracle", false),
            splits,
            &linkage,
        )
        .unwrap();
        assert_eq!(unverified.units["a.cpp"].trust, Trust::Unverified);

        linkage.verified_oracle.insert("a.cpp".to_string());
        let verified = build_manifest(
            "NTSC",
            "PAL",
            revision("base", true),
            splits,
            revision("oracle", true),
            splits,
            &linkage,
        )
        .unwrap();
        assert_eq!(verified.units["a.cpp"].trust, Trust::SourceLinked);
    }

    #[test]
    fn oracle_verification_binds_linkage_to_the_frozen_project_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let configure = "configured";
        let splits = "Sections:\n";
        let config = "hash: 0000000000000000000000000000000000000000\n";
        let manifest = serde_json::json!({
            "configure.py": digest(configure.as_bytes()),
            "config/PAL/splits.txt": digest(splits.as_bytes()),
            "config/PAL/config.yml": digest(config.as_bytes()),
        });
        std::fs::write(
            directory.path().join("run.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": 3,
                "id": "proof",
                "source": "NTSC",
                "target": "PAL",
                "stages": ["verify"],
                "repository": { "head": "oracle-commit", "clean": true },
                "owner": { "manifest": manifest },
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("result.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": 3,
                "id": "proof",
                "source": "NTSC",
                "target": "PAL",
                "published_dol_sha1": TEST_RETAIL,
                "stages": {
                    "verify": {
                        "validation": "compiled-link-inputs-and-retail-bytes",
                        "dol_sha1": TEST_RETAIL
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("publication.json"),
            r#"{"status":"published","changes":{}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(directory.path().join("verify")).unwrap();
        std::fs::write(
            directory.path().join("verify/prepared.json"),
            r#"{"candidates":[],"events":[]}"#,
        )
        .unwrap();

        let declared = BTreeSet::from(["a.cpp".to_string()]);
        let proof = oracle_verification(directory.path(), &OracleInputs {
            target: "PAL",
            configure,
            splits,
            config,
            expected_dol_sha1: TEST_RETAIL,
            declared: &declared,
            commit: "oracle-commit",
        })
        .unwrap();
        assert_eq!(proof.units, declared);

        let result_path = directory.path().join("result.json");
        let run_path = directory.path().join("run.json");
        let mut result: serde_json::Value = read_json(&result_path).unwrap();
        let mut record: serde_json::Value = read_json(&run_path).unwrap();
        result["schema"] = serde_json::json!(2);
        record["schema"] = serde_json::json!(2);
        std::fs::write(&result_path, serde_json::to_vec(&result).unwrap()).unwrap();
        std::fs::write(&run_path, serde_json::to_vec(&record).unwrap()).unwrap();
        let error = oracle_verification(directory.path(), &OracleInputs {
            target: "PAL",
            configure,
            splits,
            config,
            expected_dol_sha1: TEST_RETAIL,
            declared: &declared,
            commit: "oracle-commit",
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("requires run schema 3"));
        result["schema"] = serde_json::json!(3);
        record["schema"] = serde_json::json!(3);
        std::fs::write(&result_path, serde_json::to_vec(&result).unwrap()).unwrap();
        std::fs::write(&run_path, serde_json::to_vec(&record).unwrap()).unwrap();

        result["source"] = serde_json::json!("OTHER");
        std::fs::write(&result_path, serde_json::to_vec(&result).unwrap()).unwrap();
        let error = oracle_verification(directory.path(), &OracleInputs {
            target: "PAL",
            configure,
            splits,
            config,
            expected_dol_sha1: TEST_RETAIL,
            declared: &declared,
            commit: "oracle-commit",
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("different source versions"));
        result["source"] = serde_json::json!("NTSC");
        std::fs::write(&result_path, serde_json::to_vec(&result).unwrap()).unwrap();

        let error = oracle_verification(directory.path(), &OracleInputs {
            target: "PAL",
            configure: "different configure",
            splits,
            config,
            expected_dol_sha1: TEST_RETAIL,
            declared: &declared,
            commit: "oracle-commit",
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("exact configure.py"));

        record["stages"] = serde_json::json!(["coverage", "verify"]);
        std::fs::write(&run_path, serde_json::to_vec(&record).unwrap()).unwrap();
        let error = oracle_verification(directory.path(), &OracleInputs {
            target: "PAL",
            configure,
            splits,
            config,
            expected_dol_sha1: TEST_RETAIL,
            declared: &declared,
            commit: "oracle-commit",
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("verify-only"));
    }

    #[test]
    fn an_unknown_run_schema_is_not_read_as_a_known_one() {
        let error = validate_run_schemas(5, 5).unwrap_err();
        assert!(format!("{error:#}").contains("unsupported"));
        for schema in 1..=4 {
            assert!(validate_run_schemas(schema, schema).is_ok(), "{schema}");
        }
        // The scorer has to follow the tool: a run this build writes must be
        // one it can score.
        assert!(validate_run_schemas(crate::run::SCHEMA, crate::run::SCHEMA).is_ok());
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
                expected_retail_sha1: TEST_RETAIL.into(),
                verified_dol_sha1: Some(TEST_RETAIL.into()),
            },
            oracle: Revision {
                id: "oracle".into(),
                splits_sha256: String::new(),
                configure_sha256: None,
                expected_retail_sha1: TEST_RETAIL.into(),
                verified_dol_sha1: Some(TEST_RETAIL.into()),
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
    fn a_real_run_must_match_the_exact_recorded_baseline_digest() {
        let truth = body(&[(".text", 0x1000, 0x2000)]);
        let mut manifest = manifest(&[("a.cpp", truth.clone(), truth, false)]);
        manifest.baseline.splits_sha256 = "exact-file".into();
        let mut run =
            facts(blocks(&[("a.cpp", 0x1000, 0x2000)]), blocks(&[("a.cpp", 0x1000, 0x2000)]));
        run.allow_structural_baseline = false;
        run.baseline_splits_sha256 = Some("same-bodies-different-file".into());
        assert!(!score(&manifest, &run).baseline_agrees);
        run.baseline_splits_sha256 = Some("exact-file".into());
        assert!(score(&manifest, &run).baseline_agrees);
    }

    #[test]
    fn a_deleted_published_split_file_is_not_read_as_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("result.json"),
            r#"{"schema":1,"id":"run","source":"NTSC","target":"PAL","stages":{}}"#,
        )
        .unwrap();
        let before = "Sections:\n\na.cpp:\n\t.text start:0x00001000 end:0x00002000\n";
        let before_digest = digest(before.as_bytes());
        std::fs::write(
            directory.path().join("run.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "id": "run",
                "source": "NTSC",
                "target": "PAL",
                "stages": [],
                "owner": { "manifest": { "config/PAL/splits.txt": before_digest.clone() } },
            }))
            .unwrap(),
        )
        .unwrap();
        let encoded: String = before.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(
            directory.path().join("publication.json"),
            serde_json::to_vec(&serde_json::json!({
                "status": "published",
                "changes": {
                    "config/PAL/splits.txt": {
                        "before_sha256": before_digest,
                        "after_sha256": null,
                        "before": encoded,
                        "after": null
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let error = match read_run(directory.path()) {
            Ok(_) => panic!("deletion should be rejected"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("deleted config/PAL/splits.txt"));
    }

    #[test]
    fn the_command_fails_after_writing_diagnostics_for_a_baseline_mismatch() {
        let directory = tempfile::tempdir().unwrap();
        let run = directory.path().join("run");
        let output = directory.path().join("score");
        std::fs::create_dir_all(&run).unwrap();
        let truth = body(&[(".text", 0x1000, 0x2000)]);
        let mut manifest = manifest(&[("a.cpp", truth.clone(), truth, false)]);
        manifest.baseline.splits_sha256 = "expected".into();
        let manifest_path = directory.path().join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(
            run.join("result.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "id": "run",
                "source": "NTSC",
                "target": "PAL",
                "stages": {},
                "published_dol_sha1": TEST_RETAIL,
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            run.join("run.json"),
            r#"{"schema":1,"id":"run","source":"NTSC","target":"PAL","stages":[],"owner":{"manifest":{"config/PAL/splits.txt":"different"}}}"#,
        )
        .unwrap();
        std::fs::write(run.join("publication.json"), r#"{"status":"published","changes":{}}"#)
            .unwrap();

        let error = score_command(&ScoreArgs {
            manifest: manifest_path,
            run,
            output: Some(output.clone()),
            fixture: None,
        })
        .expect_err("an invalid comparison must not exit successfully");
        assert!(format!("{error:#}").contains("exact baseline"));
        assert!(output.join("score.json").is_file(), "diagnostics should survive the failure");
    }

    #[test]
    fn a_noop_run_proves_its_unpublished_baseline_by_digest() {
        let truth = body(&[(".text", 0x1000, 0x2000)]);
        let mut manifest = manifest(&[("a.cpp", truth.clone(), truth, false)]);
        manifest.baseline.splits_sha256 = "known-baseline".into();
        let mut run = facts(IndexMap::new(), IndexMap::new());
        run.use_manifest_baseline = true;
        run.baseline_splits_sha256 = Some("known-baseline".into());
        run.published_dol_sha1 = Some(TEST_RETAIL.into());
        assert!(score(&manifest, &run).baseline_agrees);

        let directory = tempfile::tempdir().unwrap();
        write_run_fixture(directory.path(), &run, &manifest).unwrap();
        let published =
            std::fs::read_to_string(directory.path().join("published.splits.txt")).unwrap();
        assert!(
            Body::of(&Splits::parse(&published).unwrap().blocks, "a.cpp")
                .same_structure(&manifest.units["a.cpp"].baseline)
        );
        let provenance: RunFixtureProvenance =
            read_json(&directory.path().join("run-provenance.json")).unwrap();
        assert_eq!(provenance.published_splits_sha256, digest(published.as_bytes()));

        run.baseline_splits_sha256 = Some("different-baseline".into());
        assert!(!score(&manifest, &run).baseline_agrees);
    }
}
