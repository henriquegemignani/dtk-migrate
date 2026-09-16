//! The pipeline: prepare once, evaluate in parallel, integrate in order,
//! publish once.
//!
//! The shape exists to make a long run's conclusions reproducible and its
//! failures cheap.
//!
//! - **Prepare once.** Every worker starts from the same frozen baseline, so
//!   two candidates evaluated in different lanes were measured against the same
//!   thing.
//! - **Evaluate in parallel, reduce in order.** Results are combined in
//!   candidate order, never completion order, so the run does not depend on
//!   which lane finished first.
//! - **Integrate.** Workers each proved their batch alone. The union has to be
//!   proved too, because two changes that are fine apart can conflict together.
//! - **Publish once.** Only the coordinator writes to the user's checkout, only
//!   the four files a migration may touch, and only after re-proving the result
//!   there. Anything else changing underneath stops publication rather than
//!   overwriting it.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    build::{context::BuildContext, process::Cancel},
    stages::{
        Candidate, Event, Selections, Stage, coverage::Coverage, derive::Derive,
        discover::Discover, verify::Verify,
    },
    workspace::{Manifest, Snapshot, fingerprint},
};

pub mod jobs;
pub mod publish;

/// Bumped when a run directory's layout changes, so an old one is not resumed
/// by a tool that would misread it.
pub const SCHEMA: u32 = 1;

/// The stages, in the only order they may run in.
///
/// Naming comes first because everything else depends on it: the matcher
/// anchors its proposals on symbol names, so each name established widens what
/// coverage and discovery can propose. Verification comes last because it is
/// the only stage that asks whether a whole file is right, which is only worth
/// asking once its boundaries are.
pub const ORDER: [&str; 4] = ["derive", "coverage", "discover", "verify"];

pub fn stage_for(name: &str) -> Result<Box<dyn Stage + Send + Sync>> {
    Ok(match name {
        "coverage" => Box::new(Coverage),
        "discover" => Box::new(Discover),
        "verify" => Box::new(Verify),
        "derive" => Box::new(Derive),
        other => bail!("Unknown stage: {other}"),
    })
}

/// What a run was asked to do, and what it froze to do it with.
///
/// Written to `run.json` before any work starts. `--resume` reads it back and
/// refuses to continue if anything it describes has changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub schema: u32,
    pub id: String,
    pub root: PathBuf,
    pub source: String,
    pub target: String,
    pub stages: Vec<String>,
    pub workers: usize,
    pub build_jobs: usize,
    pub batch_size: usize,
    pub limit: Option<usize>,
    /// Evaluate only these units, if given. Everything else eligible is still
    /// reported, so a focused run does not make an untested proposal look
    /// ineligible.
    #[serde(default)]
    pub only: Vec<String>,
    pub build_timeout_seconds: Option<f64>,
    pub tools: FrozenTools,
    pub environment: Environment,
    /// The owner project's inputs as they were when the run started.
    pub owner: Snapshot,
}

/// Copies of the binaries a run used, taken so a mid-run upgrade cannot change
/// what a later batch means.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenTools {
    pub dtk: PathBuf,
    pub ninja: PathBuf,
    pub python: PathBuf,
    /// This binary, which the patched configure rule re-enters.
    pub hook: PathBuf,
    /// Where the downloaded compilers and tools live.
    pub toolchain_root: PathBuf,
}

/// Everything outside the project that could change a build's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    pub dtk_sha256: String,
    pub ninja_sha256: String,
    pub migrate_sha256: String,
    /// Variables the compiler and linker read. A changed `PATH` can select a
    /// different assembler without anything else in the project moving.
    pub build_environment: Vec<(String, Option<String>)>,
}

const BUILD_VARIABLES: [&str; 10] = [
    "PATH",
    "INCLUDE",
    "LIB",
    "CC",
    "CXX",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "PYTHONPATH",
];

impl Environment {
    pub fn of(tools: &FrozenTools) -> Result<Self> {
        Ok(Self {
            dtk_sha256: crate::workspace::hash_file(&tools.dtk)?,
            ninja_sha256: crate::workspace::hash_file(&tools.ninja)?,
            migrate_sha256: crate::workspace::hash_file(&tools.hook)?,
            build_environment: BUILD_VARIABLES
                .iter()
                .map(|key| ((*key).to_string(), std::env::var(key).ok()))
                .collect(),
        })
    }
}

/// What one stage concluded, as written to `<stage>/result.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage: String,
    pub accepted: Vec<Candidate>,
    pub deferred: Vec<Candidate>,
    /// Which alternative each accepted candidate was proved with.
    #[serde(default)]
    pub selections: Selections,
    pub events: Vec<Event>,
    pub validation: String,
    pub dol_sha1: String,
    pub baseline: crate::project::report::Measures,
    pub final_measures: crate::project::report::Measures,
    #[serde(default)]
    pub reserved_by_earlier_stage: Vec<String>,
    #[serde(default)]
    pub eligible_excluded_by_only: Vec<String>,
    pub seconds: f64,
}

/// Where a run keeps everything it produced.
pub struct RunDir {
    pub path: PathBuf,
}

impl RunDir {
    pub fn stage(&self, stage: &str) -> PathBuf { self.path.join(stage) }

    pub fn baseline(&self, stage: &str) -> PathBuf { self.stage(stage).join("baseline") }

    pub fn integration(&self) -> PathBuf { self.path.join("integration") }

    pub fn pool(&self) -> PathBuf { self.path.join("pool") }
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Failed to parse {}", path.display()))
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(value)?;
    std::fs::write(path, text).with_context(|| format!("Failed to write {}", path.display()))
}

/// Builds the context a stage uses inside one workspace.
pub fn context(
    root: &Path,
    run: &RunRecord,
    output: PathBuf,
    cancel: Option<Cancel>,
) -> BuildContext {
    BuildContext {
        root: root.to_path_buf(),
        source: run.source.clone(),
        target: run.target.clone(),
        tools: crate::build::context::Toolchain {
            dtk: run.tools.dtk.clone(),
            ninja: run.tools.ninja.clone(),
            python: run.tools.python.clone(),
            hook: run.tools.hook.clone(),
            toolchain_root: Some(run.tools.toolchain_root.clone()),
        },
        output,
        build_jobs: run.build_jobs,
        build_timeout: run.build_timeout_seconds.map(Duration::from_secs_f64),
        cancel,
    }
}

/// Refuses to continue if a frozen tool has changed since the run started.
pub fn check_environment(run: &RunRecord) -> Result<()> {
    let current = Environment::of(&run.tools)?;
    if current != run.environment {
        bail!(
            "The tools or build environment changed since this run started; \
             its measurements no longer describe one thing. Start a fresh run."
        );
    }
    Ok(())
}

/// Runs one stage end to end and leaves an integrated workspace behind.
///
/// Returns the integrated workspace and what the stage concluded. `reserved`
/// names belong to an earlier stage and are withheld: a unit an earlier stage
/// certified is that stage's for the rest of the run, because a later stage
/// extending it would invalidate the certificate and cost the whole run its
/// publication.
pub fn run_stage(
    dir: &RunDir,
    run: &RunRecord,
    stage_name: &str,
    source_root: &Path,
    reserved: &BTreeSet<String>,
    cancel: Option<Cancel>,
) -> Result<(PathBuf, StageResult)> {
    let started = Instant::now();
    let stage = stage_for(stage_name)?;
    let stage_dir = dir.stage(stage_name);
    let baseline_dir = dir.baseline(stage_name);
    let prepared_path = stage_dir.join("prepared.json");
    let manifest_path = stage_dir.join("manifest.json");

    let source = Snapshot::of(source_root)?;
    let source_fingerprint = source.fingerprint()?;

    let (prepared, manifest) = if prepared_path.exists() {
        // Resuming: the frozen baseline and the stage before it must both be
        // exactly what this stage's candidates were derived from.
        let stored: StoredPreparation = read_json(&prepared_path)?;
        if stored.source_fingerprint != source_fingerprint {
            bail!("Upstream {stage_name} inputs changed; start a new run");
        }
        let manifest: Manifest = read_json(&manifest_path)?;
        let current = Snapshot::of(&baseline_dir)?;
        if current.manifest != manifest || current.mappings != stored.symbol_mappings {
            bail!("The frozen {stage_name} baseline changed; start a new run");
        }
        (stored, manifest)
    } else {
        if baseline_dir.exists() {
            crate::workspace::reset_workspace(source_root, &baseline_dir, &source.manifest)?;
        } else {
            crate::workspace::copy_snapshot(source_root, &baseline_dir, &source.manifest)?;
        }
        crate::workspace::seed_objdiff(source_root, &baseline_dir)?;
        let ctx = context(&baseline_dir, run, stage_dir.join("preparation"), cancel.clone());
        let limit = if run.only.is_empty() { run.limit } else { None };
        let mut prepared = stage.prepare(&ctx, limit)?;

        let reserved_here: Vec<String> = prepared
            .candidates
            .iter()
            .map(|c| c.name.clone())
            .filter(|name| reserved.contains(name))
            .collect();
        prepared.candidates.retain(|c| !reserved.contains(&c.name));

        let mut excluded: Vec<String> = Vec::new();
        if !run.only.is_empty() {
            let available: BTreeSet<&str> =
                prepared.candidates.iter().map(|c| c.name.as_str()).collect();
            let missing: Vec<&String> =
                run.only.iter().filter(|name| !available.contains(name.as_str())).collect();
            if !missing.is_empty() {
                bail!("Requested {stage_name} candidates were not proposed: {missing:?}");
            }
            // Report what a focused run skipped, so an untested proposal is not
            // mistaken for an ineligible one.
            excluded = available
                .iter()
                .filter(|n| !run.only.contains(&n.to_string()))
                .map(|n| n.to_string())
                .collect();
            prepared.candidates.retain(|c| run.only.contains(&c.name));
        }

        let snapshot = Snapshot::of(&baseline_dir)?;
        let stored = StoredPreparation {
            prepared,
            source_fingerprint,
            symbol_mappings: snapshot.mappings.clone(),
            reserved_by_earlier_stage: reserved_here,
            eligible_excluded_by_only: excluded,
        };
        write_json(&manifest_path, &snapshot.manifest)?;
        write_json(&prepared_path, &stored)?;
        (stored, snapshot.manifest)
    };

    let candidates = prepared.prepared.candidates.clone();
    let batches = jobs::batches(&candidates, run.batch_size);
    tracing::info!("{stage_name}: {} candidates in {} batches", candidates.len(), batches.len());

    let outcomes = jobs::execute(
        dir,
        run,
        stage.as_ref(),
        stage_name,
        &baseline_dir,
        &manifest,
        &prepared.prepared,
        &batches,
        cancel.clone(),
    )?;

    // Integration proves the union in one workspace, then retries what the
    // workers deferred — but only after something was accepted, since a
    // deferred candidate saw this very baseline and nothing has changed for it
    // until then.
    let integrated = dir.integration();
    crate::workspace::reset_workspace(&baseline_dir, &integrated, &manifest)?;
    crate::workspace::seed_objdiff(&baseline_dir, &integrated)?;
    let ctx = context(&integrated, run, stage_dir.join("integration-evidence"), cancel);

    let worker_accepted: BTreeSet<String> = outcomes
        .iter()
        .flat_map(|outcome| outcome.accepted.iter().map(|c| c.name.clone()))
        .collect();
    let proposed: Vec<Candidate> =
        candidates.iter().filter(|c| worker_accepted.contains(&c.name)).cloned().collect();

    let mut events: Vec<Event> = outcomes.iter().flat_map(|o| o.events.clone()).collect();
    // A worker already found an alternative that works for each candidate it
    // accepted; integration tries that one first rather than rediscovering it.
    let preferred: Selections = outcomes.iter().flat_map(|o| o.selections.clone()).collect();
    let mut outcome = stage.evaluate(&ctx, &prepared.prepared, &proposed, &preferred)?;
    let mut selections = outcome.selections.clone();
    events.extend(outcome.events.clone());
    let mut accepted: BTreeSet<String> = outcome.accepted.iter().map(|c| c.name.clone()).collect();
    let mut pending: Vec<Candidate> =
        candidates.iter().filter(|c| !accepted.contains(&c.name)).cloned().collect();

    while !pending.is_empty() && !accepted.is_empty() {
        let retry = stage.evaluate(&ctx, &prepared.prepared, &pending, &preferred)?;
        events.extend(retry.events.clone());
        let added: BTreeSet<String> = retry.accepted.iter().map(|c| c.name.clone()).collect();
        outcome = retry;
        if added.is_empty() {
            break;
        }
        accepted.extend(added.iter().cloned());
        selections.extend(outcome.selections.clone());
        pending.retain(|c| !added.contains(&c.name));
    }

    selections.retain(|name, _| accepted.contains(name));
    let result = StageResult {
        stage: stage_name.to_string(),
        selections,
        accepted: candidates.iter().filter(|c| accepted.contains(&c.name)).cloned().collect(),
        deferred: pending,
        events,
        validation: outcome.validation.clone(),
        dol_sha1: ctx.dol_sha1()?,
        baseline: prepared.prepared.baseline.measures.clone(),
        final_measures: outcome.report.measures.clone(),
        reserved_by_earlier_stage: prepared.reserved_by_earlier_stage.clone(),
        eligible_excluded_by_only: prepared.eligible_excluded_by_only.clone(),
        seconds: started.elapsed().as_secs_f64(),
    };
    write_json(&stage_dir.join("result.json"), &result)?;
    for (name, contents) in stage.artifacts(&prepared.prepared, &result)? {
        std::fs::write(stage_dir.join(name), contents)?;
    }
    Ok((integrated, result))
}

/// A stage's preparation as stored on disk, with what it was derived from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPreparation {
    #[serde(flatten)]
    pub prepared: crate::stages::Prepared,
    pub source_fingerprint: String,
    pub symbol_mappings: serde_json::Value,
    #[serde(default)]
    pub reserved_by_earlier_stage: Vec<String>,
    #[serde(default)]
    pub eligible_excluded_by_only: Vec<String>,
}

/// A digest of the manifest, used as a baseline identity in job records.
pub fn baseline_fingerprint(manifest: &Manifest) -> Result<String> { fingerprint(manifest) }
