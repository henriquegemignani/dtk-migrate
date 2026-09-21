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
        Candidate, Event, MutationScope, Selections, Stage, coverage::Coverage, derive::Derive,
        discover::Discover, verify::Verify,
    },
    workspace::{Manifest, Snapshot, fingerprint},
};

pub mod jobs;
pub mod publish;

/// Bumped when a run directory's layout changes, so an old one is not resumed
/// by a tool that would misread it.
pub const SCHEMA: u32 = 9;

/// Stored preparations and worker results that may be interpreted by the same
/// coordinator compatibility level. Bump this when a same-schema executable
/// would prepare, evaluate or integrate an existing artifact differently.
pub const RESUME_COMPATIBILITY: u32 = 1;

/// Fresh runs keep more work available than there are worker lanes, so a slow
/// batch cannot leave the rest of the machine idle. Runs created before this
/// was introduced retain version 1 and therefore their exact stored job
/// partition when resumed with a newer coordinator.
pub const BATCHING_VERSION: u32 = 2;

fn legacy_resume_compatibility() -> u32 { 0 }

fn legacy_batching_version() -> u32 { 1 }

/// The stages, in the only order they may run in.
///
/// Naming comes first because everything else depends on it: the matcher
/// anchors its proposals on symbol names, so each name established widens what
/// coverage and discovery can propose. Verification comes last because it is
/// the only stage that asks whether a whole file is right, which is only worth
/// asking once its boundaries are.
pub const ORDER: [&str; 4] = ["derive", "coverage", "discover", "verify"];

/// How many times a stage may be asked what the last acceptance made possible.
///
/// Each round costs the stage a fresh look at the whole project, and the
/// interesting cascades are short: a unit unblocked by its neighbour usually
/// settles on the next pass.
const MAX_REDISCOVERY_ROUNDS: usize = 3;

pub fn stage_for(name: &str) -> Result<Box<dyn Stage + Send + Sync>> {
    Ok(match name {
        "coverage" => Box::new(Coverage::default()),
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
    /// Lets an explicit coordinator upgrade distinguish a compatible bug fix
    /// from a binary that would reinterpret the run's stored artifacts.
    #[serde(default = "legacy_resume_compatibility")]
    pub resume_compatibility: u32,
    pub id: String,
    pub root: PathBuf,
    pub source: String,
    pub target: String,
    pub stages: Vec<String>,
    pub workers: usize,
    pub build_jobs: usize,
    pub batch_size: usize,
    /// The batching algorithm is part of a run's frozen execution plan. It is
    /// deliberately independent of schema compatibility so an upgraded
    /// coordinator can reuse already completed worker jobs.
    #[serde(default = "legacy_batching_version")]
    pub batching_version: u32,
    pub limit: Option<usize>,
    /// Evaluate only these units, if given. Everything else eligible is still
    /// reported, so a focused run does not make an untested proposal look
    /// ineligible.
    #[serde(default)]
    pub only: Vec<String>,
    pub build_timeout_seconds: Option<f64>,
    pub tools: FrozenTools,
    pub environment: Environment,
    /// The environment used to fingerprint worker jobs before the first
    /// compatible coordinator upgrade. Keeping it stable lets completed jobs
    /// remain reusable; [`coordinator_upgrades`](Self::coordinator_upgrades)
    /// records which binary evaluated later work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_environment: Option<Environment>,
    /// Explicit, ordered changes of the executable coordinating this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coordinator_upgrades: Vec<CoordinatorUpgrade>,
    /// Git identity of the owner checkout before any stage ran. Absent for
    /// projects outside Git; a benchmark may require it when a revision-bound
    /// build proof matters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RepositoryState>,
    /// The owner project's inputs as they were when the run started.
    pub owner: Snapshot,
}

impl RunRecord {
    pub fn artifact_environment(&self) -> &Environment {
        self.artifact_environment.as_ref().unwrap_or(&self.environment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorUpgrade {
    pub from_sha256: String,
    pub to_sha256: String,
    pub frozen_executable: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryState {
    pub head: String,
    pub clean: bool,
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
    /// A digest of the injected coverage evidence, when a test is supplying it.
    ///
    /// Without this, a run could be executed against injected evidence and
    /// resumed against the matcher — or against *different* injected evidence —
    /// and the two halves would be describing different worlds while claiming to
    /// be one run. Absent in every real migration, which is the normal case.
    #[serde(default)]
    pub injected_evidence_sha256: Option<String>,
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
            injected_evidence_sha256: crate::stages::coverage::injected_evidence_digest()?,
        })
    }
}

/// What one stage concluded, as written to `<stage>/result.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage: String,
    /// Every distinct candidate body the stage offered to an evaluator, across
    /// workers and coordinator rediscovery rounds. `accepted` deliberately
    /// keeps only the final candidate per unit; this history is what lets an
    /// audit answer whether an earlier proposal was already correct.
    pub offered: Vec<Candidate>,
    pub accepted: Vec<Candidate>,
    pub deferred: Vec<Candidate>,
    /// Which alternative each accepted candidate was proved with.
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
    /// Every change integration applied, in order, including ones a later
    /// round superseded. What publication replays.
    pub applied: Vec<crate::stages::Applied>,
    /// Coverage retry accounting across workers and coordinator rounds.
    #[serde(default)]
    pub retry: RetryCounts,
    /// Wall-clock phase timings. Together with each job's own duration these
    /// show whether a run is waiting on preparation, parallel workers, or the
    /// ordered coordinator rather than requiring an external profiler.
    #[serde(default)]
    pub timing: StageTiming,
    pub seconds: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageTiming {
    pub preparation_seconds: f64,
    pub worker_seconds: f64,
    pub integration_seconds: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetryCounts {
    /// Alternative trial executions, including coordinator revalidation.
    pub attempted: usize,
    /// Previously tried alternative states suppressed during rediscovery.
    pub skipped_as_unchanged: usize,
    /// Units offered under fresh evidence in coordinator rediscovery rounds.
    pub regenerated: usize,
    /// Times the coordinator stopped with acceptances still arriving.
    pub budget_exhausted: usize,
}

impl StageResult {
    /// Every name this stage changed, in its own namespace. Transaction
    /// neighbours are units even when the candidate has another scope.
    pub fn changed_scopes(&self, stage: &dyn Stage) -> Result<BTreeSet<MutationScope>> {
        let mut scopes = BTreeSet::new();
        scopes.extend(stage.accepted_scopes(&self.accepted)?);
        for entry in &self.applied {
            scopes.extend(stage.applied_scopes(entry)?);
        }
        Ok(scopes)
    }
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
        only: run.only.clone(),
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
/// scopes belong to an earlier stage and are withheld: a unit an earlier stage
/// certified is that stage's for the rest of the run, because a later stage
/// extending it would invalidate the certificate and cost the whole run its
/// publication.
pub fn run_stage(
    dir: &RunDir,
    run: &RunRecord,
    stage_name: &str,
    source_root: &Path,
    reserved: &BTreeSet<MutationScope>,
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

        let mut reserved_here = Vec::new();
        let mut available = Vec::new();
        for candidate in prepared.candidates {
            if is_reserved(stage.as_ref(), &candidate, reserved)? {
                reserved_here.push(candidate.name);
            } else {
                available.push(candidate);
            }
        }
        prepared.candidates = stage.choose_variants(available)?;

        let mut excluded: Vec<String> = Vec::new();
        let mut resolved: Vec<String> = Vec::new();
        if !run.only.is_empty() {
            let focused = focus(stage.as_ref(), &prepared.candidates, &run.only, reserved)?;
            let elsewhere: Vec<&String> =
                run.only.iter().filter(|name| !focused.resolved.contains(*name)).collect();
            if !elsewhere.is_empty() {
                // Not an error here: a later stage may propose them. The run
                // checks the whole pipeline before it publishes.
                tracing::info!("{stage_name}: requested units not involved here: {elsewhere:?}");
            }
            prepared.candidates = focused.roots;
            excluded = focused.skipped;
            resolved = focused.resolved.into_iter().collect();
        }

        // Carried into evaluation, where a stage may find work preparation could
        // not see and still has to respect what this run rules out.
        prepared.permitted = crate::stages::Permitted {
            reserved: reserved
                .iter()
                .filter_map(|scope| match scope {
                    MutationScope::Unit(name) | MutationScope::CodeDependency(name) => {
                        Some(name.clone())
                    }
                    _ => None,
                })
                .collect(),
            reserved_data: reserved
                .iter()
                .filter_map(|scope| match scope {
                    MutationScope::UnitData(name) | MutationScope::DataDependency(name) => {
                        Some(name.clone())
                    }
                    _ => None,
                })
                .collect(),
            reserved_link: reserved
                .iter()
                .filter_map(|scope| match scope {
                    MutationScope::UnitLink(name) => Some(name.clone()),
                    _ => None,
                })
                .collect(),
            only: run.only.iter().cloned().collect(),
        };

        let snapshot = Snapshot::of(&baseline_dir)?;
        let stored = StoredPreparation {
            prepared,
            source_fingerprint,
            symbol_mappings: snapshot.mappings.clone(),
            reserved_by_earlier_stage: reserved_here,
            eligible_excluded_by_only: excluded,
            only_resolved: resolved,
        };
        write_json(&manifest_path, &snapshot.manifest)?;
        write_json(&prepared_path, &stored)?;
        (stored, snapshot.manifest)
    };

    let candidates = prepared.prepared.candidates.clone();
    let footprints = candidates
        .iter()
        .map(|candidate| stage.footprint(candidate))
        .collect::<Result<Vec<_>>>()?;
    let batches =
        jobs::batches(&candidates, run.batch_size, &footprints, run.workers, run.batching_version)?;
    tracing::info!("{stage_name}: {} candidates in {} batches", candidates.len(), batches.len());

    let worker_started = Instant::now();
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
    let worker_seconds = worker_started.elapsed().as_secs_f64();

    // Integration proves the union in one workspace, then retries what the
    // workers deferred — but only after something was accepted, since a
    // deferred candidate saw this very baseline and nothing has changed for it
    // until then.
    let integration_started = Instant::now();
    let integrated = dir.integration();
    crate::workspace::reset_workspace(&baseline_dir, &integrated, &manifest)?;
    crate::workspace::seed_objdiff(&baseline_dir, &integrated)?;
    let ctx = context(&integrated, run, stage_dir.join("integration-evidence"), cancel);

    // The candidate as accepted, paired with the selection made against it. A
    // stage proving a refreshed proposal records an id that exists only in that
    // one, so looking the name back up in the original list — or taking the
    // candidate from one worker and the id from another — would hand
    // publication an id its evidence has never heard of.
    let mut proposed: Vec<Candidate> = Vec::new();
    let mut preferred = Selections::new();
    let mut tried: crate::stages::Tried = crate::stages::Tried::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for worker in &outcomes {
        for (unit, ids) in &worker.tried {
            tried.entry(unit.clone()).or_default().extend(ids.iter().cloned());
        }
        for candidate in &worker.accepted {
            if !seen.insert(candidate.name.clone()) {
                continue;
            }
            proposed.push(candidate.clone());
            if let Some(id) = worker.selections.get(&candidate.name) {
                preferred.insert(candidate.name.clone(), id.clone());
            }
        }
    }

    let mut events: Vec<Event> = outcomes.iter().flat_map(|o| o.events.clone()).collect();
    let mut retry = RetryCounts::default();
    let mut offered: Vec<Candidate> = Vec::new();
    let mut remember = |candidate: &Candidate| {
        if !offered
            .iter()
            .any(|seen| seen.name == candidate.name && seen.evidence == candidate.evidence)
        {
            offered.push(candidate.clone());
        }
    };
    for candidate in &candidates {
        remember(candidate);
    }
    for worker in &outcomes {
        for candidate in worker.accepted.iter().chain(&worker.deferred) {
            remember(candidate);
        }
    }
    // One entry per unit, last acceptance winning: a unit extended twice is one
    // final proposal, not two competing ones.
    let mut accepted: indexmap::IndexMap<String, Candidate> = indexmap::IndexMap::new();
    let mut selections = Selections::new();
    let mut applied: Vec<crate::stages::Applied> = Vec::new();
    // Handed over and still not settled. Kept apart from the work queue, which
    // is whatever the next round should look at — reusing the queue as the
    // deferred result would lose earlier failures the moment rediscovery
    // replaced it, and would report a just-accepted unit as deferred if the
    // round limit cut in first.
    let mut unresolved: indexmap::IndexMap<String, Candidate> =
        candidates.iter().map(|c| (c.name.clone(), c.clone())).collect();

    // Integration is itself a round: if every worker's candidate holds, the
    // workspace has changed and the only work left may be a unit that became
    // eligible because of it.
    let mut queue = proposed;
    let mut outcome = None;
    for round in 0..=MAX_REDISCOVERY_ROUNDS {
        // The first round runs even with nothing to try. A stage that found no
        // candidates, or whose candidates were all rejected by the workers, has
        // succeeded at finding nothing — and it still owes the run a measured,
        // unchanged baseline to record. Only a *later* round is pointless when
        // the queue empties, since the round before it already measured this
        // same workspace.
        if queue.is_empty() && outcome.is_some() {
            break;
        }
        for candidate in &queue {
            remember(candidate);
        }
        let result = stage.integrate(&ctx, &prepared.prepared, &queue, &preferred)?;
        events.extend(result.events.clone());
        for (unit, ids) in &result.tried {
            tried.entry(unit.clone()).or_default().extend(ids.iter().cloned());
        }
        let added: BTreeSet<String> = result.accepted.iter().map(|c| c.name.clone()).collect();
        for candidate in &result.accepted {
            accepted.insert(candidate.name.clone(), candidate.clone());
            unresolved.shift_remove(&candidate.name);
        }
        // A unit accepted in an earlier round and merely not extended again is
        // settled, not deferred.
        for candidate in &result.deferred {
            if !accepted.contains_key(&candidate.name) {
                unresolved.insert(candidate.name.clone(), candidate.clone());
            }
        }
        selections.extend(result.selections.clone());
        applied.extend(result.applied.clone());
        outcome = Some(result);

        if added.is_empty() {
            break;
        }
        // Something landed, so ask the stage what that made possible. This is
        // the only place it happens: one workspace holding every batch's result.
        let rediscovered = stage.rediscover(&ctx, &prepared.prepared, &tried)?;
        let discovered = rediscovered.as_ref().map(|r| r.candidates.as_slice()).unwrap_or_default();
        retry.skipped_as_unchanged += rediscovered.as_ref().map_or(0, |r| r.skipped_unchanged);
        retry.regenerated += discovered.len();
        if !discovered.is_empty() {
            events.push(
                Event::new("", "rediscovered")
                    .because(format!("{} units with new evidence", discovered.len())),
            );
        }
        // A stage that regenerated evidence has the complete eligible set.
        // Re-adding an old refusal here would retry it after any unrelated
        // acceptance. Stages without rediscovery retain their historical
        // integration retry of unsettled worker candidates.
        queue = rediscovered
            .map(|r| r.candidates)
            .unwrap_or_else(|| unresolved.values().cloned().collect());
        if round == MAX_REDISCOVERY_ROUNDS {
            // An acceptance in the last allowed round is not itself proof of
            // unfinished work. Regenerate once to distinguish a settled
            // cascade from one actually stopped by the budget.
            if !queue.is_empty() {
                events.push(Event::new("", "rediscovery-limit-reached").because(format!(
                    "stopped after {MAX_REDISCOVERY_ROUNDS} rounds with {} units still offered",
                    queue.len()
                )));
                retry.budget_exhausted += 1;
            }
            break;
        }
    }

    // Round 0 always evaluates, so this holds however the loop left; it is
    // asserted rather than assumed because the alternative is recording a
    // stage's result from a measurement that was never taken.
    let Some(outcome) = outcome else {
        bail!("{stage_name}: the first evaluation round did not run, so there is nothing to record")
    };
    selections.retain(|name, _| accepted.contains_key(name));
    retry.attempted = events
        .iter()
        .filter(|event| {
            event.alternative.is_some() && matches!(event.status.as_str(), "accepted" | "rejected")
        })
        .count();
    let result = StageResult {
        stage: stage_name.to_string(),
        offered,
        selections,
        accepted: accepted.into_values().collect(),
        deferred: unresolved.into_values().collect(),
        events,
        validation: outcome.validation.clone(),
        dol_sha1: ctx.dol_sha1()?,
        baseline: prepared.prepared.baseline.measures.clone(),
        final_measures: outcome.report.measures.clone(),
        reserved_by_earlier_stage: prepared.reserved_by_earlier_stage.clone(),
        eligible_excluded_by_only: prepared.eligible_excluded_by_only.clone(),
        applied,
        retry,
        timing: StageTiming {
            preparation_seconds: worker_started.duration_since(started).as_secs_f64(),
            worker_seconds,
            integration_seconds: integration_started.elapsed().as_secs_f64(),
        },
        seconds: started.elapsed().as_secs_f64(),
    };
    write_json(&stage_dir.join("result.json"), &result)?;
    for (name, contents) in stage.artifacts(&prepared.prepared, &result)? {
        std::fs::write(stage_dir.join(name), contents)?;
    }
    Ok((integrated, result))
}

fn is_reserved(
    stage: &dyn Stage,
    candidate: &Candidate,
    reserved: &BTreeSet<MutationScope>,
) -> Result<bool> {
    stage.is_reserved(candidate, reserved)
}

/// What `--only` means for one stage.
struct Focus {
    /// Requested candidates this stage proposed, to be evaluated.
    roots: Vec<Candidate>,
    /// Every other candidate it proposed, so a focused run does not make an
    /// untested proposal look ineligible.
    skipped: Vec<String>,
    /// Requested names this stage accounts for.
    resolved: BTreeSet<String>,
}

/// Narrows a stage's candidates to what `--only` names.
///
/// A requested name is a *root* when this stage proposed it, and is evaluated.
/// It is a *dependency* when some requested root's change must also write it —
/// the neighbour a transaction narrows — and naming it permits that write
/// without making it a candidate. It is *already handled* when an earlier stage
/// changed it and reserved it. Anything else is simply not this stage's: the
/// pipeline decides whether it was a mistake, see [`check_only_resolved`].
fn focus(
    stage: &dyn Stage,
    candidates: &[Candidate],
    only: &[String],
    reserved: &BTreeSet<MutationScope>,
) -> Result<Focus> {
    let requested: BTreeSet<&str> = only.iter().map(String::as_str).collect();
    let mut roots = Vec::new();
    for candidate in candidates {
        let selected = match stage.scope(candidate) {
            MutationScope::Unit(name)
            | MutationScope::UnitData(name)
            | MutationScope::UnitLink(name) => requested.contains(name.as_str()),
            MutationScope::CodeDependency(_) | MutationScope::DataDependency(_) => false,
            MutationScope::Symbol(_) => {
                stage.writes(candidate)?.iter().any(|unit| requested.contains(unit.as_str()))
            }
        };
        if selected {
            roots.push(candidate.clone());
        }
    }
    let mut involved: BTreeSet<String> = reserved
        .iter()
        .filter_map(|scope| match scope {
            MutationScope::Unit(name)
            | MutationScope::UnitData(name)
            | MutationScope::UnitLink(name) => Some(name.clone()),
            MutationScope::CodeDependency(_)
            | MutationScope::DataDependency(_)
            | MutationScope::Symbol(_) => None,
        })
        .collect();
    for root in &roots {
        if let MutationScope::Unit(name)
        | MutationScope::UnitData(name)
        | MutationScope::UnitLink(name) = stage.scope(root)
        {
            involved.insert(name);
        }
        involved.extend(stage.writes(root)?);
    }
    let resolved =
        requested.iter().filter(|name| involved.contains(**name)).map(|n| n.to_string()).collect();
    let skipped: BTreeSet<String> = candidates
        .iter()
        .filter(|candidate| !roots.iter().any(|root| root.name == candidate.name))
        .map(|c| c.name.clone())
        .collect();
    Ok(Focus { roots, skipped: skipped.into_iter().collect(), resolved })
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
    /// The `--only` names this stage accounted for: its candidate roots, the
    /// units their changes write, and names an earlier stage already changed.
    /// Stored so a resumed run checks the same thing the original did.
    pub only_resolved: Vec<String>,
}

/// Refuses to publish a focused run that never involved a requested name.
///
/// Each stage resolves only the names it can: coverage cannot know what
/// discovery will propose, and discovery never sees a unit coverage already
/// changed. Whether a name was a mistake is therefore a question about the
/// whole pipeline, answered once every stage has had its turn and before
/// anything reaches the user's checkout.
pub fn check_only_resolved<'a>(
    only: &[String],
    resolved: impl IntoIterator<Item = &'a String>,
) -> Result<()> {
    let resolved: BTreeSet<&String> = resolved.into_iter().collect();
    let missing: Vec<&String> = only.iter().filter(|name| !resolved.contains(name)).collect();
    if !missing.is_empty() {
        bail!(
            "Requested units were neither proposed by any stage nor written by a requested \
             candidate's change, so nothing was published: {missing:?}"
        );
    }
    Ok(())
}

/// A digest of the manifest, used as a baseline identity in job records.
pub fn baseline_fingerprint(manifest: &Manifest) -> Result<String> { fingerprint(manifest) }

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        project::report::Report,
        stages::{Applied, Outcome, Prepared, Selections},
    };

    /// A stage whose only behaviour is which units each candidate writes.
    struct Writes(BTreeMap<&'static str, &'static [&'static str]>);

    impl Stage for Writes {
        fn name(&self) -> &'static str { "fixture" }

        fn prepare(&self, _: &BuildContext, _: Option<usize>) -> Result<Prepared> { unreachable!() }

        fn writes(&self, candidate: &Candidate) -> Result<BTreeSet<String>> {
            Ok(self.0[candidate.name.as_str()].iter().map(|u| u.to_string()).collect())
        }

        fn evaluate(
            &self,
            _: &BuildContext,
            _: &Prepared,
            _: &[Candidate],
            _: &Selections,
        ) -> Result<Outcome> {
            unreachable!()
        }

        fn validate(
            &self,
            _: &BuildContext,
            _: &[Candidate],
            _: &Prepared,
            _: &Selections,
            _: &[Applied],
        ) -> Result<Report> {
            unreachable!()
        }
    }

    fn stage() -> Writes {
        Writes(BTreeMap::from([("A.cpp", &["A.cpp", "B.cpp"][..]), ("Q.cpp", &["Q.cpp"][..])]))
    }

    fn candidates() -> Vec<Candidate> { vec![Candidate::new("A.cpp"), Candidate::new("Q.cpp")] }

    fn only(names: &[&str]) -> Vec<String> { names.iter().map(|n| n.to_string()).collect() }

    fn none() -> BTreeSet<MutationScope> { BTreeSet::new() }

    #[test]
    fn a_required_neighbour_may_be_permitted_without_being_a_candidate() {
        let focused = focus(&stage(), &candidates(), &only(&["A.cpp", "B.cpp"]), &none()).unwrap();
        assert_eq!(focused.roots.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["A.cpp"]);
        assert_eq!(focused.skipped, ["Q.cpp"]);
        assert_eq!(focused.resolved, BTreeSet::from(["A.cpp".into(), "B.cpp".into()]));
    }

    #[test]
    fn a_dependency_counts_only_for_a_requested_root() {
        // B.cpp is written only by A.cpp's change, which was not asked for.
        let focused = focus(&stage(), &candidates(), &only(&["Q.cpp", "B.cpp"]), &none()).unwrap();
        assert_eq!(focused.resolved, BTreeSet::from(["Q.cpp".into()]));
        let error = check_only_resolved(&only(&["Q.cpp", "B.cpp"]), &focused.resolved).unwrap_err();
        assert!(error.to_string().contains("B.cpp"), "{error}");
        let neighbour_alone = focus(&stage(), &candidates(), &only(&["B.cpp"]), &none()).unwrap();
        assert!(neighbour_alone.roots.is_empty());
        assert!(neighbour_alone.resolved.is_empty());
    }

    #[test]
    fn a_later_stage_accepts_names_an_earlier_stage_already_changed() {
        // Coverage changed A.cpp and B.cpp and reserved them; discovery has no
        // candidate for either and must not treat the request as a mistake.
        let reserved = BTreeSet::from([
            MutationScope::Unit("A.cpp".into()),
            MutationScope::Unit("B.cpp".into()),
        ]);
        let focused = focus(&stage(), &[], &only(&["A.cpp", "B.cpp"]), &reserved).unwrap();
        assert!(focused.roots.is_empty());
        assert_eq!(focused.resolved.len(), 2);
    }

    #[test]
    fn a_name_is_checked_against_every_stage_together() {
        // Coverage resolves A.cpp; only discovery proposes D.cpp.
        let coverage = focus(&stage(), &candidates(), &only(&["A.cpp", "D.cpp"]), &none()).unwrap();
        assert!(!coverage.resolved.contains("D.cpp"));
        let discover = focus(
            &Writes(BTreeMap::from([("D.cpp", &["D.cpp"][..])])),
            &[Candidate::new("D.cpp")],
            &only(&["A.cpp", "D.cpp"]),
            &BTreeSet::from([
                MutationScope::Unit("A.cpp".into()),
                MutationScope::Unit("B.cpp".into()),
            ]),
        )
        .unwrap();
        check_only_resolved(
            &only(&["A.cpp", "D.cpp"]),
            coverage.resolved.iter().chain(&discover.resolved),
        )
        .unwrap();
        let error =
            check_only_resolved(&only(&["A.cpp", "nowhere.cpp"]), &coverage.resolved).unwrap_err();
        assert!(error.to_string().contains("nowhere.cpp"), "{error}");
    }

    #[test]
    fn a_renamed_symbol_cannot_reserve_an_identically_named_unit() {
        let symbol = Candidate {
            name: "A.cpp".into(),
            evidence: serde_json::to_value(crate::stages::derive::Rename {
                new: "renamed".into(),
                unit: "B.cpp".into(),
                method: "fixture".into(),
                tier: crate::derive::propose::Tier::Confident,
                signal: None,
                off_spine: false,
            })
            .unwrap(),
        };
        let result = StageResult {
            stage: "derive".into(),
            offered: vec![symbol.clone()],
            accepted: vec![symbol.clone()],
            deferred: Vec::new(),
            selections: Selections::new(),
            events: Vec::new(),
            validation: String::new(),
            dol_sha1: String::new(),
            baseline: Default::default(),
            final_measures: Default::default(),
            reserved_by_earlier_stage: Vec::new(),
            eligible_excluded_by_only: Vec::new(),
            applied: Vec::new(),
            retry: RetryCounts::default(),
            timing: StageTiming::default(),
            seconds: 0.0,
        };
        let reserved = result.changed_scopes(&Derive).unwrap();
        assert_eq!(reserved, BTreeSet::from([MutationScope::Symbol("A.cpp".into())]));
        assert!(is_reserved(&Derive, &symbol, &reserved).unwrap());
        assert!(!is_reserved(&stage(), &Candidate::new("A.cpp"), &reserved).unwrap());
        let focused = focus(&stage(), &candidates(), &only(&["A.cpp"]), &reserved).unwrap();
        assert_eq!(focused.roots.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["A.cpp"]);
        assert_eq!(focused.resolved, BTreeSet::from(["A.cpp".into()]));

        // `--only` names units: a same-spelling symbol is not itself a root.
        let derive = focus(&Derive, &[symbol], &only(&["A.cpp"]), &none()).unwrap();
        assert!(derive.roots.is_empty());
        assert!(derive.resolved.is_empty());

        let symbol_for_b = result.accepted[0].clone();
        let derive_for_b = focus(&Derive, &[symbol_for_b], &only(&["B.cpp"]), &none()).unwrap();
        assert_eq!(derive_for_b.roots.len(), 1);
        assert_eq!(derive_for_b.resolved, BTreeSet::from(["B.cpp".into()]));
    }

    #[test]
    fn current_stage_results_require_selection_and_application_history() {
        let result = StageResult {
            stage: "coverage".into(),
            offered: Vec::new(),
            accepted: Vec::new(),
            deferred: Vec::new(),
            selections: Selections::new(),
            events: Vec::new(),
            validation: String::new(),
            dol_sha1: String::new(),
            baseline: Default::default(),
            final_measures: Default::default(),
            reserved_by_earlier_stage: Vec::new(),
            eligible_excluded_by_only: Vec::new(),
            applied: Vec::new(),
            retry: RetryCounts::default(),
            timing: StageTiming::default(),
            seconds: 0.0,
        };
        let serialized = serde_json::to_value(result).unwrap();
        for field in ["offered", "selections", "applied"] {
            let mut missing = serialized.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<StageResult>(missing).is_err(), "{field}");
        }
    }
}
