//! Splitting candidates into batches and evaluating them in parallel lanes.
//!
//! Each lane owns a private copy of the project and evaluates whole batches in
//! it. Nothing is shared between lanes but the frozen baseline they all reset
//! from, which is read-only for the duration.
//!
//! A completed batch writes its result next to its evidence. On `--resume`
//! those results are reused, but only when the job they describe is identical:
//! same baseline, same candidates, same stage, same tools, same timeout. A
//! result that does not match is rerun rather than trusted.

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    build::process::Cancel,
    run::{RunDir, RunRecord, context, read_json, write_json},
    stages::{Candidate, Event, Footprint, Prepared, Selections, Stage},
    workspace::{Manifest, fingerprint},
};

/// Splits candidates into batches of about `size`.
///
/// Versions 1 and 2 keep candidates whose footprints conflict — one reads or
/// writes a unit the other may write, or both claim the same ground — in one
/// lane. Version 3 keeps ordinary conflict components together but caps a
/// component larger than `size`. Its workers only propose results; coordinator
/// integration preserves candidate order and adaptively re-proves combinations,
/// so splitting a broad dependency hub cannot make completion order decide the
/// result and no longer strands every other worker behind one serial lane.
///
/// Components are placed by their first candidate, and a batch lists its
/// candidates in their original order, so the result depends only on the
/// candidate list.
pub fn batches(
    candidates: &[Candidate],
    size: usize,
    footprints: &[Footprint],
    workers: usize,
    version: u32,
) -> Result<Vec<Vec<Candidate>>> {
    assert_eq!(candidates.len(), footprints.len(), "one footprint per candidate");
    if !matches!(version, 1..=4) {
        bail!("Unsupported batching version {version}");
    }
    if size == 0 || candidates.is_empty() {
        return Ok(vec![candidates.to_vec()]);
    }
    let size = match version {
        1 => size,
        2..=4 => {
            // Keep four jobs ready per lane. The expensive outliers are whole
            // candidate batches: a batch with several slow linker refusals
            // held one lane for twenty minutes after its eleven siblings had
            // finished. Smaller batches let those outliers run on separate
            // lanes while still amortising workspace resets and group builds.
            let jobs_per_lane = if version >= 4 { 4 } else { 2 };
            let target = workers.max(1).saturating_mul(jobs_per_lane).min(candidates.len());
            size.min(candidates.len().div_ceil(target).max(1))
        }
        _ => unreachable!("batching version was checked above"),
    };
    let components = conflict_components(footprints);
    let mut result: Vec<Vec<Candidate>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    for component in components {
        if version >= 3 && component.len() > size {
            if !current.is_empty() {
                current.sort_unstable();
                result.push(current.iter().map(|&index| candidates[index].clone()).collect());
                current.clear();
            }
            for chunk in component.chunks(size) {
                result.push(chunk.iter().map(|&index| candidates[index].clone()).collect());
            }
            continue;
        }
        if !current.is_empty() && current.len() + component.len() > size {
            current.sort_unstable();
            result.push(current.iter().map(|&index| candidates[index].clone()).collect());
            current.clear();
        }
        current.extend(component);
    }
    if !current.is_empty() {
        current.sort_unstable();
        result.push(current.iter().map(|&index| candidates[index].clone()).collect());
    }
    Ok(result)
}

/// Candidate indices grouped by conflict, each group ascending, groups ordered
/// by their first member.
fn conflict_components(footprints: &[Footprint]) -> Vec<Vec<usize>> {
    let mut parent: Vec<usize> = (0..footprints.len()).collect();
    fn root(parent: &mut [usize], mut index: usize) -> usize {
        while parent[index] != index {
            parent[index] = parent[parent[index]];
            index = parent[index];
        }
        index
    }
    fn join(parent: &mut [usize], a: usize, b: usize) {
        let (a, b) = (root(parent, a), root(parent, b));
        // The smaller index stays the root, so a component is named by its
        // first candidate.
        if a != b {
            let (low, high) = (a.min(b), a.max(b));
            parent[high] = low;
        }
    }

    // Shared units, by index rather than pairwise.
    let mut by_unit: std::collections::BTreeMap<&str, usize> = Default::default();
    for (index, footprint) in footprints.iter().enumerate() {
        for unit in &footprint.units {
            match by_unit.get(unit.as_str()) {
                Some(&first) => join(&mut parent, first, index),
                None => {
                    by_unit.insert(unit, index);
                }
            }
        }
    }
    // Overlapping or touching ground, by a sweep over each section.
    let mut intervals: Vec<(&str, u32, u32, usize)> = footprints
        .iter()
        .enumerate()
        .flat_map(|(index, footprint)| {
            footprint
                .intervals
                .iter()
                .map(move |(section, start, end)| (section.as_str(), *start, *end, index))
        })
        .collect();
    intervals.sort_unstable();
    let mut reach: Option<(&str, u32, usize)> = None;
    for (section, start, end, index) in intervals {
        match reach {
            Some((open, far, owner)) if open == section && start <= far => {
                join(&mut parent, owner, index);
                reach = Some((section, far.max(end), owner));
            }
            _ => reach = Some((section, end, index)),
        }
    }

    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for index in 0..footprints.len() {
        groups.entry(root(&mut parent, index)).or_default().push(index);
    }
    groups.into_values().collect()
}

/// Everything that decides whether a stored result may be reused.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub schema: u32,
    pub stage: String,
    pub job_id: String,
    pub baseline_fingerprint: String,
    /// One digest over the whole job, so a single comparison answers "is this
    /// the same work?".
    pub fingerprint: String,
    pub candidates: Vec<Candidate>,
}

/// What one lane concluded about one batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub schema: u32,
    pub job_id: String,
    pub fingerprint: String,
    pub accepted: Vec<Candidate>,
    pub deferred: Vec<Candidate>,
    pub events: Vec<Event>,
    pub validation: String,
    /// Which alternative each accepted candidate was proved with, so
    /// integration can try the same one first.
    #[serde(default)]
    pub selections: Selections,
    /// What this batch already asked about, so the coordinator does not spend a
    /// build putting the same question a second time.
    #[serde(default)]
    pub tried: crate::stages::Tried,
    /// Wall time spent resetting and evaluating this job. Older stored jobs
    /// deserialize as zero and remain reusable.
    #[serde(default)]
    pub seconds: f64,
}

fn job_fingerprint(
    baseline: &str,
    batch: &[Candidate],
    stage: &str,
    run: &RunRecord,
) -> Result<String> {
    fingerprint(&serde_json::json!({
        "baseline": baseline,
        "candidates": batch,
        "stage": stage,
        // A compatible coordinator upgrade is allowed to reuse completed
        // worker jobs. Their identity remains the environment under which the
        // run first measured them; the run separately records every binary
        // that coordinated later work.
        "environment": run.artifact_environment(),
        "build_timeout": run.build_timeout_seconds,
    }))
}

/// Checks a stored result really describes this job before reusing it.
fn accept_stored(result: &JobResult, spec: &JobSpec) -> Result<()> {
    if result.schema != spec.schema
        || result.job_id != spec.job_id
        || result.fingerprint != spec.fingerprint
    {
        bail!("Stored result belongs to a different job or baseline");
    }
    let expected: BTreeSet<&str> = spec.candidates.iter().map(|c| c.name.as_str()).collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for candidate in result.accepted.iter().chain(&result.deferred) {
        if !seen.insert(candidate.name.as_str()) {
            bail!("Stored result repeats a candidate");
        }
    }
    if seen != expected {
        bail!("Stored result does not cover exactly this job's candidates");
    }
    Ok(())
}

/// Evaluates every batch across `run.workers` lanes and returns their results
/// in batch order.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    dir: &RunDir,
    run: &RunRecord,
    stage: &(dyn Stage + Send + Sync),
    stage_name: &str,
    baseline: &Path,
    manifest: &Manifest,
    prepared: &Prepared,
    batches: &[Vec<Candidate>],
    cancel: Option<Cancel>,
) -> Result<Vec<JobResult>> {
    execute_in(
        dir,
        run,
        stage,
        stage_name,
        baseline,
        manifest,
        prepared,
        batches,
        cancel,
        &dir.stage(stage_name).join("jobs"),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_in(
    dir: &RunDir,
    run: &RunRecord,
    stage: &(dyn Stage + Send + Sync),
    stage_name: &str,
    baseline: &Path,
    manifest: &Manifest,
    prepared: &Prepared,
    batches: &[Vec<Candidate>],
    cancel: Option<Cancel>,
    jobs_dir: &Path,
) -> Result<Vec<JobResult>> {
    crate::run::check_environment(run)?;
    let baseline_hash = crate::run::baseline_fingerprint(manifest)?;

    let specs: Vec<JobSpec> = batches
        .iter()
        .enumerate()
        .map(|(index, batch)| {
            Ok(JobSpec {
                schema: crate::run::SCHEMA,
                stage: stage_name.to_string(),
                job_id: format!("{index:05}"),
                baseline_fingerprint: baseline_hash.clone(),
                fingerprint: job_fingerprint(&baseline_hash, batch, stage_name, run)?,
                candidates: batch.clone(),
            })
        })
        .collect::<Result<_>>()?;

    let cancel = cancel.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let results: Mutex<Vec<Option<JobResult>>> = Mutex::new(vec![None; specs.len()]);
    let failures: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    let lanes = run.workers.max(1).min(specs.len().max(1));
    let next = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for lane in 0..lanes {
            let specs = &specs;
            let results = &results;
            let failures = &failures;
            let cancel = cancel.clone();
            let next = &next;
            handles.push(scope.spawn(move || {
                // Pull work only after finishing the current batch. Trial cost
                // is dominated by how far a failure bisects, which candidate
                // count cannot predict; a static stripe left lanes idle behind
                // one unexpectedly expensive batch.
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if index >= specs.len() {
                        return;
                    }
                    if cancel.load(Ordering::SeqCst) {
                        return;
                    }
                    let spec = &specs[index];
                    let output = jobs_dir.join(&spec.job_id);
                    match run_one(
                        run,
                        stage,
                        spec,
                        prepared,
                        baseline,
                        manifest,
                        &dir.pool().join(format!("worker-{lane}")),
                        &output,
                        cancel.clone(),
                    ) {
                        Ok(result) => results.lock().unwrap()[index] = Some(result),
                        Err(error) => {
                            if cancel.load(Ordering::SeqCst) {
                                return;
                            }
                            // Stop the other lanes, but keep what they finished:
                            // a resumed run reuses those instead of redoing them.
                            cancel.store(true, Ordering::SeqCst);
                            let _ = write_json(
                                &output.join("failure.json"),
                                &serde_json::json!({ "error": format!("{error:#}") }),
                            );
                            failures
                                .lock()
                                .unwrap()
                                .push((spec.job_id.clone(), format!("{error:#}")));
                        }
                    }
                }
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
    });

    let failures = failures.into_inner().unwrap();
    if !failures.is_empty() {
        bail!("Worker jobs failed; successful siblings are retained for --resume: {failures:?}");
    }
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, result)| result.with_context(|| format!("Batch {index} produced no result")))
        .collect()
}

/// Evaluates one batch in one lane's workspace.
#[allow(clippy::too_many_arguments)]
fn run_one(
    run: &RunRecord,
    stage: &(dyn Stage + Send + Sync),
    spec: &JobSpec,
    prepared: &Prepared,
    baseline: &Path,
    manifest: &Manifest,
    workspace: &Path,
    output: &Path,
    cancel: Cancel,
) -> Result<JobResult> {
    let started = Instant::now();
    let result_path = output.join("result.json");
    if let Ok(stored) = read_json::<JobResult>(&result_path)
        && accept_stored(&stored, spec).is_ok()
    {
        tracing::info!("{}: batch {} reused from a previous run", spec.stage, spec.job_id);
        return Ok(stored);
    }

    crate::workspace::reset_workspace(baseline, workspace, manifest)?;
    crate::workspace::seed_objdiff(baseline, workspace)?;
    write_json(&output.join("job.json"), spec)?;
    tracing::info!("{}: batch {} ({} candidates)", spec.stage, spec.job_id, spec.candidates.len());

    let ctx = context(workspace, run, output.join("process"), Some(cancel));
    let outcome = stage.evaluate(&ctx, prepared, &spec.candidates, &Selections::new())?;
    let result = JobResult {
        schema: crate::run::SCHEMA,
        job_id: spec.job_id.clone(),
        fingerprint: spec.fingerprint.clone(),
        accepted: outcome.accepted,
        deferred: outcome.deferred,
        events: outcome.events,
        validation: outcome.validation,
        selections: outcome.selections,
        tried: outcome.tried,
        seconds: started.elapsed().as_secs_f64(),
    };
    accept_stored(&result, spec).context("The stage returned candidates it was not given")?;
    write_json(&result_path, &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(count: usize) -> Vec<Candidate> {
        (0..count).map(|i| Candidate::new(format!("u{i}"))).collect()
    }

    fn alone(candidates: &[Candidate]) -> Vec<Footprint> {
        candidates.iter().map(|c| Footprint::of(&c.name)).collect()
    }

    fn names(batch: &[Candidate]) -> Vec<&str> { batch.iter().map(|c| c.name.as_str()).collect() }

    fn spec(names: &[&str]) -> JobSpec {
        JobSpec {
            schema: crate::run::SCHEMA,
            stage: "verify".into(),
            job_id: "00000".into(),
            baseline_fingerprint: "base".into(),
            fingerprint: "job".into(),
            candidates: names.iter().map(|n| Candidate::new(*n)).collect(),
        }
    }

    fn result(accepted: &[&str], deferred: &[&str]) -> JobResult {
        JobResult {
            tried: Default::default(),
            schema: crate::run::SCHEMA,
            job_id: "00000".into(),
            fingerprint: "job".into(),
            accepted: accepted.iter().map(|n| Candidate::new(*n)).collect(),
            deferred: deferred.iter().map(|n| Candidate::new(*n)).collect(),
            events: Vec::new(),
            validation: "fixture".into(),
            selections: Selections::new(),
            seconds: 0.0,
        }
    }

    #[test]
    fn candidates_are_batched_in_order() {
        let all = candidates(5);
        let split = batches(&all, 2, &alone(&all), 1, 1).unwrap();
        assert_eq!(split.len(), 3);
        assert_eq!(split[0][0].name, "u0");
        assert_eq!(split[2][0].name, "u4");
    }

    #[test]
    fn a_batch_size_of_zero_means_one_batch() {
        let all = candidates(5);
        assert_eq!(batches(&all, 0, &alone(&all), 3, 2).unwrap().len(), 1);
    }

    #[test]
    fn candidates_sharing_a_unit_are_decided_in_one_lane() {
        // u0 and u3 both depend on shared.cpp: a transaction for one reads or
        // writes what the other may change.
        let all = candidates(4);
        let mut footprints = alone(&all);
        footprints[0].units.insert("shared.cpp".into());
        footprints[3].units.insert("shared.cpp".into());
        let split = batches(&all, 2, &footprints, 1, 1).unwrap();
        assert_eq!(split.iter().map(|b| names(b)).collect::<Vec<_>>(), [vec!["u0", "u3"], vec![
            "u1", "u2"
        ]]);
    }

    #[test]
    fn candidates_claiming_touching_ground_are_decided_in_one_lane() {
        let all = candidates(3);
        let mut footprints = alone(&all);
        footprints[0].intervals.push((".text".into(), 0x100, 0x200));
        footprints[1].intervals.push((".data".into(), 0x100, 0x200));
        footprints[2].intervals.push((".text".into(), 0x200, 0x280));
        let split = batches(&all, 1, &footprints, 1, 1).unwrap();
        assert_eq!(split.iter().map(|b| names(b)).collect::<Vec<_>>(), [vec!["u0", "u2"], vec![
            "u1"
        ]]);
    }

    #[test]
    fn a_component_is_never_split_to_honour_the_batch_size() {
        let all = candidates(3);
        let mut footprints = alone(&all);
        for footprint in &mut footprints {
            footprint.units.insert("hub.cpp".into());
        }
        let split = batches(&all, 1, &footprints, 1, 1).unwrap();
        assert_eq!(split.len(), 1);
        assert_eq!(names(&split[0]), ["u0", "u1", "u2"]);
    }

    #[test]
    fn current_batching_caps_a_dependency_hub() {
        let all = candidates(5);
        let mut footprints = alone(&all);
        for footprint in &mut footprints {
            footprint.units.insert("hub.cpp".into());
        }
        let split = batches(&all, 2, &footprints, 1, 3).unwrap();
        assert_eq!(split.iter().map(|batch| names(batch)).collect::<Vec<_>>(), [
            vec!["u0", "u1"],
            vec!["u2", "u3"],
            vec!["u4"]
        ]);
    }

    #[test]
    fn batching_depends_only_on_the_candidate_list() {
        let all = candidates(6);
        let mut footprints = alone(&all);
        footprints[1].units.insert("x.cpp".into());
        footprints[4].units.insert("x.cpp".into());
        assert_eq!(
            batches(&all, 2, &footprints, 1, 1)
                .unwrap()
                .iter()
                .map(|b| names(b))
                .collect::<Vec<_>>(),
            batches(&all, 2, &footprints, 1, 1)
                .unwrap()
                .iter()
                .map(|b| names(b))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn prior_runs_keep_two_batches_ready_per_worker() {
        let all = candidates(55);
        let split = batches(&all, 40, &alone(&all), 3, 2).unwrap();
        assert_eq!(split.len(), 6);
        assert!(split.iter().all(|batch| batch.len() <= 10));
    }

    #[test]
    fn fresh_runs_spread_slow_batches_across_more_lanes() {
        let all = candidates(231);
        let split = batches(&all, 40, &alone(&all), 6, 4).unwrap();
        assert_eq!(split.len(), 24);
        assert!(split.iter().all(|batch| batch.len() <= 10));
    }

    #[test]
    fn resumed_legacy_runs_keep_their_original_partition() {
        let all = candidates(55);
        let split = batches(&all, 40, &alone(&all), 3, 1).unwrap();
        assert_eq!(split.iter().map(Vec::len).collect::<Vec<_>>(), [40, 15]);
    }

    #[test]
    fn an_unknown_batching_version_is_refused() {
        let all = candidates(1);
        assert!(batches(&all, 40, &alone(&all), 3, 99).is_err());
    }

    #[test]
    fn a_result_covering_exactly_the_job_is_reusable() {
        assert!(accept_stored(&result(&["a"], &["b"]), &spec(&["a", "b"])).is_ok());
    }

    #[test]
    fn a_result_from_a_different_job_is_not_reused() {
        let mut stored = result(&["a"], &["b"]);
        stored.fingerprint = "other".into();
        assert!(accept_stored(&stored, &spec(&["a", "b"])).is_err());
    }

    #[test]
    fn a_result_that_omits_a_candidate_is_not_reused() {
        assert!(accept_stored(&result(&["a"], &[]), &spec(&["a", "b"])).is_err());
    }

    #[test]
    fn a_result_that_invents_a_candidate_is_not_reused() {
        assert!(accept_stored(&result(&["a", "c"], &["b"]), &spec(&["a", "b"])).is_err());
    }

    #[test]
    fn a_result_that_repeats_a_candidate_is_not_reused() {
        assert!(accept_stored(&result(&["a"], &["a", "b"]), &spec(&["a", "b"])).is_err());
    }
}
