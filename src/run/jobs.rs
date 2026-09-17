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
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    build::process::Cancel,
    run::{RunDir, RunRecord, context, read_json, write_json},
    stages::{Candidate, Event, Prepared, Selections, Stage},
    workspace::{Manifest, fingerprint},
};

/// Splits candidates into batches of at most `size`, in order.
pub fn batches(candidates: &[Candidate], size: usize) -> Vec<Vec<Candidate>> {
    if size == 0 {
        return vec![candidates.to_vec()];
    }
    candidates.chunks(size).map(<[Candidate]>::to_vec).collect()
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
        "environment": run.environment,
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
    crate::run::check_environment(run)?;
    let baseline_hash = crate::run::baseline_fingerprint(manifest)?;
    let stage_dir = dir.stage(stage_name);

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

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for lane in 0..lanes {
            let specs = &specs;
            let results = &results;
            let failures = &failures;
            let cancel = cancel.clone();
            let stage_dir = stage_dir.as_path();
            handles.push(scope.spawn(move || {
                // Round-robin rather than contiguous chunks: batches are
                // ordered by expected size, so striping keeps the lanes even.
                for index in (lane..specs.len()).step_by(lanes) {
                    if cancel.load(Ordering::SeqCst) {
                        return;
                    }
                    let spec = &specs[index];
                    let output = stage_dir.join("jobs").join(&spec.job_id);
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
        }
    }

    #[test]
    fn candidates_are_batched_in_order() {
        let all = candidates(5);
        let split = batches(&all, 2);
        assert_eq!(split.len(), 3);
        assert_eq!(split[0][0].name, "u0");
        assert_eq!(split[2][0].name, "u4");
    }

    #[test]
    fn a_batch_size_of_zero_means_one_batch() {
        assert_eq!(batches(&candidates(5), 0).len(), 1);
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
