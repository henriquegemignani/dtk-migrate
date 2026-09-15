//! The four things a migration can try, and the shape they all share.
//!
//! A stage proposes candidates, tries them in a private copy of the project,
//! and keeps only what the build agrees with. What differs between stages is
//! what a candidate *is* and what counts as agreement:
//!
//! | stage | candidate | kept when |
//! |---|---|---|
//! | derive | a symbol rename | it links, and reduces no unit's matched code |
//! | coverage | a target range assigned to a source unit | the evidence holds and retail bytes survive |
//! | discover | a split range | matched code goes up and no existing unit regresses |
//! | verify | a whole source file, enabled | its object is really linked and the result is retail |
//!
//! None of them keeps anything on the strength of a proposal alone, and none of
//! them is allowed to conclude something the build did not show.

use std::collections::{BTreeMap, VecDeque};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    build::context::{BuildContext, is_trial_failure},
    project::report::Report,
};

pub mod coverage;
pub mod discover;
pub mod verify;

/// Which alternative a stage chose for a candidate, when a candidate has more
/// than one way to be right.
///
/// Only coverage does: a unit can be claimed by an exact-body run, a layout
/// group or a bounded sequence, and which one survived the build is part of the
/// result rather than an implementation detail. Recording it lets publication
/// re-check the same range rather than a differently-derived one.
pub type Selections = BTreeMap<String, String>;

/// One thing a stage wants to try, and whatever evidence it carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// The unit this is about. Candidates are addressed by unit name across the
    /// whole pipeline, which is how a later stage knows to leave alone what an
    /// earlier one already published.
    pub name: String,
    /// Stage-specific evidence, carried from `prepare` to `evaluate` and into
    /// the run's record.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub evidence: serde_json::Value,
}

impl Candidate {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), evidence: serde_json::Value::Null }
    }
}

/// Something worth recording that is not an accepted or rejected candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub unit: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Event {
    pub fn new(unit: impl Into<String>, status: impl Into<String>) -> Self {
        Self { unit: unit.into(), status: status.into(), reason: None }
    }

    pub fn because(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// What a stage found before trying anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prepared {
    pub candidates: Vec<Candidate>,
    /// The measurement everything later is compared against.
    pub baseline: Report,
    #[serde(default)]
    pub events: Vec<Event>,
    /// Stage-specific state that `evaluate` and the run's record need.
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// What a stage concluded after trying them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub accepted: Vec<Candidate>,
    /// Which alternative each accepted candidate was proved with. Empty for a
    /// stage whose candidates have only one form.
    #[serde(default)]
    pub selections: Selections,
    /// Rejected here, but not ruled out: a different batch, boundary or
    /// baseline can change the answer, which is why this is not a blacklist.
    pub deferred: Vec<Candidate>,
    #[serde(default)]
    pub events: Vec<Event>,
    pub report: Report,
    /// What acceptance actually proved, in one phrase, recorded alongside the
    /// result so nobody has to infer it later.
    pub validation: String,
}

pub trait Stage {
    fn name(&self) -> &'static str;

    /// Builds the baseline and works out what is worth trying.
    fn prepare(&self, ctx: &BuildContext, limit: Option<usize>) -> Result<Prepared>;

    /// Tries the given candidates against the prepared baseline.
    ///
    /// `preferred` names the alternative a worker already found to work, so
    /// integration tries that one first instead of rediscovering it.
    fn evaluate(
        &self,
        ctx: &BuildContext,
        prepared: &Prepared,
        candidates: &[Candidate],
        preferred: &Selections,
    ) -> Result<Outcome>;

    /// Rechecks an accepted set in the project that is about to keep it.
    ///
    /// A worker proved something in its own copy. Publication applies the same
    /// change to the user's checkout, where the surroundings may differ, so the
    /// gate runs once more there.
    fn validate(
        &self,
        ctx: &BuildContext,
        accepted: &[Candidate],
        prepared: &Prepared,
        selections: &Selections,
    ) -> Result<Report>;

    /// Extra files this stage wants written beside its result, as
    /// (name, contents).
    ///
    /// Coverage writes a summary that separates the four things a migration can
    /// mean by progress, because a single number would be read as the strongest
    /// of them.
    fn artifacts(
        &self,
        _prepared: &Prepared,
        _result: &crate::run::StageResult,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }
}

/// Tries a batch, halving it on failure until single candidates are isolated.
///
/// Batching is what makes a run affordable: one build can clear forty
/// candidates. Bisection is what keeps it honest: when a batch fails, the
/// failure belongs to some subset, and splitting finds which without giving up
/// on the rest. A single candidate that still fails is deferred, not condemned —
/// a different baseline may accept it later.
///
/// `trial` receives the already-accepted set and the batch under test, and is
/// responsible for applying them and putting things back on failure. An error
/// it returns that is not a trial failure — a cancellation, an unreadable
/// report — stops everything.
pub fn bisect(
    candidates: &[Candidate],
    failure_status: &str,
    success_status: &str,
    mut trial: impl FnMut(&[Candidate], &[Candidate]) -> Result<()>,
) -> Result<(Vec<Candidate>, Vec<Candidate>, Vec<Event>)> {
    let mut accepted: Vec<Candidate> = Vec::new();
    let mut deferred: Vec<Candidate> = Vec::new();
    let mut events: Vec<Event> = Vec::new();

    // Depth-first over halves, so candidates are decided in the order given and
    // a run is reproducible from its candidate list alone.
    let mut queue: VecDeque<Vec<Candidate>> = VecDeque::new();
    queue.push_back(candidates.to_vec());
    while let Some(batch) = queue.pop_front() {
        if batch.is_empty() {
            continue;
        }
        match trial(&accepted, &batch) {
            Ok(()) => {
                events.extend(batch.iter().map(|c| Event::new(&c.name, success_status)));
                accepted.extend(batch);
            }
            Err(error) if is_trial_failure(&error) => {
                if batch.len() > 1 {
                    let middle = batch.len() / 2;
                    queue.push_front(batch[middle..].to_vec());
                    queue.push_front(batch[..middle].to_vec());
                } else {
                    events.push(
                        Event::new(&batch[0].name, failure_status).because(format!("{error:#}")),
                    );
                    deferred.extend(batch);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok((accepted, deferred, events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{context::ValidationError, process::CommandError};

    fn candidates(names: &[&str]) -> Vec<Candidate> {
        names.iter().map(|n| Candidate::new(*n)).collect()
    }

    fn names(candidates: &[Candidate]) -> Vec<&str> {
        candidates.iter().map(|c| c.name.as_str()).collect()
    }

    fn build_failure() -> anyhow::Error {
        anyhow::Error::new(CommandError::Failed { status: Some(1) })
    }

    #[test]
    fn a_batch_that_builds_is_accepted_whole() {
        let all = candidates(&["a", "b", "c"]);
        let mut trials = 0;
        let (accepted, deferred, events) = bisect(&all, "failed", "kept", |_, _| {
            trials += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(trials, 1, "one build should clear the whole batch");
        assert_eq!(names(&accepted), ["a", "b", "c"]);
        assert!(deferred.is_empty());
        assert!(events.iter().all(|e| e.status == "kept"));
    }

    #[test]
    fn one_bad_candidate_is_isolated_and_the_rest_survive() {
        let all = candidates(&["a", "b", "c", "d"]);
        let (accepted, deferred, _) = bisect(&all, "failed", "kept", |_, batch| {
            if batch.iter().any(|c| c.name == "c") { Err(build_failure()) } else { Ok(()) }
        })
        .unwrap();
        assert_eq!(names(&accepted), ["a", "b", "d"]);
        assert_eq!(names(&deferred), ["c"]);
    }

    #[test]
    fn a_deferred_candidate_records_why() {
        let all = candidates(&["a"]);
        let (_, deferred, events) = bisect(&all, "failed-build", "kept", |_, _| {
            Err(anyhow::Error::new(ValidationError("retail bytes differ".into())))
        })
        .unwrap();
        assert_eq!(names(&deferred), ["a"]);
        let event = events.iter().find(|e| e.unit == "a").unwrap();
        assert_eq!(event.status, "failed-build");
        assert!(event.reason.as_ref().unwrap().contains("retail bytes differ"));
    }

    #[test]
    fn each_trial_sees_what_has_already_been_accepted() {
        let all = candidates(&["a", "b"]);
        let mut seen: Vec<Vec<String>> = Vec::new();
        bisect(&all, "failed", "kept", |accepted, batch| {
            seen.push(accepted.iter().chain(batch).map(|c| c.name.clone()).collect());
            // Fail the pair so it splits, then accept each half.
            if batch.len() > 1 { Err(build_failure()) } else { Ok(()) }
        })
        .unwrap();
        assert_eq!(seen[0], ["a", "b"]);
        assert_eq!(seen[1], ["a"]);
        assert_eq!(seen[2], ["a", "b"], "the second half is tried on top of the first");
    }

    #[test]
    fn candidates_are_decided_in_the_order_they_were_given() {
        let all = candidates(&["a", "b", "c", "d", "e"]);
        let (accepted, deferred, _) = bisect(&all, "failed", "kept", |_, batch| {
            if batch.len() > 1 { Err(build_failure()) } else { Ok(()) }
        })
        .unwrap();
        assert_eq!(names(&accepted), ["a", "b", "c", "d", "e"]);
        assert!(deferred.is_empty());
    }

    #[test]
    fn an_error_that_is_not_the_candidates_fault_stops_everything() {
        let all = candidates(&["a", "b"]);
        let result =
            bisect(&all, "failed", "kept", |_, _| Err(anyhow::Error::new(CommandError::Cancelled)));
        assert!(result.is_err());
    }

    #[test]
    fn an_empty_candidate_list_does_nothing() {
        let (accepted, deferred, events) =
            bisect(&[], "failed", "kept", |_, _| panic!("should not run")).unwrap();
        assert!(accepted.is_empty() && deferred.is_empty() && events.is_empty());
    }
}
