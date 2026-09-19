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

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    build::context::{BuildContext, is_trial_failure},
    project::report::Report,
};

pub mod coverage;
pub mod derive;
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

/// A mutation's namespace. A derived symbol name can spell exactly the same
/// string as a translation unit without reserving that unit's later work.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MutationScope {
    Unit(String),
    Symbol(String),
}

/// One thing a stage wants to try, and whatever evidence it carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// Stage-specific name: a symbol for derive, a unit for the other stages.
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
    /// The alternative the event is about, when a candidate has several.
    ///
    /// A candidate's alternatives can change different units: a refusal of one
    /// that writes only the candidate says nothing about a neighbour that a
    /// different, untried alternative would have written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternative: Option<String>,
}

impl Event {
    pub fn new(unit: impl Into<String>, status: impl Into<String>) -> Self {
        Self { unit: unit.into(), status: status.into(), reason: None, alternative: None }
    }

    pub fn because(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn about(mut self, alternative: impl Into<String>) -> Self {
        self.alternative = Some(alternative.into());
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
    /// What the run will let this stage touch, filled in after preparation.
    #[serde(default)]
    pub permitted: Permitted,
}

/// The units a run allows a stage to change.
///
/// A stage that finds new work while evaluating — a unit whose evidence only
/// exists once its neighbour lands — still has to honour what the run set aside
/// for another stage or narrowed down with `--only`. Preparation cannot apply
/// those limits itself, because they are the run's to apply and are imposed on
/// the candidate list afterwards.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Permitted {
    /// Names reserved by an earlier stage. Never touch these.
    #[serde(default)]
    pub reserved: BTreeSet<String>,
    /// When a run was narrowed, the only names it may touch.
    #[serde(default)]
    pub only: BTreeSet<String>,
}

impl Permitted {
    pub fn allows(&self, name: &str) -> bool {
        !self.reserved.contains(name) && (self.only.is_empty() || self.only.contains(name))
    }
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
    /// Every alternative this pass actually asked about, accepted or not, so a
    /// later round does not spend a build re-asking.
    #[serde(default)]
    pub tried: Tried,
    #[serde(default)]
    pub events: Vec<Event>,
    pub report: Report,
    /// What acceptance actually proved, in one phrase, recorded alongside the
    /// result so nobody has to infer it later.
    pub validation: String,
    /// Every change applied, in order. Empty for a stage whose acceptances are
    /// fully described by `accepted`.
    #[serde(default)]
    pub applied: Vec<Applied>,
}

/// One change a stage applied while integrating, in the order it applied them.
///
/// `accepted` keeps one final candidate per unit, which is the right answer to
/// "what does each unit look like now" and the wrong one to "how did it get
/// there": a unit extended twice, or a neighbour narrowed by a transaction a
/// later refinement superseded, changed the project through a change no final
/// candidate still carries. Publication replays this history instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Applied {
    /// The candidate whose proposal carried the change.
    pub unit: String,
    /// The selection it was applied under.
    pub id: String,
    /// Every unit it wrote. All of them belong to this stage for the rest of
    /// the run, not only the candidate.
    pub units: Vec<String>,
    /// What the stage needs to re-check it, in the stage's own terms.
    #[serde(default)]
    pub record: serde_json::Value,
}

/// What evaluating a candidate may read or change.
///
/// Two candidates whose footprints conflict are one scheduling unit: they go
/// to the same worker, in candidate order, so which of them is decided first
/// can never depend on which lane finished first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Footprint {
    pub units: BTreeSet<String>,
    /// (section, start, end) ranges whose ownership may change.
    pub intervals: Vec<(String, u32, u32)>,
}

impl Footprint {
    pub fn of(name: &str) -> Self {
        Self { units: BTreeSet::from([name.to_string()]), intervals: Vec::new() }
    }

    /// Whether the two share a unit, or claim ranges that overlap or touch.
    pub fn conflicts(&self, other: &Footprint) -> bool {
        !self.units.is_disjoint(&other.units)
            || self.intervals.iter().any(|(section, start, end)| {
                other.intervals.iter().any(|(s, a, b)| s == section && start <= b && a <= end)
            })
    }
}

/// Alternative ids a unit has already been asked about, so that rediscovery can
/// tell a genuinely new proposal from the one that was just refused.
pub type Tried = BTreeMap<String, BTreeSet<String>>;

pub trait Stage {
    fn name(&self) -> &'static str;

    /// The namespace this candidate mutates. A symbol rename must not reserve
    /// a translation unit that happens to have the same spelling.
    fn scope(&self, candidate: &Candidate) -> MutationScope {
        MutationScope::Unit(candidate.name.clone())
    }

    /// Builds the baseline and works out what is worth trying.
    fn prepare(&self, ctx: &BuildContext, limit: Option<usize>) -> Result<Prepared>;

    /// Work the stage could not see until something was accepted.
    ///
    /// A boundary landing can give a unit its first usable evidence, and that
    /// unit may never have been a candidate. Only the coordinator calls this,
    /// between evaluation rounds: a worker proves the candidates it was handed
    /// in its own workspace, and a batch that invented new ones would be
    /// reporting on units another batch is holding at the same time.
    ///
    /// Must honour [`Prepared::permitted`], and must not return a proposal made
    /// only of alternatives listed in `tried` — that is the same question
    /// again, and answering it costs a build.
    fn rediscover(
        &self,
        _ctx: &BuildContext,
        _prepared: &Prepared,
        _tried: &Tried,
    ) -> Result<Vec<Candidate>> {
        Ok(Vec::new())
    }

    /// Units this candidate can change, or whose identity a symbol rename
    /// establishes. A focused run uses these to select symbol prerequisites
    /// and to permit every unit a transaction writes.
    fn writes(&self, candidate: &Candidate) -> Result<BTreeSet<String>> {
        Ok(BTreeSet::from([candidate.name.clone()]))
    }

    /// What evaluating this candidate may read or change, for scheduling.
    fn footprint(&self, candidate: &Candidate) -> Result<Footprint> {
        Ok(Footprint::of(&candidate.name))
    }

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
    /// gate runs once more there. `applied` is the history integration
    /// recorded, which the project must still be the result of.
    fn validate(
        &self,
        ctx: &BuildContext,
        accepted: &[Candidate],
        prepared: &Prepared,
        selections: &Selections,
        applied: &[Applied],
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
