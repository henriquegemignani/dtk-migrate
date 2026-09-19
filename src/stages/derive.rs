//! Naming target symbols from what the compiled source objects say.
//!
//! This runs first, because everything else depends on it: the matcher anchors
//! its proposals on symbol names, so every name established here widens what
//! coverage and discovery can later propose. Measured on a real PAL migration,
//! naming first took discovery from a frontier of roughly 29 candidates to 349,
//! of which 156 were accepted.
//!
//! A rename changes no bytes, so the retail hash cannot tell a right name from a
//! wrong one. The names are corroborated before they reach here, by comparing
//! compiled source objects against the extracted originals. What the build
//! *does* decide is whether a name can be applied at all: naming an address
//! after a function another unit compiles from source puts that name in two
//! linked objects, and the linker rejects it. That failure is loud, so a batch
//! that will not link is bisected exactly as a split candidate is, and only the
//! offending names are dropped. A rename that reduces any unit's matched code
//! is also rejected — that would mean a name took a pairing away from someone.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    build::context::{BuildContext, is_trial_failure},
    derive::{self, propose::Tier},
    project::{report::Report, symbols::Renames, transaction::Owned},
    stages::{Candidate, Event, MutationScope, Outcome, Prepared, Selections, Stage},
};

pub struct Derive;

const VALIDATION: &str = "objdiff body comparison between compiled source and extracted objects; the build decides only whether a name can be applied";

/// The rename one candidate carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rename {
    pub new: String,
    /// Source TU whose compiled-object evidence identified this symbol.
    pub unit: String,
    pub method: String,
    pub tier: Tier,
    /// Which rule settled it, and whether the unit's own ordering agreed.
    ///
    /// A rename decided against the run is right often enough to keep, and
    /// unusual enough to be worth a reviewer opening it in objdiff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    #[serde(default)]
    pub off_spine: bool,
}

impl Stage for Derive {
    fn name(&self) -> &'static str { "derive" }

    fn scope(&self, candidate: &Candidate) -> MutationScope {
        MutationScope::Symbol(candidate.name.clone())
    }

    fn writes(&self, candidate: &Candidate) -> Result<BTreeSet<String>> {
        Ok(BTreeSet::from([rename_of(candidate)?.unit]))
    }

    fn prepare(&self, ctx: &BuildContext, limit: Option<usize>) -> Result<Prepared> {
        let baseline = ctx.build(None)?;

        let mut request = derive::Request::new(ctx.root.clone(), ctx.target.clone());
        // The version being migrated from is the check on a misplaced name: if
        // it places the name where the target already has it, our own unmatched
        // source is the likelier explanation and nothing is renamed.
        request.reference = Some(ctx.source.clone());
        let result = derive::derive(&request)?;

        let mut candidates: Vec<Candidate> = Vec::new();
        for (old, proposal) in &result.accepted {
            // Only what is safe to apply unreviewed reaches a build.
            if proposal.tier > Tier::Probable {
                continue;
            }
            candidates.push(Candidate {
                name: old.clone(),
                evidence: serde_json::to_value(Rename {
                    new: proposal.new.clone(),
                    unit: proposal.unit.clone(),
                    method: proposal.method.clone(),
                    tier: proposal.tier,
                    signal: proposal.signal.clone(),
                    off_spine: proposal.off_spine.unwrap_or(false),
                })?,
            });
        }
        if let Some(limit) = limit {
            candidates.truncate(limit);
        }

        let mut events: Vec<Event> = result
            .rejected
            .iter()
            .map(|entry| Event::new(&entry.old, "rejected").because(&entry.reason))
            .collect();
        // A correction overwrites a name somebody already had reason to trust,
        // so it is recorded by name rather than disappearing into a count.
        let chosen: BTreeSet<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        let corrections: Vec<&derive::Correction> = result
            .corrections
            .iter()
            .filter(|entry| chosen.contains(entry.address_named.as_str()))
            .collect();
        events.extend(corrections.iter().map(|entry| {
            Event::new(&entry.unit, "misplaced-name").because(format!(
                "{} should be {}{}",
                entry.address_named,
                entry.should_be,
                if entry.frees_name_for.is_empty() {
                    String::new()
                } else {
                    format!(", freeing the name for {}", entry.frees_name_for.join(", "))
                }
            ))
        }));
        events.extend(
            result
                .failures
                .iter()
                .map(|failure| Event::new(&failure.unit, "unreadable").because(&failure.error)),
        );

        let mut extra = serde_json::Map::new();
        extra.insert("corrections".into(), serde_json::to_value(&corrections)?);
        extra.insert("proposed".into(), serde_json::to_value(result.proposed)?);
        extra.insert("units".into(), serde_json::to_value(result.units)?);
        Ok(Prepared { candidates, baseline, events, extra, permitted: Default::default() })
    }

    fn evaluate(
        &self,
        ctx: &BuildContext,
        _prepared: &Prepared,
        candidates: &[Candidate],
        _preferred: &Selections,
    ) -> Result<Outcome> {
        let names: BTreeSet<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        if names.len() != candidates.len() {
            bail!("Duplicate derivation candidate names");
        }
        let path = ctx.root.join("config").join(&ctx.target).join("symbols.txt");
        let mut owned = Owned::take(&path)?;
        let original = String::from_utf8(owned.original().to_vec())?;

        let mut report = ctx.build(None)?;
        let mut applied: BTreeMap<String, String> = BTreeMap::new();
        let mut accepted: BTreeSet<String> = BTreeSet::new();
        let mut events: Vec<Event> = Vec::new();

        // Each trial renders from the untouched original, so a rejected batch
        // leaves nothing behind.
        let write = |owned: &mut Owned, mapping: &BTreeMap<String, String>| -> Result<()> {
            let renames = Renames::from_pairs(mapping);
            let (rendered, _) = crate::project::symbols::render_renames(&original, &renames);
            owned.write(rendered.as_bytes())
        };

        let mut queue: Vec<Vec<Candidate>> = vec![candidates.to_vec()];
        while let Some(batch) = queue.pop() {
            if batch.is_empty() {
                continue;
            }
            let mut proposed = applied.clone();
            for candidate in &batch {
                proposed.insert(candidate.name.clone(), rename_of(candidate)?.new);
            }
            write(&mut owned, &proposed)?;

            let outcome = match ctx.trial_build() {
                Ok(tested) => {
                    // A name cannot add matched code on its own, but it can let
                    // the comparison pair functions it could not pair before, so
                    // the measure may rise. It must never fall.
                    if regresses(&report, &tested) {
                        Err("regresses-existing-code")
                    } else {
                        Ok(tested)
                    }
                }
                Err(error) if is_trial_failure(&error) => Err("name-conflict"),
                Err(error) => return Err(error),
            };

            match outcome {
                Ok(tested) => {
                    for candidate in &batch {
                        let rename = rename_of(candidate)?;
                        applied.insert(candidate.name.clone(), rename.new.clone());
                        accepted.insert(candidate.name.clone());
                        events.push(
                            Event::new(&candidate.name, "accepted")
                                .because(format!("{} by {}", rename.new, rename.method)),
                        );
                    }
                    report = tested;
                }
                Err(status) => {
                    write(&mut owned, &applied)?;
                    if batch.len() > 1 {
                        let middle = batch.len() / 2;
                        queue.push(batch[middle..].to_vec());
                        queue.push(batch[..middle].to_vec());
                    } else {
                        events.push(Event::new(&batch[0].name, status));
                    }
                }
            }
        }

        write(&mut owned, &applied)?;
        let final_report = ctx.build(None)?;
        if regresses(&report, &final_report) {
            bail!("Final derivation report regressed after validation");
        }
        owned.commit();
        Ok(Outcome {
            tried: Default::default(),
            accepted: candidates.iter().filter(|c| accepted.contains(&c.name)).cloned().collect(),
            deferred: candidates.iter().filter(|c| !accepted.contains(&c.name)).cloned().collect(),
            selections: Selections::new(),
            events,
            report: final_report,
            validation: VALIDATION.to_string(),
            applied: Vec::new(),
        })
    }

    fn validate(
        &self,
        ctx: &BuildContext,
        _accepted: &[Candidate],
        _prepared: &Prepared,
        _selections: &Selections,
        _applied: &[crate::stages::Applied],
    ) -> Result<Report> {
        ctx.build(None)
    }
}

fn rename_of(candidate: &Candidate) -> Result<Rename> {
    serde_json::from_value(candidate.evidence.clone())
        .with_context(|| format!("Missing rename for {}", candidate.name))
}

fn regresses(before: &Report, after: &Report) -> bool {
    let new = after.by_source_name();
    before.by_source_name().iter().any(|(name, unit)| {
        new.get(name).map(|u| u.matched_code()).unwrap_or(0) < unit.matched_code()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_candidate_carries_the_rename_it_proposes() {
        let candidate = Candidate {
            name: "fn_8030DA80".into(),
            evidence: serde_json::to_value(Rename {
                new: "GetTextureElement".into(),
                unit: "Texture.cpp".into(),
                method: "call-site".into(),
                tier: Tier::Confident,
                signal: None,
                off_spine: false,
            })
            .unwrap(),
        };
        let rename = rename_of(&candidate).unwrap();
        assert_eq!(rename.new, "GetTextureElement");
        assert_eq!(rename.tier, Tier::Confident);
    }

    #[test]
    fn a_candidate_with_no_rename_is_an_error_rather_than_a_default() {
        let candidate = Candidate::new("fn_1");
        assert!(rename_of(&candidate).unwrap_err().to_string().contains("Missing rename"));
    }
}
