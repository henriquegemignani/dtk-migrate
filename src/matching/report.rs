//! The JSON report `match` writes, and the tier accounting behind it.
//!
//! The report is the tool's record of what it believed and why: every match
//! carries the evidence class that decided it, the runner-up it beat, and --
//! under `--validate` -- whether it agreed with a name the target already had.
//! Nothing here decides anything; it renders what `matching` concluded.

use std::collections::{BTreeMap, HashSet};

use serde::Serialize;
use tracing::info;

use crate::analysis::{
    data_matching::DataMatch,
    matching::{MatchResult, MatchTarget, MatchTier},
};

#[derive(Serialize)]
pub struct Report {
    pub source: String,
    pub target: String,
    pub summary: Summary,
    pub matches: Vec<ReportMatch>,
    pub unmatched_source: Vec<String>,
    pub unmatched_target: Vec<String>,
}

#[derive(Serialize)]
pub struct Summary {
    pub source_functions: usize,
    pub target_functions: usize,
    pub matched: usize,
    /// Matches that would give a currently-unnamed target function a name.
    pub renames: usize,
    /// Of those, the ones safe to apply without review.
    pub confident_renames: usize,
    /// Of those, the ones needing review before use.
    pub candidate_renames: usize,
    pub by_tier: Vec<(String, usize)>,
    pub by_method: Vec<(String, usize)>,
    pub rounds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<Validation>,
}

/// Accuracy measured against target functions whose real name is already known.
#[derive(Serialize)]
pub struct Validation {
    pub checked: usize,
    pub correct: usize,
    pub incorrect: usize,
    pub precision: f32,
    /// Named target functions the matcher left unmatched.
    pub missed: usize,
    pub recall: f32,
    /// The same numbers split by tier. `confident` is the one that has to hold
    /// up, since it's the only tier applied without review.
    pub by_tier: Vec<TierAccuracy>,
}

#[derive(Serialize)]
pub struct TierAccuracy {
    pub tier: String,
    pub checked: usize,
    pub correct: usize,
    pub incorrect: usize,
    pub precision: f32,
}

#[derive(Serialize)]
pub struct ReportMatch {
    pub source_name: String,
    /// Whether the source symbol is marked local scope, e.g. a per-translation-unit
    /// template instantiation. Carried onto a rename so the target gets the
    /// same scope, rather than every duplicate ending up global.
    pub source_local: bool,
    #[serde(serialize_with = "hex")]
    pub source_address: u32,
    pub target_name: String,
    #[serde(serialize_with = "hex")]
    pub target_address: u32,
    #[serde(serialize_with = "tier_name")]
    pub tier: MatchTier,
    pub method: &'static str,
    pub confidence: f32,
    pub evidence: u32,
    pub round: u32,
    /// The strongest name that lost to this one, when something competed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative: Option<ReportAlternative>,
    /// Whether applying this match would name a previously-unnamed function.
    #[serde(skip)]
    pub renames: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<&'static str>,
}

#[derive(Serialize)]
pub struct ReportAlternative {
    pub name: String,
    pub relative_score: f32,
}

fn hex<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    serializer.serialize_str(&format!("{value:#010X}"))
}

impl Report {
    pub fn build(
        source: &MatchTarget,
        target: &MatchTarget,
        result: &MatchResult,
        validate: bool,
    ) -> Self {
        let mut matches = Vec::with_capacity(result.matches.len());
        for m in &result.matches {
            let source_name = source.symbol_name(m.source).to_string();
            let target_name = target.symbol_name(m.target).to_string();
            let will_rename = source.is_named(m.source) && !target.is_named(m.target);

            // Only target functions that already carry a real name can be
            // scored, and only then against a source that also has one.
            let verdict = if validate && source.is_named(m.source) && target.is_named(m.target) {
                Some(if source_name == target_name { "correct" } else { "incorrect" })
            } else {
                None
            };

            matches.push(ReportMatch {
                source_name,
                source_local: source.is_local(m.source),
                source_address: source.graph.node(m.source).address,
                target_name,
                target_address: target.graph.node(m.target).address,
                tier: m.tier(),
                method: m.method.as_str(),
                confidence: (m.confidence * 1000.0).round() / 1000.0,
                evidence: m.evidence,
                round: m.round,
                alternative: m.runner_up.map(|a| ReportAlternative {
                    name: source.symbol_name(a.source).to_string(),
                    relative_score: (a.relative_score * 1000.0).round() / 1000.0,
                }),
                renames: will_rename,
                verdict,
            });
        }
        matches.sort_by(|a, b| {
            b.confidence.total_cmp(&a.confidence).then(a.target_address.cmp(&b.target_address))
        });

        let unmatched_source = unmatched(source, &result.source_to_target);
        let unmatched_target = unmatched(target, &result.target_to_source);

        // Tallied from the finished rows rather than accumulated alongside
        // them, so there's one source of truth for what a match's tier and
        // rename status are.
        let mut tier_counts: BTreeMap<MatchTier, usize> = BTreeMap::new();
        let mut method_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut rename_tiers: BTreeMap<MatchTier, usize> = BTreeMap::new();
        for m in &matches {
            *tier_counts.entry(m.tier).or_default() += 1;
            *method_counts.entry(m.method).or_default() += 1;
            if m.renames {
                *rename_tiers.entry(m.tier).or_default() += 1;
            }
        }
        let renames: usize = rename_tiers.values().sum();

        let validation = validate.then(|| {
            let checked = matches.iter().filter(|m| m.verdict.is_some()).count();
            let correct = matches.iter().filter(|m| m.verdict == Some("correct")).count();

            // A named target function left unmatched is a miss only if the source
            // actually had that name to give.
            let source_names: HashSet<&str> = (0..source.graph.len() as u32)
                .filter(|&node| source.is_named(node))
                .map(|node| source.symbol_name(node))
                .collect();
            let missed = result
                .target_to_source
                .iter()
                .enumerate()
                .filter(|(node, matched)| {
                    let node = *node as u32;
                    matched.is_none()
                        && target.is_named(node)
                        && source_names.contains(target.symbol_name(node))
                })
                .count();

            // Scored per tier, so the tier boundaries can be justified from
            // data rather than asserted.
            let mut tier_scores: BTreeMap<MatchTier, (usize, usize)> = BTreeMap::new();
            for m in &matches {
                let Some(verdict) = m.verdict else { continue };
                let entry = tier_scores.entry(m.tier).or_default();
                entry.0 += 1;
                if verdict == "correct" {
                    entry.1 += 1;
                }
            }

            Validation {
                checked,
                correct,
                incorrect: checked - correct,
                precision: if checked > 0 { correct as f32 / checked as f32 } else { 0.0 },
                missed,
                recall: if checked + missed > 0 {
                    correct as f32 / (checked + missed) as f32
                } else {
                    0.0
                },
                by_tier: tier_scores
                    .iter()
                    .map(|(tier, &(checked, correct))| TierAccuracy {
                        tier: tier.as_str().to_string(),
                        checked,
                        correct,
                        incorrect: checked - correct,
                        precision: if checked > 0 { correct as f32 / checked as f32 } else { 0.0 },
                    })
                    .collect(),
            }
        });

        Report {
            source: source.name.clone(),
            target: target.name.clone(),
            summary: Summary {
                source_functions: source.graph.len(),
                target_functions: target.graph.len(),
                matched: result.matches.len(),
                renames,
                confident_renames: rename_tiers.get(&MatchTier::Confident).copied().unwrap_or(0),
                candidate_renames: rename_tiers
                    .iter()
                    .filter(|(tier, _)| **tier != MatchTier::Confident)
                    .map(|(_, count)| count)
                    .sum(),
                by_tier: tier_counts
                    .iter()
                    .map(|(tier, count)| (tier.as_str().to_string(), *count))
                    .collect(),
                by_method: method_counts
                    .iter()
                    .map(|(method, count)| (method.to_string(), *count))
                    .collect(),
                rounds: result.rounds,
                validation,
            },
            matches,
            unmatched_source,
            unmatched_target,
        }
    }

    /// Matches that would give a currently-unnamed target function a name.
    pub fn renameable(&self) -> impl Iterator<Item = &ReportMatch> {
        self.matches.iter().filter(|m| m.renames)
    }

    pub fn print_summary(&self) {
        let s = &self.summary;
        info!("Matched {}/{} target functions", s.matched, s.target_functions);
        for (method, count) in &s.by_method {
            info!("  {:>12}: {}", method, count);
        }
        for (tier, count) in &s.by_tier {
            info!("  {:>12}: {}", tier, count);
        }
        info!(
            "{} target functions would gain a name: {} confident, {} needing review",
            s.renames, s.confident_renames, s.candidate_renames
        );
        if let Some(v) = &s.validation {
            info!(
                "Validation: {}/{} correct ({:.2}% precision), {} missed ({:.2}% recall)",
                v.correct,
                v.checked,
                v.precision * 100.0,
                v.missed,
                v.recall * 100.0
            );
            for t in &v.by_tier {
                info!(
                    "  {:>12}: {}/{} correct ({:.2}%), {} wrong",
                    t.tier,
                    t.correct,
                    t.checked,
                    t.precision * 100.0,
                    t.incorrect
                );
            }
        }
    }
}

fn tier_name<S>(tier: &MatchTier, serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    serializer.serialize_str(tier.as_str())
}

fn unmatched(target: &MatchTarget, map: &[Option<u32>]) -> Vec<String> {
    map.iter()
        .enumerate()
        .filter(|(_, matched)| matched.is_none())
        .map(|(node, _)| target.symbol_name(node as u32).to_string())
        .collect()
}

/// Data matches that would give a currently-unnamed target symbol a name.
pub fn renameable_data<'a>(
    source: &MatchTarget,
    target: &MatchTarget,
    data_matches: &'a [DataMatch],
) -> Vec<&'a DataMatch> {
    data_matches
        .iter()
        .filter(|dm| source.is_named_at(dm.source) && !target.is_named_at(dm.target))
        .collect()
}
