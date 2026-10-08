//! Scoring a proposed function pairing by comparing the two bodies.
//!
//! objdiff pairs symbols **by name**, so a proposal that `fn_8030DA80` is some
//! named source function is invisible to it: the two sides have different names
//! and never get paired at all. Every placeholder function in an ordinary
//! comparison therefore carries no match percent. That is a property of the
//! question, not an oversight — the measurement does not exist until the rename
//! has been made.
//!
//! objdiff will, however, accept an explicit mapping. Telling it "compare this
//! placeholder against that source function" makes the pair scorable without
//! renaming anything, without rebuilding, and without writing to the project.
//!
//! One diff reports a percent for every symbol in the object, so a whole
//! permutation of pairings costs a single comparison. Packing candidate
//! pairings into permutations covers the full cross product in about as many
//! comparisons as one target has candidates, rather than one per pairing.

use std::collections::BTreeMap;

use anyhow::Result;
use objdiff_core::diff::{DiffObjConfig, MappingConfig, diff_objs};

use crate::derive::objects::{Compiled, Function};

/// How far two sizes may differ before a pairing is not worth scoring.
///
/// The target version inlines differently, so sizes move. The filter only has
/// to be tight enough to keep the cross product affordable without discarding a
/// real counterpart, which is why it is a ratio and a generous one.
pub const DEFAULT_SIZE_RATIO: f64 = 2.5;

/// What the field of candidates for one target function looks like.
#[derive(Debug, Clone)]
pub struct Ranked {
    /// The best-scoring source name.
    pub name: String,
    pub percent: f32,
    /// How far ahead of the runner-up it is.
    pub margin: f32,
    pub candidates: usize,
    /// How many candidates reached the near-exact line.
    pub exact: usize,
    /// Every candidate, best first.
    pub order: Vec<(String, f32)>,
}

/// A score this high means the two bodies differ by a few instructions at most,
/// which is a different kind of statement from a merely good score: the pairing
/// is either right, or the counterpart is a near-duplicate of it. Above this
/// line the useful question is not how far ahead the best candidate is, but how
/// many candidates reach it at all.
pub const EXACT_PERCENT: f32 = 99.0;

/// Pairings worth scoring, filtered by how far the two sizes may differ.
pub fn candidate_pairs<'a>(
    targets: &'a [&'a Function],
    sources: &'a [&'a Function],
    size_ratio: f64,
) -> Vec<(&'a str, &'a str)> {
    let mut pairs = Vec::new();
    for target in targets {
        for source in sources {
            if target.size == 0 || source.size == 0 {
                continue;
            }
            let (low, high) = (target.size.min(source.size), target.size.max(source.size));
            if high as f64 / low as f64 > size_ratio {
                continue;
            }
            pairs.push((target.name.as_str(), source.name.as_str()));
        }
    }
    pairs
}

/// Packs pairings into rounds that use each symbol at most once.
///
/// A mapping has to be a one-to-one correspondence for one comparison to mean
/// anything, so a target with five candidates needs five rounds — but every
/// other target can be scored in each of those same rounds for free.
pub fn permutations<'a>(pairs: &[(&'a str, &'a str)]) -> Vec<Vec<(&'a str, &'a str)>> {
    let mut remaining: Vec<(&str, &str)> = pairs.to_vec();
    let mut rounds = Vec::new();
    while !remaining.is_empty() {
        let mut targets = BTreeMap::new();
        let mut sources = BTreeMap::new();
        let mut current = Vec::new();
        let mut rest = Vec::new();
        for (target, source) in remaining {
            if targets.contains_key(target) || sources.contains_key(source) {
                rest.push((target, source));
                continue;
            }
            targets.insert(target, ());
            sources.insert(source, ());
            current.push((target, source));
        }
        rounds.push(current);
        remaining = rest;
    }
    rounds
}

/// A match percent for every plausible pairing, keyed by target then source.
pub fn score_matrix(
    target: &Compiled,
    source: &Compiled,
    targets: &[&Function],
    sources: &[&Function],
    size_ratio: f64,
) -> Result<BTreeMap<String, BTreeMap<String, f32>>> {
    let pairs = candidate_pairs(targets, sources, size_ratio);
    score_pairs(target, source, &pairs)
}

/// Score an explicit candidate set, including graph-supported pairs whose
/// sizes differ too much for the ordinary body-search filter.
pub fn score_pairs(
    target: &Compiled,
    source: &Compiled,
    pairs: &[(&str, &str)],
) -> Result<BTreeMap<String, BTreeMap<String, f32>>> {
    let mut scores: BTreeMap<String, BTreeMap<String, f32>> = BTreeMap::new();
    if pairs.is_empty() {
        return Ok(scores);
    }
    let config = DiffObjConfig::default();
    for round in permutations(pairs) {
        let mapping = MappingConfig {
            // objdiff's "left" is the object being explained, which here is the
            // one carrying the placeholder names.
            mappings: round
                .iter()
                .map(|(target, source)| ((*target).to_string(), (*source).to_string()))
                .collect(),
            ..Default::default()
        };
        let result =
            diff_objs(Some(&target.object), Some(&source.object), None, &config, &mapping)?;
        let Some(left) = result.left else { continue };
        for (index, diff) in left.symbols.iter().enumerate() {
            let Some(percent) = diff.match_percent else { continue };
            let Some(symbol) = target.object.symbols.get(index) else { continue };
            let Some((_, paired)) = round.iter().find(|(name, _)| *name == symbol.name) else {
                continue;
            };
            scores.entry(symbol.name.clone()).or_default().insert((*paired).to_string(), percent);
        }
    }
    Ok(scores)
}

/// The best candidate for each target, its lead over the runner-up, and the
/// field behind it.
pub fn rank(
    scores: &BTreeMap<String, BTreeMap<String, f32>>,
    exact_percent: f32,
) -> BTreeMap<String, Ranked> {
    let mut ranked = BTreeMap::new();
    for (target, candidates) in scores {
        if candidates.is_empty() {
            continue;
        }
        let mut order: Vec<(String, f32)> =
            candidates.iter().map(|(name, percent)| (name.clone(), *percent)).collect();
        // Best first; ties broken by name so a run is reproducible.
        order.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let (name, percent) = order[0].clone();
        let runner_up = order.get(1).map(|(_, value)| *value).unwrap_or(0.0);
        ranked.insert(target.clone(), Ranked {
            name,
            percent,
            margin: percent - runner_up,
            candidates: order.len(),
            exact: order.iter().filter(|(_, value)| *value >= exact_percent).count(),
            order,
        });
    }
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, size: u64) -> Function {
        Function { name: name.into(), address: 0x1000, size, relocations: Vec::new() }
    }

    #[test]
    fn sizes_too_far_apart_are_not_worth_scoring() {
        let targets = [function("fn_1", 100)];
        let sources = [function("Small", 10), function("Close", 120)];
        let targets: Vec<&Function> = targets.iter().collect();
        let sources: Vec<&Function> = sources.iter().collect();
        let pairs = candidate_pairs(&targets, &sources, DEFAULT_SIZE_RATIO);
        assert_eq!(pairs, [("fn_1", "Close")]);
    }

    #[test]
    fn a_zero_sized_function_is_never_paired() {
        let targets = [function("fn_1", 0)];
        let sources = [function("Real", 40)];
        let targets: Vec<&Function> = targets.iter().collect();
        let sources: Vec<&Function> = sources.iter().collect();
        assert!(candidate_pairs(&targets, &sources, DEFAULT_SIZE_RATIO).is_empty());
    }

    #[test]
    fn each_round_uses_every_symbol_at_most_once() {
        let pairs = [("a", "x"), ("a", "y"), ("b", "x"), ("b", "y")];
        let rounds = permutations(&pairs);
        for round in &rounds {
            let targets: Vec<&str> = round.iter().map(|(t, _)| *t).collect();
            let sources: Vec<&str> = round.iter().map(|(_, s)| *s).collect();
            assert_eq!(
                targets.len(),
                targets.iter().collect::<std::collections::BTreeSet<_>>().len()
            );
            assert_eq!(
                sources.len(),
                sources.iter().collect::<std::collections::BTreeSet<_>>().len()
            );
        }
        // Two candidates each: two rounds cover the whole cross product.
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds.iter().map(Vec::len).sum::<usize>(), 4);
    }

    #[test]
    fn a_clear_winner_gets_the_margin_over_the_runner_up() {
        let scores = BTreeMap::from([(
            "fn_1".to_string(),
            BTreeMap::from([("A".to_string(), 95.0), ("B".to_string(), 60.0)]),
        )]);
        let ranked = rank(&scores, EXACT_PERCENT);
        let best = &ranked["fn_1"];
        assert_eq!(best.name, "A");
        assert_eq!(best.percent, 95.0);
        assert_eq!(best.margin, 35.0);
        assert_eq!(best.candidates, 2);
        assert_eq!(best.exact, 0);
    }

    #[test]
    fn a_lone_candidate_leads_by_its_whole_score() {
        let scores =
            BTreeMap::from([("fn_1".to_string(), BTreeMap::from([("A".to_string(), 99.6)]))]);
        let best = &rank(&scores, EXACT_PERCENT)["fn_1"];
        assert_eq!(best.margin, 99.6);
        assert_eq!(best.exact, 1);
    }

    #[test]
    fn two_near_exact_candidates_are_both_counted() {
        let scores = BTreeMap::from([(
            "fn_1".to_string(),
            BTreeMap::from([("A".to_string(), 99.5), ("B".to_string(), 99.2)]),
        )]);
        let best = &rank(&scores, EXACT_PERCENT)["fn_1"];
        assert_eq!(best.exact, 2, "a near-duplicate is exactly what this has to catch");
    }
}
