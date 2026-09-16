//! The four methods that propose a name for a target symbol.
//!
//! Strongest first, by what each one actually observes:
//!
//! - **body-match** compares the two function bodies. It is the only method
//!   that looks at the function itself rather than its surroundings.
//! - **call-site** aligns the relocations inside a function whose name already
//!   agrees, which names whatever it calls — including in units with no source
//!   of their own, since a call site names its callee.
//! - **function-position** names a placeholder sitting between two agreeing
//!   names.
//! - **misplaced-name** asks the opposite question: whether a name the target
//!   already carries belongs to a different function.
//!
//! Where a body comparison and a position disagree, the position loses. A body
//! comparison and a call site both observe the function; a position observes
//! only its neighbours.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::derive::{
    body::{self, Ranked},
    objects::{Compiled, Function, is_derivable, is_usable_source_name},
    ordering,
};

/// How sure a proposal is, and therefore what a run will do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Safe to apply without review.
    Confident,
    /// Corroborated, but by one signal.
    Probable,
    /// Reported for a person to judge.
    Candidate,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confident => "confident",
            Self::Probable => "probable",
            Self::Candidate => "candidate",
        }
    }
}

/// What a method observed, which decides who wins when two disagree.
///
/// A body comparison and a call site both look at the function itself; a
/// position only looks at its neighbours, so when the two disagree the position
/// is the one that loses rather than the one that poisons the result.
fn strength(method: &str) -> u8 {
    match method {
        "function-position" => 1,
        _ => 2,
    }
}

/// One proposed rename, with everything that decided it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub old: String,
    pub new: String,
    pub unit: String,
    pub method: String,
    pub tier: Tier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub margin: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidates: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<usize>,
    /// How many functions in this unit already agreed by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchors: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub functions: Option<usize>,
    /// Whether a decided pairing sits off the unit's ordering run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub off_spine: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen_percent: Option<f32>,
    /// Misplaced-name findings only, from here down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contested: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_percent: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namesake_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_size: Option<u64>,
    /// Every unit that proposed this rename, filled in when they are reconciled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
}

impl Proposal {
    fn new(old: &str, new: &str, unit: &str, method: &str, tier: Tier) -> Self {
        Self {
            old: old.to_string(),
            new: new.to_string(),
            unit: unit.to_string(),
            method: method.to_string(),
            tier,
            signal: None,
            percent: None,
            margin: None,
            candidates: None,
            exact: None,
            anchors: None,
            functions: None,
            off_spine: None,
            chosen_percent: None,
            contested: None,
            reference_size: None,
            own_percent: None,
            carried_size: None,
            namesake_size: None,
            replacement_size: None,
            units: Vec::new(),
        }
    }

    pub fn strength(&self) -> u8 { strength(&self.method) }
}

/// Thresholds the body comparison is judged against.
///
/// Calibrated against agreement on a 45-unit sample. The margin does nearly all
/// the work: at a fixed margin of 15, raising the score floor from 0 to 90
/// discards a quarter of the results and moves precision by less than half a
/// point.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub size_ratio: f64,
    pub percent: f32,
    pub margin: f32,
    pub confident_percent: f32,
    pub confident_margin: f32,
    /// A lone candidate at this score needs no lead: the margin rule exists to
    /// separate two plausible readings of one body, and above this line there is
    /// only one reading. `CFishCloud`'s `__dt__CFishCloudModifier` scores 99.6
    /// against a field of other destructors topping out at 89.8 — a lead of 9.8
    /// that the margin rule rejects and that is nonetheless unambiguous.
    pub exact_percent: f32,
    /// Ordering can settle a pairing the body scores cannot, but only above the
    /// same floor; a poor match in the right place is still a poor match.
    pub order_percent: f32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            size_ratio: body::DEFAULT_SIZE_RATIO,
            percent: 70.0,
            margin: 15.0,
            confident_percent: 80.0,
            confident_margin: 30.0,
            exact_percent: body::EXACT_PERCENT,
            order_percent: 70.0,
        }
    }
}

/// A pairing of one list's position with another's.
pub type Pair = (usize, usize);

/// An alignment: every pairing, and the subset that matched by name.
pub type Alignment = (Vec<Pair>, BTreeSet<Pair>);

/// One candidate for an undecided target: where its source sits, and what the
/// body comparison thought of it.
type Candidate = (usize, (String, f32));

/// A target the scores could not settle: its name, its field of candidates, and
/// where each of those candidates sits.
type Undecided = (String, Ranked, Vec<Candidate>);

/// Index pairs of a longest common subsequence of two key lists.
fn common_subsequence(left: &[String], right: &[String]) -> Vec<(usize, usize)> {
    let (rows, columns) = (left.len(), right.len());
    let mut best = vec![vec![0usize; columns + 1]; rows + 1];
    for i in (0..rows).rev() {
        for j in (0..columns).rev() {
            best[i][j] = if left[i] == right[j] {
                best[i + 1][j + 1] + 1
            } else {
                best[i + 1][j].max(best[i][j + 1])
            };
        }
    }
    let mut pairs = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < rows && j < columns {
        if left[i] == right[j] {
            pairs.push((i, j));
            i += 1;
            j += 1;
        } else if best[i + 1][j] >= best[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    pairs
}

/// Pairs two ordered lists on shared names, filling equal-length gaps by
/// position.
///
/// Returns the pairs and the subset that matched *by name*. A gap whose two
/// sides differ in length is left unpaired: that is where the target version
/// genuinely restructured the code, and guessing across it is how a rename pass
/// starts inventing names.
pub fn align(left: &[String], right: &[String]) -> Alignment {
    // A placeholder must never anchor: it is unnamed on purpose, and two
    // unrelated `fn_` names comparing unequal is not the point — the point is
    // that it carries no evidence. Unique sentinels keep them out of the
    // subsequence entirely.
    let masked_left: Vec<String> = left
        .iter()
        .enumerate()
        .map(
            |(index, name)| {
                if is_usable_source_name(name) { name.clone() } else { format!("\0L{index}") }
            },
        )
        .collect();
    let masked_right: Vec<String> = right
        .iter()
        .enumerate()
        .map(|(index, name)| if is_derivable(name) { format!("\0R{index}") } else { name.clone() })
        .collect();
    let anchors = common_subsequence(&masked_left, &masked_right);

    let mut pairs = Vec::new();
    let (mut previous_i, mut previous_j) = (0usize, 0usize);
    for &(i, j) in anchors.iter().chain(std::iter::once(&(left.len(), right.len()))) {
        if i.saturating_sub(previous_i) == j.saturating_sub(previous_j)
            && i >= previous_i
            && j >= previous_j
        {
            pairs.extend((previous_i..i).zip(previous_j..j));
        }
        if i < left.len() {
            pairs.push((i, j));
        }
        previous_i = i + 1;
        previous_j = j + 1;
    }
    (pairs, anchors.into_iter().collect())
}

/// Renames implied by one unit's source object against its extracted object.
pub fn positional(source: &Compiled, target: &Compiled, unit: &str) -> Vec<Proposal> {
    let left: Vec<String> = source.functions.iter().map(|f| f.name.clone()).collect();
    let right: Vec<String> = target.functions.iter().map(|f| f.name.clone()).collect();
    let (pairs, anchors) = align(&left, &right);

    // A unit where nothing agrees is not evidence of anything: every pairing in
    // it would rest on position alone, so a whole file would be named on one
    // coincidence repeated per function.
    if anchors.is_empty() {
        return Vec::new();
    }
    let (anchor_count, function_count) = (anchors.len(), target.functions.len());
    let mut proposals = Vec::new();

    for (i, j) in pairs {
        let (defined, original) = (&source.functions[i], &target.functions[j]);
        let anchored = anchors.contains(&(i, j));
        if !anchored && is_usable_source_name(&defined.name) && is_derivable(&original.name) {
            let mut proposal = Proposal::new(
                &original.name,
                &defined.name,
                unit,
                "function-position",
                // Only the surrounding anchors place this function, so a size
                // agreement is the one independent corroboration available.
                if defined.size == original.size { Tier::Probable } else { Tier::Candidate },
            );
            proposal.anchors = Some(anchor_count);
            proposal.functions = Some(function_count);
            proposals.push(proposal);
        }
        // Relocations are only comparable once the two functions are known to
        // be the same function; an unanchored pairing is too weak to mine call
        // sites from, because every name it yields would rest on a guess.
        if !anchored {
            continue;
        }
        let outgoing: Vec<String> = defined.relocations.iter().map(|r| r.target.clone()).collect();
        let existing: Vec<String> = original.relocations.iter().map(|r| r.target.clone()).collect();
        let (calls, call_anchors) = align(&outgoing, &existing);
        for (x, y) in calls {
            let (from, to) = (&defined.relocations[x], &original.relocations[y]);
            if call_anchors.contains(&(x, y)) || to.kind != from.kind {
                continue;
            }
            if !is_derivable(&to.target) || !is_usable_source_name(&from.target) {
                continue;
            }
            let mut proposal = Proposal::new(
                &to.target,
                &from.target,
                unit,
                "call-site",
                // Every reference accounted for on both sides is a stronger
                // statement than an alignment with something left over.
                if defined.relocations.len() == original.relocations.len() {
                    Tier::Confident
                } else {
                    Tier::Probable
                },
            );
            proposal.anchors = Some(anchor_count);
            proposal.functions = Some(function_count);
            proposals.push(proposal);
        }
    }
    proposals
}

/// Whether the scores alone settle a pairing, and how confidently.
///
/// Two rules, because a score field has two shapes that admit one reading. The
/// usual one is a clear lead over the runner-up. The other is a single
/// candidate so close to exact that the rest of the field is not competing with
/// it at all — the case a fixed margin misjudges, because it measures the
/// runner-up rather than the winner.
fn decide(best: &Ranked, limits: &Limits) -> Option<(&'static str, Tier)> {
    if best.percent >= limits.exact_percent && best.exact == 1 {
        return Some(("sole-exact", Tier::Confident));
    }
    if best.percent < limits.percent || best.margin < limits.margin {
        return None;
    }
    let confident =
        best.percent >= limits.confident_percent && best.margin >= limits.confident_margin;
    Some(("margin", if confident { Tier::Confident } else { Tier::Probable }))
}

fn round2(value: f32) -> f32 { (value * 100.0).round() / 100.0 }

fn body_entry(
    unit: &str,
    old: &str,
    new: &str,
    signal: &str,
    tier: Tier,
    best: &Ranked,
) -> Proposal {
    let mut proposal = Proposal::new(old, new, unit, "body-match", tier);
    proposal.signal = Some(signal.to_string());
    proposal.percent = Some(round2(best.percent));
    proposal.margin = Some(round2(best.margin));
    proposal.candidates = Some(best.candidates);
    proposal.exact = Some(best.exact);
    proposal
}

/// Renames implied by comparing function bodies.
///
/// Position says where a function sits between its neighbours; this says what
/// the function *is*. The target version inlines differently enough that
/// ordering alone misplaces functions, so where the two disagree this is the
/// better evidence — but only when one candidate stands clearly apart. A high
/// score with no lead over the runner-up is the shape a wrong name takes, and a
/// field of uniformly poor scores means the counterpart was inlined away and
/// there is nothing here to name.
///
/// What the scores settle then places what they do not. The settled pairings
/// and the functions already agreeing by name form an increasing run through
/// the two objects, and a pairing the scores left ambiguous is believed when it
/// takes its place in that run and no other ambiguous pairing wants the same
/// seat.
pub fn by_body(
    unit: &str,
    target: &Compiled,
    source: &Compiled,
    limits: &Limits,
) -> Result<Vec<Proposal>> {
    let unnamed: Vec<&Function> =
        target.functions.iter().filter(|f| is_derivable(&f.name)).collect();
    let named: Vec<&Function> =
        source.functions.iter().filter(|f| is_usable_source_name(&f.name)).collect();
    if unnamed.is_empty() || named.is_empty() {
        return Ok(Vec::new());
    }
    let scores = body::score_matrix(target, source, &unnamed, &named, limits.size_ratio)?;
    let ranked = body::rank(&scores, limits.exact_percent);

    let at: BTreeMap<&str, usize> =
        target.functions.iter().enumerate().map(|(i, f)| (f.name.as_str(), i)).collect();
    let source_at: BTreeMap<&str, usize> =
        source.functions.iter().enumerate().map(|(i, f)| (f.name.as_str(), i)).collect();

    // A function both objects already call by the same name is a pairing
    // nothing has to derive, so it anchors the run for free.
    let mut decided: Vec<(usize, usize)> = target
        .functions
        .iter()
        .filter(|f| is_usable_source_name(&f.name))
        .filter_map(|f| Some((at[f.name.as_str()], *source_at.get(f.name.as_str())?)))
        .collect();

    let mut proposals: Vec<Proposal> = Vec::new();
    let mut undecided: Vec<(usize, Undecided)> = Vec::new();
    for (old, best) in &ranked {
        match decide(best, limits) {
            Some((signal, tier)) => {
                decided.push((at[old.as_str()], source_at[best.name.as_str()]));
                proposals.push(body_entry(unit, old, &best.name, signal, tier, best));
            }
            None => {
                let candidates: Vec<Candidate> = best
                    .order
                    .iter()
                    .filter(|(_, percent)| *percent >= limits.order_percent)
                    .filter_map(|(name, percent)| {
                        Some((*source_at.get(name.as_str())?, (name.clone(), *percent)))
                    })
                    .collect();
                if !candidates.is_empty() {
                    undecided.push((at[old.as_str()], (old.clone(), best.clone(), candidates)));
                }
            }
        }
    }

    let backbone = ordering::spine(&decided);
    let on_spine: BTreeSet<(usize, usize)> = backbone.iter().copied().collect();
    for proposal in &mut proposals {
        let pair = (at[proposal.old.as_str()], source_at[proposal.new.as_str()]);
        proposal.off_spine = Some(!on_spine.contains(&pair));
    }

    let pending: Vec<(usize, Vec<Candidate>)> =
        undecided.iter().map(|(position, payload)| (*position, payload.2.clone())).collect();
    let carried: BTreeMap<usize, &Undecided> =
        undecided.iter().map(|(position, payload)| (*position, payload)).collect();
    for (position, _, (name, percent)) in ordering::rescue(&pending, &backbone) {
        let (old, best, _) = carried[&position];
        let mut proposal = body_entry(unit, old, &name, "order", Tier::Probable, best);
        proposal.off_spine = Some(false);
        proposal.chosen_percent = Some(round2(percent));
        proposals.push(proposal);
    }
    Ok(proposals)
}

/// How far a function may sit from the size of the name it carries before that
/// name is worth re-examining.
///
/// Wider than the body comparison's ratio, because this is looking for a name
/// on the wrong function rather than a version's inlining drift, and a false
/// suspicion here costs one comparison while a missed one leaves a wrong name
/// in place.
pub const SUSPECT_RATIO: f64 = 2.0;

/// Names the target carries that the source says belong to another function.
///
/// Everything else here names functions that have no name. This asks the
/// opposite question, because a wrong name does more damage than a missing one:
/// it is the answer to the question the rest of the tool is asking, so it
/// silently blocks the correct rename and reports only that the name was taken.
///
/// The matcher places names by propagating them between versions, so the way
/// this goes wrong is a shift: two adjacent functions, the first named with the
/// second's name. The size disagreement is the cheap tell and is only a
/// suspicion; the body comparison decides. A correction is proposed only when
/// one source function explains the address near-exactly, alone, and at a size
/// that fits — a high bar, because unlike every other method this one overwrites
/// a name somebody already has reason to trust.
///
/// `reference` is another version's symbol sizes, and it is what keeps this
/// honest. The source object is only authoritative about a name's body when the
/// unit actually matches; where it does not, a function the source failed to
/// inline is indistinguishable from a name on the wrong address. If the
/// reference version carries the same name at a size the target address agrees
/// with, then two versions place the name here and only our unbuilt source
/// objects disagree, so the finding is marked contested and demoted — reported
/// for a person, never renamed automatically.
pub fn misplaced(
    unit: &str,
    target: &Compiled,
    source: &Compiled,
    limits: &Limits,
    reference: Option<&BTreeMap<String, u64>>,
) -> Result<Vec<Proposal>> {
    let defined: BTreeMap<&str, &Function> =
        source.functions.iter().map(|f| (f.name.as_str(), f)).collect();
    let present: BTreeSet<&str> = target.functions.iter().map(|f| f.name.as_str()).collect();

    let suspects: Vec<&Function> = target
        .functions
        .iter()
        .filter(|function| {
            let Some(namesake) = defined.get(function.name.as_str()) else { return false };
            if !is_usable_source_name(&function.name) || function.size == 0 || namesake.size == 0 {
                return false;
            }
            let (low, high) = (function.size.min(namesake.size), function.size.max(namesake.size));
            high as f64 / low as f64 > SUSPECT_RATIO
        })
        .collect();
    if suspects.is_empty() {
        return Ok(Vec::new());
    }

    let named: Vec<&Function> =
        source.functions.iter().filter(|f| is_usable_source_name(&f.name)).collect();
    // A generous ratio, so the name the address currently carries is scored too
    // and the report can say what it lost as well as what it gained.
    let scores = body::score_matrix(
        target,
        source,
        &suspects,
        &named,
        limits.size_ratio.max(SUSPECT_RATIO * 2.0),
    )?;

    let mut found = Vec::new();
    for (old, best) in body::rank(&scores, limits.exact_percent) {
        if best.percent < limits.exact_percent || best.exact != 1 {
            continue;
        }
        // Either the name is where it belongs, or the name this would free is
        // already on another function here and the two would have to trade
        // places — a swap, which no single rename can express.
        if best.name == old || present.contains(best.name.as_str()) {
            continue;
        }
        let Some(carrier) = target.function(&old) else { continue };
        let Some(replacement) = defined.get(best.name.as_str()) else { continue };
        if replacement.size == 0 || carrier.size == 0 {
            continue;
        }
        let (low, high) = (carrier.size.min(replacement.size), carrier.size.max(replacement.size));
        if high as f64 / low as f64 > limits.size_ratio {
            continue;
        }
        // The other version's opinion on where this name lives. It knows
        // nothing about our source, so when it agrees with the address the
        // disagreement is ours to fix in the source, not the symbol file's.
        let elsewhere = reference.and_then(|sizes| sizes.get(&old)).copied();
        let contested = elsewhere.is_some_and(|size| {
            size > 0
                && carrier.size > 0
                && size.max(carrier.size) as f64 / size.min(carrier.size) as f64
                    <= limits.size_ratio
        });

        let mut proposal = Proposal::new(
            &old,
            &best.name,
            unit,
            "misplaced-name",
            if contested { Tier::Candidate } else { Tier::Confident },
        );
        proposal.signal = Some("misplaced".to_string());
        proposal.contested = Some(contested);
        proposal.reference_size = elsewhere;
        proposal.percent = Some(round2(best.percent));
        proposal.margin = Some(round2(best.margin));
        proposal.candidates = Some(best.candidates);
        proposal.exact = Some(best.exact);
        // None, not zero: a namesake too far off in size to be scored at all is
        // a different statement from one that scored nothing.
        proposal.own_percent =
            best.order.iter().find(|(name, _)| name == &old).map(|(_, p)| round2(*p));
        proposal.carried_size = Some(carrier.size);
        proposal.namesake_size = defined.get(old.as_str()).map(|f| f.size);
        proposal.replacement_size = Some(replacement.size);
        found.push(proposal);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> { values.iter().map(|v| (*v).to_string()).collect() }

    #[test]
    fn functions_agreeing_by_name_anchor_the_alignment() {
        let left = names(&["A", "B", "C"]);
        let right = names(&["A", "fn_1", "C"]);
        let (pairs, anchors) = align(&left, &right);
        assert_eq!(anchors, BTreeSet::from([(0, 0), (2, 2)]));
        assert!(pairs.contains(&(1, 1)), "the equal-length gap is filled by position");
    }

    #[test]
    fn a_gap_whose_sides_differ_in_length_is_left_unpaired() {
        let left = names(&["A", "B", "C", "D"]);
        let right = names(&["A", "fn_1", "D"]);
        let (pairs, _) = align(&left, &right);
        // B and C share one target slot; neither is paired with it.
        assert!(!pairs.contains(&(1, 1)), "{pairs:?}");
        assert!(!pairs.contains(&(2, 1)), "{pairs:?}");
    }

    #[test]
    fn two_placeholders_never_anchor_each_other() {
        let left = names(&["fn_1", "B"]);
        let right = names(&["fn_1", "B"]);
        let (_, anchors) = align(&left, &right);
        // Only B agrees: fn_1 is unnamed on purpose on both sides.
        assert_eq!(anchors, BTreeSet::from([(1, 1)]));
    }

    #[test]
    fn a_compiler_local_label_never_anchors_either() {
        let left = names(&["@468", "B"]);
        let right = names(&["@468", "B"]);
        let (_, anchors) = align(&left, &right);
        assert_eq!(anchors, BTreeSet::from([(1, 1)]));
    }

    fn ranked(order: &[(&str, f32)]) -> Ranked {
        let order: Vec<(String, f32)> = order.iter().map(|(n, p)| ((*n).to_string(), *p)).collect();
        let (name, percent) = order[0].clone();
        let runner_up = order.get(1).map(|(_, p)| *p).unwrap_or(0.0);
        Ranked {
            name,
            percent,
            margin: percent - runner_up,
            candidates: order.len(),
            exact: order.iter().filter(|(_, p)| *p >= 99.0).count(),
            order,
        }
    }

    #[test]
    fn a_clear_lead_settles_a_pairing() {
        let limits = Limits::default();
        let best = ranked(&[("A", 95.0), ("B", 50.0)]);
        assert_eq!(decide(&best, &limits), Some(("margin", Tier::Confident)));
    }

    #[test]
    fn a_narrow_lead_is_probable_rather_than_confident() {
        let limits = Limits::default();
        let best = ranked(&[("A", 75.0), ("B", 55.0)]);
        assert_eq!(decide(&best, &limits), Some(("margin", Tier::Probable)));
    }

    #[test]
    fn a_lone_near_exact_candidate_needs_no_lead() {
        // CFishCloud's destructor: 99.6 against a field topping out at 89.8, a
        // lead the margin rule rejects and that is nonetheless unambiguous.
        let limits = Limits::default();
        let best = ranked(&[("__dt__CFishCloudModifier", 99.6), ("__dt__COther", 89.8)]);
        assert_eq!(decide(&best, &limits), Some(("sole-exact", Tier::Confident)));
    }

    #[test]
    fn two_near_exact_candidates_settle_nothing() {
        let limits = Limits::default();
        let best = ranked(&[("A", 99.6), ("B", 99.2)]);
        assert_eq!(decide(&best, &limits), None);
    }

    #[test]
    fn a_field_of_poor_scores_settles_nothing() {
        let limits = Limits::default();
        assert_eq!(decide(&ranked(&[("A", 40.0), ("B", 10.0)]), &limits), None);
    }

    #[test]
    fn a_high_score_with_no_lead_settles_nothing() {
        let limits = Limits::default();
        assert_eq!(decide(&ranked(&[("A", 90.0), ("B", 88.0)]), &limits), None);
    }

    #[test]
    fn a_position_is_weaker_evidence_than_a_body() {
        assert!(strength("function-position") < strength("body-match"));
        assert_eq!(strength("call-site"), strength("body-match"));
        assert_eq!(strength("misplaced-name"), strength("body-match"));
    }
}
