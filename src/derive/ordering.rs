//! Corroborating a function pairing with the order the two objects define it in.
//!
//! A compiler emits functions in roughly the order the source declares them, so
//! the pairings inside one unit mostly form an increasing run: the n-th unnamed
//! target function answers to a source function further down than the
//! (n-1)-th did. That run is a second, independent signal from the body
//! comparison, and it is at its most useful exactly where the body comparison
//! is weakest — a pair of near-identical functions like `RemoveRepulsor` and
//! `RemoveAttractor`, which score within a tenth of a point of each other on
//! both targets, and which only one assignment puts in order.
//!
//! The run corroborates and never vetoes. Real units reorder: a destructor the
//! target emits first can live near the end of the source object, and two
//! template instantiations can swap. Those pairings are decided by their bodies
//! and stay decided; they are merely reported as sitting off the run, because a
//! unit that reorders is a unit where a body comparison has the least help.

use std::collections::BTreeSet;

/// Indices of a longest strictly increasing subsequence.
pub fn longest_increasing(values: &[usize]) -> Vec<usize> {
    let mut best: Vec<usize> = Vec::new();
    let mut previous: Vec<isize> = vec![-1; values.len()];
    for (index, value) in values.iter().enumerate() {
        // The first position whose tail value is not below this one.
        let mut low = 0;
        let mut high = best.len();
        while low < high {
            let middle = (low + high) / 2;
            if values[best[middle]] < *value {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        previous[index] = if low > 0 { best[low - 1] as isize } else { -1 };
        if low == best.len() {
            best.push(index);
        } else {
            best[low] = index;
        }
    }
    let mut positions = Vec::new();
    let mut cursor = best.last().map(|last| *last as isize).unwrap_or(-1);
    while cursor >= 0 {
        positions.push(cursor as usize);
        cursor = previous[cursor as usize];
    }
    positions.reverse();
    positions
}

/// A `(target position, source position)` pairing inside one unit.
pub type Pair = (usize, usize);

/// The order-consistent backbone of a unit's decided pairings.
///
/// The result is the subset that forms one increasing run, which is what later
/// pairings are measured against. Everything else is a genuine reordering,
/// reported rather than corrected.
pub fn spine(decided: &[Pair]) -> Vec<Pair> {
    let mut ordered = decided.to_vec();
    ordered.sort();
    let sources: Vec<usize> = ordered.iter().map(|(_, source)| *source).collect();
    longest_increasing(&sources).into_iter().map(|position| ordered[position]).collect()
}

/// The source positions the backbone leaves open for a target position.
///
/// Exclusive bounds: a pairing landing outside them contradicts the run.
pub fn window(backbone: &[Pair], target: usize) -> (Option<usize>, Option<usize>) {
    let mut low: Option<usize> = None;
    let mut high: Option<usize> = None;
    for &(spine_target, spine_source) in backbone {
        if spine_target < target {
            low = Some(low.map_or(spine_source, |value: usize| value.max(spine_source)));
        } else if spine_target > target {
            high = Some(high.map_or(spine_source, |value: usize| value.min(spine_source)));
        }
    }
    (low, high)
}

/// True when a pairing sits inside the run rather than contradicting it.
pub fn fits(backbone: &[Pair], target: usize, source: usize) -> bool {
    let (low, high) = window(backbone, target);
    low.is_none_or(|low| source > low) && high.is_none_or(|high| source < high)
}

/// Pairings the ordering settles, from candidates the body scores could not.
///
/// Each entry is a target position and its candidates in the order the body
/// comparison preferred. The best candidate the backbone leaves room for is
/// provisional; it is returned only if it also keeps its place among its
/// neighbours here, so two targets competing for one pair of sources have to
/// agree on which way round they go before either is believed.
pub fn rescue<T: Clone>(
    undecided: &[(usize, Vec<(usize, T)>)],
    backbone: &[Pair],
) -> Vec<(usize, usize, T)> {
    let mut ordered = undecided.to_vec();
    ordered.sort_by_key(|(target, _)| *target);

    let picks: Vec<(usize, usize, T)> = ordered
        .into_iter()
        .filter_map(|(target, candidates)| {
            let (source, payload) =
                candidates.into_iter().find(|(source, _)| fits(backbone, target, *source))?;
            Some((target, source, payload))
        })
        .collect();

    picks
        .iter()
        .enumerate()
        .filter(|(index, (_, source, _))| {
            let before = index.checked_sub(1).map(|i| picks[i].1);
            let after = picks.get(index + 1).map(|pick| pick.1);
            before.is_none_or(|before| before < *source)
                && after.is_none_or(|after| after > *source)
        })
        .map(|(_, pick)| pick.clone())
        .collect()
}

/// Decided pairings that sit off the run, worth a reviewer's attention.
pub fn off_spine(decided: &[Pair], backbone: &[Pair]) -> Vec<Pair> {
    let on: BTreeSet<Pair> = backbone.iter().copied().collect();
    let mut found: Vec<Pair> = decided.iter().copied().filter(|pair| !on.contains(pair)).collect();
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_increasing_run_is_kept_whole() {
        assert_eq!(longest_increasing(&[1, 2, 3]), [0, 1, 2]);
    }

    #[test]
    fn one_element_out_of_order_is_dropped() {
        // 5 is the odd one out of 1, 5, 2, 3.
        assert_eq!(longest_increasing(&[1, 5, 2, 3]), [0, 2, 3]);
    }

    #[test]
    fn nothing_increases_in_an_empty_list() {
        assert!(longest_increasing(&[]).is_empty());
    }

    #[test]
    fn the_spine_is_the_pairings_that_agree_on_an_order() {
        // (1, 9) contradicts the rest and is left off.
        let decided = [(0, 0), (1, 9), (2, 1), (3, 2)];
        assert_eq!(spine(&decided), [(0, 0), (2, 1), (3, 2)]);
    }

    #[test]
    fn a_pairing_off_the_spine_is_reported_not_removed() {
        let decided = [(0, 0), (1, 9), (2, 1)];
        let backbone = spine(&decided);
        assert_eq!(off_spine(&decided, &backbone), [(1, 9)]);
    }

    #[test]
    fn the_window_is_what_the_neighbours_leave_open() {
        let backbone = [(0, 10), (4, 20)];
        assert_eq!(window(&backbone, 2), (Some(10), Some(20)));
        assert!(fits(&backbone, 2, 15));
        assert!(!fits(&backbone, 2, 10), "the bounds are exclusive");
        assert!(!fits(&backbone, 2, 25));
    }

    #[test]
    fn an_unbounded_side_constrains_nothing() {
        let backbone = [(4, 20)];
        assert_eq!(window(&backbone, 0), (None, Some(20)));
        assert!(fits(&backbone, 0, 1));
        assert!(!fits(&backbone, 0, 20));
    }

    #[test]
    fn the_best_candidate_the_run_leaves_room_for_is_chosen() {
        let backbone = [(0, 10), (4, 20)];
        // 30 is preferred by the body scores but contradicts the run.
        let undecided = vec![(2, vec![(30, "wrong"), (15, "right")])];
        assert_eq!(rescue(&undecided, &backbone), [(2, 15, "right")]);
    }

    #[test]
    fn two_targets_that_disagree_about_their_order_settle_nothing() {
        let backbone = [(0, 10), (9, 30)];
        // Target 2 wants source 25 and target 3 wants 15: one of them must be
        // wrong, and nothing here says which.
        let undecided = vec![(2, vec![(25, "a")]), (3, vec![(15, "b")])];
        assert!(rescue(&undecided, &backbone).is_empty());
    }

    #[test]
    fn two_targets_in_agreement_are_both_settled() {
        let backbone = [(0, 10), (9, 30)];
        let undecided = vec![(2, vec![(15, "a")]), (3, vec![(25, "b")])];
        assert_eq!(rescue(&undecided, &backbone), [(2, 15, "a"), (3, 25, "b")]);
    }

    #[test]
    fn a_candidate_the_run_has_no_room_for_settles_nothing() {
        let backbone = [(0, 10), (4, 20)];
        let undecided = vec![(2, vec![(30, "wrong")])];
        assert!(rescue(&undecided, &backbone).is_empty());
    }
}
