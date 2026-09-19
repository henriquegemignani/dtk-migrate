//! Bounded search for a joint partition of a target function run.
//!
//! A missing target attribution is an explicit unknown state, and a source
//! unit without a placed member may be skipped. Neither state is published:
//! only a unique, fully explained partition can become a transaction. Keeping
//! them in the search prevents a weakly supported cut from being forced merely
//! because every byte and every source unit was assumed to need an owner.

use std::{cmp::Ordering, collections::BTreeMap};

use serde::{Deserialize, Serialize};

/// A target function. Gaps between functions are part of the following unit's
/// proposed interval; the caller decides whether that padding is acceptable.
#[derive(Debug, Clone)]
pub struct Piece {
    pub start: u32,
    pub end: u32,
    /// Independently attributed source unit, if there is one.
    pub independent: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegmentScore {
    pub independent: u32,
    pub complete: bool,
    pub explained: u32,
    pub padding: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Rank {
    placed: u32,
    unknown: u32,
    skipped: u32,
    independent: u32,
    complete: u32,
    explained: u32,
    padding: u32,
}

impl Rank {
    fn compare(self, other: Self) -> Ordering {
        (
            self.placed,
            std::cmp::Reverse(self.unknown),
            std::cmp::Reverse(self.skipped),
            self.complete,
            self.independent,
            self.explained,
            std::cmp::Reverse(self.padding),
        )
            .cmp(&(
                other.placed,
                std::cmp::Reverse(other.unknown),
                std::cmp::Reverse(other.skipped),
                other.complete,
                other.independent,
                other.explained,
                std::cmp::Reverse(other.padding),
            ))
    }
}

/// One unit's interval; `None` is an unmatched source unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub unit: String,
    pub range: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Search {
    Decisive(Vec<Placement>),
    Ambiguous { best: Vec<Placement>, competing: Vec<Placement>, shared_independent: Vec<u32> },
    Incomplete,
    Exhausted,
}

#[derive(Clone)]
struct Path {
    rank: Rank,
    placements: Vec<Placement>,
}

struct Explorer<'a, F> {
    units: &'a [String],
    pieces: &'a [Piece],
    end: u32,
    budget: usize,
    visited: usize,
    exhausted: bool,
    memo: BTreeMap<(usize, usize), Vec<Path>>,
    evaluate: F,
}

impl<F: FnMut(&str, u32, u32) -> Option<SegmentScore>> Explorer<'_, F> {
    fn keep_two(paths: &mut Vec<Path>, path: Path) {
        paths.push(path);
        paths.sort_by(|left, right| right.rank.compare(left.rank));
        paths.truncate(2);
    }

    fn solve(&mut self, unit_index: usize, piece_index: usize) -> Vec<Path> {
        if let Some(found) = self.memo.get(&(unit_index, piece_index)) {
            return found.clone();
        }
        self.visited += 1;
        if self.visited > self.budget {
            self.exhausted = true;
            return Vec::new();
        }
        if unit_index == self.units.len() && piece_index == self.pieces.len() {
            return vec![Path { rank: Rank::default(), placements: Vec::new() }];
        }
        let mut found = Vec::new();
        if piece_index < self.pieces.len() && self.pieces[piece_index].independent.is_none() {
            for mut suffix in self.solve(unit_index, piece_index + 1) {
                suffix.rank.unknown += 1;
                Self::keep_two(&mut found, suffix);
            }
        }
        if unit_index == self.units.len() {
            self.memo.insert((unit_index, piece_index), found.clone());
            return found;
        }
        let unit = &self.units[unit_index];
        // An unmatched source unit is a real hypothesis, but never an
        // automatic ownership change. An independent member forbids it.
        if !self.pieces[piece_index..]
            .iter()
            .any(|piece| piece.independent.as_deref() == Some(unit))
        {
            let name = unit.clone();
            for mut suffix in self.solve(unit_index + 1, piece_index) {
                suffix.rank.skipped += 1;
                suffix.placements.insert(0, Placement { unit: name.clone(), range: None });
                Self::keep_two(&mut found, suffix);
            }
        }
        if piece_index == self.pieces.len() {
            self.memo.insert((unit_index, piece_index), found.clone());
            return found;
        }
        let start = self.pieces[piece_index].start;
        let mut has_member = false;
        for next in piece_index + 1..=self.pieces.len() {
            let piece = &self.pieces[next - 1];
            if piece.independent.as_deref().is_some_and(|owner| owner != unit) {
                break;
            }
            has_member |= piece.independent.as_deref() == Some(unit);
            if !has_member {
                continue;
            }
            let end = self.pieces.get(next).map_or(self.end, |piece| piece.start);
            if end <= start {
                continue;
            }
            let Some(score) = (self.evaluate)(unit, start, end) else { continue };
            let name = unit.clone();
            for mut suffix in self.solve(unit_index + 1, next) {
                suffix.rank.placed += 1;
                suffix.rank.independent += score.independent;
                suffix.rank.complete += u32::from(score.complete);
                suffix.rank.explained += score.explained;
                suffix.rank.padding += score.padding;
                suffix
                    .placements
                    .insert(0, Placement { unit: name.clone(), range: Some((start, end)) });
                Self::keep_two(&mut found, suffix);
            }
        }
        self.memo.insert((unit_index, piece_index), found.clone());
        found
    }
}

/// Search all function-boundary cuts in a bounded source-order run. A budget
/// hit is never interpreted as a decisive answer, even if one path was found.
pub fn search(
    units: &[String],
    pieces: &[Piece],
    end: u32,
    budget: usize,
    evaluate: impl FnMut(&str, u32, u32) -> Option<SegmentScore>,
) -> Search {
    if units.len() < 2
        || pieces.is_empty()
        || pieces.last().is_some_and(|piece| piece.end > end)
        || pieces.windows(2).any(|pair| pair[0].end > pair[1].start)
    {
        return Search::Incomplete;
    }
    let mut explorer = Explorer {
        units,
        pieces,
        end,
        budget,
        visited: 0,
        exhausted: false,
        memo: BTreeMap::new(),
        evaluate,
    };
    let paths = explorer.solve(0, 0);
    if explorer.exhausted {
        return Search::Exhausted;
    }
    let Some(best) = paths.first() else { return Search::Incomplete };
    if best.rank.unknown > 0 || best.rank.skipped > 0 {
        return Search::Incomplete;
    }
    if paths.get(1).is_some_and(|second| second.rank.compare(best.rank) == Ordering::Equal) {
        let competing = &paths[1];
        let shared_independent = pieces
            .iter()
            .filter(|piece| {
                let Some(owner) = piece.independent.as_deref() else { return false };
                [best, competing].into_iter().all(|path| {
                    path.placements.iter().any(|placement| {
                        placement.unit == owner
                            && placement.range.is_some_and(|(start, end)| {
                                start <= piece.start && piece.end <= end
                            })
                    })
                })
            })
            .map(|piece| piece.start)
            .collect();
        Search::Ambiguous {
            best: best.placements.clone(),
            competing: competing.placements.clone(),
            shared_independent,
        }
    } else {
        Search::Decisive(best.placements.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unique_three_unit_partition_is_decisive() {
        let units = ["A".into(), "B".into(), "C".into()];
        let pieces = [
            Piece { start: 0x1000, end: 0x1020, independent: Some("A".into()) },
            Piece { start: 0x1020, end: 0x1040, independent: Some("B".into()) },
            Piece { start: 0x1040, end: 0x1060, independent: Some("C".into()) },
        ];
        let found = search(&units, &pieces, 0x1060, 100, |_, _, _| {
            Some(SegmentScore { independent: 1, complete: true, ..Default::default() })
        });
        assert!(matches!(found, Search::Decisive(placements) if placements.len() == 3));
    }

    #[test]
    fn an_unplaced_function_can_leave_two_equal_cuts_unresolved() {
        let units = ["A".into(), "B".into()];
        let pieces = [
            Piece { start: 0x1000, end: 0x1020, independent: Some("A".into()) },
            Piece { start: 0x1020, end: 0x1040, independent: None },
            Piece { start: 0x1040, end: 0x1060, independent: Some("B".into()) },
        ];
        let found = search(&units, &pieces, 0x1060, 100, |_, _, _| {
            Some(SegmentScore { independent: 1, complete: true, ..Default::default() })
        });
        match found {
            Search::Ambiguous { best, competing, shared_independent } => {
                assert_eq!(shared_independent, vec![0x1000, 0x1040]);
                assert_ne!(best, competing);
            }
            other => panic!("expected competing partitions, got {other:?}"),
        }
    }

    #[test]
    fn a_budget_hit_does_not_publish_a_partial_search() {
        let units = ["A".into(), "B".into()];
        let pieces = [Piece { start: 0x1000, end: 0x1020, independent: Some("A".into()) }, Piece {
            start: 0x1020,
            end: 0x1040,
            independent: Some("B".into()),
        }];
        assert_eq!(
            search(&units, &pieces, 0x1040, 1, |_, _, _| Some(SegmentScore::default())),
            Search::Exhausted
        );
    }

    #[test]
    fn an_unexplained_target_function_is_left_unknown() {
        let units = ["A".into(), "B".into()];
        let pieces = [
            Piece { start: 0x1000, end: 0x1020, independent: Some("A".into()) },
            Piece { start: 0x1020, end: 0x1040, independent: None },
            Piece { start: 0x1040, end: 0x1060, independent: Some("B".into()) },
        ];
        let found = search(&units, &pieces, 0x1060, 100, |_, start, end| {
            (end <= 0x1020 || start >= 0x1040).then_some(SegmentScore {
                independent: 1,
                complete: true,
                ..Default::default()
            })
        });
        assert_eq!(found, Search::Incomplete);
    }

    #[test]
    fn source_order_does_not_override_contrary_independent_members() {
        let units = ["A".into(), "B".into()];
        let pieces = [Piece { start: 0x1000, end: 0x1020, independent: Some("B".into()) }, Piece {
            start: 0x1020,
            end: 0x1040,
            independent: Some("A".into()),
        }];
        assert_eq!(
            search(&units, &pieces, 0x1040, 100, |_, _, _| Some(SegmentScore::default())),
            Search::Incomplete
        );
    }
}
