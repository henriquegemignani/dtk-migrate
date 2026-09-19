//! Left and right boundary hypotheses, judged one edge at a time.
//!
//! Every generator proposes a whole range, and until now a range's two ends
//! stood or fell together: a sequence bounded by its neighbours' stale splits
//! proposed the whole gap between them, right or wrong at both ends. But the
//! two ends are separate claims with separate evidence. A layout group may
//! place a unit's first function exactly while ending in the middle of the
//! unit; a sequence may reach the true end while overshooting the start.
//!
//! An [`EdgeHypothesis`] is one such end: an address, which side of the unit it
//! bounds, which evidence families proposed it, and whether the observations
//! support it. Support needs two facts, one on each side of the address: the
//! function just inside belongs to the unit, and the function just outside is
//! independently someone else's (or there is none). An edge held up only by
//! a neighbour's current split is not supported, because splits are the
//! observations being corrected.

use serde::{Deserialize, Serialize};

use crate::analysis::ownership::{HelperPosition, ObservationIndex, TargetFunctionObservation};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Side {
    Left,
    Right,
}

/// What stands on one side of an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Party {
    /// A member of the unit with independent attribution.
    IndependentMember,
    /// An unattributed function placed at the unit's head or tail by its
    /// neighbours and called only by members of the unit on the same side of
    /// the edge.
    CallerConfinedHelper,
    /// A function independently attributed to another unit.
    ForeignIndependent,
    /// No function at all: the section ends here.
    SectionBoundary,
    /// Anything else, which supports nothing.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeParty {
    pub party: Party,
    /// The function standing there, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_id: Option<String>,
    /// The unit the attribution names, when it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeHypothesis {
    pub side: Side,
    pub module: String,
    pub section: String,
    pub address: String,
    /// The evidence families that proposed this address, as `kind` or
    /// `kind:support-group`.
    pub families: Vec<String>,
    pub inside: EdgeParty,
    pub outside: EdgeParty,
    pub supported: bool,
    /// The unit whose independent attribution pins the far side. The edge
    /// depends on that observation, not on the unit's current split.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<String>,
    /// Other supported addresses for the same side of the same unit, which
    /// make this one ambiguous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub competing: Vec<String>,
}

fn hex(value: u32) -> String { format!("{value:#010X}") }

fn parse(value: &str) -> u32 {
    let digits = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    u32::from_str_radix(digits, 16).unwrap_or(0)
}

fn party(kind: Party, function: Option<&TargetFunctionObservation>) -> EdgeParty {
    EdgeParty {
        party: kind,
        function: function.map(|function| function.address.clone()),
        attribution_id: None,
        unit: None,
    }
}

/// Judges the edge of `unit` at `address` on `side`, from observations alone.
pub fn judge(
    observations: &ObservationIndex,
    unit: &str,
    module: &str,
    section: &str,
    side: Side,
    address: u32,
    families: Vec<String>,
) -> EdgeHypothesis {
    let functions = observations.section_functions(module, section);
    // The functions either side of the address. Extents never overlap, so the
    // one starting last before the address is the only one that can straddle
    // it, and a straddled address is no boundary at all.
    let split = functions.partition_point(|function| parse(&function.address) < address);
    let before = split.checked_sub(1).map(|index| &functions[index]);
    let straddles = before.is_some_and(|function| parse(&function.end) > address);
    let after = functions.get(split);
    let (inside, outside) = match side {
        Side::Left => (after, before),
        Side::Right => (before, after),
    };

    let inside = match inside {
        _ if straddles => party(Party::Unsupported, None),
        None => party(Party::Unsupported, None),
        Some(function) => {
            let start = parse(&function.address);
            match observations.at_target(module, section, start) {
                Some(item) if item.source.unit == unit && item.independent => EdgeParty {
                    party: Party::IndependentMember,
                    function: Some(function.address.clone()),
                    attribution_id: Some(item.id.clone()),
                    unit: Some(item.source.unit.clone()),
                },
                Some(item) => EdgeParty {
                    party: Party::Unsupported,
                    function: Some(function.address.clone()),
                    attribution_id: Some(item.id.clone()),
                    unit: Some(item.source.unit.clone()),
                },
                None if placed_at_edge(observations, unit, module, function, side, address) => {
                    party(Party::CallerConfinedHelper, Some(function))
                }
                None => party(Party::Unsupported, Some(function)),
            }
        }
    };
    let outside = match outside {
        _ if straddles => party(Party::Unsupported, None),
        None => party(Party::SectionBoundary, None),
        Some(function) => match observations.at_target(module, section, parse(&function.address)) {
            Some(item) if item.source.unit != unit && item.independent => EdgeParty {
                party: Party::ForeignIndependent,
                function: Some(function.address.clone()),
                attribution_id: Some(item.id.clone()),
                unit: Some(item.source.unit.clone()),
            },
            Some(item) => EdgeParty {
                party: Party::Unsupported,
                function: Some(function.address.clone()),
                attribution_id: Some(item.id.clone()),
                unit: Some(item.source.unit.clone()),
            },
            None => party(Party::Unsupported, Some(function)),
        },
    };
    let supported = matches!(inside.party, Party::IndependentMember | Party::CallerConfinedHelper)
        && matches!(outside.party, Party::ForeignIndependent | Party::SectionBoundary);
    EdgeHypothesis {
        side,
        module: module.to_string(),
        section: section.to_string(),
        address: hex(address),
        families,
        depends_on: (outside.party == Party::ForeignIndependent)
            .then(|| outside.unit.clone())
            .flatten(),
        inside,
        outside,
        supported,
        competing: Vec::new(),
    }
}

/// Whether an unattributed function just inside the edge is a helper of
/// `unit` whose position puts it there: at the unit's head for a left edge, at
/// its tail for a right one, so that what stands outside is the bound that
/// places it. Its callers must be the unit's and lie on the inside of the
/// edge. The complete body is checked again by the ownership assessment; this
/// only decides whether the edge can be proposed.
fn placed_at_edge(
    observations: &ObservationIndex,
    unit: &str,
    module: &str,
    function: &TargetFunctionObservation,
    side: Side,
    address: u32,
) -> bool {
    let Some(placement) =
        observations.helper_placement(unit, module, &function.section, parse(&function.address))
    else {
        return false;
    };
    let facing = match side {
        Side::Left => HelperPosition::Head,
        Side::Right => HelperPosition::Tail,
    };
    let inside = |section: &str, start: u32, _end: u32| {
        section != function.section
            || match side {
                Side::Left => start >= address,
                Side::Right => start < address,
            }
    };
    placement.position == facing
        && observations.helper_callers_confined(unit, module, function, &placement, inside)
}
