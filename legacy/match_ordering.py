"""Corroborates a function pairing with the order the two objects define it in.

A compiler emits functions in roughly the order the source declares them, so the
pairings inside one unit mostly form an increasing run: the n-th unnamed target
function answers to a source function further down than the (n-1)-th did. That
run is a second, independent signal from the body comparison, and it is at its
most useful exactly where the body comparison is at its weakest -- a pair of
near-identical functions like `RemoveRepulsor` and `RemoveAttractor`, which
score within a tenth of a point of each other on both targets, but which only
one assignment puts in order.

The run is a corroboration and never a veto. Real units reorder: a destructor
the target emits first can live near the end of the source object, and two
template instantiations can swap. Those pairings are decided by their bodies and
stay decided; ordering only reports that they sit off the run, so a reviewer
knows where to look.
"""

from __future__ import annotations


def longest_increasing(values):
    """Positions of a longest strictly increasing subsequence of `values`."""
    best, previous = [], [-1] * len(values)
    for index, value in enumerate(values):
        low, high = 0, len(best)
        while low < high:
            middle = (low + high) // 2
            if values[best[middle]] < value:
                low = middle + 1
            else:
                high = middle
        previous[index] = best[low - 1] if low else -1
        if low == len(best):
            best.append(index)
        else:
            best[low] = index
    positions, cursor = [], best[-1] if best else -1
    while cursor >= 0:
        positions.append(cursor)
        cursor = previous[cursor]
    return positions[::-1]


def spine(decided):
    """The order-consistent backbone of a unit's decided pairings.

    `decided` is `(target position, source position)` pairs. The result is the
    subset that forms one increasing run, which is what later pairings are
    measured against; everything else is a genuine reordering, reported rather
    than corrected.
    """
    ordered = sorted(decided)
    kept = longest_increasing([source for _, source in ordered])
    return [ordered[position] for position in kept]


def window(backbone, target):
    """The source positions the backbone leaves open for a target position.

    Exclusive bounds: a pairing that lands outside them contradicts the run.
    """
    low, high = None, None
    for spine_target, spine_source in backbone:
        if spine_target < target:
            low = spine_source if low is None else max(low, spine_source)
        elif spine_target > target:
            high = spine_source if high is None else min(high, spine_source)
    return low, high


def fits(backbone, target, source):
    """True when a pairing sits inside the run rather than contradicting it."""
    low, high = window(backbone, target)
    return (low is None or source > low) and (high is None or source < high)


def rescue(undecided, backbone):
    """Pairings the ordering settles, from candidates the body scores could not.

    Each entry of `undecided` is `(target position, [(source position, payload)
    ...])` with the candidates in the order the body comparison preferred. The
    best candidate that the backbone leaves room for is provisional; it is only
    returned if it also keeps its place among its neighbours here, so that two
    targets competing for one pair of sources have to agree on which way round
    they go before either is believed.
    """
    picks = []
    for target, candidates in sorted(undecided):
        choice = next(
            (
                (source, load)
                for source, load in candidates
                if fits(backbone, target, source)
            ),
            None,
        )
        if choice is not None:
            picks.append((target, *choice))
    settled = []
    for index, (target, source, payload) in enumerate(picks):
        before = picks[index - 1][1] if index else None
        after = picks[index + 1][1] if index + 1 < len(picks) else None
        if before is not None and before >= source:
            continue
        if after is not None and after <= source:
            continue
        settled.append((target, source, payload))
    return settled


def off_spine(decided, backbone):
    """Decided pairings that sit off the run, worth a reviewer's attention.

    These stay accepted -- their bodies decided them -- but a unit that reorders
    is also a unit where a body comparison has the least help, so naming them is
    the point of reporting at all.
    """
    on = set(backbone)
    return [pair for pair in sorted(decided) if pair not in on]
