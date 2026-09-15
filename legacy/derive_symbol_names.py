#!/usr/bin/env python3
"""Derives target-version symbol names by comparing compiled source objects to
the originals extracted from the target binary.

For every unit that has both a source object and an extracted object, four
methods propose names, strongest first:

`body-match` compares the two function bodies with objdiff. Three things can
settle one: a candidate that leads the runner-up clearly, a lone candidate close
enough to exact that nothing else in the field is competing with it, or -- for
the pairs that are genuinely too alike to score apart -- the order the two
objects define their functions in. `call-site` aligns the relocations inside a
function whose name already agrees, which names whatever it calls -- including
in units with no source of their own, since a call site names its callee.
`function-position` names a placeholder sitting between two agreeing names.

`misplaced-name` asks the opposite question of the other three: not what an
unnamed function should be called, but whether a name already in `symbols.txt`
is on the wrong function. A wrong name blocks the correct one and reports only
that the name was taken, so it hides exactly the rename it displaces.

PAL inlines differently enough that ordering alone misplaces functions, so where
a body comparison and a position disagree the position loses; it observes only a
function's neighbours, while the other two observe the function itself. Where
nothing stands clearly apart the answer is to abstain: a counterpart that was
inlined away has no name to find, and guessing one is how a rename pass starts
inventing them.

This is a different signal from `dtk match`, which compares two versions of the
same binary. Here the source object states what the unit is *supposed* to
contain, so every comparison stays inside one translation unit.

The output is a rename file for `dtk symbols rename`. Nothing is applied without
`--apply`, and a proposal is dropped unless every unit that has an opinion about
the symbol agrees.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

import elf_objects
import match_ordering
import objdiff_probe
import project_modules
import split_confidence_loop as scl

# Calibrated against NTSC agreement over a 45-unit sample; see
# docs/symbol_derivation.md. The margin does nearly all the work: at a fixed
# margin of 15, raising the score floor from 0 to 90 discards a quarter of the
# results and moves precision by less than half a point.
BODY_LIMITS = {
    "size_ratio": 2.5,
    "percent": 70.0,
    "margin": 15.0,
    "confident_percent": 80.0,
    "confident_margin": 30.0,
    # A lone candidate at this score needs no lead: the margin rule exists to
    # separate two plausible readings of the same body, and above this line
    # there is only one reading. CFishCloud's `__dt__CFishCloudModifier` scores
    # 99.6 against a field of other destructors topping out at 89.8 -- a lead of
    # 9.8 that the margin rule rejects and that is nonetheless unambiguous.
    "exact_percent": 99.0,
    # Ordering can settle a pairing the body scores cannot, but only above the
    # same floor; a poor match in the right place is still a poor match.
    "order_percent": 70.0,
}


def is_derivable(name):
    """True for a target name that is a dtk placeholder rather than a real name."""
    return scl.is_auto_symbol(name)


def is_usable_source_name(name):
    """True for a source name worth copying onto a target symbol.

    CodeWarrior's own local labels (`@468`, `@stringBase0`) are numbered per
    object and carry no meaning across a comparison, and a placeholder is by
    definition not a name, so neither may ever be proposed.
    """
    return bool(name) and not name.startswith("@") and not scl.is_auto_symbol(name)


def _common_subsequence(left, right):
    """Index pairs of a longest common subsequence of two key lists."""
    rows, columns = len(left), len(right)
    best = [[0] * (columns + 1) for _ in range(rows + 1)]
    for i in range(rows - 1, -1, -1):
        for j in range(columns - 1, -1, -1):
            best[i][j] = (
                best[i + 1][j + 1] + 1
                if left[i] == right[j]
                else max(best[i + 1][j], best[i][j + 1])
            )
    pairs, i, j = [], 0, 0
    while i < rows and j < columns:
        if left[i] == right[j]:
            pairs.append((i, j))
            i += 1
            j += 1
        elif best[i + 1][j] >= best[i][j + 1]:
            i += 1
        else:
            j += 1
    return pairs


def align(source, target, key):
    """Pair two ordered lists on shared names, filling equal-length gaps by position.

    Returns `(pairs, anchors)`, where `anchors` are the pairs that matched by
    name. A gap whose two sides differ in length is left unpaired: that is
    where the target version genuinely restructured the code, and guessing
    across it is how a rename pass starts inventing names.
    """
    left = [key(item) for item in source]
    right = [key(item) for item in target]
    # A placeholder must never anchor: it is unnamed on purpose, and two
    # unrelated `fn_` names comparing unequal is not the point -- the point is
    # that it carries no evidence. Unique sentinels keep them out of the
    # subsequence entirely.
    anchors = _common_subsequence(
        [f"\0L{n}" if not is_usable_source_name(v) else v for n, v in enumerate(left)],
        [f"\0R{n}" if is_derivable(v) else v for n, v in enumerate(right)],
    )
    pairs, previous_i, previous_j = [], 0, 0
    for i, j in anchors + [(len(left), len(right))]:
        if i - previous_i == j - previous_j:
            pairs.extend(zip(range(previous_i, i), range(previous_j, j)))
        if i < len(left):
            pairs.append((i, j))
        previous_i, previous_j = i + 1, j + 1
    return pairs, set(anchors)


def unit_proposals(source, target, unit):
    """Renames implied by one unit's source object against its extracted object."""
    proposals = []
    pairs, anchors = align(
        source["functions"], target["functions"], lambda f: f["name"]
    )
    # A unit where nothing agrees is not evidence of anything: every pairing in
    # it would rest on position alone, so a whole file would be named on one
    # coincidence repeated per function. Every such unit is already dropped by
    # the equal-length rule below, but only because their function counts
    # happen to differ -- that is a property of this data, not a rule.
    if not anchors:
        return []
    evidence = {"anchors": len(anchors), "functions": len(target["functions"])}
    for i, j in pairs:
        defined, original = source["functions"][i], target["functions"][j]
        anchored = (i, j) in anchors
        if (
            not anchored
            and is_usable_source_name(defined["name"])
            and is_derivable(original["name"])
        ):
            proposals.append(
                {
                    "old": original["name"],
                    "new": defined["name"],
                    "unit": unit,
                    "method": "function-position",
                    # Only the surrounding anchors place this function, so a
                    # size agreement is the one independent corroboration
                    # available for it.
                    "tier": (
                        "probable"
                        if defined["size"] == original["size"]
                        else "candidate"
                    ),
                    **evidence,
                }
            )
        # Relocations are only comparable once the two functions are known to be
        # the same function; an unanchored pairing is too weak to mine call
        # sites from, because every name it yields would rest on a guess.
        if not anchored:
            continue
        calls, call_anchors = align(
            defined["relocations"], original["relocations"], lambda r: r["target"]
        )
        for x, y in calls:
            outgoing, existing = defined["relocations"][x], original["relocations"][y]
            if (x, y) in call_anchors or existing["type"] != outgoing["type"]:
                continue
            if not is_derivable(existing["target"]):
                continue
            if not is_usable_source_name(outgoing["target"]):
                continue
            proposals.append(
                {
                    "old": existing["target"],
                    "new": outgoing["target"],
                    "unit": unit,
                    "method": "call-site",
                    "tier": (
                        "confident"
                        if len(defined["relocations"]) == len(original["relocations"])
                        else "probable"
                    ),
                    **evidence,
                }
            )
    return proposals


def _body_entry(unit, old, new, signal, tier, best, extra=None):
    """One body-match proposal, carrying what decided it."""
    return {
        "old": old,
        "new": new,
        "unit": unit,
        "method": "body-match",
        "signal": signal,
        "tier": tier,
        "percent": round(best["percent"], 2),
        "margin": round(best["margin"], 2),
        "candidates": best["candidates"],
        "exact": best["exact"],
        **(extra or {}),
    }


def _decide(best, limits):
    """Whether the scores alone settle a pairing, and how confidently.

    Two rules, because a score field has two shapes that admit one reading. The
    usual one is a clear lead over the runner-up. The other is a single
    candidate so close to exact that the rest of the field is not competing with
    it at all -- the case a fixed margin misjudges, because it measures the
    runner-up rather than the winner.
    """
    if best["percent"] >= limits["exact_percent"] and best["exact"] == 1:
        return "sole-exact", "confident"
    if best["percent"] < limits["percent"] or best["margin"] < limits["margin"]:
        return None, None
    confident = (
        best["percent"] >= limits["confident_percent"]
        and best["margin"] >= limits["confident_margin"]
    )
    return "margin", "confident" if confident else "probable"


def body_proposals(objdiff, unit, target_path, source_path, target, source, limits):
    """Renames implied by comparing function bodies with objdiff.

    Position says where a function sits between its neighbours; this says what
    the function *is*. PAL inlines differently enough that ordering alone
    misplaces functions, so where the two disagree this is the better evidence
    -- but only when one candidate stands clearly apart. A high score with no
    lead over the runner-up is the shape a wrong name takes, and a field of
    uniformly poor scores means the counterpart was inlined away and there is
    nothing here to name.

    What the scores settle on their own then places what they do not. The
    settled pairings and the functions already agreeing by name form an
    increasing run through the two objects, and a pairing the scores left
    ambiguous is believed when it takes its place in that run and no other
    ambiguous pairing wants the same seat.
    """
    unnamed = [f for f in target["functions"] if is_derivable(f["name"])]
    named = [f for f in source["functions"] if is_usable_source_name(f["name"])]
    if not unnamed or not named:
        return []
    scores = objdiff_probe.score_matrix(
        objdiff, target_path, source_path, unnamed, named, limits["size_ratio"]
    )
    ranked = objdiff_probe.rank(scores, limits["exact_percent"])
    at = {f["name"]: i for i, f in enumerate(target["functions"])}
    source_at = {f["name"]: i for i, f in enumerate(source["functions"])}

    # A function both objects already call by the same name is a pairing nothing
    # has to derive, so it anchors the run for free.
    agreed = [
        (at[f["name"]], source_at[f["name"]])
        for f in target["functions"]
        if f["name"] in source_at and is_usable_source_name(f["name"])
    ]
    proposals, decided, undecided = [], list(agreed), []
    for old, best in ranked.items():
        signal, tier = _decide(best, limits)
        if signal is None:
            candidates = [
                (source_at[name], (name, percent))
                for name, percent in best["order"]
                if percent >= limits["order_percent"]
            ]
            if candidates:
                undecided.append((at[old], (old, best, candidates)))
            continue
        decided.append((at[old], source_at[best["name"]]))
        proposals.append(_body_entry(unit, old, best["name"], signal, tier, best))

    backbone = match_ordering.spine(decided)
    on_spine = set(backbone)
    for proposal in proposals:
        pair = (at[proposal["old"]], source_at[proposal["new"]])
        proposal["off_spine"] = pair not in on_spine

    settled = match_ordering.rescue(
        [
            (position, [(where, load) for where, load in payload[2]])
            for position, payload in undecided
        ],
        backbone,
    )
    carried = {position: payload for position, payload in undecided}
    for position, _, (name, percent) in settled:
        old, best, _ = carried[position]
        proposals.append(
            _body_entry(
                unit,
                old,
                name,
                "order",
                "probable",
                best,
                {"off_spine": False, "chosen_percent": round(percent, 2)},
            )
        )
    return proposals


# How far a function may sit from the size of the name it carries before that
# name is worth re-examining. Wider than `size_ratio`, because this is looking
# for a name on the wrong function rather than a version's inlining drift, and
# a false suspicion here costs one objdiff run while a missed one leaves a wrong
# name in place.
SUSPECT_RATIO = 2.0


def misplaced_names(
    objdiff, unit, target_path, source_path, target, source, limits, reference=None
):
    """Names the target carries that the source says belong to another function.

    Everything else here names functions that have no name. This asks the
    opposite question -- whether a name already in `symbols.txt` is on the wrong
    address -- because a wrong name does more damage than a missing one: it is
    the answer to the question the rest of the tool is asking, so it silently
    blocks the correct rename and reports only that the name was taken.

    `dtk match` places names by propagating them between versions, so the way
    this goes wrong is a shift: two adjacent functions, the first named with the
    second's name. `CFishCloud` carries `BuildBoidNearList` on a 0xE8 function
    while the source compiles that name to 0x330 and compiles `OldBuildBoidNearList`
    to 0xE8, and the 0x330 function next door is still a placeholder.

    The size disagreement is the cheap tell and is only a suspicion; objdiff
    decides. A correction is proposed only when one source function explains the
    address near-exactly, alone, and at a size that fits -- a high bar, because
    unlike every other method here this one overwrites a name somebody already
    has reason to trust.

    `reference` is the other version's symbol sizes, and it is what keeps this
    honest. The source object is only authoritative about a name's body when the
    unit actually matches; where it does not, a function the source failed to
    inline is indistinguishable from a name on the wrong address. If the
    reference version carries the same name at a size the target address agrees
    with, then two versions place the name here and only our unbuilt source
    objects, so the finding is marked `contested` and demoted below the applied
    tiers -- reported for a human, never renamed automatically.
    """
    defined = {f["name"]: f for f in source["functions"]}
    present = {f["name"] for f in target["functions"]}
    suspects = []
    for function in target["functions"]:
        namesake = defined.get(function["name"])
        if namesake is None or not is_usable_source_name(function["name"]):
            continue
        low, high = function["size"], namesake["size"]
        if not low or not high:
            continue
        if max(low, high) / min(low, high) > SUSPECT_RATIO:
            suspects.append(function)
    if not suspects:
        return []
    # A generous ratio, so the name the address currently carries is scored too
    # and the report can say what it lost as well as what it gained.
    scores = objdiff_probe.score_matrix(
        objdiff,
        target_path,
        source_path,
        suspects,
        [f for f in source["functions"] if is_usable_source_name(f["name"])],
        max(limits["size_ratio"], SUSPECT_RATIO * 2),
    )
    found = []
    for old, best in objdiff_probe.rank(scores, limits["exact_percent"]).items():
        if best["percent"] < limits["exact_percent"] or best["exact"] != 1:
            continue
        if best["name"] == old or best["name"] in present:
            # Either the name is where it belongs, or the name this would free
            # is already on another function here and the two would have to
            # trade places -- a swap, which no single rename can express.
            continue
        carrier = next(f for f in target["functions"] if f["name"] == old)
        replacement = defined[best["name"]]
        if not replacement["size"] or not carrier["size"]:
            continue
        ratio = max(carrier["size"], replacement["size"]) / min(
            carrier["size"], replacement["size"]
        )
        if ratio > limits["size_ratio"]:
            continue
        # The other version's opinion on where this name lives. It knows nothing
        # about our source, so when it agrees with the address the disagreement
        # is ours to fix in the source, not the symbol file's.
        elsewhere = (reference or {}).get(old)
        contested = bool(
            elsewhere
            and carrier["size"]
            and max(elsewhere, carrier["size"]) / min(elsewhere, carrier["size"])
            <= limits["size_ratio"]
        )
        found.append(
            {
                "old": old,
                "new": best["name"],
                "unit": unit,
                "method": "misplaced-name",
                "signal": "misplaced",
                "contested": contested,
                "reference_size": elsewhere,
                "tier": "candidate" if contested else "confident",
                "percent": round(best["percent"], 2),
                "margin": round(best["margin"], 2),
                "candidates": best["candidates"],
                "exact": best["exact"],
                # None, not zero: a namesake too far off in size to be scored at
                # all is a different statement from one that scored nothing.
                "own_percent": (
                    round(dict(best["order"])[old], 2)
                    if old in dict(best["order"])
                    else None
                ),
                "carried_size": carrier["size"],
                "namesake_size": defined[old]["size"],
                "replacement_size": replacement["size"],
            }
        )
    return found


SYMBOL_LINE = re.compile(r"^(\S+) = (\.\w+):0x([0-9A-Fa-f]+);")
SYMBOL_SIZE = re.compile(r"^(\S+) = \.\w+:0x[0-9A-Fa-f]+;.*\bsize:0x([0-9A-Fa-f]+)")


def load_symbol_sizes(path):
    """Name to size for every sized symbol in a dtk symbols file."""
    sizes = {}
    if not path.is_file():
        return sizes
    for line in path.read_text(encoding="utf-8").splitlines():
        found = SYMBOL_SIZE.match(line.strip())
        if found:
            sizes[found.group(1)] = int(found.group(2), 16)
    return sizes


def load_symbols(path):
    """Name to `(section, address)` for every symbol in a dtk symbols file."""
    symbols = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        found = SYMBOL_LINE.match(line.strip())
        if found:
            symbols[found.group(1)] = (found.group(2), int(found.group(3), 16))
    return symbols


def unit_key(path):
    """A unit's identity, independent of whether it is named .c, .cpp or .o."""
    return PurePosixPath(str(path).replace("\\", "/")).with_suffix("").as_posix()


def address_owner(root, version, module=project_modules.DOL_NAME):
    """Answers which unit's split contains an address, by name and section."""
    text = project_modules.find(root, version, module).splits.read_text(
        encoding="utf-8"
    )
    _, blocks, _ = scl.parse_splits(text)
    spans = []
    for name, lines in blocks.items():
        for line in lines:
            found = scl.parse_range(line)
            if found:
                spans.append((found[0], found[1], found[2], unit_key(name)))

    def owner(section, address):
        for span_section, start, end, name in spans:
            if span_section == section and start <= address < end:
                return name
        return None

    return owner


# What a method actually observed. A body comparison and a call site both look
# at the function itself; a position only looks at its neighbours, so when the
# two disagree the position is the one that loses rather than the one that
# poisons the result.
STRENGTH = {
    "misplaced-name": 2,
    "body-match": 2,
    "call-site": 2,
    "function-position": 1,
}


def resolve(proposals, symbols, defined_by=None, owner=None):
    """Keep only unambiguous renames that a symbols file can actually apply."""
    tiers = {"confident": 0, "probable": 1, "candidate": 2}
    by_old, rejected = {}, []
    for proposal in proposals:
        by_old.setdefault(proposal["old"], []).append(proposal)

    accepted = {}
    for old, group in by_old.items():
        best = max(STRENGTH[p["method"]] for p in group)
        group = [p for p in group if STRENGTH[p["method"]] == best]
        names = {p["new"] for p in group}
        if len(names) > 1:
            rejected.append(
                {"old": old, "reason": "units disagree", "names": sorted(names)}
            )
            continue
        new = names.pop()
        if old not in symbols:
            rejected.append({"old": old, "reason": "not in symbols file", "new": new})
            continue
        # Renaming onto a name that already exists elsewhere would put two
        # symbols with one name in the file, which silently breaks whichever
        # reference resolves to the wrong address.
        if new in symbols and symbols[new] != symbols[old]:
            rejected.append({"old": old, "reason": "name already taken", "new": new})
            continue
        # A name a source object defines is exported by that unit's compiled
        # object whenever the unit is linked from source. Giving the same name
        # to an address outside that unit puts it in two linked objects, and
        # the linker rejects that outright -- the one failure here that is loud
        # rather than silent, so it is worth refusing up front. The symbols
        # file cannot answer this: it describes the extracted objects, and the
        # competing definition comes from the compiler.
        if defined_by and owner:
            claimants = defined_by.get(new)
            if claimants and owner(*symbols[old]) not in claimants:
                rejected.append(
                    {
                        "old": old,
                        "reason": "name defined by another unit's source",
                        "new": new,
                        "defined_in": sorted(claimants)[:3],
                    }
                )
                continue
        accepted[old] = min(group, key=lambda p: tiers[p["tier"]]) | {
            "new": new,
            "units": sorted({p["unit"] for p in group}),
        }

    # Two addresses claiming one name is the same collision seen from the other
    # side, and neither claim is more credible than the other.
    by_new = {}
    for old, proposal in accepted.items():
        by_new.setdefault(proposal["new"], []).append(old)
    for new, olds in by_new.items():
        if len(olds) > 1:
            for old in olds:
                del accepted[old]
                rejected.append(
                    {
                        "old": old,
                        "reason": "name claimed by several symbols",
                        "new": new,
                    }
                )
    return accepted, rejected


def unit_objects(root, version, module=project_modules.DOL_NAME):
    """Units that have both a compiled source object and an extracted one."""
    selected = project_modules.find(root, version, module)
    source_root, target_root = selected.sources, selected.extracted
    if not source_root.is_dir():
        # A REL the version does not build has an `obj/` but never a `src/`, so
        # there is nothing to compare against and the reason is worth naming.
        raise SystemExit(
            f"No compiled source objects under {source_root}"
            + (
                f"; {version} may not build the {module!r} module"
                if not selected.is_dol
                else ""
            )
        )
    units = []
    for source in sorted(source_root.rglob("*.o")):
        relative = source.relative_to(source_root)
        target = target_root / relative
        if target.is_file():
            units.append((relative.as_posix(), source, target))
    return units


def _one_unit(entry, objdiff, limits, reference=None):
    """Every proposal one unit implies, or the error that stopped it."""
    unit, source_path, target_path = entry
    try:
        source = elf_objects.read_object(source_path)
        target = elf_objects.read_object(target_path)
    except (ValueError, OSError, IndexError, struct.error) as exc:
        return [], {"unit": unit, "error": str(exc)}, unit_key(unit), set()
    found = unit_proposals(source, target, unit)
    if objdiff is not None:
        found += body_proposals(
            objdiff, unit, target_path, source_path, target, source, limits
        )
        found += misplaced_names(
            objdiff, unit, target_path, source_path, target, source, limits, reference
        )
    defines = {
        f["name"] for f in source["functions"] if is_usable_source_name(f["name"])
    }
    return found, None, unit_key(unit), defines


def derive(
    root,
    version,
    only=None,
    limit=None,
    objdiff=None,
    limits=None,
    jobs=1,
    module=project_modules.DOL_NAME,
    reference=None,
):
    """Collect, reconcile and report every rename the object pairs imply."""
    proposals, failures = [], []
    units = unit_objects(root, version, module)
    # The other version's symbol sizes, so a correction can be told apart from
    # a unit whose source has not been matched yet. See `misplaced_names`.
    sizes = (
        load_symbol_sizes(project_modules.find(root, reference, module).symbols)
        if reference
        else None
    )
    if only:
        wanted = set(only)
        units = [u for u in units if u[0] in wanted or Path(u[0]).stem in wanted]
    if limit is not None:
        units = units[:limit]
    # Body matching is one objdiff process per permutation, so the work is
    # almost entirely spent waiting on subprocesses; threads are enough.
    if jobs > 1 and objdiff is not None:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(
                pool.map(lambda entry: _one_unit(entry, objdiff, limits, sizes), units)
            )
    else:
        results = [_one_unit(entry, objdiff, limits, sizes) for entry in units]
    defined_by = {}
    for found, failure, key, defines in results:
        proposals.extend(found)
        if failure:
            failures.append(failure)
        for name in defines:
            defined_by.setdefault(name, set()).add(key)
    symbols = load_symbols(project_modules.find(root, version, module).symbols)
    accepted, rejected = resolve(
        proposals, symbols, defined_by, address_owner(root, version, module)
    )
    return {
        "units": len(units),
        "proposed": len(proposals),
        "accepted": accepted,
        "rejected": rejected,
        "failures": failures,
        "corrections": corrections(accepted, rejected),
    }


def corrections(accepted, rejected):
    """Misplaced names, and the rename each one is standing in the way of.

    A correction is deliberately reported and applied on its own rather than
    paired with the rename it unblocks. Freeing a name cannot collide with
    anything -- the name it moves to is unused -- so it is safe whatever else
    lands, including when the pipeline bisects a failing batch and separates
    the two halves. Applying both at once is the case that is not safe: half a
    swap puts one name on two addresses. The blocked rename is simply proposed
    again by the next run, once the name it wants is free.
    """
    blocked = {}
    for entry in rejected:
        if entry["reason"] == "name already taken":
            blocked.setdefault(entry["new"], []).append(entry["old"])
    return [
        {
            "unit": proposal["unit"],
            "address_named": old,
            "should_be": proposal["new"],
            "contested": proposal.get("contested", False),
            "reference_size": proposal.get("reference_size"),
            "percent": proposal["percent"],
            "own_percent": proposal["own_percent"],
            "carried_size": proposal["carried_size"],
            "namesake_size": proposal["namesake_size"],
            "frees_name_for": sorted(blocked.get(old, [])),
        }
        for old, proposal in sorted(accepted.items())
        if proposal["method"] == "misplaced-name"
    ]


def write_renames(path, accepted):
    """Write the rename file `dtk symbols rename` consumes."""
    lines = [
        f"{old} = {proposal['new']}"
        for old, proposal in sorted(accepted.items(), key=lambda kv: kv[1]["new"])
    ]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True, help="game project root")
    parser.add_argument(
        "--target", required=True, help="version to name, e.g. GM8P01_00"
    )
    parser.add_argument("--dtk", type=Path, help="dtk executable, required by --apply")
    parser.add_argument("--out", type=Path, help="rename file to write")
    parser.add_argument("--report", type=Path, help="JSON report to write")
    parser.add_argument("--unit", action="append", help="restrict to these units")
    parser.add_argument("--limit", type=int, help="only consider the first N units")
    parser.add_argument(
        "--objdiff",
        type=Path,
        help="objdiff-cli path; enables body comparison, the strongest method",
    )
    parser.add_argument(
        "--size-ratio",
        type=float,
        default=BODY_LIMITS["size_ratio"],
        help="widest size difference a body-match candidate may have",
    )
    parser.add_argument(
        "--body-percent",
        type=float,
        default=BODY_LIMITS["percent"],
        help="lowest body match percent to accept",
    )
    parser.add_argument(
        "--body-margin",
        type=float,
        default=BODY_LIMITS["margin"],
        help="lowest lead over the runner-up to accept",
    )
    parser.add_argument(
        "--exact-percent",
        type=float,
        default=BODY_LIMITS["exact_percent"],
        help="score above which a lone candidate needs no lead over the field",
    )
    parser.add_argument(
        "--order-percent",
        type=float,
        default=BODY_LIMITS["order_percent"],
        help="lowest score an ordering-settled pairing may have",
    )
    parser.add_argument(
        "--reference",
        help="other version to check a misplaced name against, e.g. GM8E01_00",
    )
    parser.add_argument(
        "--jobs", type=int, default=8, help="units to body-match in parallel"
    )
    parser.add_argument(
        "--module",
        default=project_modules.DOL_NAME,
        help="linked module to name, e.g. a REL beside the DOL (default: main)",
    )
    parser.add_argument(
        "--tier",
        choices=["confident", "probable", "candidate"],
        default="probable",
        help="lowest tier to include (default: probable)",
    )
    parser.add_argument(
        "--apply", action="store_true", help="run `dtk symbols rename` on the result"
    )
    args = parser.parse_args(argv)

    limits = BODY_LIMITS | {
        "size_ratio": args.size_ratio,
        "percent": args.body_percent,
        "margin": args.body_margin,
        "exact_percent": args.exact_percent,
        "order_percent": args.order_percent,
    }
    result = derive(
        args.project,
        args.target,
        only=args.unit,
        limit=args.limit,
        objdiff=args.objdiff,
        limits=limits,
        jobs=args.jobs,
        module=args.module,
        reference=args.reference,
    )
    allowed = {"confident": {"confident"}, "probable": {"confident", "probable"}}.get(
        args.tier, {"confident", "probable", "candidate"}
    )
    kept = {
        old: proposal
        for old, proposal in result["accepted"].items()
        if proposal["tier"] in allowed
    }

    counts = {}
    for proposal in kept.values():
        key = (proposal["method"], proposal.get("signal", ""), proposal["tier"])
        counts[key] = counts.get(key, 0) + 1
    print(f"units compared:      {result['units']}")
    print(f"raw proposals:       {result['proposed']}")
    print(f"unambiguous:         {len(result['accepted'])}")
    print(f"kept at --tier {args.tier}: {len(kept)}")
    for (method, signal, tier), count in sorted(counts.items()):
        label = f"{method}/{signal}" if signal else method
        print(f"    {label:30} {tier:10} {count}")
    reordered = sorted(
        {p["unit"] for p in kept.values() if p.get("off_spine")},
    )
    if reordered:
        print(
            f"units whose functions reorder: {len(reordered)} "
            "(body scores decided these; ordering does not corroborate them)"
        )
        for unit in reordered[:10]:
            names = [
                p["new"]
                for p in kept.values()
                if p.get("off_spine") and p["unit"] == unit
            ]
            print(f"    {unit}: {', '.join(sorted(names)[:3])}")
    contested = [c for c in result["corrections"] if c["contested"]]
    if contested:
        print(
            f"\nmisplaced names CONTESTED: {len(contested)} "
            "(the reference version places the name here too -- review by hand)"
        )
        for entry in contested:
            print(f"    {entry['unit']}")
            print(
                f"      {entry['address_named'][:64]}"
                f"\n        carries 0x{entry['carried_size']:X}; "
                f"our source compiles that name to 0x{entry['namesake_size']:X}, "
                f"but the reference has it at 0x{entry['reference_size']:X}"
                f"\n        would be {entry['should_be'][:56]}  "
                f"({entry['percent']}%)"
                "\n        not renamed: an unmatched source explains this equally well"
            )
    corrected = [c for c in result["corrections"] if c["address_named"] in kept]
    if corrected:
        print(
            f"\nmisplaced names corrected: {len(corrected)} "
            "(a name already in symbols.txt that sits on the wrong function)"
        )
        for entry in corrected:
            print(f"    {entry['unit']}")
            print(
                f"      {entry['address_named'][:64]}"
                f"\n        carries 0x{entry['carried_size']:X}, "
                f"but that name compiles to 0x{entry['namesake_size']:X}"
                f"\n        -> {entry['should_be'][:64]}  ({entry['percent']}%)"
            )
            for waiting in entry["frees_name_for"]:
                print(f"        frees the name for {waiting}, proposable next run")
        print()
    if result["rejected"]:
        reasons = {}
        for entry in result["rejected"]:
            reasons[entry["reason"]] = reasons.get(entry["reason"], 0) + 1
        print("rejected:")
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"    {reason:30} {count}")
    for failure in result["failures"]:
        print(f"    unreadable: {failure['unit']}: {failure['error']}")

    out = args.out or (
        project_modules.find(args.project, args.target, args.module).build
        / "derived_renames.txt"
    )
    written = write_renames(out, kept)
    print(f"wrote {written} renames to {out}")
    if args.report:
        args.report.write_text(
            json.dumps(
                {**result, "accepted": kept, "tier": args.tier}, indent=2, default=str
            ),
            encoding="utf-8",
        )

    if args.apply:
        if not args.dtk:
            raise SystemExit("--apply needs --dtk")
        symbols = project_modules.find(args.project, args.target, args.module).symbols
        subprocess.run(
            [str(args.dtk), "symbols", "rename", str(symbols), str(out)], check=True
        )
        print(f"applied {written} renames to {symbols}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
