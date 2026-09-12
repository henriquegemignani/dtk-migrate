#!/usr/bin/env python3
"""Derives target-version symbol names by comparing compiled source objects to
the originals extracted from the target binary.

For every unit that has both a source object and an extracted object, three
methods propose names, strongest first:

`body-match` compares the two function bodies with objdiff and takes the
candidate that both scores well and leads the runner-up clearly. `call-site`
aligns the relocations inside a function whose name already agrees, which names
whatever it calls -- including in units with no source of their own, since a
call site names its callee. `function-position` names a placeholder sitting
between two agreeing names.

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


def body_proposals(objdiff, unit, target_path, source_path, target, source, limits):
    """Renames implied by comparing function bodies with objdiff.

    Position says where a function sits between its neighbours; this says what
    the function *is*. PAL inlines differently enough that ordering alone
    misplaces functions, so where the two disagree this is the better evidence
    -- but only when one candidate stands clearly apart. A high score with no
    lead over the runner-up is the shape a wrong name takes, and a field of
    uniformly poor scores means the counterpart was inlined away and there is
    nothing here to name.
    """
    unnamed = [f for f in target["functions"] if is_derivable(f["name"])]
    named = [f for f in source["functions"] if is_usable_source_name(f["name"])]
    if not unnamed or not named:
        return []
    scores = objdiff_probe.score_matrix(
        objdiff, target_path, source_path, unnamed, named, limits["size_ratio"]
    )
    proposals = []
    for old, best in objdiff_probe.rank(scores).items():
        if best["percent"] < limits["percent"] or best["margin"] < limits["margin"]:
            continue
        proposals.append(
            {
                "old": old,
                "new": best["name"],
                "unit": unit,
                "method": "body-match",
                "tier": (
                    "confident"
                    if best["percent"] >= limits["confident_percent"]
                    and best["margin"] >= limits["confident_margin"]
                    else "probable"
                ),
                "percent": round(best["percent"], 2),
                "margin": round(best["margin"], 2),
                "candidates": best["candidates"],
            }
        )
    return proposals


SYMBOL_LINE = re.compile(r"^(\S+) = (\.\w+):0x([0-9A-Fa-f]+);")


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
STRENGTH = {"body-match": 2, "call-site": 2, "function-position": 1}


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


def _one_unit(entry, objdiff, limits):
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
):
    """Collect, reconcile and report every rename the object pairs imply."""
    proposals, failures = [], []
    units = unit_objects(root, version, module)
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
                pool.map(lambda entry: _one_unit(entry, objdiff, limits), units)
            )
    else:
        results = [_one_unit(entry, objdiff, limits) for entry in units]
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
    }


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
        key = (proposal["method"], proposal["tier"])
        counts[key] = counts.get(key, 0) + 1
    print(f"units compared:      {result['units']}")
    print(f"raw proposals:       {result['proposed']}")
    print(f"unambiguous:         {len(result['accepted'])}")
    print(f"kept at --tier {args.tier}: {len(kept)}")
    for (method, tier), count in sorted(counts.items()):
        print(f"    {method:18} {tier:10} {count}")
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
