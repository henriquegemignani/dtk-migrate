"""Scores a proposed function pairing with objdiff, without touching the project.

objdiff pairs symbols by name, so a proposal that a placeholder is some source
function is invisible to it. The inputs are ours, though: renaming both sides to
one short token in a temporary copy makes the pair visible. dtk's placeholder
names are short, and a token no longer than the shorter of the two names fits
in place, so no string table has to move, nothing is rebuilt, and the project's
own files are never opened for writing.

One objdiff run reports a match percent for every symbol in the object, so a
whole permutation of pairings costs a single invocation. Packing the candidate
pairings into permutations covers the full cross product in about as many runs
as one target has candidates, rather than one run per pairing.
"""

from __future__ import annotations

import json
import struct
import subprocess
import tempfile
from pathlib import Path

import elf_objects

# Tokens must fit inside both original names, so they are short and fixed width.
TOKEN_WIDTH = 5


def patch_symbols(data, mapping):
    """Rewrite symbol names in place. Each token must fit the name it replaces."""
    (table,) = struct.unpack_from(">I", data, 32)
    entry_size, count, _ = struct.unpack_from(">HHH", data, 46)
    headers = [
        struct.unpack_from(">10I", data, table + i * entry_size) for i in range(count)
    ]
    symtab = next(h for h in headers if h[1] == elf_objects.SHT_SYMTAB)
    strings = headers[symtab[6]][4]
    out = bytearray(data)
    for index in range(symtab[5] // 16):
        (offset,) = struct.unpack_from(">I", data, symtab[4] + index * 16)
        end = data.index(b"\0", strings + offset)
        name = data[strings + offset : end].decode("utf-8", "replace")
        token = mapping.get(name)
        if token is not None and len(token) <= len(name):
            out[strings + offset : strings + offset + len(token) + 1] = (
                token.encode() + b"\0"
            )
    return bytes(out)


def _permutations(pairs):
    """Pack pairings into rounds that use each symbol at most once."""
    remaining = list(pairs)
    while remaining:
        seen_target, seen_source, current, rest = set(), set(), [], []
        for target, source in remaining:
            if target in seen_target or source in seen_source:
                rest.append((target, source))
                continue
            seen_target.add(target)
            seen_source.add(source)
            current.append((target, source))
        yield current
        remaining = rest


def _run(objdiff, target_bytes, source_bytes, assignment):
    """Match percents for one permutation, keyed by token."""
    left = patch_symbols(target_bytes, {t: k for k, (t, _) in assignment.items()})
    right = patch_symbols(source_bytes, {s: k for k, (_, s) in assignment.items()})
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target.o"
        source = Path(directory) / "source.o"
        target.write_bytes(left)
        source.write_bytes(right)
        result = subprocess.run(
            [
                str(objdiff),
                "diff",
                "-1",
                str(target),
                "-2",
                str(source),
                next(iter(assignment)),
                "-o",
                "-",
                "--format",
                "json",
            ],
            capture_output=True,
            check=False,
        )
    if result.returncode:
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return {
        symbol["name"]: symbol["match_percent"]
        for symbol in payload.get("left", {}).get("symbols", [])
        if symbol.get("name") in assignment and symbol.get("match_percent") is not None
    }


def candidate_pairs(targets, sources, size_ratio):
    """Pairings worth scoring, filtered by how far the two sizes may differ.

    PAL inlines differently, so sizes move; the filter only has to be tight
    enough to keep the cross product affordable without discarding a real
    counterpart, which is why it is a ratio and a generous one.
    """
    pairs = []
    for target in targets:
        for source in sources:
            if min(len(target["name"]), len(source["name"])) < TOKEN_WIDTH:
                continue
            low, high = target["size"], source["size"]
            if not low or not high:
                continue
            if max(low, high) / min(low, high) > size_ratio:
                continue
            pairs.append((target["name"], source["name"]))
    return pairs


def score_matrix(objdiff, target_path, source_path, targets, sources, size_ratio=2.5):
    """`{target name: {source name: match percent}}` for every plausible pairing."""
    pairs = candidate_pairs(targets, sources, size_ratio)
    if not pairs:
        return {}
    target_bytes = target_path.read_bytes()
    source_bytes = source_path.read_bytes()
    scores = {}
    for round_number, assignment in enumerate(_permutations(pairs)):
        tokens = {
            f"Q{index:0{TOKEN_WIDTH - 1}d}": pair
            for index, pair in enumerate(assignment)
        }
        for token, percent in _run(objdiff, target_bytes, source_bytes, tokens).items():
            target, source = tokens[token]
            scores.setdefault(target, {})[source] = percent
    return scores


# A score this high means the two bodies differ by a few instructions at most,
# which is a different kind of statement from a merely good score: the pairing
# is either right or the counterpart is a near-duplicate of it. So the useful
# question above this line is not how far ahead the best candidate is, but how
# many candidates reach it at all.
EXACT_PERCENT = 99.0


def rank(scores, exact_percent=EXACT_PERCENT):
    """Best candidate, its lead over the runner-up, and the field behind it."""
    ranked = {}
    for target, candidates in scores.items():
        if not candidates:
            continue
        order = sorted(candidates.items(), key=lambda item: -item[1])
        best, percent = order[0]
        runner_up = order[1][1] if len(order) > 1 else 0.0
        ranked[target] = {
            "name": best,
            "percent": percent,
            "margin": percent - runner_up,
            "candidates": len(order),
            "exact": sum(1 for _, value in order if value >= exact_percent),
            "order": order,
        }
    return ranked
