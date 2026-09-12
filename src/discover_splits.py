#!/usr/bin/env python3
"""Discover useful code splits by measured compiler progress, without claiming whole-file matches.

Run from a dtk-template project. Every accepted batch must increase objdiff matched
code and preserve the retail build. The latter checks split integrity only: files
not enabled in configure.py are still linked from extracted objects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import split_confidence_loop as scl


def code_bytes(unit):
    return int(unit.get("measures", {}).get("matched_code", 0))


def by_path(report):
    return {
        scl.strip_source_root(u["metadata"]["source_path"]): u
        for u in report["units"]
        if u.get("metadata", {}).get("source_path")
        and u["metadata"].get("module_id", 0) == 0
    }


def code_proposals(proposals, existing):
    """Retain all proposed code, including gaps; compiler comparison tests ownership.

    Data stays untouched. A partial code split can expose many matching functions
    even when the rest of the translation unit is unfinished or differs by version.
    Never extend over another established unit.
    """
    result = []
    for name, lines in proposals.items():
        ranges = [
            r for l in lines if (r := scl.parse_range(l)) and r[0] in (".text", ".init")
        ]
        if not ranges:
            continue
        body = list(existing.get(name, []))
        for section in sorted({r[0] for r in ranges}):
            section_ranges = [r for r in ranges if r[0] == section]
            old = [r for l in body if (r := scl.parse_range(l)) and r[0] == section]
            start = min(r[1] for r in section_ranges + old)
            end = max(r[2] for r in section_ranges + old)
            if old == [(section, start, end)]:
                continue
            occupied = [
                r
                for n, ls in existing.items()
                if n != name
                for l in ls
                if (r := scl.parse_range(l)) and r[0] == section
            ]
            if any(start < r[2] and r[1] < end for r in occupied):
                continue
            body = [l for l in body if not (r := scl.parse_range(l)) or r[0] != section]
            body.append(f"\t{section:11} start:0x{start:08X} end:0x{end:08X}")
        if body and body != existing.get(name):
            result.append((name, body))
    return sorted(
        result,
        key=lambda item: (
            -sum(
                r[2] - r[1]
                for l in item[1]
                if (r := scl.parse_range(l)) and r[0] in (".text", ".init")
            )
        ),
    )


def data_only_in_source(source, name):
    """True when this unit emits no code at all in the source version.

    Such a unit can never be reached by a code pass: there is no .text to
    anchor, which is exactly why coverage dispositions it `zero-code`. Its
    data can still be proposed by symbol name, so it is the one case where a
    proposal may create the target unit outright. This asks the source split,
    not the proposal -- a proposal missing .text usually means dtk could not
    match the code, which is the case the rule below exists to reject.
    """
    body = source.get(name)
    return bool(body) and not any(
        (r := scl.parse_range(l)) and r[0] in (".text", ".init") for l in body
    )


def section_size(body, section):
    """How many bytes a unit's body claims in one section, if it claims any."""
    ranges = [r for l in body or [] if (r := scl.parse_range(l)) and r[0] == section]
    return max(r[2] for r in ranges) - min(r[1] for r in ranges) if ranges else None


def extended_end(section, start, end, occupied, source_body):
    """Grow a proposed range over an unowned remainder that would strand a symbol.

    dtk ends a proposed range at the last symbol it could match, so an unmatched
    symbol sitting immediately after lands in a remainder nothing owns. Nothing
    emits it, and the unit's own code still references it, so the link fails
    with an undefined symbol -- `musyx/runtime/synth.c` lost its whole data
    migration to a four-byte tail of exactly this shape.

    Claiming that remainder is only safe with evidence that it belongs here, so
    the growth is bounded twice: never into the next owner's range, and never
    past the size the same unit has in the source version. A unit whose source
    body is unknown or already large enough is left alone.
    """
    expected = section_size(source_body, section)
    if expected is None or end - start >= expected:
        return end
    limit = start + expected
    following = [r[1] for r in occupied if r[1] >= end]
    if following:
        limit = min(limit, min(following))
    return max(end, limit)


def data_proposals(proposals, existing, source=None):
    """Extend established units with proposed non-code sections.

    dtk match --splits proposes a range for every section by symbol-name
    correspondence, but code_proposals only ever acts on .text/.init. A unit
    whose code is already split and matched can still be missing its .rodata,
    .bss, .sdata, .sbss, or similar ranges: the symbols are already correctly
    named in the target, dtk already proposed the range, nothing ever claimed
    it, it just was never carried over.

    A unit that already has a split is only ever extended. A new unit is
    created from data alone in exactly one case: `source` maps unit name to
    its source-version body, and that body has no code at all, so no code
    pass could ever have placed it. Either way, a proposal is dropped if it
    would overlap another established unit.
    """
    source = source or {}
    result = []
    names = list(existing) + [
        n for n in proposals if n not in existing and data_only_in_source(source, n)
    ]
    for name in names:
        body = existing.get(name, [])
        lines = proposals.get(name)
        if not lines:
            continue
        ranges = [
            r
            for l in lines
            if (r := scl.parse_range(l)) and r[0] not in (".text", ".init")
        ]
        if not ranges:
            continue
        new_body = list(body)
        for section in sorted({r[0] for r in ranges}):
            section_ranges = [r for r in ranges if r[0] == section]
            old = [r for l in new_body if (r := scl.parse_range(l)) and r[0] == section]
            start = min(r[1] for r in section_ranges + old)
            end = max(r[2] for r in section_ranges + old)
            if old == [(section, start, end)]:
                continue
            occupied = [
                r
                for n, ls in existing.items()
                if n != name
                for l in ls
                if (r := scl.parse_range(l)) and r[0] == section
            ]
            if any(start < r[2] and r[1] < end for r in occupied):
                continue
            end = extended_end(section, start, end, occupied, source.get(name))
            new_body = [
                l for l in new_body if not (r := scl.parse_range(l)) or r[0] != section
            ]
            new_body.append(f"\t{section:11} start:0x{start:08X} end:0x{end:08X}")
        if new_body != body:
            result.append((name, new_body))
    return sorted(result, key=lambda item: item[0])


def main():
    from migration_workspace import project_lock

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="GM8E01_00")
    parser.add_argument("--target", required=True)
    parser.add_argument("--dtk", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--build-jobs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=40)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if (
        args.batch_size < 1
        or args.build_jobs < 1
        or (args.limit is not None and args.limit < 1)
    ):
        parser.error("batch size, build jobs, and limit must be positive")
    root, dtk = args.project_root.resolve(), args.dtk.resolve()
    out = root / "build" / args.target / "discovery"
    out.mkdir(parents=True, exist_ok=True)
    with project_lock(root):
        _execute(args, root, dtk, out)


def _execute(args, root, dtk, out):
    from discovery_adapter import VALIDATION, evaluate, prepare
    from migration_runtime import BuildContext

    archive = out / "runs" / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    archive.mkdir(parents=True)
    ctx = BuildContext(root, args.source, args.target, dtk, out, args.build_jobs)
    paths = [
        root / "config" / args.target / name for name in ("splits.txt", "symbols.txt")
    ]
    original = {p: p.read_bytes() for p in paths}
    owned = dict(original)
    for p, data in original.items():
        (archive / ("input-" + p.name)).write_bytes(data)
    for name in (
        "discover_splits.py",
        "discovery_adapter.py",
        "migration_runtime.py",
        "split_confidence_loop.py",
    ):
        shutil.copyfile(Path(__file__).with_name(name), archive / name)
    (out / "build.log").write_text("", encoding="utf-8")
    succeeded = False
    try:
        prepared = prepare(ctx, args.limit)
        owned = {p: p.read_bytes() for p in paths}
        events = list(prepared["events"])
        candidates = prepared["candidates"]
        for i in range(0, len(candidates), args.batch_size):
            result = evaluate(ctx, candidates[i : i + args.batch_size])
            owned = {p: p.read_bytes() for p in paths}
            events.extend(result["events"])
        report = ctx.build()
        baseline = prepared["starting"]["measures"]
        total = int(baseline.get("total_code", 0))
        result = {
            "source": args.source,
            "target": args.target,
            "baseline": baseline,
            "final": report["measures"],
            "events": events,
            "dtk_sha256": hashlib.sha256(dtk.read_bytes()).hexdigest(),
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "split_sha256": hashlib.sha256(paths[0].read_bytes()).hexdigest(),
            "symbols_sha256": hashlib.sha256(paths[1].read_bytes()).hexdigest(),
            "matched_percent_of_baseline_code": 100
            * int(report["measures"].get("matched_code", 0))
            / total
            if total
            else 0,
            "validation": VALIDATION,
        }
        (out / "result.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        succeeded = True
        print(json.dumps(result["final"], indent=2))
    except BaseException:
        for p, data in original.items():
            if p.read_bytes() == owned[p]:
                p.write_bytes(data)
        raise
    finally:
        for name in ("build.log", "proposals.txt", "matches.json", "renames.txt") + (
            ("result.json",) if succeeded else ()
        ):
            if (out / name).exists():
                shutil.copyfile(out / name, archive / name)


if __name__ == "__main__":
    main()
