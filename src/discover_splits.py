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
