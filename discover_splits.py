#!/usr/bin/env python3
"""Discover useful code splits by measured compiler progress, without claiming whole-file matches.

Run from a dtk-template project. Every accepted batch must increase objdiff matched
code and preserve the retail build. The latter checks split integrity only: files
not enabled in configure.py are still linked from extracted objects.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import split_confidence_loop as scl


def code_bytes(unit):
    return int(unit.get("measures", {}).get("matched_code", 0))


def by_path(report):
    return {scl.strip_source_root(u["metadata"]["source_path"]): u
            for u in report["units"] if u.get("metadata", {}).get("source_path")
            and u["metadata"].get("module_id", 0) == 0}


def code_proposals(proposals, existing):
    """Retain all proposed code, including gaps; compiler comparison tests ownership.

    Data stays untouched. A partial code split can expose many matching functions
    even when the rest of the translation unit is unfinished or differs by version.
    Never extend over another established unit.
    """
    result = []
    for name, lines in proposals.items():
        ranges = [r for l in lines if (r := scl.parse_range(l)) and r[0] in (".text", ".init")]
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
            occupied = [r for n, ls in existing.items() if n != name
                        for l in ls if (r := scl.parse_range(l)) and r[0] == section]
            if any(start < r[2] and r[1] < end for r in occupied):
                continue
            body = [l for l in body if not (r := scl.parse_range(l)) or r[0] != section]
            body.append(f"\t{section:11} start:0x{start:08X} end:0x{end:08X}")
        if body and body != existing.get(name):
            result.append((name, body))
    return sorted(result, key=lambda item: -sum(r[2] - r[1] for l in item[1]
                  if (r := scl.parse_range(l)) and r[0] in (".text", ".init")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="GM8E01_00")
    parser.add_argument("--target", required=True)
    parser.add_argument("--dtk", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=40)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if args.batch_size < 1 or (args.limit is not None and args.limit < 1):
        parser.error("batch size and limit must be positive")
    args.dtk = args.dtk.resolve()
    root = Path.cwd()
    out = root / "build" / args.target / "discovery"
    out.mkdir(parents=True, exist_ok=True)
    archive = out / "runs" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    archive.mkdir(parents=True)
    splits = root / "config" / args.target / "splits.txt"
    symbols = splits.with_name("symbols.txt")
    original = splits.read_bytes()
    original_symbols = symbols.read_bytes()
    (archive / "input-splits.txt").write_bytes(original)
    (archive / "input-symbols.txt").write_bytes(original_symbols)
    shutil.copyfile(__file__, archive / "discover_splits.py")
    shutil.copyfile(scl.__file__, archive / "split_confidence_loop.py")
    header, blocks, order = scl.parse_splits(original.decode("utf-8"))
    log = (out / "build.log").open("w", encoding="utf-8")

    def run(cmd):
        log.write("+ " + " ".join(map(str, cmd)) + "\n")
        log.flush()
        subprocess.run(list(map(str, cmd)), check=True, stdout=log, stderr=log)

    def build():
        run([sys.executable, "configure.py", "configure", "-v", args.target, "--dtk", args.dtk])
        run(["ninja", f"build/{args.target}/report.json", f"build/{args.target}/ok"])
        if (root / "orig" / args.target / "sys" / "main.dol").read_bytes() != (root / "build" / args.target / "main.dol").read_bytes():
            raise RuntimeError("Retail DOL bytes differ despite a passing ninja checksum target")
        return scl.load_report(args.target)

    report = build()
    baseline = report["measures"]
    events = []
    succeeded = False

    def save_state():
        scl.write_splits(splits, header, blocks, order)

    def try_batch(batch):
        nonlocal report
        before = by_path(report)
        staged = dict(blocks)
        staged.update(batch)
        staged_order = order + [n for n, _ in batch if n not in blocks]
        scl.write_splits(splits, header, staged, staged_order)
        try:
            trial = build()
        except subprocess.CalledProcessError:
            save_state()
            if len(batch) > 1:
                mid = len(batch) // 2
                try_batch(batch[:mid])
                try_batch(batch[mid:])
            else:
                print(f"  deferred build conflict: {batch[0][0]}", flush=True)
                events.append({"unit": batch[0][0], "status": "build-conflict"})
            return
        after = by_path(trial)
        keep = [(n, ls) for n, ls in batch
                if code_bytes(after.get(n, {})) > code_bytes(before.get(n, {}))]
        if len(keep) != len(batch):
            for n, _ in batch:
                if n not in {name for name, _ in keep}:
                    events.append({"unit": n, "status": "no-matched-code-gain"})
            save_state()
            if keep:
                try_batch(keep)
            return
        # Protect existing progress too; aggregate gain alone could hide a regression.
        if any(code_bytes(after.get(n, {})) < code_bytes(u) for n, u in before.items()):
            save_state()
            if len(batch) > 1:
                mid = len(batch) // 2
                try_batch(batch[:mid])
                try_batch(batch[mid:])
            else:
                events.append({"unit": batch[0][0], "status": "regresses-existing-code"})
            return
        for name, lines in keep:
            gain = code_bytes(after[name]) - code_bytes(before.get(name, {}))
            print(f"  + {name}: {gain} additional matched code bytes", flush=True)
            events.append({"unit": name, "status": "accepted", "gain": gain})
            if name not in blocks:
                order.append(name)
            blocks[name] = lines
        report = trial
        print(f"Matched code: {report['measures']['matched_code_percent']:.3f}%", flush=True)

    try:
        run([args.dtk, "match", f"config/{args.source}/config.yml", f"config/{args.target}/config.yml",
             "--splits", out / "proposals.txt", "--renames", out / "renames.txt", "-o", out / "matches.json"])
        # Names are matcher evidence, not a claim of linked-byte equality.
        run([args.dtk, "symbols", "rename", symbols, out / "renames.txt"])
        renamed_report = build()
        renamed_units = by_path(renamed_report)
        if any(code_bytes(renamed_units.get(n, {})) < code_bytes(u) for n, u in by_path(report).items()):
            symbols.write_bytes(original_symbols)
            report = build()
            events.append({"status": "rename-batch-reverted", "reason": "regressed existing matched code"})
        else:
            report = renamed_report
        _, proposals, _ = scl.parse_splits((out / "proposals.txt").read_text(encoding="utf-8"))
        candidates = code_proposals(proposals, blocks)
        if args.limit:
            candidates = candidates[:args.limit]
        print(f"Trying {len(candidates)} code split proposals", flush=True)
        for i in range(0, len(candidates), args.batch_size):
            try_batch(candidates[i:i + args.batch_size])
        save_state()
        report = build()  # Never leave a report describing a reverted trial.
        result = {"source": args.source, "target": args.target,
                  "baseline": baseline, "final": report["measures"], "events": events,
                  "dtk_sha256": hashlib.sha256(args.dtk.read_bytes()).hexdigest(),
                  "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "split_sha256": hashlib.sha256(splits.read_bytes()).hexdigest(),
                  "symbols_sha256": hashlib.sha256(symbols.read_bytes()).hexdigest(),
                  "matched_percent_of_baseline_code": 100 * int(report["measures"].get("matched_code", 0)) / int(baseline["total_code"]),
                  "validation": "objdiff matched code; retail hash checks split integrity, not candidate source linkage"}
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        succeeded = True
        print(json.dumps(result["final"], indent=2))
    except BaseException:
        splits.write_bytes(original)
        symbols.write_bytes(original_symbols)
        build()
        raise
    finally:
        log.close()
        for name in ("build.log", "proposals.txt", "matches.json", "renames.txt") + (("result.json",) if succeeded else ()):
            if (out / name).exists():
                shutil.copyfile(out / name, archive / name)


if __name__ == "__main__":
    main()
