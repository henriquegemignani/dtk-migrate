"""Measured code discovery with explicit paths and isolated, reversible trials."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import split_confidence_loop as scl
from discover_splits import by_path, code_bytes, code_proposals
from migration_runtime import TRIAL_ERRORS, trial_build

VALIDATION = "objdiff matched code; retail hash checks split integrity, not candidate source linkage"


def _replace(path, data, expected):
    """Replace a complete input, checking that it still belongs to this trial."""
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        if path.read_bytes() != expected:
            raise RuntimeError(
                f"{path.name} changed during trial; refusing to overwrite edits"
            )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _regresses(before, after):
    old, new = by_path(before), by_path(after)
    return any(
        code_bytes(new.get(name, {})) < code_bytes(unit) for name, unit in old.items()
    )


def prepare(ctx, limit=None):
    """Prepare matcher evidence and safe renames exactly once for a snapshot."""
    ctx.output.mkdir(parents=True, exist_ok=True)
    splits = ctx.root / "config" / ctx.target / "splits.txt"
    symbols = splits.with_name("symbols.txt")
    original = symbols.read_bytes()
    owned = original
    events = []
    starting = ctx.build()
    try:
        ctx.run(
            [
                ctx.dtk,
                "match",
                f"config/{ctx.source}/config.yml",
                f"config/{ctx.target}/config.yml",
                "--splits",
                ctx.output / "proposals.txt",
                "--renames",
                ctx.output / "renames.txt",
                "-o",
                ctx.output / "matches.json",
            ]
        )
        try:
            ctx.run([ctx.dtk, "symbols", "rename", symbols, ctx.output / "renames.txt"])
            owned = symbols.read_bytes()
            renamed = ctx.build()
            reason = (
                "regressed existing matched code"
                if _regresses(starting, renamed)
                else None
            )
        except TRIAL_ERRORS as exc:
            owned = symbols.read_bytes()
            reason = str(exc)
        if reason:
            if symbols.read_bytes() != owned:
                raise RuntimeError(
                    "Symbols changed during preparation; refusing to overwrite edits"
                )
            _replace(symbols, original, owned)
            owned = original
            events.append({"status": "rename-batch-reverted", "reason": reason})
        baseline = ctx.build()
        _, blocks, _ = scl.parse_splits(splits.read_text(encoding="utf-8"))
        _, proposals, _ = scl.parse_splits(
            (ctx.output / "proposals.txt").read_text(encoding="utf-8")
        )
        candidates = [
            {"name": n, "lines": ls} for n, ls in code_proposals(proposals, blocks)
        ]
        if limit is not None:
            candidates = candidates[:limit]
        return {
            "candidates": candidates,
            "baseline": baseline,
            "starting": starting,
            "events": events,
        }
    except BaseException:
        if symbols.read_bytes() == owned:
            _replace(symbols, original, owned)
        raise


def evaluate(ctx, candidates):
    """Evaluate one deterministic batch, bisect conflicts, and rebuild final evidence."""
    splits = ctx.root / "config" / ctx.target / "splits.txt"
    original = splits.read_bytes()
    owned = original
    header, blocks, order = scl.parse_splits(original.decode("utf-8"))
    report = ctx.build()
    accepted_names = set()
    events = []

    def write(staged, staged_order):
        nonlocal owned
        if splits.read_bytes() != owned:
            raise RuntimeError(
                "Splits changed during trial; refusing to overwrite edits"
            )
        descriptor, name = tempfile.mkstemp(prefix="trial-splits.", dir=splits.parent)
        os.close(descriptor)
        temporary = Path(name)
        try:
            scl.write_splits(temporary, header, staged, staged_order)
            data = temporary.read_bytes()
            _replace(splits, data, owned)
            owned = data
        finally:
            temporary.unlink(missing_ok=True)

    def retry(batch, status):
        write(blocks, order)
        if len(batch) > 1:
            middle = len(batch) // 2
            trial(batch[:middle])
            trial(batch[middle:])
        else:
            events.append({"unit": batch[0]["name"], "status": status})

    def trial(batch):
        nonlocal report
        staged = dict(blocks)
        staged.update((c["name"], c["lines"]) for c in batch)
        staged_order = order + [c["name"] for c in batch if c["name"] not in blocks]
        write(staged, staged_order)
        try:
            tested = trial_build(ctx)
        except TRIAL_ERRORS:
            retry(batch, "build-conflict")
            return
        before, after = by_path(report), by_path(tested)
        keep = [
            c
            for c in batch
            if code_bytes(after.get(c["name"], {}))
            > code_bytes(before.get(c["name"], {}))
        ]
        if len(keep) != len(batch):
            kept_names = {c["name"] for c in keep}
            events.extend(
                {"unit": c["name"], "status": "no-matched-code-gain"}
                for c in batch
                if c["name"] not in kept_names
            )
            write(blocks, order)
            if keep:
                trial(keep)
            return
        if _regresses(report, tested):
            retry(batch, "regresses-existing-code")
            return
        for c in keep:
            name = c["name"]
            events.append(
                {
                    "unit": name,
                    "status": "accepted",
                    "gain": code_bytes(after[name]) - code_bytes(before.get(name, {})),
                }
            )
            if name not in blocks:
                order.append(name)
            blocks[name] = c["lines"]
            accepted_names.add(name)
        report = tested

    try:
        if len({c["name"] for c in candidates}) != len(candidates):
            raise ValueError("Duplicate discovery candidate names")
        if candidates:
            trial(candidates)
        write(blocks, order)
        final = ctx.build()
        if _regresses(report, final):
            raise RuntimeError("Final discovery report regressed after validation")
        return {
            "accepted": [c for c in candidates if c["name"] in accepted_names],
            "deferred": [c for c in candidates if c["name"] not in accepted_names],
            "events": events,
            "report": final,
            "validation": VALIDATION,
        }
    except BaseException:
        if splits.read_bytes() == owned:
            _replace(splits, original, owned)
        raise
