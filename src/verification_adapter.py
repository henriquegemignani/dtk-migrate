"""Transactional whole-source verification for isolated and serial migration jobs."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import tempfile

from discover_splits import by_path, code_bytes
from migration_runtime import TRIAL_ERRORS, ValidationError
import split_confidence_loop as scl
from verify_source_units import legacy_blocks, render_config


class ConfigChangedError(RuntimeError):
    """The configuration changed outside the active transaction."""


def _check_owned(path, expected):
    try:
        current = path.read_bytes()
    except FileNotFoundError as error:
        raise ConfigChangedError(f"Configuration disappeared during verification: {path}") from error
    if current != expected:
        raise ConfigChangedError(f"Configuration changed during verification; preserving edits: {path}")


def _replace(path, expected, replacement):
    """Atomically replace only the last bytes written by this transaction."""
    _check_owned(path, expected)
    if expected == replacement:
        return replacement
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, path.stat().st_mode)
        _check_owned(path, expected)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return replacement


def _rollback(path, expected, original):
    try:
        _replace(path, expected, original)
    except ConfigChangedError:
        pass  # Never overwrite an intervening edit or mask the original error.


def configured_names(text, target):
    """Identify direct target flags so resumed trials recheck migrated units."""
    names = set()
    for node in ast.walk(ast.parse(text)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "Object" and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)):
            continue
        status = node.args[0]
        if (isinstance(status, ast.Call) and isinstance(status.func, ast.Name)
                and status.func.id == "MatchingFor" and not status.keywords
                and target in [ast.literal_eval(arg) for arg in status.args]):
            names.add(node.args[1].value)
    for _, _, version, old_names in legacy_blocks(text.replace("\r\n", "\n")):
        if version == target:
            names.update(old_names)
    return names


def validate(ctx, names):
    """Require retail byte equality and actual compiled linker dependencies."""
    names = set(names) | configured_names((ctx.root / "configure.py").read_text(encoding="utf-8"), ctx.target)
    report = ctx.build()
    units = by_path(report)
    inputs = ctx.run([ctx.ninja, "-t", "inputs", f"build/{ctx.target}/main.elf"], capture=True)

    def normalize(path):
        return os.path.normcase(os.path.normpath(str(ctx.root / Path(path.replace("\\", "/")))))

    inputs = {normalize(p) for p in inputs.splitlines() if p.strip()}
    objdiff = json.loads((ctx.root / "objdiff.json").read_text(encoding="utf-8"))
    comparison = {}
    for unit in objdiff["units"]:
        name = scl.strip_source_root(unit.get("metadata", {}).get("source_path", ""))
        if name in names:
            if name in comparison:
                raise ValidationError(f"Ambiguous objdiff source unit: {name}")
            comparison[name] = unit
    for name in sorted(set(names)):
        if units.get(name, {}).get("metadata", {}).get("complete") is not True:
            raise ValidationError(f"{name} was not configured to link from source")
        obj_path = comparison.get(name, {}).get("base_path", "")
        if not obj_path or normalize(obj_path) not in inputs:
            raise ValidationError(f"{name}'s compiled object is not an input to main.elf")
    return report


def prepare(ctx, limit=None):
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    path = ctx.root / "configure.py"
    original = path.read_bytes()
    text = original.decode("utf-8")
    migrated = {}
    for _, _, version, names in legacy_blocks(text.replace("\r\n", "\n")):
        migrated.setdefault(version, set()).update(names)
    rendered = render_config(text, ctx.target, set())
    owned = original
    try:
        owned = _replace(path, owned, rendered.encode("utf-8"))
        baseline = validate(ctx, configured_names(rendered, ctx.target))
        _check_owned(path, owned)
        candidates = [{"name": name} for name, unit in by_path(baseline).items()
                      if not unit.get("metadata", {}).get("complete") and code_bytes(unit) > 0
                      and unit.get("sections")
                      and all(s.get("fuzzy_match_percent", 0) == 100 for s in unit["sections"])]
        units = by_path(baseline)
        candidates.sort(key=lambda candidate: (-code_bytes(units[candidate["name"]]), candidate["name"]))
        if limit is not None:
            candidates = candidates[:limit]
        return {"candidates": candidates, "baseline": baseline, "events": [],
                "migrated_legacy": {v: sorted(names) for v, names in migrated.items()}}
    except BaseException:
        _rollback(path, owned, original)
        raise


def evaluate(ctx, candidates):
    path = ctx.root / "configure.py"
    original = path.read_bytes()
    text = original.decode("utf-8")
    # Preflight before writing and preserve caller order for deterministic bisection.
    render_config(text, ctx.target, {c["name"] for c in candidates})
    baseline_names = configured_names(text, ctx.target)
    accepted, deferred, events = [], [], []
    owned = original

    def write(batch):
        nonlocal owned
        names = {c["name"] for c in batch}
        owned = _replace(path, owned, render_config(text, ctx.target, names).encode("utf-8"))

    def trial(batch):
        if not batch:
            return
        proposed = accepted + batch
        write(proposed)
        try:
            validate(ctx, baseline_names | {c["name"] for c in proposed})
        except TRIAL_ERRORS as error:
            write(accepted)
            if len(batch) > 1:
                mid = len(batch) // 2
                trial(batch[:mid])
                trial(batch[mid:])
            else:
                deferred.extend(batch)
                events.append({"unit": batch[0]["name"], "status": "failed-source-link-or-hash",
                               "reason": str(error)})
            return
        accepted.extend(batch)
        events.extend({"unit": c["name"], "status": "retail-hash-verified-source"} for c in batch)

    try:
        trial(list(candidates))
        write(accepted)
        report = validate(ctx, baseline_names | {c["name"] for c in accepted})
        _check_owned(path, owned)
        return {"accepted": accepted, "deferred": deferred, "events": events, "report": report,
                "validation": "compiled-link-inputs-and-retail-bytes"}
    except BaseException:
        _rollback(path, owned, original)
        raise
