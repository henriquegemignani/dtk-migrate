"""Transactional whole-source verification for isolated and serial migration jobs."""

from __future__ import annotations

import ast
import json
import os
import tempfile
from pathlib import Path, PurePosixPath

import split_confidence_loop as scl
from discover_splits import by_path, code_bytes
from migration_runtime import TRIAL_ERRORS, ValidationError, trial_build
from verify_source_units import legacy_blocks, render_config, unrewritable_names


class ConfigChangedError(RuntimeError):
    """The configuration changed outside the active transaction."""


def _check_owned(path, expected):
    try:
        current = path.read_bytes()
    except FileNotFoundError as error:
        raise ConfigChangedError(
            f"Configuration disappeared during verification: {path}"
        ) from error
    if current != expected:
        raise ConfigChangedError(
            f"Configuration changed during verification; preserving edits: {path}"
        )


def _replace(path, expected, replacement):
    """Atomically replace only the last bytes written by this transaction."""
    _check_owned(path, expected)
    if expected == replacement:
        return replacement
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
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
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Object"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            continue
        status = node.args[0]
        if (
            isinstance(status, ast.Call)
            and isinstance(status.func, ast.Name)
            and status.func.id == "MatchingFor"
            and not status.keywords
            and target in [ast.literal_eval(arg) for arg in status.args]
        ):
            names.add(node.args[1].value)
    for _, _, version, old_names in legacy_blocks(text.replace("\r\n", "\n")):
        if version == target:
            names.update(old_names)
    return names


# Sections that hold no bytes. They exist as a name, an address and a size, so
# a fuzzy match percent over one of them scores our symbol annotations rather
# than anything in the binary. dtk auto-sizes a symbol to the gap before the
# next one, which is how `GXMisc.c`'s `FinishQueue` came to be 0xC in PAL and
# 0x8 in NTSC -- one wrong size, a 75% section score, and a unit whose code is a
# byte-identical match was never offered as a candidate at all.
EMPTY_SECTIONS = frozenset({".bss", ".sbss", ".sbss2"})


def matches_on_content(unit):
    """True when every section that actually holds bytes is a full fuzzy match.

    A unit with nothing but empty sections answers False: there is no evidence
    either way, and this is the gate that decides what is worth a build.
    """
    sections = [
        section
        for section in unit.get("sections", [])
        if section.get("name") not in EMPTY_SECTIONS
    ]
    return bool(sections) and all(
        section.get("fuzzy_match_percent", 0) == 100 for section in sections
    )


def module_of(target_path, version):
    """The REL module a compiled object belongs to, or None for the DOL.

    dtk puts a module's extracted objects under `build/<version>/<module>/obj/`
    and the DOL's directly under `build/<version>/obj/`, so the path says which
    link an object is destined for. This matters because a unit configured with
    `MatchingFor(<version>)` may live in either, and the two are validated
    against different artifacts.
    """
    parts = PurePosixPath(str(target_path).replace("\\", "/")).parts
    try:
        after = parts[parts.index(version) + 1 :]
    except ValueError:
        return None
    return after[0] if len(after) > 1 and after[0] != "obj" else None


def validate(ctx, names, *, trial=False, record=None):
    """Require retail byte equality and actual compiled linker dependencies.

    `record`, when given, collects the configured units this version has no
    split for. Such a unit is declared `MatchingFor(<target>)` but appears in
    neither the report nor `objdiff.json`, because dtk emits no rule for a unit
    it cannot place -- so nothing is compiled and nothing is linked. That is
    vacuous rather than wrong (the units it happens to are empty ones, whose
    split in the source version is a zero-length range), and it is a standing
    property of the configuration rather than anything a candidate did. Failing
    the whole stage on it would block work that has nothing to do with it, so it
    is reported and stepped over.
    """
    names = set(names) | configured_names(
        (ctx.root / "configure.py").read_text(encoding="utf-8"), ctx.target
    )
    report = trial_build(ctx) if trial else ctx.build()
    units = by_path(report)

    def normalize(path):
        return os.path.normcase(
            os.path.normpath(str(ctx.root / Path(path.replace("\\", "/"))))
        )

    objdiff = json.loads((ctx.root / "objdiff.json").read_text(encoding="utf-8"))
    comparison = {}
    for unit in objdiff["units"]:
        name = scl.strip_source_root(unit.get("metadata", {}).get("source_path", ""))
        if name in names:
            if name in comparison:
                raise ValidationError(f"Ambiguous objdiff source unit: {name}")
            comparison[name] = unit

    linked = {}

    def links(module):
        """Objects the given module's link actually consumes."""
        if module not in linked:
            artifact = (
                f"build/{ctx.target}/main.elf"
                if module is None
                else f"build/{ctx.target}/{module}/{module}.plf"
            )
            found = ctx.run([ctx.ninja, "-t", "inputs", artifact], capture=True)
            linked[module] = {normalize(p) for p in found.splitlines() if p.strip()}
        return linked[module]

    for name in sorted(set(names)):
        unit = comparison.get(name, {})
        if not unit and name not in units:
            # No split for this version, so there is no object and no link to
            # check. Anything with a split reaches the assertions below.
            if record is not None:
                record.append(name)
            continue
        module = module_of(unit.get("target_path", ""), ctx.target)
        # dtk's report covers the DOL; a REL's units are absent from it entirely,
        # so their completeness is a question it cannot answer. The link check
        # below is the half that actually tests "configured to link from source",
        # and it works for every module.
        if (
            module is None
            and units.get(name, {}).get("metadata", {}).get("complete") is not True
        ):
            raise ValidationError(f"{name} was not configured to link from source")
        obj_path = unit.get("base_path", "")
        artifact = "main.elf" if module is None else f"{module}.plf"
        if not obj_path or normalize(obj_path) not in links(module):
            raise ValidationError(
                f"{name}'s compiled object is not an input to {artifact}"
            )
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
        unsplit = []
        baseline = validate(ctx, configured_names(rendered, ctx.target), record=unsplit)
        _check_owned(path, owned)
        candidates = [
            {"name": name}
            for name, unit in by_path(baseline).items()
            if not unit.get("metadata", {}).get("complete")
            and code_bytes(unit) > 0
            and matches_on_content(unit)
        ]
        units = by_path(baseline)
        candidates.sort(
            key=lambda candidate: (
                -code_bytes(units[candidate["name"]]),
                candidate["name"],
            )
        )
        # Candidates come from the build report, which says nothing about how an
        # object is declared. Dropping the ones whose declaration cannot be
        # rewritten here costs those units; leaving them in costs whichever
        # batch they land in, after that batch has already done its builds.
        blocked = unrewritable_names(rendered)
        events = [
            {
                "unit": candidate["name"],
                "status": "skipped",
                "reason": f"{blocked[candidate['name']]} cannot be widened safely",
            }
            for candidate in candidates
            if candidate["name"] in blocked
        ]
        events.extend(
            {
                "unit": name,
                "status": "configured-without-split",
                "reason": f"MatchingFor({ctx.target}) but {ctx.target} has no split "
                "for it, so nothing is compiled or linked",
            }
            for name in sorted(unsplit)
        )
        candidates = [c for c in candidates if c["name"] not in blocked]
        if limit is not None:
            candidates = candidates[:limit]
        return {
            "candidates": candidates,
            "baseline": baseline,
            "events": events,
            "migrated_legacy": {v: sorted(names) for v, names in migrated.items()},
        }
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
        owned = _replace(
            path, owned, render_config(text, ctx.target, names).encode("utf-8")
        )

    def trial(batch):
        if not batch:
            return
        proposed = accepted + batch
        write(proposed)
        try:
            validate(
                ctx,
                baseline_names | {c["name"] for c in proposed},
                trial=True,
            )
        except TRIAL_ERRORS as error:
            write(accepted)
            if len(batch) > 1:
                mid = len(batch) // 2
                trial(batch[:mid])
                trial(batch[mid:])
            else:
                deferred.extend(batch)
                events.append(
                    {
                        "unit": batch[0]["name"],
                        "status": "failed-source-link-or-hash",
                        "reason": str(error),
                    }
                )
            return
        accepted.extend(batch)
        events.extend(
            {"unit": c["name"], "status": "retail-hash-verified-source"} for c in batch
        )

    try:
        trial(list(candidates))
        write(accepted)
        report = validate(ctx, baseline_names | {c["name"] for c in accepted})
        _check_owned(path, owned)
        return {
            "accepted": accepted,
            "deferred": deferred,
            "events": events,
            "report": report,
            "validation": "compiled-link-inputs-and-retail-bytes",
        }
    except BaseException:
        _rollback(path, owned, original)
        raise
