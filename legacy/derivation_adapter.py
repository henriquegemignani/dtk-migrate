"""Symbol naming from compiled objects, as an isolated and reversible migration stage.

Runs before the other stages because they depend on it: `dtk match` anchors its
proposals on symbol names, so every name established here widens what coverage
and discovery can later propose.

A rename changes no bytes, so a retail hash cannot tell a right name from a
wrong one -- the names themselves are corroborated before they ever reach here,
by comparing compiled source objects against the extracted originals (see
`derive_symbol_names`). What the build *does* decide is whether a name can be
applied at all: naming an address after a function some other unit compiles from
source puts that name in two linked objects, and the linker rejects it. That
failure is loud, so a batch that fails to link is bisected exactly as a split
candidate is.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import derive_symbol_names as deriver
from discover_splits import by_path, code_bytes
from migration_runtime import TRIAL_ERRORS, trial_build

VALIDATION = (
    "objdiff body comparison between compiled source and extracted objects; "
    "the build checks that each name can be linked, not that it is correct"
)

SYMBOL_LINE = re.compile(r"^(\S+)( = \.\w+:0x[0-9A-Fa-f]+;.*)$")


def objdiff_path(ctx):
    """The frozen objdiff binary, resolved exactly as the build resolves it."""
    suffix = ".exe" if os.name == "nt" else ""
    tools = ctx.toolchain_root or ctx.root
    path = tools / f"build/tools/objdiff-cli{suffix}"
    return path if path.exists() else None


def apply_renames(text, mapping):
    """Rewrite symbol names in a dtk symbols file.

    Done here rather than through `dtk symbols rename` so the stage does not
    depend on a subcommand the run's frozen dtk may predate, and so the write
    stays inside this transaction.
    """
    lines = []
    for line in text.splitlines():
        found = SYMBOL_LINE.match(line.strip())
        if found and found.group(1) in mapping:
            indent = line[: len(line) - len(line.lstrip())]
            lines.append(f"{indent}{mapping[found.group(1)]}{found.group(2)}")
        else:
            lines.append(line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


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
    """Derive every name the compiled objects imply, once, for this snapshot."""
    baseline = ctx.build()
    objdiff = objdiff_path(ctx)
    events = []
    if objdiff is None:
        # Without objdiff only the two weaker methods run. That is a real
        # reduction in reach, so it is recorded rather than passed over.
        events.append({"status": "objdiff-unavailable", "reason": "body matching off"})
    result = deriver.derive(
        ctx.root,
        ctx.target,
        objdiff=objdiff,
        limits=deriver.BODY_LIMITS,
        jobs=ctx.build_jobs,
        # The version being migrated from is the check on a misplaced name: if
        # it places the name where the target already has it, our own unmatched
        # source is the likelier explanation and nothing is renamed.
        reference=ctx.source,
    )
    candidates = [
        {
            "name": old,
            "new": proposal["new"],
            "method": proposal["method"],
            "tier": proposal["tier"],
            # Which rule settled it, and whether the unit's own ordering agreed.
            # A rename decided against the run is right often enough to keep and
            # unusual enough to be worth a reviewer opening it in objdiff.
            "signal": proposal.get("signal"),
            "off_spine": bool(proposal.get("off_spine")),
        }
        for old, proposal in sorted(result["accepted"].items())
        if proposal["tier"] in ("confident", "probable")
    ]
    if limit is not None:
        candidates = candidates[:limit]
    events.extend(
        {"unit": entry["old"], "status": "rejected", "reason": entry["reason"]}
        for entry in result["rejected"]
    )
    # A correction overwrites a name somebody already had reason to trust, so it
    # is recorded as its own event rather than disappearing into the rename
    # count -- it is the one outcome here a reviewer would want to see by name.
    chosen = {candidate["name"] for candidate in candidates}
    corrections = [
        entry for entry in result["corrections"] if entry["address_named"] in chosen
    ]
    events.extend(
        {
            "unit": entry["unit"],
            "status": "misplaced-name",
            "was": entry["address_named"],
            "should_be": entry["should_be"],
            "percent": entry["percent"],
            "frees_name_for": entry["frees_name_for"],
        }
        for entry in corrections
    )
    return {
        "candidates": candidates,
        "baseline": baseline,
        "starting": baseline,
        "events": events,
        "corrections": corrections,
    }


def evaluate(ctx, candidates):
    """Apply one batch of renames, bisecting whatever will not link."""
    symbols = ctx.root / "config" / ctx.target / "symbols.txt"
    original = symbols.read_bytes()
    owned = original
    report = ctx.build()
    applied = {}
    accepted_names = set()
    events = []

    def write(mapping):
        nonlocal owned
        if symbols.read_bytes() != owned:
            raise RuntimeError(
                "Symbols changed during trial; refusing to overwrite edits"
            )
        data = apply_renames(original.decode("utf-8"), mapping).encode("utf-8")
        _replace(symbols, data, owned)
        owned = data

    def retry(batch, status):
        write(applied)
        if len(batch) > 1:
            middle = len(batch) // 2
            trial(batch[:middle])
            trial(batch[middle:])
        else:
            events.append({"unit": batch[0]["name"], "status": status})

    def trial(batch):
        nonlocal report
        write(applied | {c["name"]: c["new"] for c in batch})
        try:
            tested = trial_build(ctx)
        except TRIAL_ERRORS:
            retry(batch, "name-conflict")
            return
        # A name cannot add matched code on its own, but it can let objdiff pair
        # functions it could not pair before, so the measure may rise. It must
        # never fall: that would mean a name took a pairing away from a unit.
        if _regresses(report, tested):
            retry(batch, "regresses-existing-code")
            return
        for candidate in batch:
            applied[candidate["name"]] = candidate["new"]
            accepted_names.add(candidate["name"])
            events.append(
                {
                    "unit": candidate["name"],
                    "status": "accepted",
                    "new": candidate["new"],
                    "method": candidate["method"],
                }
            )
        report = tested

    try:
        if len({c["name"] for c in candidates}) != len(candidates):
            raise ValueError("Duplicate derivation candidate names")
        if candidates:
            trial(candidates)
        write(applied)
        final = ctx.build()
        if _regresses(report, final):
            raise RuntimeError("Final derivation report regressed after validation")
        return {
            "accepted": [c for c in candidates if c["name"] in accepted_names],
            "deferred": [c for c in candidates if c["name"] not in accepted_names],
            "events": events,
            "report": final,
            "validation": VALIDATION,
        }
    except BaseException:
        if symbols.read_bytes() == owned:
            _replace(symbols, original, owned)
        raise
