"""Evidence-backed partial translation-unit coverage in isolated workspaces."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

from discover_splits import by_path, code_bytes
from migration_runtime import TRIAL_ERRORS, ValidationError
import split_confidence_loop as scl


EVIDENCE_SCHEMA = 1
POLICY_VERSION = 1
VALIDATION = "unique-normalized-body-ownership-and-extracted-link-inputs-and-retail-bytes"


def _replace(path, data, expected):
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        if path.read_bytes() != expected:
            raise RuntimeError(f"{path.name} changed during coverage trial; refusing to overwrite edits")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_splits(path, header, blocks, order, expected):
    descriptor, name = tempfile.mkstemp(prefix="coverage-splits.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        scl.write_splits(temporary, header, blocks, order)
        data = temporary.read_bytes()
        _replace(path, data, expected)
        return data
    finally:
        temporary.unlink(missing_ok=True)


def _int_measure(report, name):
    return int(report.get("measures", {}).get(name, 0))


def _regresses(before, after):
    old, new = by_path(before), by_path(after)
    return any(code_bytes(new.get(name, {})) < code_bytes(unit) for name, unit in old.items())


def _ranges(lines):
    return [value for line in lines if (value := scl.parse_range(line))]


def _overlaps_existing(section, start, end, blocks):
    return any(section == other_section and start < other_end and other_start < end
               for lines in blocks.values() for other_section, other_start, other_end in _ranges(lines))


def _alternative(section, start, end, anchors):
    identity = f"{section}:{start:08X}-{end:08X}"
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:16],
        "section": section,
        "start": f"0x{start:08X}",
        "end": f"0x{end:08X}",
        "covered_bytes": end - start,
        "lines": [f"\t{section:11} start:0x{start:08X} end:0x{end:08X}"],
        "anchors": anchors,
    }


def build_alternatives(unit, target_blocks):
    """Create exact anchors, then contiguous runs; never bridge or widen."""
    eligible = [anchor for anchor in unit["anchors"] if anchor["eligible"]]
    individual = []
    for anchor in eligible:
        start, end = int(anchor["target_address"], 16), int(anchor["target_end"], 16)
        if not _overlaps_existing(anchor["section"], start, end, target_blocks):
            individual.append(_alternative(anchor["section"], start, end, [anchor]))
    individual.sort(key=lambda alt: (-alt["covered_bytes"], int(alt["start"], 16)))

    runs = []
    ordered = sorted(eligible, key=lambda anchor: (anchor["section"], int(anchor["target_address"], 16)))
    current = []
    for anchor in ordered:
        if (current and (anchor["section"] != current[-1]["section"]
                         or int(anchor["target_address"], 16) != int(current[-1]["target_end"], 16))):
            if len(current) > 1:
                runs.append(current)
            current = []
        current.append(anchor)
    if len(current) > 1:
        runs.append(current)
    combined = []
    for anchors in runs:
        start, end = int(anchors[0]["target_address"], 16), int(anchors[-1]["target_end"], 16)
        if not _overlaps_existing(anchors[0]["section"], start, end, target_blocks):
            combined.append(_alternative(anchors[0]["section"], start, end, anchors))
    combined.sort(key=lambda alt: (-alt["covered_bytes"], int(alt["start"], 16)))

    result, seen = [], set()
    for alternative in individual + combined:
        key = (alternative["section"], alternative["start"], alternative["end"])
        if key not in seen:
            seen.add(key)
            result.append(alternative)
    return result


def _disposition(unit, alternatives):
    if alternatives:
        return "eligible"
    if unit["code_bytes"] == 0:
        return "zero-code"
    if unit["code_bytes"] < 256:
        return "tiny-code"
    if unit.get("ambiguous_exact_bodies", 0):
        return "ambiguous-shared-evidence"
    reasons = {reason for anchor in unit["anchors"] for reason in anchor["reasons"]}
    if "target range is owned by another explicit unit" in reasons:
        return "overlap"
    if "function range is not split-aligned" in reasons:
        return "alignment"
    return "no-qualifying-anchor"


def prepare(ctx, limit=None):
    ctx.output.mkdir(parents=True, exist_ok=True)
    baseline = ctx.build()
    evidence_path = ctx.output / "coverage-evidence.json"
    try:
        ctx.run([ctx.dtk, "match", f"config/{ctx.source}/config.yml",
                 f"config/{ctx.target}/config.yml", "--coverage", evidence_path])
    except TRIAL_ERRORS as error:
        log = (ctx.output / "build.log").read_text(encoding="utf-8", errors="replace")
        if "coverage" in log.lower() and ("unrecognized" in log.lower() or "unknown" in log.lower()):
            raise RuntimeError("DTK does not support `match --coverage`; build the coverage-capable DTK revision") from error
        raise
    if not evidence_path.is_file():
        raise RuntimeError("DTK completed without writing coverage evidence")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if evidence.get("schema") != EVIDENCE_SCHEMA or evidence.get("policy", {}).get("version") != POLICY_VERSION:
        raise RuntimeError("Unsupported DTK coverage evidence schema or policy")

    splits = ctx.root / "config" / ctx.target / "splits.txt"
    _, target_blocks, _ = scl.parse_splits(splits.read_text(encoding="utf-8"))
    source_units = [unit for unit in evidence["source_units"] if not unit.get("autogenerated")]
    missing = [unit for unit in source_units if unit["name"] not in target_blocks]
    dispositions, candidates = {}, []
    for unit in missing:
        alternatives = build_alternatives(unit, target_blocks)
        dispositions[unit["name"]] = _disposition(unit, alternatives)
        if alternatives:
            candidates.append({
                "name": unit["name"],
                "policy_version": POLICY_VERSION,
                "source_code_bytes": unit["code_bytes"],
                "alternatives": alternatives,
            })
    candidates.sort(key=lambda candidate: (-max(alt["covered_bytes"] for alt in candidate["alternatives"]),
                                            candidate["name"]))
    if limit is not None:
        candidates = candidates[:limit]
    return {
        "candidates": candidates,
        "baseline": baseline,
        "events": [],
        "inventory": {
            "evidence_schema": evidence["schema"],
            "policy": evidence["policy"],
            "source": evidence["source"],
            "target": evidence["target"],
            "source_units": len(source_units),
            "baseline_represented": len({unit["name"] for unit in source_units} & set(target_blocks)),
            "missing": len(missing),
            "dispositions": dispositions,
        },
    }


def _normalize(root, value):
    return os.path.normcase(os.path.normpath(str(root / Path(value.replace("\\", "/")))))


def _validate_extracted_inputs(ctx, names, report):
    inputs = ctx.run([ctx.ninja, "-t", "inputs", f"build/{ctx.target}/main.elf"], capture=True)
    inputs = {_normalize(ctx.root, line) for line in inputs.splitlines() if line.strip()}
    objdiff = json.loads((ctx.root / "objdiff.json").read_text(encoding="utf-8"))
    target_paths = {_normalize(ctx.root, unit.get("target_path", "")): unit
                    for unit in objdiff["units"] if unit.get("target_path")}
    units = by_path(report)
    for name in names:
        object_name = str(PurePosixPath(name).with_suffix(".o"))
        expected = _normalize(ctx.root, f"build/{ctx.target}/obj/{object_name}")
        unit = target_paths.get(expected)
        if unit is None or expected not in inputs:
            raise ValidationError(f"{name}'s extracted target object is not an input to main.elf")
        base = unit.get("base_path")
        if base and _normalize(ctx.root, base) in inputs:
            raise ValidationError(f"{name}'s compiled source object was enabled during coverage")
        if units.get(name, {}).get("metadata", {}).get("complete") is True:
            raise ValidationError(f"{name} was marked complete during coverage")


def _failure_category(error, log):
    text = f"{error}\n{log}".lower()
    if "retail dol bytes differ" in text or "checksum" in text:
        return "retail-mismatch"
    if "cycle" in text:
        return "link-order-cycle"
    if "undefined:" in text or "undefined symbol" in text:
        return "undefined-symbol"
    if "multiply defined" in text or "duplicate symbol" in text:
        return "duplicate-symbol"
    if "invalid alignment" in text or "split alignment" in text:
        return "split-alignment"
    if "cannot open" in text or "no such file" in text or "fatal error" in text:
        return "compilation-missing-include"
    if "compiled source object was enabled" in text or "extracted target object is not" in text:
        return "source-linkage-violation"
    if "regresses an existing unit" in text or "reduces source-linked code" in text:
        return "regression"
    if "compilation terminated" in text or "mwcc fatal" in text or "syntax error" in text:
        return "compilation-failure"
    return "unknown-failure"


def validate(ctx, candidates, selected):
    expected = {candidate["name"]: candidate for candidate in candidates}
    if set(selected) != set(expected):
        raise ValidationError("Coverage selection does not match accepted candidates")
    for name, alternative_id in selected.items():
        if alternative_id not in {alternative["id"] for alternative in expected[name]["alternatives"]}:
            raise ValidationError(f"Unknown coverage alternative for {name}")
    report = ctx.build()
    _validate_extracted_inputs(ctx, set(expected), report)
    return report


def evaluate(ctx, candidates, preferred=None):
    splits = ctx.root / "config" / ctx.target / "splits.txt"
    original = splits.read_bytes()
    owned = original
    header, blocks, order = scl.parse_splits(original.decode("utf-8"))
    report = ctx.build()
    starting_complete = _int_measure(report, "complete_code")
    accepted, deferred, selected, events = [], [], {}, []
    preferred = preferred or {}

    def write():
        nonlocal owned
        owned = _write_splits(splits, header, blocks, order, owned)

    try:
        if len({candidate["name"] for candidate in candidates}) != len(candidates):
            raise ValueError("Duplicate coverage candidate names")
        for candidate in candidates:
            alternatives = list(candidate["alternatives"])
            wanted = preferred.get(candidate["name"])
            alternatives.sort(key=lambda alternative: alternative["id"] != wanted if wanted else False)
            chosen = None
            for alternative in alternatives:
                before_log = (ctx.output / "build.log").stat().st_size if (ctx.output / "build.log").exists() else 0
                blocks[candidate["name"]] = alternative["lines"]
                if candidate["name"] not in order:
                    order.append(candidate["name"])
                write()
                try:
                    tested = ctx.build()
                    _validate_extracted_inputs(ctx, {candidate["name"]}, tested)
                    if _regresses(report, tested):
                        raise ValidationError("coverage candidate regresses an existing unit")
                    if _int_measure(tested, "complete_code") < starting_complete:
                        raise ValidationError("coverage candidate reduces source-linked code")
                except TRIAL_ERRORS as error:
                    blocks.pop(candidate["name"], None)
                    if candidate["name"] in order:
                        order.remove(candidate["name"])
                    write()
                    log_path = ctx.output / "build.log"
                    log = log_path.read_text(encoding="utf-8", errors="replace")[before_log:] if log_path.exists() else ""
                    events.append({"unit": candidate["name"], "alternative": alternative["id"],
                                   "status": "rejected", "category": _failure_category(error, log),
                                   "reason": str(error),
                                   "exit_status": getattr(error, "returncode", None),
                                   "log": str(log_path)})
                    continue
                chosen, report = alternative, tested
                break
            if chosen is None:
                deferred.append(candidate)
                continue
            accepted.append(candidate)
            selected[candidate["name"]] = chosen["id"]
            events.append({"unit": candidate["name"], "alternative": chosen["id"],
                           "status": "accepted", "covered_bytes": chosen["covered_bytes"]})
        write()
        final = validate(ctx, accepted, selected)
        if _regresses(report, final):
            raise RuntimeError("Final coverage report regressed after validation")
        return {"accepted": accepted, "deferred": deferred, "selected": selected,
                "events": events, "report": final, "validation": VALIDATION}
    except BaseException:
        if splits.read_bytes() == owned:
            _replace(splits, original, owned)
        raise


def summary(prepared, result):
    inventory = prepared["inventory"]
    alternatives = {candidate["name"]: {alt["id"]: alt for alt in candidate["alternatives"]}
                    for candidate in result["accepted"]}
    selected = {name: alternatives[name][identity] for name, identity in result["selected"].items()}
    dispositions = dict(inventory["dispositions"])
    for name in result["selected"]:
        dispositions[name] = "accepted"
    rejected = {event["unit"] for event in result["events"] if event["status"] == "rejected"}
    for candidate in result["deferred"]:
        dispositions[candidate["name"]] = (
            "build-failure" if candidate["name"] in rejected else "deferred")
    baseline_measures = result["baseline"]
    final_measures = result["report"]["measures"]
    return {
        "schema": EVIDENCE_SCHEMA,
        "policy": inventory["policy"],
        "source": inventory["source"],
        "target": inventory["target"],
        "source_units": inventory["source_units"],
        "baseline_represented": inventory["baseline_represented"],
        "final_represented": inventory["baseline_represented"] + len(selected),
        "newly_supported_units": len(selected),
        "newly_assigned_code_bytes": sum(alt["covered_bytes"] for alt in selected.values()),
        "candidate_evidence": prepared["candidates"],
        "selected": selected,
        "dispositions": dispositions,
        "events": result["events"],
        "metrics": {
            "representation": {
                "baseline_tus": inventory["baseline_represented"],
                "final_tus": inventory["baseline_represented"] + len(selected),
                "source_tus": inventory["source_units"],
            },
            "objdiff_matching": {
                "baseline_code_bytes": int(baseline_measures.get("matched_code", 0)),
                "final_code_bytes": int(final_measures.get("matched_code", 0)),
            },
            "configured_source_linkage": {
                "baseline_code_bytes": int(baseline_measures.get("complete_code", 0)),
                "final_code_bytes": int(final_measures.get("complete_code", 0)),
            },
            "verified_source_linkage": {
                "new_units": 0,
                "new_code_bytes": 0,
                "reason": "coverage keeps candidate source objects disabled",
            },
        },
        "measures": final_measures,
        "validation": result["validation"],
    }


def markdown_summary(value):
    lines = ["# Coverage stage result", "",
             f"- Represented source TUs: {value['baseline_represented']} → {value['final_represented']} / {value['source_units']}",
             f"- Newly supported TUs: {value['newly_supported_units']}",
             f"- Newly assigned code bytes: {value['newly_assigned_code_bytes']}",
             f"- Validation: `{value['validation']}`", "",
             "This stage certifies only the newly selected ranges; pre-existing ownership is not re-certified.",
             "", "## Separate progress metrics", "",
             "| Metric | Baseline | Final |", "|---|---:|---:|",
             f"| Represented source TUs | {value['metrics']['representation']['baseline_tus']} | {value['metrics']['representation']['final_tus']} |",
             f"| Objdiff-matched code bytes | {value['metrics']['objdiff_matching']['baseline_code_bytes']} | {value['metrics']['objdiff_matching']['final_code_bytes']} |",
             f"| Configured source-linked code bytes | {value['metrics']['configured_source_linkage']['baseline_code_bytes']} | {value['metrics']['configured_source_linkage']['final_code_bytes']} |",
             "| Newly verified source-linked code bytes | 0 | 0 |",
             "", "## Selected ranges", ""]
    if value["selected"]:
        lines.extend(["| TU | Section | Range | Bytes |", "|---|---|---:|---:|"])
        for name, alternative in sorted(value["selected"].items()):
            lines.append(f"| `{name}` | `{alternative['section']}` | `{alternative['start']}..{alternative['end']}` | {alternative['covered_bytes']} |")
    else:
        lines.append("No range passed the coverage gates.")
    lines.extend(["", "## Remaining dispositions", ""])
    counts = {}
    for disposition in value["dispositions"].values():
        counts[disposition] = counts.get(disposition, 0) + 1
    for disposition, count in sorted(counts.items()):
        lines.append(f"- {disposition}: {count}")
    return "\n".join(lines) + "\n"
