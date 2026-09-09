#!/usr/bin/env python3
"""Evaluate coverage ownership without exposing target names or splits to proposals."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import coverage_adapter as coverage
import split_confidence_loop as scl


def partition(name):
    return (
        "calibration" if hashlib.sha256(name.encode()).digest()[0] < 128 else "held-out"
    )


def _range_state(name, section, start, end, oracle_blocks):
    own_ranges = [
        value
        for line in oracle_blocks.get(name, [])
        if (value := scl.parse_range(line)) and value[0] == section
    ]
    if any(left <= start and end <= right for _, left, right in own_ranges):
        return "correct"
    overlaps_other = any(
        section == other_section and start < right and left < end
        for other_name, lines in oracle_blocks.items()
        if other_name != name
        for line in lines
        if (value := scl.parse_range(line))
        for other_section, left, right in [value]
    )
    return "incorrect" if overlaps_other else "unknown"


def ownership_at_layout(target_layout, oracle_blocks):
    result = {}
    parsed = {
        name: [value for line in lines if (value := scl.parse_range(line))]
        for name, lines in oracle_blocks.items()
    }
    for item in target_layout:
        address = int(item["address"], 16)
        owners = [
            name
            for name, ranges in parsed.items()
            if any(
                section == item["section"] and start <= address < end
                for section, start, end in ranges
            )
        ]
        result[(item["section"], item["address"])] = (
            owners[0] if len(owners) == 1 else None
        )
    return result


def score_candidate(candidate, oracle_blocks, oracle_owners):
    scored_alternatives = []
    unique_anchors = {}
    for alternative in candidate["alternatives"]:
        section = alternative["section"]
        start, end = int(alternative["start"], 16), int(alternative["end"], 16)
        scored_alternatives.append(
            {
                "id": alternative["id"],
                "evidence": alternative.get("evidence", "exact-body"),
                "state": _range_state(
                    candidate["name"], section, start, end, oracle_blocks
                ),
            }
        )
        for anchor in alternative["anchors"]:
            unique_anchors[
                (
                    alternative.get("evidence", "exact-body"),
                    anchor["section"],
                    anchor["target_address"],
                )
            ] = anchor
    anchors = [
        {
            "address": anchor["target_address"],
            "evidence": key[0],
            "state": (
                "correct"
                if oracle_owners.get((anchor["section"], anchor["target_address"]))
                == candidate["name"]
                else "unknown"
                if oracle_owners.get((anchor["section"], anchor["target_address"]))
                is None
                else "incorrect"
            ),
        }
        for key, anchor in unique_anchors.items()
    ]
    return {
        "name": candidate["name"],
        "partition": partition(candidate["name"]),
        "selected_alternative": candidate["alternatives"][0],
        "alternatives": scored_alternatives,
        "anchors": anchors,
    }


def summarize(records):
    result = {}
    for name in ("calibration", "held-out"):
        rows = [record for record in records if record["partition"] == name]
        anchors = [anchor for row in rows for anchor in row["anchors"]]
        alternatives = [
            alternative for row in rows for alternative in row["alternatives"]
        ]
        result[name] = {
            "tus": len(rows),
            "ranges": len(alternatives),
            "ranges_correct": sum(
                alternative["state"] == "correct" for alternative in alternatives
            ),
            "ranges_incorrect": sum(
                alternative["state"] == "incorrect" for alternative in alternatives
            ),
            "ranges_unknown": sum(
                alternative["state"] == "unknown" for alternative in alternatives
            ),
            "anchors": len(anchors),
            "anchors_correct": sum(anchor["state"] == "correct" for anchor in anchors),
            "anchors_incorrect": sum(
                anchor["state"] == "incorrect" for anchor in anchors
            ),
            "anchors_unknown": sum(anchor["state"] == "unknown" for anchor in anchors),
            "represented_bytes": sum(
                row["selected_alternative"]["covered_bytes"]
                for row in rows
                if row["alternatives"][0]["state"] == "correct"
            ),
            "evidence": {
                evidence: {
                    "ranges": sum(
                        alternative["evidence"] == evidence
                        for alternative in alternatives
                    ),
                    "ranges_incorrect": sum(
                        alternative["evidence"] == evidence
                        and alternative["state"] == "incorrect"
                        for alternative in alternatives
                    ),
                    "ranges_unknown": sum(
                        alternative["evidence"] == evidence
                        and alternative["state"] == "unknown"
                        for alternative in alternatives
                    ),
                    "anchors": sum(
                        anchor["evidence"] == evidence for anchor in anchors
                    ),
                    "anchors_incorrect": sum(
                        anchor["evidence"] == evidence
                        and anchor["state"] == "incorrect"
                        for anchor in anchors
                    ),
                    "anchors_unknown": sum(
                        anchor["evidence"] == evidence and anchor["state"] == "unknown"
                        for anchor in anchors
                    ),
                }
                for evidence in ("exact-body", "this-layout-shift")
            },
        }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--source", default="GM8E01_00")
    parser.add_argument("--target", default="GM8E01_02")
    parser.add_argument("--dtk", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--oracle-splits",
        type=Path,
        help="independent target splits used only for scoring",
    )
    args = parser.parse_args(argv)
    root, dtk = args.project_root.resolve(), args.dtk.resolve(strict=True)
    with dtk.open("rb") as stream:
        dtk_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    output = (
        args.output or root / "build" / args.target / "coverage-calibration"
    ).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source_config, target_config = (
        f"config/{args.source}/config.yml",
        f"config/{args.target}/config.yml",
    )
    masked, oracle = output / "masked-evidence.json", output / "oracle-evidence.json"
    subprocess.run(
        [
            dtk,
            "match",
            source_config,
            target_config,
            "--validate",
            "--coverage",
            masked,
        ],
        cwd=root,
        check=True,
    )
    subprocess.run(
        [dtk, "match", source_config, target_config, "--coverage", oracle],
        cwd=root,
        check=True,
    )
    with dtk.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != dtk_sha256:
            raise RuntimeError("DTK changed during coverage calibration")
    masked_value = json.loads(masked.read_text(encoding="utf-8"))
    oracle_value = json.loads(oracle.read_text(encoding="utf-8"))
    if not masked_value.get("target_ownership_masked") or oracle_value.get(
        "target_ownership_masked"
    ):
        raise RuntimeError("DTK did not isolate target ownership for calibration")
    for value in (masked_value, oracle_value):
        if (
            value.get("schema") != coverage.EVIDENCE_SCHEMA
            or value.get("policy", {}).get("version") != coverage.POLICY_VERSION
        ):
            raise RuntimeError("Unsupported DTK coverage evidence schema or policy")

    oracle_splits = (
        args.oracle_splits.resolve()
        if args.oracle_splits
        else root / "config" / args.target / "splits.txt"
    )
    _, oracle_blocks, _ = scl.parse_splits(oracle_splits.read_text(encoding="utf-8"))
    oracle_owners = ownership_at_layout(oracle_value["target_layout"], oracle_blocks)
    candidates: list[dict[str, Any]] = []
    for unit in masked_value["source_units"]:
        if unit.get("autogenerated") or unit["name"] not in oracle_blocks:
            continue
        alternatives = coverage.build_alternatives(unit, {})
        if alternatives:
            candidates.append(
                {
                    "name": unit["name"],
                    "policy_version": coverage.POLICY_VERSION,
                    "source_code_bytes": unit["code_bytes"],
                    "alternatives": alternatives,
                }
            )
    candidates.sort(
        key=lambda candidate: (
            -max(a["covered_bytes"] for a in candidate["alternatives"]),
            candidate["name"],
        )
    )
    records = [
        score_candidate(candidate, oracle_blocks, oracle_owners)
        for candidate in candidates
    ]
    measures = summarize(records)
    result = {
        "schema": 2,
        "policy": masked_value["policy"],
        "source": args.source,
        "target": args.target,
        "oracle_splits": str(oracle_splits),
        "partition": "sha256-first-byte-less-than-128",
        "dtk_sha256": dtk_sha256,
        "records": records,
        "measures": measures,
    }
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Coverage calibration",
        "",
        f"Policy version: {masked_value['policy']['version']}",
        "",
        "| Partition | TUs | Ranges | Correct | Unknown | Incorrect | Anchors correct | Unknown | Incorrect | Bytes |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, value in measures.items():
        lines.append(
            f"| {name} | {value['tus']} | {value['ranges']} | {value['ranges_correct']} | "
            f"{value['ranges_unknown']} | {value['ranges_incorrect']} | {value['anchors_correct']} | "
            f"{value['anchors_unknown']} | {value['anchors_incorrect']} | {value['represented_bytes']} |"
        )
    (output / "result.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(measures, indent=2))
    if any(
        value["ranges_incorrect"] or value["anchors_incorrect"]
        for value in measures.values()
    ):
        raise SystemExit("Coverage policy produced an incorrect ownership assignment")


if __name__ == "__main__":
    main()
