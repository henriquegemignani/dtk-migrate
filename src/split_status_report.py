#!/usr/bin/env python3

###
# Writes a per-unit migration status report for a target version, comparing
# its splits.txt against a known source version's and, for units not yet
# migrated, dtk match's current proposal -- run through the same
# reduction/filtering pipeline split_confidence_loop.py applies before
# staging (fragmented-run bridging and dominant-cluster reduction, alignment
# filtering, boundary-artifact detection), so the "why isn't this present"
# column reflects what the promotion loop actually sees, not a raw dtk match
# dump. Read-only: never touches splits.txt, symbols.txt, or the skip list.
#
# Usage (run from the project's root directory, after a `dtk match --splits`
# and a real build have populated build/<target>/):
#   python /path/to/src/split_status_report.py --target GM8P01_00
###

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path

ROOT_DIR = Path.cwd()
SCRIPT_DIR = Path(__file__).resolve().parent

spec = importlib.util.spec_from_file_location(
    "scl", str(SCRIPT_DIR / "split_confidence_loop.py")
)
scl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scl)

CANDIDATE_REASON_RE = re.compile(r"#\s*candidate:\s*(.+)$")


def section_range(s):
    start = int(s["metadata"]["virtual_address"])
    return start, start + int(s["size"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default="GM8E01_00",
        help="source version (the one with known names)",
    )
    parser.add_argument("--target", required=True, help="target version to report on")
    parser.add_argument(
        "--proposals",
        type=Path,
        help="DTK proposal file (default: newest discovery/legacy proposal)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="where to write the report (default: docs/<target>_split_status.md)",
    )
    args = parser.parse_args()

    ntsc_text = (ROOT_DIR / "config" / args.source / "splits.txt").read_text(
        encoding="utf-8"
    )
    pal_text = (ROOT_DIR / "config" / args.target / "splits.txt").read_text(
        encoding="utf-8"
    )
    _, ntsc_blocks, ntsc_order = scl.parse_splits(ntsc_text)
    _, pal_blocks, pal_order = scl.parse_splits(pal_text)

    proposal_options = [
        ROOT_DIR / "build" / args.target / "match_candidates.txt",
        ROOT_DIR / "build" / args.target / "discovery" / "proposals.txt",
    ]
    proposal_path = args.proposals or max(
        (p for p in proposal_options if p.exists()),
        key=lambda p: p.stat().st_mtime,
        default=proposal_options[0],
    )
    if not proposal_path.exists():
        parser.error(
            f"{proposal_path} not found -- run split_confidence_loop.py (or `dtk match --splits`) first"
        )
    proposal_raw_text = proposal_path.read_text(encoding="utf-8")
    _, proposal_blocks, proposal_order = scl.parse_splits(proposal_raw_text)
    raw_proposal_blocks = scl.raw_proposal_lines(proposal_raw_text)

    report_path = ROOT_DIR / "build" / args.target / "report.json"
    if not report_path.exists():
        parser.error(
            f"{report_path} not found -- run `ninja build/{args.target}/report.json` first"
        )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    by_source_path = {}
    for u in report["units"]:
        sp = u.get("metadata", {}).get("source_path", "")
        if sp:
            by_source_path[scl.strip_source_root(sp)] = u

    skip_path = ROOT_DIR / "build" / args.target / "split_confidence_skip.txt"
    skip_reasons = scl.load_skip_list_with_reasons(skip_path)
    neighbors = scl.SymbolNeighbors(ROOT_DIR / "config" / args.target / "symbols.txt")

    def existing_status(name: str):
        unit = by_source_path.get(name)
        if unit is None:
            return (
                "exists, but not matching/linked",
                "no diffable entry in the report; compilation and linkage are unverified",
                "Regenerate the report and check source availability and path mapping.",
                "no diffable report entry",
            )

        bad = [
            s
            for s in unit.get("sections") or []
            if s.get("fuzzy_match_percent", 0.0) < 100.0
        ]
        linked = unit.get("metadata", {}).get("complete") is True
        if linked:
            return (
                "configured to link from source",
                "Link flag is not evidence of a fresh retail hash check.",
                "",
                "source link enabled",
            )
        if not unit.get("sections"):
            return (
                "exists; comparison unavailable",
                "No comparable sections in the report.",
                "Check source availability and report generation.",
                "comparison unavailable",
            )
        if unit.get("sections") and not bad:
            return (
                "comparison matches; source not linked",
                "Whole-file output has not been hash-verified.",
                "Test the compiled object as a real link input before enabling MatchingFor.",
                "comparison matches",
            )
        worst = min(bad, key=lambda s: s.get("fuzzy_match_percent", 0.0))
        detail = "; ".join(
            f"{s['name']} {s.get('fuzzy_match_percent', 0.0):.2f}%" for s in bad
        )
        text_mismatch = any(s["name"] in (".text", ".init") for s in bad)
        boundary_artifact = not text_mismatch and all(
            neighbors.borders_unclaimed(*section_range(s)) for s in bad
        )
        if boundary_artifact:
            improve = (
                "An adjacent auto symbol suggests a possible boundary artifact, but does not prove it. "
                "Compare using a link that actually includes this compiled source object."
            )
            subcat = "likely boundary artifact"
        else:
            improve = (
                f"{worst['name']} doesn't border an unclaimed/auto-named neighbor, so this isn't the "
                "known boundary-bleed pattern; needs manual investigation to tell a real content "
                "mismatch from a misplaced boundary with an already-named sibling unit."
            )
            subcat = "unclear mismatch, needs investigation"
        return "exists, but not matching/linked", detail, improve, subcat

    def missing_status(name: str):
        if name in skip_reasons:
            reason = skip_reasons[name]
            return (
                "not present",
                f"rejected: {reason}",
                "A previous proposal failed a check. Retry after tooling, symbols or boundaries change; "
                "failure of one proposal does not rule out this unit.",
                "previous proposal rejected",
            )

        lines = proposal_blocks.get(name)
        if lines is None:
            return (
                "not present",
                "dtk match found no functions from this source unit with a plausible correspondence in the target",
                "Investigate attribution and improve automated proposal generation; a missing proposal "
                "does not prove the code is absent.",
                "no candidate found",
            )

        raw_lines = raw_proposal_blocks.get(name, [])
        was_fragmented = scl.is_fragmented(lines)
        if was_fragmented:
            reduced = scl.dominant_cluster(raw_lines)
            if reduced is None:
                return (
                    "not present",
                    "matcher proposed disjoint ranges in the same section, and every range in each "
                    "fragmented section is itself misaligned -- no valid boundary to even guess",
                    "Needs manual investigation of the real boundary; dtk's own bridging (for small "
                    "unmatched-function gaps) and dominant_cluster (for larger gaps) both gave up here.",
                    "fragmented, unresolvable",
                )
            lines = reduced

        aligned_lines = scl.drop_misaligned_sections(lines, raw_lines)
        if not aligned_lines:
            return (
                "not present",
                "every section dtk match proposed for this unit fails the target section's alignment "
                "requirement (ALIGNMENT_REASON) -- dtk dol split would hard-reject it",
                "Needs a correctly-aligned boundary found manually; the proposed one(s) can't be staged as-is.",
                "misaligned proposal",
            )
        dropped_for_alignment = len(aligned_lines) != len(lines)
        lines = aligned_lines

        reasons = set()
        for line in raw_lines:
            m = CANDIDATE_REASON_RE.search(line)
            if m:
                for part in m.group(1).split(";"):
                    reasons.add(part.strip())

        subcat_bits = []
        if was_fragmented:
            subcat_bits.append("reduced from fragmented")
        if dropped_for_alignment:
            subcat_bits.append("a section dropped for misalignment")

        if not reasons:
            detail = "candidate boundary proposed, every function individually confident-tier -- not yet tried"
            improve = "Run another promotion round; this is a strong candidate."
            subcat = ", ".join(subcat_bits) or "confident candidate, untried"
            return "not present", detail, improve, subcat

        reason_text = "; ".join(sorted(reasons))
        improve = (
            "Awaiting a neighboring unit's boundary to be claimed, or byte-verification should confirm it "
            "directly if the mismatch is a boundary artifact."
            if "borders" in reason_text or "unclaimed" in reason_text
            else "Needs its target functions' non-text content matched/migrated too before this can be staged."
            if "non-text content" in reason_text
            else "Needs the missing target functions to be matched first, or the split alignment fixed."
            if "missing functions" in reason_text or "alignment" in reason_text
            else "Run another promotion round once blockers above are cleared; may need manual review."
        )
        subcat = (
            ", ".join(subcat_bits + ["unit-tier issues"])
            if subcat_bits
            else "candidate proposed, unit-tier issues"
        )
        return (
            "not present",
            f"candidate proposed but unit-tier Candidate: {reason_text}",
            improve,
            subcat,
        )

    rows = []
    for name in ntsc_order:
        if name in pal_blocks:
            status, detail, improve, subcat = existing_status(name)
        else:
            status, detail, improve, subcat = missing_status(name)
        rows.append((name, status, detail, improve, subcat))

    counts = Counter(r[1] for r in rows)
    subcounts = Counter((r[1], r[4]) for r in rows)
    print("Summary:", dict(counts))

    out_path = args.output or (ROOT_DIR / "docs" / f"{args.target}_split_status.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# {args.target} split migration status\n\n")
        f.write(
            f"Generated by comparing every unit split in `config/{args.source}/splits.txt` (source) "
            f"against `config/{args.target}/splits.txt` (target) and, for units not yet migrated, the "
            "latest available `dtk match` proposal. Missing-unit explanations use the historical "
            "loop's reduction heuristics; discovery can retain useful partial code that these "
            "heuristics discard. Proposal and report files can become stale after changes.\n\n"
        )
        f.write("## Summary\n\n")
        measures = report["measures"]
        f.write(
            f"- Objdiff matched code: {measures.get('matched_code_percent', 0):.3f}% "
            f"({measures.get('matched_code', 0)} / {measures.get('total_code', 0)} bytes)\n"
        )
        f.write(
            f"- Configured source-linked code: {measures.get('complete_code_percent', 0):.3f}%\n"
        )
        f.write(
            "- Split presence, objdiff matching, and retail-hash-verified source linkage are distinct.\n"
        )
        f.write(f"- Total {args.source} units: {len(rows)}\n")
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            f.write(f"- **{k}**: {v} ({v / len(rows):.1%})\n")
            subs = sorted(
                ((sub, n) for (status, sub), n in subcounts.items() if status == k),
                key=lambda x: -x[1],
            )
            if len(subs) > 1 or (len(subs) == 1 and subs[0][0] != "linked"):
                f.writelines(f"  - {sub}: {n}\n" for sub, n in subs)
        f.write("\n## Per-unit status\n\n")
        f.write(
            f"| {args.source} unit | {args.target} status | Detail | Possible improvement |\n"
        )
        f.write("|---|---|---|---|\n")
        for name, status, detail, improve, _subcat in rows:
            name_e = name.replace("|", "\\|")
            detail_e = detail.replace("|", "\\|")
            improve_e = improve.replace("|", "\\|")
            f.write(f"| {name_e} | {status} | {detail_e} | {improve_e} |\n")

    print("wrote", out_path)


if __name__ == "__main__":
    main()
