"""Evidence-backed partial translation-unit coverage in isolated workspaces."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from itertools import pairwise
from pathlib import Path, PurePosixPath

import split_audit
import split_confidence_loop as scl
from discover_splits import by_path, code_bytes
from migration_runtime import TRIAL_ERRORS, ValidationError, trial_build

EVIDENCE_SCHEMA = 8
POLICY_VERSION = 8
VALIDATION = "unique-exact-or-corroborated-layout-or-boundary-sequence-or-bounded-layout-or-vtable-helper-or-ownership-transition-or-adjacent-owner-transition-required-extracts-and-extracted-link-inputs-and-retail-bytes"
MIN_LAYOUT_BOUNDARY_FUNCTIONS = 4
MIN_LAYOUT_BOUNDARY_BYTES = 1024
MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES = 16
MAX_LAYOUT_BOUNDARY_SIZE_DELTA = 0.02
MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA = 1
LAYOUT_BOUNDARY_POLICY = {
    "infer_layout_corroborated_boundaries": True,
    "minimum_layout_boundary_functions": MIN_LAYOUT_BOUNDARY_FUNCTIONS,
    "minimum_layout_boundary_bytes": MIN_LAYOUT_BOUNDARY_BYTES,
    "minimum_layout_boundary_changed_accesses": MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES,
    "maximum_layout_boundary_size_delta": MAX_LAYOUT_BOUNDARY_SIZE_DELTA,
    "maximum_layout_boundary_function_delta": MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA,
}
MIN_VTABLE_BOUNDARY_FUNCTIONS = 8
MIN_VTABLE_BOUNDARY_MATCH_RATIO = 0.85
MIN_VTABLE_BOUNDARY_TARGET_COVERAGE = 0.85
MIN_VTABLE_BOUNDARY_MATCHED_SLOTS = 8
MIN_VTABLE_BOUNDARY_UNIT_SLOTS = 4
MAX_VTABLE_BOUNDARY_SIZE_DELTA = 0.03
MAX_VTABLE_BOUNDARY_FUNCTION_DELTA = 1
MAX_VTABLE_BOUNDARY_GAP_HELPERS = 1
MAX_VTABLE_SIZE_PADDING = 16
VTABLE_BOUNDARY_POLICY = {
    "infer_vtable_corroborated_boundaries": True,
    "minimum_vtable_boundary_functions": MIN_VTABLE_BOUNDARY_FUNCTIONS,
    "minimum_vtable_boundary_match_ratio": MIN_VTABLE_BOUNDARY_MATCH_RATIO,
    "minimum_vtable_boundary_target_coverage": MIN_VTABLE_BOUNDARY_TARGET_COVERAGE,
    "minimum_vtable_boundary_matched_slots": MIN_VTABLE_BOUNDARY_MATCHED_SLOTS,
    "minimum_vtable_boundary_unit_slots": MIN_VTABLE_BOUNDARY_UNIT_SLOTS,
    "maximum_vtable_boundary_size_delta": MAX_VTABLE_BOUNDARY_SIZE_DELTA,
    "maximum_vtable_boundary_function_delta": MAX_VTABLE_BOUNDARY_FUNCTION_DELTA,
    "maximum_vtable_boundary_gap_helpers": MAX_VTABLE_BOUNDARY_GAP_HELPERS,
    "maximum_vtable_size_padding": MAX_VTABLE_SIZE_PADDING,
}
MIN_OWNERSHIP_TRANSITION_FUNCTIONS = 8
MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS = 2
MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS = 1
MAX_OWNERSHIP_TRANSITION_SIZE_DELTA = 0.02
MATCH_TIERS = {"confident", "probable", "candidate"}
STRONG_MATCH_TIERS = {"confident", "probable"}
OWNERSHIP_TRANSITION_POLICY = {
    "infer_ownership_transition_boundaries": True,
    "minimum_ownership_transition_functions": MIN_OWNERSHIP_TRANSITION_FUNCTIONS,
    "minimum_ownership_transition_strong_functions": MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS,
    "minimum_ownership_transition_edge_strong_functions": MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS,
    "maximum_ownership_transition_size_delta": MAX_OWNERSHIP_TRANSITION_SIZE_DELTA,
    "require_complete_ownership_transition_sequence": True,
    "require_nonempty_ownership_transition_correction": True,
}
MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS = 8
MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS = 2
MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS = 2
MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS = 4
MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS = 2
MAX_ADJACENT_OWNER_SIZE_DELTA = 0.10
MAX_ADJACENT_OWNER_GAP_HELPERS = 1
ADJACENT_OWNER_TRANSITION_POLICY = {
    "infer_adjacent_owner_transition_boundaries": True,
    "minimum_adjacent_owner_transition_functions": MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS,
    "minimum_adjacent_owner_transition_strong_functions": MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS,
    "minimum_adjacent_owner_transition_direct_anchors": MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS,
    "minimum_adjacent_owner_support_functions": MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS,
    "minimum_adjacent_owner_support_strong_functions": MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS,
    "maximum_adjacent_owner_size_delta": MAX_ADJACENT_OWNER_SIZE_DELTA,
    "maximum_adjacent_owner_gap_helpers": MAX_ADJACENT_OWNER_GAP_HELPERS,
    "require_complete_adjacent_owner_sequences": True,
    "require_atomic_adjacent_owner_revision": True,
}

_EXTRACT_FIELDS = (
    "symbol",
    "rename",
    "binary",
    "header",
    "relocations",
    "header_type",
    "custom_type",
    "custom_data",
)


def _replace(path, data, expected):
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        if path.read_bytes() != expected:
            raise RuntimeError(
                f"{path.name} changed during coverage trial; refusing to overwrite edits"
            )
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


def _yaml_value(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _validate_extract_path(value):
    if not isinstance(value, str) or not value:
        raise ValueError(f"Unsafe required extract path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(
        part in {".", ".."} or ":" in part or "\\" in part for part in path.parts
    ):
        raise ValueError(f"Unsafe required extract path: {value!r}")


def _extract_block(lines):
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if re.match(r"^extract:\s*(?:#.*)?(?:\r?\n)?$", line)
        ),
        None,
    )
    if start is None:
        return None
    end = start + 1
    while end < len(lines):
        line = lines[end]
        if (
            line.strip()
            and not line.lstrip().startswith("#")
            and re.match(r"^[A-Za-z_][^:]*:", line)
        ):
            break
        end += 1
    return start, end


def _configured_extract_symbols(lines, start, end):
    symbols = set()
    for line in lines[start + 1 : end]:
        match = re.match(r"^\s*-\s+symbol:\s*(.*?)\s*(?:\r?\n)?$", line)
        if not match:
            continue
        value = match.group(1)
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = value.split(" #", 1)[0].strip().strip("'\"")
        if isinstance(value, str):
            symbols.add(value)
    return symbols


def render_required_extracts(data, extracts):
    """Add active top-level extracts while preserving all unrelated YAML bytes."""
    if not extracts:
        return data
    text = data.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    block = _extract_block(lines)
    created = block is None
    if block is None:
        insert = next(
            (
                index
                for index, line in enumerate(lines)
                if re.match(r"^modules:\s*", line)
            ),
            len(lines),
        )
        lines[insert:insert] = [f"extract:{newline}"]
        block = (insert, insert + 1)
    start, end = block
    configured = _configured_extract_symbols(lines, start, end)
    pending = []
    for extract in extracts:
        symbol = extract.get("target_symbol")
        if not isinstance(symbol, str) or not symbol:
            raise ValueError("Required extract has no target symbol")
        for field in ("binary", "header", "relocations"):
            if value := extract.get(field):
                _validate_extract_path(value)
        if symbol in configured:
            continue
        pending.append(extract)
        configured.add(symbol)
    if not pending:
        return data

    list_indent = next(
        (
            match.group(1)
            for line in lines[start + 1 : end]
            if (match := re.match(r"^(\s*)-\s+", line))
        ),
        "",
    )
    item_lines = []
    for extract in pending:
        values = {
            "symbol": extract["target_symbol"],
            "rename": extract.get("rename"),
            "binary": extract.get("binary"),
            "header": extract.get("header"),
            "relocations": extract.get("relocations"),
            "header_type": extract.get("header_type"),
            "custom_type": extract.get("custom_type"),
            "custom_data": extract.get("custom_data"),
        }
        item_lines.append(
            f"{list_indent}- symbol: {_yaml_value(values['symbol'])}{newline}"
        )
        for field in _EXTRACT_FIELDS[1:]:
            if values[field] is not None:
                item_lines.append(
                    f"{list_indent}  {field}: {_yaml_value(values[field])}{newline}"
                )
    if created and end < len(lines) and lines[end].strip():
        item_lines.append(newline)

    insert = end
    while insert > start + 1 and not lines[insert - 1].strip():
        insert -= 1
    if insert > 0 and not lines[insert - 1].endswith(("\n", "\r")):
        lines[insert - 1] += newline
    lines[insert:insert] = item_lines
    return "".join(lines).encode("utf-8")


def _write_required_extracts(path, extracts, expected):
    data = render_required_extracts(expected, extracts)
    if data != expected:
        _replace(path, data, expected)
    return data


def _int_measure(report, name):
    return int(report.get("measures", {}).get(name, 0))


def _regresses(before, after):
    old, new = by_path(before), by_path(after)
    return any(
        code_bytes(new.get(name, {})) < code_bytes(unit) for name, unit in old.items()
    )


def _ranges(lines):
    return [value for line in lines if (value := scl.parse_range(line))]


def _overlaps_existing(section, start, end, blocks):
    return any(
        section == other_section and start < other_end and other_start < end
        for lines in blocks.values()
        for other_section, other_start, other_end in _ranges(lines)
    )


def _alternative(
    section,
    start,
    end,
    anchors,
    *,
    evidence="exact-body",
    group=None,
    owner_revisions=None,
):
    owner_revisions = owner_revisions or []
    identity = (
        f"{evidence}:{group or ''}:{section}:{start:08X}-{end:08X}:"
        f"{json.dumps(owner_revisions, sort_keys=True, separators=(',', ':'))}"
    )
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:16],
        "evidence": evidence,
        "support_group": group,
        "section": section,
        "start": f"0x{start:08X}",
        "end": f"0x{end:08X}",
        "covered_bytes": end - start,
        "lines": [f"\t{section:11} start:0x{start:08X} end:0x{end:08X}"],
        "anchors": anchors,
        "owner_revisions": owner_revisions,
    }


def _valid_transition_edge(edge, unit, start, end):
    functions = edge.get("functions", [])
    ranges = [
        (int(item["target_address"], 16), int(item["target_end"], 16))
        for item in functions
    ]
    source_addresses = [int(item["source_address"], 16) for item in functions]
    tiers = [item.get("tier") for item in functions]
    strong = sum(tier in STRONG_MATCH_TIERS for tier in tiers)
    if (
        edge.get("unit") != unit
        or int(edge.get("start", "0"), 16) != start
        or int(edge.get("end", "0"), 16) != end
        or edge.get("bytes") != end - start
        or edge.get("strong_functions") != strong
        or any(tier not in MATCH_TIERS for tier in tiers)
        or any(
            right <= left or right - left != item.get("size")
            for item, (left, right) in zip(functions, ranges)
        )
        or source_addresses != sorted(source_addresses)
        or len(set(source_addresses)) != len(source_addresses)
        or any(
            left_end != right_start
            for (_, left_end), (right_start, _) in pairwise(ranges)
        )
    ):
        return False
    if start == end:
        return not functions and strong == 0
    return (
        bool(functions)
        and ranges[0][0] == start
        and ranges[-1][1] == end
        and strong >= MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS
    )


def _single_section_range(blocks, unit, section):
    ranges = [
        value
        for line in blocks.get(unit, [])
        if (value := scl.parse_range(line)) and value[0] == section
    ]
    return ranges[0] if len(ranges) == 1 else None


def _relative_size_delta(source_bytes, target_bytes):
    base = max(source_bytes, target_bytes)
    return abs(source_bytes - target_bytes) / base if base else 0.0


def _sequence_details(functions):
    try:
        source_addresses = [int(item["source_address"], 16) for item in functions]
        target_ranges = [
            (int(item["target_address"], 16), int(item["target_end"], 16))
            for item in functions
        ]
        tiers = [item.get("tier") for item in functions]
    except KeyError, TypeError, ValueError:
        return None
    if (
        any(tier not in MATCH_TIERS for tier in tiers)
        or any(not item.get("primary") for item in functions)
        or source_addresses != sorted(source_addresses)
        or len(set(source_addresses)) != len(source_addresses)
        or any(
            right <= left or right - left != item.get("size")
            for item, (left, right) in zip(functions, target_ranges)
        )
        or any(
            left_end > right_start
            for (_, left_end), (right_start, _) in pairwise(target_ranges)
        )
    ):
        return None
    return target_ranges, sum(tier in STRONG_MATCH_TIERS for tier in tiers)


def _partition_covers(start, end, function_ranges, helpers):
    try:
        helper_ranges = [
            (int(helper["target_address"], 16), int(helper["target_end"], 16))
            for helper in helpers
        ]
    except KeyError, TypeError, ValueError:
        return False
    pieces = sorted(function_ranges + helper_ranges)
    return (
        bool(pieces)
        and pieces[0][0] == start
        and pieces[-1][1] == end
        and all(right > left for left, right in pieces)
        and all(
            left_end == right_start
            for (_, left_end), (right_start, _) in pairwise(pieces)
        )
        and all(
            right - left == helper.get("size")
            for helper, (left, right) in zip(helpers, helper_ranges)
        )
    )


def _direct_anchor_count(unit, section, start, end, owner):
    count = 0
    for anchor in unit.get("anchors", []):
        try:
            anchor_start = int(anchor["target_address"], 16)
            anchor_end = int(anchor["target_end"], 16)
        except KeyError, TypeError, ValueError:
            continue
        existing_owner = anchor.get("existing_target_owner")
        if (
            anchor.get("section") == section
            and start <= anchor_start < anchor_end <= end
            and anchor_end - anchor_start == anchor.get("size")
            and anchor.get("size", 0) >= 16
            and not anchor.get("source_weak")
            and not anchor.get("target_weak")
            and anchor.get("source_extent_known") is True
            and anchor.get("target_extent_known") is True
            and anchor.get("source_unit_explicit") is True
            and anchor.get("source_unit_wholly_owned") is True
            and not anchor.get("template_instantiation")
            and anchor.get("unique_source") is True
            and anchor.get("unique_target") is True
            and anchor.get("normalized_body_equal") is True
            and anchor.get("relocation_layout_equal") is True
            and (
                existing_owner in (None, unit["name"], owner)
                or anchor.get("existing_owner_autogenerated") is True
            )
        ):
            count += 1
    return count


def _adjacent_owner_alternative(
    unit, transition, target_blocks, source_units, source_blocks
):
    try:
        section = transition["section"]
        side = transition["side"]
        start = int(transition["target_start"], 16)
        end = int(transition["target_end"], 16)
        owner = transition["owner"]
        owner_name = owner["unit"]
        original_start = int(owner["original_start"], 16)
        original_end = int(owner["original_end"], 16)
        revised_start = int(owner["revised_start"], 16)
        revised_end = int(owner["revised_end"], 16)
    except KeyError, TypeError, ValueError:
        return None
    owner_source = source_units.get(owner_name)
    candidate_details = _sequence_details(transition.get("functions", []))
    owner_details = _sequence_details(owner.get("functions", []))
    current_owner_range = _single_section_range(target_blocks, owner_name, section)
    previous_range = _single_section_range(
        target_blocks, transition.get("previous_unit"), section
    )
    next_range = _single_section_range(
        target_blocks, transition.get("next_unit"), section
    )
    source_previous = _single_section_range(
        source_blocks, transition.get("previous_unit"), section
    )
    source_candidate = _single_section_range(source_blocks, unit.get("name"), section)
    source_next = _single_section_range(
        source_blocks, transition.get("next_unit"), section
    )
    if (
        not transition.get("eligible")
        or section != ".text"
        or side not in {"next-prefix", "previous-suffix"}
        or end <= start
        or owner_source is None
        or candidate_details is None
        or owner_details is None
        or current_owner_range != (section, original_start, original_end)
        or owner_name == unit.get("name")
        or transition.get("previous_unit") not in source_units
        or transition.get("next_unit") not in source_units
        or source_previous is None
        or source_candidate is None
        or source_next is None
        or source_previous[2] != source_candidate[1]
        or source_candidate[2] != source_next[1]
        or source_candidate[2] - source_candidate[1] != unit["code_bytes"]
    ):
        return None
    candidate_ranges, candidate_strong = candidate_details
    owner_ranges, owner_strong = owner_details
    candidate_functions = transition.get("functions", [])
    owner_functions = owner.get("functions", [])
    helpers = owner.get("gap_helpers", [])
    candidate_bytes = end - start
    owner_bytes = revised_end - revised_start
    candidate_delta = _relative_size_delta(unit["code_bytes"], candidate_bytes)
    owner_delta = _relative_size_delta(owner_source["code_bytes"], owner_bytes)
    direct_anchors = _direct_anchor_count(unit, section, start, end, owner_name)
    target_addresses = {left for left, _ in owner_ranges}
    helper_addresses = {
        int(helper.get("target_address", "0"), 16) for helper in helpers
    }
    allowed_callers = target_addresses | helper_addresses
    if (
        len(candidate_functions) < MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS
        or transition.get("source_functions") != len(candidate_functions)
        or transition.get("aligned_functions") != len(candidate_functions)
        or transition.get("strong_functions") != candidate_strong
        or candidate_strong < MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS
        or transition.get("direct_anchors") != direct_anchors
        or direct_anchors < MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS
        or transition.get("source_bytes") != unit["code_bytes"]
        or transition.get("target_bytes") != candidate_bytes
        or transition.get("match_ratio") != 1.0
        or transition.get("target_coverage") != 1.0
        or transition.get("alignment_margin", 0.0) < 0.1
        or any(value % 4 for value in (start, end, revised_start, revised_end))
        or candidate_delta > MAX_ADJACENT_OWNER_SIZE_DELTA
        or abs(transition.get("size_delta", -1.0) - round(candidate_delta, 3))
        > 0.000001
        or not _partition_covers(start, end, candidate_ranges, [])
        or owner.get("source_functions") != len(owner_functions)
        or owner.get("aligned_functions") != len(owner_functions)
        or len(owner_functions) < MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS
        or owner.get("strong_functions") != owner_strong
        or owner_strong < MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS
        or owner.get("target_functions") != len(owner_functions) + len(helpers)
        or owner.get("source_bytes") != owner_source["code_bytes"]
        or owner.get("target_bytes") != owner_bytes
        or owner_delta > MAX_ADJACENT_OWNER_SIZE_DELTA
        or abs(owner.get("size_delta", -1.0) - round(owner_delta, 3)) > 0.000001
        or len(helpers) > MAX_ADJACENT_OWNER_GAP_HELPERS
        or not _partition_covers(revised_start, revised_end, owner_ranges, helpers)
        or any(
            not helper.get("callers")
            or any(
                int(caller, 16) not in allowed_callers for caller in helper["callers"]
            )
            or not any(
                int(caller, 16) in target_addresses for caller in helper["callers"]
            )
            for helper in helpers
        )
    ):
        return None
    if side == "next-prefix":
        valid_boundary = (
            owner_name == transition.get("next_unit")
            and previous_range is not None
            and previous_range[2] == start
            and next_range == current_owner_range
            and source_next[2] - source_next[1] == owner["source_bytes"]
            and original_start < end < original_end
            and revised_start == end
            and revised_end == original_end
        )
    else:
        valid_boundary = (
            owner_name == transition.get("previous_unit")
            and next_range is not None
            and next_range[1] == end
            and previous_range == current_owner_range
            and source_previous[2] - source_previous[1] == owner["source_bytes"]
            and original_start < start < original_end
            and revised_start == original_start
            and revised_end == start
        )
    relinquished = (
        (original_start, revised_start)
        if side == "next-prefix"
        else (revised_end, original_end)
    )
    overlaps = [
        (name, other_start, other_end)
        for name, lines in target_blocks.items()
        for line in lines
        if (value := scl.parse_range(line))
        for other_section, other_start, other_end in [value]
        if section == other_section and start < other_end and other_start < end
    ]
    if (
        not valid_boundary
        or relinquished[0] >= relinquished[1]
        or any(name != owner_name for name, _, _ in overlaps)
        or not any(
            name == owner_name
            and max(start, other_start) == relinquished[0]
            and min(end, other_end) == relinquished[1]
            for name, other_start, other_end in overlaps
        )
    ):
        return None
    revision = {
        "unit": owner_name,
        "section": section,
        "original_start": owner["original_start"],
        "original_end": owner["original_end"],
        "revised_start": owner["revised_start"],
        "revised_end": owner["revised_end"],
    }
    anchors = [
        {**item, "section": section, "target_address": item["target_address"]}
        for item in candidate_functions
    ]
    group = (
        f"{transition['previous_unit']}|{transition['next_unit']}|{side}|"
        f"{owner['original_start']}|{owner['original_end']}"
    )
    return _alternative(
        section,
        start,
        end,
        anchors,
        evidence="adjacent-owner-transition-boundary",
        group=group,
        owner_revisions=[revision],
    )


def build_alternatives(unit, target_blocks, source_units=None, source_blocks=None):
    """Create exact, layout-shift, and bounded sequence ranges."""
    eligible = [anchor for anchor in unit["anchors"] if anchor["eligible"]]
    individual = []
    for anchor in eligible:
        start, end = int(anchor["target_address"], 16), int(anchor["target_end"], 16)
        if not _overlaps_existing(anchor["section"], start, end, target_blocks):
            individual.append(_alternative(anchor["section"], start, end, [anchor]))
    individual.sort(key=lambda alt: (-alt["covered_bytes"], int(alt["start"], 16)))

    runs = []
    ordered = sorted(
        eligible,
        key=lambda anchor: (anchor["section"], int(anchor["target_address"], 16)),
    )
    current = []
    for anchor in ordered:
        if current and (
            anchor["section"] != current[-1]["section"]
            or int(anchor["target_address"], 16) != int(current[-1]["target_end"], 16)
        ):
            if len(current) > 1:
                runs.append(current)
            current = []
        current.append(anchor)
    if len(current) > 1:
        runs.append(current)
    combined = []
    for anchors in runs:
        start, end = (
            int(anchors[0]["target_address"], 16),
            int(anchors[-1]["target_end"], 16),
        )
        if not _overlaps_existing(anchors[0]["section"], start, end, target_blocks):
            combined.append(_alternative(anchors[0]["section"], start, end, anchors))
    combined.sort(key=lambda alt: (-alt["covered_bytes"], int(alt["start"], 16)))

    layout_groups = {}
    for anchor in unit.get("layout_shift_anchors", []):
        if anchor["eligible"]:
            layout_groups.setdefault(anchor["support_group"], []).append(anchor)
    shifted = []
    for group, anchors in layout_groups.items():
        anchors.sort(key=lambda anchor: int(anchor["target_address"], 16))
        sections = {anchor["section"] for anchor in anchors}
        deltas = {tuple(anchor["offset_deltas"]) for anchor in anchors}
        breakpoints = {anchor["inferred_breakpoint"] for anchor in anchors}
        source_addresses = [int(anchor["source_address"], 16) for anchor in anchors]
        target_ranges = [
            (
                int(anchor["target_address"], 16),
                int(anchor["target_end"], 16),
            )
            for anchor in anchors
        ]
        if (
            len(anchors) < 2
            or len(sections) != 1
            or len(deltas) != 1
            or len(breakpoints) != 1
            or source_addresses != sorted(source_addresses)
            or len(set(source_addresses)) != len(source_addresses)
            or any(
                left < previous_end
                for (_, previous_end), (left, _) in pairwise(target_ranges)
            )
            or {anchor["support_functions"] for anchor in anchors} != {len(anchors)}
            or {anchor["support_bytes"] for anchor in anchors}
            != {sum(anchor["size"] for anchor in anchors)}
            or {anchor["support_changed_accesses"] for anchor in anchors}
            != {sum(anchor["changed_this_accesses"] for anchor in anchors)}
        ):
            continue
        start = int(anchors[0]["target_address"], 16)
        end = max(int(anchor["target_end"], 16) for anchor in anchors)
        if end - start > 2 * unit["code_bytes"]:
            continue
        section = anchors[0]["section"]
        if not _overlaps_existing(section, start, end, target_blocks):
            shifted.append(
                _alternative(
                    section,
                    start,
                    end,
                    anchors,
                    evidence="this-layout-shift",
                    group=group,
                )
            )
    shifted.sort(key=lambda alt: (-alt["covered_bytes"], int(alt["start"], 16)))

    sequences = []
    for sequence in unit.get("boundary_sequences", []):
        start, end = (
            int(sequence["target_start"], 16),
            int(sequence["target_end"], 16),
        )
        common_invalid = (
            not sequence["eligible"]
            or sequence["section"] != ".text"
            or end <= start
            or sequence["target_bytes"] != end - start
            or _overlaps_existing(sequence["section"], start, end, target_blocks)
        )
        if common_invalid:
            continue

        method = sequence.get("acceptance_method")
        if method == "ownership-transition-boundary":
            functions = sequence.get("functions", [])
            source_addresses = [int(item["source_address"], 16) for item in functions]
            target_ranges = [
                (int(item["target_address"], 16), int(item["target_end"], 16))
                for item in functions
            ]
            support = sequence.get("ownership_transition_support") or {}
            original_start = int(support.get("original_target_start", "0"), 16)
            original_end = int(support.get("original_target_end", "0"), 16)
            aligned_start = int(support.get("aligned_target_start", "0"), 16)
            aligned_end = int(support.get("aligned_target_end", "0"), 16)
            size_base = max(unit["code_bytes"], end - start)
            size_delta = (
                abs(unit["code_bytes"] - (end - start)) / size_base
                if size_base
                else 0.0
            )
            tiers = [item.get("tier") for item in functions]
            strong = sum(tier in STRONG_MATCH_TIERS for tier in tiers)
            if (
                len(functions) < MIN_OWNERSHIP_TRANSITION_FUNCTIONS
                or sequence["aligned_functions"] != len(functions)
                or sequence["source_functions"] != len(functions)
                or sequence["target_functions"] != len(functions)
                or sequence["aligned_bytes"] != end - start
                or sequence["target_bytes"] != end - start
                or sequence["match_ratio"] != 1.0
                or sequence["order_ratio"] != 1.0
                or sequence["target_coverage"] != 1.0
                or sequence["alignment_margin"] < 0.1
                or strong < MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS
                or sequence["strong_functions"] != strong
                or any(tier not in MATCH_TIERS for tier in tiers)
                or not all(item["primary"] for item in functions)
                or source_addresses != sorted(source_addresses)
                or len(set(source_addresses)) != len(source_addresses)
                or any(
                    right <= left or right - left != item["size"]
                    for item, (left, right) in zip(functions, target_ranges)
                )
                or any(
                    left_end != right_start
                    for (_, left_end), (right_start, _) in pairwise(target_ranges)
                )
                or not target_ranges
                or target_ranges[0][0] != start
                or target_ranges[-1][1] != end
                or aligned_start != start
                or aligned_end != end
                or support.get("source_bytes") != unit["code_bytes"]
                or support.get("aligned_target_bytes") != end - start
                or original_start > start
                or original_end < end
                or original_start >= original_end
                or (original_start == start and original_end == end)
                or size_delta > MAX_OWNERSHIP_TRANSITION_SIZE_DELTA
                or abs(support.get("size_delta", -1.0) - round(size_delta, 3))
                > 0.000001
                or not _valid_transition_edge(
                    support.get("left", {}),
                    sequence["previous_unit"],
                    original_start,
                    start,
                )
                or not _valid_transition_edge(
                    support.get("right", {}),
                    sequence["next_unit"],
                    end,
                    original_end,
                )
            ):
                continue
            anchors = [
                {
                    **item,
                    "section": sequence["section"],
                    "target_address": item["target_address"],
                }
                for item in functions
            ]
            evidence = "ownership-transition-boundary"
            group = (
                f"{sequence['previous_unit']}|{sequence['next_unit']}|"
                f"{support['original_target_start']}|{support['original_target_end']}"
            )
        elif method == "layout-corroborated-boundary":
            support_group = sequence.get("layout_support_group")
            anchors = sorted(
                (
                    anchor
                    for anchor in unit.get("layout_shift_anchors", [])
                    if anchor["eligible"] and anchor["support_group"] == support_group
                ),
                key=lambda anchor: int(anchor["source_address"], 16),
            )
            source_addresses = [int(anchor["source_address"], 16) for anchor in anchors]
            target_ranges = [
                (int(anchor["target_address"], 16), int(anchor["target_end"], 16))
                for anchor in anchors
            ]
            support_functions = {anchor["support_functions"] for anchor in anchors}
            support_bytes = {anchor["support_bytes"] for anchor in anchors}
            support_changed = {anchor["support_changed_accesses"] for anchor in anchors}
            deltas = {tuple(anchor["offset_deltas"]) for anchor in anchors}
            breakpoints = {anchor["inferred_breakpoint"] for anchor in anchors}
            size_base = max(unit["code_bytes"], sequence["target_bytes"])
            size_delta = (
                abs(unit["code_bytes"] - sequence["target_bytes"]) / size_base
                if size_base
                else 0.0
            )
            if (
                not support_group
                or not anchors
                or support_functions != {len(anchors)}
                or support_bytes != {sum(anchor["size"] for anchor in anchors)}
                or support_changed
                != {sum(anchor["changed_this_accesses"] for anchor in anchors)}
                or len(deltas) != 1
                or not 1 <= len(next(iter(deltas), ())) <= 2
                or len(breakpoints) != 1
                or len(anchors) < MIN_LAYOUT_BOUNDARY_FUNCTIONS
                or sum(anchor["size"] for anchor in anchors) < MIN_LAYOUT_BOUNDARY_BYTES
                or sum(anchor["changed_this_accesses"] for anchor in anchors)
                < MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES
                or size_delta > MAX_LAYOUT_BOUNDARY_SIZE_DELTA
                or abs(sequence["source_functions"] - sequence["target_functions"])
                > MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA
                or source_addresses != sorted(source_addresses)
                or len(set(source_addresses)) != len(source_addresses)
                or any(
                    left < previous_end
                    for (_, previous_end), (left, _) in pairwise(target_ranges)
                )
                or any(left < start or right > end for left, right in target_ranges)
            ):
                continue
            evidence = "layout-corroborated-boundary"
            group = (
                f"{sequence['previous_unit']}|{sequence['next_unit']}|{support_group}"
            )
        elif method == "vtable-corroborated-boundary":
            functions = sequence.get("functions", [])
            source_addresses = [int(item["source_address"], 16) for item in functions]
            target_ranges = [
                (int(item["target_address"], 16), int(item["target_end"], 16))
                for item in functions
            ]
            target_addresses = {left for left, _ in target_ranges}
            function_pairs = {
                (item["source_address"], item["target_address"]) for item in functions
            }
            support = sequence.get("vtable_support") or {}
            unit_slots = support.get("unit_slots", [])
            slot_pairs = {
                (slot.get("source_address"), slot.get("target_address"))
                for slot in unit_slots
            }
            slot_offsets = [slot.get("slot_offset") for slot in unit_slots]
            helpers = sequence.get("gap_helpers", [])
            helper_ranges = [
                (int(helper["target_address"], 16), int(helper["target_end"], 16))
                for helper in helpers
            ]
            helper_addresses = {left for left, _ in helper_ranges}
            allowed_callers = target_addresses | helper_addresses
            size_base = max(unit["code_bytes"], sequence["target_bytes"])
            size_delta = (
                abs(unit["code_bytes"] - sequence["target_bytes"]) / size_base
                if size_base
                else 0.0
            )
            source_functions = sequence["source_functions"]
            target_functions = sequence["target_functions"]
            source_vtable_size = support.get("source_size", 0)
            target_vtable_size = support.get("target_size", 0)
            if (
                sequence["aligned_functions"] != len(functions)
                or sequence["aligned_bytes"] != sum(item["size"] for item in functions)
                or any(
                    right <= left or right - left != item["size"]
                    for item, (left, right) in zip(functions, target_ranges)
                )
                or len(functions) < MIN_VTABLE_BOUNDARY_FUNCTIONS
                or source_functions <= 0
                or len(functions) / source_functions < MIN_VTABLE_BOUNDARY_MATCH_RATIO
                or sum(item["size"] for item in functions) / sequence["target_bytes"]
                < MIN_VTABLE_BOUNDARY_TARGET_COVERAGE
                or source_functions - len(functions) not in (0, 1)
                or abs(source_functions - target_functions)
                > MAX_VTABLE_BOUNDARY_FUNCTION_DELTA
                or size_delta > MAX_VTABLE_BOUNDARY_SIZE_DELTA
                or not all(item["primary"] for item in functions)
                or source_addresses != sorted(source_addresses)
                or len(set(source_addresses)) != len(source_addresses)
                or any(
                    left < previous_end
                    for (_, previous_end), (left, _) in pairwise(target_ranges)
                )
                or any(left < start or right > end for left, right in target_ranges)
                or not support.get("source_address")
                or not support.get("target_address")
                or support.get("matched_slots", 0) < MIN_VTABLE_BOUNDARY_MATCHED_SLOTS
                or support.get("agreeing_slots") != support.get("matched_slots")
                or len(unit_slots) < MIN_VTABLE_BOUNDARY_UNIT_SLOTS
                or len(unit_slots) > support.get("agreeing_slots", 0)
                or len(set(slot_offsets)) != len(unit_slots)
                or any(
                    not isinstance(offset, int)
                    or offset < 0
                    or offset % 4
                    or offset >= source_vtable_size
                    for offset in slot_offsets
                )
                or not slot_pairs <= function_pairs
                or source_vtable_size <= 0
                or target_vtable_size <= 0
                or abs(source_vtable_size - target_vtable_size)
                > MAX_VTABLE_SIZE_PADDING
                or not 1 <= len(helpers) <= MAX_VTABLE_BOUNDARY_GAP_HELPERS
                or len(helpers) != target_functions - len(functions)
                or any(
                    right <= left
                    or right - left != helper["size"]
                    or left < start
                    or right > end
                    or not helper.get("callers")
                    or any(
                        int(caller, 16) not in allowed_callers
                        for caller in helper["callers"]
                    )
                    or not any(
                        int(caller, 16) in target_addresses
                        for caller in helper["callers"]
                    )
                    for helper, (left, right) in zip(helpers, helper_ranges)
                )
                or any(
                    left < other_end and other_start < right
                    for left, right in helper_ranges
                    for other_start, other_end in target_ranges
                )
                or any(
                    left < other_end and other_start < right
                    for index, (left, right) in enumerate(helper_ranges)
                    for other_start, other_end in helper_ranges[index + 1 :]
                )
            ):
                continue
            anchors = [
                {
                    **item,
                    "section": sequence["section"],
                    "target_address": item["target_address"],
                }
                for item in functions
            ]
            evidence = "vtable-corroborated-boundary"
            group = (
                f"{sequence['previous_unit']}|{sequence['next_unit']}|"
                f"{support['source_address']}|{support['target_address']}"
            )
        elif method == "matched-sequence":
            functions = sequence.get("functions", [])
            source_addresses = [int(item["source_address"], 16) for item in functions]
            target_ranges = [
                (int(item["target_address"], 16), int(item["target_end"], 16))
                for item in functions
            ]
            if (
                sequence["aligned_functions"] != len(functions)
                or sequence["aligned_bytes"] != sum(item["size"] for item in functions)
                or not all(item["primary"] for item in functions)
                or source_addresses != sorted(source_addresses)
                or len(set(source_addresses)) != len(source_addresses)
                or any(
                    left < previous_end
                    for (_, previous_end), (left, _) in pairwise(target_ranges)
                )
                or any(left < start or right > end for left, right in target_ranges)
            ):
                continue
            anchors = [
                {
                    **item,
                    "section": sequence["section"],
                    "target_address": item["target_address"],
                }
                for item in functions
            ]
            evidence = "boundary-sequence"
            group = f"{sequence['previous_unit']}|{sequence['next_unit']}"
        else:
            continue

        sequences.append(
            _alternative(
                sequence["section"],
                start,
                end,
                anchors,
                evidence=evidence,
                group=group,
            )
        )
    sequences.sort(key=lambda alt: (-alt["covered_bytes"], int(alt["start"], 16)))

    adjacent = []
    if source_units is not None and source_blocks is not None:
        for transition in unit.get("adjacent_owner_transitions", []):
            alternative = _adjacent_owner_alternative(
                unit, transition, target_blocks, source_units, source_blocks
            )
            if alternative is not None:
                adjacent.append(alternative)
    adjacent.sort(key=lambda alt: (-alt["covered_bytes"], int(alt["start"], 16)))

    result, seen = [], set()
    for alternative in adjacent + sequences + shifted + individual + combined:
        key = (
            alternative["section"],
            alternative["start"],
            alternative["end"],
            json.dumps(alternative["owner_revisions"], sort_keys=True),
        )
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
    reasons = {
        reason
        for anchor in unit["anchors"] + unit.get("layout_shift_anchors", [])
        for reason in anchor["reasons"]
    }
    if "target range is owned by another explicit unit" in reasons:
        return "overlap"
    if "function range is not split-aligned" in reasons:
        return "alignment"
    if unit.get("layout_shift_candidates", 0):
        return "layout-shift-insufficient-support"
    if unit.get("boundary_sequences"):
        return "boundary-sequence-insufficient-support"
    return "no-qualifying-anchor"


def prepare(ctx, limit=None):
    ctx.output.mkdir(parents=True, exist_ok=True)
    baseline = ctx.build()
    evidence_path = ctx.output / "coverage-evidence.json"
    try:
        ctx.run(
            [
                ctx.dtk,
                "match",
                f"config/{ctx.source}/config.yml",
                f"config/{ctx.target}/config.yml",
                "--coverage",
                evidence_path,
            ]
        )
    except TRIAL_ERRORS as error:
        log = (ctx.output / "build.log").read_text(encoding="utf-8", errors="replace")
        if "coverage" in log.lower() and (
            "unrecognized" in log.lower() or "unknown" in log.lower()
        ):
            raise RuntimeError(
                "DTK does not support `match --coverage`; build the coverage-capable DTK revision"
            ) from error
        raise
    if not evidence_path.is_file():
        raise RuntimeError("DTK completed without writing coverage evidence")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    policy = evidence.get("policy", {})
    if (
        evidence.get("schema") != EVIDENCE_SCHEMA
        or policy.get("version") != POLICY_VERSION
        or any(
            policy.get(key) != value
            for key, value in (
                LAYOUT_BOUNDARY_POLICY
                | VTABLE_BOUNDARY_POLICY
                | OWNERSHIP_TRANSITION_POLICY
                | ADJACENT_OWNER_TRANSITION_POLICY
            ).items()
        )
    ):
        raise RuntimeError("Unsupported DTK coverage evidence schema or policy")

    splits = ctx.root / "config" / ctx.target / "splits.txt"
    _, target_blocks, _ = scl.parse_splits(splits.read_text(encoding="utf-8"))
    source_splits = ctx.root / "config" / ctx.source / "splits.txt"
    _, source_blocks, _ = scl.parse_splits(source_splits.read_text(encoding="utf-8"))
    source_units = [
        unit for unit in evidence["source_units"] if not unit.get("autogenerated")
    ]
    source_units_by_name = {unit["name"]: unit for unit in source_units}
    missing = [unit for unit in source_units if unit["name"] not in target_blocks]
    dispositions, candidates = {}, []
    for unit in missing:
        alternatives = build_alternatives(
            unit, target_blocks, source_units_by_name, source_blocks
        )
        dispositions[unit["name"]] = _disposition(unit, alternatives)
        if alternatives:
            candidates.append(
                {
                    "name": unit["name"],
                    "policy_version": POLICY_VERSION,
                    "source_code_bytes": unit["code_bytes"],
                    "required_extracts": unit.get("required_extracts", []),
                    "alternatives": alternatives,
                }
            )
    candidates.sort(
        key=lambda candidate: (
            -max(alt["covered_bytes"] for alt in candidate["alternatives"]),
            candidate["name"],
        )
    )
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
            "baseline_represented": len(
                {unit["name"] for unit in source_units} & set(target_blocks)
            ),
            "missing": len(missing),
            "dispositions": dispositions,
        },
        # Audited, not evaluated: a unit that already owns a range counts as
        # represented, so no stage will look for its real one. Reporting is the
        # whole contribution here -- repair needs the range to be separately
        # determinable, which this cannot decide.
        "stunted_splits": split_audit.stunted_splits(
            target_blocks, split_audit.load_blocks(ctx.root, ctx.source)
        ),
    }


def _normalize(root, value):
    return os.path.normcase(
        os.path.normpath(str(root / Path(value.replace("\\", "/"))))
    )


def _validate_extracted_inputs(ctx, names, report):
    inputs = ctx.run(
        [ctx.ninja, "-t", "inputs", f"build/{ctx.target}/main.elf"], capture=True
    )
    inputs = {
        _normalize(ctx.root, line) for line in inputs.splitlines() if line.strip()
    }
    objdiff = json.loads((ctx.root / "objdiff.json").read_text(encoding="utf-8"))
    target_paths = {
        _normalize(ctx.root, unit.get("target_path", "")): unit
        for unit in objdiff["units"]
        if unit.get("target_path")
    }
    units = by_path(report)
    for name in names:
        object_name = str(PurePosixPath(name).with_suffix(".o"))
        expected = _normalize(ctx.root, f"build/{ctx.target}/obj/{object_name}")
        unit = target_paths.get(expected)
        if unit is None or expected not in inputs:
            raise ValidationError(
                f"{name}'s extracted target object is not an input to main.elf"
            )
        base = unit.get("base_path")
        if base and _normalize(ctx.root, base) in inputs:
            raise ValidationError(
                f"{name}'s compiled source object was enabled during coverage"
            )
        if units.get(name, {}).get("metadata", {}).get("complete") is True:
            raise ValidationError(f"{name} was marked complete during coverage")


def _validate_required_extracts(ctx, extracts):
    for extract in extracts:
        for field, directory in (
            ("binary", "bin"),
            ("header", "include"),
            ("relocations", "bin"),
        ):
            relative = extract.get(field)
            if relative:
                _validate_extract_path(relative)
            if (
                relative
                and not (
                    ctx.root / "build" / ctx.target / directory / relative
                ).is_file()
            ):
                raise ValidationError(
                    f"required extract did not generate {field} output: {relative}"
                )
        header = extract.get("header")
        rename = extract.get("rename")
        if header and rename and extract.get("header_type") != "none":
            generated = ctx.root / "build" / ctx.target / "include" / header
            if rename not in generated.read_text(encoding="utf-8", errors="replace"):
                raise ValidationError(
                    f"required extract header {header} does not declare {rename}"
                )


def _failure_category(error, log):
    text = f"{error}\n{log}".lower()
    if "timed out after" in text:
        return "build-timeout"
    if "retail dol bytes differ" in text or "checksum" in text:
        return "retail-mismatch"
    if "cycle" in text:
        return "link-order-cycle"
    if (
        "multiply defined" in text
        or "multiply-defined" in text
        or "duplicate symbol" in text
    ):
        return "duplicate-symbol"
    if "undefined:" in text or "undefined symbol" in text:
        return "undefined-symbol"
    if "invalid alignment" in text or "split alignment" in text:
        return "split-alignment"
    if "cannot open" in text or "no such file" in text or "fatal error" in text:
        return "compilation-missing-include"
    if (
        "compiled source object was enabled" in text
        or "extracted target object is not" in text
    ):
        return "source-linkage-violation"
    if "regresses an existing unit" in text or "reduces source-linked code" in text:
        return "regression"
    if (
        "compilation terminated" in text
        or "mwcc fatal" in text
        or "syntax error" in text
    ):
        return "compilation-failure"
    return "unknown-failure"


def _apply_owner_revisions(blocks, revisions):
    plans = []
    seen = set()
    for revision in revisions:
        try:
            name = revision["unit"]
            section = revision["section"]
            original_start = int(revision["original_start"], 16)
            original_end = int(revision["original_end"], 16)
            revised_start = int(revision["revised_start"], 16)
            revised_end = int(revision["revised_end"], 16)
        except (KeyError, TypeError, ValueError) as error:
            raise ValidationError("Malformed adjacent-owner revision") from error
        key = (name, section)
        if key in seen:
            raise ValidationError(
                f"Duplicate adjacent-owner revision for {name} {section}"
            )
        seen.add(key)
        if (
            revised_end <= revised_start
            or original_end <= original_start
            or revised_start < original_start
            or revised_end > original_end
            or (revised_start == original_start and revised_end == original_end)
            or _single_section_range(blocks, name, section)
            != (section, original_start, original_end)
        ):
            raise ValidationError(
                f"Adjacent owner {name} no longer has its exact evidenced {section} range"
            )
        matching = [
            index
            for index, line in enumerate(blocks[name])
            if scl.parse_range(line) == (section, original_start, original_end)
        ]
        if len(matching) != 1:
            raise ValidationError(
                f"Adjacent owner {name} range is not uniquely revisable"
            )
        plans.append((name, matching[0], section, revised_start, revised_end))
    for name, index, section, revised_start, revised_end in plans:
        updated = list(blocks[name])
        updated[index] = (
            f"\t{section:11} start:0x{revised_start:08X} end:0x{revised_end:08X}"
        )
        blocks[name] = updated


def _validate_selected_splits(ctx, expected, selected):
    splits = ctx.root / "config" / ctx.target / "splits.txt"
    _, blocks, _ = scl.parse_splits(splits.read_text(encoding="utf-8"))
    for name, alternative_id in selected.items():
        alternative = next(
            item
            for item in expected[name]["alternatives"]
            if item["id"] == alternative_id
        )
        if blocks.get(name) != alternative["lines"]:
            raise ValidationError(f"Coverage split for {name} changed after selection")
        for revision in alternative.get("owner_revisions", []):
            revised = (
                revision["section"],
                int(revision["revised_start"], 16),
                int(revision["revised_end"], 16),
            )
            if (
                _single_section_range(blocks, revision["unit"], revision["section"])
                != revised
            ):
                raise ValidationError(
                    f"Adjacent owner {revision['unit']} revision changed after selection"
                )


def validate(ctx, candidates, selected):
    expected = {candidate["name"]: candidate for candidate in candidates}
    if set(selected) != set(expected):
        raise ValidationError("Coverage selection does not match accepted candidates")
    for name, alternative_id in selected.items():
        if alternative_id not in {
            alternative["id"] for alternative in expected[name]["alternatives"]
        }:
            raise ValidationError(f"Unknown coverage alternative for {name}")
    _validate_selected_splits(ctx, expected, selected)
    report = ctx.build()
    _validate_extracted_inputs(ctx, set(expected), report)
    _validate_required_extracts(
        ctx,
        [
            extract
            for candidate in candidates
            for extract in candidate.get("required_extracts", [])
        ],
    )
    return report


def evaluate(ctx, candidates, preferred=None):
    splits = ctx.root / "config" / ctx.target / "splits.txt"
    config = ctx.root / "config" / ctx.target / "config.yml"
    original = splits.read_bytes()
    owned = original
    original_config = config.read_bytes()
    owned_config = original_config
    header, blocks, order = scl.parse_splits(original.decode("utf-8"))
    report = ctx.build()
    starting_complete = _int_measure(report, "complete_code")
    accepted, deferred, selected, events = [], [], {}, []
    preferred = preferred or {}

    def write():
        nonlocal owned
        owned = _write_splits(splits, header, blocks, order, owned)

    def write_extracts(extracts):
        nonlocal owned_config
        owned_config = _write_required_extracts(config, extracts, owned_config)

    try:
        if len({candidate["name"] for candidate in candidates}) != len(candidates):
            raise ValueError("Duplicate coverage candidate names")
        for candidate in candidates:
            candidate_config = owned_config
            required_extracts = candidate.get("required_extracts", [])
            write_extracts(required_extracts)
            alternatives = list(candidate["alternatives"])
            wanted = preferred.get(candidate["name"])
            alternatives.sort(
                key=lambda alternative: alternative["id"] != wanted if wanted else False
            )
            chosen = None
            for alternative in alternatives:
                before_log = (
                    (ctx.output / "build.log").stat().st_size
                    if (ctx.output / "build.log").exists()
                    else 0
                )
                trial_blocks = {name: list(lines) for name, lines in blocks.items()}
                trial_order = list(order)
                try:
                    _apply_owner_revisions(
                        blocks, alternative.get("owner_revisions", [])
                    )
                    is_new = candidate["name"] not in blocks
                    blocks[candidate["name"]] = alternative["lines"]
                    if is_new:
                        order[:] = scl.order_new_code_units(
                            order, blocks, [candidate["name"]]
                        )
                    write()
                    tested = trial_build(ctx)
                    _validate_extracted_inputs(ctx, {candidate["name"]}, tested)
                    _validate_required_extracts(ctx, required_extracts)
                    if _regresses(report, tested):
                        raise ValidationError(
                            "coverage candidate regresses an existing unit"
                        )
                    if _int_measure(tested, "complete_code") < starting_complete:
                        raise ValidationError(
                            "coverage candidate reduces source-linked code"
                        )
                except TRIAL_ERRORS as error:
                    blocks.clear()
                    blocks.update(trial_blocks)
                    order[:] = trial_order
                    write()
                    log_path = ctx.output / "build.log"
                    log = (
                        log_path.read_text(encoding="utf-8", errors="replace")[
                            before_log:
                        ]
                        if log_path.exists()
                        else ""
                    )
                    events.append(
                        {
                            "unit": candidate["name"],
                            "alternative": alternative["id"],
                            "status": "rejected",
                            "category": _failure_category(error, log),
                            "reason": str(error),
                            "exit_status": getattr(error, "returncode", None),
                            "log": str(log_path),
                        }
                    )
                    continue
                chosen, report = alternative, tested
                break
            if chosen is None:
                if (
                    config.read_bytes() == owned_config
                    and owned_config != candidate_config
                ):
                    _replace(config, candidate_config, owned_config)
                    owned_config = candidate_config
                deferred.append(candidate)
                continue
            accepted.append(candidate)
            selected[candidate["name"]] = chosen["id"]
            events.append(
                {
                    "unit": candidate["name"],
                    "alternative": chosen["id"],
                    "status": "accepted",
                    "evidence": chosen["evidence"],
                    "covered_bytes": chosen["covered_bytes"],
                }
            )
        write()
        final = validate(ctx, accepted, selected)
        if _regresses(report, final):
            raise RuntimeError("Final coverage report regressed after validation")
        return {
            "accepted": accepted,
            "deferred": deferred,
            "selected": selected,
            "events": events,
            "report": final,
            "validation": VALIDATION,
        }
    except BaseException:
        if splits.read_bytes() == owned:
            _replace(splits, original, owned)
        if config.read_bytes() == owned_config:
            _replace(config, original_config, owned_config)
        raise


def summary(prepared, result):
    inventory = prepared["inventory"]
    alternatives = {
        candidate["name"]: {alt["id"]: alt for alt in candidate["alternatives"]}
        for candidate in result["accepted"]
    }
    selected = {
        name: alternatives[name][identity]
        for name, identity in result["selected"].items()
    }
    dispositions = dict(inventory["dispositions"])
    for name in result["selected"]:
        dispositions[name] = "accepted"
    rejected = {
        event["unit"] for event in result["events"] if event["status"] == "rejected"
    }
    for candidate in result["deferred"]:
        dispositions[candidate["name"]] = (
            "build-failure" if candidate["name"] in rejected else "deferred"
        )
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
        "newly_assigned_code_bytes": sum(
            alt["covered_bytes"] for alt in selected.values()
        ),
        "candidate_evidence": prepared["candidates"],
        "eligible_excluded_by_only": prepared.get("eligible_excluded_by_only", []),
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
        "stunted_splits": prepared.get("stunted_splits", []),
        "validation": result["validation"],
    }


def markdown_summary(value):
    lines = [
        "# Coverage stage result",
        "",
        f"- Represented source TUs: {value['baseline_represented']} → {value['final_represented']} / {value['source_units']}",
        f"- Newly supported TUs: {value['newly_supported_units']}",
        f"- Newly assigned code bytes: {value['newly_assigned_code_bytes']}",
        f"- Validation: `{value['validation']}`",
        "",
        "This stage certifies only the newly selected ranges; pre-existing ownership is not re-certified.",
        "",
        "## Separate progress metrics",
        "",
        "| Metric | Baseline | Final |",
        "|---|---:|---:|",
        f"| Represented source TUs | {value['metrics']['representation']['baseline_tus']} | {value['metrics']['representation']['final_tus']} |",
        f"| Objdiff-matched code bytes | {value['metrics']['objdiff_matching']['baseline_code_bytes']} | {value['metrics']['objdiff_matching']['final_code_bytes']} |",
        f"| Configured source-linked code bytes | {value['metrics']['configured_source_linkage']['baseline_code_bytes']} | {value['metrics']['configured_source_linkage']['final_code_bytes']} |",
        "| Newly verified source-linked code bytes | 0 | 0 |",
        "",
        "## Selected ranges",
        "",
    ]
    if value["selected"]:
        lines.extend(
            [
                "| TU | Evidence | Section | Range | Bytes |",
                "|---|---|---|---:|---:|",
            ]
        )
        for name, alternative in sorted(value["selected"].items()):
            lines.append(
                f"| `{name}` | `{alternative['evidence']}` | `{alternative['section']}` | "
                f"`{alternative['start']}..{alternative['end']}` | {alternative['covered_bytes']} |"
            )
    else:
        lines.append("No range passed the coverage gates.")
    excluded = value.get("eligible_excluded_by_only", [])
    if excluded:
        lines.extend(
            [
                "",
                "## Eligible candidates excluded by `--only`",
                "",
                *[f"- `{name}`" for name in excluded],
            ]
        )
    lines.extend(["", "## Remaining dispositions", ""])
    counts = {}
    for disposition in value["dispositions"].values():
        counts[disposition] = counts.get(disposition, 0) + 1
    for disposition, count in sorted(counts.items()):
        lines.append(f"- {disposition}: {count}")
    lines.extend(_stunted_section(value.get("stunted_splits", [])))
    return "\n".join(lines) + "\n"


def _stunted_section(stunted):
    """Report units whose existing range is too small to be the whole unit.

    These never appear as candidates: owning any range makes a unit represented,
    so this stage skips it and discovery only extends what is already there. The
    report is the only place they can surface at all.
    """
    if not stunted:
        return []
    lines = [
        "",
        "## Stunted splits",
        "",
        (
            f"{len(stunted)} units claim less than half the bytes the same unit"
            " claims in the source version. A range this small is usually built on"
            " a symbol that several source objects define, so the two versions'"
            " linkers placed it in different units and matching its name proved"
            " nothing about ownership."
        ),
        "",
        (
            "These are **not** candidates: owning any range makes a unit"
            " represented, so no stage looks for its real one while the fragment"
            " stands. Removing a fragment is only safe when the unit's true range"
            " is separately determinable, which this audit does not decide."
        ),
        "",
        "| TU | Section | Claimed | Source version | Ratio |",
        "|---|---|---:|---:|---:|",
    ]
    for entry in stunted[:20]:
        lines.append(
            f"| `{entry['unit']}` | `{entry['section']}` | {entry['claimed_bytes']} | "
            f"{entry['expected_bytes']} | {entry['ratio']:.3f} |"
        )
    if len(stunted) > 20:
        lines.append(f"\n…and {len(stunted) - 20} more; see `coverage.json`.")
    return lines
