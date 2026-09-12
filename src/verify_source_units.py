#!/usr/bin/env python3
"""Enable whole source files only after their compiled objects pass the retail hash.

Run from a dtk-template project after discovering splits. MatchingFor calls in
configure.py record accepted files in VERSIONS order. Trials are transactional; failures are bisected
and left disabled. No source code or hand-picked target addresses are changed.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path

from migration_runtime import BuildContext

BEGIN = "# BEGIN AUTOMATED SOURCE VERIFICATION\n"
END = "# END AUTOMATED SOURCE VERIFICATION\n"


def legacy_blocks(text):
    """Read only the exact old override shape; never discard user-added logic."""
    pattern = re.compile(
        r"^"
        + re.escape(BEGIN)
        + r"# Version: (\S+)\n(.*?)^"
        + re.escape(END.rstrip("\n"))
        + r"(?:\n\n?|$)",
        re.MULTILINE | re.DOTALL,
    )
    blocks = []
    for match in pattern.finditer(text):
        version, body = match.group(1, 2)
        tree = ast.parse(body)
        assignments = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "_verified_source_units"
                for t in n.targets
            )
        ]
        if len(assignments) != 1:
            raise ValueError(f"Unrecognized legacy verification block for {version}")
        names = ast.literal_eval(assignments[0].value)
        if not isinstance(names, set) or not all(isinstance(n, str) for n in names):
            raise ValueError(
                f"Expected literal unit names in legacy block for {version}"
            )
        # Compare syntax trees so harmless whitespace/comments are allowed, but
        # extra statements, different conditions or changed loop logic are not.
        expected = (
            f"if config.version == {version!r}:\n"
            f"    _verified_source_units = {ast.get_source_segment(body, assignments[0].value)}\n"
            "    for _verified_lib in config.libs:\n"
            "        for _verified_obj in _verified_lib['objects']:\n"
            "            if _verified_obj.name in _verified_source_units:\n"
            "                _verified_obj.completed = True\n"
        )
        if ast.dump(tree) != ast.dump(ast.parse(expected)):
            raise ValueError(
                f"Modified legacy verification block for {version}; refusing to remove it"
            )
        blocks.append((match.start(), match.end(), version, names))
    if len(blocks) != len(
        re.findall(r"^" + re.escape(BEGIN), text, re.MULTILINE)
    ) or len(blocks) != len(
        re.findall(r"^" + re.escape(END.rstrip("\n")) + r"$", text, re.MULTILINE)
    ):
        raise ValueError("Malformed legacy verification block")
    return blocks


def is_already_universal(status):
    """True for a status that already enables an object for every version."""
    return (isinstance(status, ast.Name) and status.id == "Matching") or (
        isinstance(status, ast.Constant) and status.value is True
    )


def is_rewritable(status):
    """True when adding a version to this status is a rename of its argument list.

    The grammar this understands is `Matching`/`True`, `MatchingFor(...)`, and
    the flat negatives `NonMatching`/`Equivalent`/`False`. Anything else -- most
    of all `EquivalentFor(...)`, which means "links from source for these
    versions, but only in a `--non-matching` build" -- states something a longer
    `MatchingFor` cannot. Promoting `EquivalentFor("A", "B")` to
    `MatchingFor("A", "B", "C")` would silently claim A and B are byte-identical
    when they are only equivalent, so such an object is left alone rather than
    rewritten into a stronger claim than anyone has evidence for.
    """
    if is_already_universal(status):
        return True
    if (
        isinstance(status, ast.Call)
        and isinstance(status.func, ast.Name)
        and status.func.id == "MatchingFor"
        and not status.keywords
    ):
        return True
    return (
        isinstance(status, ast.Name) and status.id in ("NonMatching", "Equivalent")
    ) or (isinstance(status, ast.Constant) and status.value is False)


def unrewritable_names(text):
    """Objects whose matching expression `render_config` must not touch.

    The verification stage picks its candidates from the build report, which
    says nothing about how an object is declared, so without this it can choose
    one it cannot then express -- which is a whole batch lost at evaluate time,
    long after the work is done.
    """
    blocked = {}
    for node in ast.walk(ast.parse(text.replace("\r\n", "\n"))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Object"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and not is_rewritable(node.args[0])
        ):
            status = node.args[0]
            blocked[node.args[1].value] = (
                status.func.id
                if isinstance(status, ast.Call) and isinstance(status.func, ast.Name)
                else ast.dump(status)
            )
    return blocked


def render_config(original, version, names):
    """Edit only selected Object statuses; preserve existing flags and VERSIONS order.

    Legacy overrides for every version are migrated as baseline configuration.
    Each trial is rendered from the unchanged input, so failed additions disappear
    when the caller renders the accepted set again.
    """
    text = original.replace("\r\n", "\n")
    tree = ast.parse(text)
    assignments = [
        n
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "VERSIONS" for t in n.targets)
    ]
    if len(assignments) != 1:
        raise ValueError("Expected one literal VERSIONS list in configure.py")
    versions = ast.literal_eval(assignments[0].value)
    if (
        not isinstance(versions, (list, tuple))
        or not all(isinstance(v, str) for v in versions)
        or len(set(versions)) != len(versions)
    ):
        raise ValueError("VERSIONS must contain unique version strings")
    rank = {v: i for i, v in enumerate(versions)}
    if version not in rank:
        raise ValueError(f"Unknown target version: {version}")
    wanted = {name: {version} for name in names}
    edits = []
    for start, end, old_version, old_names in legacy_blocks(text):
        if old_version not in rank:
            raise ValueError(f"Unknown legacy version: {old_version}")
        for name in old_names:
            wanted.setdefault(name, set()).add(old_version)
        edits.append(
            (len(text[:start].encode("utf-8")), len(text[:end].encode("utf-8")), b"")
        )

    # AST columns are UTF-8 byte offsets, not Python character indices.
    data = text.encode("utf-8")
    offsets = [0]
    for line in data.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    found = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Object"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in wanted
        ):
            continue
        name = node.args[1].value
        if name in found:
            raise ValueError(f"Multiple Object declarations for {name}")
        found.add(name)
        status = node.args[0]
        if is_already_universal(status):
            continue  # Already enabled for every version; never narrow it.
        if (
            isinstance(status, ast.Call)
            and isinstance(status.func, ast.Name)
            and status.func.id == "MatchingFor"
            and not status.keywords
        ):
            old = [ast.literal_eval(arg) for arg in status.args]
            if any(v not in rank for v in old):
                raise ValueError(f"Unknown MatchingFor version in {name}: {old}")
        elif (
            isinstance(status, ast.Name) and status.id in ("NonMatching", "Equivalent")
        ) or (isinstance(status, ast.Constant) and status.value is False):
            old = []
        else:
            raise ValueError(f"Unsupported matching expression for {name}")
        values = sorted(set(old) | wanted[name], key=rank.__getitem__)
        if status.end_lineno is None or status.end_col_offset is None:
            raise ValueError(
                f"Missing source location for matching expression in {name}"
            )
        start = offsets[status.lineno - 1] + status.col_offset
        end = offsets[status.end_lineno - 1] + status.end_col_offset
        if b"#" in data[start:end]:
            raise ValueError(
                f"Comments inside MatchingFor for {name}; refusing to discard them"
            )
        replacement = "MatchingFor(" + ", ".join(json.dumps(v) for v in values) + ")"
        edits.append((start, end, replacement.encode("utf-8")))
    missing = set(wanted) - found
    if missing:
        raise ValueError(f"Missing Object declarations: {', '.join(sorted(missing))}")
    for start, end, replacement in sorted(edits, reverse=True):
        data = data[:start] + replacement + data[end:]
    result = data.decode("utf-8")
    ast.parse(result)
    return result.replace("\n", "\r\n") if "\r\n" in original else result


def main():
    from migration_workspace import project_lock

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source", default="GM8E01_00")
    parser.add_argument("--dtk", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--build-jobs", type=int, default=4)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--migrate-only",
        action="store_true",
        help="migrate legacy overrides into MatchingFor and verify the target without trying new files",
    )
    args = parser.parse_args()
    if args.build_jobs < 1 or (args.limit is not None and args.limit < 1):
        parser.error("build jobs and limit must be positive")
    root = args.project_root.resolve()
    dtk = args.dtk.resolve()
    out = root / "build" / args.target / "source-verification"
    out.mkdir(parents=True, exist_ok=True)
    with project_lock(root):
        _execute(args, root, dtk, out)


def _execute(args, root, dtk, out):
    from verification_adapter import _rollback, evaluate, prepare

    ctx = BuildContext(root, args.source, args.target, dtk, out, args.build_jobs)
    config_path = root / "configure.py"
    original = config_path.read_bytes()
    owned = original
    try:
        prepared = prepare(ctx, limit=args.limit)
        owned = render_config(original.decode("utf-8"), args.target, set()).encode(
            "utf-8"
        )
        candidates = [] if args.migrate_only else prepared["candidates"]
        print(
            f"Testing {len(candidates)} whole files as compiled link inputs", flush=True
        )
        evaluated = evaluate(ctx, candidates)
        owned = render_config(
            owned.decode("utf-8"),
            args.target,
            {c["name"] for c in evaluated["accepted"]},
        ).encode("utf-8")
        result = {
            "target": args.target,
            "baseline": prepared["baseline"]["measures"],
            "final": evaluated["report"]["measures"],
            "accepted": sorted(c["name"] for c in evaluated["accepted"]),
            "deferred": [c["name"] for c in evaluated["deferred"]],
            "events": prepared["events"] + evaluated["events"],
            "migrated_legacy": prepared["migrated_legacy"],
            "validation": evaluated["validation"],
            "dtk_sha256": hashlib.sha256(dtk.read_bytes()).hexdigest(),
            "dol_sha1": ctx.dol_sha1(),
        }
        (out / "result.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(result["final"], indent=2))
    except BaseException:
        _rollback(config_path, owned, original)
        raise


if __name__ == "__main__":
    main()
