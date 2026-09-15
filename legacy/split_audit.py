"""Read-only audits of a target version's splits against the source version's.

These look at splits that already exist rather than at proposals, which is the
one blind spot the migration stages share: a unit that owns *some* range counts
as represented, so coverage skips it and discovery only ever extends what is
already there. A badly wrong range is therefore worse than no range at all,
because nothing will look for the right one while it stands.
"""

from __future__ import annotations

import project_modules
import split_confidence_loop as scl

# A unit that genuinely shrank between versions keeps the same order of
# magnitude. Everything observed below half was a misattributed fragment, and
# the population thins out well before that, so the threshold does not sit on
# a gradient.
STUNTED_RATIO = 0.5


def section_bytes(body, section=".text"):
    """Total bytes a unit's body claims in one section."""
    return sum(
        r[2] - r[1] for l in body or [] if (r := scl.parse_range(l)) and r[0] == section
    )


def stunted_splits(target_blocks, source_blocks, section=".text", ratio=STUNTED_RATIO):
    """Units whose target split claims far less than the same unit's source split.

    The usual cause is a range built on a symbol that several source objects
    define -- a weak symbol, template instantiation or inline destructor. The
    two versions' linkers resolve it to different units, so matching the name
    proves nothing about ownership, and the range lands wherever the other
    version happened to put that one function.

    Compared against the source version's *split* rather than against the
    compiled source object: an object also contains inline functions that never
    reach the binary, which makes correct splits look stunted (`dolphin/mtx/mtx44.c`
    claims 5% of its object and 100% of its source split).
    """
    found = []
    for unit, body in target_blocks.items():
        claimed = section_bytes(body, section)
        expected = section_bytes(source_blocks.get(unit), section)
        if not claimed or not expected or claimed >= expected * ratio:
            continue
        found.append(
            {
                "unit": unit,
                "section": section,
                "claimed_bytes": claimed,
                "expected_bytes": expected,
                "ratio": claimed / expected,
            }
        )
    return sorted(found, key=lambda entry: entry["ratio"])


def read_blocks(path):
    """Parsed split blocks for one module, or empty when it has no splits file."""
    if not path or not path.is_file():
        return {}
    _, blocks, _ = scl.parse_splits(path.read_text(encoding="utf-8"))
    return blocks


def load_blocks(root, version, module=project_modules.DOL_NAME):
    """Parsed split blocks for one version's module, the DOL by default."""
    return read_blocks(project_modules.find(root, version, module).splits)


def audit(root, source, target, section=".text", module=project_modules.DOL_NAME):
    """Every stunted split in one target module, judged against its counterpart."""
    return stunted_splits(
        load_blocks(root, target, module), load_blocks(root, source, module), section
    )


def audit_modules(root, source, target, section=".text"):
    """Stunted splits across every module, each judged against its counterpart.

    Modules are paired by position because their names differ across regions,
    so each result records both names rather than assuming one.
    """
    found = []
    for target_module, source_module in project_modules.pair(root, source, target):
        if source_module is None:
            continue
        for entry in stunted_splits(
            read_blocks(target_module.splits),
            read_blocks(source_module.splits),
            section,
        ):
            found.append(
                {**entry, "module": target_module.name, "against": source_module.name}
            )
    return sorted(found, key=lambda entry: entry["ratio"])


def unsplit_modules(root, source, target):
    """Modules the target has not begun splitting, but the source has.

    A module with no unit splits at all is invisible to every stage: it never
    appears as a candidate, and nothing reports it as missing. Metroid Prime's
    PAL NES emulator sits here -- its splits file holds only a section header.
    """
    found = []
    for target_module, source_module in project_modules.pair(root, source, target):
        if source_module is None:
            continue
        target_blocks = read_blocks(target_module.splits)
        source_blocks = read_blocks(source_module.splits)
        if target_blocks or not source_blocks:
            continue
        found.append(
            {
                "module": target_module.name,
                "against": source_module.name,
                "source_units": len(source_blocks),
                "source_code_bytes": sum(
                    section_bytes(body) for body in source_blocks.values()
                ),
                "built": target_module.sources.is_dir(),
            }
        )
    return found


def relocated_units(root, source, target):
    """Units a version links into a different module than the other version does.

    A translation unit can move between the DOL and a REL between releases, which
    makes a unit look missing in one module and unexplained in another. Reported
    rather than acted on: whether the move is real or an artefact of one side
    being unsplit cannot be told from splits alone.
    """

    def owners(version):
        found = {}
        for module in project_modules.modules(root, version):
            for unit in read_blocks(module.splits):
                found[unit] = module.name
        return found

    source_owners, target_owners = owners(source), owners(target)
    return sorted(
        (
            {
                "unit": unit,
                "source_module": source_owners[unit],
                "target_module": module,
            }
            for unit, module in target_owners.items()
            if unit in source_owners
            and (source_owners[unit] == project_modules.DOL_NAME)
            != (module == project_modules.DOL_NAME)
        ),
        key=lambda entry: entry["unit"],
    )
