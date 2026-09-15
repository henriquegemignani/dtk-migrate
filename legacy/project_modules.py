"""Where a version keeps each linked module's splits, symbols and build output.

Everything else in this repository addresses the DOL and nothing else: paths are
written `config/<version>/splits.txt`, and `discover_splits` filters report units
on `module_id == 0`. A game that ships RELs keeps whole translation units outside
that view -- Metroid Prime's NES emulator is 34 KB of PAL code that no stage can
currently see.

Nothing about a module's location is conventional, so all of it is read from
`config.yml` rather than assumed:

- the config directory need not match the module name (NTSC keeps `NESemuP.rel`
  under `config/GM8E01_00/NESemu/`),
- and the name need not match between versions (`NESemuP` against `NESPALemuP`),

which is also why modules are paired across versions by position rather than by
name. The build directory is the REL object's own basename.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DOL_NAME = "main"
_ENTRY = re.compile(r"^(\s*)-\s+object:\s*(\S+)")
_FIELD = re.compile(r"^\s*(splits|symbols):\s*(\S+)")


@dataclass(frozen=True)
class Module:
    """One linked output of a version: the DOL itself, or a REL beside it."""

    root: Path
    version: str
    name: str
    splits: Path
    symbols: Path
    build: Path
    is_dol: bool

    @property
    def sources(self):
        """Compiled source objects.

        Shared by every module of a version: a source file is compiled once into
        `build/<version>/src` whichever module it ends up linked into. Pairing
        that one tree against a module's own `obj/` therefore selects exactly the
        units that module contains -- and is why a file moving between the DOL
        and a REL changes which `obj/` holds it, never where it compiles to.
        """
        return self.root / "build" / self.version / "src"

    @property
    def extracted(self):
        """Objects split out of this module's shipped binary."""
        return self.build / "obj"


def _module_entries(text):
    """`(object, splits, symbols)` for each uncommented entry under `modules:`."""
    entries = []
    inside = False
    current = None
    for line in text.splitlines():
        if re.match(r"^modules:\s*$", line):
            inside = True
            continue
        if inside and line.strip() and not line.startswith((" ", "\t", "-", "#")):
            break  # A new top-level key ends the block.
        if not inside or line.lstrip().startswith("#"):
            continue
        found = _ENTRY.match(line)
        if found:
            current = {"object": found.group(2)}
            entries.append(current)
            continue
        field = _FIELD.match(line)
        if field and current is not None:
            current[field.group(1)] = field.group(2)
    return [e for e in entries if "splits" in e and "symbols" in e]


def modules(root, version):
    """Every module of one version, the DOL first."""
    root = Path(root)
    config = root / "config" / version
    build = root / "build" / version
    found = [
        Module(
            root=root,
            version=version,
            name=DOL_NAME,
            splits=config / "splits.txt",
            symbols=config / "symbols.txt",
            build=build,
            is_dol=True,
        )
    ]
    manifest = config / "config.yml"
    if not manifest.is_file():
        return found
    for entry in _module_entries(manifest.read_text(encoding="utf-8")):
        found.append(
            Module(
                root=root,
                version=version,
                name=Path(entry["object"]).stem,
                splits=root / entry["splits"],
                symbols=root / entry["symbols"],
                build=build / Path(entry["object"]).stem,
                is_dol=False,
            )
        )
    return found


def find(root, version, name=DOL_NAME):
    """One module by name, defaulting to the DOL."""
    for module in modules(root, version):
        if module.name == name:
            return module
    available = ", ".join(m.name for m in modules(root, version))
    raise SystemExit(f"{version} has no module {name!r}; available: {available}")


def pair(root, source, target):
    """Match each target module to its source counterpart, by position.

    Names differ across regions, so position in `config.yml` is the only stable
    correspondence available. A target module with no counterpart is paired with
    `None` rather than dropped: that is itself worth reporting.
    """
    sources = modules(root, source)
    targets = modules(root, target)
    return [
        (t, sources[index] if index < len(sources) else None)
        for index, t in enumerate(targets)
    ]
