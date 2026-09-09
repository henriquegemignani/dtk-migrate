#!/usr/bin/env python3

# Historical all-sections promotion loop. For code discovery use discover_splits.py;
# for actual compiled-object link verification use verify_source_units.py.
#
# Objdiff scores describe comparison coverage, not whole-file correctness.
# A retail hash is evidence for source code only when those compiled objects
# actually occur in the linker inputs. This loop does not enable candidates,
# so its hash check validates split integrity and its raw-ELF fallback is
# disabled unless a caller explicitly supplies verified source-link provenance.

from __future__ import annotations

import argparse
import bisect
import json
import platform
import re
import struct
import subprocess
import sys
from itertools import pairwise
from pathlib import Path

ROOT_DIR = Path.cwd()
EXE = ".exe" if platform.system() == "Windows" else ""
DTK_OVERRIDE: Path | None = None

ENTRY_RE = re.compile(
    r"^(?P<section>\S+)\s+start:0x(?P<start>[0-9A-Fa-f]+)\s+end:0x(?P<end>[0-9A-Fa-f]+)"
)

# configure.py's src_dir overrides (grep '"src_dir"' configure.py): most units
# live under the default "src/", but the two SDK-derived modules override it.
# report.json's metadata.source_path carries this prefix; splits.txt/the
# match proposal never do -- get this wrong and every SDK-sourced candidate
# (dolphin/*, musyx/*, runtime/*) silently looks "not found in the rebuilt
# report" even when it built and matched perfectly.
SOURCE_ROOTS = ("extern/musyx/src/", "extern/sdk/", "src/")


def strip_source_root(path: str) -> str:
    for root in SOURCE_ROOTS:
        if path.startswith(root):
            return path[len(root) :]
    return path


SYMBOL_RE = re.compile(r"^(\S+) = \.\w+:0x([0-9A-Fa-f]+);")

# dtk's own convention for a symbol it invented because nothing claims that
# address yet (src/util/config.rs, is_auto_symbol) -- not a real name from
# any source file.
AUTO_SYMBOL_PREFIXES = ("lbl_", "fn_", "jumptable_", "gap_", "pad_", "dtor_")


def is_auto_symbol(name: str) -> bool:
    return name.startswith(AUTO_SYMBOL_PREFIXES)


class SymbolNeighbors:
    """Answers 'what symbol sits right next to this address' from a target
    version's symbols.txt, to detect a specific false-rejection shape: a
    candidate's data (a vtable, typically) is correctly sized and its bytes
    genuinely match, but objdiff's target-side comparison symbol bleeds a few
    bytes into whatever unclaimed content sits next to it, since that
    neighbor has no boundary of its own yet -- see docs/match_learnings.md,
    "vtable near-miss". Every case found this way involved an auto_*-style
    generated name (lbl_/jumptable_/etc, see AUTO_SYMBOL_PREFIXES) directly
    adjacent to the candidate's start or end."""

    def __init__(self, symbols_path: Path):
        pairs = []
        for line in symbols_path.read_text(encoding="utf-8").splitlines():
            m = SYMBOL_RE.match(line)
            if m:
                pairs.append((int(m.group(2), 16), m.group(1)))
        pairs.sort()
        self.addrs = [a for a, _ in pairs]
        self.names = [n for _, n in pairs]

    def border_flags(self, start: int, end: int) -> tuple[bool, bool]:
        """(bleeds_before, bleeds_after): whether the symbol immediately
        preceding `start`, or at/after `end`, is one dtk invented because
        nothing claims that address yet. Split out from borders_unclaimed
        so a caller that finds a `True` can tell which side it's on --
        needed to look up the *specific* address a companion candidate
        would need to cover (see build_proposal_range_index)."""
        i = bisect.bisect_left(self.addrs, end)
        bleeds_after = i < len(self.names) and is_auto_symbol(self.names[i])
        j = bisect.bisect_left(self.addrs, start) - 1
        bleeds_before = j >= 0 and is_auto_symbol(self.names[j])
        return bleeds_before, bleeds_after

    def borders_unclaimed(self, start: int, end: int) -> bool:
        return any(self.border_flags(start, end))


def run(cmd, capture=False):
    # Match and split must use the same binary. Passing --dtk only to match
    # otherwise lets configure/ninja silently download a different DTK.
    if DTK_OVERRIDE is not None and len(cmd) > 1 and str(cmd[1]) == "configure.py":
        cmd = [*cmd, "--dtk", str(DTK_OVERRIDE)]
    print("+", " ".join(str(c) for c in cmd))
    if capture:
        return subprocess.run(
            cmd, cwd=ROOT_DIR, check=True, capture_output=True, text=True
        )
    subprocess.run(cmd, cwd=ROOT_DIR, check=True)
    return None


CONFLICT_RE = re.compile(
    r"Mismatched splits for .*?\(([^)]+)\) and function .*?\(([^)]+)\)"
)
CYCLE_RE = re.compile(r"Cyclic dependency encountered while resolving link order: (.+)")
# decomp-toolkit's own root-cause diagnosis for a link-order cycle: it isolates
# the specific section (and a small handful of its edges) that's actually
# necessary and sufficient to recreate the cycle, rather than just the raw
# DFS-found chain (which can span nearly an entire section -- a single
# contradictory edge from one section, combined with an otherwise-total order
# in another, closes a cycle spanning everything between the two endpoints;
# see docs/match_learnings.md). When present, this is far more precise than
# CYCLE_RE's full chain, which still follows it for backward compatibility.
CONFLICT_SECTION_RE = re.compile(
    r"Conflict across section\(s\) \[[^\]]*\] \(removing their edges together would resolve the cycle\):\n"
    r"((?:[ \t]+\[[^\]]+\]\s+\S.*? -> \S.*?\n)+)"
)
CONFLICT_EDGE_RE = re.compile(r"^[ \t]+\[[^\]]+\]\s+(.+?) -> (.+?)$", re.MULTILINE)


def extract_conflict_names(text: str) -> set[str]:
    """Pulls unit names out of the split-step failure shapes seen so far: a
    .ctors-table entry and its target function attributed to different units,
    or a link-order cycle. For a cycle, prefers dtk's own precise diagnosis
    (CONFLICT_SECTION_RE) when present -- a handful of names that are
    actually responsible -- over the raw DFS chain (CYCLE_RE), which can name
    hundreds of innocent bystanders. Falls back to the raw chain only when no
    precise diagnosis was given (a genuinely multi-section conflict dtk
    couldn't isolate to one section)."""
    names: set[str] = set()
    m = CONFLICT_RE.search(text)
    if m:
        names.update(m.groups())
    precise_blocks = CONFLICT_SECTION_RE.findall(text)
    if precise_blocks:
        for block in precise_blocks:
            for a, b in CONFLICT_EDGE_RE.findall(block):
                names.add(a.strip())
                names.add(b.strip())
        return names
    m = CYCLE_RE.search(text)
    if m:
        names.update(part.strip() for part in m.group(1).split("->"))
    return names


ADDR_RE = re.compile(r"0x[0-9A-Fa-f]{6,8}")


def nearest_candidate_by_address(
    text: str, remaining: list[tuple[str, list[str]]]
) -> str | None:
    """Fallback for a split-step failure shape extract_conflict_names doesn't
    recognize (e.g. an alignment error on an auto_* leftover chunk, which
    names that auto chunk, not one of ours). These are all local
    address-space problems, so the staged candidate whose range sits closest
    to whatever address the message names is the most likely cause -- drop
    that one instead of giving up outright."""
    addrs = [int(a, 16) for a in ADDR_RE.findall(text)]
    if not addrs:
        return None
    best_name, best_dist = None, None
    for name, lines in remaining:
        for line in lines:
            r = parse_range(line)
            if not r:
                continue
            _, start, end = r
            dist = min(min(abs(addr - start), abs(addr - end)) for addr in addrs)
            if best_dist is None or dist < best_dist:
                best_name, best_dist = name, dist
    return best_name


def clean_entry_line(line: str) -> str:
    """Strips a proposal file's leading '#' and trailing '# candidate: ...'
    annotation, if present. A no-op on an already-clean splits.txt line."""
    line = line.removeprefix("#")
    idx = line.find("  # candidate:")
    if idx != -1:
        line = line[:idx]
    return line


def parse_range(line: str):
    m = ENTRY_RE.match(line.strip())
    if not m:
        return None
    return m["section"], int(m["start"], 16), int(m["end"], 16)


def parse_splits(text: str):
    """Parses a splits.txt or `dtk match --splits` proposal file into
    (header text, {unit name: [clean body lines]}, name order). Candidate
    lines are uncommented. Everything up to the first blank line is kept
    only as header text -- a real splits.txt's 'Sections:' block, or a
    proposal file's banner comment (discarded by callers either way)."""
    lines = text.replace("\r\n", "\n").split("\n")
    header_lines = []
    i = 0
    while i < len(lines):
        header_lines.append(lines[i])
        i += 1
        if header_lines[-1].strip() == "":
            break
    header = "\n".join(header_lines) + "\n"

    blocks: dict[str, list[str]] = {}
    order: list[str] = []
    name, body = None, []

    def flush():
        nonlocal name, body
        if name is not None and body:
            blocks[name] = body
            order.append(name)
        name, body = None, []

    for line in lines[i:]:
        if line.strip() == "":
            flush()
            continue
        is_header = not line.startswith(("\t", " ")) and line.rstrip().endswith(":")
        if is_header:
            flush()
            name = line.rstrip()[:-1]
            continue
        if name is None:
            continue  # banner text before the first real unit
        body.append(clean_entry_line(line))
    flush()
    return header, blocks, order


def raw_proposal_lines(text: str) -> dict[str, list[str]]:
    """Same unit-block parsing as parse_splits, but keeps each line exactly
    as written -- '#'-comment prefix and trailing '# candidate: ...' reason
    both intact. dominant_cluster needs the reason text (specifically,
    whether dtk match already flagged a range as failing the section's
    alignment requirement) that parse_splits's cleaned lines discard."""
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip() == "":
            i += 1
            break
        i += 1

    blocks: dict[str, list[str]] = {}
    name, body = None, []

    def flush():
        nonlocal name, body
        if name is not None and body:
            blocks[name] = body
        name, body = None, []

    for line in lines[i:]:
        if line.strip() == "":
            flush()
            continue
        is_header = not line.startswith(("\t", " ")) and line.rstrip().endswith(":")
        if is_header:
            flush()
            name = line.rstrip()[:-1]
            continue
        if name is None:
            continue
        body.append(line)
    flush()
    return blocks


def write_splits(
    path: Path, header: str, blocks: dict[str, list[str]], order: list[str]
):
    """Writes blocks in exactly `order`. Callers must pass the target file's
    own original order for its existing blocks -- the file isn't sorted by
    address, so re-sorting it would turn every untouched unit into a diff.
    `header` already ends in the blank line that follows 'Sections:', so
    blocks are appended, not joined -- joining would double up that blank."""
    parts = [header]
    for name in order:
        parts.append(f"{name}:\n")
        for line in blocks[name]:
            parts.append(line + "\n")
        parts.append("\n")
    text = "".join(parts)
    while text.endswith("\n\n"):
        text = text[:-1]
    path.write_text(text, encoding="utf-8")


class FunctionConfidence:
    """Looks up dtk match's own per-function tier/confidence for addresses in
    a candidate's .text ranges, from the `--output` JSON report. This is a
    much stronger signal than a proposal's size or its coarse unit-level
    tier: `classify()`'s Confident/Candidate split is an AND of eight
    conditions (see unit_matching.rs), several of which -- like requiring a
    file's non-text content to *also* already be matched -- demote a unit to
    Candidate even when every one of its functions is individually a strong,
    Confident-tier match. Cross-checking against this session's actual
    pass/fail results: every candidate that came back 0% fuzzy had *no*
    individually-Confident functions backing it (all were 'probable', at
    0.8-0.93 confidence) -- so this is what should drive priority, not size."""

    def __init__(self, report: dict):
        matches = report.get("matches", [])
        pairs = sorted((int(m["target_address"], 16), m) for m in matches)
        self.addrs = [a for a, _ in pairs]
        self.by_addr = {a: m for a, m in pairs}

    def functions_in(self, start: int, end: int) -> list[dict]:
        lo = bisect.bisect_left(self.addrs, start)
        hi = bisect.bisect_left(self.addrs, end)
        return [self.by_addr[a] for a in self.addrs[lo:hi]]

    def score(self, lines: list[str]) -> tuple[bool, float]:
        """(all_confident, min_confidence) across every .text range in a
        candidate. `all_confident` is the primary sort key: True first.
        A candidate with no .text (a pure data/bss proposal) scores
        (False, -1.0) -- there's no function-level signal for it, so it
        falls behind every candidate this signal actually supports."""
        funcs = []
        for line in lines:
            r = parse_range(line)
            if r and r[0] == ".text":
                funcs.extend(self.functions_in(r[1], r[2]))
        if not funcs:
            return False, -1.0
        all_confident = all(f["tier"] == "confident" for f in funcs)
        min_confidence = min(f["confidence"] for f in funcs)
        return all_confident, min_confidence


def is_fragmented(lines: list[str]) -> bool:
    """True if a proposed unit's lines put 2+ disjoint ranges in the same
    section. A single translation unit compiles to one contiguous chunk per
    section, so this means the matcher found two separate clusters of
    functions it believes belong to the same source file with something
    else's code sitting between them -- accepting it stages a boundary that
    can never satisfy link order (the unit would have to sit both before and
    after whatever's in the gap), guaranteeing a cyclic-dependency failure at
    build time. It's not a low-confidence guess to verify; it's already
    self-contradictory, so it's dropped before ever reaching the build."""
    by_section: dict[str, int] = {}
    for line in lines:
        r = parse_range(line)
        if r:
            by_section[r[0]] = by_section.get(r[0], 0) + 1
    return any(count > 1 for count in by_section.values())


ALIGNMENT_REASON = "split boundary doesn't meet the section's required alignment"


def drop_misaligned_sections(lines: list[str], raw_lines: list[str]) -> list[str]:
    """dtk match already flags a range that fails its section's own
    alignment requirement (ALIGNMENT_REASON) in the raw proposal comment.
    dominant_cluster (below) already checks this when reducing a
    fragmented proposal -- but an ordinary, already-single-range
    candidate's raw comment gets silently discarded by parse_splits's
    cleaning (clean_entry_line) and was never checked at all before
    staging. That's not just a wasted build for that one candidate:
    `dtk dol split` hard-rejects a misaligned boundary outright ("Invalid
    alignment for split"), and the auto-generated placeholder chunk that
    starts immediately after inherits whatever address the previous
    declared split ends at -- so one misaligned candidate can manufacture
    an alignment failure (or contribute to a link-order cycle) that looks
    like it's about a completely unrelated unit. Found responsible for
    13 of 61 non-fragmented candidates in one real batch, several of
    which were also tangled up in a since-fixed .bss link-order cycle.
    Call unconditionally on every candidate's final lines, fragmented-
    reduced or not -- a no-op when nothing's flagged."""
    raw_by_clean = {clean_entry_line(l): l for l in raw_lines}
    return [l for l in lines if ALIGNMENT_REASON not in raw_by_clean.get(l, "")]


def dominant_cluster(raw_lines: list[str]) -> list[str] | None:
    """Best-effort reduction of a fragmented proposal to a stageable one: per
    section, if 2+ disjoint ranges were proposed, keep only the largest
    aligned one -- whatever its share of the section's bytes -- and drop the
    rest. A section with just one range passes through unchanged, unless
    that one range is itself misaligned (see below), in which case it's
    dropped too. Takes raw (still '#'-commented) proposal lines, not
    parse_splits's cleaned ones -- it needs dtk match's own per-range reason
    annotation to rule out a range up front (see below).

    This is a real bet, not a structural fix: dtk validates that a staged
    split's compiled object exactly matches its declared range, so keeping
    only the dominant cluster only produces a valid split when the *dropped*
    smaller fragments are actually someone else's code -- typically a small
    member function (operator=, a dtor, a copy ctor) that MWCC emitted as a
    local instantiation inside this TU in one version but not, at the same
    relative position, in the other (see docs/match_learnings.md, the
    MetroidPrime/main.cpp writeup). Nothing here can distinguish that from a
    genuine missing piece of this unit's own code from the boundary alone --
    that's exactly what the existing verify step (100% fuzzy match, then a
    real link) is for. A wrong guess fails it and gets skip-listed like any
    other rejected candidate; staging one isn't conservative on purpose --
    a bad guess costs one cheap, reversible build attempt, not a real
    mistake (see docs/match_learnings.md, splits are cheap to revert).

    One thing *is* checked up front rather than left to the build, though:
    a range dtk match already flagged with ALIGNMENT_REASON is never picked,
    even if it's the biggest -- `dtk dol split` rejects a misaligned
    boundary outright ("Invalid alignment for split: ..."), a hard failure
    the verify step can't distinguish from a real conflict, so it's cheaper
    to rule out here than to burn a build (and a `nearest_candidate_by_address`
    misfire, see stage_and_build) discovering it.

    Returns None only if every section was entirely misaligned -- there's
    no valid range left to pick at all, not even a risky one."""
    by_section: dict[str, list[tuple[int, int, str, bool]]] = {}
    for raw_line in raw_lines:
        cleaned = clean_entry_line(raw_line)
        r = parse_range(cleaned)
        if r:
            section, start, end = r
            by_section.setdefault(section, []).append(
                (start, end, cleaned, ALIGNMENT_REASON in raw_line)
            )

    kept: list[str] = []
    for ranges in by_section.values():
        if len(ranges) == 1:
            # Not fragmented, but still don't forward a misaligned single
            # range just because it slipped in alongside a fragmented
            # section elsewhere in this same unit -- same hard failure.
            if not ranges[0][3]:
                kept.append(ranges[0][2])
            continue
        aligned = [r for r in ranges if not r[3]]
        if not aligned:
            continue  # every range in this section is misaligned -- skip it
        largest = max(aligned, key=lambda r: r[1] - r[0])
        kept.append(largest[2])
    return kept or None


def load_skip_list(path: Path) -> set[str]:
    """Reads just the names, for the fast membership check candidate
    selection needs. Each line is `name<TAB>reason`; a bare name (no tab) is
    accepted too, for any list written before reasons were tracked."""
    return set(load_skip_list_with_reasons(path))


def load_skip_list_with_reasons(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, reason = line.partition("\t")
        result[name] = reason or "(no reason recorded)"
    return result


def append_skip_list(path: Path, entries: list[tuple[str, str]]):
    """`entries` is (name, reason) pairs -- see `load_skip_list_with_reasons`
    for the format. Kept human-reviewable on purpose: `review_skip_list.py`-
    style auditing (or just `grep`) needs the reason, not just the name, to
    tell a genuine bad match from collateral damage of a script bug."""
    if not entries:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_skip_list(path)
    new = [(n, r) for n, r in entries if n not in existing]
    if not new:
        return
    with path.open("a", encoding="utf-8") as f:
        for name, reason in new:
            f.write(f"{name}\t{reason}\n")


def build_claimed_ranges(blocks: dict[str, list[str]]):
    claimed: dict[str, list[tuple[int, int]]] = {}
    for lines in blocks.values():
        for r in (parse_range(l) for l in lines):
            if r:
                section, start, end = r
                claimed.setdefault(section, []).append((start, end))
    return claimed


def build_proposal_range_index(
    pool: dict[str, list[str]],
) -> tuple[dict[tuple[str, int], str], dict[tuple[str, int], str]]:
    """Maps a candidate's own range boundaries back to its name, keyed by
    (section, address) -- so a candidate found to border unclaimed content
    (SymbolNeighbors.border_flags) can be matched to whichever OTHER
    still-available candidate's range starts (`starts`) or ends (`ends`)
    exactly there: the actual missing puzzle piece dtk match already
    proposed a boundary for, not just 'some address is unclaimed'."""
    starts: dict[tuple[str, int], str] = {}
    ends: dict[tuple[str, int], str] = {}
    for name, lines in pool.items():
        for line in lines:
            r = parse_range(line)
            if r:
                section, start, end = r
                starts[(section, start)] = name
                ends[(section, end)] = name
    return starts, ends


def overlaps_claimed(claimed, section, start, end) -> bool:
    return any(start < e and s < end for s, e in claimed.get(section, []))


def reconfigure_and_build(version: str, target: str):
    run([sys.executable, "configure.py", "configure", "-v", version])
    run(["ninja", target])


LINKER_UNDEFINED_OBJECT_RE = re.compile(r"in ([A-Za-z0-9_]+)\.o")


def verify_link(version: str) -> tuple[bool, str]:
    """`ninja build/<version>/report.json` (what the rest of this script
    checks) never touches main.elf at all -- a candidate can compile clean
    and match 100% while calling a function that's genuinely unnamed
    anywhere in symbols.txt (not matched, not even given an address), which
    only surfaces as an undefined-symbol *linker* error, and only once
    something is actually compiled from source rather than pulled from
    orig/ as a raw leftover byte range. Found this the hard way: a promoted
    candidate broke a real `ninja` (see docs/match_learnings.md). This is
    the missing check -- run after every promotion, before the split is
    considered real."""
    try:
        run([sys.executable, "configure.py", "configure", "-v", version], capture=True)
        run(["ninja", f"build/{version}/main.elf"], capture=True)
        return True, ""
    except subprocess.CalledProcessError as e:
        return False, (e.stdout or "") + (e.stderr or "")


def verify_full_hash(version: str) -> tuple[bool, str]:
    """Even a clean link (verify_link) doesn't prove *where* anything
    landed. dominant_cluster's whole bet is a split boundary narrower than
    what the source unit's NTSC size implies -- MWCC still emits every
    function the TU has (a __sinit_* static-initializer being the common
    one), and if the declared range doesn't cover it, the linker packs the
    overflow whereever link order says next, which can land it on a byte
    range a neighboring unit (still raw orig/ bytes) expects to own.
    report.json's fuzzy score is purely local to each declared range, and a
    link only needs every *symbol* to resolve to *something* -- neither
    catches a few bytes quietly landing in the wrong place. Found this the
    hard way: CGrenadeLauncher.cpp's reduced split passed both, and only
    broke build/{version}/ok (see docs/match_learnings.md, 'the hash check
    is the only real oracle'). This is the actual gate; run after every
    promotion, before the split is considered real."""
    try:
        run(["ninja", f"build/{version}/ok"], capture=True)
        return True, ""
    except subprocess.CalledProcessError as e:
        return False, (e.stdout or "") + (e.stderr or "")


def diff_symbol_addresses(version: str, dtk: Path) -> str:
    """`dtk dol diff` walks every named symbol and reports each one whose
    linked address/size/content disagrees with what config/symbols.txt
    declared -- far more specific than build/{version}/ok's single
    pass/fail bit, and exactly the address-bearing text
    nearest_candidate_by_address needs to place blame on a promoted unit."""
    try:
        result = run(
            [
                str(dtk),
                "-L",
                "error",
                "dol",
                "diff",
                f"config/{version}/config.yml",
                f"build/{version}/main.elf",
            ],
            capture=True,
        )
        return (result.stdout or "") + (result.stderr or "") if result else ""
    except subprocess.CalledProcessError as e:
        return (e.stdout or "") + (e.stderr or "")


def load_report(version: str) -> dict:
    path = ROOT_DIR / "build" / version / "report.json"
    return json.loads(path.read_text(encoding="utf-8"))


class Dol:
    """Minimal reader for a GameCube DOL: address-to-file-offset lookup and
    PowerPC `bl` decoding, used to read a call site's real branch target
    straight out of the retail binary."""

    def __init__(self, path: Path):
        self.data = path.read_bytes()
        text = zip(
            struct.unpack(">7I", self.data[0x00:0x1C]),
            struct.unpack(">7I", self.data[0x48:0x64]),
            struct.unpack(">7I", self.data[0x90:0xAC]),
        )
        data = zip(
            struct.unpack(">11I", self.data[0x1C:0x48]),
            struct.unpack(">11I", self.data[0x64:0x90]),
            struct.unpack(">11I", self.data[0xAC:0xD8]),
        )
        self.sections = [(o, a, s) for o, a, s in list(text) + list(data) if s]

    def va_to_file_offset(self, va: int) -> int | None:
        for off, addr, size in self.sections:
            if addr <= va < addr + size:
                return off + (va - addr)
        return None

    def read_bytes(self, va: int, length: int) -> bytes | None:
        """None for a BSS address, same as va_to_file_offset -- the DOL's
        11 data-section slots never cover BSS (it's runtime-zeroed, not
        stored in the file), so no entry in `self.sections` claims it."""
        off = self.va_to_file_offset(va)
        if off is None:
            return None
        return self.data[off : off + length]

    def read_u32(self, va: int) -> int | None:
        off = self.va_to_file_offset(va)
        if off is None:
            return None
        return struct.unpack(">I", self.data[off : off + 4])[0]

    def decode_bl_target(self, va: int) -> int | None:
        """None unless the instruction at `va` is a real `bl` (opcode 18,
        LK set) -- both to reject a misaligned read and because a plain `b`
        (LK clear, a tail-call/branch) isn't what a relocated call compiles
        to here."""
        instr = self.read_u32(va)
        if instr is None or (instr >> 26) != 18 or not (instr & 1):
            return None
        li = instr & 0x03FFFFFC
        if li & 0x02000000:
            li -= 0x04000000
        return (va + li) & 0xFFFFFFFF


SHT_NOBITS = 8


class Elf:
    """Minimal reader for a linked ELF (main.elf): address-to-file-offset
    lookup via its section headers. Deliberately reads from the *linked*
    result, not an unlinked per-unit .o -- an unlinked object's relocated
    fields (call targets, data pointers) hold placeholder values that
    would never byte-match the retail DOL even for genuinely correct code;
    only fully-linked, fully-relocated bytes are safe to compare raw."""

    def __init__(self, path: Path):
        self.data = path.read_bytes()
        e_shoff = struct.unpack(">I", self.data[0x20:0x24])[0]
        e_shentsize = struct.unpack(">H", self.data[0x2E:0x30])[0]
        e_shnum = struct.unpack(">H", self.data[0x30:0x32])[0]
        e_shstrndx = struct.unpack(">H", self.data[0x32:0x34])[0]

        raw = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            name_off, sh_type, _flags, sh_addr, sh_offset, sh_size = struct.unpack(
                ">IIIIII", self.data[off : off + 24]
            )
            raw.append((name_off, sh_type, sh_addr, sh_offset, sh_size))

        strtab_off = raw[e_shstrndx][3]

        def section_name(name_off: int) -> str:
            end = self.data.index(b"\0", strtab_off + name_off)
            return self.data[strtab_off + name_off : end].decode("ascii")

        # (type, addr, offset, size) -- name kept only for section_name's
        # lookup above, not needed afterward.
        self.sections = [
            (sh_type, addr, offset, size) for _, sh_type, addr, offset, size in raw
        ]

    def read_bytes(self, va: int, length: int) -> bytes | None:
        """None for a BSS address (SHT_NOBITS -- runtime-zeroed, no file
        content to read) or one no section covers at all."""
        for sh_type, addr, offset, size in self.sections:
            if sh_type != SHT_NOBITS and addr <= va and va + length <= addr + size:
                file_off = offset + (va - addr)
                return self.data[file_off : file_off + length]
        return None


FN_RE = re.compile(r'^\.fn\s+"?([^",]+)"?,')
# Matches every instruction line, to find a function's real first
# instruction. BL_INSTR_RE (below) matches only `bl` lines specifically --
# using it alone to track fn_starts would record the offset of a function's
# *first branch-and-link*, not its first instruction (almost never the
# same one), silently corrupting every offset computed from it. Found this
# the hard way: it looked like it worked (found a real address, backed by a
# real opcode-18 decode) purely by luck on the first call site tried, then
# fell apart on the 2nd and 3rd -- see docs/match_learnings.md.
ANY_INSTR_RE = re.compile(
    r"^/\* ([0-9A-Fa-f]{8}) [0-9A-Fa-f]{8}\s+[0-9A-Fa-f]{2} [0-9A-Fa-f]{2} [0-9A-Fa-f]{2} [0-9A-Fa-f]{2} \*/"
)
BL_INSTR_RE = re.compile(
    r"^/\* ([0-9A-Fa-f]{8}) [0-9A-Fa-f]{8}\s+([0-9A-Fa-f]{2} [0-9A-Fa-f]{2} [0-9A-Fa-f]{2} [0-9A-Fa-f]{2}) \*/\s+bl (\S+)"
)

# MWCC's placeholder encoding for a `bl` to an external symbol the compiler
# has no local definition for: displacement zeroed, LK set. This is what a
# genuinely undefined reference looks like in an otherwise-valid object file
# -- distinct from a real (non-zero) relocation to something the compiler
# *did* resolve within the same translation unit.
UNRESOLVED_BL_BYTES = "48 00 00 01"


def parse_disasm(
    disasm_text: str,
) -> tuple[dict[str, int], dict[str, list[tuple[str, int]]]]:
    """Parses `dtk elf disasm` output for (a) each function's own start
    offset within the object file, and (b) every still-unresolved `bl`,
    grouped by the mangled name of the symbol it targets. Offsets are
    relative to the object's own start, not any one function's -- callers
    convert to a real address via `function's own start` + `retail address
    of that function`, since a compiled object can (and does, in practice)
    contain extra functions -- template instantiation helpers, mainly --
    that aren't part of the target version's declared split, making a flat
    whole-object offset unreliable past the first such divergence."""
    fn_starts: dict[str, int] = {}
    unresolved: dict[str, list[tuple[str, int]]] = {}
    current_fn: str | None = None
    for line in disasm_text.splitlines():
        m = FN_RE.match(line)
        if m:
            current_fn = m.group(1)
            continue
        m = ANY_INSTR_RE.match(line)
        if not m or current_fn is None:
            continue
        offset = int(m.group(1), 16)
        fn_starts.setdefault(current_fn, offset)
        bl_m = BL_INSTR_RE.match(line)
        if bl_m and bl_m.group(2) == UNRESOLVED_BL_BYTES:
            unresolved.setdefault(bl_m.group(3), []).append((current_fn, offset))
    return fn_starts, unresolved


def resolve_undefined_symbol(
    dol: Dol,
    disasm_text: str,
    mangled_target: str,
    function_vas: dict[str, int],
) -> tuple[int, int] | None:
    """Attempts to recover `mangled_target`'s real address by reading every
    known call site's actual encoded branch target out of the retail DOL --
    the target binary is a real linked executable, so a `bl` there always
    carries its true, resolved destination even when nothing in symbols.txt
    names it yet. `function_vas` must be restricted to functions individually
    at 100% fuzzy_match_percent (report.json), since only those are provably
    byte-for-byte aligned with retail; anything less makes the offset math
    meaningless. Returns (address, corroborating_call_count) only when every
    checkable call site agrees -- a single disagreement is treated as total
    failure, not a majority vote, since there's no way to tell which
    instance would be lying."""
    fn_starts, unresolved = parse_disasm(disasm_text)
    targets: set[int] = set()
    checked = 0
    for caller, call_offset in unresolved.get(mangled_target, []):
        func_va = function_vas.get(caller)
        func_start = fn_starts.get(caller)
        if func_va is None or func_start is None:
            continue
        call_va = func_va + (call_offset - func_start)
        target = dol.decode_bl_target(call_va)
        if target is not None:
            targets.add(target)
            checked += 1
    if checked == 0 or len(targets) != 1:
        return None
    return targets.pop(), checked


LINKER_ERROR_RE = re.compile(r"Linker Error:\n((?:#(?!##)[^\n]*\n)+)")
UNDEFINED_SYMBOL_RE = re.compile(r"undefined: '(.+?)'", re.DOTALL)
REFERENCED_FROM_RE = re.compile(r"Referenced from '(.+?)' in (\S+)\.o", re.DOTALL)


def parse_linker_errors(text: str) -> list[dict[str, str]]:
    """Parses mwldeppc's undefined-symbol errors out of captured build
    output. Each error's demangled names wrap across several `#`-prefixed
    continuation lines -- those are rejoined into single strings first."""
    errors = []
    for block in LINKER_ERROR_RE.findall(text):
        joined = " ".join(line.lstrip("#").strip() for line in block.splitlines())
        undefined_m = UNDEFINED_SYMBOL_RE.search(joined)
        ref_m = REFERENCED_FROM_RE.search(joined)
        if undefined_m and ref_m:
            errors.append(
                {
                    "undefined": undefined_m.group(1),
                    "referenced_from": ref_m.group(1),
                    "object": ref_m.group(2),
                }
            )
    return errors


def normalize_signature(s: str) -> str:
    """The linker error's demangled names are reassembled from wrapped
    lines (see parse_linker_errors) and don't reliably preserve the space
    after a comma that report.json's and `dtk demangle`'s own renderings
    do -- comparing signatures verbatim silently fails on that alone, so
    every comparison strips whitespace entirely first."""
    return re.sub(r"\s+", "", s)


def demangled_to_mangled(unit: dict, demangled_name: str) -> str | None:
    """Looks up a function's mangled name from report.json's per-unit
    function list by its demangled form -- the linker error only gives the
    demangled version, but the disassembly (and dtk match's own data) index
    by mangled name."""
    target = normalize_signature(demangled_name)
    for f in unit.get("functions") or []:
        if (
            normalize_signature(f.get("metadata", {}).get("demangled_name", ""))
            == target
        ):
            return f["name"]
    return None


AUTO_SYMBOL_LINE_RE = re.compile(r"^(\S+)\s*=\s*\.text:(0x[0-9A-Fa-f]+);(.*)$")


def apply_symbol_fix(symbols_path: Path, mangled_name: str, address: int) -> bool:
    """Renames dtk's auto-generated placeholder at `address` (if any) to
    `mangled_name`, in place. This address was read directly out of the
    retail DOL's own already-resolved branch instructions, cross-checked
    against every call site with unanimous agreement required -- that's
    ground truth read off a real linked binary, not a guess, so it's safe
    to apply immediately. Still refuses to touch a line that already has a
    real (non-auto) name: that would be overwriting a human's or a prior
    tool run's decision, which is a genuine conflict for a person to look
    at, not something to silently clobber. Returns whether it applied."""
    lines = symbols_path.read_text(encoding="utf-8").splitlines(keepends=True)
    for i, line in enumerate(lines):
        m = AUTO_SYMBOL_LINE_RE.match(line.strip())
        if m is None or int(m.group(2), 16) != address:
            continue
        name = m.group(1)
        if name == mangled_name:
            return True
        if not is_auto_symbol(name):
            return False
        lines[i] = line.replace(name, mangled_name, 1)
        symbols_path.write_text("".join(lines), encoding="utf-8")
        return True
    return False


def suggest_undefined_symbol_fixes(
    version: str, unit_name: str, link_error_text: str, report: dict, symbols_path: Path
) -> bool:
    """For every undefined-symbol error blamed on `unit_name`, tries to
    recover the real address from the retail DOL (see resolve_undefined_symbol)
    and, when every call site agrees, applies it to symbols.txt via
    apply_symbol_fix and prints what it did. Returns True only if every
    error for this unit got resolved and applied -- the caller can then
    retry linking this unit instead of giving up on it."""
    errors = [
        e
        for e in parse_linker_errors(link_error_text)
        if e["object"] == Path(unit_name).stem
    ]
    if not errors:
        return False

    unit = next(
        (
            u
            for u in report["units"]
            if strip_source_root(u.get("metadata", {}).get("source_path", ""))
            == unit_name
        ),
        None,
    )
    if unit is None:
        return False

    dol_path = ROOT_DIR / "orig" / version / "sys" / "main.dol"
    if not dol_path.exists():
        return False
    dol = Dol(dol_path)

    obj_path = ROOT_DIR / "build" / version / "src" / Path(unit_name).with_suffix(".o")
    if not obj_path.exists():
        return False
    disasm_path = ROOT_DIR / "build" / version / f"{Path(unit_name).stem}.disasm.s"
    try:
        run(
            [
                str(ROOT_DIR / "build" / "tools" / f"dtk{EXE}"),
                "elf",
                "disasm",
                str(obj_path),
                str(disasm_path),
            ]
        )
        disasm_text = disasm_path.read_text(encoding="utf-8")
    except subprocess.CalledProcessError, OSError:
        return False
    finally:
        disasm_path.unlink(missing_ok=True)

    # Only functions individually at 100% are safe to use for the offset
    # math -- see resolve_undefined_symbol.
    function_vas = {
        f["name"]: int(f["metadata"]["virtual_address"])
        for f in unit.get("functions") or []
        if f.get("fuzzy_match_percent") == 100.0
    }
    _fn_starts, unresolved = parse_disasm(disasm_text)

    applied: dict[str, int] = {}
    all_resolved = True
    for error in errors:
        caller_mangled = demangled_to_mangled(unit, error["referenced_from"])
        if caller_mangled is None:
            all_resolved = False
            continue
        # Find which unresolved `bl` in this caller demangles to the
        # undefined symbol the linker named -- there may be several
        # different undefined symbols called from the same function.
        resolved_this_error = False
        for mangled_name, sites in unresolved.items():
            if not any(caller == caller_mangled for caller, _off in sites):
                continue
            demangled = run(
                [
                    str(ROOT_DIR / "build" / "tools" / f"dtk{EXE}"),
                    "demangle",
                    mangled_name,
                ],
                capture=True,
            ).stdout.strip()
            if normalize_signature(demangled) != normalize_signature(
                error["undefined"]
            ):
                continue
            if mangled_name in applied:
                resolved_this_error = True
                break
            result = resolve_undefined_symbol(
                dol, disasm_text, mangled_name, function_vas
            )
            if result is None:
                print(f"    (couldn't recover an address for {error['undefined']})")
                continue
            address, corroborating = result
            if apply_symbol_fix(symbols_path, mangled_name, address):
                print(
                    f"    fix applied: {mangled_name} = .text:{address:#010x}; "
                    f"// {error['undefined']} -- agrees across {corroborating} call site(s)"
                )
                applied[mangled_name] = address
                resolved_this_error = True
            else:
                print(
                    f"    possible fix: {mangled_name} = .text:{address:#010x}; "
                    f"// {error['undefined']} -- agrees across {corroborating} call site(s), "
                    f"NOT applied (existing entry already has a real name, review by hand)"
                )
            break
        if not resolved_this_error:
            all_resolved = False
    return all_resolved


def sorted_ranges_by_section(
    blocks: dict[str, list[str]],
) -> dict[str, list[tuple[int, int, str]]]:
    """(start, end, unit) triples per section, address-sorted -- the
    layout find_suspicious_sections (below) checks a candidate's proposed
    neighbors against."""
    by_section: dict[str, list[tuple[int, int, str]]] = {}
    for name, lines in blocks.items():
        for line in lines:
            r = parse_range(line)
            if r:
                section, start, end = r
                by_section.setdefault(section, []).append((start, end, name))
    for ranges in by_section.values():
        ranges.sort()
    return by_section


MAX_NTSC_NEIGHBOR_DISTANCE = 80


def find_suspicious_sections(
    name: str,
    lines: list[str],
    ntsc_position: dict[str, int],
    target_ranges_by_section: dict[str, list[tuple[int, int, str]]],
) -> list[tuple[str, str]]:
    """Flags a section whose nearest real neighbor in the *target* address
    space is nowhere near this unit's own position in NTSC's declaration
    order -- the exact shape of a real bug found staging Metroid Prime's
    PAL port: CScriptRoomAcoustics.cpp's .text was correctly placed next
    to its true NTSC neighbors (CHudDecoInterface.cpp, CGunWeapon.cpp,
    both within a handful of positions), but its .data was a weak,
    both-edges-unpinned guess that put it next to CScriptCounter.cpp and
    CEffect.cpp -- units well over a hundred positions away in NTSC,
    nowhere near where CScriptRoomAcoustics.cpp actually belongs. That one
    wrong section was enough, staged alongside enough other candidates, to
    manufacture a real link-order cycle dtk's own diagnosis couldn't
    isolate to fewer than dozens of unrelated units.

    `target_ranges_by_section` should already include every other
    candidate in this round's pool (not just already-existing splits) --
    that's what actually caught this: CScriptCounter.cpp and CEffect.cpp
    were both being staged in the very same batch, not pre-existing.
    Looks at whichever real (non-auto, already-declared) unit sits
    immediately before/after this candidate's own range, per section --
    a section with no real neighbor on either side yet is left alone,
    since there's nothing there to contradict. Returns (section, reason)
    pairs for anything suspicious."""
    our_pos = ntsc_position.get(name)
    if our_pos is None:
        return []
    flagged = []
    for line in lines:
        r = parse_range(line)
        if not r:
            continue
        section, start, end = r
        items = [
            it for it in target_ranges_by_section.get(section, []) if it[2] != name
        ]
        i = bisect.bisect_left(items, (start, end, ""))
        neighbor_names = [items[j][2] for j in (i - 1, i) if 0 <= j < len(items)]
        distances = [
            abs(ntsc_position[n] - our_pos)
            for n in neighbor_names
            if n in ntsc_position
        ]
        if distances and min(distances) > MAX_NTSC_NEIGHBOR_DISTANCE:
            flagged.append(
                (
                    section,
                    f"target neighbor is {min(distances)} position(s) away in NTSC's own declaration order",
                )
            )
    return flagged


def build_link_order_graph(blocks: dict[str, list[str]]) -> dict[str, set[str]]:
    """Mirrors decomp-toolkit's resolve_link_order (src/util/split.rs): for
    each section, sorts every declared range by address and adds a directed
    edge from one unit to the next whenever they differ -- unioned across
    every section into one graph. A cycle in this graph is exactly what
    `dtk dol split` rejects with 'Cyclic dependency encountered while
    resolving link order'; building it here lets a candidate batch be
    checked for one before ever running a real build.

    Skips .bss entirely. decomp-toolkit's real resolve_link_order only
    skips edges touching a "common" BSS split (the CodeWarrior/mwld
    analogue of an ELF COMMON symbol -- a pool of tentative definitions
    the linker packs by its own rules, not link order), since regular
    (non-common) BSS follows real order same as any other section. This
    script has no way to tell common from non-common from splits.txt
    alone -- "common" is determined internally by dtk from the target's
    own .map file -- so it conservatively treats all of .bss as unordered.
    That's strictly more cautious than the real dtk build (which can still
    accept a batch this pre-check would trim candidates out of), never
    less: this is only a fast pre-filter, and stage_and_build's real-build
    retry loop is still the authority for whatever this approximation
    misses. (Found staging Metroid Prime's PAL port: a 386-node cyclic
    component that collapsed to 0 once .bss was excluded here.)"""
    by_section: dict[str, list[tuple[int, int, str]]] = {}
    for name, lines in blocks.items():
        for line in lines:
            r = parse_range(line)
            if r and r[0] != ".bss":
                section, start, end = r
                by_section.setdefault(section, []).append((start, end, name))
    graph: dict[str, set[str]] = {}
    for ranges in by_section.values():
        ranges.sort()
        for (_, _, a), (_, _, b) in pairwise(ranges):
            if a != b:
                graph.setdefault(a, set()).add(b)
    return graph


def find_sccs(graph: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan's strongly-connected-components algorithm, mirroring
    decomp-toolkit's tarjan_sccs (src/util/split.rs) -- used to find every
    genuinely tangled node set in a candidate batch's implied link order,
    the same way dtk's own diagnose_link_cycle does when a real build
    fails, just without needing the build to fail first."""
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old_limit, 2 * len(graph) + 100))
    index_counter = [0]
    stack: list[str] = []
    lowlink: dict[str, int] = {}
    index: dict[str, int] = {}
    on_stack: dict[str, bool] = {}
    result: list[list[str]] = []

    def strongconnect(node: str):
        index[node] = index_counter[0]
        lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack[node] = True

        for successor in graph.get(node, ()):
            if successor not in index:
                strongconnect(successor)
                lowlink[node] = min(lowlink[node], lowlink[successor])
            elif on_stack.get(successor):
                lowlink[node] = min(lowlink[node], index[successor])

        if lowlink[node] == index[node]:
            scc = []
            while True:
                w = stack.pop()
                on_stack[w] = False
                scc.append(w)
                if w == node:
                    break
            result.append(scc)

    try:
        for node in list(graph.keys()):
            if node not in index:
                strongconnect(node)
    finally:
        sys.setrecursionlimit(old_limit)
    return result


def resolve_batch_link_order(
    existing_blocks: dict[str, list[str]],
    scored_candidates: list[tuple[str, list[str]]],
) -> tuple[list[tuple[str, list[str]]], list[tuple[str, str]]]:
    """Greedily drops low-priority candidates until the model is acyclic.
    This does not guarantee a minimum removal set. It uses a simplified
    address-adjacency graph decomp-toolkit's own resolve_link_order builds
    (see build_link_order_graph) -- entirely in-process, so a batch that
    would otherwise take dozens of real (multi-second) builds to whittle
    down one candidate at a time gets resolved in milliseconds, before a
    single build runs. Found the hard way: staging ~80 confidence-sorted
    candidates scattered across the whole binary produced one enormous
    cyclic component spanning nearly all of .data -- dtk's own cycle
    diagnosis can only isolate a *small* culprit set, so it fell back to
    dumping the entire component, and the old one-drop-per-real-build loop
    just flailed through it a name at a time without ever resolving the
    actual structural issue.

    `scored_candidates` must already be priority-ordered (best first) --
    within a cyclic set, the lowest-priority (last) candidate is dropped
    first, so the highest-confidence ones survive whenever possible. Only
    ever drops a *candidate*; existing_blocks is trusted as already
    acyclic (a real, previously-verified build) and never touched.

    Still just a model of dtk's real graph, not dtk itself -- alignment,
    .ctors-specific quirks, and anything else dtk's own splitter checks
    can still fail a real build afterward. stage_and_build's existing
    retry loop stays as the safety net for whatever this misses."""
    candidates = dict(scored_candidates)
    order = [n for n, _ in scored_candidates]
    dropped: list[tuple[str, str]] = []
    while True:
        blocks = dict(existing_blocks)
        blocks.update({n: candidates[n] for n in order})
        graph = build_link_order_graph(blocks)
        sccs = find_sccs(graph)
        cyclic_candidates = {
            n for scc in sccs if len(scc) > 1 for n in scc if n in candidates
        }
        if not cyclic_candidates:
            break
        worst = max((n for n in order if n in cyclic_candidates), key=order.index)
        order.remove(worst)
        dropped.append(
            (
                worst,
                "implied link order conflicts with another staged candidate (resolved before building)",
            )
        )
    kept = [(n, candidates[n]) for n in order]
    return kept, dropped


MAX_CONFLICT_RETRIES = 450


def trim_to_confirmed_functions(
    unit: dict, lines: list[str], bad_section_names: set[str]
) -> list[str] | None:
    """A rejected candidate's *section*-level fuzzy score can hide that most
    of its individual functions actually compiled byte-identical -- dtk's
    report carries a separate fuzzy_match_percent per function, not just the
    section aggregate main() otherwise checks. Anchor on the largest
    confirmed (100%) function and grow outward through however many
    neighboring functions are *also* confirmed, stopping at the first one
    that isn't (or has no score at all -- e.g. one the matcher never placed
    a target for). The result is a smaller .text boundary this session has
    direct build evidence for, not a static heuristic's guess -- it still
    gets verified the same way as everything else, via a follow-up build.

    Sections other than .text are dropped unless they were already
    confirmed (i.e. not in `bad_section_names`): there's no per-symbol
    equivalent of this signal for data, so a boundary this method can't
    back up isn't carried along for the ride.

    Returns None if there's no .text range, no confirmed function to anchor
    on, or the trim wouldn't actually shrink anything."""
    text_range = None
    for line in lines:
        r = parse_range(line)
        if r and r[0] == ".text":
            text_range = (r[1], r[2])
            break
    if text_range is None:
        return None
    start, end = text_range
    funcs = []
    for f in unit.get("functions", []):
        va = int(f["metadata"]["virtual_address"])
        size = int(f["size"])
        if start <= va < end and size > 0:
            funcs.append((va, size, f.get("fuzzy_match_percent")))
    funcs.sort()
    if not funcs:
        return None
    confirmed_indices = [i for i, (_, _, pct) in enumerate(funcs) if pct == 100.0]
    if not confirmed_indices:
        return None
    anchor = max(confirmed_indices, key=lambda i: funcs[i][1])
    lo = anchor
    while lo > 0 and funcs[lo - 1][2] == 100.0:
        lo -= 1
    hi = anchor
    while hi + 1 < len(funcs) and funcs[hi + 1][2] == 100.0:
        hi += 1
    new_start, new_end = funcs[lo][0], funcs[hi][0] + funcs[hi][1]
    if (new_start, new_end) == (start, end) or new_start >= new_end:
        return None
    trimmed = [f"\t.text       start:{new_start:#010x} end:{new_end:#010x}"]
    for line in lines:
        r = parse_range(line)
        if r and r[0] != ".text" and r[0] not in bad_section_names:
            trimmed.append(line)
    return trimmed


def classify_built_unit(
    name, lines, by_path, neighbors, orig_dol, linked_elf, *, source_linked=False
):
    """Classifies one staged-and-built candidate against `by_path` (a
    report's units, keyed by source path -- see main()). Returns (bucket,
    reason, byte_confirmed, trim): bucket is 'promoted', 'rejected', or
    'blocked'; reason is None for 'promoted'; byte_confirmed is True only
    for a 'promoted' unit confirmed via direct byte comparison rather than
    dtk's fuzzy score; trim is a smaller, build-evidenced boundary worth a
    retry (see trim_to_confirmed_functions) when bucket is 'rejected' over a
    .text/.init mismatch specifically, else None. This is the same logic
    main() always ran inline, pulled out so a trimmed retry candidate can be
    classified through it too instead of duplicating the rules."""
    unit = by_path.get(name)
    if unit is None:
        return "rejected", "not found in the rebuilt report", False, None
    sections = unit.get("sections") or []
    if not sections:
        return "rejected", "no comparable sections in rebuilt report", False, None
    bad = [s for s in sections if s.get("fuzzy_match_percent", 0.0) < 100.0]
    if not bad:
        return "promoted", None, False, None
    worst = min(bad, key=lambda s: s.get("fuzzy_match_percent", 0.0))
    pct = worst.get("fuzzy_match_percent", 0.0)
    reason = f"{worst['name']} only {pct:.2f}% fuzzy"

    def section_range(s):
        start = int(s["metadata"]["virtual_address"])
        return start, start + int(s["size"])

    # See docs/match_learnings.md, "vtable near-miss": bordering unclaimed
    # content is only a boundary artifact (not a real mismatch) in a data
    # section, which holds not-yet-relocated pointer bytes pre-link -- .text
    # holds real instructions, so a mismatch there is never that, and it's
    # excluded outright regardless of what borders it. That's also exactly
    # the shape trim_to_confirmed_functions can do something about.
    if any(s["name"] in (".text", ".init") for s in bad):
        bad_names = {s["name"] for s in bad}
        trim = trim_to_confirmed_functions(unit, lines, bad_names)
        return "rejected", reason, False, trim
    elif all(neighbors.borders_unclaimed(*section_range(s)) for s in bad):
        own_ranges = {
            r[0]: (r[1], r[2] - r[1]) for r in (parse_range(l) for l in lines) if r
        }
        confirmed = (
            source_linked
            and orig_dol is not None
            and linked_elf is not None
            and all(
                (rng := own_ranges.get(s["name"])) is not None
                and (target_bytes := orig_dol.read_bytes(*rng)) is not None
                and target_bytes == linked_elf.read_bytes(*rng)
                for s in bad
            )
        )
        if confirmed:
            return "promoted", None, True, None
        return (
            "blocked",
            f"{reason} -- neighboring auto symbol is only a boundary-artifact heuristic",
            False,
            None,
        )
    else:
        return "rejected", reason, False, None


def stage_and_build(
    splits_path,
    header,
    existing_blocks,
    existing_order,
    candidates,
    original_text,
    version,
):
    """Stages `candidates` on top of `existing_blocks` and builds. The DOL
    split step catches things the address-overlap filter can't -- e.g. a
    .ctors table entry and the function it points to ending up attributed to
    two different unit names -- and fails the whole build over it. When that
    happens, drop whichever side of the reported conflict is one of our own
    candidates and retry; restore the original file and re-raise for
    anything that isn't one of ours to drop. Returns (report, built,
    excluded), where `built` is the subset of `candidates` actually staged
    in the build that produced `report`."""
    remaining = list(candidates)
    excluded: list[tuple[str, str]] = []
    for _ in range(MAX_CONFLICT_RETRIES):
        staged = dict(existing_blocks)
        staged.update(remaining)
        write_splits(
            splits_path, header, staged, existing_order + [n for n, _ in remaining]
        )
        if not remaining:
            return load_report(version), remaining, excluded
        try:
            run(
                [sys.executable, "configure.py", "configure", "-v", version],
                capture=True,
            )
            run(["ninja", f"build/{version}/report.json"], capture=True)
            return load_report(version), remaining, excluded
        except subprocess.CalledProcessError as e:
            text = (e.stdout or "") + (e.stderr or "")
            conflict_names = extract_conflict_names(text)
            # A cyclic-dependency chain can print hundreds of unit names --
            # observed one spanning nearly the whole .text section, naming 4
            # of 5 staged candidates, when dropping just 1 of those 4 (found
            # by bisecting) was enough to fix it on its own. Dropping every
            # name that merely *appears* in the chain wastes good candidates
            # as collateral; drop only the first and let the next retry's
            # (much smaller) error decide whether more are actually needed.
            matching = [name for name, _ in remaining if name in conflict_names]
            dropped = matching[:1]
            reason = "structural split conflict (see log)"
            if not dropped:
                # An unrecognized failure shape -- fall back to proximity
                # rather than giving up immediately, since every shape seen
                # so far has been a local address-space problem.
                nearest = nearest_candidate_by_address(text, remaining)
                if nearest is not None:
                    dropped = [nearest]
                    reason = "unrecognized split-step failure nearby (see log); dropped by address proximity"
            if not dropped:
                splits_path.write_text(original_text, encoding="utf-8")
                print(
                    "\nBuild failed for a reason this script can't auto-resolve; restored the original splits.txt."
                )
                print(text[-4000:])
                raise
            for name in dropped:
                print(f"  drop {name}: {reason}")
            excluded.extend((name, reason) for name in dropped)
            remaining = [(n, l) for n, l in remaining if n not in dropped]
    splits_path.write_text(original_text, encoding="utf-8")
    raise RuntimeError(
        f"gave up after {MAX_CONFLICT_RETRIES} conflict retries; restored the original splits.txt"
    )


def _main():
    global DTK_OVERRIDE
    parser = argparse.ArgumentParser(
        description="Speculatively build dtk match's candidate split proposals and keep "
        "only the ones with matching comparison sections (not whole-file link verification)."
    )
    parser.add_argument(
        "--source",
        default="GM8E01_00",
        help="source version (the one with known names)",
    )
    parser.add_argument(
        "--target", required=True, help="target version to propose new splits for"
    )
    parser.add_argument(
        "--dtk",
        type=Path,
        default=None,
        help="path to the dtk binary (default: build/tools/dtk)",
    )
    parser.add_argument(
        "-c",
        "--min-confidence",
        type=float,
        default=None,
        help="passed through to `dtk match`",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="seed this many candidates, highest function confidence first; companions may exceed this",
    )
    parser.add_argument(
        "--skip-file",
        type=Path,
        default=None,
        help="units to never re-try, one per line -- units this script rejected "
        "before are appended here automatically (default: build/<target>/split_confidence_skip.txt)",
    )
    args = parser.parse_args()

    dtk = args.dtk or (ROOT_DIR / "build" / "tools" / f"dtk{EXE}")
    if not dtk.exists():
        parser.error(f"{dtk} not found; run configure.py once first, or pass --dtk")
    DTK_OVERRIDE = dtk.resolve()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")

    splits_path = ROOT_DIR / "config" / args.target / "splits.txt"
    proposal_path = ROOT_DIR / "build" / args.target / "match_candidates.txt"
    proposal_path.parent.mkdir(parents=True, exist_ok=True)
    skip_path = args.skip_file or (
        ROOT_DIR / "build" / args.target / "split_confidence_skip.txt"
    )
    skip_list = load_skip_list(skip_path)

    match_report_path = ROOT_DIR / "build" / args.target / "match_report.json"
    print(f"Matching {args.source} -> {args.target} ...")
    match_cmd = [
        str(dtk),
        "match",
        f"config/{args.source}/config.yml",
        f"config/{args.target}/config.yml",
        "--splits",
        str(proposal_path),
        "-o",
        str(match_report_path),
    ]
    if args.min_confidence is not None:
        match_cmd += ["-c", str(args.min_confidence)]
    run(match_cmd)
    func_confidence = FunctionConfidence(
        json.loads(match_report_path.read_text(encoding="utf-8"))
    )

    original_text = splits_path.read_text(encoding="utf-8")
    header, existing_blocks, existing_order = parse_splits(original_text)
    proposal_text = proposal_path.read_text(encoding="utf-8")
    _, proposal_blocks, proposal_order = parse_splits(proposal_text)
    raw_proposal_blocks = raw_proposal_lines(proposal_text)

    # Source declaration order is a heuristic for nearby target units, not
    # ground truth: section order and template ownership can differ by version.
    source_splits_path = ROOT_DIR / "config" / args.source / "splits.txt"
    _, _, source_order = parse_splits(source_splits_path.read_text(encoding="utf-8"))
    ntsc_position = {name: i for i, name in enumerate(source_order)}

    claimed = build_claimed_ranges(existing_blocks)
    candidates: list[tuple[str, list[str]]] = []
    reduced_names: set[str] = set()
    fragmented = 0
    reduced = 0
    skipped_known_bad = 0
    misaligned_units = 0
    for name in proposal_order:
        if name in existing_blocks:
            continue
        if name in skip_list:
            skipped_known_bad += 1
            continue
        lines = proposal_blocks[name]
        if is_fragmented(lines):
            trimmed = dominant_cluster(raw_proposal_blocks[name])
            if trimmed is None:
                fragmented += 1
                continue
            lines = trimmed
            reduced += 1
            reduced_names.add(name)
        aligned_lines = drop_misaligned_sections(lines, raw_proposal_blocks[name])
        if len(aligned_lines) != len(lines):
            misaligned_units += 1
        lines = aligned_lines
        if not lines:
            continue
        ranges = [r for r in (parse_range(l) for l in lines) if r]
        if any(
            overlaps_claimed(claimed, section, start, end)
            for section, start, end in ranges
        ):
            print(f"  skip {name}: overlaps an existing or already-staged split")
            continue
        for section, start, end in ranges:
            claimed.setdefault(section, []).append((start, end))
        candidates.append((name, lines))

    if fragmented:
        print(
            f"  ({fragmented} proposed unit(s) skipped: disjoint ranges in the same section, every "
            "range misaligned -- no valid boundary to even guess)"
        )
    if reduced:
        print(
            f"  ({reduced} proposed unit(s) had disjoint ranges -- staging the largest aligned cluster "
            "per section as a smaller boundary, a real bet verified the same as everything else)"
        )
    if misaligned_units:
        print(
            f"  ({misaligned_units} proposed unit(s) had a section dropped: dtk match already flagged "
            "its boundary as failing the section's alignment requirement, see drop_misaligned_sections)"
        )
    if skipped_known_bad:
        print(
            f"  ({skipped_known_bad} proposed unit(s) skipped: already ruled out by a previous run, see {skip_path})"
        )

    # A section whose nearest real target-side neighbor is nowhere near
    # this unit's own NTSC position is a weak, likely-wrong match, even
    # when nothing else caught it -- see find_suspicious_sections. Drop
    # just the flagged section(s); the rest of the candidate (often just
    # .text) is usually still a real, worthwhile bet, and this is cheap
    # to run before ever staging anything, let alone building it.
    target_ranges_by_section = sorted_ranges_by_section(
        {**existing_blocks, **dict(candidates)}
    )
    suspicious_sections = 0
    suspicious_units = 0
    checked_candidates = []
    for name, lines in candidates:
        flagged = find_suspicious_sections(
            name, lines, ntsc_position, target_ranges_by_section
        )
        if not flagged:
            checked_candidates.append((name, lines))
            continue
        flagged_names = {s for s, _ in flagged}
        for section, reason in flagged:
            print(f"  drop {name} [{section}]: {reason}")
        suspicious_sections += len(flagged)
        suspicious_units += 1
        kept = [l for l in lines if (r := parse_range(l)) and r[0] not in flagged_names]
        if kept:
            checked_candidates.append((name, kept))
    candidates = checked_candidates
    if suspicious_units:
        print(
            f"  ({suspicious_sections} section(s) across {suspicious_units} unit(s) dropped: target "
            "neighbor contradicts NTSC's own declaration order, see find_suspicious_sections)"
        )

    # Full pool, keyed by name -- companion pull-in (below) needs to find a
    # specific OTHER candidate by its exact address, independent of which
    # ones confidence-sorting picked.
    all_candidates_by_name = dict(candidates)
    starts_index, ends_index = build_proposal_range_index(all_candidates_by_name)
    symbols_path = ROOT_DIR / "config" / args.target / "symbols.txt"
    neighbors = SymbolNeighbors(symbols_path)

    # Primary signal: whether every function dtk match found in this
    # candidate's .text is individually Confident-tier -- a proposal can
    # still land in the *unit*-level Candidate tier for reasons unrelated to
    # match quality (e.g. a sibling .rodata symbol not yet migrated), but a
    # function-level Confident match is the strongest predictor this session
    # actually found of a real 100% fuzzy match. Size is only the tiebreak.
    scored = [(name, lines, func_confidence.score(lines)) for name, lines in candidates]
    scored.sort(key=lambda c: (not c[2][0], -c[2][1], len(c[1])))
    total_scored = len(scored)
    high_confidence = sum(1 for _, _, (all_conf, _) in scored if all_conf)
    if args.limit:
        scored = scored[: args.limit]
    top_candidates = [(name, lines) for name, lines, _ in scored]

    # A candidate that borders unclaimed content will get rejected as
    # `blocked` no matter how good its own match is (see the vtable
    # near-miss check below) -- not because it's wrong, but because
    # whatever's next to it hasn't been staged. Confidence-sorted picking
    # scatters candidates across the whole binary, so that neighbor is
    # usually NOT in the same batch, and the same candidate just gets
    # reproposed and re-blocked forever. Since dtk match already proposed a
    # boundary for real units at these exact addresses (starts_index/
    # ends_index, built from the full pool above), pull in whichever
    # specific candidate would fill each gap, transitively -- its own
    # confidence doesn't matter here, since the real 100%-fuzzy-and-hash-
    # checked build still gates it exactly like everything else.
    selected_names = {n for n, _ in top_candidates}
    companion_of: dict[str, str] = {}
    worklist = list(top_candidates)
    while worklist:
        name, lines = worklist.pop()
        for line in lines:
            r = parse_range(line)
            if not r:
                continue
            section, start, end = r
            bleeds_before, bleeds_after = neighbors.border_flags(start, end)
            found = []
            if bleeds_after:
                found.append(starts_index.get((section, end)))
            if bleeds_before:
                found.append(ends_index.get((section, start)))
            for companion_name in found:
                if companion_name is None or companion_name in selected_names:
                    continue
                selected_names.add(companion_name)
                companion_of[companion_name] = name
                companion_lines = all_candidates_by_name[companion_name]
                worklist.append((companion_name, companion_lines))

    candidates = top_candidates + [
        (name, all_candidates_by_name[name]) for name in companion_of
    ]

    # Most "structural split conflict" build failures turn out to be one
    # staged candidate's implied link order fighting another's, not
    # fighting anything already established -- resolvable analytically, by
    # inspecting the same address-adjacency graph dtk itself builds (see
    # resolve_batch_link_order), without ever running a real build. Doing
    # this first turns what used to take dozens of slow build-and-drop-one
    # retries into a single, near-instant pass; stage_and_build's own
    # retry loop still catches whatever this simplified model misses.
    candidates, link_order_dropped = resolve_batch_link_order(
        existing_blocks, candidates
    )
    if link_order_dropped:
        print(
            f"  ({len(link_order_dropped)} candidate(s) dropped up front: implied link order "
            "conflicts with another staged candidate, resolved before building)"
        )

    if not candidates:
        print("No new candidate units to try.")
        return

    print(
        f"\n{high_confidence} of {total_scored} remaining candidates have every function "
        "individually Confident-tier -- staging highest-confidence first:"
    )
    if companion_of:
        print(
            f"({len(companion_of)} more pulled in to fill a boundary a staged candidate would "
            "otherwise border unclaimed, transitively)"
        )
    print(f"\nStaging {len(candidates)} candidate unit(s) for a speculative build:")
    for name, lines in candidates:
        all_conf, min_conf = func_confidence.score(lines)
        tag = (
            "confident"
            if all_conf
            else ("no .text" if min_conf < 0 else "mixed/probable")
        )
        if name in reduced_names:
            tag += ", reduced from fragmented"
        if name in companion_of:
            tag += f", pulled in to unblock {companion_of[name]}"
        print(f"  ? {name} ({len(lines)} section(s), {tag})")
    print()

    report, built, excluded = stage_and_build(
        splits_path,
        header,
        existing_blocks,
        existing_order,
        candidates,
        original_text,
        args.target,
    )
    excluded = link_order_dropped + excluded

    # `stage_and_build` leaves splits.txt in the fully-staged (unverified)
    # state on success -- anything below here that raises must still fall
    # back to the original file rather than leaving that staged state as
    # the final on-disk result.
    try:
        by_path = {
            strip_source_root(u["metadata"]["source_path"]): u
            for u in report["units"]
            if u.get("metadata", {}).get("source_path")
        }

        # A default build links candidates from extracted retail objects. Reading
        # those bytes back cannot validate compiled output. Do not construct a
        # comparison ELF without proving source linkage (verify_source_units.py).
        linked_elf = None
        orig_dol = None

        # symbols_path/neighbors were already built (from the same,
        # untouched-since-then symbols.txt) before staging, for the
        # companion pull-in above -- reused here unchanged.
        promoted: list[str] = []
        rejected: list[tuple[str, str]] = []
        blocked: list[tuple[str, str]] = []
        byte_confirmed: list[str] = []
        trim_candidates: list[tuple[str, list[str]]] = []
        trim_origin: dict[str, str] = {}
        candidates_by_name = dict(candidates)
        for name, lines in built:
            bucket, reason, was_byte_confirmed, trim = classify_built_unit(
                name, lines, by_path, neighbors, orig_dol, linked_elf
            )
            if bucket == "promoted":
                promoted.append(name)
                if was_byte_confirmed:
                    byte_confirmed.append(name)
            elif bucket == "blocked":
                blocked.append((name, reason))
            elif trim is not None:
                trim_candidates.append((name, trim))
                trim_origin[name] = reason
            else:
                rejected.append((name, reason))

        final_blocks = dict(existing_blocks)
        for name in promoted:
            final_blocks[name] = candidates_by_name[name]
        write_splits(splits_path, header, final_blocks, existing_order + promoted)

        # A section-level fuzzy score can hide that most of a rejected
        # candidate's own functions actually compiled byte-identical (see
        # trim_to_confirmed_functions) -- retry each one with its boundary
        # shrunk to just the confirmed-matching run. Verified the same way
        # as everything else, via a real build, not assumed correct because
        # the per-function data looked good.
        if trim_candidates:
            print(
                f"\n{len(trim_candidates)} rejected unit(s) had at least one objdiff-matched function "
                "-- retrying with the boundary shrunk to that comparison-matched run:"
            )
            for name, lines in trim_candidates:
                print(f"  ? {name} (was: {trim_origin[name]})")
            retry_existing_blocks = dict(final_blocks)
            retry_report, retry_built, retry_excluded = stage_and_build(
                splits_path,
                header,
                retry_existing_blocks,
                existing_order + promoted,
                trim_candidates,
                original_text,
                args.target,
            )
            excluded += retry_excluded
            retry_by_path = {
                strip_source_root(u["metadata"]["source_path"]): u
                for u in retry_report["units"]
                if u.get("metadata", {}).get("source_path")
            }
            for name, lines in retry_built:
                candidates_by_name[name] = lines
                # orig_dol/linked_elf reflect the *first* build, now stale
                # for a byte comparison against this retry's own link --
                # pass None rather than risk confirming against the wrong
                # bytes. Worst case a genuinely-confirmable retry candidate
                # is undercounted as rejected instead, not wrongly promoted.
                bucket, reason, was_byte_confirmed, _ = classify_built_unit(
                    name, lines, retry_by_path, neighbors, None, None
                )
                if bucket == "promoted":
                    promoted.append(name)
                    if was_byte_confirmed:
                        byte_confirmed.append(name)
                elif bucket == "blocked":
                    blocked.append((name, reason))
                else:
                    rejected.append(
                        (
                            name,
                            f"auto-trimmed boundary still {reason} (was: {trim_origin[name]})",
                        )
                    )
            final_blocks = dict(existing_blocks)
        for name in promoted:
            final_blocks[name] = candidates_by_name[name]
        write_splits(splits_path, header, final_blocks, existing_order + promoted)
    except Exception:
        splits_path.write_text(original_text, encoding="utf-8")
        print("\nEvaluating the build failed; restored the original splits.txt.")
        raise

    print(
        f"\nPromoted {len(promoted)} unit(s) with matching comparison sections (pending final split-integrity check):"
    )
    for name in promoted:
        tag = (
            " (confirmed by direct byte comparison, not fuzzy match)"
            if name in byte_confirmed
            else ""
        )
        print(f"  + {name}{tag}")
    print(f"\nRejected {len(rejected)} unit(s):")
    for name, reason in rejected:
        print(f"  - {name}: {reason}")
    if blocked:
        print(
            f"\nBlocked on an unclaimed neighbor (not persisted, retry later) {len(blocked)} unit(s):"
        )
        for name, reason in blocked:
            print(f"  - {name}: {reason}")
    if excluded:
        print(
            f"\nExcluded {len(excluded)} unit(s) before build, due to a structural split conflict:"
        )
        for name, reason in excluded:
            print(f"  - {name}: {reason}")

    # Only `rejected` (a real build actually scored these bytes as wrong) is
    # persisted. `excluded` (structural conflicts) and `blocked` (mismatches
    # that border a symbol dtk invented for still-unclaimed content) both
    # looked like they deserved the same treatment, but direct testing
    # disproved that for `excluded` -- a unit dropped there has repeatedly
    # turned out to build cleanly and match 100% when tried alone or in a
    # different batch (e.g. GuiSys/CGuiGroup.cpp -- see
    # docs/match_learnings.md, "vtable near-miss" for the `blocked` case).
    # Neither is a property of the unit itself, so blacklisting either was
    # actively wrong -- it silently discarded good candidates. They'll just
    # get re-proposed and re-tried (cheaply) next run instead.
    append_skip_list(skip_path, rejected)

    unlinkable: list[tuple[str, str]] = []
    if promoted:
        print(
            "\nVerifying the promoted set actually links (report.json alone doesn't check this)..."
        )
        for _ in range(MAX_CONFLICT_RETRIES):
            ok, text = verify_link(args.target)
            if ok:
                break
            culprit_objects = set(LINKER_UNDEFINED_OBJECT_RE.findall(text))
            reverted = [name for name in promoted if Path(name).stem in culprit_objects]
            if not reverted:
                splits_path.write_text(original_text, encoding="utf-8")
                print(
                    "\nThe promoted set fails to link and the cause couldn't be matched to a "
                    "specific unit; restored the original splits.txt."
                )
                print(text[-4000:])
                raise RuntimeError("promoted set fails to link")
            still_broken = []
            for name in reverted:
                print(f"  {name}: calls an undefined symbol at link time (see log)")
                if suggest_undefined_symbol_fixes(
                    args.target, name, text, report, symbols_path
                ):
                    print(
                        f"    -> resolved and applied to symbols.txt; retrying {name}"
                    )
                else:
                    print(f"  revert {name}")
                    unlinkable.append((name, "causes an undefined-symbol link error"))
                    still_broken.append(name)
            promoted = [n for n in promoted if n not in still_broken]
            final_blocks = dict(existing_blocks)
            for name in promoted:
                final_blocks[name] = candidates_by_name[name]
            write_splits(splits_path, header, final_blocks, existing_order + promoted)
        else:
            splits_path.write_text(original_text, encoding="utf-8")
            raise RuntimeError(
                f"gave up after {MAX_CONFLICT_RETRIES} link-check retries"
            )

        if unlinkable:
            print(
                f"\nReverted {len(unlinkable)} unit(s) that broke the link (not persisted, retry later):"
            )
            for name, reason in unlinkable:
                print(f"  - {name}: {reason}")

        hash_broken: list[tuple[str, str]] = []
        if promoted:
            print(
                "\nVerifying the promoted set doesn't break the full-DOL hash check..."
            )
            for _ in range(MAX_CONFLICT_RETRIES):
                ok, _text = verify_full_hash(args.target)
                if ok:
                    break
                diff_text = diff_symbol_addresses(args.target, dtk)
                nearest = nearest_candidate_by_address(
                    diff_text, [(n, candidates_by_name[n]) for n in promoted]
                )
                if nearest is None:
                    splits_path.write_text(original_text, encoding="utf-8")
                    print(
                        "\nThe promoted set breaks the full-DOL hash check and the cause couldn't be "
                        "matched to a specific unit; restored the original splits.txt."
                    )
                    print(diff_text[-4000:])
                    raise RuntimeError("promoted set breaks the full-DOL hash check")
                reason = (
                    "breaks the full-DOL hash check -- boundary too narrow for what the compiler "
                    "actually emits for this unit (see log)"
                )
                print(f"  revert {nearest}: {reason}")
                hash_broken.append((nearest, reason))
                promoted = [n for n in promoted if n != nearest]
                final_blocks = dict(existing_blocks)
                for name in promoted:
                    final_blocks[name] = candidates_by_name[name]
                write_splits(
                    splits_path, header, final_blocks, existing_order + promoted
                )
            else:
                splits_path.write_text(original_text, encoding="utf-8")
                raise RuntimeError(
                    f"gave up after {MAX_CONFLICT_RETRIES} hash-check retries"
                )

        # Address proximity only chooses a trial to revert. It does not prove
        # that unit caused the batch failure, so never permanently blacklist it.

        if unlinkable or hash_broken:
            print("\nRegenerating report.json for the final, verified set...")
            run(["ninja", f"build/{args.target}/report.json"])

        if promoted:
            # These units are now proven byte-identical, part of a clean
            # link, AND confirmed against the full-DOL hash check -- the
            # compiler emitted their real mangled names into the linked
            # ELF, so `dol apply` (see decomp-toolkit's src/cmd/dol.rs) can
            # safely copy those names/sizes/scopes back into symbols.txt,
            # replacing any auto_* placeholder dtk had invented there.
            print(
                "\nSyncing symbol names/sizes for the newly fully-matching unit(s) (`ninja apply`)..."
            )
            run([sys.executable, "configure.py", "configure", "-v", args.target])
            run(["ninja", "apply"])

    print(
        "\nKept comparison-matched splits. The retail hash checks split integrity only: "
        "candidates are not enabled as source link inputs. Whole-file verification requires "
        "linking their compiled objects and then checking the retail hash."
    )


def main():
    # The historical loop has several independent failure paths, including
    # symbol fixes and apply. Roll all inputs back together, not just splits.
    probe = argparse.ArgumentParser(add_help=False)
    probe.add_argument("--target")
    probe.add_argument("--skip-file", type=Path)
    args, _ = probe.parse_known_args()
    snapshots = {}
    if args.target:
        paths = [
            ROOT_DIR / "config" / args.target / name
            for name in ("splits.txt", "symbols.txt")
        ]
        paths.append(
            args.skip_file
            or ROOT_DIR / "build" / args.target / "split_confidence_skip.txt"
        )
        snapshots = {p: p.read_bytes() if p.exists() else None for p in paths}
    try:
        _main()
        if args.target:
            reconfigure_and_build(args.target, f"build/{args.target}/report.json")
            ok, output = verify_full_hash(args.target)
            if not ok:
                raise RuntimeError(output)
    except BaseException:
        for path, data in snapshots.items():
            if data is None:
                if path.exists():
                    path.unlink()
            elif not path.exists() or path.read_bytes() != data:
                path.write_bytes(data)
        if args.target and DTK_OVERRIDE is not None:
            try:
                reconfigure_and_build(args.target, f"build/{args.target}/report.json")
            except (OSError, subprocess.CalledProcessError) as error:
                print(
                    f"Input files restored, but regenerating the baseline report failed: {error}"
                )
        raise


if __name__ == "__main__":
    main()
