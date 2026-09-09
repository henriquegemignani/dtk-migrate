# Investigation: precise link-order cycle resolution

> **2026-09-09 audit:** this is a historical investigation of the old loop, not
> a verified explanation of every current cycle. The new `discover_splits.py`
> uses build-driven batch bisection and does not use this mass-drop heuristic.
> Its code-only proposals avoid speculative data-order constraints. A retail hash
> validates compiled candidates only when they are actual source link inputs;
> see [validation_audit.md](validation_audit.md). Prior claims that all retained
> candidates were byte-verified have been withdrawn.

## Context

`split_confidence_loop.py` stages a batch of candidate unit splits, then pre-filters
out anything that would make the implied link order cyclic
(`build_link_order_graph` / `find_sccs` / `resolve_batch_link_order`), before ever
running a real build — this mirrors decomp-toolkit's own `resolve_link_order`
(`src/util/split.rs`) closely enough to predict a real `dtk dol split` failure in
milliseconds instead of burning a build on it.

Running a full round against `decomp/prime`'s `GM8P01_00` (PAL) target, with the
skip list cleared, produced a **674-node cyclic component** spanning almost the
entire remaining candidate pool (~500 candidates + already-staged units). The
current resolution strategy (`resolve_batch_link_order`) repeatedly drops the
single lowest-*confidence*-priority candidate still in a cyclic SCC until the graph
is acyclic. Against a component this size, that means dropping dozens to hundreds
of candidates — most of which are very likely *not* actually responsible for the
cycle.

## Prior explanation of the large cycle (recheck against current inputs)

An SCC shows contradictory graph constraints; it does not identify which
constraint or candidate is wrong, or prove the graph model correct:

- Ordinary object sections generally follow link order; linker-packed common
  BSS must be handled separately. If a candidate's
  boundary is even slightly mis-attributed in one section, you get a direct
  contradiction with its true position in another section — a cycle.
- One considered-and-rejected theory: that edges between candidates separated by
  a large unclaimed gap are spurious, since the Python graph only connects
  *known* ranges and skips over unclaimed address space between them. This does
  **not** hold up — by transitivity, whatever eventually fills that gap still has
  to link somewhere between the two candidates, so "A before B" remains a real
  constraint regardless of gap size. Confirmed by sampling actual edges: 452 of
  1748 edges in the batch had gaps >100 bytes (worst: 22,112 bytes), and none of
  that changes the constraint's validity, provided those edges model real ordering.
- The real explanation: most of the candidate pool forms one long, nearly-total
  chain (address order roughly tracks NTSC declaration order across every
  section). A single backward edge dropped into that chain doesn't just conflict
  locally — it closes a cycle spanning *every node between its two endpoints*.
  A small number of genuinely mis-attributed candidates is enough to tangle
  the majority of a large batch this way.

## What to investigate

**Core question: can the actual small set of contradictory candidates be isolated,
instead of the current confidence-based mass-drop?**

decomp-toolkit's own real cycle diagnosis (triggered on an actual build failure,
see `CONFLICT_SECTION_RE` / `extract_conflict_names` in `split_confidence_loop.py`,
and `diagnose_link_cycle` in decomp-toolkit's `src/util/split.rs`) already isolates
a small, precise edge set responsible for a cycle, rather than the whole SCC. The
Python pre-filter has the same graph available in-memory (`find_sccs`) but doesn't
attempt this — it just repeatedly strips the lowest-priority node from *any*
cyclic SCC.

### Leading hypothesis to test first

`resolve_batch_link_order` drops nodes by **match confidence**, which has no
relationship to which node is actually causing a given cycle. A much more
targeted signal already exists in the same file: `ntsc_position` (source
declaration order, built in `main()` and already used by
`find_suspicious_sections` for a similar purpose). For a candidate stuck in a
cyclic SCC, compare its position among the *other SCC members* by address
against its position by `ntsc_position` — the candidate(s) most out of order
relative to NTSC's own declared sequence are the most likely actual culprits,
independent of match confidence.

Concretely: instead of `worst = max((n for n in order if n in cyclic_candidates),
key=order.index)` (confidence-based), try ranking cyclic-candidate nodes by
how much their address-rank-among-SCC-members disagrees with their
NTSC-declaration-rank, and drop from that ranking instead. Re-run `find_sccs`
after each drop exactly as today; the loop structure doesn't need to change,
only the drop-order heuristic.

### How to validate

1. Try to reproduce the historical component using the read-only snippet below.
   Its size depends on the exact proposals, existing splits and tool revision.
   For an actual old-loop build trial, from `decomp/prime`, with
   `build/GM8P01_00/split_confidence_skip.txt` empty (or close to it) and
   `config/GM8P01_00/splits.txt` at its current state, run:
   ```
   python /path/to/split_confidence_loop.py --target GM8P01_00 --dtk /path/to/development/dtk
   ```
   inspect the cyclic component (or adapt the standalone repro
   snippet below, which doesn't require a real build — it only needs
   `match_candidates.txt` from a `dtk match` run and the current
   `splits.txt`/`symbols.txt`).
2. Before changing the drop heuristic, measure whether the "out of NTSC order"
   signal actually concentrates on a small subset of the 674 nodes — if most of
   the SCC is *not* NTSC-order-suspicious, this hypothesis is wrong and needs
   rethinking (check whether the suspicious few, once dropped, actually collapse
   the SCC to empty using `find_sccs` again on the reduced graph, without running
   a real build yet).
3. Only once the reduced-node-count approach demonstrably resolves the same
   cycle with far fewer drops (ideally single digits, not dozens+), wire it into
   `resolve_batch_link_order` and validate end-to-end with a real round (a real
   build + full-DOL hash check is still the final authority — this only changes
   how many good candidates survive the pre-filter, never what counts as
   "passing").

### Standalone repro snippet (no real build needed)

```python
import importlib.util
spec = importlib.util.spec_from_file_location("scl", r"path/to/split_confidence_loop.py")
scl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scl)

# run from decomp/prime's root, or adjust paths
text = open("build/GM8P01_00/match_candidates.txt", encoding="utf-8").read()
_, blocks, order = scl.parse_splits(text)
raw = scl.raw_proposal_lines(text)
existing_text = open("config/GM8P01_00/splits.txt", encoding="utf-8").read()
_, existing_blocks, _ = scl.parse_splits(existing_text)

candidates = {}
for name in order:
    if name in existing_blocks:
        continue
    lines = blocks[name]
    if scl.is_fragmented(lines):
        trimmed = scl.dominant_cluster(raw[name])
        if trimmed is None:
            continue
        lines = trimmed
    lines = scl.drop_misaligned_sections(lines, raw[name])
    if lines:
        candidates[name] = lines

full_blocks = dict(existing_blocks)
full_blocks.update(candidates)
graph = scl.build_link_order_graph(full_blocks)
sccs = [s for s in scl.find_sccs(graph) if len(s) > 1]
print("cyclic SCCs:", len(sccs), "sizes:", sorted(len(s) for s in sccs))
```

## Constraints to keep in mind

- The real build's own retry loop (`stage_and_build`'s `extract_conflict_names`
  path) remains the authority for anything this pre-filter misses or gets wrong
  — this is purely a speed/precision improvement to the pre-filter, not a new
  source of truth. Don't weaken that safety net.
- Per the project's standing approach (see decomp-toolkit's
  `docs/match_learnings.md`): splits are cheap to revert, so it's fine to try a
  more aggressive drop-fewer-nodes heuristic and let a real build prove it wrong
  — don't over-engineer the analytical model trying to be perfect before ever
  testing it against a real round.
- If the NTSC-order hypothesis doesn't pan out cleanly, the fallback is simply to
  detect when `resolve_batch_link_order` would drop an unreasonably large
  fraction of a batch (e.g. >50%) and, for that batch only, skip the bulk
  pre-filter and let the slower one-at-a-time real-build retry loop (which
  already has precise per-edge diagnosis) handle it instead — strictly worse
  throughput, but no worse than what happens today when the pre-filter empties
  the batch entirely.
