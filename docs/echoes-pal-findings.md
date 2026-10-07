# Findings from migrating Echoes G2ME01 -> G2MP01

Evidence from four consecutive `run --stages all` passes on a clean checkout
(worktree `echoes-wt/migrate-pal`). Passes 1-3 converged: accepted counts fell
from thousands to single digits (derive 10295 -> 5209 -> 524 -> 30; verify
89 -> 6 -> 13 after the manual data splits below).

## What stopped the tool, and how it was worked around by hand

1. **Data ranges identified but never applied.** `data-evidence.json` held 1475
   `candidate` and 157 `confident` ranges. 368 of them (333 candidates) had
   bytes identical in both DOLs to the source unit's range of the same size;
   351 applied cleanly. Applying them and renaming 22 `lbl_` symbols by offset
   from the source range took verify deferrals from 163 to 102 and linked 13
   more units, with no retail hash change. Candidates were held by
   "target is missing functions the source unit has" / "edge borders an
   unmatched function", which are properties of the *text* run, not of the
   data bytes.
   *Implemented:* `DataSizeBasis::ByteIdentical`. A member whose target bytes,
   with relocated words masked, equal the paired source symbol's bytes over the
   source's known size (at least 8 bytes, not one repeated byte) has a witnessed
   extent, so it no longer counts as a guessed size. Re-running from the state
   before the hand-applied splits, one `run --stages all` accepted 171 discover
   candidates (192 data ranges) with a passing build and retail hash, reaching
   8100 matched functions against 8084 from the manual work. The evidence
   schema moved from 5 to 6.
2. **Range ends are symbol ends, not alignment-valid ends.** The split step
   rejects `ends within symbol`, `Unsplit data ... to next split` and
   `Invalid alignment for split`. These were fixed with a loop that reads
   dtk's error and drops or extends the offending range. *Proposal:* do the
   same inside discover (dtk errors are precise and cheap to parse), rather
   than refusing the whole batch.
3. **Wrong text edges for a unit.** `Dolphin/vi/vi.c` was split at
   0x803536AC..0x80355084 in PAL; the real range is 0x803533B0..0x80355548.
   The trailing functions had already been named from `vi.c` by derive, and
   `ar.c` has no split at all. Verify showed this only as
   `multiply-defined`/`undefined`. *Proposal:* after derive, a function whose
   new name belongs to unit U and which sits adjacent to U's range is evidence
   to extend U; and a verify failure listing symbols of a unit should be fed
   back as boundary evidence.
4. **Confident matches left unnamed.** 1691 target functions "would gain a
   name" after pass 2 (1393 confident); several surfaced as `undefined`
   at link time (`__nw__FUlPCcPCc`, `CVector2f::CVector2f(float,float)`).
   *Proposal:* when a verify failure names an undefined symbol that has a
   confident match, rename and retry.
5. **A unit can be correctly split yet not linkable.** PAL `vi.c` is ~0x7FC
   bytes larger than NTSC; the NTSC source fails the retail hash. Verify
   correctly refuses it; the split was kept and the unit left unlinked.
