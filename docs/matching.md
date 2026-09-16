# Matching two versions of one executable

Working notes from building and tuning `dtk-migrate match`: the wrong turns, the
surprising measurements, and the reasoning that is not obvious from the code.

Every measurement here is against the Metroid Prime decompilation, which has
several versions of the same executable and is the driving use case. Specific
numbers drift as the algorithm changes; the shape of each finding should hold.

> **Provenance.** These notes were written while this code lived in a fork of
> decomp-toolkit, and the measurements in them predate the move. They are
> observations, not current guarantees — reproduce one before relying on it. In
> particular, anything below that treats a retail hash as evidence about a
> candidate's *source* is wrong in the way
> [the audit](history/validation_audit.md) describes: a file `configure.py` has
> not enabled still links from its extracted original, so the hash says nothing
> about it. That is what `verify` exists to settle.

## The governing constraint

**An absent symbol name is better than a wrong one.** A wrong name reads as established fact,
propagates into decompiled source and onward into further version ports, and nothing prompts
anyone to re-check it. This one preference reshaped the design more than any accuracy number did:
it's why matches are tiered instead of thresholded, why `--renames` only ever carries confident
matches, and why the collision guard in the rename applier skips-and-reports instead of asserting a
name is free. Any future change to the scoring or tiering should be checked against this before
being checked against a precision number — a small accuracy gain that blurs the confident/candidate
boundary is a bad trade.

## Architecture, briefly

The pipeline: `CallGraph::build` (`src/analysis/callgraph.rs`) derives caller/callee edges from
relocations already resolved by `Tracker`, `fingerprint_all` (`src/analysis/fingerprint.rs`)
computes a relocation-masked instruction hash plus string references per function, and
`match_functions` (`src/analysis/matching.rs`) does the matching in two tiers:

1. **Anchors** — functions matched by content alone: identical name, unique masked-instruction
   hash, or a string literal referenced by exactly one function on each side.
2. **Propagation** — grows outward from anchors along call-graph edges (call-site position, sole
   remaining caller) and link order (position between two anchors), voting each round and
   committing only mutual, unambiguous winners.

The result is then classified into three tiers (`Match::tier()`) — confident / probable /
candidate — based on the *kind* of evidence, not a cut on the confidence score. `dtk-migrate match` reads
two project configs, `dtk-migrate symbols rename` applies a rename file to a `symbols.txt` in place.

## Findings that changed the design

### Confidence is not comparable across binary pairs

The single biggest realization: the same confidence number means different things depending on how
similar the two binaries are.

- Between close revisions (e.g. two NTSC builds a patch apart), layout-vote confidence is *tightly
  bimodal* — matches land at either ~0.867 (same opcodes and reference counts, different operands)
  or 0.98 (byte-identical after masking), with almost nothing between. A threshold barely
  discriminates anything.
- Between distant binaries (e.g. the NTSC source against the Wii Trilogy port), confidence spreads
  *broadly* across 0.56–0.98, and there the threshold actually separates good matches from bad
  ones.

This is why `Match::tier()` classifies on evidence kind (identical encoding, corroboration count,
runner-up margin) rather than on `confidence` directly. `confidence` is still computed and reported
— it's useful within one run, and `--min-confidence` still gates what's considered at all — but it
is not the thing tiering is built on. If you're tempted to simplify tiering into `confidence >= X`,
re-derive X for a distant pair and a close pair separately first; they won't agree.

### The identical-body promotion needed the same length guard as the hash anchor

`anchor_by_exact_hash` (tier 1) has always required `instruction_count >= MIN_DISTINCTIVE_INSTRUCTIONS`
(4), with the reasoning that short functions collide by coincidence — a bare `blr`, or
`li r3, 0; blr`, hashes identically against every other such stub in the binary, so "these two hash
the same" carries zero information below some minimum size.

The promotion path in `tier()` — a propagated match whose bodies hash identically gets promoted to
confident even though the hash wasn't globally unique — did not have this guard when first written.
It reused the raw `exact_hash == exact_hash` comparison. Found by review, not by testing: a stub
`blr` matched on a single layout vote could reach `confident` purely because its trivial body
happened to hash the same as its (correct, or incorrect) counterpart.

This was not theoretical once measured. Adding the shared guard (`is_distinctive`, now used by both
the anchor and the promotion) moved thousands of matches per close-revision pair out of `confident`
into `probable`/`candidate`, and it eliminated the one genuinely wrong confident match found in
testing before the fix existed: `__close_console` matched to `__write_console` — two console stub
functions with short, identical bodies, matched on layout position alone.

**Lesson**: when the same kind of evidence (`exact_hash` equality) is used to decide two different
things (an anchor vs. a promotion), any guard on one needs to be checked against the other. They
drifted here because the promotion path was added later in a different code path
(`accept_votes`/`confidence_for`) than the original anchor (`anchor_by_exact_hash`), and nothing
forced them to share the constant until it was pulled out explicitly.

There's also a degenerate case worth remembering: `CallGraph::build` only admits symbols with
`size >= 4` as nodes, so a genuinely zero-size function can't reach this path. But a node whose
section lookup fails, or whose section has no data at that range (e.g. bss), still produces a valid
`Fingerprint` with `instruction_count == 0` and `exact_hash` equal to the digest of zero bytes —
two such nodes are then "byte-identical" by the same comparison. The length guard closes this too,
incidentally, since `0 < MIN_DISTINCTIVE_INSTRUCTIONS`.

### A rename set must tolerate a name appearing more than once

First version of the rename applier (`src/util/renames.rs`) treated two source functions being
assigned the same target name as a hard parse error. This looked obviously correct — a name should
identify one symbol — and broke on the second real test run: `dtk-migrate match` producing a rename set
from a real one-to-one function matching, applied via `dtk-migrate symbols rename`, failed with:

```
'construct<10CModelData>__4rstlFPvRC10CModelData' is already assigned to 'fn_800CBB34'.
```

Checking the source project's own `symbols.txt` showed the same name at two different addresses,
`scope:local`, one per translation unit. Local template instantiations legitimately repeat their
mangled name across translation units — the source binary itself has 12 such duplicate function
names. A rename set derived from matching two versions of that same binary correctly reproduces
this: it isn't a bug in the matcher, and refusing it drops correct renames.

Fixed by making `Renames::insert` allow two entries assigning the same target name, rather than
rejecting them. What's still refused: renaming the *same source symbol* twice to different names
(that's actually contradictory), and — in `apply_renames`, not `Renames::parse` — assigning a name
that's already held by a symbol not itself being renamed away, since that actually would collide two
live symbols under one name.

**Lesson**: before treating any "this shouldn't happen" case as a hard error in code that consumes
real compiler output, check whether the compiler itself already does it. C++ name mangling
collisions across translation units (local template instantiations, anonymous namespaces before
they're disambiguated, etc.) are exactly the kind of thing that looks like corrupted input but is
actually normal.

### Project-relative paths don't work when a command spans two projects

Every other dtk command resolves a project config's relative paths (`object_base`, `symbols`,
`splits`, ...) against the process working directory — fine when a command operates on one project,
since you either run from the project root or pass `-C`. `match` takes two configs, which may be in
different repositories entirely (the eventual cross-game use case), so `-C` has nothing to point at
that serves both.

First approach considered: rewrite the paths inside the loaded `ProjectConfig` to be absolute before
using them. Abandoned — `object_base` and friends are `Utf8UnixPathBuf`, and joining a Windows
absolute path (`C:\Users\...`) onto that type silently produces something with the drive letter
lost (`/Users/henri/...`), which then fails to open with a confusing "not found" rather than an
obviously-wrong-path error. `ExtractConfig` and other nested config structs also carry more paths
than are obvious from a first read, so this approach means keeping a rewrite list in sync with the
config schema by hand.

What worked: reproduce "run from the project root" literally. `load_analyzed` resolves each
config's root (working directory if it already works there, else walk up from the config file
looking for what `object_base`/`object` names, else an explicit `--source-root`/`--target-root`),
then `WorkingDirectory::enter` changes into it for the duration of that one project's load, restoring
the previous directory via `Drop` — including on an early return through `?`. This is why the two
configs are loaded fully sequentially rather than in parallel (`source_analyzed` finishes, including
its guard's `Drop`, before `target_analyzed` starts): the working directory is process-global state,
so only one project's root can be "entered" at a time.

**Lesson**: don't rewrite path fields defensively when the actual constraint is "code downstream
assumes CWD == project root." Reproducing that assumption directly (enter/restore) is less code and
doesn't need to track every path field a config type happens to carry.

### Propagation needs far more rounds for distant binaries, and the cap failing was silent

The propagation round cap started at 24 (`MatchOptions::default`), sized against close-revision
pairs where propagation converges in 2–9 rounds. Running against the Wii Trilogy port —
structurally the same source but a much smaller, differently-organized overlap — hit the cap at
exactly 24 without an explicit signal; the only symptom was a suspiciously round final match count.
Each propagation round only advances the matched frontier by one call-graph hop, and a pair with
few anchors and a sparse initial matched set needs many more hops to reach everything reachable.

Raised the default to 100, exposed `--max-rounds`, and — more importantly — added an explicit
`log::warn!` when the loop exits via the cap rather than via "a round found nothing," since that
distinction (converged vs. truncated) is invisible from the match count alone and was the whole
reason the bug went unnoticed initially.

**Lesson**: any iterate-to-fixpoint loop with a safety cap needs to say out loud when the cap was
the reason it stopped, not just when the natural fixpoint was reached. Silent truncation looks
identical to a correct small result.

## Measurement discipline that mattered

**`--validate` (hide the target's real names, match anyway, then score against the hidden names)
is the only ground truth available**, and even that thins out fast: a version pair with only a few
hundred pre-existing names to hide leaves a correspondingly small scored sample, wide enough
confidence intervals that a "97%" and a "100%" aren't necessarily distinguishable. Treat any
single-pair percentage from a small `--validate` run as indicative, not exact, and prefer looking at
the *list* of disagreements over the summary percentage — see the next point.

**Apparent errors are usually ground-truth noise, not matcher errors**, and checking this by hand
was worth more than any amount of aggregate statistics. Recurring shapes found by reading actual
mismatches:
- Truncated names in an older symbols file (compare full name length, not just the visible prefix).
- Human capitalization/spelling drift between manually-named versions (`CARDStat` vs. `CardStat`,
  `CShockWave` vs. `CShockwave`).
- Compiler-generated suffix drift (`__arraydtor$381` vs. `__arraydtor$159` — same function, the
  numeric suffix isn't semantic).
Before concluding a tier's precision is below what its intended use requires, pull the actual
"incorrect" rows and read them; the number of *genuine* errors is consistently much smaller than the
raw mismatch count suggests.

**Multi-source consensus was investigated as a coverage strategy and found to be primarily useful
for something else.** Simulated (without building the feature) by running independent `dtk-migrate match`
invocations from different source versions against the same target and joining the reports on
target address:
- Coverage gain from combining sources was small (order 5%), and only from sources on genuinely
  independent axes. Two near-identical source versions (e.g. two NTSC patch revisions) add *zero*
  combined coverage over either alone — they anchor on the same content and propagate the same way,
  so agreement between them proves nothing.
- Precision value was the real finding: independent routes to the same target agreed on the
  overwhelming majority of shared matches, and where they *disagreed*, those disagreements were
  concentrated exactly on the kind of adjacent-same-class confusion (e.g. two sibling methods on the
  same class) that's hardest to catch any other way. This is planned as the mechanism behind the
  `Candidate` tier eventually meaning "evidence disagreed" instead of just "evidence was thin" — see
  [match_plan.md](match_plan.md), task 2.

**Test on an isolated copy, not the real project directory**, when validating anything that writes
files (`symbols rename`). Every destructive-path test in this work was run against a
scratch copy of the relevant `config/` directories, diffed against the untouched original
afterward, and the copy deleted once confirmed. This caught the shared-name bug (see above) without
ever risking the user's actual `symbols.txt`.

## Findings from the first real migration

NTSC `GM8E01_00` → PAL `GM8P01_00`, 2026-09-06, in the Metroid Prime repo. 237 confident split
proposals went in; 58 survived to a clean `ninja` link. What removed the other 179 was not matcher
error — every reverted unit's function correspondences were correct — but link-time constraints the
matcher never sees. The lesson that subsumes all the ones below: **a function match is evidence about
identity, not about linkability.** Whether a unit can be linked from source depends on things outside
the call graph: its data, its neighbors, its duplicates, and what the rest of the still-original
binary expects to find at its addresses.

### A `.text`-only split is not a linkable unit

169 of 237 confidently-matched units carry `.rodata`/`.data`/`.bss`/`.sdata*` content in the source.
Migrating only the code left that data in decomp-toolkit's auto-generated leftover object, which
then defined the same globals (`__DBInterface`, `__PADSpec`, `__files`, …) as the newly compiled
object — "multiply-defined" from the linker. Nearly every non-trivial translation unit has *some*
non-text content, if only an `.sdata2` float constant, so this isn't an edge case; it's the norm.
The Confident tier must require either a `.text`-only source unit or a migrated data split.

### Data can be aligned positionally without an LCS, but only all-or-nothing

Task 3c (`src/analysis/data_matching.rs`) needed the same kind of thing `Matcher::align()` does for
call sites — pair up a source function's references with a target function's — but for data refs
there's no pre-existing partial map to anchor an LCS on the way matched callees anchor a call
sequence. The fallback used instead: trust position only when the two reference sequences are
exactly the same length, and require relocation kind and addend to agree at each position too. A
function whose data-ref count differs between source and target contributes nothing, rather than a
best-effort partial alignment — consistent with the governing principle, since a wrong data symbol
name is exactly as bad as a wrong function name.

This turned out not to be a meaningful limitation between close revisions in practice: validated
read-only against real NTSC→PAL data, the same function-match set that previously produced zero data
renames produced 2,360 confident ones on the first try, plus 90 non-code split proposals (`.data`,
`.sdata2`, `.rodata`, `.sbss`, `.bss`, `.sdata`) alongside 51 `.text` ones — real names recovered
included static tables, vtables, and string-pool labels, several correctly carrying `local`. Close
revisions apparently don't reorder or add/remove data references within an unchanged function often
enough for the all-or-nothing gate to matter; it may bite harder on a more distant pair.

### A data split boundary must land on a 4-byte address — a symbol's own extent doesn't

The read-only validation of task 3c looked clean, but the first real `ninja` run against a fresh
PAL migration failed immediately: `Invalid alignment for split: auto_06_803C15FF_rodata .rodata
6:0x803C15FF`. `src/util/split.rs`'s split-object logic requires every split boundary to be at
least 4-byte aligned, with no exception by section — the `while align > 4` loop that backs off from
a symbol's own declared alignment has a hard floor at 4, and a `.rodata` split ending at an address
one byte short of that floor cannot satisfy it no matter what.

The bug: `group_runs` computed a data run's `end` as the *last member symbol's own byte extent*
(`address + size`). That's correct for functions, which are always instruction-aligned and sit back
to back — but data doesn't: a short string or byte array's raw end routinely falls on an odd address,
and the compiler never pads between symbols *within* one translation unit's contribution to a
section, only (sometimes) between translation units. Using the symbol's own end as the split
boundary conflated "where this symbol's bytes stop" with "where this unit's claim on the section
stops," and those aren't the same address.

Fixed by extending a run's `end` to the *next* layout item's start address (same section) — the true
unit boundary, padding included — falling back to the section's own end for the last run in it. This
alone resolved the great majority of cases (the address in the crash above moved from `...15FF` to
the already-aligned `...1600`), because the next item usually does start on an aligned address. A
second, unconditional gate — demote to Candidate whenever the resulting `start`/`end` still isn't
4-aligned — catches the remainder without guessing: on the real PAL data, 33 of the proposals that
would otherwise have been confident were caught this way, with zero confident proposals left
misaligned afterward.

**Lesson**: an invariant that holds by construction for one kind of item (functions: always
word-aligned, contiguous) is not safe to assume for a structurally similar but differently-behaved
item (data: arbitrary size, no inter-symbol padding) just because the same code path handles both.
Generalizing `unit_matching.rs` to cover data surfaced this immediately in the first real build,
exactly where `--validate` (which never touches the linker) could not have caught it — some
invariants only show up under the tool that actually enforces them.

### The linker's ctors/dtors consistency check is a feature, not an obstacle

The first failure was `Mismatched splits for .ctors … (__init_cpp_exceptions.cpp) and function …
(runtime/__init_cpp_exceptions.cpp)`. Signature analysis hardcodes that unit's name, our `.text`
split used NTSC's, and `split_ctors_dtors` refused the disagreement. Correct behaviour — a `.ctors`
entry in a different object from its function breaks `mwldeppc`. Note the check adopts the
function's unit when *no* ctors split exists yet, so of the 12 units reverted for this, only the
hardcoded one was a confirmed conflict.

### Renaming a duplicate name without its scope creates a linker collision

Template instantiations legitimately repeat their mangled name across TUs (see above), and NTSC
marks all-but-one copy `scope:local`. Our renames carried the name but not the scope, so once enough
of PAL was split into separate objects for the linker to see both copies, they were multiply-defined.
Fixed by hand for 11 names. `--renames` should emit the source symbol's scope and `symbols rename`
should apply it. This is independent of splits — it's a rename-tool gap that any sufficiently split
target will expose.

### Probable attribution plus Confident-only renames leaves placeholders behind

`propose_units` trusts Probable matches when deciding which unit a function belongs to; `--renames`
writes Confident only. So a Probable member of a linked unit still reads `fn_802CD604` in
`symbols.txt` while the compiled source defines the real name, and every leftover object that calls
it by the placeholder fails to link. Two of the nine dependency-revert units were exactly this.
Either rename every member of a linkable unit or require every member to be Confident.

### `MatchingFor(version)` is a claim, and we made it without checking

The project's convention is that `MatchingFor` means "verified byte-identical for this version".
We set it for 199 units from function matches alone. The build linked 58 and `report.json` showed
some of those still aren't 100%. The right process is compile-only first, read the per-unit report,
mark only the 100% units — and check each unit's undefined externals against `symbols.txt` before
linking. The tooling for this (report.json, dtk's ELF parsing) already exists; it just wasn't in the
loop.

### Process notes

- `configure.py` needs `--non-matching` for an in-progress version, or the default ninja target
  includes a full-ROM checksum that can only pass at 100%. Not a defect; easy to mistake for one.
- The link step reports at most ~100 errors then says "too many link errors", so each build round
  reveals only part of the problem. Scanning the source `splits.txt` ahead of time for units with
  non-text sections found the 169 in one pass where the linker would have taken many.
- `dtk-migrate match` itself took ~2 s per run against 16k × 15k functions. The whole cost is in the
  build-verify loop, which is why automating it (plan task 3b) matters more than matcher speed.
- Two throwaway Python scripts (merge splits in address order; add/remove a version in
  `MatchingFor` tuples) did all the applying. Now: the splits merge is `dtk-migrate splits merge` (plan task
  3d); `MatchingFor` editing still isn't, since automating *which* units qualify needs task 3b first.

### A collision guard needs to know what it's guarding against

Fixing the 3a items (2026-09-07) and re-running against PAL's already-migrated state surfaced one
more: `apply_renames`'s collision guard — reject a rename whose target name is already held by a
symbol not itself being renamed away — rejected exactly the renames the new `local` marker exists
for. A name already present in the file is precisely what "this is a legitimate duplicate" looks
like; the guard couldn't tell that from "this would silently merge two unrelated symbols" because it
never looked. PAL's three real `AlarmHandler`/`OnReset` collisions from the first migration were
still skipped even carrying `scope:local`, until the guard was taught to let a local rename through
unconditionally and keep the check only for global ones. **Lesson, same shape as the ctors/dtors one
above**: a safety check written before a new case exists can't account for that case just because the
case later starts producing correctly-shaped input — it has to be told. Re-verify a guard's
assumptions whenever the data it's guarding against gains a new legitimate variant, not just when it
gains a new invalid one.

## Findings from the second real migration

NTSC `GM8E01_00` → PAL `GM8P01_00` again, 2026-09-07, this time from a freshly-reverted,
freshly-pulled PAL — a clean re-run of the whole pipeline with task 3c's data matching and 3a's
tightened tier in place, not a continuation of the first migration's partial state. Result: **105
units link for PAL**, versus 58 the first time, from 137 candidate units (of 155 newly-split) whose
NTSC counterpart was itself already `MatchingFor` — the other 18 aren't matching on NTSC either, so
there was no basis to expect PAL to link from source for them, and they were left alone.

Two rounds of real `ninja` failures, both the exact failure classes task 3b is meant to catch
automatically, neither a matcher error:

- **28 units multiply-defined** against their own leftover object — a `MatchingFor` claim from a
  function match alone (still not verified by compiling) asserted more than the match actually
  established, echoing the first migration's `MatchingFor(version) is a claim` finding almost
  exactly, just at a smaller rate (28 of 137 vs. most of 199 before) now that the tightened tier and
  data migration remove the two largest causes.
- **4 units undefined** on a dependency that isn't matching yet — `CTransitionManager` failing on
  `CTreeUtils::GetTransitionTree` is the literal example task 3b's plan entry names, reproduced
  independently on a second run.

Excluding those 32 (by removing `"GM8P01_00"` from their `MatchingFor` tuple in `configure.py`) gave
a clean link. This is still all manual — a scripted diff of "what did I just enable" against "what
did `ninja` reject" — which is exactly the loop task 3b would automate.

### The hash check is the only real oracle — linking clean is not enough

The 105-unit build above was verified with `configure.py --non-matching`, which links successfully
and was reported as the migration's result. It was wrong. `--non-matching` explicitly skips the
default target's full-DOL SHA-1 check against retail — it exists so an in-progress version can build
at all, but that means it verifies *nothing* about byte accuracy. Told directly that "files marked as
matching are these that do not cause an invalid hash when linked," a real hash-checked build was run
for the first time, and it failed on a completely clean link with every enabled unit reporting
`complete: true` in `report.json`.

This matters beyond the specific miss: **every verification step used before this point — `--validate`
(scores against hidden names, never touches a linker), `report.json`'s per-unit `complete` flag, a
`--non-matching` link — is blind to whole classes of real error.** Only the actual retail hash check
catches them, because it's the only check that looks at the *final linked bytes* rather than at
either the matcher's own confidence or a per-object diff computed independently of the real link.
Bisecting the 448-byte discrepancy (halving the enabled unit set, rebuilding, checking `main.dol`'s
size against `orig/<version>/sys/main.dol` each round — plain byte count, not even a full hash, since
any deviation already proves the point) isolated it to two units, and each is a distinct failure mode
report.json's own top-level fields don't expose:

- **`Kyoto/Text/CRemoveColorOverrideInstruction.cpp`** had a confident match for its `.data` (a
  vtable) but not its `.text` — its two member functions never got a `--splits` proposal at all.
  Marking the *file* `MatchingFor` still compiles the whole thing; the linker had nothing else
  claiming that address range, so it wasn't multiply-defined, and nothing referenced the new
  functions from elsewhere, so nothing was undefined either. The extra ~192 bytes were simply
  appended, growing the DOL and shifting every subsequent address. `report.json` showed this unit
  as `complete: true, matched_code_percent: 100.0` — accurately describing the *matched* code, which
  said nothing about the *unmatched* code sitting right next to it in the same file. **The gate for
  `MatchingFor` needs to be per source file, not per split**: every section that file will emit —
  code included, even where no split proposal ever claimed it — has to be accounted for, or the file
  isn't safe to mark regardless of what did get proposed.
- **`GuiSys/CGuiWidgetIdDB.cpp`** had `matched_code_percent: 100.0` and `complete: true` end to end,
  yet contributed the other ~224 (plus a small non-additive interaction between the two, since
  192 + 224 ≠ 448 but enabling both together reproduced 448 exactly). Its `.rodata` — a string-literal
  pool — sat at `fuzzy_match_percent: 95.38` in the same report, buried in a `sections` array
  `complete` never looks at. The *position* of the reference was correctly confident (same function,
  same call site); the *content* wasn't (PAL's actual string bytes differ from NTSC's — plausibly
  region-specific text, i.e. legitimate content, not a wrong match). Structural confidence about
  which data a function references and byte confidence about what that data actually contains are
  different claims, and only diffing the compiled output against retail settles the second one.
  **The gate needs `fuzzy_match_percent == 100` on every section, not the coarser `complete` boolean**,
  which can be true while real bytes differ.

Both are now fixed in the prime repo (excluded from `MatchingFor`); the resulting `main.dol` is
byte-identical to `orig/GM8P01_00/sys/main.dol`, confirmed both via `dtk shasum` and a raw `cmp`.
103 of the original 137 candidate units remain enabled.

**Lesson, and it subsumes every other one in this document**: a check that doesn't exercise the same
path the real artifact goes through will eventually pass something that path rejects. `--validate`,
`report.json`, and `--non-matching` linking are all *proxies* for "is this actually correct," each
cheaper and faster than a real build, and each was trusted a little further than its actual coverage
justified. None of that is wasted — they're still the right tools for iterating quickly — but the
governing principle's "an absent name is better than a wrong one" has a build-side twin that this
migration made concrete: **an unverified `MatchingFor` is a claim, not a fact, until something has
actually compared the final linked bytes against retail.** Task 3b's compile-verify loop needs both
fixes above built in from the start, not bolted on after the fact.

## Findings from continued PAL migration work

2026-09-08, same NTSC → PAL pair, driven by a build-verify promotion loop built on top of `dtk
match --splits` (the prime repo's `tools/split_confidence_loop.py` — task 3b's compile-verify loop,
implemented outside dtk since it needs nothing from the matcher itself). Net result over the
session: PAL units present went from 247 to 282 of 814 (30.3% → 34.6%), across several rounds, each
gated on a full-DOL hash check, not just a clean link. Getting there surfaced four more real dtk
findings, three fixed, one still open.

### A run breaks on any unattributed function, even a harmless one

`group_runs` (`unit_matching.rs`) ends a run the instant `same_run` hits a function the matcher
didn't attribute to the current unit at all — correct when that function genuinely belongs to
someone else, but not when it's a tiny function (an inline accessor, a trivial dtor) that simply
didn't carry enough signal for Tier 1/2 matching to pin down individually. Concrete case:
`CScriptPickup.cpp`'s real, single 852-byte constructor was proposed as two disjoint fragments (20
and 832 bytes) with a 204-byte gap between them — five genuinely unmatched functions (8–112 bytes
each, real, correctly-detected function boundaries in the target, just individually unmatched)
sitting in the middle. Downstream tooling that has to pick just one fragment as the whole boundary
(the prime repo's `dominant_cluster`) gets a hard 0% match, not a partial one, since PowerPC's
relative branch/load encoding doesn't degrade gracefully to a boundary that's off by even a few
bytes — source similarity between NTSC and PAL buys no partial credit on compiled bytes.

Fixed with `bridge_gap`: when a run resumes with the *same* unit after a small enough span (≤512
bytes) of exactly these unattributed items, bridge across it instead of ending the run — refusing to
cross a section boundary, a different unit's match, or an address some other unit's split has
already claimed, any of which is real evidence the gap isn't this unit's. A bridged run can never
reach `Confident` (the bridged content was never actually verified, just judged likely) — enforced
for free, since `all_confident` already excludes unattributed members from consideration and
`classify()` adds its own `"bridges unmatched functions between two runs of the same unit"` reason
whenever bridging happened. Verified against a live re-proposal: total candidate fragment count fell
from ~3,540 to 2,298 (−35%) project-wide, and specific fragmented units improved concretely
(`CParasite.cpp` 16 → 9 fragments, `CPhysicsActor.cpp` 17 → 8), while a genuinely large gap (~1.1–1.6
KB on `CGrenadeLauncher.cpp`, real missing content, not a matching gap) correctly stayed unbridged.

### A confidently-matched section can still fail comparison because of its *neighbor*, not its own content

**Audit qualification (2026-09-09):** this section's boundary-artifact explanation
is a hypothesis for mismatches, not something an adjacent auto symbol proves.
The former script's default link used extracted original objects for candidates,
so the claimed 25 direct-byte-confirmed promotions below were not independent
verification of compiled output. The proposed comparison is valid only with
explicit compiled-object link provenance.

Referenced in this doc's own earlier text (the `CRemoveColorOverrideInstruction.cpp`/vtable
discussion) but never written up on its own: objdiff's target-side comparison symbol, for a section
whose neighbor hasn't been claimed by any split yet, bleeds a few bytes past the true boundary into
whatever unclaimed content sits next to it — because that neighbor has no boundary of its own yet
for the comparison to stop at. A genuinely correct split then reports well under 100%
`fuzzy_match_percent` for a reason that has nothing to do with its own content being wrong. Every
case found this way has the mismatched section's start or end address landing exactly on one of
dtk's own auto-generated placeholder names (`lbl_`/`fn_`/`jumptable_`/`gap_`/`pad_`/`dtor_` — see
`is_auto_symbol`, `src/util/config.rs`) — the one dependable signal that a section's neighbor, not
the section itself, is what's actually still unclaimed.

This is not itself a dtk bug — it's an inherent property of diffing against a partially-migrated
target — but it means neither `report.json`'s `fuzzy_match_percent` nor a clean link is sufficient
to reject a candidate this way. The only thing that actually settles it: read the exact declared
`[start, end)` range's raw bytes from a fully linked, fully relocated ELF (an unlinked `.o`'s
relocated fields are placeholders that would never byte-match even for genuinely correct code) and
compare directly against the retail DOL at the same range, bypassing objdiff's symbol-pairing
entirely. Implemented prime-side (`split_confidence_loop.py`'s `Elf`/`Dol` classes); in one real
round this promoted 25 units in a single batch that fuzzy-matching alone had been leaving
permanently blocked.

### BSS address-adjacency is not a reliable link-order signal — but the reason is narrower than "no file content"

`resolve_link_order` (`src/util/split.rs`) treats every section's address-adjacency uniformly:
consecutive splits with different units become a directed edge, unioned across all sections into one
graph, and a cycle in that graph is a hard build failure. Staging roughly 120 otherwise-independent
candidates for PAL in one batch produced a single 386-node cyclic component — spanning nearly the
entire unclaimed `.text` region — that `diagnose_link_cycle`'s own small-combination search couldn't
isolate to fewer than dozens of unrelated units, because it genuinely wasn't a small number of bad
edges.

First fix tried: exclude every `.bss`-kind section from the graph outright, on the reasoning that BSS
has no file content and the linker is free to place it however it likes. This was wrong, and wrong
in a way the test suite couldn't catch: staging a batch under this rule produced a **clean, acyclic**
graph and a **clean link**, but the full-DOL hash check failed with a symbol relocated roughly 400 KB
from its expected address (`lbl_803DF5A8` expected at `0x803DF5A8`, found at `0x80444A08`) — the fix
had discarded real ordering evidence (regular, per-TU BSS genuinely does follow link order, same as
any other section) along with the fake ordering evidence it was meant to remove, and the now-
underconstrained toposort picked a valid-looking but wrong order for regular BSS.

The actual distinction, already half-encoded in the code before either fix: "common" BSS
(`ObjSplit::common`) is the CodeWarrior/mwld analogue of an ELF COMMON symbol — a pool of tentative,
uninitialized definitions the *linker* packs by its own rules (alignment, size), not by link order.
The pre-existing code already skipped the one non-common-to-common transition edge, but still let
common-to-common pairs add edges, and excluded nothing else. Fixed by skipping any edge where
*either* endpoint is common, and otherwise generating BSS edges exactly like every other section.
Verified against the same real batch: the reported conflict narrowed from `[".bss", ".data"]` to
just `[".data"]` (a separate, much smaller, correctly-diagnosed residual — see below), and the
promoted set that had previously required reverting every single unit one at a time now passed the
full hash check clean on the first attempt.

**Lesson**: a fix validated only by "does the graph stay acyclic" or "does it link" is validated
against the wrong oracle when the actual failure mode is *silent wrong placement*, not a build error
— this is the same shape as "the hash check is the only real oracle" above, just for a decomp-
toolkit-internal graph invariant instead of a project-level migration claim. The tell here specifically was that the *fix that was wrong* also looked like a complete success by every check except the one that actually verifies final bytes.

**Still open**: even with the common/non-common distinction correct, a residual, smaller `.bss`-only
cyclic component can still occur (observed: a chain through several `Kyoto/Graphics`/`Collision`/
`dolphin`/`musyx` units, none individually mismatched — every one checked had a correct, nearby
NTSC-consistent neighbor). Current best explanation: BSS placement is alignment/size-packing driven
even for regular, non-common variables — not strictly monotonic with declaration order the way
`.text`/`.data` are, just *usually* close enough not to matter. That slack is normally harmless, but
staging many simultaneously-correct candidates in one batch gives more opportunity for several small,
individually-unremarkable local perturbations to compound into a real topological contradiction once
unioned with `.text`'s ordering. Doesn't yet have a fix; treating BSS edges as a soft/tie-breaking
constraint rather than a hard one is the likely direction, not yet attempted.

### The `.ctors`/function unit-attribution check has a path-prefix bug (open)

`resolve_link_order`'s "Mismatched splits for `.ctors` X and function Y" check (the one documented
above as "a feature, not an obstacle") fired incorrectly for a genuinely single-unit case:
`runtime/__init_cpp_exceptions.cpp`'s `.ctors` entry was attributed to a unit named
`__init_cpp_exceptions.cpp` — the same name with the directory prefix silently dropped — while its
function correctly kept the full `runtime/` prefix, so the check saw two different units where there
is only one. Confirmed NTSC's own `splits.txt` declares this unit consistently, with the prefix, in
every section. Not yet root-caused to a specific line (the `.ctors`-to-unit lookup is a separate code
path from the address-adjacency edges above) or fixed; currently worked around by skip-listing the
one known victim prime-side.

## Things worth re-checking before extending this further

- `MatchOptions::use_layout` has no CLI flag yet. Link-order inference assumes both binaries keep
  the same translation-unit layout, which holds within one game's revisions and will not hold
  across different games — the eventual second target for this tool. It needs to be exposed and
  probably default differently once source and target no longer share a codebase-and-linker
  lineage.
- The propagation vote weights, the tier thresholds (`CONTESTED_MARGIN`, `CORROBORATION_FOR_PROBABLE`,
  `MIN_DISTINCTIVE_INSTRUCTIONS`) were tuned against Metroid Prime's specific binary characteristics
  (PowerPC, Metrowerks CodeWarrior, this codebase's particular mix of templated STL-alike code).
  They are constants, not learned, and there's no reason to expect them to transfer unchanged to a
  structurally different binary — re-measure with `--validate` before trusting them elsewhere.
- Every "done" measurement in this document and in any plan doc was taken against a specific build
  of `dtk` and a specific commit of the target decompilation project. If either the scoring formula
  or the underlying `symbols.txt` files move, the numbers are stale — re-run rather than cite them
  as current fact.
