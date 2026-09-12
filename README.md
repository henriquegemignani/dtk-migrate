# dtk-version-matching

Automatically transfers symbols and split proposals between versions of a
decomp-toolkit / dtk-template game project, then tests the proposals by compiling.
The source version can be partially matched. Development currently targets
Metroid Prime `GM8E01_00` (NTSC 0-00) → `GM8P01_00` (PAL).

## What the measurements mean

- **Split coverage:** a target address range is assigned to a source file. This
  alone says nothing about whether that file compiles or matches.
- **Objdiff matched code:** bytes in functions classified as matching by the
  project's objdiff configuration. A partly finished file can contribute useful
  matches. Relocation comparison policy matters; this is not raw byte equality.
- **Source-linked code:** source objects enabled in the build configuration.
  `metadata.complete` reflects this setting, not a byte comparison.
- **Verified source linkage:** the candidate compiled objects are actual inputs
  to the linker, and the resulting DOL equals retail. This is the whole-file gate.

A retail hash with a candidate still linked from extracted original objects does
**not** prove that candidate's source matches. The former workflow and docs made
this mistake, including a circular "direct byte comparison" fallback. See
[the audit](docs/validation_audit.md).

## Requirements

Use **uv and Python 3.14t**. From this repository, `uv sync` installs the pinned
free-threaded interpreter and creates the environment. Run commands with `uv run`.
The game project must contain `configure.py`, `tools/project.py`, Ninja,
`config/<version>/{config.yml,splits.txt,symbols.txt}`, extracted retail inputs,
and installed compiler tools (build the project once before snapshotting it).

Use a DTK build containing `match --splits`, `match --coverage`, and `symbols rename`. A downloaded
release is not guaranteed to have these development features. Pass an absolute
`--dtk` path: both matching and configure/Ninja then use that binary. Do not copy a
development executable over a Ninja-managed downloaded tool.

Migration commands share an OS-held project lock. Do not run an unrelated build
in a checkout while migration uses it. The parallel runner builds in private copies.

## Repository layout

- `src/` contains the command-line applications and their shared runtime modules.
- `tests/` contains the `unittest` suite.
- `docs/` contains operational guidance and validation records.

## Parallel migration

From this repository:

```sh
uv run src/parallel_migration.py --project-root ../prime --source GM8E01_00 --target GM8P01_00 --dtk /path/to/dtk --stage both --workers 3 --build-jobs 4
```

`--stage` accepts `derive`, `coverage`, `discover`, `verify`, `both` (default), or
`all`. `all` runs symbol derivation → coverage → discovery → source verification.
Derivation runs first because the later stages depend on it: `dtk match` anchors
its proposals on symbol names, so every name established there widens what
coverage and discovery can propose. Measured on `GM8P01_00`, naming first took
discovery from a frontier of roughly 29 candidates to 349, of which 156 were
accepted. `--limit` bounds
candidates **per stage**; `--batch-size` defaults to 40. `--workers 1` uses exactly
the same batches and validation as parallel execution. The default resource
setting is three processes with four Ninja jobs each. Warmed candidate builds
time out after 120 seconds by default; use `--build-timeout SECONDS` to adjust
that bound without limiting cold baseline builds. See the measured guidance
in [parallel execution](docs/parallel.md) before choosing a pool size.
Use `--only UNIT` to evaluate an exact proposed unit name without running other
candidates; repeat the option to select more than one unit. Coverage reports list
all other eligible candidates under `eligible_excluded_by_only`, so a focused run
does not make an untested proposal look ineligible.

The runner captures current files, including dirty and untracked inputs and
submodule contents, freezes tool binaries and scripts, and gives each worker a
private configuration and build cache. It prepares proposals once, evaluates
batches concurrently, then revalidates their union in deterministic order. Only
the coordinator publishes validated changes. User input drift stops publication.
Python's free-threaded runtime does not replace process and filesystem isolation.

Derivation is opt-in through `--stage derive` or `--stage all`. It names target
symbols by comparing compiled source objects against the originals extracted
from the target binary, exactly as [the standalone tool](#derive-symbol-names-from-compiled-objects)
does, and stages only `confident` and `probable` proposals. A rename changes no
bytes, so the retail hash cannot tell a right name from a wrong one; the names
are corroborated before they reach the stage, by the body comparison. What the
build decides is whether a name can be *applied*: naming an address after a
function another unit compiles from source puts that name in two linked objects,
and the linker rejects it. That failure is loud, so a batch that will not link is
bisected exactly as a split candidate is, and only the offending names are
dropped. A rename that reduces any unit's matched code is also rejected.

Coverage is opt-in through `--stage coverage` or `--stage all`. Policy version 8
accepts strict exact-body intervals, corroborated `this`-layout groups, and
boundary-constrained function sequences. A layout
group requires at least two unique functions whose normalized instruction streams
and relocation layouts agree after masking only proven object-relative offsets;
all functions must infer the same transformation with at most two constant deltas
separated by one breakpoint. The runner
proposes the group span, never an individual layout function, then checks ownership,
linker inputs, existing-unit regressions, and retail bytes. It deliberately allows
zero objdiff gain and keeps the candidate source object disabled. A boundary
sequence uses the immediate represented source neighbors to bound one unclaimed
target gap, then requires a decisive monotone alignment with enough unique exact-body
anchors, strong matches, functions, and bytes. The complete gap is tried as one range; DTK
does not widen from the first or last matched function. A passing range
therefore establishes partial split representation; it does not establish source
equivalence.
When normal function matching is inconclusive, four unique layout-shift functions
covering at least 1,024 bytes and 16 changed member accesses can corroborate the
complete neighbor-bounded gap. This fallback additionally requires source and target
function counts to differ by at most one and text sizes by at most 2%. It assigns
ownership without treating the weaker function alignment as rename evidence.
For polymorphic classes whose compiler output moves one function body into a local
helper, a second complete-gap fallback requires at least eight monotonically aligned
functions covering 85% of both the source functions and target bytes. A uniquely
paired vtable must agree in every matchable slot, including at least eight matched
slots and four slots belonging to the candidate TU. Source and target text sizes
must be within 3%, function counts within one, and the only unmatched target helper
must be called entirely from inside the gap and from at least one aligned function.
The runner revalidates the vtable pairs and helper call graph before trying the range.
When a stale neighboring split makes the bounded gap too wide, an ownership-transition
fallback may trim the gap to the candidate's complete aligned function sequence. It
requires at least eight contiguous primary matches covering every source function,
two strong matches, a decisive alignment, and source/target sizes within 2%. Every
excluded function at either edge must contiguously cover that edge and map to the
stated adjacent source TU; each nonempty edge needs a strong match. At least one edge
must be nonempty. The runner independently rechecks the sequence, sizes, and both
ownership transitions before trying the trimmed range.
If the candidate's complete sequence occupies a prefix or suffix of an adjacent
explicit target owner, the adjacent-owner transition fallback can shrink that
owner and assign the recovered interval in one transaction. The candidate needs
all of its source functions aligned contiguously, at least eight functions, two
strong matches, two direct exact-body anchors, and no more than 10% size drift.
The retained owner needs its own complete monotone alignment with at least four
functions, two strong matches, no more than 10% size drift, and at most one
caller-local helper between aligned functions. The runner reconstructs both
sequences and boundary geometry, applies both range changes atomically for every
trial, and rolls both back together after rejection or failure.
When functions in an eligible boundary sequence strictly identify data symbols used by
source-side asset extraction, DTK also proposes equivalent target extraction entries.
The target symbol and its existing extent stay intact, while `rename` preserves the
source include's output name. The runner applies these entries with the split trial,
checks the generated files and renamed header declaration, and rolls both files back
when the candidate fails.
The run's `coverage/coverage.json` and `coverage/coverage.md` separate represented
TUs, objdiff matching, configured source linkage, and verified source linkage.

Calibrate the policy against a named target. Exact-body and layout-shift generation
mask target names and ownership. Boundary sequences deliberately retain only the
two represented neighbor ranges needed to determine the gap; the candidate's own
target split does not determine either boundary. The complete proposals are then
scored against the ownership oracle:

```sh
uv run src/calibrate_coverage.py --project-root F:/programming/decomp/prime --source GM8E01_00 --target GM8P01_00 --dtk /path/to/dtk
```

If the target has already received the proposals being evaluated, pass
`--oracle-splits` with a saved pre-change split file to keep the labels independent.

Runs and evidence live under `build/parallel-migration/runs/<RUN_ID>` in the game
project. Resume an interrupted run using its saved options:

```sh
uv run src/parallel_migration.py --project-root ../prime --resume RUN_ID
```

Changed project inputs, tools, scripts, or interpreter require a fresh run.
Successful sibling jobs are retained after a worker failure. Windows Job Objects
stop Ninja and compiler descendants when a worker is cancelled. Symlinks and
junctions in snapshot inputs are rejected; use materialized project files.

## Discover useful code splits

```sh
uv run src/discover_splits.py --project-root ../prime --target GM8P01_00 --dtk /path/to/dtk
```

`--source` defaults to `GM8E01_00`. `--batch-size` defaults to 40; `--limit N`
bounds the number of proposals examined. This script:

1. Checks the baseline build and generates fresh DTK proposals and confident renames.
2. Stages code ranges, including proposed fragments and extensions to existing
   partial code splits.
3. Compiles and measures each candidate, retaining it only if it adds matched
   code without reducing another existing unit's matched code.
4. Extends already-established units with proposed non-code ranges (`.rodata`,
   `.bss`, `.sdata`, `.sbss`, ...) that DTK's own proposals already name but
   that were never carried over. These never create a new unit and never
   claim a range another explicit unit already owns, so there is no matched-
   code signal to gate on; a candidate is kept once its batch still builds and
   still preserves the retail hash.
   DTK ends a proposed range at the last symbol it could match, so an unmatched
   symbol immediately after it lands in a remainder nothing owns. Nothing emits
   that symbol and the unit's own code still references it, so the link fails on
   an undefined symbol — `musyx/runtime/synth.c` lost its whole data migration to
   a four-byte tail of exactly this shape. A proposed range is therefore grown
   over such a remainder, bounded twice: never into the next owner's range, and
   never past the size the same unit has in the source version. Measured against
   an archived run, this changes 74 of 214 data proposals and touches 32 of the
   64 units that previously failed to build.
5. Requires a retail build check for every accepted batch. This checks split
   integrity; candidates remain disabled as whole source files.
6. Bisects failing batches, rebuilds the final state, and records commands and
   results under `build/<target>/discovery/`.

One rejected proposal does not permanently blacklist a source file. A different
boundary, neighboring split, symbol map, or tool revision can change its result.
An exception or interrupt restores the input splits and symbols and attempts to
rebuild them. Process termination or power loss cannot run Python cleanup.

## Linked modules beside the DOL

A game may ship RELs alongside its DOL. Each is a module with its own splits and
symbols, and `src/project_modules.py` reads their locations from the version's
`config.yml` rather than assuming them, because nothing about the layout is
conventional: Metroid Prime keeps `NESemuP.rel` under `config/GM8E01_00/NESemu/`
but builds it to `build/GM8E01_00/NESemuP/`, and the same module is called
`NESPALemuP` in PAL. Modules are therefore paired across versions **by position**
in `config.yml`, and each result records both names.

Compiled source objects are shared: a file compiles once into `build/<version>/src`
whichever module links it, while only the extracted objects are per-module under
`build/<version>/<module>/obj`. Pairing that one source tree against a module's
own `obj/` selects exactly the units that module contains — and is what makes a
file moving between the DOL and a REL observable, since such a move changes which
`obj/` holds it and never where it compiles to. `split_audit.relocated_units`
reports those moves; `split_audit.unsplit_modules` reports a module the target has
not begun splitting at all.

`derive_symbol_names.py --module NAME` names symbols in a module other than the
DOL. The rest of the pipeline is still DOL-only: coverage, discovery and
verification all gate on builds, and a version that excludes a module from
`config.build_rels` produces no compiled source objects for it, so there would be
nothing to compare. Enabling the module in the game project comes first.

## Derive symbol names from compiled objects

```sh
uv run src/derive_symbol_names.py --project ../prime --target GM8P01_00
```

Names target symbols by comparing each unit's **compiled source object**
(`build/<target>/src/...`) with the **object extracted from the target binary**
(`build/<target>/obj/...`). Both already exist after a normal build, so this
costs a couple of seconds and no compilation of its own.

Three methods contribute, strongest first:

- **`body-match`** (needs `--objdiff`). Compares function bodies directly.
  objdiff pairs symbols by name, so a proposed pairing is invisible to it, but
  the inputs are ours: renaming both sides to one short token in a temporary
  copy makes the pair scorable. Nothing is rebuilt and the project's files are
  never written. A name is taken only when one candidate both scores well and
  leads the runner-up clearly -- see [the method notes](docs/symbol_derivation.md).
- **`call-site`.** Aligning the relocations inside a function whose name already
  agrees names whatever it calls, **including in units with no source of their
  own**: where the source object calls `GetTextureElement__20CParticleDataFactory...`
  and the extracted object calls `fn_8030DA80`, that address has its name.
- **`function-position`.** A placeholder sitting between two agreeing names is
  the function the source defines there.

PAL inlines differently enough that ordering alone misplaces functions, so
where `body-match` and `function-position` disagree the position loses: a body
comparison and a call site both observe the function itself, while a position
only observes its neighbours. Two equally strong methods that disagree are
dropped rather than ranked.

This is a different signal from `dtk match`, which compares two versions of the
same binary. Here the source object states what the unit is *supposed* to
contain, so the comparison stays inside one translation unit and rests on names
the build already agrees on.

Nothing is written to `symbols.txt` without `--apply` (which needs `--dtk`);
by default the run only writes a rename file for `dtk symbols rename`. A
proposal is dropped unless every unit with an opinion agrees, the symbol exists,
and the new name is not already taken at another address. `--tier` selects how
much to keep:

| tier | evidence |
|---|---|
| `confident` | a body match that scores high and leads clearly, or a call site inside a name-anchored function whose relocation lists align exactly |
| `probable` | a body match past both thresholds, a call site in a shorter alignment, or a positional function name whose size also agrees |
| `candidate` | a positional function name whose size disagrees |

`--tier probable` is the default. `--unit` restricts the run, `--report` writes
JSON, and `--limit` bounds the units examined. `--body-percent`, `--body-margin`
and `--size-ratio` tune body matching; the defaults are calibrated, so prefer
`--tier` for routine tightening.

Gaps whose two sides differ in length are deliberately left unpaired: that is
where the target version restructured the code, and pairing across it is how a
rename pass starts inventing names. For the same reason call sites are only
mined from function pairs that matched *by name* — a positionally guessed
function pair would make every name inside it rest on that guess.

## Verify whole source files

```sh
uv run src/verify_source_units.py --project-root ../prime --target GM8P01_00 --dtk /path/to/dtk
```

This tests currently comparison-matched files as **compiled link inputs**. It
bisects failing groups, checks the linker dependency graph, checks the retail
hash, and also compares the final DOL directly with retail. Accepted files are
recorded directly in each object's `MatchingFor(...)` call in `configure.py`, with
arguments ordered by `VERSIONS`. Existing version flags are preserved;
`NonMatching` becomes `MatchingFor(<target>)` where needed. Commands and results go under
`build/<target>/source-verification/`.

Old `BEGIN AUTOMATED SOURCE VERIFICATION` blocks are migrated automatically on
the next successful run. To migrate them and verify the current target without
trying additional files, pass `--migrate-only`. Failed trials restore the accepted
declarations; exceptions restore the complete original file.

The configure adapter requires a literal `VERSIONS` list and unique literal
`Object(status, "path")` declarations. It supports `MatchingFor`, `NonMatching`/
`Equivalent`/`False`, and already-enabled `Matching`/`True`; unknown expressions or modified
legacy block logic fail before editing. The all-sections objdiff filter is
conservative: files with misleading data comparisons may remain untested. Failure
of an individual trial also does not rule out a mutually dependent group.

## Status and the historical loop

```sh
uv run --project /path/to/dtk-version-matching /path/to/dtk-version-matching/src/split_status_report.py --target GM8P01_00
uv run python -m unittest -v
```

Run the status command from the game checkout, and tests from this repository.
The report distinguishes comparison matches from source-link configuration. It
requires a report and DTK proposals from a previous run. Tests run from this repo.

`split_confidence_loop.py` remains available for the older all-sections approach,
but does not verify candidate source linkage. Its unsafe ELF fallback is disabled
by default. Its persistent skip list refers to failed proposals, not definitive
proof that a unit cannot be migrated. Prefer the two commands above for new work.

See [Prime commands](docs/prime.md), [validation audit](docs/validation_audit.md),
and [link-order investigation](docs/link_order_cycle_investigation.md).
