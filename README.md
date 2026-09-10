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

`--stage` accepts `coverage`, `discover`, `verify`, `both` (default), or `all`.
`all` runs coverage → discovery → source verification. `--limit` bounds
candidates **per stage**; `--batch-size` defaults to 40. `--workers 1` uses exactly
the same batches and validation as parallel execution. The default resource
setting is three processes with four Ninja jobs each. Warmed candidate builds
time out after 120 seconds by default; use `--build-timeout SECONDS` to adjust
that bound without limiting cold baseline builds. See the measured guidance
in [parallel execution](docs/parallel.md) before choosing a pool size.
Use `--only UNIT` to evaluate an exact proposed unit name without running other
candidates; repeat the option to select more than one unit.

The runner captures current files, including dirty and untracked inputs and
submodule contents, freezes tool binaries and scripts, and gives each worker a
private configuration and build cache. It prepares proposals once, evaluates
batches concurrently, then revalidates their union in deterministic order. Only
the coordinator publishes validated changes. User input drift stops publication.
Python's free-threaded runtime does not replace process and filesystem isolation.

Coverage is opt-in through `--stage coverage` or `--stage all`. Policy version 5
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
   partial code splits. Existing data ranges are preserved.
3. Compiles and measures each candidate, retaining it only if it adds matched
   code without reducing another existing unit's matched code.
4. Requires a retail build check for every accepted batch. This checks split
   integrity; candidates remain disabled as whole source files.
5. Bisects failing batches, rebuilds the final state, and records commands and
   results under `build/<target>/discovery/`.

One rejected proposal does not permanently blacklist a source file. A different
boundary, neighboring split, symbol map, or tool revision can change its result.
An exception or interrupt restores the input splits and symbols and attempts to
rebuild them. Process termination or power loss cannot run Python cleanup.

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
