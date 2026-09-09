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

Run the scripts **from the game project's root**, not this repository. They use
`Path.cwd()` and expect `configure.py`, `tools/project.py`, Ninja,
`config/<version>/{config.yml,splits.txt,symbols.txt}`, extracted retail inputs,
and the project's compiler tools. Python 3.9 or later is supported.

Use a DTK build containing `match --splits` and `symbols rename`. A downloaded
release is not guaranteed to have these development features. Pass an absolute
`--dtk` path: both matching and configure/Ninja then use that binary. Do not copy a
development executable over a Ninja-managed downloaded tool.

Run only one migration/build process per game checkout; they share configuration,
build files, and reports.

## Discover useful code splits

```sh
python /path/to/discover_splits.py --target GM8P01_00 --dtk /path/to/dtk
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
python /path/to/verify_source_units.py --target GM8P01_00 --dtk /path/to/dtk
```

This tests currently comparison-matched files as **compiled link inputs**. It
bisects failing groups, checks the linker dependency graph, checks the retail
hash, and also compares the final DOL directly with retail. Accepted files are
recorded in a generated, version-specific block in `configure.py`; other versions
keep their existing settings. Commands and results go under
`build/<target>/source-verification/`.

The current configure adapter requires the dtk-template `config.libs` structure
and `if args.mode == "configure":` dispatch. The all-sections objdiff filter is
conservative: files with misleading data comparisons may remain untested. Failure
of an individual trial also does not rule out a mutually dependent group.

## Status and the historical loop

```sh
python /path/to/split_status_report.py --target GM8P01_00
python -m unittest -v test_migration
```

The report distinguishes comparison matches from source-link configuration. It
requires a report and DTK proposals from a previous run. Tests run from this repo.

`split_confidence_loop.py` remains available for the older all-sections approach,
but does not verify candidate source linkage. Its unsafe ELF fallback is disabled
by default. Its persistent skip list refers to failed proposals, not definitive
proof that a unit cannot be migrated. Prefer the two commands above for new work.

See [Prime commands](docs/prime.md), [validation audit](docs/validation_audit.md),
and [link-order investigation](docs/link_order_cycle_investigation.md).
