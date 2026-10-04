# dtk-migrate

Carries decompilation progress from one version of a game to another. Given a
[decomp-toolkit](https://github.com/encounter/decomp-toolkit) project with two
versions of the same executable, one partly matched and one not, it transfers
symbol names, split boundaries and finally whole source files.

Nothing is kept on the strength of a proposal. Every change is applied to a
private copy of the project, compiled, measured, and discarded unless the build
agrees with it.

## What a result means

The tool keeps four questions apart, weakest evidence first, because a single
percentage would be read as the strongest of them.

| | what it says | what it does not say |
|---|---|---|
| **Binary TU identification** | target functions are attributed to a source translation unit, with competing explanations retained | that both split edges are known or safe to apply |
| **Boundary recovery** | the evidence supports both ends of a target range | that the range can safely be applied |
| **Applied ownership** | a target range is assigned to a source file and survives the build | that the file compiles, or matches |
| **Verified source linkage** | the compiled object is a real linker input **and** the result equals retail | — this is the only whole-file proof |

Objdiff matched-code percentage is a separate function comparison, and
`configure.py` linkage is a build setting. Neither by itself proves source
linkage.

A retail hash with a candidate still linked from its extracted original does
**not** prove that candidate's source is right. See
[the audit](docs/history/validation_audit.md) for how an earlier version of this
tool got that wrong.

## Requirements

- A Rust toolchain, and `cargo install --path .`
- A decomp-toolkit project that has been built once, so its compilers, tools and
  extracted originals are in place
- Python and Ninja on `PATH`, for the project's own build

## Migrating

```sh
dtk-migrate run --project-root ../prime --source GM8E01_00 --target GM8P01_00 --stages all
```

Stages run in a fixed order, and `--stages` selects which to run:

- `derive` validates symbol names using binary and compiled-source function comparisons.
- `coverage` assigns target ranges to source units using binary ownership
  evidence; it does not claim the source matches.
- `discover` adds code splits that improve matched code and supported data
  splits, while preserving retail bytes.
- `verify` links compiled source objects and marks files matching only when
  the linked result equals retail byte for byte.

`--workers` sets how many candidate batches are evaluated at once, each in its
own copy of the project. Workers pull from a shared queue, and fresh runs keep
enough independent batches available to avoid waiting behind one slow linker.
Evidence lands in
`build/dtk-migrate/runs/<id>/`, and `--resume <id>` continues an interrupted run
without redoing finished work.

See [runs](docs/runs.md) for the run directory, isolation and resource guidance,
and [coverage](docs/coverage.md) for what each stage will and will not accept.
The current performance investigation has a [continuation handoff](docs/performance-handoff.md).

## Matching two versions directly

```sh
dtk-migrate match config/GM8E01_00/config.yml config/GM8P01_00/config.yml \
    -r renames.txt --candidates candidates.txt
dtk-migrate symbols rename config/GM8P01_00/symbols.txt renames.txt
```

`--renames` carries only matches safe to apply unreviewed; everything else goes
to `--candidates` with its alternatives, for a person to judge. `--identifications`
writes the complete source-independent TU inventory, including tentative and
blocked hypotheses. It reads the two binaries and their metadata; compiled
source objects and buildable source files are not required. `--splits`
proposes split boundaries in `splits.txt` syntax, which `splits merge` folds in.
See [matching](docs/matching.md).

## Naming symbols from compiled objects

```sh
dtk-migrate derive --project-root ../prime --target GM8P01_00 --reference GM8E01_00
```

Compares compiled source objects with extracted target objects. With
`--reference`, it also evaluates names proposed by the binary matcher using
objdiff, including functions without target splits. Compiled target-version
source objects provide an additional comparison when available. Ambiguous
results and disagreements stay in the report. See
[symbol derivation](docs/symbol_derivation.md).

## Other commands

- `dtk-migrate audit` — splits that already exist and are probably wrong, which
  is the blind spot every stage shares
- `dtk-migrate calibrate` — scores the coverage policy against a version that
  already has the answers, with those answers hidden while it decides

## Building

`cargo test` runs the suite. Two integration tests need more than the crate:
`tests/pipeline.rs` drives the real binary against a fixture project and needs
Python and Ninja, and `tests/real_project.rs` checks the project readers against
a real checkout when `DTK_MIGRATE_TEST_PROJECT` points at one.

This depends on a decomp-toolkit branch that exposes its analysis as a library.
To build against a local checkout instead of fetching it, add a
`.cargo/config.toml`:

```toml
[patch."https://github.com/henriquegemignani/decomp-toolkit"]
decomp-toolkit = { path = "../../decomp-toolkit" }
```

That override makes cargo rewrite one line of `Cargo.lock`, dropping the pinned
git revision. Do not commit that line.
