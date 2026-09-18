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
| **Split coverage** | a target range is assigned to a source file | that the file compiles, or matches |
| **Objdiff matched code** | bytes in functions a comparison calls matching | that the file is finished |
| **Configured source linkage** | the file is enabled in `configure.py` | anything measured; it is a build setting |
| **Verified source linkage** | the compiled object is a real linker input **and** the result equals retail | — this is the only whole-file proof |

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

Stages run in a fixed order — `derive`, `coverage`, `discover`, `verify` — and
`--stages` selects which of them to run. `--workers` sets how many candidate
batches are evaluated at once, each in its own copy of the project. Evidence
lands in `build/dtk-migrate/runs/<id>/`, and `--resume <id>` continues an
interrupted run without redoing finished work.

See [runs](docs/runs.md) for the run directory, isolation and resource guidance,
and [coverage](docs/coverage.md) for what each stage will and will not accept.

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

Compares each unit's compiled source object with the object extracted from the
target binary. Both already exist after a build, so this costs seconds. It is a
different signal from `match`, which compares two binaries: here the source
object states what the unit is *supposed* to contain. See
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
