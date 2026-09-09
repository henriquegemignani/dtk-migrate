# Isolated migration execution

The runner supports local Windows execution. All processes use explicit roots;
the coordinator never changes its working directory. Separate processes remain
necessary under Python 3.14t because DTK and generated build files have mutable
process and checkout state.

## Execution and evidence

`parallel_migration.py` snapshots current project files rather than committed
HEAD. Source, configuration, relevant untracked files, populated submodules,
retail inputs, compiler tools, Ninja, DTK, scripts, and interpreter identity are
fingerprinted. Generated reports and build state are private. User objdiff symbol
mappings are retained separately from generated object paths. Inputs cannot be
symlinks or junctions. No mutable files are hard-linked between workers.

The generated Ninja split rule uses DTK's `--no-update` and bounded `-j` flags.
`migration_configure.py` preserves those flags when Ninja regenerates its rules;
it does not edit the project's configure script or build helper sources.

Coverage preparation generates independent exact-body and corroborated `this`-layout
ownership evidence without applying symbol renames. Discovery preparation then runs matching and confident
renames once. Every batch starts from the same prepared baseline. With `--stage
all`, source verification starts only after coverage and discovery integration
have produced the next baselines. A single project lock
prevents multiple migration pools from competing for the checkout.

Each job records its baseline fingerprint, candidate list, accepted/deferred
changes, command log, report, retail hash, and duration. Results are reduced in
candidate order, never completion order. The coordinator rebuilds combined
changes, bisects conflicts, and retries deferred candidates after progress.
Coverage requires bounded ownership evidence, extracted linker inputs, no existing
regression, and retail integrity; it does not require objdiff code gain. Discovery
requires code gain without per-unit regression plus retail integrity; source
verification also requires compiled objects in the linker dependency graph.

Publication accepts only target splits, target symbols, and `configure.py` changes.
It checks the owner fingerprint, journals original/new bytes, replaces inputs,
and regenerates the owner's report. A failed build restores only bytes still owned
by publication, preserving intervening user edits. A crash releases the OS lock;
`--resume` recovers a partial publication and reuses only matching completed jobs.

## Resource settings and benchmarking

The default is three worker processes and four Ninja jobs per worker on
the development host (24 logical CPUs, 48 GiB RAM). Native thread pools are bounded
to the same per-worker job limit. Disk preflight includes copies and build headroom.
Both stages keep their artifacts for inspection and resume, so long runs consume
additional disk. `--ninja` accepts a portable executable; the default resolves
Chocolatey's launcher to the real binary before freezing it.

Replay a prepared stage without publishing:

```sh
uv run src/benchmark_parallel.py --run-dir F:/programming/decomp/prime/build/parallel-migration/runs/RUN_ID --stage discover --repetitions 3
```

Use `F:/programming/decomp/prime` for future benchmark inputs and artifacts. The
paths in the measured sections below describe historical runs and remain relative
to the checkout used for those runs.

Use `--stage coverage` to replay a prepared coverage candidate set. Coverage
equality includes the selected alternative IDs and complete final report hash.
For the required one-worker/three-worker correctness replay without collecting
warm performance samples, add `--cold-only --repetitions 1`.

The benchmark uses identical inputs and candidate partitions for one and three
workers, alternates their order, and requires identical integrated decisions,
measures, and retail hashes. Cold samples use fresh worker directories; warm
samples retain caches but rerun every job. It records medians, integration time,
verified candidates per minute, and disk usage. Measurements include private
pool setup/reset, compilation, and union integration; matcher preparation and
owner publication are excluded and must be considered for full-run latency.

Do not assume three workers are faster for a small or mostly rejected candidate
set. Use `--workers 1` when measured warm throughput does not improve.
Reduce `--batch-size` for small candidate sets if you want multiple workers busy;
three candidates with the default batch size of forty form only one job. Keep
batch size fixed when comparing worker counts.

### Measured Prime replay

On 2026-09-09, a three-candidate discovery replay with batch size one and four
Ninja jobs per worker produced these medians across three repetitions:

| Private replay | One worker | Three workers |
|---|---:|---:|
| Fresh worker and integration directories | 306 s | 288 s |
| Retained caches, all jobs rerun | 164 s | 111 s |

Three workers were **1.49× faster on the warm replay**, supporting the default of
three workers and four build jobs each. Serial integration accounted for about
72 seconds of each warm sample. This is a small discovery workload, not a speedup
guarantee for every batch size or game.

All twelve samples agreed on decisions and retail hash. All 36 saved worker
reports and six final integration reports had identical complete-report hashes.
The sampled candidates were deferred, so accepted candidates per minute was zero
in both modes. The replay artifacts occupied approximately 7.8 GiB, including the
shared benchmark toolchain and excluding the original prepared run.

Evidence: Prime's
`build/parallel-migration/benchmarks/20260909T085824.747819Z/result.json`.
The benchmark now compares complete-report hashes as well as aggregate measures,
so a per-unit difference cannot be hidden by equal totals.

### Layout-shift coverage validation

Policy version 2 was calibrated against the named PAL target with target names and
ownership hidden during proposal generation and the pre-feature split file supplied
as an independent oracle. Across the deterministic calibration and held-out
partitions, all 813 layout-shift anchors with known ownership pointed to the correct
source TU. Another 118 anchors landed in unlabeled portions of partial PAL splits
and remain unknown; none landed in a different explicit TU. All 49 group ranges
with complete known ownership were correct; another 44 remain unknown.

The subsequent 35-candidate PAL run accepted 16 layout-group ranges totaling
30,056 bytes. Representation rose from 747 to 763 of 822 source TUs. The combined
run retained retail DOL SHA-1
`4d3780c77842ae7fddbdd5732b70bed100df5c65`; configured source linkage remained
176,844 bytes because coverage keeps source objects disabled. Evidence is under
`build/parallel-migration/runs/20260909T204906.906167Z/` in the F: checkout.

### Measured coverage replay

The first complete PAL coverage run prepared 30 candidate TUs with batch size one.
For correctness acceptance, the same frozen baseline and candidate bundles were
replayed once with a fresh one-worker pool and once with a fresh three-worker pool:

| Fresh coverage replay | Seconds |
|---|---:|
| One worker | 2,127.10 |
| Three workers | 1,581.54 |

Three workers were **1.35× faster** across worker evaluation plus canonical union
integration. This is a single cold equivalence replay rather than a performance
benchmark with warm repetitions. Both samples accepted the same 13 TUs, selected
the same exact alternative IDs, produced the same complete-report SHA-256
`7bd0e84e1b9116ffffb74a7b4cd642c69b0a73591c1171455a8ca9d642a98a78`, and kept
the retail DOL SHA-1 `4d3780c77842ae7fddbdd5732b70bed100df5c65`.

Evidence: Prime's
`build/parallel-migration/benchmarks/20260909T151934.581608Z/result.json`. The two
fresh pools and integrations occupy approximately 3.03 GiB.

## Parallel development and PAL investigations

Define shared interfaces before distributing changes. Use separate checkouts and
test files: one agent owns snapshot/process support, one owns discovery, and one
owns source verification. The coordinator owns scheduling, integration, tests,
and review. `BuildContext` supplies paths and resource limits; adapters expose
`prepare(context, limit)` and `evaluate(context, candidates)`, and source
verification additionally exposes `validate(context, names)`.

Use one shared worker pool for PAL data/relocation attribution, whole-file section
boundaries, and undefined-symbol investigations. Each DTK experiment must have a
separate build output and a fingerprinted executable. Integrate tooling first,
then revalidate game proposals under the combined tool revision. Keep `_02` as
secondary calibration. Distributed workers and in-process DTK parallelization
are outside this implementation.

Run all checks with `uv run python -m unittest -v`. The suite covers configuration
editing, real process isolation and cancellation, crash recovery, deterministic
integration, baseline drift, and guarded publication rollback.
