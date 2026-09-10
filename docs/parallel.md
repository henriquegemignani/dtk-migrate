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

Coverage preparation generates independent exact-body, corroborated `this`-layout,
and boundary-constrained sequence ownership evidence without applying symbol
renames. Discovery preparation then runs matching and confident
renames once. Every batch starts from the same prepared baseline. With `--stage
all`, source verification starts only after coverage and discovery integration
have produced the next baselines. A single project lock
prevents multiple migration pools from competing for the checkout.

Each job records its baseline fingerprint, candidate list, accepted/deferred
changes, command log, report, retail hash, and duration. Results are reduced in
candidate order, never completion order. The coordinator rebuilds combined
changes, bisects conflicts, and retries deferred candidates only after an
accepted change creates a new baseline. It reuses the adapter's validated final
report instead of performing a duplicate final link.
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

Candidate builds use a 120-second timeout by default. The timeout starts only
after the private workspace has a prepared baseline, so a legitimate cold build
is not bounded by the trial limit. Override it with `--build-timeout SECONDS` for
unusually large incremental links. A timeout kills the complete compiler/linker
process tree and enters the normal bisection or deferred-candidate path.

Use the stage and total timings in `result.json` for migration measurements.
System-wide ETW capture is intentionally excluded from future runs: a full
GeneralProfile trace consumed 36.3 GB, took several minutes to flush and copy,
and still lost events.

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
batch size fixed when comparing worker counts. Avoid `--batch-size 1` for a full
migration: the adapters already bisect rejected groups, while singleton batches
force a configure and link cycle for every candidate.

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

### Boundary-sequence coverage validation

Policy version 4 can fill a single target `.text` gap between the same two explicit
neighboring TUs found around a source TU. DTK solves a maximum-cardinality monotone
alignment inside that gap using its selected function matches and their reported
runner-ups. Automatic eligibility requires at least four aligned functions, 75%
source-function coverage, 90% order preservation, 512 aligned bytes, 40% target-gap
coverage, two strong matches, two unique exact-body anchors, and a 10% margin
over a same-cardinality competing alignment. A range is rejected if the best chain
uses a runner-up, overlaps another explicit unit, is misaligned, or differs from the
source text size by more than the bounded ratio.

An eligible sequence can also carry required top-level asset extraction entries. DTK
derives them from strict, positionally aligned data references in the selected function
pairs. The runner preserves the target symbol extent, uses `rename` for the source output
symbol, and treats `config.yml` and `splits.txt` as one transaction. Generated binary,
header, and relocation outputs are checked before acceptance.

The `GM8E01_00` to `GM8E01_02` leave-one-out calibration produced 42 calibration
and 38 held-out boundary ranges. All 80 stayed inside the correct target TU; their
1,088 aligned function anchors also had no cross-unit attribution. Evidence is in
`build/GM8E01_02/boundary-sequence-calibration/` in the F: Prime checkout.

For PAL, `CGameProjectile.cpp` aligned 25 of 28 source functions monotonically:
9 strong matches, 2 unique exact-body anchors, and 9,396 aligned function bytes covered 82.2%
of the neighbor-bounded gap. Run `20260909T232431.370448Z` accepted the complete
`.text 0x80038EAC..0x8003BB50` range (11,428 bytes). Representation rose from 781
to 782 of 822 source TUs, objdiff-matched code rose from 1,306,876 to 1,307,156
bytes (33.441055%), source-linked code remained 176,844 bytes, and the retail DOL
SHA-1 remained `4d3780c77842ae7fddbdd5732b70bed100df5c65`.

### Layout-corroborated boundary validation

Policy version 5 generalizes the layout transform to two arbitrary constant deltas
separated by at most one member-offset breakpoint. A group can corroborate the
complete gap between the same two explicit neighboring TUs when it contains at
least four unique functions, 1,024 instruction bytes, and 16 changed `this` accesses.
The bounded source and target text sizes must be within 2%, their function counts
must differ by at most one, and every layout anchor must preserve source and target
order. This path assigns the target range but does not use the weaker function
alignment for symbol renames or data extraction.

The porting adapter independently rechecks the group totals, transform, ordering,
gap bounds, size and function-count limits, existing ownership, and alignment before
starting the normal isolated build, no-regression, extracted-input, and retail-byte
validation.

### Vtable-corroborated boundary validation

Policy version 6 handles a narrow compiler transformation in which the target moves
part of one source function into a local helper. The normal sequence still must align
at least eight primary functions monotonically and cover 85% of the source functions
and target bytes. Source and target function counts may differ by one and their text
sizes by at most 3%. The candidate must own a unique source vtable whose uniquely
paired target object agrees at every matchable function slot, with at least eight
matched slots overall and four slots from the candidate TU. Every unmatched target
function must be a single helper inside the bounded gap, have no callers outside the
gap, and be called by an aligned function. The adapter independently reconstructs and
checks these relationships from the serialized evidence.

For PAL `CShockWave.cpp`, 9 of 10 functions align over 4,208 bytes, or 97.1% of the
4,332-byte target gap. Its source and target vtables agree in all 24 matchable slots;
seven slots point to aligned `CShockWave` functions. The one unmatched 124-byte target
helper is called only by the aligned constructor. The independent ownership oracle
scores the complete range and all nine aligned function anchors as correct.

Run `20260910T123136.416946Z` accepted
`.text 0x80221D1C..0x80222E08`. Representation rose from 787 to 788 of 823 source
TUs. Objdiff-matched and source-linked code stayed at 1,361,884 and 177,036 bytes,
respectively, because the source object remains disabled. The final DOL SHA-1 stayed
`4d3780c77842ae7fddbdd5732b70bed100df5c65`.

### Ownership-transition boundary validation

Policy version 7 can recover a candidate when an adjacent represented TU has a stale
boundary inside the neighbor-bounded gap. DTK accepts only a complete sequence of at
least eight source functions mapped to one contiguous target span in strict primary
order, with at least two strong matches, a 10% alignment margin, and no more than 2%
text-size drift. The part trimmed from either edge must itself be a contiguous set of
functions mapped to the stated previous or next source TU, with at least one strong
match on every nonempty edge. At least one edge must be trimmed.

The runner recomputes all counts, spans, order, size drift, and edge coverage from the
serialized function evidence. A focused `--only` run retains the names of other
proposed candidates in `eligible_excluded_by_only` in its JSON and Markdown reports.
This distinguishes a candidate excluded by the operator's filter from one rejected by
the evidence policy.

### Adjacent-owner transition validation

Policy version 8 handles the stricter case in which the candidate's complete target
sequence occupies a prefix or suffix already assigned to its immediate source-order
neighbor. The candidate must align every source function to one contiguous target
span, with at least eight functions, two strong matches, two direct exact-body anchors,
and no more than 10% source/target size drift. The retained portion of the adjacent
owner must independently align every source function, with at least four functions,
two strong matches, no more than 10% size drift, and at most one target-only helper
whose callers all lie in that owner.

The evidence names the owner's exact current and revised ranges. The adapter verifies
the source adjacency, owner identity, full sequences, counts, anchors, helper callers,
size bounds, and prefix/suffix geometry from the serialized inventories. Candidate
insertion and owner revision are one operation in worker trials, integration,
publication, rollback, and final-state validation.

Masked-name `GM8E01_02` calibration scored all 430 calibration and 463 held-out ranges
correct, with no unknown or incorrect ranges. PAL calibration scored 3,610 ranges
correct and 308 unknown, with none incorrect. The all-pending PAL evaluation contained
34 unrepresented TUs and made only `MetroidPrime/CFluidPlane.cpp` eligible under the
new rule.

The unfiltered stage-all run `20260910T165851.040686Z` used three workers, four Ninja
jobs each, batch size 40, and no candidate filter. Coverage accepted `CFluidPlane` as
`.text 0x80125CC0..0x801263CC` and atomically moved the start of
`CFluidPlaneManager` from `0x80125CC4` to `0x801263CC`. Discovery accepted none of
its 29 candidates, and source verification accepted none of its 94 candidates. Split
representation rose from 789 to 790 of 823 source TUs; matched code rose by 716 bytes
to 1,363,208 bytes (34.87504%), while source-linked code stayed at 177,036 bytes
(4.5291233%). The final DOL SHA-1 remained
`4d3780c77842ae7fddbdd5732b70bed100df5c65`.

The run took 1,390.09 seconds: 365.95 seconds for coverage, 285.15 for discovery,
and 664.17 for source verification. Its frozen inputs, candidate evidence, job logs,
publication journal, final report, and ordinary timings are retained under
`build/parallel-migration/runs/20260910T165851.040686Z/` in the F: checkout.

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
