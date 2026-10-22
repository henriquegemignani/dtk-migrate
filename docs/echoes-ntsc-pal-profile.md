# Where the time goes: Echoes G2ME01 → G2MP01 (profile of one run)

One `dtk-migrate run --source G2ME01 --target G2MP01 --stages all` on Echoes
`origin/main` (`ea46ebbac`), run id `20748-142434`, release-like dev build of
dtk-migrate built into this worktree's own `target/`. Defaults: 6 workers,
4 Ninja jobs each, 60 s candidate timeout, batch size 40, derive tier `probable`.
Host: 24 logical CPUs, 15–16 GB free RAM, F: drive.

**Wall clock: 17 min 52 s (1072 s).** Raw data:
`artifacts/collected/echoes.stderr.log` (RUST_LOG=info) and
`artifacts/collected/echoes-ntsc-pal-resources.csv` (4–5 s samples, unusable
before ~70 s into the run), plus the run directory's `result.json` and
`! timing` lines in every `build.log`.

## Read this first: this run did almost no migration

`origin/main` already holds a converged PAL migration. Every stage offered a
handful of candidates and **accepted none**:

| stage | offered | accepted | deferred |
|---|---:|---:|---:|
| derive | 2 | 0 | 2 |
| coverage | 2 | 0 | 2 |
| discover | 9 | 0 | 9 |
| verify | 5 | 0 | 5 |

The published DOL and all config files are unchanged (`git status` clean).
So the 17m52s is the **fixed cost of the pipeline**, a floor. A run that starts
from an unmigrated PAL state (thousands of accepted candidates, bisection,
rediscovery; see `echoes-pal-findings.md`) will add trial and integration
time on top of everything below. I did not measure that case.

## Per-stage wall time

| stage | total | preparation | workers | integration | other |
|---|---:|---:|---:|---:|---:|
| (startup, freezing tools) | 2 s | | | | |
| derive | 201 s | 133 s | 0 s (skipped by design) | 68 s | |
| coverage | 291 s | 150 s | 116 s | 24 s | |
| discover | 314 s | 148 s | 137 s | 29 s | |
| verify | 170 s | 111 s | 40 s | 19 s | |
| owner validation + publish | 94 s | | | | |
| **sum** | **1072 s** | **542 s (51%)** | **293 s (27%)** | **140 s (13%)** | 96 s (9%) |

Stage timestamps: derive done at 204 s, coverage 494 s, discover 809 s,
verify 979 s, end 1072 s.

## What the time is actually spent on

### 1. A from-scratch compile of the baseline, five times (≈ 433 s, 40% of wall)

Every stage's preparation freezes the current project and builds it cold:
`ninja build/G2MP01/ok` compiles **all ~760 MWCC objects** then links, hashes
and checks; then `ninja report.json` compiles ~205 more objects and runs
objdiff's report. Owner validation at the end does the same again.

| where | `ninja ok` | `ninja report.json` |
|---|---:|---:|
| derive preparation | 57.3 s | 34.3 s |
| coverage preparation | 53.1 s | 31.8 s |
| discover preparation | 52.7 s (+7.2 s second build) | 30.4 s (+0.6 s) |
| verify preparation | 56.3 s | 30.5 s |
| owner validation | 57.0 s | 29.6 s |
| **total** | **276 s** | **157 s** |

Nothing changed between stages (zero acceptances), so each of these five
builds produced the identical result. This is the largest single item and
the most obviously redundant one in this scenario. Even when stages do accept
changes, the compile inputs (source files, flags) are untouched by
split/symbol edits, so the object files could be carried into the next stage
rather than rebuilt.

### 2. Copying the project (≈ 150–200 s across preparations and integration)

Preparation minus its two cold builds and the coverage-evidence step leaves
about 25–45 s per stage for snapshotting the project, writing the manifest and
creating baseline/integration workspaces (each run directory baseline is
~240 MB; the run dir is 2.6 GB, of which `pool/` is 1.4 GB). Derive's 68 s of
"integration" is mostly this: its own log line reports only 22 s of ordered
integration after the 5 configure + trial builds (about 15 s), so roughly
45 s is workspace set-up. These are estimates by subtraction. No log line times
the copy directly.

### 3. Worker workspace resets dominate "worker time" (≈ 70–80% of 293 s)

Candidate trials themselves are cheap: `configure` 1.8–2.4 s, a trial
`ninja ok` link 1.2–8.7 s (failed trials stop early at ~1.2–1.9 s, real links
are 5–8 s), `report.json` 0.6–1.2 s. A whole 1-candidate batch is 10–25 s.
What dominates is getting a lane its private workspace:

| stage | lane resets (parallel) | breakdown of a first, contended reset |
|---|---|---|
| coverage | 58.3 s × 2 lanes | restore 23.2 s (3760 files / 66 MB) + build-cache seed 16.7 s (4472 files / 152 MB) + baseline verify 18.5 s |
| discover | 77.4 s × 4 lanes (first wave), 24.8–29.4 s × 5 (later) | restore 29.3 + cache 22.5 + baseline verify 25.6 |
| verify | 23.6–23.9 s × 5 lanes | baseline verify 22.7 (workspaces already warm: restore/cache 0) |

So worker wall time is "copy ~4,000–8,000 small files, then re-verify the
baseline", with the actual candidate builds being the minority. With 6 lanes
copying at once the same copy takes 2–3× longer than the 23–29 s a single lane
needs (discover: 77 s for the first four lanes versus ~29 s for later ones),
which points to file-system / Defender contention on thousands of small files
rather than CPU. Excluding `build/dtk-migrate` and `.git` from antivirus
(`Add-Exclusion.ps1` exists in the Echoes repo) was not tried.

### 4. Evidence analysis (≈ 40 s + 25 s)

dtk-migrate's own matching and coverage evidence is minor after the
optimized-dev build change: each of coverage and discover spends
~19–21 s (source analysis 1.2–1.3 s, target 1.2–1.4 s, matching 0.2–0.3 s,
object evidence 4.7 s, **report writing 11–13 s**). Tier-1/2 matching
(16,558 anchors; 16,715 of 16,725 functions matched) is a fraction of a
second per call. One-time load of the ownership observations in
discover: 12.3 s.

### 5. Coordinator-side single-threaded steps

Integration rounds are short when nothing is accepted: derive 22 s,
coverage 5 s, discover 5.7 s, verify 2.7 s. Final validation of the
published state (owner validation) costs the 94 s listed above and is another
cold build.

## Resource use during the run

CPU averaged only 22–36% per stage on 24 logical CPUs (overall mean 29%,
p90 55%, max 99% during cold compiles); disk queue length averaged
0.0–0.3 with spikes to 7–8 during copy phases; free RAM never fell below
12.8 GB. The machine was never CPU-, memory- or disk-bandwidth-bound; the
long stretches are serial (one cold build with `-j4`, a single copy) or
small-file-latency bound.

| stage | CPU avg | CPU p90 | disk queue avg / max |
|---|---:|---:|---:|
| derive | 22.9% | 42% | 0.29 / 8 |
| coverage | 21.6% | 34% | 0.02 / 1 |
| discover | 35.6% | 55% | 0.34 / 7 |
| verify | 34.6% | 50% | 0.06 / 2 |
| owner validation + publish | 41.4% | 69% | 0.00 / 0 |

## Where to look for savings (ordered by size in this run)

1. **Reuse the compiled baseline objects across stages and into owner
   validation** instead of 5 cold compiles of 760 + 205 objects: up to ~430 s
   here (≈ 40%).
2. **Run the cold baseline build with more than `-j4`** when it is the only
   thing running (preparation, owner validation): the host sat at ~20% CPU
   while it ran.
3. **Cheaper workspace resets**: seed workers from one shared warm copy,
   avoid re-running "baseline verify" (18–28 s per lane) when the baseline
   digest is unchanged, and measure the 2–3× contention penalty against an
   antivirus exclusion. Worth up to ~200 s of the 293 s worker time.
4. **Snapshot/manifest copy time** (~25–45 s per stage) is not logged
   separately; add a timing line before optimizing it.
5. Skipping stages with no eligible work would not help much by itself
   (derive still cost 201 s for 2 candidates): the cost is per-stage set-up,
   not per-candidate.

## Reproducing

```bash
CARGO_TARGET_DIR=$PWD/target cargo build
RUST_LOG=info ./target/debug/dtk-migrate run \
  --project-root F:/programming/claude-worktrees/echoes/migration-profile-ntsc-pal \
  --source G2ME01 --target G2MP01 --stages all
```

The Echoes worktree needs `orig/G2ME01`, `orig/G2MP01`, `build/compilers` and
`build/tools` copied in, `git submodule update --init extern/musyx`, and a
`configure.py -v G2MP01` + `ninja` baseline. Revert any
`config/G2MP01/splits.txt` normalisation that build leaves behind before the run.

## After the changes

Same Echoes project and command, each row adds one change. Wall clock from the
shell's `time`; stage times from the stages' `result.json`.

| run | change | total | derive | coverage | discover | verify | final validation |
|---|---|---:|---:|---:|---:|---:|---:|
| `20748-142434` | none (above) | 1072 s | 201 | 291 | 314 | 170 | 94 |
| `20748-150557` | later stages' baselines and final validation start from the previous stage's outputs; parallel copies; stat-cached baseline checks | 498 s | 139 | 145 | 150 | 51 | 12 |
| `20748-151846` | path-safety checks cached per directory | 366 s | 123 | 111 | 100 | 24 | 6 |
| `20748-153819` | tool paths spelled as the owner's build spells them (compilers reached through a junction), so the checkout's own build warms derive's baseline | 306 s | 53 | 117 | 103 | 25 | 6 |

(A run in between, `20748-152913`, took 7m26s: the junction was created with
mixed path separators, `mklink` refused it, and derive and final validation
fell back to cold builds. It is not a measurement of the idea.)

What each change fixed:

- **Cold baselines.** Coverage, discover and verify now seed their baseline from
  the previous stage's integration workspace, and final validation adopts those
  outputs into the checkout. Their `ninja ok` went from ~55 s to 0.1 s and the
  report from ~31 s to 0.5 s.
- **Copies were not slow, the checks around them were.** robocopy copies the
  4,469-file build directory in 1.0 s (32 threads) or 2.8 s (one). The tool took
  9–22 s because `safe_path` re-checked every parent directory of every file for
  links (~30 metadata calls per file). Remembering directories that passed took
  the baseline seed from 8.8 s to 1.3 s and a fresh worker from 42 s to 8 s.
- **Importing the checkout's build.** Ninja treats a changed command line as
  stale, and the workers spelled `build\compilers\...` as an absolute path where
  the owner's graph used a relative one, so none of the owner's 964 objects
  counted. Workers now get `build/compilers` as a junction to the shared
  compilers (snapshots skip that directory, so it is never copied or hashed) and
  the same relative tool paths a plain `configure.py` uses. Derive's baseline
  then needed zero compiles: `ninja ok` 4.1 s and report 0.5 s, against 51 s and
  29 s cold. The import is skipped unless the checkout's `.ninja_log` is newer
  than every file in the shared compilers. Ninja still decides what is stale, and
  the baseline's retail hash and report are measured as usual.

- **`--portable-build-ninja`.** When the project's `configure.py` offers it,
  every trial, integration and final-validation configure now passes it. Without
  it the graph records absolute header paths in `.ninja_deps`, so outputs seeded
  from another directory were tracked against the donor's headers rather than
  the workspace's. With it the graph is relocatable, so seeding is sound as well
  as fast. The owner's build is only reused if it was configured the same way
  (`python configure.py --portable-build-ninja ...`); otherwise its commands
  differ and derive builds cold. A run with a portable
  owner build: 299 s, zero compiles in derive's baseline and in final validation.
  The ordinary graph is still restored for the owner afterwards.

If the checkout has no usable build, derive pays one cold build (about 80 s
here), which is the budgeted baseline.

### What the remaining 305 s is

Timestamps from `DTK_MIGRATE_LOG_TIME=1` (run `20748-154502`, 304 s):

| phase | seconds |
|---|---:|
| start-up, snapshot, derive baseline (seed 1.4, configure, 4 s link/hash, 0.5 s report) | 17 |
| derive matching and candidate selection | 14 |
| derive integration (5 configure + trial builds of 2 candidates) | 24 |
| coverage evidence: matching 4.5, report 11, then 27 s of post-processing | 42 |
| coverage workers (2 candidates, 3–4 trial builds, lane set-up 4.6) | 64 |
| discover evidence: matching 3.5, report 11, then 21 s of post-processing | 36 |
| discover: load observations 8.7, lane set-up up to 8, 9 one-candidate batches | 59 |
| verify (5 one-candidate batches) | 22 |
| final validation | 8 |
| other (per-stage baseline seed, configure, integration resets) | ~19 |

None of it is a baseline build. About 80 s is evidence computed three times for a
project that did not change between stages (matching and the coverage report are
identical in the coverage and discover logs), and the 21–27 s after each
"Coverage evidence time" line is the ownership-observation artifact being
serialised and compressed. About 170 s is candidate trials, mostly failed
builds of 2–9 s each plus a `configure.py` of 1.7–2.4 s per trial.

Next candidates, not done: cache matching and coverage evidence by the stage's
input fingerprint when the previous stage accepted nothing; skip the repeated
`configure.py` when a trial changes no configure input; use fewer lanes when
batches are single candidates.

## Second pass: the remaining work, measured and trimmed

With `DTK_MIGRATE_LOG_TIME=1` and per-phase "took" lines in each stage's
`prepare`, the 299 s run broke down as follows (seconds, run `20748-155542`
and the following runs; owner build configured with `--portable-build-ninja`):

| phase | before | after |
|---|---:|---:|
| coverage `alternatives` loop (per source unit, independent) | 20.3 | 2.7 |
| coverage workers: each trial re-read and re-parsed the 150 MB observation report (~8–12 s per trial) | 58–66 | 35 |
| discover workers: the same report parsed a second time after prepare had just built it | ~8 | 0 |
| discover: coverage evidence written as pretty JSON and parsed back | (not separable) | taken from memory |
| **whole run** | **299** | **253–257** |

What changed: the alternatives loop runs on rayon; observation indexes are
shared by every lane of the process (and handed over from the prepare step that
built them) instead of reloaded per trial; discover takes the matcher's coverage
report from memory. The remaining wall time, 253 s:

| phase | seconds |
|---|---:|
| derive: baseline check 6.7, `derive::derive` 18.5, 2-candidate integration ~24 | ~55 |
| coverage: evidence 18.5 (report building 11), validate 7.3, workers 35, integration 5 | ~70 |
| discover: matcher 18, rename batch 3.6 + rebuild 9, load evidence 7.4, workers ~55 | ~95 |
| verify: 5 one-candidate batches | ~25 |
| final validation and start-up | ~10 |

What is left is either real trial work (each trial is a `configure.py` of 1.8–2.9 s
plus a split/link/hash of 5–9 s; about 140 s in total across the stages) or
single-threaded analysis that is computed twice because coverage and discover
each run the matcher (18 s each) and each validate the same 150 MB observation
report (7 s each). Further cuts need that analysis shared between stages, or
split inside (`build_coverage_report` is ~11 s of one thread; so is
`derive::derive`'s ~18 s), which is more than an easy change.

`tests/historical_recall.rs::the_fixture_is_readable_project_data_rather_than_a_saved_verdict`
fails in this worktree because `tests/fixtures/ownership/baseline.splits.txt` is
LF in the index and CRLF on disk (autocrlf), so its SHA-256 differs; it is
unrelated to these changes.

## Traced run on latest main (243 s)

Echoes at `origin/main` (7319a60ce), `configure.py --portable-build-ninja
--no-compile-commands`, both baselines built first (NTSC 82 s, PAL 65 s). One full
NTSC → PAL run under `DTK_MIGRATE_PROFILE` (stack sampler at ~9 Hz effective, every
thread, plus a span per child process and per phase): 243 s wall, 239–243 s across
three runs. Every sampled interval is counted once, in this priority: a child process
running → named analysis category → deepest project frame → idle.

| wall seconds | share | what |
|---:|---:|---|
| 57.8 | 23.8% | ninja in worker workspaces (62 invocations, 181 s summed over 6 lanes) |
| 46.2 | 19.0% | `ObservationIndex` load/validate, single-threaded, 4 loads of 9–12 s each |
| 30.7 | 12.7% | matcher outside its index load (coverage and discover each run it) |
| 27.0 | 11.1% | workspace reset/copy (`safe_path`, snapshot, build cache seeding) |
| 21.8 | 9.0% | derive scoring (`objdiff` diff of compiled units) |
| 15.1 | 6.2% | no thread running project code (waiting on pipes/process start) |
| 13.5 / 13.3 / 3.8 | 5.6 / 5.5 / 1.6% | ninja in integration / baseline / owner workspaces |
| 1.9 | 0.8% | alternatives |

Per trial (4 measured): `ninja` 5.4–5.9 s = `dtk split` 2.4 + `configure.py`
regeneration by ninja ~0.5 + link ~2.3. The extra `configure.py` run before each trial
is gone, and `compile_commands.json` is skipped inside dtk-migrate's own configure runs.

Inline-aware sampling of the load shows the hot line: `parse_hex`
(`src/analysis/ownership.rs`) calls `trim_start_matches("0x")` with a string pattern,
which builds a two-way string searcher on every call (twice per call, 87 call
sites). It is the leaf of 15.8 thread-seconds under the load and 9.0 under the
matcher. `safe_path`'s remaining cost is mutex contention on the validated-directory
set plus `Path` component parsing.

After replacing the `trim_start_matches("0x")` calls with a byte-prefix strip
(`parse_hex` and the coverage analysis) and making the validated-directory set a
`RwLock` with one lookup per directory, the same run takes 190 s (was 243 s):
coverage evidence generation 29.9 → 15.1 s, validation 12.3 → 5.3 s, the discover
matcher 27.4 → 16.3 s, discover's evidence load 11.6 → 5.7 s. The stack samples of that
run were not written (the sampler produced an empty file; not yet explained), so its
wall-clock partition is not available.
