# Migration performance: continuation for a separate agent

Continue the performance work in `F:\programming\decomp\dtk-version-matching`.
The objective is a complete Prime `GM8E01_00` → `GM8J01_00` migration in under
30 minutes, or measured evidence that available system resources impose a
higher floor. That objective has **not** been reached. Do not infer a resource
limit from the current runs: the machine was not continuously CPU, disk, or
memory bound. Keep migration experiments and their project copies on `F:`;
the user's `C:` drive has insufficient space and must not be used for them.

The user asked to **minimize full benchmarks**. Do targeted diagnostics and
tests first. When a full migration is justified, start it, then wait for the
process to finish without frequent progress checks or analysis during the run.
Analyze its saved logs and artifacts afterward. Do not lower the standard of
proof: candidate changes still need a retail link/hash build, and the user's
60-second maximum trial timeout remains in force. The user's goal is end-to-end
time, not just faster individual linker calls.

## Repository state

The performance code is at `8fe64eb`; `98d31e9` added this handoff document.
The commits leading to that code are:

| Commit | Change |
| --- | --- |
| `d474a72` | Trial timing, bounded builds, optimized analysis path, initial parallel scheduling |
| `8a52f33` | Batch coverage trials; skip redundant derivation workers |
| `a83c35a` | Reuse coverage observations during adaptive trials |
| `f1ba776` | Parallelize verification retry subtrees |
| `93df3ea` | Parallelize discovery retry subtrees |
| `8fe64eb` | Seed private workers with validated baseline build outputs |

There were no uncommitted tracked changes at handoff. `.claude/` contains
untracked local settings; leave it alone. The six commits passed 604 unit tests,
the cascade, transactions, composed-stages, pipeline, real-project,
historical-recall, verify-parallel, and discover-parallel suites, plus nightly
formatting and Clippy. A fresh-worker test confirmed that build-cache seeding
avoids rebuilding the 17 baseline objects in its fixture. An attempted graph
reuse shortcut was removed after a cascade test showed it could miss split
changes; do not reintroduce it without preserving that behavior.

Read [`runs.md`](runs.md) before modifying the runner. Relevant code is
`src/run/jobs.rs` (batch sizing and workers), `src/run/mod.rs` (integration and
rediscovery), `src/workspace/mod.rs` (snapshot/reset/cache),
`src/stages/coverage/mod.rs` (adaptive proof), and `src/build/process.rs`
(timeout and process-tree handling). Preserve deterministic coordinator order,
private worker workspaces, resume identity, and final retail-hash validation.

## Reproducible benchmark evidence

All three full migrations used Prime base commit
`ca286f453d30c201304a82939fa8929181cc9d30`, 60-second candidate timeout,
and Ninja `-j 2` per worker. All published the same retail DOL SHA-1,
`f7fc8f599c8632aafe543cb071eef6df45e4a886`, with 1,661 derive, 401
coverage, 180 discovery, and 18 verify acceptances. The two recent runs are
under the agent-owned benchmark checkout
`F:\programming\decomp\prime-migration-gm8j-optimized`:

| Run | dtk commit / workers | Derive | Coverage | Discover | Verify | Total |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `20718-100852` | `d474a72`, 12 | 596.5 s | 2697.8 s | 908.1 s | 1163.0 s | 91.6 min |
| `20718-123443` | through `93df3ea`, 12 | 220.4 s | 2556.4 s | 724.8 s | 536.8 s | 67.3 min |
| `20718-140420` | `8fe64eb`, 32 | 135.1 s | 2741.7 s | 941.2 s | 580.1 s | 73.3 min |

The first run is in
`F:\programming\decomp\prime-migration-gm8j-12w`. Stage `result.json`
files under each run directory contain `timing.preparation_seconds`,
`worker_seconds`, and `integration_seconds`. The latest 32-worker run's log and
resource samples are `artifacts/collected/gm8j-32w.stderr.log` and
`artifacts/collected/gm8j-32w-resources.csv` in this repository. The 12-worker run's
samples are `artifacts/collected/gm8j-optimized-2-resources.csv`. These archived files are
local artifacts, not committed fixtures; retain the run directories until the
investigation is finished. The benchmark checkout currently contains the
latest run's published edits, so restore only its known tracked migration
outputs before a fresh run; do not discard the run artifacts.

The 32-worker comparison changes **both** worker count and build-cache seeding,
so it does not isolate either effect. Still, it disproves the assumption that
more concurrent workers automatically improve throughput. Coverage scheduled
423 candidates in 118 batches. The first 32 workspace resets took about 135 s
each in parallel; later resets often took 20–40 s. Discovery scheduled 231
candidates in 116 batches. With 32 workers, coverage integration alone took
1,846 s; the 12-worker run spent 1,552 s there. Resource samples during the
32-worker coverage workers averaged about 61% CPU with an average F: disk queue
of 3.2 and at least 11.8 GB free RAM. Those samples do not prove a hard
hardware limit.

Repeated 60-second candidate timeouts are a likely source of wasted bisection.
Ninja and the process runner buffer command output, so the last printed edge
does not establish which child was running at the deadline. Keep the existing
run artifacts, but do not capture traces of future runs: they take too long and
too much disk space. The targeted process sampling below sufficed for this
case.

### Targeted timeout replay (2026-09-22)

The saved `coverage/jobs/00010/job.json` and `coverage/baseline` from run
`20718-140420` provided an exact narrow replay. In a disposable F-drive copy,
apply the job's accepted `CPlayerCameraBob.cpp` transaction, then the first
`OSRtc.c` alternative (`f096e448`, `.text 0x8036F604..0x803701C0`). Run the
frozen configure hook and `ninja -j 2 build/GM8J01_00/ok` with a 60-second
deadline. The replay timed out at 60.17 seconds. Process samples put `dtk.exe`
split at about 0.3–2.3 seconds, Python graph regeneration at 2.3–3.1 seconds,
and `mwldeppc.exe` link from 3.4 seconds through the deadline. The linker
accumulated 56.6 CPU seconds and was still active; neither split nor configure
was the stalled phase in this example.

Replacing that alternative with the job's accepted `OSRtc.c` range
(`8bfd6234`, `.text 0x8036F90C..0x8036FC70`) completed the same Ninja
link/DOL/check target in 6.67 seconds. Linker activity was about 3 seconds;
the DOL matched retail bytes and SHA-1
`f7fc8f599c8632aafe543cb071eef6df45e4a886`. A separate Ninja report
took 0.26 seconds. No source compilation was triggered by either transaction.
The replay script, process samples, and small logs are in
`artifacts/collected/timeout-diagnostic/`, ignored by Git. The disposable
project copy remains in `target/timeout-diagnostic/workspace/`. The saved coverage results
report five distinct timeout alternatives across the initial job and
rediscovery workers. Four produce the same full `OSRtc.c` range above, from
different starting boundaries. The fifth inserts `OSSync.c` at
`.text 0x803701C0..0x80370244`; replaying it after the job's three accepted
changes also timed out at 60.27 seconds. Split finished around 2.4 seconds, graph
regeneration around 3.2 seconds, and `mwldeppc.exe` ran through the deadline
with 56.6 CPU seconds. All five alternatives were rejected, and none was the
alternative selected for acceptance. Both distinct timeout patterns reproduced
in an isolated single-worker replay, so concurrent contention is not needed
to explain these coverage timeouts. The evidence does not quantify the savings
from changing trial order or rule out contention elsewhere.

### Targeted workspace reset measurements (2026-09-22)

`reset_workspace` now reports separate worker-manifest, baseline-verification,
and restoration times; build-cache seeding reports its copy time and volume.
The batch log includes these numbers and objdiff seeding in one compact line.
`examples/profile_workspace_reset.rs` reruns only these operations against a
saved baseline, without evaluating candidates or collecting traces.

The F-drive benchmark used `20718-140420/coverage/baseline` and its 2,203-entry
manifest. Each fresh worker restored 227.0 MB of inputs and seeded 97.6 MB of
generated output in 3,779 files. Results in seconds:

| Trial | Total | Worker manifest | Baseline verify | Restore | Cache seed |
| --- | ---: | ---: | ---: | ---: | ---: |
| One fresh worker | 20.36 | 0.00 | 5.28 | 7.65 | 7.43 |
| Same worker, unchanged | 6.23 | 0.46 | 5.77 | 0.00 | 0.00 |
| Same worker, one changed split file | 6.20 | 0.46 | 5.73 | 0.01 | 0.00 |
| Two fresh workers concurrently | 21.92 each | 0.00 | 5.92 | 8.34 | 7.65 |
| Three warm workers concurrently | 7.35 each | 0.52 | 6.82 | 0.00 | 0.00 |

The warm reset spends over 90% of its time verifying the same unchanged
baseline, even when it copies no inputs. Restoring the changed split file gave
it a fresh timestamp, and Ninja's dry run correctly scheduled `SPLIT` and
`RUN configure.py`. The 32-worker full run's roughly 135-second first resets
and 20–40-second later resets are much slower than these one-to-three-worker
measurements. Its old logs lack phase timings, so these experiments do not
isolate the high-concurrency slowdown or establish a resource floor. Many
simultaneous hash passes and private copies are a plausible cause; the new
per-phase log will distinguish them in a later comparable run.

## Next work

1. Reset profiling is complete at one-to-three-worker scale. Investigate
   whether a stage-owned immutable baseline can be verified once before its
   parallel jobs, rather than rehashed for every batch. Preserve validation
   across resume and external edits, and keep warm-workspace timestamp
   correctness. Use the new phase timings in a later comparable run to explain
   the 32-worker slowdown before claiming a hardware limit.
2. Timeout diagnosis is complete for the saved coverage examples: two distinct
   rejected transaction patterns are CPU-bound inside the linker even without
   competing workers. Examine candidate ordering and repeated broad `OSRtc.c`
   trials before changing the 60-second cap. Any shortcut must preserve the
   chance to accept valid coverage and still require a retail link/hash for
   accepted candidates. Do not collect another trace for this investigation.
3. Coverage scheduling version 5 moves retry and bisection decisions to the
   coordinator. Build lanes now receive fixed alternatives, mutate only their
   private workspace and return the result; failed union halves can occupy
   separate idle lanes. A fixture verifies the halves run in different lanes,
   and coordinator integration remains the ordered proof. This changes fresh
   run behavior, so resume compatibility is 6 and older runs retain their
   recorded scheduling version. The change has not had a full Prime benchmark;
   compare worker-tail and rediscovery-round time before claiming improvement.
4. The scheduling change passes all 604 library tests, every integration and
   example target, `cargo +nightly fmt --all -- --check`, and
   `cargo +nightly clippy --all-targets -- -D warnings`. The remaining
   performance proof is one complete F-drive migration at fixed settings
   against a comparable baseline. Wait for it to exit, then compare stage and
   command timing, accepted/deferred units, and retail hash. Do not claim the
   30-minute objective from a partial run.

The previous 12-worker settings, for a later justified comparison, were:

```powershell
cargo run -- run --project-root F:\programming\decomp\prime-migration-gm8j-optimized `
  --source GM8E01_00 --target GM8J01_00 --stages all `
  --workers 12 --build-jobs 2 --batch-size 40 --build-timeout 60
```

First confirm the benchmark checkout is at the recorded base and restore only
the tracked files published by the previous migration. Check `run.json` in the
saved runs for exact settings and tool hashes. The command starts a *new* full
run, so do not execute it merely to inspect the current artifacts.

This file is a handoff, not a new policy. Update or remove it as measurements
supersede the recorded hypotheses.

## Run storage reduction (2026-10-01)

New runs exclude `build/compilers` from every private workspace and pass the
owner's shared directory through `configure.py --compilers`. Compiler contents
are hashed separately at start/resume and before/after publication, not for
every worker job. Resume compatibility is now 8 because workspace manifests
have changed; existing run directories and evidence are retained.

Ownership observations now use streamed compact JSON with Zstandard level 3,
stored as `ownership-<digest>.json.zst`. Readers retain plain JSON support and
validate the same canonical report digest. A read-only compression check of
one retained Prime observation (run `20726-224231`) reduced 154,039,478 bytes
to 7,964,018 bytes (5.2% retained) with an exact decompression round trip, even
before removing JSON whitespace. This measures storage savings, not migration
runtime; no full migration was run for this change.
