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

`main` is at `8fe64eb` after these committed changes:

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
resource samples are `target/gm8j-32w.stderr.log` and
`target/gm8j-32w-resources.csv` in this repository. The 12-worker run's
samples are `target/gm8j-optimized-2-resources.csv`. These `target/` files are
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
One example is
`20718-140420/coverage/rediscovery-workers-3/00000/process/build.log`:
the timed-out `ninja build/GM8J01_00/ok` invocation had already completed a
roughly 18-second split and started `RUN configure.py`; the next operation is
not exposed clearly by Ninja's buffered output. A successful trial nearby
took 34 s total. Do not assume the linker itself hung. Identify the active
child process or add phase timing before changing timeout or bisection policy.

## Next work

1. Instrument `reset_workspace` and cache seeding separately (manifest scan,
   baseline verification, copies, generated-output seeding). Use a targeted
   F-drive benchmark on a few existing worker workspaces to find what made
   32 concurrent first resets take 135 s and repeated resets take 20–40 s.
   Preserve manifest validation and Ninja timestamp correctness.
2. Diagnose the timed-out Ninja process tree and measure split, graph
   regeneration, compilation, link, checksum, and report phases separately.
   Test a narrow reproducer from saved candidate/job artifacts rather than
   another full migration. Determine whether contention turns otherwise valid
   candidates into timeout-driven bisection trees.
3. Use those measurements to choose a scheduling change. Candidate batch size
   currently shrinks to provide four jobs per worker (`src/run/jobs.rs`); at 32
   workers this produced 118 coverage and 116 discovery batches, with costly
   resets. Consider a bound based on measured reset cost and slow-job tails,
   while keeping deterministic ordering and resume compatibility. A batching
   algorithm change needs a new version and tests.
4. Run targeted integration tests and the repository's full Rust checks. Only
   after a substantial change survives those checks, run one complete F-drive
   migration at fixed settings against a comparable baseline. Wait for it to
   exit, then compare stage and command timing, accepted/deferred units, and
   retail hash. Do not claim the 30-minute objective from a partial run.

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
