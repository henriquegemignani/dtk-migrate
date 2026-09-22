# Runs: isolation, evidence and resuming

A run's job is to make a long sequence of builds add up to something
reproducible. That means every candidate is measured against a known baseline,
the user's checkout is left alone until there is something proven to publish, and
a run that stops halfway can be continued rather than restarted.

## The shape

**Prepare once.** Each stage copies the project's *current* state into a frozen
baseline and works out its candidates there. Dirty and untracked build inputs
are included: those are usually exactly what someone wants tested. Every worker
resets from that one baseline, so two candidates evaluated in different lanes
were measured against the same thing.

**Evaluate in parallel, reduce in order.** Candidates are batched, and each batch
is evaluated in a private copy of the project. Results are combined in candidate
order, never completion order, so the outcome does not depend on which lane
finished first. Candidates whose changes depend on one another — a coverage
transaction that reads or writes a unit another may write — are one conflict
component and always share a batch, even past `--batch-size`.

**Integrate.** Workers each proved their batch alone; the union has to be proved
too, because two changes that are fine apart can conflict together. Deferred
candidates are retried against the integrated state, but only after something has
been accepted — until then nothing has changed for them. A coverage transaction
whose preconditions no longer hold is refused as stale and regenerated from
fresh evidence in the next round, never adjusted to fit.

**Publish once.** Only the coordinator writes to the user's checkout.

## What is frozen

Before any work starts, a run copies the binaries it will use — decomp-toolkit,
Ninja, and this tool itself — into its own directory, and records their digests
alongside the variables a compiler reads (`PATH`, `INCLUDE`, `CFLAGS` and so on).
A later stage that finds any of them changed refuses to continue: its earlier
measurements no longer describe one thing.

Ninja is resolved through a package manager's launcher first. Chocolatey puts a
shim on `PATH` that finds the real binary relative to itself, and freezing a shim
freezes nothing.

The project's own downloaded compilers stay where they are and are passed to each
worker's configure step as inputs. Copying them per worker would multiply
gigabytes, and they would otherwise become download targets in each worker's
build graph.

## What a workspace contains

The snapshot covers everything except what a build regenerates: `build.ninja`,
`objdiff.json`, compile databases and Ninja's own logs are excluded, and under
`build/` only `compilers`, `tools` and `binutils` are kept. Caches, `.git` and
`.agents` directories at any depth are skipped. Git ignore rules are not used
as a blanket filter: Prime ignores retail DOLs under `orig/` and downloaded
toolchain files under `build/`, both of which the trial needs.

Symlinks and reparse points are refused outright. A snapshot that follows a link
is not a copy of the project; it is a second name for the original, and a trial
writing through it would edit the user's checkout.

Hand-made objdiff symbol mappings are read separately from the generated file and
fingerprinted on their own, because they are the user's rather than the build's.

Resetting a workspace between batches restores only what changed and keeps the
compiler output, which is what makes the second trial fast. Restored files get a
current timestamp, since an old one would let Ninja treat different bytes as up
to date.

## Two rules that keep trials reversible

The generated build graph is patched after each configure:

- `dol split` gains `--no-update`, so the splitter does not rewrite the project's
  own `splits.txt` and `symbols.txt` as a side effect of building, and a bounded
  `-j` so one worker's dtk does not take the machine.
- the `configure` rule is pointed back at this binary, so regenerating the graph
  mid-build does not undo the first change.

Both edits refuse a rule they do not recognise rather than guessing. Each trial
still configures explicitly: a split or symbol edit may not be a declared Ninja
dependency of the generated graph, so skipping that step can test stale inputs.
After final validation, publication regenerates the owner's ordinary build
graph so a later plain `ninja` no longer carries either trial-only edit.

## The run directory

Under `build/dtk-migrate/runs/<id>/`:

```
run.json                what was asked for, and what was frozen
tools/                  the frozen dtk, ninja and dtk-migrate
<stage>/
  baseline/             the frozen copy every worker resets from
  prepared.json         the candidates, the evidence, and what they came from
  manifest.json         the baseline's file digests
  jobs/<n>/             one batch: its spec, its result, its command log
  integration-evidence/ the union's build log
  result.json           what the stage concluded
  coverage.{json,md}    coverage only: measures plus the complete TU identification inventory
pool/worker-N/          the private workspaces
integration/            the workspace the stages chain through
publication.json        the journal, written before the first write
final-certificates.json the final per-unit bodies and certificate dependencies
result.json             the whole run
```

Rejected trial events record a typed `refusal`: its kind, affected symbol or unit
names when recognizable, and the failed command's executable, arguments, log
byte range, and bounded stdout/stderr excerpts. The full output remains in the
job or integration `build.log`. Classification reads that command's full log
byte range when available, including diagnostics between the bounded excerpts;
if the log is unavailable it uses the excerpts. A later failure cannot inherit
diagnostic text from an earlier trial in the same log. Unknown failures retain
the command evidence without inventing a cause.

## Publication

Only four files may change: `configure.py` and the target's `config.yml`,
`splits.txt` and `symbols.txt`. Any other difference stops publication rather
than being written.

The checkout must still be byte-for-byte what the run measured. Every replacement
is journalled with both the old and new bytes before it happens, so an
interrupted publication is recognised on the next `--resume` and undone. The
stage gate then runs again *there*, because a worker proved something in a copy.
For coverage, final validation first checks that every code section and every
data section coverage changed still agrees with its last accepted transaction.
Data added later to an untouched section may remain in the final body. The
validator rechecks the evidence, then replays coverage's `applied` history
backwards and checks each transaction's read dependencies against the split map
at the moment it was accepted. A later coverage transaction may change a read
neighbour; reverse replay restores its earlier state before checking the older
transaction. A refinement cannot hide an earlier transaction's effect on a
neighbour. Verification proves final source link inputs first; only units it
actually source-links may supersede coverage's earlier extracted-input trial
condition.

Reservations have separate code, data and link scopes. Coverage's code claim
can be followed by an independently witnessed data addition and then source
verification for the same TU. A coverage transaction also reserves code or
data boundaries it read from neighbours; those dependencies are not counted
as units changed by a focused `--only` request. Discovery retains a data-only
candidate when a code candidate for the same unit is reserved or refused.

Successful publication writes `final-certificates.json` with each certified
unit's complete final body when one exists, its accepted coverage transaction chain, the
selected discovery evidence digest, and whether this run verified its source
link. Transaction read dependencies name the neighbouring unit and section.
The journal stores the certificate graph's and whole-run `result.json`'s SHA-256.
Both are written before the journal commits `published`; resuming an already
published run refuses a missing or changed record. An interrupted publication
removes either unfinished record while rolling back.

A rollback never overwrites an edit made meanwhile. Someone else's work outranks
undoing ours: the file is left as they made it and named in the journal.

One OS lock per project stops two migrations sharing a checkout. It is released
if the holder dies.

## Resuming

`--resume <id>` continues a run. A stage whose preparation is on disk reuses it,
after checking that the frozen baseline and the stage before it are unchanged. A
batch whose stored result matches the job exactly — same baseline, candidates,
stage, tools and timeout — is reused; anything else is rerun rather than trusted.

A worker failure stops the other lanes but keeps what they finished, so a resumed
run picks up from there.

On Windows, candidate timeouts and command timing logs measure awake system
time. Suspending the computer does not consume a candidate's timeout budget or
turn an unfinished build into a candidate refusal on wake.

An incomplete run normally resumes under the same `dtk-migrate` executable that
started it; the error names the frozen copy if the current executable differs.
After a compatible bug fix, explicitly adopt the current binary with:

```text
dtk-migrate run --project-root <project> --resume <id> --resume-with-current
```

The run freezes that executable under its `tools/` directory, appends the old
and new SHA-256 identities to `run.json`, and uses the new copy for subsequent
integration and build hooks. Completed worker jobs keep the environment under
which they were measured, so matching sibling results remain reusable. The
upgrade works only when the run schema and `RESUME_COMPATIBILITY` level match;
a change that would reinterpret preparation, worker outcomes or integration
must bump that level and requires a fresh run. Without the explicit flag, a
different executable remains an error. Runs created before the compatibility
field existed are refused unless their exact executable digest appears in the
audited predecessor list; sharing schema 9 alone is not compatibility.

Resuming a run that already published validates its saved result and certificates,
then does no build work. A run written
by a tool with a different run schema (currently 9) is refused rather than
reinterpreted. Schema 9 requires coverage's extract inventories and the stage's
selection and applied-transaction history; missing safety data cannot silently
be read as empty. The read-only benchmark retains a separate legacy adapter.

## Resource settings

The default worker count is one per four available logical CPUs, capped at six;
Ninja gets four jobs per worker. On a 24-core host this means six workers and
up to 24 build jobs. Native thread pools inside dtk and the compilers are bounded to the same
per-worker limit; Ninja's `-j` only limits the processes it starts, and without
that bound concurrent workers can oversubscribe the machine by a factor of its core
count. Fresh runs aim for at least four batches per worker, and workers pull from
one shared queue. A measured discovery batch with 20 candidates took 1,257
seconds after its eleven siblings finished in at most 246 seconds; smaller
batches spread those slow linker refusals across lanes. Ordinary conflict components remain in one
batch. A component larger than the computed batch size is split into ordered
chunks: worker results are proposals against the same frozen baseline, and the
coordinator re-proves their ordered combination before keeping it.
Derivation goes straight to integration: its evaluator already trials the full
union of names and bisects a failed union, so worker screening would repeat the
same retail builds without strengthening the final proof.

Disk is checked before starting, for every copy plus headroom. Both the baselines
and the job artifacts are kept for inspection and resume, so a long run consumes
more of it.

  New runs bound candidate builds to 60 seconds by default, and reject a
  `--build-timeout` above 60 seconds. A resumed run keeps its recorded bound.
  The bound applies only to
*candidate* builds: the first, cold build of a workspace is deliberately
unbounded, so a legitimate cold build is not judged by the trial limit. A timeout
kills the whole compiler and linker process tree and enters the normal bisection
path.

`--batch-size` defaults to 40. A larger batch costs less when it passes and more
when it does not, since a failure is bisected. Keep the default for full runs;
`--batch-size 1` is for narrow diagnostics and was responsible for hundreds of
avoidable full-link cycles in one measured run. The value is an upper bound:
the scheduler may make smaller batches to supply the worker queue. A run records
the batching algorithm version, so a compatible coordinator upgrade preserves
an older run's exact job partition and can reuse its completed batches.

Each stage result records preparation, worker and integration wall time, and
each worker result records its own wall time.
Every command log also ends each invocation with `! timing seconds=<elapsed>
outcome=<ok|failed|timeout|cancelled|io-error>`. These lines distinguish
configure, link/hash and report time inside a worker or integration round,
  including failed trials, without changing the run schema.
  With `RUST_LOG=info`, coverage evidence also logs elapsed time for source
  and target analysis, matching, identification and compiled-object evidence,
  and report generation.

Coverage integration tries each candidate's alternatives against the current
split map in coordinator order, preferring a worker selection when available.
An alternative with stale ownership fails before a build; the next alternative
can be tried locally. The chosen transactions are then proved by one combined
link/hash build. If that build fails, integration restores the baseline and
bisects the candidates in order, committing each passing subgroup before trying
the next. A failing single-candidate leaf uses ordinary per-alternative builds.
Coverage workers use the same adaptive proof for multi-candidate batches, so a
passing batch needs one link/hash trial instead of one per candidate. The
coordinator still re-proves the combination across workers. The in-process
matcher returns its typed coverage report directly;
only the durable observation record is serialized, instead of writing and
immediately reparsing a second full JSON report during every rediscovery round.
Adaptive integration keeps one parsed observation index across its subgroups;
bisecting a failed union does not parse the same report again for each half.
Build or hash failures still use bisection.

Rediscovered coverage candidates are evaluated in parallel worker batches
against the coordinator's current split state. Integration keeps their
original order and tries locally applicable alternatives as one group, using
worker selections as preferences.
The final combined build remains required; worker proofs are not publication
certificates. This avoids one serial link per rediscovered candidate when the
workers' selections can be combined.

Discovery shares its verified ownership observation index across worker lanes.
Code proposal validation used to re-read and parse the same 149 MB report for
every candidate and retry; the cached index is keyed by its schema, digest,
path and version pair, and the report is verified when first loaded.

When verification retries at least 16 candidates after an acceptance, it
pretests balanced subtrees of the ordered bisection in the worker pool against
that exact integration baseline. If a worker exhausts a subtree without
accepting anyone, the coordinator reuses its failure when it reaches the same
subtree. An earlier acceptance invalidates that result, so the coordinator
then evaluates the subtree itself. Pretest jobs are stored under
`verify/pretests-<round>` and fingerprinted against their baseline for resume.

Candidate builds run the retail link/hash target before generating
`report.json`, under one shared timeout budget. A state the linker or checksum
rejects therefore never spends time in objdiff report generation. Baseline and
final builds use the same ordering without a timeout.

The development Cargo profile is optimized while retaining debug assertions
and symbols. `cargo build` is the normal installation path for this local tool,
and whole-executable matching is CPU-bound enough that an unoptimized binary
can dominate a migration even while the linker workers are idle. On the same
Prime NTSC-to-PAL read-only match, the previously frozen unoptimized binary took
44.47 seconds and the optimized development build took 2.65 seconds (16.8x);
their renames outputs were byte-identical. This is a benchmark of the matcher
and report generation only, not of a migration pipeline. It excludes workspace
setup, object-evidence collection, candidate compilation, executable linking,
integration, rediscovery, verification and publication. Treat it as evidence
for the optimized Rust analysis path, not as an estimate of end-to-end migration
speedup.

`--only UNIT` evaluates an exact unit and nothing else. Every other eligible
candidate is still reported under `eligible_excluded_by_only`, so a focused run
does not make an untested proposal look ineligible. A transaction that would also
have to change a unit outside `--only` is refused as `dependency-not-permitted`,
naming the unit it needed. Naming that unit too (`--only A.cpp --only B.cpp`)
permits the whole transaction without making the neighbour a candidate of its
own. Names are resolved across the whole pipeline: a unit an earlier stage
already changed is satisfied in later stages, and a unit only a later stage
proposes is not an error in an earlier one. A name no stage proposed, and no
requested candidate's change writes, stops the run before publication.
Derived renames are scoped as symbols, so an old symbol spelled `A.cpp` cannot
reserve the unit `A.cpp`. With `--only A.cpp`, derive selects renames whose
compiled-object evidence names that unit, regardless of the old symbol's
spelling; a same-spelling symbol in another unit does not satisfy the request.
Discover skips its whole-executable matcher rename batch under `--only`; its
split candidates were generated before that batch, and a focused run must not
publish symbol changes outside the requested unit. A missing matcher rename
file is an error in both focused and unfocused runs.
