# Runs: isolation, evidence and resuming

A run's job is to make a long sequence of builds add up to something
reproducible. That means every candidate is measured against a known baseline,
the user's checkout is left alone until there is something proven to publish, and
a run that stops halfway can be continued rather than restarted.

## The shape

**Prepare once.** Each stage copies the project's *current* state into a frozen
baseline and works out its candidates there. Dirty and untracked files are
included: those are usually exactly what someone wants tested. Every worker
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
`build/` only `compilers`, `tools` and `binutils` are kept. Caches and `.git` are
skipped.

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

Both edits refuse a rule they do not recognise rather than guessing.
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
job or integration `build.log`. Classification uses that command's output, so a
later failure cannot inherit diagnostic text from an earlier trial in the same
log. Unknown failures retain the command evidence without inventing a cause.

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
validator then replays coverage's `applied` history backwards, checks the
transaction's read dependencies in the sections it changed, and rechecks its
evidence. A refinement cannot hide an earlier transaction's effect on a
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
The journal stores the file's SHA-256; resuming an already published run
refuses a changed certificate record. An interrupted publication removes an
unfinished record while rolling back.

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

Resuming a run that already published does nothing and says so. A run written
by a tool with a different run schema (currently 8, which also records typed
trial refusals, their command-local evidence and retry counts) is refused rather
than reinterpreted.

## Resource settings

The defaults are three workers and four Ninja jobs each, measured on a 24-core
host. Native thread pools inside dtk and the compilers are bounded to the same
per-worker limit; Ninja's `-j` only limits the processes it starts, and without
that bound a three-worker run oversubscribes the machine by a factor of its core
count.

Disk is checked before starting, for every copy plus headroom. Both the baselines
and the job artifacts are kept for inspection and resume, so a long run consumes
more of it.

Candidate builds time out after 120 seconds by default. The bound applies only to
*candidate* builds: the first, cold build of a workspace is deliberately
unbounded, so a legitimate cold build is not judged by the trial limit. A timeout
kills the whole compiler and linker process tree and enters the normal bisection
path.

`--batch-size` defaults to 40. A larger batch costs less when it passes and more
when it does not, since a failure is bisected. Keep the default for full runs;
`--batch-size 1` is for narrow diagnostics and was responsible for hundreds of
avoidable full-link cycles in one measured run.

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
publish symbol changes outside the requested unit.
