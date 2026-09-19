# What each stage will and will not accept

Four stages, in the order they run. Each keeps only what its own gate agrees
with, and each gate proves something different. The order matters: naming comes
first because the matcher anchors its proposals on symbol names, so every name
established widens what the later stages can propose. Measured on the Metroid
Prime PAL target, naming first took discovery from a frontier of roughly 29
candidates to 349, of which 156 were accepted.

A unit an earlier stage changed is reserved for the rest of the run — including
a neighbour that coverage narrowed as part of another unit's transaction.
Coverage records the exact bodies it validated and re-checks them at
publication, so a later stage extending the same unit would invalidate that
certificate and cost the whole run its publication — every other stage's work
included. Leaving the unit to the next run is far cheaper.

## derive — symbol names

Names target symbols by comparing each unit's compiled source object with the
object extracted from the target binary. See
[symbol derivation](symbol_derivation.md) for the four methods and how they are
reconciled.

A rename changes no bytes, so the retail hash cannot tell a right name from a
wrong one. The names are corroborated before they reach the build. What the
build decides is whether a name can be *applied*: naming an address after a
function another unit compiles from source puts that name in two linked objects,
and the linker rejects it. That failure is loud, so a batch that will not link is
bisected and only the offending names are dropped.

**Accepted when** the batch links and no unit's matched code falls. It may rise —
a name can let the comparison pair functions it could not pair before — but a
fall would mean a name took a pairing away from someone.

## coverage — which source file owns a target range

Policy version 14, evidence schema 11, identification schema 3. Every threshold
lives in one policy module (`src/analysis/policy.rs`) shared by the evidence
generator and the stage that re-derives it. Evidence comes from `match --coverage`;
each *alternative* is one complete way a unit could claim a range, tried
strongest first until one survives a build. Every alternative is one
[ownership transaction](#ownership-transactions) over all the units it changes.

The evidence also carries the complete `match --identifications` inventory.
Function attribution and TU identification are observations made before byte
thresholds, ownership-overlap checks, `--only`, source-object availability or a
trial build. Each record distinguishes pre-existing names from binary evidence,
retains materially competing identities, and reports candidate member sequences,
unexplained target functions, missing source members, uncertain helpers and
separate boundary/application blockers. A deferred or build-refused proposal
keeps both this identification and every boundary alternative it offered.

Identification, boundary certainty and application are independent. A TU may be
corroborated while an edge remains unresolved, or may have a complete observed
sequence that cannot yet be applied because ownership is contested. The summary
includes every source split unit even when `--only` limits the mutations.

**Accepted when** the evidence holds on re-derivation, the transaction's
preconditions still hold and its change is nobody else's ground, the build
reproduces retail bytes, every unit it wrote is still linked from its extracted
original, and no existing unit lost matched code. Acceptance
deliberately does **not** require any gain in matched code, and the candidate's
source object stays disabled throughout — this stage has no evidence about
whether that source is right.

The forms of evidence it accepts:

**Exact bodies.** A function whose normalised instruction stream and relocation
layout are identical in both versions, unique on both sides, with known extents
and no weak or template symbol involved. Adjacent anchors also offer their merged
range, and each anchor offers its own range alone.

**Corroborated `this`-layout groups.** Functions differing only where a member
offset moved. A group needs at least two unique functions agreeing on the same
inferred transformation, with at most two constant deltas separated by one
breakpoint. The group span is proposed, never an individual function.

**Boundary sequences.** One unclaimed target gap, bounded by the two represented
neighbours, filled by a decisive monotone alignment with enough unique anchors,
strong matches, functions and bytes. The complete gap is tried as one range; the
range is never widened from the first or last matched function. This establishes
partial split representation, not source equivalence.

Three fallbacks exist for cases ordinary matching cannot settle, each with its
own minimums:

- **Layout-corroborated.** Four unique layout-shift functions covering at least
  1,024 bytes and 16 changed member accesses. Source and target function counts
  must differ by at most one, and text sizes by at most 2%.
- **Vtable-corroborated.** For a polymorphic class whose compiler output moved
  one body into a local helper: at least eight monotonically aligned functions
  covering 85% of both the source functions and the target bytes, plus a uniquely
  paired vtable agreeing in every matchable slot. The only unmatched helper must
  be called from inside the gap.
- **Ownership transition.** When a stale neighbouring split makes the gap too
  wide, the candidate's own complete aligned sequence trims it. Both edges must
  transfer cleanly to the stated adjacent units.

**Composed boundaries.** A range's two ends are separate claims. Every
alternative's left and right edge is judged on its own (`src/analysis/boundaries.rs`):
an edge is *supported* when the function just inside it belongs to the unit —
independently attributed, or a caller-confined helper (below) — and the function
just outside is independently attributed to another unit, or the section ends
there. A neighbour's current split never supports an edge; splits are what is
being corrected. When, within one section, exactly one left and exactly one right
address proposed by any of the unit's alternatives are supported, and no single
alternative already proposes both, the two are composed into one claim. The
alternatives behind the two edges must agree about every function they both
place and keep source order across their union; the range must be tiled by target
functions with no more than alignment padding between them, may not reach
another unit's split, and faces the same complete ownership assessment as any
other claim. More than one supported address on a side is left undecided. The
original alternatives stay as fallbacks, and a range with both edges supported
ranks ahead of any otherwise equally attributed range that lacks them. Every
alternative records its judged edges, the evidence families behind each, and
the unit whose attribution pins the far side.

New ground must otherwise be independently attributed or padding. Two narrow
explanations extend that, both decided from the observation report alone so that
trial and publication recompute them identically:

- an **order-bracketed member** is attributed to the unit without independent
  support, but both of its target neighbours are independent members of the unit,
  held by the same range, whose source addresses bracket its own;
- a **caller-confined helper** is unattributed, and position, not its callers,
  decides which units could own it. Its target neighbours (across alignment
  padding at most) must either be two functions attributed to the unit in source
  order, placing it inside the unit, or form a *seam*: on one side the unit's own
  first or last source function, on the other the section's end or a function
  independently attributed to another unit that is *that* unit's last or first
  source function. A seam admits two owners, so callers then choose. Every
  caller must be the unit's and held by the same body, and must be either
  independently attributed or one of the members that place the helper. A
  weakly attributed caller elsewhere would make the helper's owner rest on that
  attribution alone. At most one helper per claim: two unexplained functions are
  a cluster needing its own identification. An edge may rest on a helper only
  when the helper sits at the unit's head (left edge) or tail (right edge) with
  the bound outside. Identification schema 3 records each target function's
  callers for this. A schema 2 report still loads and never explains a helper,
  and its reference keeps saying schema 2: a reference whose schema differs from
  its artifact's is refused, like one whose digest differs.

**Complete small sequences.** A unit too small for a boundary sequence's byte and
function minimums may still be recovered whole, but only when completeness
replaces size. Within one code section: every source function of the unit (one
contiguous run in the source) pairs, in order and by its exact source address,
with the target functions that tile the range, and there are exactly as many of
them, so no version-specific insertion is left unexplained; none is ambiguous; at
least two are independently attributed. Each end must be bounded by the section's
end, by an independently attributed foreign function, or by a function attributed
to the unit that neighbours this one on that side in the source version. The
global minimums are not lowered. A weak or weakly attributed member of such a
range is classed `complete-sequence-member`, decided by the same check at trial
and publication; the alternative records how each end was resolved.

**Adjacent-owner transitions** go further: when the candidate's sequence occupies
a prefix or suffix of an adjacent unit's declared range, that unit shrinks and
the candidate takes what it gives up, in one transaction. Both range changes
apply together for every trial and roll back together on failure.

**Joint source-order runs** search several neighbouring source units together
when at least one is missing or an independent target member lies in the wrong
split. The search uses independently attributed target functions as hard
members, tries cuts only at function boundaries, and checks each resulting
body with the same ownership assessment as an individual proposal. Target
functions without a supported owner and source units without a placed member
remain explicit unknown states. Only a unique, fully placed partition becomes
one transaction over every changed unit; a tied, incomplete or budget-limited
search changes nothing and appears in the initial preparation's
`joint_run_diagnostics`. A tie records both partitions and the independent
function addresses they share. The search is bounded by units, target
functions, windows and explored states, so it cannot
silently pick the best partition seen before exhaustion. Source order is used
only within a run whose independent members also occur in that target order.

### Ownership transactions

A transaction (`src/project/ownership_transaction.rs`) is the only form in which
coverage changes ownership, in trials, integration, calibration and
publication alike. It carries:

- every written unit's **exact before-state** and **complete after-body**;
- the **read set**: every other unit whose ranges touch the changed ones, with
  the body it had when the evidence was gathered;
- the **transfers** — which addresses move from which unit to which — derived
  from the bodies and re-checked against them on every use;
- any **release** of ground to nobody, which must be declared with a reason
  (coverage never declares one, so it never shrinks a unit without a receiver);
- the evidence references, the observation digest, a digest of the policy and
  the required extracts, and a SHA-256 **identity** over all of it. A selection
  records this identity.

Applying one builds and checks the whole resulting split map before replacing
anything: identity and transfers, split attributes and unparsed lines on every
retained range, no member overlapping any unit, and no new link-order cycle.
Growth is a metric, not a gate — a boundary move with zero net bytes is a valid
change. Refusals made without a build are reported by category:

| Category | Meaning |
|---|---|
| `stale-precondition` | A written or read unit changed, or unowned ground was claimed, since the transaction was derived. The coordinator regenerates it; it is never patched into place. |
| `ownership-preflight` | The change itself is inconsistent: an overlap, an unexplained loss, dropped attributes. |
| `link-order-cycle` | It would make dtk's link order unsatisfiable. |
| `dependency-not-permitted` | It must write a unit that `--only` or an earlier stage's reservation excludes. The whole transaction is refused; its candidate half alone would be a different change. |

Candidates whose transactions read or write a common unit, or claim touching
ground, form one conflict component and are always evaluated in the same worker,
in candidate order. `coverage.json` lists every applied transaction with its
per-unit gains and losses, including ones a later refinement superseded.

When functions in an eligible sequence identify data symbols the source version
extracts as assets, equivalent extraction entries are added to the target's
`config.yml`, and the generated files and renamed header declaration are checked
before the candidate is kept. For a joint transaction, the chosen alternative
renders the union of its written units' required extracts; trying a narrower
fallback starts again from the original configuration.

### Calibrating the policy

```sh
dtk-migrate calibrate --project-root ../prime --source GM8E01_00 --target GM8E01_02
```

Generates evidence twice: once with the target's names and ownership hidden, once
without. The hidden run produces the alternatives; the visible one supplies the
answers. Units split into a calibration half and a held-out half by a hash of the
name. Any incorrect assignment fails the command — the policy is meant to
abstain, not guess. A range falling where the oracle says nothing is *unknown*,
not wrong.

If the target has already received the proposals being evaluated, pass
`--oracle-splits` with a saved pre-change splits file so calibration cannot score
its own output.

## discover — split boundaries by measured progress

Proposes code ranges, including fragments and extensions to existing partial
splits, then extends established units with non-code ranges the matcher already
named but that were never carried over.

**Accepted when** the unit's own matched code went up, no other unit's went down,
and the build reproduces retail bytes. That last check tests *split integrity*
only: a file `configure.py` has not enabled still links from its extracted
original, so it says nothing about the candidate's source.

A data candidate is exempt from the code-gain test, because extending a matched
unit's data ranges cannot move the matched-code count. It still faces the build,
the retail check, and the aggregate regression check.

Two things happen before a build is spent:

- A batch implying a **cyclic link order** is bisected without compiling. dtk
  rejects such a batch outright, and the same graph can be built from the splits
  file. Only a cycle the batch introduces counts.
- A proposed range is **grown over an unowned remainder** that would strand a
  symbol. The matcher ends a range at the last symbol it could match, so an
  unmatched symbol immediately after lands in a remainder nothing owns, nothing
  emits it, and the link fails undefined — `musyx/runtime/synth.c` lost its whole
  data migration to a four-byte tail of exactly this shape. The growth is bounded
  twice: never into the next owner's range, and never past the size the same unit
  has in the source version.

## verify — whole source files

The only stage whose acceptance means "this file's source is correct".

**Accepted when** the compiled object is a real input to the link — checked
against Ninja's own input list for the artifact it belongs to — *and* the built
executable equals retail byte for byte. Both halves are needed. A retail hash
alone proves nothing here, and that is the circularity an earlier version of this
tool fell into; see [the audit](history/validation_audit.md).

Accepted files are recorded in each object's `MatchingFor(...)` call in
`configure.py`, with arguments in `VERSIONS` order. Existing flags are preserved.
An object whose status cannot be widened safely — `EquivalentFor(...)` most of
all, which claims less than `MatchingFor` — is reported and left alone rather
than promoted.

A unit declared for the target that the target has no split for is reported
rather than failed: nothing is compiled and nothing is linked, which is vacuous
rather than wrong, and it is a standing property of the configuration rather than
anything a candidate did.

## What a rejection is not

One rejected proposal does not permanently rule a unit out. A different boundary,
a neighbouring split, a symbol map or a tool revision can change the answer, which
is why a deferred candidate is deferred and not blacklisted. A stale transaction
in particular is a question asked of a world that no longer exists: its
regenerated successor has a different identity and is asked afresh.

A failed trial also does not rule out a mutually dependent group: two files that
only link together will both fail alone.
