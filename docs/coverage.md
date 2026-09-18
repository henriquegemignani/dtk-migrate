# What each stage will and will not accept

Four stages, in the order they run. Each keeps only what its own gate agrees
with, and each gate proves something different. The order matters: naming comes
first because the matcher anchors its proposals on symbol names, so every name
established widens what the later stages can propose. Measured on the Metroid
Prime PAL target, naming first took discovery from a frontier of roughly 29
candidates to 349, of which 156 were accepted.

A unit an earlier stage accepted is reserved for the rest of the run. Coverage
records the exact range it validated and re-checks it at publication, so a later
stage extending the same unit would invalidate that certificate and cost the
whole run its publication — every other stage's work included. Leaving the unit
to the next run is far cheaper.

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

Policy version 9, evidence schema 10. Evidence comes from `match --coverage`;
each *alternative* is
one complete way a unit could claim a range, tried strongest first until one
survives a build.

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

**Accepted when** the evidence holds on re-derivation, the range is nobody
else's, the build reproduces retail bytes, the unit is still linked from its
extracted original, and no existing unit lost matched code. Acceptance
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

**Adjacent-owner transitions** go further: when the candidate's sequence occupies
a prefix or suffix of an adjacent unit's declared range, that unit shrinks and
the candidate takes what it gives up, in one transaction. Both range changes
apply together for every trial and roll back together on failure.

When functions in an eligible sequence identify data symbols the source version
extracts as assets, equivalent extraction entries are added to the target's
`config.yml`, and the generated files and renamed header declaration are checked
before the candidate is kept.

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
is why a deferred candidate is deferred and not blacklisted.

A failed trial also does not rule out a mutually dependent group: two files that
only link together will both fail alone.
