# Deriving symbol names from compiled objects

`dtk-migrate derive` names target-version symbols by comparing each unit's
compiled source object (`build/<target>/src/...`) against the object extracted
from the target binary (`build/<target>/obj/...`). Both already exist after a
normal build, so this costs seconds and no compilation of its own.

The same code runs as the pipeline's first stage, where the names it proposes
also have to survive a build; see [coverage](coverage.md).

## Why this is a different signal from `match`

`dtk-migrate match` compares two versions of the same binary, so its evidence is
whatever survived between them. Here the source object states what a unit is
*supposed* to contain, which confines every comparison to one translation unit
and lets names the build already agrees on act as anchors.

## The four methods

### `body-match`

The strongest, and the only one that observes the function itself rather than
its surroundings.

objdiff pairs symbols **by name**, so a proposal that `fn_8030DA80` is some
source function is invisible to it -- the two sides have different names and
never get paired. Every placeholder function in an ordinary comparison therefore
carries no match percent at all. This is a property of the question, not an
oversight: the measurement does not exist until the rename has been made.

objdiff will, however, accept an explicit mapping. Telling it "compare this
placeholder against that source function" makes the pair scorable without
renaming anything, without rebuilding, and without writing to the project.

> An earlier version of this tool shelled out to `objdiff-cli`, which has no way
> to state a mapping, and worked around it by rewriting both objects' string
> tables to a shared five-character token in a temporary copy. Comparing in
> process removes the copy, the patching, and the separate binary to locate.

One comparison reports a match percent for **every** symbol in the object, so a
whole permutation of pairings costs a single diff. Packing candidate pairings
into permutations covers the full cross product in about as many comparisons as
one target has candidates, rather than one per pairing.

**An absolute threshold does not work.** Match percent measures body similarity,
which conflates "wrong pairing" with "right pairing, but PAL differs and the
source has not been adapted yet". Correct names routinely score 0%. What
separates them is the **margin** over the runner-up: a wrong name has no clear
lead, because the true counterpart is sitting in the same candidate list scoring
far better. Where nothing stands apart, the method abstains -- PAL inlines
differently, so many functions have no counterpart to find, and inventing one is
exactly the failure this is guarding against.

**A margin is not the only shape an unambiguous answer has**, and on its own it
leaves most of the remaining work on the table. Two further rules settle
pairings it cannot.

#### Sole near-exact candidate

Above about 99% two bodies differ by a handful of instructions, which is a
different kind of statement from merely scoring well: the pairing is either right
or the counterpart is a near-duplicate. The useful question there is not how far
ahead the best candidate is, but **how many candidates reach that band at all**.
When exactly one does, it is settled regardless of its lead.

`CFishCloud`'s `__dt__18CFishCloudModifierFv` is the case: 99.58 against a field
of *other destructors* topping out at 89.79. A lead of 9.79 fails the margin
rule, and the pairing is nonetheless unambiguous -- the runner-up is high because
destructors resemble each other, not because it is a competing reading.

Two candidates in the band means the opposite: the bodies really are
interchangeable, and no score will separate them.

#### Ordering

A compiler emits functions roughly in declaration order, so the pairings inside
one unit mostly form an increasing run. That run is independent of the bodies,
and it is most useful exactly where the body scores are weakest.

The pairings the scores already settled, plus the functions both objects call by
the same name, are reduced to their longest increasing run -- the *spine*. An
undecided pairing is then believed when its best candidate takes a free seat in
that run **and** no other undecided pairing wants the same seat in the opposite
order.

`CFishCloud`'s `RemoveRepulsor`/`RemoveAttractor` is the case: each scores 99.66
on its own target and 99.56-99.64 on the other, margins of 0.02 and 0.10. The
scores decide nothing; only one of the two assignments runs in the same direction
as the rest of the unit.

**The run corroborates and never vetoes.** Units do reorder -- a destructor the
target emits first can live near the end of the source object, and two template
instantiations can swap. Pairings their bodies settled stay settled; sitting off
the run is reported (`off_spine`) so a reviewer knows which handful to open in
objdiff, not used to reject them. In the sample below, all 9 off-spine renames
agree with NTSC.

### `call-site`

Aligning the relocations inside a function whose name already agrees names
whatever that function calls. This reaches **units with no source of their own**,
since a call site names its callee: where the source object calls
`GetTextureElement__20CParticleDataFactoryFR12CInputStreamP11CSimplePool` and
the extracted object calls `fn_8030DA80`, that address has its name.

### `function-position`

A placeholder sitting between two agreeing names is the function the source
defines there. The weakest method, because it observes only a function's
neighbours. Gaps whose two sides differ in length are left unpaired, and a unit
where nothing agrees is refused outright.

### `misplaced-name`

The other three ask what an unnamed function should be called. This asks whether
a name **already in `symbols.txt`** is on the wrong function, which is a
different and more damaging failure: a wrong name is the answer to the question
the other methods are asking, so it silently blocks the correct rename and the
report says only `name already taken`.

`dtk-migrate match` places names by propagating them between versions, so the way this
goes wrong is a **shift** -- two adjacent functions, the first carrying the
second's name. `CFishCloud` is the worked example:

| | `0x801C1FBC` | `0x801C20A4` |
|---|---|---|
| PAL name | `BuildBoidNearList` | `fn_801C20A4` |
| size | `0xE8` | `0x330` |
| best objdiff match | `OldBuildBoidNearList` **99.83%** | `BuildBoidNearList` **99.89%** |
| that source function's size | `0xE8` | `0x330` |

NTSC independently has the same two adjacent at the same sizes in the same order
(`0x801CF134/0xE8`, then `0x801CF21C/0x330`). The names are one function early.

A function whose size disagrees with what its own name compiles to, by more than
`SUSPECT_RATIO`, is *suspected*; objdiff decides. A correction is proposed only
when one source function explains the address near-exactly, alone, at a
plausible size, and the name being freed is not already on another function in
the same object. The bar is higher than anywhere else here because this is the
only method that overwrites a name somebody already had reason to trust.

#### The reference check

This method's one real weakness is that it treats the source object as
authoritative about what a name's body should be. In a unit that does not match
yet, that is false: a function the source failed to inline is indistinguishable
from a name on the wrong address, and the size tell fires either way.

`--reference` (the pipeline passes the version being migrated *from*) settles
it, because the other version knows nothing about our source. Three real
findings, separated by exactly this:

| unit | PAL address | our source says | reference says | verdict |
|---|---|---|---|---|
| `CFishCloud` | `0xE8` | `BuildBoidNearList` is `0x330` | `0x330` | corrected |
| `CPathFindArea` | `0xA4` | `GetIObjObjectFor` is `0x2C` | `0x2C` | corrected |
| `CPoseAsTransformsVariableSize` | `0x130` | `CPoseAsTransforms::__ct` is `0x30` | **`0x130`** | contested |

The first two: two versions independently disagree with where the name sits, so
the name is wrong. The third: both binaries place the name exactly where it is,
and only our source objects dissent -- and that file is marked `NonMatching`,
emitting `TSegIdMapVariableSize::__ct` standalone where the binary inlines it.
The name is right and the *source* is what needs work.

Without this check the third was proposed as `confident` alongside the other
two, at 99.87%. A contested finding is demoted to the `candidate` tier, below
what `--tier probable` writes out, and reported under its own heading -- it is
worth a human's attention and must never be renamed automatically.

**A correction is emitted alone, never paired with the rename it unblocks.**
Freeing a name collides with nothing -- the name it moves *to* is unused -- so
it is safe however the rest of the batch lands, including when the pipeline
bisects a failure and separates the two halves. Applying both at once is the
unsafe case: half a swap puts one name on two addresses. The blocked rename is
proposed again by the next run, once the name it wants is free, and the report
says so (`frees the name for fn_801C20A4, proposable next run`).

## Precedence

`body-match`, `call-site` and `misplaced-name` all observe the function itself
and rank equally; `function-position` ranks below them. When a stronger method disagrees with a
weaker one the weaker loses. When two equally strong methods disagree the symbol
is dropped -- neither claim is more credible.

After that, a rename still has to survive: every unit with an opinion agreeing,
the symbol existing in `symbols.txt`, the new name not already being taken at
another address, and no single name being claimed by two addresses.

## What is not protected

Renaming a symbol changes no bytes, so a retail hash cannot validate this tool's
output the way it validates split discovery -- a wrong name still produces a
byte-identical DOL. Linking is by name, so a wrong-but-unique name is referenced
by nothing: the cost of an error is mislabeling, not miscompilation, and a
rename is one line in `symbols.txt` to revert.

The cross-check that *is* available, and that the calibration below rests on, is
NTSC: the PAL address given a name should sit in the same translation unit that
NTSC gives that name. It is external to the tool and reads evidence the tool
never touches.

## Calibration

A 45-unit sample of `GM8P01_00`, ranking every unnamed target function against
every source function whose size is within `--size-ratio`. 1293 targets ranked,
scored against NTSC agreement. "unknown" is a name NTSC does not carry, so it
can be neither confirmed nor refuted.

| score | margin | kept | agrees | disagrees | unknown | precision |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0 | 1293 | 1122 | 50 | 121 | 95.7% |
| 0 | 15 | 786 | 768 | 7 | 11 | 99.1% |
| 0 | 30 | 653 | 646 | 3 | 4 | 99.5% |
| **70** | **15** | **739** | **724** | **4** | **11** | **99.5%** |
| 70 | 30 | 639 | 632 | 3 | 4 | 99.5% |
| 80 | 30 | 608 | 601 | 3 | 4 | 99.5% |
| 90 | 15 | 597 | 584 | 3 | 10 | 99.5% |
| 95 | 50 | 319 | 317 | 2 | 0 | 99.4% |

Two things decided the defaults.

**The margin does nearly all the work.** At a fixed margin of 15, raising the
score floor from 0 to 90 discards a quarter of the results (786 to 597) and
moves precision by less than half a point. Raising the margin from 0 to 15 at a
fixed floor cuts disagreements from 50 to 7. This is the measured form of the
point above: a low score means "PAL differs here", while a low margin means
"something else is a better answer".

**Precision saturates around 99.5%.** No threshold reaches 100%, and the
residual two or three are the shape already known to be a false alarm in this
cross-check: rstl template instantiations and weak destructors, which
CodeWarrior emits into whichever translation unit instantiates them first, so
the name is right and only the owning unit moved.

Defaults are therefore a score floor of 70 and a margin of 15 -- the point on
the frontier that keeps the most results at the best precision available --
with `confident` at 80 and 30. Raw argmax with no threshold is already 95.7%;
the thresholds buy the last four points and cost 43% of the volume.

### The two later rules

Measured on the 59 `GM8P01_00` units that still held three or more placeholders,
each rule switched off by raising its threshold above any attainable score.

| rules in force | renames | body-match | agrees | disagrees | unknown | precision |
|---|---:|---:|---:|---:|---:|---:|
| margin only | 227 | 72 | 58 | 0 | 14 | 100% |
| + sole near-exact | 257 | 103 | 82 | 0 | 21 | 100% |
| + ordering | 318 | 188 | 153 | 0 | 35 | 100% |
| **both** | **326** | **196** | **159** | **0** | **37** | **100%** |

Body matching goes from 72 renames to 196 on the same units, with no NTSC
disagreement either before or after. The two rules overlap heavily -- a lone
near-exact candidate is usually also in order -- but each reaches cases the other
does not, so both are on by default.

The margin rule is not weakened by this: it still settles 72 of these on its own
and is what the other two are measured against. What changed is that it is no
longer the only question asked. Note also how little of the sample NTSC can
adjudicate at all (37 of 196 are names NTSC does not carry); the precision
figures are a floor on the evidence available, not a proof of the rest.

`--exact-percent` and `--order-percent` expose both thresholds; setting either
above 100 disables that rule.
