# Deriving symbol names from compiled objects

`src/derive_symbol_names.py` names target-version symbols by comparing each
unit's compiled source object (`build/<target>/src/...`) against the object
extracted from the target binary (`build/<target>/obj/...`). Both already exist
after a normal build.

## Why this is a different signal from `dtk match`

`dtk match` compares two versions of the same binary, so its evidence is
whatever survived between them. Here the source object states what a unit is
*supposed* to contain, which confines every comparison to one translation unit
and lets names the build already agrees on act as anchors.

## The three methods

### `body-match`

The strongest, and the only one that observes the function itself rather than
its surroundings. It needs `--objdiff`.

objdiff pairs symbols **by name**, so a proposal that `fn_8030DA80` is some
source function is invisible to it -- the two sides have different names and
never get paired. Every placeholder function in the report therefore carries no
`fuzzy_match_percent` at all. This is a property of the data, not an oversight:
the measurement does not exist until the rename has been made.

The inputs are ours, though. Renaming both sides to one short token in a
temporary copy makes the pair scorable. dtk's placeholder names (`fn_XXXXXXXX`,
11 characters) are shorter than mangled source names, so the token is written
straight into `.strtab` in place; no string table moves, nothing is rebuilt, and
the project's own files are never opened for writing.

One objdiff run reports a match percent for **every** symbol in the object, so a
whole permutation of pairings costs a single invocation. Packing candidate
pairings into permutations covers the full cross product in about as many runs
as one target has candidates, rather than one run per pairing.

**An absolute threshold does not work.** Match percent measures body similarity,
which conflates "wrong pairing" with "right pairing, but PAL differs and the
source has not been adapted yet". Correct names routinely score 0%. What
separates them is the **margin** over the runner-up: a wrong name has no clear
lead, because the true counterpart is sitting in the same candidate list scoring
far better. Where nothing stands apart, the method abstains -- PAL inlines
differently, so many functions have no counterpart to find, and inventing one is
exactly the failure this is guarding against.

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

## Precedence

`body-match` and `call-site` both observe the function itself and rank equally;
`function-position` ranks below them. When a stronger method disagrees with a
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
