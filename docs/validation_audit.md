# PAL migration validation audit — 2026-09-09

## Scope and baseline

The requested target is at least 15% matched PAL code from the partially matched
Prime NTSC 0-00 source, using scripts for all target changes. Manual investigation
was used to diagnose tooling and check evidence; no game C/C++ code or target
address was edited by hand.

The Prime checkout was based on
`aea197232958c1929496e0d96e4a970d08d67e31`. Its existing PAL symbols, splits and
source-link flags were retained as the baseline. The DTK checkout was at
`190a86784d5098d48ce414ad7c08df6533154008`, with a pre-existing uncommitted
`bridge_gap` change in `src/analysis/unit_matching.rs`; that change was left
untouched. The existing DTK executable was used without rebuilding:

`SHA-256 c627ef0838672a2f10f328c88069a09d50765ec232351d9dd158345160c61b57`

Tests used Windows, Python 3.9.12, Prime's configured CodeWarrior toolchain and
objdiff v3.7.0. The default objdiff relocation policy was retained. Scores below
use the same report-wide denominator before and after, including the unported
NES REL; DOL-only percentages are slightly higher.

## Confirmed tooling problems

### The old byte-comparison fallback was circular

`tools/project.py::add_unit` selects the compiled object only when
`Object.completed` is true (or an assembly override applies). The old split loop
never enabled its candidates. Linking and reading `main.elf` therefore compared
extracted original bytes with original bytes for those candidates. This could
"confirm" a data section even when the source object disagreed with it.

The fallback now requires explicit source-link provenance and is disabled in the
historical loop. A regression test supplies identical fake retail/ELF bytes and
checks that they cannot promote a mismatching compiled section.

`verify_source_units.py` instead stages generated source-link flags, builds,
checks that the compiled objects occur in the linker dependency graph, requires
the retail checksum and directly compares the final DOL with retail. Failed
groups are bisected and failed files remain disabled.

### Split counts and completion flags overstated progress

The starting report contained only 256,284 matched code bytes (6.5565%), although
many more units had splits. `metadata.complete` reflects source-link
configuration. It is not objdiff proving completeness. Conversely, matching
comparison sections do not imply a file is linked. The old status report labeled
such files "exists and linked" without checking the flag.

The status report now separates those states, treats missing comparisons as
unverified, and includes code percentages instead of only unit counts. Empty
section lists can no longer pass the historical loop's match gate.

### The all-sections gate discarded useful partial code

A file can contain matching functions alongside unfinished or version-dependent
functions and data. Requiring every section to match before retaining any split
unnecessarily discarded those functions from migration progress. Choosing one
small fragment and shrinking to a matching run also prevented the rest of the
file from being explored; the old loop skipped any unit already present.

`discover_splits.py` tests broader proposed code ranges, preserves existing data,
allows extensions to existing partial code splits, and retains a proposal only
when it adds matched code without reducing another existing unit's matched code.
Every accepted batch also passes the retail build check for split integrity.
These are useful **provisional comparison splits**, not a claim that every byte
inside their full ranges belongs to a completely reconstructed source file.

The first pass found four build-conflicting proposals, including a PAL compile
failure in `MetroidPrime/main.cpp` and overlapping/link-incompatible proposals.
They were isolated automatically. They do not establish that the corresponding
source files can never be migrated.

### Tool selection, retry state and final reports needed correction

`--dtk` previously selected only the matcher; subsequent configure/Ninja steps
could use or download a different executable. Both workflows now pass the same
absolute executable path to configuration. The old loop also forwards this flag.

The new discovery workflow does not permanently blacklist failed units. A failed
batch is bisected rather than attributing blame to arbitrary members of a large
SCC. The old loop no longer persists hash-failure blame based only on address
proximity. Its error cleanup now restores symbols and skip state along with
splits, and its final report is regenerated after rollback/filtering.

The new scripts restore input configuration on Python exceptions/interrupts and
rebuild the restored state where possible. Hard process termination cannot run
cleanup. Run only one writer/build per checkout.

## Measured results

First discovery command, from Prime:

```powershell
python ../dtk-version-matching/discover_splits.py --target GM8P01_00 --dtk C:/Users/henri/programming/decomp-toolkit/target/release/dtk.exe --limit 100
```

| Measurement | Baseline | First discovery pass |
|---|---:|---:|
| Total report code bytes | 3,908,836 | 3,908,836 |
| Objdiff matched code bytes | 256,284 | 648,568 |
| Objdiff matched code | 6.5565% | 16.5924% |
| Matched functions | 1,008 | 3,017 |
| Source-link-configured code bytes | 111,176 | 111,176 |
| Source-link-configured code | 2.8442% | 2.8442% |

95 proposals added 392,284 matched code bytes. Four failed builds; one other
proposal was not retained. The retail check passed after all accepted changes. The matched-code target
was exceeded without changing the denominator or the objdiff scoring policy.
This table deliberately does not present the discovery result as 16.59% verified
source linkage.

The subsequent source verification command is:

```powershell
python ../dtk-version-matching/verify_source_units.py --target GM8P01_00 --dtk C:/Users/henri/programming/decomp-toolkit/target/release/dtk.exe
```

The full source verification pass tested 90 comparison-matched files and accepted
60. Source-linked code rose from 111,176 to **173,912 bytes (4.4492%)**, and linked
data rose from 12,970 to 76,718 bytes. The final 185 source-enabled report units
include the 125-unit baseline. Both the retail hash and raw DOL equality passed;
the DOL SHA-1 is `4d3780c77842ae7fddbdd5732b70bed100df5c65`.

A bounded verifier rerun preserved all 60 generated overrides and the same
matched/linked totals. Source verification results are recorded in
`build/GM8P01_00/source-verification/result.json` and generated flags in
`configure.py`. Its actual trials demonstrate that 100% comparison sections can
still fail when compiled objects emit additional content or refer to unnamed
symbols. This is why whole-file promotion needs its own gate.

The final main-DOL-only measures are **16.7413% matched** and **4.4891% source
linked**. A bounded discovery rerun retained the same totals and archived its
inputs and script versions. Ten regression tests passed, covering circular byte
evidence, empty comparisons, transactional rollback, split extensions/overlaps,
and version-specific generated configuration with Windows newlines. Whitespace
checks passed in the script, Prime and DTK checkouts. No Rust implementation was
changed for this work, so DTK was not rebuilt or retested.

## Calibration against the final NTSC-U version

`GM8E01_02` combines aspects of NTSC 0-00 and PAL, so it was used for one read-only
hidden-name calibration, without applying changes or diverting the main effort.
The matcher found 16,589 / 16,606 target functions. Among 1,339 named matches
scored, 1,334 agreed and 5 disagreed (99.6266% agreement); two named functions were
missed. Confident-tier agreement was 1,240 / 1,243 (99.7586%).

One confident disagreement was `__arraydtor$381` versus `__arraydtor$159`. Two
others paired `CDummyFactory::Build` with `IObjFactory`'s destructor and
`CMemoryCard::GetAreaAndWorldIdForSaveId` with `CSaveWorldIntermediate`'s destructor.
These are name disagreements, not independently adjudicated matcher errors or
ground-truth errors. The old universal claim that all confident disagreements
are known naming noise was withdrawn in DTK's plan documentation.

## Remaining limits and next work

- Discovery uses the project's objdiff matching policy. It does not prove the
  correctness of every relocation or every unnamed function in a proposed range.
- Data sections are preserved during code discovery. Migrating missing data,
  full-file emitted sections and relocations should improve actual source linkage.
- Cross-unit template instantiations and deduplication can change ownership
  between versions; source-unit order is evidence, not ground truth for PAL.
- Build bisection can miss mutually dependent groups that fail individually.
  A failed individual trial stays retryable.
- The source-link verifier conservatively starts with nonempty, 100%-scored
  comparison sections. Some valid files may need a better proposal before testing.
- These are additions to the existing PAL baseline, not a clean-room migration
  from an empty target. Other games and non-dtk-template projects remain untested.

Runtime results and logs are under Prime's `build/GM8P01_00/`. Initial snapshots,
the first discovery result and `_02` calibration are under `build/migration-audit/`.
New discovery runs also archive input snapshots, script versions, logs and results
under `build/GM8P01_00/discovery/runs/`.
