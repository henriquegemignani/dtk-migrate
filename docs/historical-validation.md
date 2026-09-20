# PAL split recovery: frozen validation

This records the completed policy-16 and policy-17 migrations and subsequent
calibration, not a claim that every later PAL split can be recovered from the
old binaries. Each migration used only its frozen baseline and NTSC source
version. Later PAL splits at `ca286f45`
were used by the benchmark afterward as an oracle. The runs, manifests and
scores are retained on F: under `target/` and the isolated Prime checkout's
`build/dtk-migrate/runs/`.

| NTSC→PAL baseline | Run | Changed code exact | Changed full exact | Correct code gained | Known code wrong/lost | Published retail |
|---|---|---:|---:|---:|---:|---|
| `b65ad2a6` | `20716-030131` | 7/25 | 4/27 | 1,824 B | 0/0 B | SHA-1 `4d3780c7…` |
| `46bd33805` | `20716-035350` | 2/15 | 0/15 | 1,320 B | 0/0 B | Same retail SHA-1 |

The old, pre-safety historical run recovered 2/25 changed code bodies and
1/27 complete bodies, but left 4 changed code bodies wrong and introduced
1,884 bytes of known wrong ownership. After Change C's safety gate the
comparable figures fell to 1/25 and 0/27 with no newly wrong bytes. Policy 16
recovers Group, TableGroup, CompoundWidget, Pane, SliderGroup, Platform and
Sound exactly in code; the first four are exact in complete ownership too.
The 20-unit second-cutoff cohort is a subset of the first run's 35, and every
overlapping unit has the same code, full-body and application outcome.

Both full runs executed derive, coverage, discover and verify, published, then
resumed without rebuilding. At the older cutoff the stage times were 265,
763, 1,445 and 558 seconds respectively, and their logs contain 7, 92, 134
and 105 Ninja build invocations (338 total). At the later cutoff they were
265, 739, 1,451 and 533 seconds, with 7, 85, 134 and 101 invocations (327).
These are sums of stage wall times and logged builds, not elapsed time or
compiler-process counts. The original historical run's complete build logs
were removed, so an equivalent runtime comparison to it is unavailable.

A separate policy-17 **focused coverage-only** run at `46bd33805`
(`20716-061334`, identification schema 15) accepted exact 96-byte extensions for
`Kyoto/Text/CColorOverrideInstruction.cpp` and
`Kyoto/Text/CPopStateInstruction.cpp`. It published to the same PAL retail
SHA-1. Scored against the frozen later oracle, both are code- and full-body
exact, with 192 correct bytes gained and no known wrong or lost bytes. This
focused run does not replace either complete policy-16 run or establish their
combined result with later stages. Its score is retained at
`target/attached-policy17-schema15-score/score.json` on F:.
The policy-17 five-scenario calibration is retained under
`target/attached-policy17-schema15-calibration/`. It adds 24 exact unit
recoveries in the truncated-splits scenario without known wrong or lost bytes;
its exit remains 1 for the pre-existing unselected `ScriptLoader.cpp`
alternative/anchor fault in two scenarios.

The later **full policy-17 run** at `46bd33805` (`20716-064439`) completed all
four stages, published, and rebuilt PAL to SHA-1
`4d3780c77842ae7fddbdd5732b70bed100df5c65`. Against the same frozen
manifest, changed-code exactness rises from policy 16's 2/15 to **4/15** and
complete-body exactness from 0/15 to **2/15**. Correct code gained rises from
1,320 to **1,792 bytes**, with zero known wrong or lost bytes. The two newly
exact units are `CColorOverrideInstruction` and `CPopStateInstruction` (96
bytes each); `CImageInstruction` also gains a correct 280-byte partial body.
The score is retained at `target/attached-policy17-full-score/score.json` on
F:. The published checkout was restored to its original `46bd33805` tracked
files after scoring, so later calibration uses the frozen baseline.

Policy 18 reuses that same `46bd33805` baseline and saved later oracle. Its
five-scenario calibration exits 0: `ScriptLoader.cpp`'s wrong destructor anchor
and fallback are withheld, all exact counts are unchanged, and no selected
wrong or revised-owner-lost bytes appear. It also withholds one correct partial
188-byte `CTweakAutoMapper.cpp` destructor claim in `everything` and
`isolated-unit`, pending positive emitter-placement evidence. The full
per-scenario comparison is in `docs/pal-split-recovery-plan.md`, with records
under `target/destructor-policy18-historical-calibration/` on F:.

Policy 19 adds two order-based destructor placement routes. On the same frozen
PAL baseline and oracle, all five calibration scenarios exit 0 with the same
exact counts and per-unit selected outcomes as policy 18, no incorrect
alternatives or anchors and zero selected wrong or revised-owner-lost bytes.
The records are under `target/destructor-policy19-historical-calibration/` on
F:. Its held-out GM8E01_00→GM8E01_02 `everything` scenario restores one
208-byte exact unit and one 824-byte partial claim lost under policy 18,
without adding an incorrect hypothesis; the two earlier unrelated wrong
fallback/anchor cases remain. A separate held-out all-scenario sweep was
stopped during `isolated-unit` before that scenario produced evidence, so
the other held-out scenarios are not scored here.

Policy 20's focused HeadWidget/LightWidget trial and all five PAL calibration
scenarios are described below and in the plan. Policy 21 then adds a
competing-source-slot veto for isolated identity matches. On the held-out
GM8E01_00→GM8E01_02 `everything` scenario it removes the two known wrong
unselected alternatives and anchors (`CDrone.cpp`, `CMetroid.cpp`) without
changing any selected ownership; the command now exits 0. On the frozen
`ca286f45` NTSC→PAL pair, all five policy-21 scenarios have identical
per-unit selected outcomes and ownership measures to policy 20, with zero
wrong known bytes and neighbour losses. The current benchmark's score for
the earlier focused policy-20 run is JSON-identical to its saved score.
These are calibration and scoring checks, not a new full migration. Records
are on F: under `target/policy21-final-heldout-everything/`,
`target/policy21-final-pal-calibration/` and
`target/policy21-head-light-score/`.

The first score has 805 unit ledgers: zero lost bytes and zero newly wrong
known bytes in complete ownership. It also records **26,608 bytes accepted
where the later oracle assigns no owner**. Those bytes are unknown, not proven
correct. Its original manifest marked every unit `trust=unverified`, since no
independent verify run had yet proved the oracle revision. The full score's
changed-code remainder is 7,540 missed bytes; changed-full remainder is 8,699.

A later verify-only run at the clean `ca286f45` checkout (`20716-090512`)
rebuilt PAL to the retail hash and checked actual compiled linker inputs for
the already declared source-linked units. Its one new candidate failed the
hash and was deferred; the run published no file changes. The benchmark now
accepts Git's deterministic LF↔CRLF checkout conversion and the verify stage's
deterministic legacy-status rendering when binding that run to the oracle Git
blobs. The resulting manifest at `target/midcut-policy19-verified-manifest.json`
marks 452 of 805 units source-linked and leaves 353 unverified. Rescoring the
full policy-17 migration at `target/attached-policy17-verified-score/` preserves
all 805 non-trust unit results byte-for-byte: 4/15 changed-code exact, 1,792
correct code bytes gained, zero lost or newly wrong bytes, and no verified
control regression. The remaining unverified splits and unassigned bytes are
still unknown rather than proven correct.

## Named gaps at the older cutoff

The table names every recall unit with missing code. The figures are missed
oracle bytes, not proposed growth. The score JSON retains addresses, evidence,
offers, refusals and all affected-neighbour ledgers.

| Unit | Code missed | Main unresolved evidence or application gate |
|---|---:|---|
| `CGuiFactories` | 1,184 | Missing source endpoint, unattributed target successor and members |
| `CGuiHeadWidget` | 12 | Type-ID helper has a duplicate emitted-owner question |
| `CGuiLight` | 452 | Unmatched internal target function and right endpoint |
| `CFBStreamedCompression` | 540 | Unmatched internal functions and both target endpoints |
| `CTimeRemainderAndFraction` | 244 | No baseline TU; five-function orphan cluster is only partly assigned by the later oracle |
| `CStreamAudioManager` | 236 | Left `fn_8034F370` is unattributed; another 240 data bytes remain |
| `CBlockInstruction` | 256 | Right target boundary and weak/template member owner |
| `CColorOverrideInstruction` | 96 | Exact proposal refused for no matched source-code gain |
| `CFontInstruction` | 132 | Unsupported left target boundary |
| `CImageInstruction` | 372 | Missing source endpoint and unattributed target successor; build refusal |
| `CLineSpacingInstruction` | 12 | Small helper's emitted owner is unproved |
| `CPopStateInstruction` | 96 | Exact proposal refused for no matched source-code gain |
| `CRemoveColorOverrideInstruction` | 188 | Missing source endpoint and unattributed target predecessor |
| `CTransitionDatabaseGame` | 628 | Unmatched internal function and left endpoint |
| `CTeamAiMgr` | 1,296 | Missing source endpoints, unmatched internal functions and unattributed target edges |
| `CScriptCameraPitchVolume` | 1,000 | Members currently owned by `TypesMatch`; unmatched internal target functions |
| `CScriptRoomAcoustics` | 12 | Duplicate destructor/vtable ownership with `TypesMatch`; source-link failure |
| `CScriptTimer` | 784 | Missing left source endpoint, incomplete member attribution and build refusal |

Code-exact SliderGroup, Platform and Sound still miss respectively 16, 351
and 228 non-code bytes. Widget misses 152 non-code bytes and its source-link
attempt reports duplicate identifiers and vtable definitions. DSPStreamManager
misses 48 non-code bytes. Ten other named recall units have no missed code
but received no new code ownership; the zero byte gap is not evidence that
their source objects can link. This distinction is visible in the score's
application and verification columns.

Hidden-name GM8E01_00→GM8E01_02 calibration produced no selected wrong
boundary or wrong known byte in five scenarios. It did report two wrong
*unselected* fallback/anchor hypotheses, `CDrone` and `CMetroid`, so retained
alternatives still need scrutiny. The older baseline's binary-only hidden-name
report corroborated 19 of the 35 oracle TUs, left 15 tentative and the future
CTime TU absent. Optional compiled-object evidence changed no confidence
outcome for these 35. These held-out diagnostics were not used to tune the
policy after scoring.

The attached independent-function rule covers represented units whose next
function is already attributed without a matched-code gain. Remaining recall
work includes non-attached ownership with similarly strong evidence, positive
emitted-owner proof with complete competitor inventory, typed data/vtable/BSS
ownership transfers, and insertion/deletion-aware member matching. None should
turn a diagnostic family or orphan cluster into an owner by name, unique body
or sole caller alone.

Policy 20 adds a narrowly ordered, compiled two-unit boundary. Focused
coverage-only NTSC→PAL run `20716-101118` started from `b65ad2a6`, offered one
HeadWidget/LightWidget transaction, and published only their `.text` split
changes. The rebuilt PAL DOL has retail SHA-1
`4d3780c77842ae7fddbdd5732b70bed100df5c65`. The later, independently
verified `ca286f45` oracle was used afterward for scoring: HeadWidget is exact
in code and full ownership, LightWidget is exact in code and misses eight data
bytes. Together they gain 464 correct code bytes and lose or wrongly assign
none. The matching record is one of 824 identified units in the old report; a
single-unit HeadWidget extension still fails the ownership gate. The new
baseline-specific manifest and score are retained on F: at
`target/b65-policy20-verified-manifest.json` and
`target/b65-policy20-head-light-score/score.json`. This focused run does not
replace the full policy-16 or policy-17 migration results above.
