# Metroid Prime: NTSC 0-00 → PAL

The source `GM8E01_00` is partially matched (over 60% at the start of this task),
not fully matched. The target is `GM8P01_00`. The goal is at least 15% PAL matched
code obtained through scripts, with manual investigation used only to improve the
automated process.

## Local paths

- Script repository: `C:/Users/henri/programming/decomp/dtk-version-matching`
- Game project: `C:/Users/henri/programming/decomp/prime`
- DTK checkout: `C:/Users/henri/programming/decomp-toolkit`

DTK is not a sibling under `decomp/` in this setup. Adjust these paths elsewhere.

Build development DTK from its checkout when testing a change:

```powershell
cargo build --release --bin dtk
cargo test --release
```

Use the executable directly through `--dtk`, which is forwarded to the game's
configure script. Copying it into `build/tools/dtk.exe` is unnecessary and risks
having Ninja replace it with a downloaded release.

## Automated migration

From the tooling checkout:

```powershell
uv run src/parallel_migration.py --project-root ../prime --source GM8E01_00 --target GM8P01_00 --dtk C:/Users/henri/programming/decomp-toolkit/target/release/dtk.exe --stage all --workers 3 --build-jobs 4
uv run src/discover_splits.py --project-root ../prime --source GM8E01_00 --target GM8P01_00 --dtk C:/Users/henri/programming/decomp-toolkit/target/release/dtk.exe
uv run src/verify_source_units.py --project-root ../prime --target GM8P01_00 --dtk C:/Users/henri/programming/decomp-toolkit/target/release/dtk.exe
```

For a bounded discovery run add `--limit 100`. `--batch-size 40` sets initial
group size; failures are bisected. The old recommendation to keep `--limit` near
25 concerned the historical loop, whose companion expansion could exceed the
limit and whose cycle heuristic discarded many proposals.

The first command runs coverage, discovery, and verification in isolated workers;
the latter two are serial
alternatives using the same validation adapters. See [parallel execution](parallel.md).
Do not run these commands concurrently in one checkout. Generated reports must
describe the final accepted splits, not an intermediate trial.

## Measuring progress

Read `build/GM8P01_00/report.json`:

- `measures.matched_code_percent`: objdiff matches across the configured report,
  including the unported NES REL in the denominator.
- Category `dol` → `measures.matched_code_percent`: main DOL only.
- `complete_code_percent`: bytes configured to link from source, not a separate
  byte-equality test.

The initial report on 2026-09-09 showed 256,284 / 3,908,836 code bytes matched
(6.5565% overall; 6.6154% DOL-only), and 111,176 bytes configured to link from source
(2.8442% overall). A fresh baseline retail build passed. Split presence was much
higher than either percentage, illustrating why unit counts cannot measure this
goal. Final measurements and caveats are recorded in [the audit](validation_audit.md).

## Calibration

`GM8E01_02`, the final NTSC-U release, combines aspects of `GM8E01_00` and PAL and
is useful for calibration. A read-only check, without transferring anything to it:

```powershell
C:/Users/henri/programming/decomp-toolkit/target/release/dtk.exe match config/GM8E01_00/config.yml config/GM8E01_02/config.yml --validate -o build/ntsc02-calibration.json
```

Hidden-name validation measures name agreement on named target functions. It is
neither a compiler comparison nor a retail hash check. PAL remains the primary
target; do not spend the migration effort optimizing `_02` instead.

The partial-coverage policy has a separate ownership calibration:

```powershell
uv run src/calibrate_coverage.py --project-root ../prime --source GM8E01_00 --target GM8E01_02 --dtk C:/Users/henri/programming/decomp-toolkit/target/release/dtk.exe
```

This masks `_02` names and split ownership during proposal generation, partitions
TUs deterministically, and checks every proposed anchor and complete range against
the separately generated ownership oracle. It does not publish configuration.

## Existing legacy state

The old skip file `build/GM8P01_00/split_confidence_skip.txt` does not constrain the
new discovery script. Do not interpret its entries as proof of wrong source code.
Existing PAL splits and names predate this task; the new results measure additions
to that baseline, not a clean-room migration from an empty target configuration.

Match source-unit path casing exactly, including `runtime/` and `dolphin/`.
Windows accepting inconsistent casing does not establish Linux compatibility.
