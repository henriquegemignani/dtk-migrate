# Metroid Prime: NTSC 0-00 → PAL

The source `GM8E01_00` is partly matched, not fully matched. The target is
`GM8P01_00`. The goal is matched PAL code obtained through the tool, with manual
investigation used only to improve the automated process.

## Local paths

This checkout expects the game project and a decomp-toolkit checkout beside it:

- Tool: `C:/Users/henri/programming/decomp/dtk-version-matching`
- Game project: `C:/Users/henri/programming/decomp/prime`
- decomp-toolkit: `C:/Users/henri/programming/decomp-toolkit`

decomp-toolkit is **not** a sibling under `decomp/` here, which the
`.cargo/config.toml` path override has to account for. Adjust these elsewhere.

## Migrating

```powershell
cargo install --path .
dtk-migrate run --project-root ../prime --source GM8E01_00 --target GM8P01_00 --stages all
```

For a bounded first pass add `--limit 100`. Keep the default `--batch-size 40`
for full runs: failures are bisected, so a large batch costs less when it passes
and more when it does not. `--batch-size 1` is for narrow diagnostics and was
responsible for hundreds of avoidable full-link cycles in one measured run.

Do not run a migration and an unrelated build in the same checkout at once. The
project lock stops two migrations, but not a build someone starts by hand.

## Measuring progress

Read `build/GM8P01_00/report.json`:

- `measures.matched_code_percent` — comparison matches across the configured
  report, including the unported NES REL in the denominator
- category `dol` → `measures.matched_code_percent` — the main executable only
- `complete_code_percent` — bytes configured to link from source, which is a
  build setting rather than a byte comparison

The initial report on 2026-09-09 showed 256,284 / 3,908,836 code bytes matched
(6.5565% overall, 6.6154% for the DOL alone), and 111,176 bytes configured to
link from source (2.8442%). A fresh baseline retail build passed. Split presence
was much higher than either percentage, which is why unit counts cannot measure
this goal. Final measurements and caveats are in
[the audit](history/validation_audit.md).

## Calibration

`GM8E01_02`, the final NTSC-U release, combines aspects of `GM8E01_00` and PAL,
which makes it a useful calibration target. A read-only accuracy check, with the
target's names hidden while matching and scored against them afterwards:

```powershell
dtk-migrate match config/GM8E01_00/config.yml config/GM8E01_02/config.yml --validate -o ntsc02.json
```

That measures name agreement on already-named target functions. It is neither a
compiler comparison nor a retail hash check.

The coverage policy has its own calibration:

```powershell
dtk-migrate calibrate --project-root ../prime --source GM8E01_00 --target GM8P01_00
```

Use `GM8P01_00` when calibrating layout-shift evidence against PAL. After
applying coverage changes, pass `--oracle-splits` with the saved pre-change
splits file, so calibration cannot score its own output.

PAL remains the primary target; do not spend the migration effort optimising
`_02` instead.

## Existing state

Existing PAL splits and names predate this work. The results measure additions to
that baseline, not a clean-room migration from an empty target configuration.

The old skip file `build/GM8P01_00/split_confidence_skip.txt`, if it is still
around, constrains nothing and is not proof that any unit cannot be migrated.

Match source-unit path casing exactly, including `runtime/` and `dolphin/`.
Windows accepting inconsistent casing does not establish Linux compatibility.
