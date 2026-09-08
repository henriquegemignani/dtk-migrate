# dtk-version-matching

Migrates unit splits and symbol names from a fully-matched version of a
[decomp-toolkit](https://github.com/encounter/decomp-toolkit)/`dtk-template`
project to another version of the same game (e.g. NTSC → PAL) by using a real,
hash-checked build as the oracle: it stages `dtk match`'s proposed split
boundaries, rebuilds, and keeps only the ones that come out byte-identical —
reverting the rest. See `docs/match_learnings.md` in decomp-toolkit ("The hash
check is the only real oracle") for why this is the only trustworthy gate.

Requires a `dtk-template`-shaped project: `config/<version>/{config.yml,splits.txt,symbols.txt}`,
`orig/<version>/sys/main.dol`, `configure.py`, and a `build/tools/dtk` binary
(run `configure.py` once to fetch it, or build decomp-toolkit yourself and
point `--dtk` at it). Both scripts read `Path.cwd()` as the project root, so
run them **from the project's root directory**, not from wherever this repo
is checked out.

## `split_confidence_loop.py`

Run one promotion round against a target version:

```
python /path/to/split_confidence_loop.py --target GM8P01_00
```

- `--source` — the version with known names (default `GM8E01_00`)
- `--target` — the version to propose and verify new splits for (required)
- `--limit N` — try at most N candidates this round, highest-confidence first;
  omit to try everything. Keep this modest (20-30) — a very large batch tends
  to produce one huge link-order-cyclic component that gets pre-filtered down
  to almost nothing (see `docs/link_order_cycle_investigation.md`)
- `-c/--min-confidence` — passed through to `dtk match`
- `--dtk PATH` — dtk binary to use (default `build/tools/dtk`)
- `--skip-file PATH` — units to never retry (default
  `build/<target>/split_confidence_skip.txt`); rejected units are appended
  here automatically. Delete or truncate it to let everything be retried,
  e.g. after a decomp-toolkit or script fix that might rescue previously-lost
  candidates.

Each round prints what it staged, what got promoted/rejected/blocked, and
syncs symbol names for newly-complete units via `ninja apply`. Nothing here
sets `MatchingFor` — that's this project's own separate "done" marker, not a
correctness check.

## `split_status_report.py`

Writes a per-unit status table comparing the source and target versions'
splits, without touching anything:

```
python /path/to/split_status_report.py --target GM8P01_00
```

Writes to `docs/<target>_split_status.md` by default (`--output` to change
it). Needs `build/<target>/match_candidates.txt` and `report.json` to already
exist — run `split_confidence_loop.py` (or at least `dtk match --splits` and
`ninja build/<target>/report.json`) first.

## See also

- `docs/prime.md` — exact commands and paths for running this against
  Metroid Prime's NTSC→PAL migration, the project this was built for.
- `docs/link_order_cycle_investigation.md` — open investigation into a
  specific large-batch failure mode.
