# Running this against Metroid Prime (NTSC → PAL)

Exact paths and commands for the workflow this repo was built for: migrating
`decomp/prime`'s `GM8E01_00` (NTSC 0-00, fully matched) splits and symbol
names to `GM8P01_00` (PAL).

Paths below assume the layout used during development:

- `decomp/prime` — the game's decomp project
- `decomp/decomp-toolkit` — a local decomp-toolkit checkout, only needed if
  you're testing a decomp-toolkit change (not needed for day-to-day rounds;
  `configure.py` fetches a release `dtk` binary automatically otherwise)
- `decomp/dtk-version-matching` — this repo

Adjust to wherever you actually have them checked out.

## One-time / per-decomp-toolkit-change setup

`decomp/prime`'s `build/tools/dtk.exe` is normally a **downloaded release
binary** (`configure.py`'s `download_tool` rule), not built from a local
decomp-toolkit checkout. If you're testing a decomp-toolkit fix, you must
rebuild and copy it in yourself — nothing does this automatically, and a
later `ninja` invocation can silently re-download the stock release binary
over it:

```
cd decomp/decomp-toolkit
cargo build --release --bin dtk
cargo test --release            # don't skip this
cp target/release/dtk.exe ../prime/build/tools/dtk.exe
```

Redo the `cp` after every rebuild you want reflected in a round — the copy is
the only thing that makes prime's build use your changes.

## Running one round

From `decomp/prime`:

```
python ../dtk-version-matching/split_confidence_loop.py --target GM8P01_00 --limit 25
```

`--source` defaults to `GM8E01_00`, which is correct for this project — omit
it. Keep `--limit` around 20-30; large batches tend to produce one huge
link-order-cyclic component that the pre-filter collapses down to almost
nothing (see `link_order_cycle_investigation.md`), wasting the round.

## Running several rounds back to back

Rounds are independent and idempotent to re-run, so a simple loop works. Stop
early if a round errors, if there's nothing left to try, or if two rounds in a
row produce identical output (a sign the current candidate pool is stuck on
something no amount of re-running will fix — see below):

```bash
PREV=""
for i in $(seq 1 10); do
  echo "=== ROUND $i ==="
  OUT=$(python ../dtk-version-matching/split_confidence_loop.py --target GM8P01_00 --limit 25 2>&1)
  STATUS=$?
  echo "$OUT"
  [ $STATUS -ne 0 ] && { echo "round $i failed, stopping"; break; }
  echo "$OUT" | grep -q "No new candidate units to try." && { echo "exhausted, stopping"; break; }
  SIG=$(echo "$OUT" | grep -E "^Promoted |^Rejected |Staging [0-9]+ candidate")
  [ "$SIG" = "$PREV" ] && { echo "round $i identical to previous, stuck, stopping"; break; }
  PREV="$SIG"
done
```

If it stops on "stuck," don't just keep re-running — that means the current
top-confidence candidate pool is link-order-cyclic with itself and needs a
different `--limit`, a look at `link_order_cycle_investigation.md`, or manual
investigation of the specific conflict (`grep -c "structural split conflict"`
the round's output for how bad it is).

## Reviewing overall progress

```
python ../dtk-version-matching/split_status_report.py --target GM8P01_00
```

Writes `docs/GM8P01_00_split_status.md` in `decomp/prime` — a per-NTSC-unit
table of what's linked, what's not-present-and-why, and what's present but
still mismatching, each with a specific suggested next step. Requires a round
to have run at least once (needs `build/GM8P01_00/match_candidates.txt` and
`report.json`).

For the raw byte-matched percentage (not just unit presence), check
`build/GM8P01_00/report.json`'s `measures.matched_code_percent` after any
`ninja build/GM8P01_00/report.json`.

## When to clear the skip list

`build/GM8P01_00/split_confidence_skip.txt` accumulates rejected unit names
across rounds so they're never retried automatically. That's usually correct
— but a decomp-toolkit fix or a `split_confidence_loop.py` improvement (e.g.
the trim-and-retry mode salvaging units previously rejected only because of
one bad non-`.text` section) can make previously-rejected candidates
promotable. After a change like that, clear it and re-run:

```
> build/GM8P01_00/split_confidence_skip.txt
```

(PowerShell: `Set-Content build/GM8P01_00/split_confidence_skip.txt -Value $null`.)
Expect the first round after a full clear to be slow and to re-reject most of
what was already ruled out for real reasons — that's expected, not a bug.

## Known project-specific gotcha

`config/GM8P01_00/splits.txt` has previously accumulated units declared under
inconsistent directory casing (e.g. `Runtime/foo.c` alongside `runtime/bar.c`
for what should be the same directory). This builds and links fine on
Windows/NTFS (case-insensitive) but breaks the link on a case-sensitive
filesystem (CI, WSL, Linux) with a confusing cascade of unrelated
undefined-symbol errors, since `dtk dol split` creates one output directory
per unit path verbatim. If a Linux/CI build fails with a wall of undefined
symbols that all trace back to one directory's worth of units, check for a
casing mismatch first: `grep -c '^Runtime/' config/GM8P01_00/splits.txt` vs
`grep -c '^runtime/' config/GM8P01_00/splits.txt` (adjust the prefix). Fix by
normalizing every entry to the same case, matching the source (NTSC)
splits.txt's convention.
