# Carrying symbol renames between versions

`dtk-migrate symbols sync` copies renames the *source* version made over a
range of commits into the *target* version's `symbols.txt`.

Use it when the source's symbols are being renamed in bulk after the target was
migrated from it: the target still has the old names, and re-running a whole
migration to rediscover what the source already states would cost a build per
candidate.

```sh
# a range, as git writes it
dtk-migrate symbols sync --source G2ME01 --target G2MP01 --range origin/main..main

# or two revisions; --to defaults to HEAD and WORKTREE reads the file on disk
dtk-migrate symbols sync --source G2ME01 --target G2MP01 --from 50baeac2 --to WORKTREE

# REL modules have their own symbols files
dtk-migrate symbols sync ... --file symbols.txt --file rels/DarkSamus/symbols.txt

# nothing is written until --apply
dtk-migrate symbols sync ... --apply --renames applied.txt --unresolved todo.txt
```

## What counts as a rename

The source's `config/<source>/symbols.txt` is read at both revisions. A symbol
renamed in place is one at the same section and address whose name differs.
Only the two endpoints are compared, so `A -> B -> C` across the range is one
rename `A -> C`, and `A -> B -> A` is none. Symbols that were added or removed
are not renames. A place that holds several symbols at either revision (a label
beside an object, say) and changed names is reported rather than guessed.

## Where it applies

A rename applies to the target symbol that currently holds the old name. The
name, not the address, links the two versions, because addresses differ. That
is exactly what a migration leaves behind: target symbols named after the
source's names at the time.

| outcome | meaning |
|---|---|
| applied | one target symbol holds the old name |
| already there | the target already has the new name and not the old one |
| not in the target | nothing holds the old name; the symbol was never carried over, or was renamed since |
| ambiguous in the target | several symbols hold the old name (local duplicates), so the name does not say which |
| duplicate new name | two source renames want one name, so either would collide |
| colliding | the new name is held by a symbol that is not itself being renamed |

Swaps (`A <-> B`) are applied whole. `scope:local` follows the renamed source
symbol.

Renames that find nothing in the target are written by `--unresolved`, with the
file, place and reason. A normal `run` names those symbols from the current
source, so they usually need nothing further.

Everything is done on the text of the symbols files, so addresses, attributes
and ordering survive and the diff shows only the names.
