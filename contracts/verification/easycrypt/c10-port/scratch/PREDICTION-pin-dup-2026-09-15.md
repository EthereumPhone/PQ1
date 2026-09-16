# PREDICTION — the duplicate pin row, and the fail-open it exposes (written 2026-09-15, BEFORE computing)

## Measured before writing this

- `cert-statements-split.tsv` has 1167 rows but 1166 unique keys. The one duplicate is
  `op:base-c10-split/OpenPRE_From_TCR_DSPR_THF.eca::f`, identical twice (lines 1128/1129, same digest).
  It came in with 92ecb63 (2026-08-20), which added the 60 definition pins for the 7 non-root cone files.
- Neither checker produced it:
  - `tools/stmt_coverage.py` lists no within-file duplicate statement names, and its DECL regex does not
    enumerate `op` at all.
  - `tools/stmt_digest.py::digest_op` skips `<-` clone bindings and reports AMBIGUOUS on two
    declarations; the file has ONE `op f` declaration (:38) plus the binding `op f <- f,` (:46).
- The row generator was not committed, so the mechanism is not recoverable from the tree.
- PHASE 1c iterates manifest ROWS, checks each digest, and compares the ROW count with EXPECT_PINS. It
  has no duplicate-key check.
- PHASE 1h (`stmt_coverage.py`) reads the keys as a SET and requires only that the 1082 enumerated
  statements are pinned. **84 of the 1166 unique keys match no enumerated statement.** These are `op:`
  definition pins, e.g. `op:base-c10-split/BinaryTrees.ec::height`, and PHASE 1c's row count is their
  only protection.

## The fail-open (claimed LIVE; to be demonstrated, not argued)

Delete one of those 84 rows and duplicate any other row: the row count stays 1167, every row still
resolves and matches, and 1h is untouched. That definition is then unpinned under a GREEN gate. This is
the same class as PHASE 3's control inventory, which counts UNIQUE names for exactly this reason.

## The unit

1. Drop the duplicate row; EXPECT_PINS 1167 -> 1166.
2. PHASE 1c gains a duplicate-key guard before the loop, bracketed by BEGIN/END markers. Any key on more
   than one row is a FAIL naming the key, and the unique-key count must also equal EXPECT_PINS.
3. Isolated-logic demonstration, the same kind as PHASE 4's and EXPECT_WATCHED's, NOT wired into the gate.

## Predictions

- P1 (pre-fix PHASE 1c lines, host, symlink farm, doctored manifest with the
  `BinaryTrees.ec::height` row deleted and the `BinaryTrees.ec::list2tree` row duplicated):
  `statements pinned=1167 expected=1167`, zero FAIL lines. The fail-open is live.
- P2 (new guard block, isolated):
  - live manifest after the fix: OK, 1166 unique;
  - the P1 doctored manifest: FAIL naming the duplicated key;
  - the manifest with only the original duplicate restored: FAIL naming `OpenPRE_From_TCR_DSPR_THF.eca::f`.
- P3 (gate Run 7, ec-grind, detached): GREEN; identity changes.
  - `statements pinned=1166 expected=1166`
  - closure 42; coverage 1082/53; census added=0 removed=0; ledger 241; total 1677
  - controls 49/49; margin 4/4 and 3/3; taint closure 2; linkage 6 <-> 6; taint 15/15; count 4

## Outcome

- P1 MATCHED: the fail-open is LIVE. Setup: a symlink farm with a doctored copy of HEAD's manifest,
  where the `op:base-c10-split/BinaryTrees.ec::height` row is deleted and the
  `op:base-c10-split/BinaryTrees.ec::list2tree` row duplicated (1167 rows, 1165 unique keys). HEAD's own
  PHASE 1c lines, extracted verbatim and eval'd with `set -u`, `pipefail`, `LC_ALL=C` and
  EXPECT_PINS=1167, printed `statements pinned=1167 expected=1167 (manifest rows)` with 1167 OK lines
  and `__FAIL=0`, in 51 s.
- P1b: PHASE 1h is blind too, run rather than assumed. `tools/stmt_coverage.py` in the same farm printed
  `OK   coverage: all 1082 top-level statements across 53 CONE files are pinned`. The doctored manifest
  holds 0 exact `op:...BinaryTrees.ec::height` rows. So the definition was unpinned under a GREEN 1c
  AND a GREEN 1h.
- FIX APPLIED: the second identical row was replaced by a dated comment (manifest now 1166 rows, 1166
  unique keys), EXPECT_PINS became 1166, and a BEGIN/END `pin-key-uniqueness` block sits before the
  PHASE 1c loop.
- P2 MATCHED (the new block in isolation, EXPECT_PINS=1166):
  - live manifest: `OK   statement pin keys unique: 1166/1166`, `__FAIL=0`;
  - P1 doctored manifest: FAIL naming `op:base-c10-split/BinaryTrees.ec::list2tree`, and also
    `OpenPRE_From_TCR_DSPR_THF.eca::f` (that manifest was built from HEAD, which still carried the original
    duplicate), plus `FAIL statement pin keys: 1165 unique, committed expectation is 1166`;
  - HEAD's manifest: FAIL naming `op:base-c10-split/OpenPRE_From_TCR_DSPR_THF.eca::f`, unique count
    1166/1166.
  - Stated honestly: an isolated check of the decision lines, the same kind as PHASE 4's, not wired
    into the gate.
- Identity computed in ec-grind by scratch/calc_inputs_id.sh: `d8bf474fcbeb8a29f8a83fea86382b92`.
- P3 MATCHED. Gate Run 7 ran detached in ec-grind (`r2026.02`, `0a5b3d54dcce300e 25 configurations`):
  GREEN, 0 FAIL lines, `__GATE_EXIT=0`, identity d8bf474f matched at start and end.
  - `OK   statement pin keys unique: 1166/1166`, then `statements pinned=1166 expected=1166`.
  - closure 42; CLI 46/0; coverage 1082/53; census added=0 removed=0; ledger 241 ... total 1677.
  - controls 49/49; margin 4/4 and 3/3; taint closure 2 / 9 headlines; linkage 6 <-> 6;
    taint controls pass=15 unique=15; count controls pass=4.
