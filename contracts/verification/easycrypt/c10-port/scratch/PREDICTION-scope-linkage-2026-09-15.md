# PREDICTION — link the HEADLINE list to the scope probes, as an exact bijection (written 2026-09-15, BEFORE computing)

## Why

Run 5 gates `extract_op`'s scope isolation per headline file, but nothing ties the probe rows to
`tools/taint_closure.py`'s HEADLINE list. A seventh headline file would get no probe, and PHASE 5
would say nothing. A probe left registered for a file that no longer declares a headline would
also say nothing. This class has already happened here once: WOTSNAMED went 13 days unregistered for
taint (fixed 2026-09-14).

## The check (in `taint_closure.py --check`, no new tool file, so the hashed file LIST is unchanged)

Headline files B are computed from HEADLINE via the tool's own resolution. Admit theories T are
computed from the admits the tool finds.

1. EXACT BIJECTION: {B} == {H : `scratch/_scope_neg_op_<H>.ec` is a row of cert-controls-split.tsv}.
   A missing probe fails, and so does a probe for a non-headline file.
2. Each such row is MUST-FAIL, and its declared reason names `T.` for every admit theory T.
3. Each probe file `require`s its own headline theory B (comment-stripped scan). A copy-paste probe
   pointed at the wrong file would still pass PHASE 3 while testing nothing about its file.
4. VACUITY: a missing or row-less controls manifest, or zero matching scope rows, FAILs.

Deliberately NOT checked, because PHASE 3 already makes the case RED: a probe that references some
other symbol or requires T itself would COMPILE, and a MUST-FAIL that compiles is RED.

## Controls (scratch/taint_controls.sh; EXPECT_TAINT_CTLS 11 -> 15)

The farm must now also carry `cert-controls-split.tsv` and the `scratch/_scope_neg_op_*.ec` probes.
Otherwise T0 would go RED for the wrong reason.

| control | deletes | expected FAIL substring |
|---|---|---|
| T11 | the GprocQBound scope row | `headline file GprocQBound has no scope probe` |
| T12 | the row matcher (blinded) | `scope-probe linkage is vacuous` |
| T13 | GprocWotsNamed's probe now requires GprocQBound | `does not require its headline theory GprocWotsNamed` |
| T14 | GprocQWired's row reason no longer names the theory | `declared reason does not name admit theory FORS_C_TreePort` |

`taint_count_controls.sh` stays at 4 variants. Its V0 expectation is read from EXPECT_TAINT_CTLS,
and V1/V3 target T9/T10 by name.

## Predictions

- P1 (sandbox prototype, before touching the live tree): HEADLINE's 9 names resolve to exactly 6
  files; linkage OK 6 <-> 6; taint_controls pass=15 fail=0; taint_count_controls pass=4 fail=0.
- P2 (gate Run 6, after Run 5 is green and pushed): GREEN. No closure .ec moved, so:
  - closure 42; pins 1167; coverage 1082/53; census added=0 removed=0; ledger 241; total 1677
  - controls 49/49; margin 4/4 and 3/3; taint closure 2 / 9 headlines
  - taint controls `pass=15 unique=15 fail=0 expected=15`; count controls pass=4

## Outcome

- P1, SANDBOX PROTOTYPE, run while gate Run 5 was in flight. The sandbox is a symlink view of the tree
  with real copies of the four edited files, so the live tree was never written.
  - MATCHED: `taint_closure.py --check` gives `OK   scope-probe linkage: 6 headline files <-> 6
    registered scope probes (exact bijection)`. The 9 HEADLINE names collapse to 6 files, as predicted.
  - MATCHED: `taint_controls.sh` gives `pass=15 fail=0`, and T11..T14 are each RED for the declared reason.
  - MISS, then fixed: the prediction said `taint_count_controls.sh` stays unchanged. It did not. Its own
    farm links only `taint_controls.sh` into `scratch/`, so the new probe files were absent there, T0 went
    RED for the WRONG reason, and V0/V1/V3 failed (`pass=1 fail=3`). This is the farm hazard flagged
    before building, one level deeper. Fix: link ALL of `scratch/` except the copy under test. After it:
    `taint count controls: pass=4 fail=0`.
- PORTED to the live tree after Run 5 was committed (b207a1a) and pushed (PQ1 6419d9d6).
  - Before copying, the four sandbox files were diffed against b207a1a: only the intended hunks
    (gate 2, taint_closure.py 5, taint_controls.sh 2, taint_count_controls.sh 1). The one removed line
    was `EXPECT_TAINT_CTLS=11`.
  - The copy refused to run unless the live files still equalled b207a1a.
  - The controls manifest got a dated, comment-only closing note (still 49 rows).
- PRE-RUN, LIVE TREE:
  - `taint_closure.py --check`: `OK   scope-probe linkage: 6 headline files <-> 6 registered scope
    probes (exact bijection)`.
  - `taint controls: pass=15 fail=0`; `taint count controls: pass=4 fail=0`.
  - Identity computed in ec-grind by scratch/calc_inputs_id.sh: `1bfdb2c42b39b297522fc856285be11a`.
- P2 MATCHED. Gate Run 6 ran detached in ec-grind (`r2026.02`, `0a5b3d54dcce300e 25 configurations`).
  GREEN, 0 FAIL lines, `__GATE_EXIT=0`, identity 1bfdb2c4 matched at start and end.
  - closure 42; CLI 46/0; pins 1167/1167; coverage 1082/53
  - census added=0 removed=0; ledger 241 ... total 1677
  - controls 49/49; margin 4/4 and 3/3; taint closure 2 / 9 headlines
  - `OK   scope-probe linkage: 6 headline files <-> 6 registered scope probes (exact bijection)`
  - `OK   taint controls: pass=15 unique=15 fail=0 expected=15`
  - `OK   taint count controls: pass=4 fail=0 expected=4`
