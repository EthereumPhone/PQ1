# PREDICTION — PHASE 5 taint-control inventory guard (written 2026-09-14, BEFORE computing)

## The defect

`cert_gate_split.sh` PHASE 5 runs `scratch/taint_controls.sh` and trusts its EXIT STATUS.
That script exits nonzero only when a control FAILS. A control that never RUNS scores
nothing: a deleted block, a blinded `grade` call, or an early `exit 0` all leave `fail=0`, and
the gate echoes `OK`. This is the same class as the PHASE 3 `-ge 6` floor fixed earlier today,
in the phase whose header calls it the one mechanism that caught an end-to-end hole.

## The unit (one guard, one control-for-the-control, one gate run)

1. `EXPECT_TAINT_CTLS=11` in the gate (T0 baseline + T1..T10 graded). Gate-side, NOT in the
   controls script, so a single edit to that script cannot shrink its own expectation.
2. PHASE 5 parses the summary line and requires `fail=0`, `pass=11`, and 11 UNIQUE `OK` lines
   (parity with PHASE 3's `sort -u`: a deleted control replaced by a duplicate of another must
   not score). Lines are bracketed by BEGIN/END markers.
3. `scratch/taint_count_controls.sh` EXECUTES THOSE GATE LINES (extracted, not re-implemented)
   against real copies of `taint_controls.sh`, and the gate runs it:
   - V0 unmutated                                  -> OK
   - V1 T9's grade call blinded (`: grade ...`)   -> FAIL inventory, `pass=10 unique=10`
   - V2 `exit 0` right after T0                    -> FAIL summary line NOT PARSED
   - V3 T10's block replaced by a copy of T9's     -> FAIL inventory, `pass=11 unique=10`
4. The gate parses that script's summary as exactly `pass=4 fail=0` too, which ends the regress at
   the hashed gate.

Registered in PHASE 5 only. NOT in `cert-controls-split.tsv`, so `EXPECT_CTLS` stays 39.

## Predictions

- P1 (hole is live): HEAD's PHASE 5 lines, run against a copy with T9's grade blinded, print
  `OK   taint controls: taint controls: pass=10 fail=0`.
- P2: taint_count_controls.sh -> V0 OK, V1/V2/V3 RED for the declared reason, `pass=4 fail=0`.
- P3: the real controls produce 11 unique OK lines.
- P4 gate (ec-grind, r2026.02, 25 provers): GREEN. The identity CHANGES (value not predictable).
  No .ec edits, so: closure 42, cli 46, pins 1167, coverage 1082/53, census added=0 removed=0,
  ledger 241, parameters 221, bindings 366, meaning 406, definitions 443, total 1677,
  controls 39/39, taint closure 2 (9 headlines), taint controls `pass=11 fail=0 expected=11`,
  count controls `pass=4 fail=0`.

## Outcome

- P1 MATCHED. `git show HEAD:cert_gate_split.sh | sed -n 947,955p`, eval'd in a symlink farm
  whose `scratch/taint_controls.sh` had `: ` prefixed to T9's grade call, printed
  `OK   taint controls: taint controls: pass=10 fail=0`, and the gate's fail counter stayed 0.
- P2 MATCHED (host smoke run, 48 s): V0 OK, V1 `pass=10 unique=10`, V2 NOT PARSED,
  V3 `pass=11 unique=10`, all for the declared reason; `taint count controls: pass=4 fail=0`.
- P3 MATCHED: V0 requires `pass=11 unique=11` and got it.
- Identity computed in ec-grind by scratch/calc_inputs_id.sh: `6a06e77153057c7c54f3ab060c200e6f`.
- P4 MATCHED. Gate Run 3 in ec-grind (`### TOOLCHAIN GIT hash: r2026.02`,
  `### PROVERS 0a5b3d54dcce300e 25 configurations`): GREEN, identity 6a06e771 matched at start
  AND end. CLOSURE_COMPILED=42; CLI_FILES_RUN=46, CLI_DISAGREEMENTS=0; pins 1167/1167; coverage
  1082 statements / 53 cone files; census added=0 removed=0, ledger=241 parameters=221
  bindings=366 meaning=406 definitions=443 total=1677; controls 39/39; taint closure 2 lemmas,
  9 headlines; `OK   taint controls: pass=11 unique=11 fail=0 expected=11`;
  `OK   taint count controls: pass=4 fail=0 expected=4`.
- OPERATOR ERROR, not a prediction miss: the first launch used `docker exec -w /work -e LC_ALL=C`
  with no login shell. It printed `TOOLCHAIN UNKNOWN` / `0 configurations` and every target
  FAILed within seconds. Killed in-container, tracked tree confirmed untouched, relaunched with
  `bash -lc 'eval $(opam env); ...'`. Its log was overwritten by the valid run.
