# PREDICTION — scope isolation gated PER HEADLINE FILE, not through the chain (written 2026-09-15, BEFORE running)

## Why

Run 4 gated `extract_op`'s scope isolation through `GprocTCollNamed` alone, on the grounds that the other
five headline files sit in its require-cone. Kimi K3's review (`scratch/REVIEW-kimi-scope-isolation-2026-09-15.log`)
found that chain UNGUARDED: all six headline files are closure roots (`closure-c10-split.txt`
lines 17, 30, 31, 34, 37, 42, re-verified). So a file could leave that cone, and nothing the gate checks
would move: not the cone manifest, not coverage, not the census. That file could then require
`FORS_C_TreePort` and use the admit through a bare `smt()`, all GREEN. Disclosure is not detection.

## The unit

- Five MUST-FAIL controls, `scratch/_scope_neg_op_<H>.ec` for H in
  {GprocChargedQWired, SphincsC10CapstoneWired, GprocQWired, GprocQBound, GprocWotsNamed}. Each has
  `require H.` plus the same op probe. Declared reason:
  ``unknown variable or constant: `FORS_C_TreePort.fverify_structural'``. That reason was already OBSERVED
  in ec-grind for all six headline theories in the feasibility run
  (`PREDICTION-scope-isolation-probes-2026-09-15.md`).
- NO new positive twins. `_scope_pos_op.ec` shows the op form is well-formed once the theory is loaded.
  The body is byte-identical across all six negatives, and PHASE 3 grades any OTHER failure as WRONG
  REASON, i.e. RED: a `probe_scope` name clash, a syntax error, or H failing to load. Per-file twins
  would add rows without adding information.
- `EXPECT_CTLS` 44 -> 49; a dated note in the PHASE 5 header and in the controls manifest.
- NOT covered, stated: a SEVENTH headline file. Nothing links `tools/taint_closure.py`'s HEADLINE list to
  these control rows. That is a candidate next unit, not this one.

## Predictions

- P1: `scratch/_run_scope_ctls.sh` in ec-grind grades 10/10 (6 MUST-FAIL for the declared reason, 3
  MUST-PASS, and the lemma negative).
- P2: gate Run 5 GREEN; identity changes. No closure .ec moved, so:
  - closure 42; cli 46/0; pins 1167; coverage 1082/53
  - census added=0 removed=0; ledger 241, parameters 221, bindings 366, meaning 406, definitions 443,
    total 1677
  - `controls executed (unique)=49 expected=49`
  - margin 4/4 and 3/3; taint closure 2 / 9 headlines; taint controls pass=11 unique=11; count
    controls pass=4

## Outcome

- P1 MATCHED. `scratch/_run_scope_ctls.sh` in ec-grind (`GIT hash: r2026.02`): `scope controls
  graded=10 bad=0`.
  - Each of the five new per-file negatives was rejected with ``unknown variable or constant:
    `FORS_C_TreePort.fverify_structural'`` at line 7.
  - The GprocTCollNamed negative, the lemma negative and the three positives are unchanged.
- Identity computed in ec-grind by scratch/calc_inputs_id.sh: `37dab7b0d09385a39036c0a82c7e0f82`.
- P2 MATCHED. Gate Run 5 in ec-grind (`r2026.02`, `0a5b3d54dcce300e 25 configurations`): GREEN, 0 FAIL
  lines, `__GATE_EXIT=0`, identity 37dab7b0 matched at start and end.
  - Closure: CLOSURE_COMPILED=42; CLI 46/0; pins 1167/1167; coverage 1082/53.
  - Census: added=0 removed=0; ledger 241, parameters 221, bindings 366, meaning 406, definitions 443,
    total 1677.
  - Controls: executed (unique)=49 expected=49. All six `_scope_neg_op_<H>` rejected for the DECLARED
    reason.
  - Margin 4/4 and 3/3; taint closure 2 / 9 headlines; taint controls 11/11; count controls 4.
- RUN HISTORY, disclosed. The first Run 5 launch was a backgrounded host `docker exec` with the log
  redirected on the host. The harness stopped it ("system running low on memory"). Only the host client
  died: the in-container gate kept compiling into a dead pipe, so it could never produce a receipt.
  - It was killed in-container and verified gone, and its partial log deleted.
  - It was relaunched DETACHED (`docker exec -d`, redirect inside the container, `__GATE_EXIT` marker).
  - The receipt above is from that relaunch.
  - Host load was 36 on 24 cores from other processes (an `rg`, java, another session) and fell to about 4.5.
