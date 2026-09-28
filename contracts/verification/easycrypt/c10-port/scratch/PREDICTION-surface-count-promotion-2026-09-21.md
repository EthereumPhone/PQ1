# PREDICTION — promote the constant-sum surface count into the certified perimeter (written 2026-09-21, BEFORE changing anything)

## Why this unit

`cdrafts-split/C10DeployedScope.ec:344` and `cdrafts-split/GprocTCollNamed.ec:56` — both **cone
members** — lean on the constant `|C_T|`, and the object they lean on lives in
`experiments/wots-badenc/count/`, which the cone census does not cover. That is exactly the
question the PTgtsPin promotion answered ("where is this written down?" → "in an UNGATED
experiment"), and the answer taken there was to move it in.

This is a **gated-not-wired leaf**, deliberately. `C10DeployedScope.ec:28-30` records the same
property for its own content: nothing in `base-c10-split/` or `cdrafts-split/` requires it. The
leaves two reviews criticised (`experiments/tcollres-leg/`) were failed attempts at a *chain*
result; here the leaf IS the deliverable.

## Measured before writing this

* **All four files compile under the pinned image** (`ghcr.io/easycrypt/ec-test-box@sha256:bf1a13e7…`,
  `git-hash: r2026.02`), standalone, admit-free: VecDP, CountDS, C10SurfaceKernel, C10Surface, plus
  ScriptProbe. Measured today, not inherited from the 2026-08-14 receipt.
* **Statement/op inventory, counted with the gate's own regexes** (`stmt_coverage.DECL`, which
  includes `pred` and anchors on `^` *or* `.` — a bare `grep -c '^lemma'` undercounts, and that
  exact mistake produced a false finding in this tree on 2026-08-27):

  | file | statements | ops |
  |---|---|---|
  | VecDP.ec | 0 | 3 |
  | CountDS.ec | 21 | 6 |
  | C10SurfaceKernel.ec | 4 | 2 |
  | C10Surface.ec | 13 | 5 |
  | **total** | **38** | **16** |

* **Census preview: 16 rows, every one `defined-op`, ZERO ledger rows.** Promotion adds no
  assumption of any kind — no axiom, no admit, no clone obligation.
* **Name collisions against the cone: exactly one.** `sumz_cons` also exists in
  `cdrafts-split/IncEnc.ec` — which is **not** a cone member (0 rows in both manifests) and which
  nothing in the cone requires. EasyCrypt namespaces per theory, so this is harmless; recorded
  because a collision with a *cone* file would not have been.
* PHASE 3 compiles controls as `easycrypt compile $INC "$path"` with
  `INC="-I base-c10-split -I cdrafts-split"`, so the eight existing controls can bind to the moved
  files.
* The eight controls already carry committed two-sided verdicts: KctlC and KctlE MUST-PASS, and
  KctlA, KctlB, KctlD, CtlSum204, CtlLen42, CtlVal MUST-FAIL.

## The unit

1. `git mv` the four files into `cdrafts-split/` — **moved, not copied**, per the PTgtsPin
   precedent, so the tree holds exactly one definition and the two cannot drift.
2. Add them to `closure-c10-split.txt` (they are required by nothing, so they enter the cone only
   as roots) and to `cert-cone-files-split.tsv`.
3. Pin all 38 statements and all 16 op definitions in `cert-statements-split.tsv`.
4. Re-baseline `cert-baseline-split.tsv` with the 16 new census rows.
5. Register the eight controls in `cert-controls-split.tsv`, each graded on its observed
   `[critical]` message, not on exit status.
6. Fold in the two corrections this README's 2026-09-21 review named but could not make without a
   replay: the `2^114.0941` overstatement at `GprocTCollNamed.ec:56`, and the stale "38 gate roots"
   comment at `cert-cone-files-split.tsv:1`.

## Predictions

* **P1 — constants.** `EXPECT_STMTS` 1082 → **1120**; `EXPECT_PINS` 1166 → **1220**;
  `EXPECT_CTLS` 49 → **57**.
* **P2 — geometry.** closure roots 42 → **46**; cone files 53 → **57**; gate targets 53 → **57**
  compiled and 57 CLI-replayed.
* **P3 — census.** total 1677 → **1693**, all 16 additions `defined-op`; `definitions` 443 → **459**;
  **ledger stays exactly 241**, and `added` counts 16 with `removed=0`.
* **P4 — taint.** closure stays **2**; headline count stays **9**; scope-probe linkage stays 6↔6.
  `EXPECT_SEEDS=1` is unaffected (no admits added). `MAX_UNREGISTERED=2` is the one I am least sure
  of: 54 new declarations must all register, or the budget trips.
* **P5 — the gate goes GREEN**, and `INPUTS_SHA256` moves off `623ad0710d73000a1c693049b8933813`.
* **P6 — what it does NOT buy**, stated before the run so the receipt cannot be read as more:
  no chain result, no bound, no number attached to `T_COLL_RES_ENUM`. The surface count is a
  cardinality; `FINDING-do-not-import-the-policy-cap.md` §1 records that **no derivation connects it
  to an advantage**. Promotion buys that a constant two cone files already cite is compiled and
  digest-pinned on every run instead of rotting in an untracked directory.
* **P7 — the honest form of the constant.** What is machine-checked is the exact integer
  `22169393903687611906220091621190388` and the bracket `2^114 < |C_T| < 2^115`. The decimal
  `2^114.0941` is its base-2 logarithm computed OUTSIDE EasyCrypt and appears only in a comment
  (`C10Surface.ec:61`). After this unit the cone will contain the integer and the bracket as
  theorems, so `GprocTCollNamed.ec:56` can cite them instead of the decimal.

## Outcome

Filled in as results arrived. The predictions above are NOT edited.

* **P1 — PARTIAL MISS, and the miss is the interesting part.** `EXPECT_STMTS` 1082 → **1120** and
  `EXPECT_PINS` 1166 → **1220** both matched. `EXPECT_CTLS` did **not**: predicted 57 (all eight
  controls), actual **55**. Two of the eight were deliberately left unregistered after their
  failure reasons were OBSERVED rather than assumed. `KctlA` and `KctlB` fail with
  `anomaly: Stack overflow`, not with a proof failure — at full 43/205 scale the evaluator blows
  the stack before reaching a verdict. That reproduces the original 2026-08-14 receipt exactly
  (`WALL_MS` 42763 / 41990), so it is historical, not an artifact of the move. **A stack overflow
  does not discriminate:** it would occur just the same if `count_ds` were broken into computing
  garbage, so registering it would buy a control that fails for a reason unrelated to the property
  — the same defect class as the rotted T4. `CtlVal` perturbs the identical value and fails
  CLEANLY, because it first proves `kernelT` (the true value, which reduces in ~41 s) and rewrites
  through `count_ds_kernel`, landing the final step on a small arithmetic disequality. The
  property stays covered by a control that discriminates.
* **P2 — MATCHED.** closure roots 42 → **46**; cone files 53 → **57**; `stmt_coverage.py` reports
  "all 1120 top-level statements across 57 CONE files are pinned (roots 50 + transitively
  required)".
* **P3 — MATCHED exactly.** census 1677 → **1693**; `added=16`, `removed=0`; every addition
  `defined-op`; **ledger unchanged at 241**. Verified with `split_contract.py`'s own multiset
  comparison, not a hand-rolled diff.
* **P4 — MATCHED, including the item I flagged as least certain.** `MAX_UNREGISTERED=2` did NOT
  trip despite 54 new declarations; taint closure stays 2, headline count 9, scope-probe linkage
  6↔6.
* **P7 — acted on.** `GprocTCollNamed.ec:56` no longer calls `2^114.0941` machine-checked; it now
  cites `c10_surface_count` (the exact integer) and `c10_surface_bits` (the bracket) as closure
  members, and says explicitly that the decimal is a logarithm computed outside EasyCrypt.

Static checks before the replay, all green: `split_contract.py --pins` → `OK unique statement
pins: 1220`; `stmt_coverage.py` → 1120/57; `taint_closure.py --check` → closure 2, linkage 6↔6.

New identity computed by the gate itself (`--identity-only`, the designed fast path):
`623ad0710d73000a1c693049b8933813` → **`a814f744b21ecee6c5ecf32d2c58efc2`**.

* **P5 — MATCHED. The full pinned-image replay is GREEN**, `__GATE_EXIT=0`, 0 FAIL lines, and the
  identity moved off `623ad071...` as predicted.
  `CONE_COMPILED=57 EXPECTED=57`; `CLI_FILES_RUN=57 CLI_DISAGREEMENTS=0`; pins 1220; coverage
  1120 across 57 cone files; `ledger=241 parameters=221 bindings=366 meaning=406 definitions=459
  total=1693`; controls 55/55; margin 4/4, 3/3 and figures 7/7; taint closure 2 of 9 headlines;
  linkage 6<->6; taint controls 15/15; count controls 4/4; inputs unchanged across the run.
  The toolchain was CHECKED, not merely printed: `OK toolchain: r2026.02, 25 pinned prover
  configurations` against the digest-pinned image.
* **P6 — reaffirmed by the receipt itself.** `ledger=241` is the line that matters: 57 files and
  1120 statements now, and not one additional thing to believe. The promotion bought auditability
  of a cited constant. It bought no bound, and `T_COLL_RES_ENUM` is exactly as unbounded as it was
  this morning.

### Scorecard

Six predictions matched; one missed. The miss (`EXPECT_CTLS`) was found by RUNNING the controls
and reading their diagnostics rather than trusting their declared polarity, which is the only
reason KctlA/KctlB's non-discriminating stack overflow was caught instead of registered.
