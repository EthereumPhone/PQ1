# PREDICTION — promote the T_COLL_RES_ENUM chain into the closure (Run 1 of 2)

Written 2026-09-14 **before** the census was computed and before the gate ran.
Not edited afterwards; the result is graded in the commit and the baseline header.

## What moves
Four files enter `cdrafts-split/` from `experiments/wots-badenc/{tcoll,red}/`, code
identical (asserted by `scratch/promote_tcoll_chain.py`), comment edits only:
`TCollResEnum`, `BadEncSplit`, `BadEncToTColl`, `BadEncStep4`.  No consumer yet —
`GprocTCollNamed.ec` is Run 2.  Certification-root-only members have precedent
(`FORS_C_TreePort`).

## Predicted gate numbers
| quantity | before | predicted | basis |
|---|---|---|---|
| closure roots | 37 | **41** | +4 |
| CONE_FILES | 48 | **52** | the four require nothing outside the cone |
| top-level statements (EXPECT_STMTS) | 1024 | **1081** | +57, enumerated by `tools/stmt_coverage.py` |
| pin rows (EXPECT_PINS) | 1109 | **1166** | +57, no `op:` rows added (precedent: BadEncCountermodel) |
| controls | 15 | **36** | +21, all re-run against live trees, first lines match the experiment receipts |
| **ledger** | 241 | **241** | 0 admit/axiom/declare-axiom tokens in all four (their own perl recipe) |
| **parameters** | 217 | **221** | abstract ops `wad`, `wm`, `wm'`, `wctr'` (TCollResEnum witness data — hypotheses, like `cm`/`cm'`/`wad0`) |
| bindings | 366 | **366** | no `clone` in any of the four |
| meaning | 394 | **403** (±3) | module-types `Oracle_TCollEnum`, `Adv_TCollResEnum`; modules `O_TCollEnum_Default`, `T_COLL_RES_ENUM` + its inner `B`, `B_wit`, `R_TCOLL` + inner `O_wrap`, `AA`.  Uncertain: whether section `declare module`s are rows |
| definitions | 424 | **~442** (±3) | `EncNonInjOnSurface`, `EncNonInjOnThCSurface`, `tcoll_wf`, `wdg`, `wdg'`, `W_distinct`, `W_collides`, `W_gated`, `COLL`, `EncBridge`, `qs_ThC_images`, `wads_parallel`, `badenc_target`, `s4_qs_ts`, `s4_wads_ts`, `s4_ts_enc`, `s4_qs_ts_pend`, `s4_wads_ts_pend` (+ type `tcoll_entry` if defined) |
| census removed | — | **0** | nothing is edited in existing cone files |
| taint closure | 2 | **2** | none of the four applies `extract_op` or `fors_c_tree_port` |
| INPUTS_SHA256 | 7ec2a554… | **moves** | read off the gate, never recomputed |

## Falsifiers
* **Any ledger movement is a finding**, not a formality.
* **Any removed census row is a finding** — this unit edits no existing cone file.
* A control that COMPILES is a fail-open and stops the unit.

## Also in this run: a gate defect, found while reading PHASE 3
`cert_gate_split.sh:788-789` printed `expected>=15` but tested `[ "$n_ctl" -ge 6 ]`.
The "COUNT RAISED 6 -> 10 -> 13 -> 15" comments were updated; the number was not,
so deleting up to nine control ROWS scored OK.  Replaced by a committed
`EXPECT_CTLS` and an equality check.  Predicted: `controls executed (unique)=36 expected=36`.
