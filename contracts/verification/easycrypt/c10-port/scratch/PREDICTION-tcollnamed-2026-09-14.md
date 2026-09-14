# PREDICTION — GprocTCollNamed.ec (Run 2 of 2)

Written 2026-09-14 **before** the Run 2 census was computed and before the gate ran.
Run 1 (the promotion alone) is GREEN at `6aeac74105b8ebd64aa81768d8b6f256`:
closure 41, pins 1166, coverage 1081/52, census added=0 removed=0, ledger 241,
controls 36/36, taint closure 2, taint controls 11/11.

## What moves
* **+ `cdrafts-split/GprocTCollNamed.ec`** — one lemma,
  `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_TCOLLNAMED`:
  WOTSNAMED with its BadEnc summand replaced by `Pr[T_COLL_RES_ENUM(R_TCOLL(..)) : res]`
  via `badenc_le_tcoll`.  One new separation on F (`-O_TCollEnum_Default`), no new premise.
  **As an inequality it is strictly weaker than WOTSNAMED** (a corollary of it).
* **Comment-only corrections** in three closure files: `BadEncCountermodel.ec` and
  `TCollResEnum.ec` (the retracted "WOTS layer never encodes an adversary-chosen value"),
  `TCollResEnum.ec` ("does not control" clarified to the digest value), and
  `GprocWotsNamed.ec:49` (a `WitnessF` comment copied from a sibling; the file uses it zero times).
* **`tools/taint_closure.py` HEADLINE 7 → 9**: WOTSNAMED was never registered (a coverage
  hole the tool's own comment names), TCOLLNAMED is registered with itself.
* **3 controls** `scratch/gtn_ctl{A,B,C}.ec`.

## Predicted gate numbers
| quantity | Run 1 | predicted | basis |
|---|---|---|---|
| closure roots | 41 | **42** | +1 |
| CONE_FILES | 52 | **53** | requires nothing outside the cone |
| statements / pins | 1081 / 1166 | **1082 / 1167** | +1 lemma; comment edits enumerate nothing |
| controls | 36 | **39** | gtn A/B/C |
| **census** | 1677 | **1677, added=0 removed=0** | one lemma, no op/type/module/axiom; comment edits do not move census digests |
| **ledger** | 241 | **241** | |
| taint closure | 2 | **2** | neither named headline applies `extract_op` |
| taint headlines checked | 7 | **9** | |
| existing statement pins | — | **all unchanged** | comments stripped before digesting |
| INPUTS_SHA256 | 6aeac741… | **moves** | computed from the gate's own lines, then checked by the run |

## Falsifiers
* **Any census movement** — the unit declares nothing.
* **gtn_ctlA compiling** — the substitution would do nothing.
* **Either named headline in the taint closure** — a real finding, not a formality.
