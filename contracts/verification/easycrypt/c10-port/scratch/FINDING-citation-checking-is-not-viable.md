# FINDING — a `file:line` citation checker is NOT viable for this tree

**Date 2026-08-27.  Negative result: measured, then NOT built.**  Recorded so the next
person (or the next me) does not spend the afternoon discovering it again.

## Why it looked worth building

Stale `file:line` citations have caused **four** separate defects in three days:

* `GprocChargedQWired.ec:69` -> `:77` (mine; a `require` shifted the lemma)
* `WOTS_C_Real.ec` citing `WOTS_TW_ES.ec:569` for `encode_msgWOTS`, actually `:624`
* `C10DeployedGeometry.ec:454` citing `WOTS_C_Real.ec:337` -- the **FORK's** line, in a
  **SPLIT** file
* `C10DeployedGeometry.ec:465` -> `:464` (mine, in a draft)

No gate catches any of it: citations live in comments, and comments carry no census rows
and no statement pins.  A mechanical checker looked like the obvious fix.

## What the measurement says

581 `File.ec:N` citations across the 45 cone files.  Three candidate rules were measured:

| rule | result | verdict |
|---|---|---|
| identifier-adjacent citation resolves to that identifier's DECLARATION line | 12 exact, 12 near, **27 mismatch** of 76 | 36% false-positive — unusable |
| same, tightened to <=3 chars between identifier and citation | 12 exact, 10 near, **17 mismatch** of 58 | 29% — still unusable |
| identifier appears ON the cited line (or within 3) | 14 on-line, 10 near, **34 absent** of 58 | 59% — worse |
| **line number is beyond EOF** (zero false positives *by construction*) | **88 of 581** | see below — the 88 are CORRECT |

## The killer: this tree cites across FOUR file versions with overlapping line ranges

The out-of-range rule looked airtight — you cannot cite a line that does not exist.  It is
wrong here, because the cited file is often **not the split one**:

```
base-c10-split/SPHINCS_PLUS.ec            1020 lines
base-c10-fork/SPHINCS_PLUS.ec             4613 lines
FV-SPHINCSPLUS-EC/proofs/SPHINCS_PLUS.ec  4609 lines   (upstream MM45)
base-c10-split/FL_SL_XMSS_MT_ES.ec        1543 lines
base-c10-fork/FL_SL_XMSS_MT_ES.ec         6452 lines
```

`SPHINCS_PLUS.ec:2243` is out of range for the split file and perfectly valid for upstream
MM45.  All 88 "out of range" hits are of that shape.  **I nearly reported 88 correct
citations as stale.**

And the narrow fallback -- restrict to `cdrafts-split` files, which have no upstream twin
-- fails too, because every one has a **fork twin of similar length**:

```
WOTS_C_Multi.ec        split 969   fork 915
WOTS_C_Interactive.ec  split 3262  fork 3180
WOTS_C_Reduction.ec    split 672   fork 663
FORS_C10_Multi.ec      split 504   fork 493
```

So an in-range citation is ambiguous between two files, and the identifier-on-line rule
still misfires at ~24%.

## Verdict

**Do not build it.**  A gate check with a double-digit false-positive rate is worse than no
check: it trains readers to skip the phase, which is how a real finding gets ignored later.
The tree's citation convention is genuinely ambiguous to a machine — it is a human
convention that names a file by basename across four versions of that file.

## What IS worth doing instead

1. **Write the version when it is not the split file.**  `C10DeployedGeometry.ec:454` now
   says "(WOTS_C_Real.ec:337 — that is the FORK's line; in this SPLIT file it was :377,
   and since 2026-08-25 it is :403 and DEFINED)".  That is the fix at the source, and it
   costs nothing.
2. **Prefer `File.ec::name` over `File.ec:N`.**  Names do not drift when a `require` is
   added; line numbers do.  The tree already uses this form in the statement manifest.
3. **Re-check citations in a section when you edit near it** — which is what the
   2026-08-27 README audit did, and it caught three.
