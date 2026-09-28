# FINDING 2026-09-01 — the charged WOTS leg IS reachable from the deployed capstone, and the only thing that ever blocked it was six module separations

## Why this was worth asking

`scratch/scope_fextractop_VERDICT.md` (2026-08-12, two independent reviewers, every
citation re-verified) closed the question of what to do next. Its **recommended next
unit** was, in five steps: charge the WOTS encoded-message collision explicitly and
propagate it to a parallel deployed QWIRED theorem.

Steps 1-4 landed on 2026-08-30 (the wots-badenc promotion): the disjunction, the split,
the codeword-level lemma in the unequal branch, and the B-free bound
`MEUFGCMA_WOTSTWESNPRF_Charged`.

**Step 5 was explicitly disqualified at the time**, and for a reason that no longer
holds. The verdict said:

> Merely wiring `_Unfolded` (4-7 days): **promotes B into the headline** — it would
> make a live admit load-bearing. A regression, not progress.

Admit B (`nhchwcoll_hchwpre_msg`) was REMOVED on 2026-08-30. `_Unfolded` is admit-free
and left the taint closure the same day. The stated regression has no addressee.

## What was actually blocking it — measured, not reasoned

`EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded` (`XmssmtCC_All.ec:8811`) is applied by nothing.
The tree records that fact repeatedly but never says WHY. The answer is one line of its
own restriction set, which the unfold added over the plain lemma:

    -FC_UD.O_SMDTUD_Default, -FC_TCR.O_SMDTTCR_Default,
    -FC_PRE.O_SMDTPRE_Default, -R_SMDTUDC_Game23WOTSTWES,
    -R_SMDTTCRC_Game34WOTSTWES, -R_SMDTPREC_Game4WOTSTWES

Those six are **absent** from the deployed forger `F`'s restriction set in
`GprocQWired.ec:67`. So `R_top_C(F)` cannot be shown disjoint from them.

**PROBE (`scratch/probe_unfold_deployed.ec`), and it is a compile, not an argument.**
Instantiating `_Unfolded` at `R_top_C(F)` with the deployed `F` set verbatim:

    [critical] the module Top.RtopCSoundness.R_top_C(F) is not allowed to
               use the modules(s)
    F
    __EC_RC=1

Adding exactly those six to `F` and changing nothing else:

    __EC_RC=0

## Two routes, BOTH typecheck at the deployed adversary

The same probe establishes both:

1. **`_Unfolded` at `R_top_C(F)`** — the route the verdict named.
2. **`MEUFGCMA_WOTSTWESNPRF_Charged` at
   `R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))`** — cheaper, because the
   deployed theorem carries the WOTS game as a **summand of its statement**, not as an
   applied lemma. Transitivity alone then yields a charged deployed capstone; the
   hypertree scaffold does not need re-porting at all.

Route 2 is the one to take. The verdict costed step 5 at 4-7 days on the assumption that
`_Unfolded` had to be threaded through the chain. It does not.

## The narrowing is precedented, and the file says so in its own words

Adding six separations to `F` is formally a NARROWING (the theorem applies to fewer
adversaries). `GprocQWired.ec` does exactly this twice already and documents the price:

> "This is formally a NARROWING of the hypothesis (it applies to fewer F); it is taken
>  deliberately, and it is the price of replacing an unreduced Q with three named
>  hardness advantages."

Same trade, one leg over: the price of replacing an unreduced WOTS game with named
UD / TCR / PRE / encoding-collision advantages.

## What this does NOT establish — read this before quoting the above

* **Nothing is bounded.** The charged deployed theorem would name four terms in place of
  one opaque game. That is assumption-surface progress, not a number.
* **`badenc_is_one` does NOT apply to this instantiation.** That theorem is about
  `A_coll` (`BadEncCountermodel.ec`). The deployed BadEnc term is at
  `R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))` — a DIFFERENT object. Whether
  it is 1, small, or anything else at that composed reduction is **open**, and it is
  exactly the +C-layer question the tree records as unresolved. Do not write "this makes
  the deployed bound's vacuity visible": that is the `c10_embg_inj` vs `encode_msgWOTS`
  error one level up, which `scope_fextractop_VERDICT.md` already scores against me.
* **A probe typechecking is not a proof.** Both `have :=` statements above establish that
  the restriction and arity checks pass. The losslessness obligations of
  `MEUFGCMA_WOTSTWESNPRF_Charged` at the composed adversary are NOT discharged by this
  probe. `XmssmtCC_All.ec:8913+` proves them for the abstract `A_ht`; whether that proof
  transfers verbatim to `R_top_C(F)` is the next thing to measure, and it is the real
  remaining cost.

## Also settled here, from the same verdict

**F-EXTRACT-OP is not the next unit and should not be attempted.** The verdict's answer
is "do not close it": `FORS_C_TreePort.ec:186` defines its **own local mirror**
`SM_DT_OpenPRE`, while the headline carries the real `FTWES.F_OpenPRE.SM_DT_OpenPRE`,
which the fully-proven Gproc route already reaches (`GprocT1Opre.ec:2168`). Closing the
admit would move no term. Its stated disposition is retire/archive, which nobody has
executed and which is an owner call, not a drive-by: removal is fatal to the gate by
design and would shrink the certified surface by ~100 statements.
