# FINDING — PHASE 5's first hole is REAL, demonstrated, and sized at 921 sites

**2026-08-28.  Measured, two-sided, reproducible.**  PHASE 5's header has said since it was
built that the check "does NOT see a bare `smt()` that takes a lemma from ambient context
without naming it".  That was written as a *precaution*.  It is a *fact*, and the mechanism
works on the exact lemma PHASE 5 exists to contain.

## The probes

`scratch/probe_smt_reach.ec` (P1) — can a bare `smt()` reach an AXIOM of a required theory?

```
lemma P1_axiom_reach : 1 <= n.   proof. smt(). qed.        -> RC=0  CLOSES
```

`1 <= n` follows from `axiom n_val : n = 16` (SPHINCS_PLUS.ec:44) and from nothing else —
`n` is `op n : int.` with no other constraint.  **Axioms are reachable without naming.**

`scratch/probe_smt_lemma_reach.ec` (P2) — the one that matters.  It restates the ADMITTED
`nhchwcoll_hchwpre_msg` (`base-c10-split/WOTS_TW_ES.ec:1505`, admit at `:1513`) with its
exact hypotheses and conclusion, and offers the prover **no hint**:

```
lemma P2_lemma_reach (ps)(ad)(m m')(sig sig') :
     P m => P m' => m <> m'
  => !has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
  => has_chwpre  ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof. smt(). qed.                                          -> RC=0  CLOSES
```

**It cannot have derived this independently.**  The step the admit stands in for is
`m <> m' => encode_msgWOTS m <> encode_msgWOTS m'` — encoder injectivity, which this tree
proves is IMPOSSIBLE at C10's geometry (`WOTS_TW_ES.ec:711-725`: the largest antichain of
`{0..7}^43` is `2^123.76 < 2^128`, and C10's encoding is deliberately many-to-one).  So
`smt()` reached the admitted lemma itself.

## The control — without it the probe proves nothing

`scratch/probe_smt_lemma_reach_NEG.ec` drops `m <> m'`.  The statement is then FALSE by this
tree's own refutation: `is_chwcoll` and `is_chwpre` share the conjunct
`BaseW.val em'.[i] < BaseW.val em.[i]`, which under `em = em'` is `x < x`, false at every
index — so `!has_chwcoll` HOLDS while `has_chwpre` FAILS.

```
proof. smt(). qed.
  -> [critical] ... cannot prove goal (strict)              -> RC=1  DOES NOT CLOSE
```

So `smt` discriminates here; it is not closing everything of this shape.  **P2's closure is
therefore evidence of reachability, not an artefact.**

## The size of the exposure

Comment-stripped over the 45 cone files:

```
BARE   smt()    921
HINTED smt(..) 2139      -> 30% of smt calls give the prover no hint list
```

Concentrated in `GprocT2Trh.ec` (162), `XmssmtCC_All.ec` (150), `FxChain.ec` (143),
`GprocT1Opre.ec` (110), `WOTS_C_Interactive.ec` (79).

## What this does and does not mean

* It does **NOT** show the headline consumes the admit.  The closure is still 6 and nothing
  here exhibits an actual escaping path.
* It **does** show PHASE 5 cannot RULE THAT OUT, and that the gap is not hypothetical:
  the mechanism is demonstrated on the exact tainted lemma, at 921 candidate sites.
* PHASE 5 remains worth having — it catches named-application drift, which is how the
  regression it guards (wiring `_Unfolded`) would actually happen.  But "gate-enforced
  containment" must not be read as "proved containment".

## Why this is not fixable by more parsing

Reaching into `smt`'s selection would mean reimplementing EasyCrypt's prover-input
construction.  The honest options are (a) state the measured bound, which is what this
finding does; (b) reduce bare `smt()` in the cone, a large mechanical change with real
regression risk to 921 proofs; or (c) an `#print axioms`-style dependency facility, which
EasyCrypt does not have.  (a) is taken.
