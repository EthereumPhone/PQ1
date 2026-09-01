require import AllCore List Distr StdBigop StdOrder IntDiv RealExp.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.
require WOTS_C_Interactive.
require import XmssmtCC_All.
require import RtopCSoundness.
require import FxChain.
require import GprocFORSC10.
require FORS_C10 FORS_C10_Multi.
require DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.
require import SphincsC10CapstoneWired.
require import SphincsC10Content.
require import C10DeployedInstance.

(* ==========================================================================
   THE CAPSTONE AT THE DEPLOYED PARAMETERS.

   `EUFCMA_SPHINCS_PLUS_C10_GROUNDED` carries FOUR parameter-dependent premises
   (the dfC0 member separations).  Here they are DISCHARGED from the deployed
   constants via `c10_dfC_separations_deployed` rather than assumed, so what
   remains to assume is the parameter-INDEPENDENT modelling content: the query
   bound `c <= p_tgts`, the encode bridge, N2, AND the serialisation-width
   premise `size (emb_in witness) = 8 * n + c10_r`.

   [CORRECTED 2026-08-01, second adversarial review: this previously listed
   THREE remaining assumptions and omitted the width premise -- which is the
   DECISIVE one.  It constrains `emb_in` at a SINGLE point, so a CONSTANT
   `emb_in` satisfies it while collapsing every ThC input and making the
   S-TCR(+C) term trivially winnable.  `c10_embg_inj` in C10DeployedInstance.ec
   proves a deployed-SHAPED serialisation is injective, but it is NOT applied
   here and injectivity of THIS `emb_in` is NOT assumed -- so that collapse is
   NOT excluded at the deployed level.  Both review legs identified this
   independently as the kill shot.  Do not read this lemma as excluding it.]

   [ADDED 2026-08-02, run 12: this residual list was INCOMPLETE in the other
   direction too.  The RHS carries an UNREDUCED BAD EVENT
      Q = Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m : res /\ !covered]
   which nothing bounds below 1.  SphincsC10CapstoneWired.ec:828-834 states this
   plainly -- "if Q = 1 this bound is as uninformative as the free-real version
   was" -- and the DEPLOYED capstone, which is the headline theorem, never
   repeated it.  A reader of this header alone would think the width premise was
   the only content-free direction.  It is not: Q and the unreduced
   Pr[M.F.ITSRC10 ...] term are the other two.]

   HONEST SCOPE.  This does NOT re-instantiate the theory's abstract constants
   -- `n`, `len`, `k` are `const .. as ge1_n`-style declarations fixed at
   `require` time, so a true clone-instantiation would need the whole chain
   restructured as abstract theories.  What this lemma does is state the
   capstone UNDER the deployed equations and prove every parameter-dependent
   side condition from them.  That is the strongest deployed-parameter
   statement the current theory structure admits.
   ========================================================================== *)

lemma EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             (* WIRED (2026-07-24): additional separations required by the APPLIED hop
                lemmas (Pr_EUFCMA_C10_FSPRFPRFC / SKGPRF_C_hop / hop4_musplit /
                LeqPr_VF_C).  Standard reduction well-formedness -- F is a proof-external
                forger disjoint from the internal game/reduction states; NOT a weakening
                of the bound (the current 6-admit capstone omitted them only because it
                never applied the hops). *)
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             (* WIRED (Step 4): the FORS/VT leg is now F-DERIVED via R_fors_p(F) into
                the concrete Gproc game; F must be disjoint from the Gproc game/reduction
                states (LeqPr_VT_C_proc + EUFCMA_Gproc(R_fors_p(F)) well-formedness). *)
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  &m :
    (* ==== THE DEPLOYED PARAMETERS (sphincs-c10/src/params.rs) ==== *)
    n       = c10_n     =>   (* 16, params.rs:19 *)
    len     = c10_len   =>   (* 43, params.rs:49 *)
    k       = c10_k     =>   (* 13, params.rs:34 *)
    size (emb_in witness) = 8 * n + c10_r =>   (* NODE || u32 counter *)
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    Pr[EUFCMA_C10(F).main() @ &m : res]
      (* +C SKG-PRF advantage: GROUNDED (was the free real skg_adv) to the exact
         concrete R_SKGPRF_EUFCMA_C PRF-distinguishing term that hop-2 (SKGPRF_C_hop)
         delivers. *)
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       (* +C subst #1: FORS+C10 CONCRETE expansion.  The ITSR(+C)/C10 term is now over
          the F-DERIVED reduction R_ITSRC10_Gproc(R_fors_p(F)) (was the free
          M.R_ITSRC10_MFORSC10(A_fors)) -- delivered by LeqPr_VT_C_proc (PROVEN) then
          EUFCMA_Gproc.  Same carried M.F.ITSRC10 hardness assumption; now concrete. *)
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
                : res /\ !EUF_CMA_Gproc_I.covered] )
       (* +C subst #2: hypertree COMPONENT THEOREM expansion at A_ht := R_top_C(F)
          (2026-07-24 hop6b CLEAN closure: applied DIRECTLY at R_top_C(F), so gap
          (a) R_top_C -> R_top is DISSOLVED; the four leaf terms keep the STANDARD +C
          shape -- WOTS-TW+C multi / S-TCR(+C) / pkco-TCR / trh-TCR -- now at
          R_top_C(F).  This is a PROVEN upper bound on the UNCHANGED LHS; the four
          terms are a DIFFERENT concrete RHS from a hypothetical R_top(F) one, not
          claimed numerically equal (see header (1)).  LeqPr_VF_C already lands on
          R_top_C(F), so the sole reconciliation is the FC.O<->TRHC.O oracle-clone
          hop, discharged by RtopCSoundness.oracle_clone_hop_C. ITSRC10 stays fg). *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
move=> hn hlen hk hsz hc hencb hN2.
have [# h0 h1 h2 h3 g0 g1 g2 g3 hnem] := c10_dfC_separations_deployed hn hlen hk hsz.
exact (EUFCMA_SPHINCS_PLUS_C10_GROUNDED F &m hc hencb hN2 h0 h1 h2 h3).
qed.

(* ==========================================================================
   TIER 0, STEP 2 (2026-08-03) — A DEPLOYED CAPSTONE WHOSE PREMISES PIN THE
   ENCODER.

   READ THIS BEFORE QUOTING EITHER LEMMA.  This does NOT repair
   EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS above.  That lemma constrains the
   encoder only by `size (emb_in witness) = 8 * n + c10_r` -- a statement about
   ONE POINT -- and it remains true, and remains satisfiable by a CONSTANT
   `emb_in` under which every ThC input collapses and the S-TCR(+C) term is
   trivially winnable.  ADDING A PREMISE CANNOT UN-SATISFY THE OLD STATEMENT.

   What this gives instead is a statement whose hypotheses are met only by an
   INJECTIVE RANK-BASED SERIALISATION: `emb_in = c10_embg`, proved constant-width
   and injective (under the counter-space bound) in C10DeployedInstance.ec.
   [CORRECTED 2026-08-03, round 14, GPT-5.6 and Opus 5 independently: this read
   "MET ONLY BY THE DEPLOYED ENCODER ... the concrete NODE||u32-counter
   serialisation".  That overstates twice.  `c10_embg` serialises the counter's
   RANK IN AN ARBITRARY ENUMERATION, and `cntr` is an abstract FinType whose
   cardinality no axiom bounds -- a SINGLETON counter satisfies every premise.
   Nothing here pins cardinality, enumeration order, numeric meaning or byte
   order, so this is not the firmware's u32; it is an injective rank encoder of
   the right SHAPE.]  Whoever quotes THIS lemma knows the
   encoder collapse is excluded; whoever quotes the older one alone does not.

   THE BOUND IS UNCHANGED, term for term.  S-TCR, Q and the unreduced ITSRC10
   term are exactly where they were.  This buys non-degeneracy of the model, not
   a number.

   `CntrFT.card <= 2 ^ c10_r` cannot be discharged here: `cntr` is an abstract
   FinType, so its cardinality is not fixed by the theory.  At deployment it is
   2^32 = 2^c10_r.  Carried as a named hypothesis rather than assumed silently.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_PINNED_ENCODER
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             (* WIRED (2026-07-24): additional separations required by the APPLIED hop
                lemmas (Pr_EUFCMA_C10_FSPRFPRFC / SKGPRF_C_hop / hop4_musplit /
                LeqPr_VF_C).  Standard reduction well-formedness -- F is a proof-external
                forger disjoint from the internal game/reduction states; NOT a weakening
                of the bound (the current 6-admit capstone omitted them only because it
                never applied the hops). *)
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             (* WIRED (Step 4): the FORS/VT leg is now F-DERIVED via R_fors_p(F) into
                the concrete Gproc game; F must be disjoint from the Gproc game/reduction
                states (LeqPr_VT_C_proc + EUFCMA_Gproc(R_fors_p(F)) well-formedness). *)
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  &m :
    n       = c10_n     =>
    len     = c10_len   =>
    k       = c10_k     =>
    STCRC_WC.G.CntrFT.card <= 2 ^ c10_r =>
    emb_in = c10_embg =>
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    Pr[EUFCMA_C10(F).main() @ &m : res]
      (* +C SKG-PRF advantage: GROUNDED (was the free real skg_adv) to the exact
         concrete R_SKGPRF_EUFCMA_C PRF-distinguishing term that hop-2 (SKGPRF_C_hop)
         delivers. *)
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       (* +C subst #1: FORS+C10 CONCRETE expansion.  The ITSR(+C)/C10 term is now over
          the F-DERIVED reduction R_ITSRC10_Gproc(R_fors_p(F)) (was the free
          M.R_ITSRC10_MFORSC10(A_fors)) -- delivered by LeqPr_VT_C_proc (PROVEN) then
          EUFCMA_Gproc.  Same carried M.F.ITSRC10 hardness assumption; now concrete. *)
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
                : res /\ !EUF_CMA_Gproc_I.covered] )
       (* +C subst #2: hypertree COMPONENT THEOREM expansion at A_ht := R_top_C(F)
          (2026-07-24 hop6b CLEAN closure: applied DIRECTLY at R_top_C(F), so gap
          (a) R_top_C -> R_top is DISSOLVED; the four leaf terms keep the STANDARD +C
          shape -- WOTS-TW+C multi / S-TCR(+C) / pkco-TCR / trh-TCR -- now at
          R_top_C(F).  This is a PROVEN upper bound on the UNCHANGED LHS; the four
          terms are a DIFFERENT concrete RHS from a hypothetical R_top(F) one, not
          claimed numerically equal (see header (1)).  LeqPr_VF_C already lands on
          R_top_C(F), so the sole reconciliation is the FC.O<->TRHC.O oracle-clone
          hop, discharged by RtopCSoundness.oracle_clone_hop_C. ITSRC10 stays fg). *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
move=> hn hlen hk hcard hemb hc hencb hN2.
have hsz := c10_deployed_encoder_gives_width hemb.
exact (EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS F &m hn hlen hk hsz hc hencb hN2).
qed.

(* THE PAYOFF, MADE EXPLICIT: under the same identification, the two model
   premises the S-TCR(+C) repair actually consumes -- LEN and INJ, which reach
   SphincsC10Content's CONCLUSION 5 as hN3/hN4 -- are THEOREMS.  This is the
   statement that says the S-TCR term is a genuine second-preimage problem at
   the deployed encoder rather than a collapse artefact. *)
lemma c10_deployed_STCR_premises_hold :
     STCRC_WC.G.CntrFT.card <= 2 ^ c10_r
  => emb_in = c10_embg
  =>    (forall (x y : dgstblock * cntr), size (emb_in x) = size (emb_in y))
     /\ (forall (x y : dgstblock * cntr), emb_in x = emb_in y => x = y).
proof. exact c10_deployed_encoder_meets_model. qed.

(* ==========================================================================
   TIER 0, STEP 3 (2026-08-03) — THE CONTENT THEOREM AT THE DEPLOYED ENCODER.

   EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL carries LEN and INJ as FREE HYPOTHESES:

       (forall x y, size (emb_in x) = size (emb_in y)) =>
       (forall x y, emb_in x = emb_in y => x = y)      =>

   and they are exactly what its CONCLUSION 5 consumes -- the claim that the
   S-TCR(+C) win condition is a GENUINE second preimage rather than an artefact
   of a collapsing serialisation.  Carried as hypotheses, that conclusion says
   "IF the encoder is well-behaved THEN the win is genuine", which is not a
   statement about the deployed scheme at all.

   Here they are DISCHARGED from `emb_in = c10_embg`.
   [CORRECTED 2026-08-03, round 14, all three legs.  This read "the non-triviality
   of the S-TCR term is a THEOREM of this development".  It is not.  What is a
   theorem is PREDICATE-LEVEL: that the win condition is a second-preimage
   relation on DISTINCT inputs at a single member.  Non-triviality of the TERM
   would need `thfc` to be something, and `thfc` is axiom-free -- under
   `thfc := const` the collision conjunct holds identically and the term can
   still be 1.  Conclusion 5 also remains a conditional (it starts FROM an
   assumed ThC collision).]

   Still unchanged, and still the reason this is not a security claim: the S-TCR
   term itself is a bespoke game whose game-level reduction is deferred, Q is
   unreduced, and the ITSRC10 term is carried.  Non-degeneracy is not a bound.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL_AT_DEPLOYED_ENCODER
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top,
             -DSSC.Stateless.O_CMA_Default, -O_CMA_SPHINCSPLUSTWC_FS,
             -SKG_PRF.O_PRF_Default, -EUF_CMA_SPHINCSPLUSTWC_NPRFNPRF_V,
             -R_top_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_RV,
             -R_fors_p, -O_CMA_Gproc, -O_CMA_Gproc_I, -R_ITSRC10_Gproc,
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default })
  (mkg_adv : real)
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (* THE ENCODER IS THE DEPLOYED ONE -- these two replace the free LEN/INJ
       hypotheses the original carries, and DISCHARGE them. *)
    STCRC_WC.G.CntrFT.card <= 2 ^ c10_r =>
    emb_in = c10_embg =>
    (* ---- the capstone's OWN premises, verbatim ---- *)
    c <= p_tgts =>
    0%r <= mkg_adv =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>
    (   Pr[EUF_CMA_Gproc_I(R_fors_p(F)).main() @ &m
             : res /\ !EUF_CMA_Gproc_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>
    (* ---- N1 IS NO LONGER A PREMISE: discharged by `N1_holds` above, which
           needs the predC tie (WOTS_C_Real) AND the cw_sum/digitsum bridge.
           The `(target_sum : int)` binder was ALSO removed: it SHADOWED the
           global `target_sum`, which is why N1 could not be discharged in
           place even after both were available. ---- *)
    (* ---- N2: p_nu -- a good counter always exists (witness: MODEL_N1_N2) ---- *)
    (forall (ps : pseed) (ad : adrs) (mm : dgstblock), exists (cc : cntr), predC (ThC ps ad mm cc)) =>
    (* ---- N3/N4: emb_in constant-width + injective (witness: MODEL_emb_in) ---- *)
       (* ==== CONCLUSION 1: THE CAPSTONE BOUND, UNCHANGED AND UNWEAKENED ==== *)
       (Pr[EUFCMA_C10(F).main() @ &m : res]
          <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
               - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
           + mkg_adv
           + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                              M.F.O_ITSRC10_Default).main() @ &m : res]
               + mtree_openpre + mtree_trh + mtree_trco )
           + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                          O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
               + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                   STCRC_WC.O_STCRC_Default).main() @ &m : res]
               + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                      FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                      FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
               + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                      FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                      FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ))
       (* ==== CONCLUSION 2 (the V1 MECHANISM excluded): the EXACT hypothesis of
               predC_false_zeroes_capstone_LHS is REFUTED.
               PRECISION (do not overstate): refuting an implication's hypothesis does
               NOT falsify its conclusion.  What is established is that the KNOWN
               MECHANISM by which the LHS was shown identically zero is excluded -- NOT
               that the LHS is nonzero.  Proving `Pr[EUFCMA_C10(F0)] > 0` for some F0
               needs honest-signature verification through the d-layer address/root
               bookkeeping of `root_from_sigC`, i.e. SCHEME CORRECTNESS, which MM45
               never proves for any scheme and which is the genuine next rung. ==== *)
    /\ (! (forall (x : msgWOTS), ! predC x))
       (* ==== CONCLUSION 3: the FORS `good_pos` SHAPE, DERIVED (uses the
               inherited FTWES.ddgstblock_fu; see the header disclosure). ==== *)
    /\ 0%r < mu dmsgWOTS predC
       (* ==== CONCLUSION 4: EVERY honestly-ground counter passes the +C gate,
               at EVERY (ps,ad,m).  This is the mechanism the V1 audit zeroed. ==== *)
    /\ (forall (ps : pseed) (ad : adrs) (mm : dgstblock), predC (ThC ps ad mm (grindC ps ad mm)))
       (* ==== CONCLUSION 5 (the V2 MECHANISM excluded): the S-TCR(+C) win condition is a GENUINE
               second preimage on a SINGLE collection member at a SINGLE tweak --
               not a trivial coincidence forced by a collapsing serialisation. ==== *)
    (* ROUTE (D) [REWRITTEN 2026-08-01 after adversarial review].  The previous
       route-(D) restatement was DEFECTIVE: it had NO collision antecedent and
       NO projected equality -- its last two conjuncts were just ThC's
       DEFINITION (ThC_same_member), which holds unconditionally and asserts
       nothing about a second preimage, while the header above kept promising
       one.  ThC_coll_projects was never used.  That is the same
       still-compiles-but-no-longer-means-it defect this file keeps catching,
       introduced by me and caught by external review.

       This is now the REAL statement: FROM a ThC collision, at the fixed
       challenged member dfC0, on DISTINCT inputs -- i.e. exactly
       SMDTTCRC's winning condition. *)
    /\ (forall (ps : pseed) (tw : adrs) (mm mm' : dgstblock) (j cc : cntr),
          mm' <> mm =>
          ThC ps tw mm j = ThC ps tw mm' cc =>
             emb_in0 (mm, j) <> emb_in0 (mm', cc)
          /\ thfc dfC0 ps (emb_tw tw) (emb_in0 (mm , j ))
           = thfc dfC0 ps (emb_tw tw) (emb_in0 (mm', cc)))
       (* ==== CONCLUSION 6: on the gate-restricted set, MM45's `two_encodings`
               antichain condition holds.

               HONESTY NOTE (2026-07-25, established by running the control
               scratch/trackV_probe_C6_without_N1.ec, which COMPILED): unlike
               conclusions 2-5, THIS conclusion is NOT premise-dependent.  It is
               retained only to display the relationship; it adds NO content here.

               THE VERDICT STANDS BUT ITS STATED REASON WAS STALE, corrected
               2026-09-01.  This note used to read "already derivable from MM45's
               own UNCONDITIONAL `two_encodings` AXIOM (WOTS_TW_ES.ec:571),
               because `encode_msgWOTS d <> encode_msgWOTS d'` forces `d <> d'`".
               Three things in that sentence are false of the certified tree:
                 * `two_encodings` is a LEMMA, not an axiom
                   (base-c10-split/WOTS_TW_ES.ec:726) -- it was demoted when the
                   split base proved it from the concrete `P`, retiring encoding
                   axiom 1;
                 * it is NOT unconditional -- it carries `P m => P m'`;
                 * `:571` resolves inside `chS` in the split file.  That line
                   number is from the OLD unsplit base-c10, where the axiom did
                   live at :579.
               The conclusion is contentless for a SIMPLER reason: `predC` is
               DEFINED as `P` (cdrafts-split/WOTS_C_Real.ec:279,
               `op predC (d : msgWOTS) : bool = P d`), so this conjunct IS the
               current `two_encodings` lemma, restated.  Not a corollary of an
               ambient axiom -- the same statement.
               The INFORMATIVE version is PART B above
               (`constsum_encoding_is_two_encodings`), which is quantified over an
               ARBITRARY encoding E and therefore genuinely shows that a
               CHECKSUM-FREE constant-sum encoding satisfies the antichain
               condition -- a fact the ambient axiom cannot supply. ==== *)
    /\ (forall (d d' : msgWOTS),
          predC d => predC d' => encode_msgWOTS d <> encode_msgWOTS d' =>
          exists (i : int), 0 <= i < len
                 /\ BaseW.val (encode_msgWOTS d).[i] < BaseW.val (encode_msgWOTS d').[i]).
proof.
move=> hcard hemb hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree hN2.
have [hN3 hN4] := c10_deployed_encoder_meets_model hcard hemb.
exact (EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL F mkg_adv mtree_openpre mtree_trh mtree_trco
       &m hc hmkg hencb hdf8n hdflen hdf2 hdfnk htree hN2 hN3 hN4).
qed.

(* ==========================================================================
   ROUND-14 CORRECTIONS (2026-08-03).  Three independent reviewers took the
   Tier-0 work apart.  Two of their findings are not framing problems but
   MISSING THEOREMS, so they are proved here rather than argued in a comment.

   (1) THE "DEPLOYED PARAMETER" PREMISES ARE REDUNDANT.  Confirmed by execution:
   the four dfC0 separations follow from the WIDTH premise ALONE, with n, len
   and k FREE.  dfC0 = 1 + size (emb_in witness) = 8n + 33 = 1 (mod 8), while
   8n, 8n*len, 8n*2 and 8n*k are all = 0 (mod 8) for ANY integers -- the
   argument never looks at 16/43/13.  In EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS
   the premises `n = c10_n`, `len = c10_len`, `k = c10_k` feed ONLY
   c10_dfC_separations_deployed; GROUNDED is applied as `hc hencb hN2 h0 h1 h2 h3`
   and never sees them.  So that theorem holds verbatim with the parameters free,
   and its name promises more than its proof uses.  Stated as a lemma so the
   redundancy is machine-checked instead of asserted.

   (2) THE MUST-FAIL CONTROL IS NOT EVIDENCE OF EXCLUSION.  A control that fails
   to derive "emb_in is constant" would fail just as happily if INJ were deleted:
   failure to prove constancy is not proof of non-constancy, and degeneracy is a
   SATISFIABILITY property that no compile-failure can witness.  The
   discriminating statement is a POSITIVE one, and it breaks if val_inj or the
   two-distinct-blocks fact is ever weakened.
   ========================================================================== *)
lemma c10_dfC_separations_from_width_alone :
     size (emb_in witness) = 8 * n + c10_r
  =>    dfC0 <> 8 * n
     /\ dfC0 <> 8 * n * len
     /\ dfC0 <> 8 * n * 2
     /\ dfC0 <> 8 * n * k.
proof.
  move=> hsz; rewrite /dfC0 emb_in0_size hsz /c10_r; smt().
qed.

lemma c10_embg_not_constant :
  exists (x y : dgstblock * cntr), c10_embg x <> c10_embg y.
proof.
  have [d0 d1 hne] := two_dgstblocks.
  exists (d0, witness) (d1, witness).
  apply/negP => heq.
  have hval : DigestBlock.val d0 = DigestBlock.val d1.
  + by move: heq; rewrite /c10_embg /=; smt(eqseq_cat DigestBlock.valP).
  by move: hne hval; smt(DigestBlock.val_inj).
qed.

lemma c10_deployed_encoder_not_constant :
  emb_in = c10_embg => ! (forall (x y : dgstblock * cntr), emb_in x = emb_in y).
proof.
  move=> heq; have [x y hxy] := c10_embg_not_constant.
  apply/negP => hall.
  by move: hxy; rewrite -heq (hall x y).
qed.
