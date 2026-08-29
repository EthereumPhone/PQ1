(* ===========================================================================
   THE CHARGED, Q-WIRED CAPSTONE.

   WHAT THIS IS.  The composition of the two independent improvements the port
   already had but had never combined:

     * SphincsC10CapstoneCharged.ec:78  EUFCMA_SPHINCS_PLUS_C10_CHARGED
         -- N2-FREE.  The universal premise `exists c, predC (ThC ps ad m c)`
            (capstone premise N2) is GONE from that statement; the grind can fail,
            and the failure is CHARGED as an explicit summand
            `Pr[GAME1_INT(..) : res /\ gfail_of ..]` (its +C subst #3).
     * GprocQBound.ec:62  gproc_Q_bound
         -- replaces the unreduced Q = Pr[EUF_CMA_Gproc_I .. res /\ !covered]
            with THREE NAMED hardness advantages (one SM-DT-OpenPRE, two
            SM-DT-TCR-C).

   CHARGED carries the Q term as a PREMISE over three forall-bound reals
   (`mtree_openpre mtree_trh mtree_trco`), exactly as EUFCMA_SPHINCS_PLUS_C10
   does.  So the composition is the same five-line move GprocQWired.ec:67 makes
   on the GROUNDED capstone -- instantiate the three reals at the named terms and
   discharge the premise with gproc_Q_bound.

   WHY IT IS WORTH A FILE.  Before this, the port forced a choice: quote the
   CHARGED capstone and carry an unreduced Q, or quote the QWIRED capstone and
   carry the universal N2 premise.  Neither dominated.  This lemma has both
   improvements at once and is therefore the strongest deployed-shape statement
   the closure supports.

   WHAT IT DOES **NOT** BUY, stated as flatly as its siblings do.
     * Nothing numeric improves.  `Pr[M.F.ITSRC10 ..]` is still carried UNREDUCED
       and remains the honest headline term; scratch/_countermodel.ec proves no
       parameter-independent bound on it is provable as that game is axiomatized.
     * The WOTS-TW game `Pr[M_EUF_GCMA_WOTSTWESNPRF ..]` is still carried as an
       unreduced GAME probability.  Reducing it is the separate collision
       campaign, and it must NOT be done by applying the existing WOTS theorem,
       which consumes the admit at base-c10-split/WOTS_TW_ES.ec:1513 and would
       make a presently non-load-bearing admit LOAD-BEARING.
     * It activates NEITHER of the closure's two admits.
     * The grind-failure summand is an AVAILABILITY charge, not a security loss;
       see experiments/tcollres-leg/FINDING-n2-is-independent.md section 5.  It is
       carried here because CHARGED carries it, and carrying it is what buys the
       removal of N2.

   PLACEMENT.  A NEW file, not an edit to SphincsC10CapstoneCharged.ec or
   GprocQWired.ec.  Same reason GprocQWired gave: this NARROWS F (it adds the nine
   Q-leg separations gproc_Q_bound needs) AND replaces an exact premise with an
   upper bound, so mutating a published theorem name would hide both changes
   behind an unchanged name.  The repo's precedent is parallel-supersede
   (cert_gate_split.sh:425-426).  Dependency runs FORWARD along closure order
   (SphincsC10CapstoneCharged #21, GprocQBound #28 -> here).
   =========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS XmssmtCC_All RtopCSoundness FxChain GprocFORSC10 GprocVI.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme WOTS_C_Interactive.
require FORS_C10 FORS_C10_Multi DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
require import GFailCharged XmssmtCCCharged SphincsC10CapstoneCharged.
require import GprocT1Opre GprocT2Trh GprocT3Trco GprocQBound.
require import GprocQWired.   (* reuse its WitnessF for the anti-vacuity check *)
(* c10_n / c10_len / c10_k / c10_r for the DEPLOYED variant below.  Same import
   GprocQWired.ec:55 uses, and both files are ALREADY closure members, so this adds
   no new file to the cone -- verified after the edit (CONE_FILES stays 45). *)
require import C10DeployedInstance.
(* for c10_dfC_separations_from_width_alone -- the four dfC0 separations WITHOUT the
   redundant n/len/k premises.  C10DeployedCapstone is already a certified root and is
   already in the 45-file cone, so this adds no cone file. *)
require import C10DeployedCapstone.

import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

lemma EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* the nine Q-leg separations gproc_Q_bound needs -- identical to the
                block GprocQWired.ec carries, and a deliberate NARROWING of F. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default })
  (mkg_adv : real)
  &m :
    c <= p_tgts =>
    0%r <= mkg_adv =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>
    Pr[EUFCMA_C10(F).main() @ &m : res]
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       + mkg_adv
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                    FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                    FTWES.TRHC_TCR.O_SMDTTCR_Default,
                    FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                    FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                    FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
           + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)),
                          O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
                  res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                                  O_MEUFGCMA_WOTSC_Default.qs] ).
proof.
move=> hc hmkg hdf8n hdflen hdf2 hdfnk.
have h := EUFCMA_SPHINCS_PLUS_C10_CHARGED F mkg_adv
            Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                 FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
            Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                 FTWES.TRHC_TCR.O_SMDTTCR_Default,
                 FTWES.TRHC.O_THFC_Default).main() @ &m : res]
            Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                 FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                 FTWES.TRCOC.O_THFC_Default).main() @ &m : res]
            &m hc hmkg encode_msgWOTS_C_compat hdf8n hdflen hdf2 hdfnk _.
+ by apply (gproc_Q_bound (R_fors_p(F)) &m).
by smt().
qed.

(* ---------------------------------------------------------------------------
   ANTI-VACUITY.  The statement above NARROWS F by the nine Q-leg separations on
   top of CHARGED's already-long list.  A module-restriction set that no module
   satisfies would make the lemma vacuously true, so exhibit an inhabitant:
   GprocQWired.ec's `WitnessF`, which is STATEFUL and CALLS its oracle (it is not
   the degenerate do-nothing forger).  If any separation in the union were
   self-contradictory, the instantiation below would fail to typecheck.

   HONEST SCOPE, and it is the same caveat GprocQWired.ec:171-196 records for its
   own witness: this establishes MODULE-RESTRICTION SATISFIABILITY, not
   cryptographic non-vacuity.  `WitnessF` returns the message it just signed, so
   EUF-CMA freshness fails and its LHS success probability is ZERO.  It proves the
   hypothesis set is inhabited; it does not prove the bound is tight or the RHS
   non-trivial.  (Point made by GPT-5.6 adversarial review, 2026-08-11.)         *)
lemma charged_qwired_at_witness (mkg_adv : real) &m :
    c <= p_tgts =>
    0%r <= mkg_adv =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>
    Pr[EUFCMA_C10(WitnessF).main() @ &m : res]
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(WitnessF), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       + mkg_adv
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(WitnessF)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(WitnessF)),
                    FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(WitnessF)),
                    FTWES.TRHC_TCR.O_SMDTTCR_Default,
                    FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(WitnessF)),
                    FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                    FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(WitnessF)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(WitnessF)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
           + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(WitnessF)),
                          O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
                  res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                                  O_MEUFGCMA_WOTSC_Default.qs] ).
proof.
by apply (EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED WitnessF mkg_adv &m).
qed.


(* ==========================================================================
   H1 RESOLVED -- THE PHANTOM `mkg_adv` SUMMAND IS DROPPED.

   FxChain.ec:2824-2834 records this as an OPEN ACCOUNTING HAZARD against the
   capstone, in its own words:

     "hop3 : p_nprfprf <= p_nprfnprf + mkg_adv  (admit; mkg_adv a FREE real).
      Once the in-chain step is recognised as the identity (p_nprfprf =
      p_nprfnprf), mkg_adv becomes a PHANTOM summand: sound as an upper bound
      but silently zeroable by a consumer, and double-paying if kept alongside
      the already-idealised dcond LHS.  Honest fix: drop mkg_adv from the +C FX
      PRF-term sum ...  Do NOT leave it as an in-chain MKG-PRF summand."

   The headline still carried it.  This discharges it, and the discharge is
   TRIVIAL because of how the term enters: `mkg_adv` is a LEMMA PARAMETER --
   universally quantified, constrained only by `0%r <= mkg_adv`.  A statement
   holding for EVERY admissible value holds at 0, and 0 is the tightest
   admissible value, so instantiating there is sound and yields a STRICTLY
   TIGHTER bound with one FEWER premise and NO free real.  The hazard the
   comment names -- "silently zeroable by a consumer" -- is closed by doing the
   zeroing here, visibly, instead of leaving it available to whoever quotes the
   theorem.

   WHAT THIS DOES *NOT* MEAN, and the same comment is explicit about it:
   "WHERE THE GENUINE mkg TERM LIVES (it is NOT zero)".  The real RO-idealisation
   cost sits at the MODEL-DEFINITION / pre-hop-1 boundary -- the keyed salted
   grinder of production (sphincs-c10/src/fors.rs nonce loop) idealised to the
   uniform-conditioned `dcond` draw -- NOT between NPRFPRF and NPRFNPRF.  Dropping
   the in-chain summand does NOT make that idealisation free; it stops the chain
   DOUBLE-PAYING for something already priced in the model definition.  The
   boundary idealisation remains an open, documented assumption
   (sphincs_c10_scheme_wip.ec:52-67, FORS_C10.ec:52-54).

   STATEMENT DERIVED MECHANICALLY, not retyped: the parameter, the premise and
   the summand were deleted from EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED by
   script, with an assertion that no `mkg_adv` token survives.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* the nine Q-leg separations gproc_Q_bound needs -- identical to the
                block GprocQWired.ec carries, and a deliberate NARROWING of F. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default })
  &m :
    c <= p_tgts =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    dfC0 <> 8 * n * k =>
    Pr[EUFCMA_C10(F).main() @ &m : res]
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                    FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                    FTWES.TRHC_TCR.O_SMDTTCR_Default,
                    FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                    FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                    FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
           + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)),
                          O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
                  res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                                  O_MEUFGCMA_WOTSC_Default.qs] ).
proof.
move=> hc hd1 hd2 hd3 hd4.
have h := EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED F 0%r &m hc _ hd1 hd2 hd3 hd4; first by [].
smt().
qed.


(* ==========================================================================
   THE CLEAN STATEMENT, AT DEPLOYED PARAMETERS.

   GAP THIS CLOSES.  Surveying the capstone family, EVERY deployed variant
   carried N2 -- AT_DEPLOYED_PARAMS, AT_DEPLOYED_PARAMS_PINNED_ENCODER, and both
   of their QWIRED forms -- while the only statement free of N2, of Q and of the
   free real `mkg_adv` (CHARGED_QWIRED_TIGHT) was NOT deployed.  So the surface
   the product actually quotes, at C10's pinned parameters, was strictly WEAKER
   than the abstract headline.  This is the first deployed statement that is
   N2-free AND Q-free AND free-real-free.

   WHAT IS AND IS NOT TRADED -- CORRECTED 2026-08-27.  This paragraph used to read:
   "The four ABSTRACT width disequalities are DISCHARGED here by
   c10_dfC_separations_deployed (C10DeployedInstance.ec:294) from the four DEPLOYED
   parameter pins.  That is a trade, not an elimination: the premise count is
   unchanged at 6.  What it buys is that the remaining premises are about DEPLOYED
   PARAMETERS -- n = 16, len = 43, k = 13, and the embedding width."
   THAT WAS TRUE OF THE PROOF AS WRITTEN AND IT DID NOT HAVE TO BE.  The four dfC0
   separations DO NOT NEED n, len or k at all: the argument is MOD 8 --
   dfC0 = 8n + 33 = 1 (mod 8) while 8n, 8n*len, 8n*2 and 8n*k are 0 (mod 8) for ANY
   integers -- so it never looks at 16/43/13.  This tree recorded exactly that on
   2026-08-03 (C10DeployedCapstone.ec:407, "its name promises more than its proof
   uses") and proved `c10_dfC_separations_from_width_alone` for it.  When this lemma
   was written on 2026-08-24 I reached for the variant WITH the premises anyway.
   That was MY MISS, not a gap in the tree, and it is fixed here.

   SO IT IS NOW AN ELIMINATION, NOT A TRADE: 5 premises -> 2.  And the two that
   remain are DIFFERENT IN KIND, which the old paragraph's "n = 16, len = 43,
   k = 13, and the embedding width" phrasing hid:
     * `c <= p_tgts` is a PARAMETER CHOICE, satisfiable by construction;
     * `size (emb_in witness) = 8*n + c10_r` is a CONSTRAINT ON A FREE OP
       (`emb_in` is abstract-op:f718c0661391, unpinned anywhere in the closure).
   The second is the artifact's least visible real assumption.  Do not describe the
   deployed statement as having "one substantive premise": it has two.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* the nine Q-leg separations gproc_Q_bound needs -- identical to the
                block GprocQWired.ec carries, and a deliberate NARROWING of F. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default })
  &m :
    c <= p_tgts =>
    (* THE THREE DEPLOYED-PARAMETER PREMISES ARE GONE (2026-08-27).  They were
       REDUNDANT and this tree already knew it: C10DeployedCapstone.ec:407 records
       "the four dfC0 separations follow from the WIDTH premise ALONE, with n, len and
       k FREE ... its name promises more than its proof uses", and proves
       `c10_dfC_separations_from_width_alone` for exactly that.  The separations are a
       MOD-8 argument -- dfC0 = 8n+33 = 1 (mod 8) while 8n, 8n*len, 8n*2, 8n*k are all
       0 (mod 8) for ANY integers -- so it never looks at 16/43/13.  When this lemma was
       written on 2026-08-24 it reached for `c10_dfC_separations_deployed` (the variant
       WITH the premises) instead; that was my miss, not a gap in the tree.
       WHAT REMAINS IS TWO PREMISES, AND THEY DIFFER IN KIND:
         * `c <= p_tgts`                     -- a PARAMETER CHOICE (the SM-DT-TCR game
           must be given at least as many targets as there are instances); the tree
           classifies it as not-a-theorem-and-not-meant-to-be (C10DeployedGeometry.ec:468).
         * `size (emb_in witness) = 8*n + c10_r` -- a genuine CONSTRAINT ON A FREE OP.
           `emb_in` is abstract-op:f718c0661391; nothing in the closure pins its width.
           This is the artifact's least visible real assumption. *)
    size (emb_in witness) = 8 * n + c10_r =>   (* NODE || u32 counter *)
    Pr[EUFCMA_C10(F).main() @ &m : res]
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                    FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                    FTWES.TRHC_TCR.O_SMDTTCR_Default,
                    FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                    FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                    FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
           + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)),
                          O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
                  res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                                  O_MEUFGCMA_WOTSC_Default.qs] ).

proof.
(* Binder order follows the STATEMENT: `c <= p_tgts` (inherited from the parent) then
   the single width fact.  TWO premises now, not six.  The encode equation was a premise
   here until 2026-08-25 and is discharged by `encode_msgWOTS_C_compat`
   (WOTS_C_Real.ec); the n/len/k pins were premises until 2026-08-27 and are gone
   because the dfC0 separations never needed them.  History kept because it is the
   reason the binder list looks nothing like it did when first written:
   the first attempt used AT_DEPLOYED_PARAMS_QWIRED's order and misaligned every name:
   `hc` was fed where `n = c10_n` was expected.  EasyCrypt reported it precisely --
   "this proof-term proves: c <= p_tgts / but is expected to prove: n = c10_n" -- so
   this is read off the error, not guessed. *)
move=> hc hsz.
have [# h0 h1 h2 h3] := c10_dfC_separations_from_width_alone hsz.
exact (EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT F &m hc h0 h1 h2 h3).
qed.

(* ==========================================================================
   THE SAME STATEMENT WITH THE ENCODER PINNED, NOT MERELY WIDTH-CONSTRAINED.

   WHY THIS EXISTS, and it is NOT a cosmetic re-spelling.  _AT_PINNED_ENCODER and
   _AT_DEPLOYED_PARAMS both carry TWO premises, but they are not equally informative.
   `size (emb_in witness) = 8*n + c10_r` is DEGENERATELY SATISFIABLE, and this tree
   says so at C10DeployedInstance.ec:322 (adversarial review, 2026-08-01):

     "a CONSTANT `emb_in` satisfies it while collapsing every ThC input and making
      the S-TCR term trivially winnable."

   A constant encoder does not make the bound FALSE -- it makes it UNINFORMATIVE, by
   sending the S-TCR summand to ~1.  Pinning `emb_in = c10_embg` excludes exactly those
   models: `c10_embg_not_constant` (C10DeployedCapstone.ec) is proved PREMISE-FREE, and
   `c10_embg_inj` gives injectivity given the counter-space bound
   `STCRC_WC.G.CntrFT.card <= 2 ^ c10_r`.

   BUT THE PIN DOES NOT RESCUE THE S-TCR TERM, and an earlier draft of this comment implied
   it did.  ATTRIBUTION, corrected 2026-08-29: Kimi K3 surfaced this to me on 2026-08-27,
   but THIS TREE ALREADY RECORDED IT at C10DeployedInstance.ec:485-488 -- "Pinning `emb_in`
   moved the collapse ONE COMPOSITION STEP; it did not remove it."  I should have found that
   when I built this variant.  Verified independently: `thfc` is declared
   with ZERO AXIOMS (SPHINCS_PLUS.ec:488; no axiom row in the census mentions it).  Since
   `ThC = join_dgst (thfc ..) (thfc ..)`, the interpretation `thfc := const` STILL collapses
   every ThC input even with `emb_in` pinned.  The degeneracy simply moves ONE COMPOSITION
   STEP DOWN.  What this variant buys is therefore narrower than "non-degeneracy": it
   excludes degeneracy VIA `emb_in`, and says nothing about degeneracy via `thfc`.
   Do not describe it as making the S-TCR term meaningful.

   WHAT IT COSTS, stated plainly.  `emb_in = c10_embg` is a STRICTLY STRONGER premise
   than the width fact, so this theorem covers FEWER models than _AT_DEPLOYED_PARAMS.
   Neither supersedes the other: the width form is more general, this one is more
   informative.  Both are gated; quote whichever the claim needs.

   AND WHAT IT DOES *NOT* BUY -- CORRECTED 2026-08-29, and the correction is this tree's
   own, from 2026-08-03.  An earlier draft said the pin moves the assumption to "THIS
   SPECIFIC ENCODER".  IT DOES NOT.  C10DeployedCapstone.ec:150-156 and
   C10DeployedInstance.ec:489-493 already record why, after a round-14 review by GPT-5.6
   and Opus 5:

     `c10_embg` serialises the counter's RANK IN AN ARBITRARY ENUMERATION
     (`int2bs c10_r (index x.`2 CntrFT.enum)`), and `cntr` is an ABSTRACT FinType whose
     cardinality NO AXIOM BOUNDS.  A SINGLETON COUNTER SATISFIES EVERY PREMISE.  Nothing
     pins cardinality, enumeration order, numeric meaning or byte order.

   So the pin buys an INJECTIVE RANK ENCODER OF THE RIGHT SHAPE -- not the firmware's
   big-endian u32 inside a 32-byte slot (sphincs-c10/src/hash.rs:350-363).  It excludes
   the constant-encoder collapse and nothing more.  Do not call it "the deployed encoder",
   and do not describe it as something a reader can check against the Rust: the object
   pinned is not that object.

   STATEMENT DERIVED MECHANICALLY from _AT_DEPLOYED_PARAMS by script -- the width premise
   replaced by the encoder pin, with an assertion that no `size (emb_in` premise survives.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_PINNED_ENCODER
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* the nine Q-leg separations gproc_Q_bound needs -- identical to the
                block GprocQWired.ec carries, and a deliberate NARROWING of F. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default })
  &m :
    c <= p_tgts =>
    (* TWO PREMISES, AND THEY DIFFER IN KIND:
         * `c <= p_tgts`      -- a PARAMETER CHOICE (the SM-DT-TCR game must be given at
           least as many targets as there are instances); this tree classifies it as
           not-a-theorem-and-not-meant-to-be (C10DeployedGeometry.ec:468).
         * `emb_in = c10_embg` -- pins the SERIALISATION ITSELF.  Strictly stronger than
           the width fact the sibling assumes, and deliberately so: the width fact is
           DEGENERATELY SATISFIABLE by a constant encoder (C10DeployedInstance.ec:322),
           which collapses every ThC input and sends the S-TCR summand to ~1.  See
           `pinned_encoder_is_not_degenerate` below -- that exclusion is a THEOREM here,
           not a comment. *)
    emb_in = c10_embg =>   (* the encoder itself, not merely its width *)
    Pr[EUFCMA_C10(F).main() @ &m : res]
      <= `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
           - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA_C(F), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
       + ( Pr[M.F.ITSRC10(R_ITSRC10_Gproc(R_fors_p(F)),
                          M.F.O_ITSRC10_Default).main() @ &m : res]
           + ( Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(R_fors_p(F)),
                    FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
             + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(R_fors_p(F)),
                    FTWES.TRHC_TCR.O_SMDTTCR_Default,
                    FTWES.TRHC.O_THFC_Default).main() @ &m : res]
             + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(R_fors_p(F)),
                    FTWES.TRCOC_TCR.O_SMDTTCR_Default,
                    FTWES.TRCOC.O_THFC_Default).main() @ &m : res] ) )
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
           + Pr[GAME1_INT(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)),
                          O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
                  res /\ gfail_of O_MEUFGCMA_WOTSC_Default.ps
                                  O_MEUFGCMA_WOTSC_Default.qs] ).

proof.
(* Two premises, same count as _AT_DEPLOYED_PARAMS -- but the WIDTH fact is DERIVED here
   rather than assumed, from the premise-free `c10_embg_size`. *)
move=> hc hemb.
have hsz : size (emb_in witness) = 8 * n + c10_r by rewrite hemb c10_embg_size.
have [# h0 h1 h2 h3] := c10_dfC_separations_from_width_alone hsz.
exact (EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT F &m hc h0 h1 h2 h3).
qed.

(* ANTI-VACUITY RECEIPT for the premise above.  The whole point of pinning the encoder
   rather than its width is to exclude the degenerate constant model; a comment saying so
   is not evidence.  This is the exclusion, machine-checked, and it needs NO side
   condition -- `c10_embg_not_constant` is proved premise-free.
   HONEST SCOPE: this rules out the CONSTANT encoder.  Full injectivity additionally
   needs the counter-space bound and is `c10_embg_inj` / `c10_embg_meets_LEN_and_INJ`
   (C10DeployedInstance.ec), not restated here. *)
lemma pinned_encoder_is_not_degenerate :
  emb_in = c10_embg => exists (x y : dgstblock * cntr), emb_in x <> emb_in y.
proof. by move=> hemb; rewrite hemb; exact c10_embg_not_constant. qed.
