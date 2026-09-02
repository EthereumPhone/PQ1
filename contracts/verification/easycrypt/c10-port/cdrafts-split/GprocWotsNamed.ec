(* ==========================================================================
   GprocWotsNamed.ec -- the deployed headline with the WOTS-TW GAME NAMED.
   Landed 2026-09-01.

   WHAT IT IS.  `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS`
   (GprocChargedQWired.ec:341) is this artifact's recommended quotation surface,
   and it carries `Pr[M_EUF_GCMA_WOTSTWESNPRF ..]` as ONE OPAQUE GAME.  The
   theorem below is that statement with the opaque game replaced by the FOUR
   NAMED terms of `WotsLegCharged.ec::wots_leg_charged_at_deployed`:
   UD / TCR / PRE / encoding-collision.  Proof: transitivity, nothing else.

   THE PROHIBITION THIS SUPERSEDES, and why it is no longer binding.
   GprocChargedQWired.ec:39-42 says, of exactly this move:
       "Reducing it ... must NOT be done by applying the existing WOTS theorem,
        which consumes the admit at base-c10-split/WOTS_TW_ES.ec:1513 and would
        make a presently non-load-bearing admit LOAD-BEARING."
   That was correct when written and has had NO ADDRESSEE since 2026-08-30: the
   admit at :1513 was REMOVED, not contained, and what is applied here is the
   CHARGED theorem, which is admit-free.  The note has been corrected in place.

   PARALLEL, NOT AN EDIT.  GprocChargedQWired.ec's own PLACEMENT note takes a new
   file rather than editing its predecessor, so both surfaces stay quotable.  Same
   here: the 2-premise deployed statement is untouched and remains the thing to
   quote when the extra premises are not wanted.

   THE PRICE: premises 2 -> 4.  Six extra module separations on F (a NARROWING),
   GRIND REACHABILITY, and forger losslessness -- all three inherited verbatim
   from WotsLegCharged.ec, whose header explains each.  Quote the older statement
   unless you specifically want the WOTS leg named.

   IT BOUNDS NOTHING.  Four named terms in place of one opaque game is
   assumption-surface progress, not a number.  `Pr[M.F.ITSRC10 ..]` is still
   carried unreduced and is still the honest headline blocker; the new
   encoding-collision term is ALSO unreduced, and `badenc_is_one` does NOT bound
   it at this composed adversary.

   CONTROLS: scratch/gwn_ctl{A,B}.ec drop the charged WOTS leg and the deployed
   statement respectively from the composition.  Both MUST fail -- and the FIRST
   is the one that matters: if the composition still went through without the
   charged leg, the substitution would be doing nothing.
   ========================================================================== *)
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
require import GprocChargedQWired WotsLegCharged.

lemma EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS_WOTSNAMED
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
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default,
             (* the six WOTS-TW internals the charged leg needs -- a NARROWING *)
             -FC_UD.O_SMDTUD_Default, -FC_TCR.O_SMDTTCR_Default,
             -FC_PRE.O_SMDTPRE_Default, -R_SMDTUDC_Game23WOTSTWES,
             -R_SMDTTCRC_Game34WOTSTWES, -R_SMDTPREC_Game4WOTSTWES })
  &m :
     (* GRIND REACHABILITY -- the "+C" grind assumption, made explicit.  See
        WotsLegCharged.ec's header for why nothing in the closure supplies it. *)
     (forall (m : msg), is_lossless (dcond dmkey (good_fors m))) =>
     (forall (O <: SOracle_CMA_C{-F}), islossless O.sign => islossless F(O).forge) =>
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
       + ( (* ---- the WOTS-TW game, NAMED (was one opaque Pr[..]) ---- *)
             (   (w - 2)%r
                 * `|Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(false) @ &m : res]
                     - Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(true) @ &m : res]|
               + Pr[FC_TCR.SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_TCR.O_SMDTTCR_Default, FC.O_THFC_Default).main() @ &m : res]
               + ( Pr[FC_PRE.SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
                        FC_PRE.O_SMDTPRE_Default, FC.O_THFC_Default).main() @ &m : res]
                 + Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))).main() @ &m
                        : res /\ BadEncFlag.badenc] ) )
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
move=> hgrind Fll hc hsz.
have h1 := EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS F &m hc hsz.
have h2 := wots_leg_charged_at_deployed F &m hgrind Fll.
smt().
qed.
