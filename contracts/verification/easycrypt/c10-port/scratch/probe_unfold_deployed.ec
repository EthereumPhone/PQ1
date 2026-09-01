(* PROBE -- is _Unfolded instantiable at the DEPLOYED adversary R_top_C(F)?
   Scratch only.  Never a closure member. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS XmssmtCC_All RtopCSoundness FxChain GprocFORSC10 GprocVI.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme WOTS_C_Interactive.
require FORS_C10 FORS_C10_Multi DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
require import SphincsC10CapstoneWired.
require import GprocT1Opre GprocT2Trh GprocT3Trco GprocQBound.
require import C10DeployedInstance C10DeployedCapstone.
(* Same import surface the capstone itself opens (SphincsC10CapstoneWired.ec
   :381-387): the lemma statement below is that file's, so it needs that file's
   unqualified names (R_int_STCRC, FSSLXMTWES.*, EmsgWOTS, ...). *)
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

lemma probe_unfold_at_deployed
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
             -EUF_CMA_Gproc_I, -M.F.O_ITSRC10_Default,
             (* WIRED (2026-08-10, Q leg): the nine separations gproc_Q_bound needs.
                Same class as the "WIRED (Step 4)" block above -- F is a
                proof-external forger and these are the Gproc branch game, the
                three branch reductions and their four challengers.  This is
                formally a NARROWING of the hypothesis (it applies to fewer F);
                it is taken deliberately, and it is the price of replacing an
                unreduced Q with three named hardness advantages. *)
             -EUF_CMA_Gproc_V, -R_OPRE_Gproc, -R_TRH_Gproc, -R_TRCO_Gproc,
             -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
             -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
             -FTWES.TRCOC_TCR.O_SMDTTCR_Default, -FTWES.TRCOC.O_THFC_Default,
             (* THE SIX the unfold adds *)
             -FC_UD.O_SMDTUD_Default, -FC_TCR.O_SMDTTCR_Default,
             -FC_PRE.O_SMDTPRE_Default, -R_SMDTUDC_Game23WOTSTWES,
             -R_SMDTTCRC_Game34WOTSTWES, -R_SMDTPREC_Game4WOTSTWES })
  &m :
  true.
proof.
(* (a) the unfold is instantiable at the deployed adversary -- ESTABLISHED *)
have h1 := EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded (R_top_C(F)) &m.
(* (b) can the WOTS bound be applied DIRECTLY at the deployed composed
       adversary?  That is the cheaper route: the deployed theorem carries the
       WOTS game as a SUMMAND, so transitivity alone gives a charged capstone. *)
have h2 := MEUFGCMA_WOTSTWESNPRF_Charged
             (R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))).
trivial.
qed.
