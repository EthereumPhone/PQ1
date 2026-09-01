(* #########################################################################
   SKELETON PROBE -- contains `admit`.  NEVER PROMOTE OR VENDOR AS A RESULT.
   Purpose: validate that the CHARGED WOTS LEG can be stated and applied at the
   DEPLOYED adversary, so the only remaining work is the losslessness discharge.
   ######################################################################### *)
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

(* The missing piece: the deployed WOTS leg, CHARGED.
   Losslessness is taken as an explicit premise HERE so the skeleton can be
   validated independently; discharging it from F is the next step. *)
lemma wots_leg_charged_at_deployed
  (F <: Adv_EUFCMA_C{ -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V, -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default,
             -R_top, -R_top_C,
             -FC_UD.O_SMDTUD_Default, -FC_TCR.O_SMDTTCR_Default,
             -FC_PRE.O_SMDTPRE_Default, -R_SMDTUDC_Game23WOTSTWES,
             -R_SMDTTCRC_Game34WOTSTWES, -R_SMDTPREC_Game4WOTSTWES }) &m :
    Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
 <=   (w - 2)%r
      * `|Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(
             R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
             FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(false) @ &m : res]
          - Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(
             R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
             FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(true) @ &m : res]|
    + Pr[FC_TCR.SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(
             R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
             FC_TCR.O_SMDTTCR_Default, FC.O_THFC_Default).main() @ &m : res]
    + ( Pr[FC_PRE.SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(
             R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))),
             FC_PRE.O_SMDTPRE_Default, FC.O_THFC_Default).main() @ &m : res]
      + Pr[Game4_WOTSTWES_BadEnc(
             R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))).main() @ &m
             : res /\ BadEncFlag.badenc] ).
proof.
apply (MEUFGCMA_WOTSTWESNPRF_Charged
         (R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F)))) _ _ &m).
+ admit. (* OBLIGATION 1: choose lossless *)
+ admit. (* OBLIGATION 2: forge lossless *)
qed.
