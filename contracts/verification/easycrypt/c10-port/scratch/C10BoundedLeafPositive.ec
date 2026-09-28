(* Composition at the actual precomputed leaf reduction. This is its WOTS
   challenge bound, not yet a bounded hypertree forgery theorem. *)
require import AllCore List Distr.
require import C10BoundedLeaf C10BoundedMA XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive C10BoundedSigning.

lemma checked_leaf_member_aware
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-R_int_STCRC, -R_int_WOTSTW,
    -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
    -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
    -O_Bounded, -R_MEUFGCMAWOTSC_EUFNAGCMA_C}) &m :
  (forall (OC <: FSSLXMTWES.TRHC.Oracle_THFC {-A_ht}),
    islossless OC.query => islossless A_ht(OC).choose) =>
  (forall (OC <: FSSLXMTWES.TRHC.Oracle_THFC {-A_ht}), islossless A_ht(OC).forge) =>
  c <= p_tgts =>
  (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
  (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
    encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
  dfC0 <> 8 * n => dfC0 <> 8 * n * len => dfC0 <> 8 * n * 2 =>
  hoare[A_ht(O_THFC_MA).choose : O_THFC_MA.tws_ma = [] ==>
    all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma] =>
  Pr[BoundedGame(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)).main() @ &m : res] <=
    Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res] +
    Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)),
      STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof. exact (bounded_leaf_member_aware A_ht &m). qed.
