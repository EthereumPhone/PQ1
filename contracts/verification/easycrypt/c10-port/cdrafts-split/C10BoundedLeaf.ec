(* Composition at the actual precomputed leaf reduction. This is its WOTS
   challenge bound, not yet a bounded hypertree forgery theorem. *)
require import AllCore List Distr.
require import C10BoundedMA XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive C10BoundedSigning.

lemma bounded_leaf_choose_ll
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-R_MEUFGCMAWOTSC_EUFNAGCMA_C}) :
  (forall (OC <: FSSLXMTWES.TRHC.Oracle_THFC {-A_ht}),
    islossless OC.query => islossless A_ht(OC).choose) =>
  forall (O <: Oracle_MEUFGCMA_WOTSC {-A_ht, -R_MEUFGCMAWOTSC_EUFNAGCMA_C})
         (OC <: FC.Oracle_THFC {-A_ht, -R_MEUFGCMAWOTSC_EUFNAGCMA_C}),
    islossless O.query => islossless OC.query =>
    islossless R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht, O, OC).choose.
proof.
  move=> A_choose_ll O OC Oll OCll.
  proc.
  while true (d - size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd).
  + move=> z; wp.
    while true (nr_trees (size R_MEUFGCMAWOTSC_EUFNAGCMA_C.pkWOTStd) - size pkWOTSnt).
    - move=> z1; wp.
      while true (h' - size nodes).
      * move=> z2; wp.
        while true (nr_nodesx (size nodes + 1) - size nodescl).
        + move=> z3; by wp; call OCll; auto; smt(size_rcons).
        by auto; smt(size_rcons).
      wp.
      while true (l' - size pkWOTSlp).
      * move=> z2; by wp; call OCll; call Oll; auto; smt(size_rcons).
      by auto; smt(size_rcons).
    by auto; smt(size_rcons).
  wp; call (A_choose_ll OC OCll); by auto; smt().
qed.

lemma bounded_leaf_forge_ll
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF {-R_MEUFGCMAWOTSC_EUFNAGCMA_C}) :
  (forall (OC <: FSSLXMTWES.TRHC.Oracle_THFC {-A_ht}), islossless A_ht(OC).forge) =>
  forall (O <: Oracle_MEUFGCMA_WOTSC {-A_ht, -R_MEUFGCMAWOTSC_EUFNAGCMA_C})
         (OC <: FC.Oracle_THFC {-A_ht, -R_MEUFGCMAWOTSC_EUFNAGCMA_C}),
    islossless R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht, O, OC).forge.
proof.
  move=> A_forge_ll O OC.
  proc; inline *.
  pose dd := d.
  wp.
  while true (dd - size pkWOTSs').
  + move=> z; wp.
    while true (len - size pkWOTS_l).
    - move=> z1; by auto; smt(size_rcons).
    by auto; smt(size_rcons).
  wp; call (A_forge_ll OC); wp.
  while true (l - size sigl).
  + move=> z; wp.
    while true (dd - size sapl).
    - move=> z1; by auto; smt(size_rcons).
    by auto; smt(size_rcons).
  by auto; smt().
qed.

lemma bounded_leaf_member_aware
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
proof.
  move=> hchoose hforge hc hemb henc hdf hdflen hdf2 hwf.
  apply (bounded_interactive_D1_MA (R_MEUFGCMAWOTSC_EUFNAGCMA_C(A_ht)) &m).
  + exact (bounded_leaf_choose_ll A_ht hchoose).
  + exact (bounded_leaf_forge_ll A_ht hforge).
  + exact hc.
  + exact hemb.
  + exact henc.
  exact (R_leaf_C_A_wf_MA A_ht hdf hdflen hdf2 hwf).
qed.
