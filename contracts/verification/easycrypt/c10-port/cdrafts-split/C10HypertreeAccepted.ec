(* Four-term bounded hypertree bound with no universal reachability premise and no grind-failure charge. RHS reductions use a transparent transcript observer. No numerical challenge bound or costed shared-oracle simulation is claimed. *)
require import AllCore List C10HypertreeCorrect XmssmtCC_All Distr StdOrder C10AcceptedReduction C10BoundedHypertree C10BoundedMA GFailCharged WOTS_C_Interactive.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive.

section.
declare module A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF
  {-Observe,-R_SMDTTCRCPKCO_C,-R_SMDTTCRCTRH_C,-PKCOC.O_THFC_Default,-TRHC.O_THFC_Default}.

lemma pkco_oracle_observation :
  equiv[A(R_SMDTTCRCPKCO_C(Observe(A),PKCOC_TCR.O_SMDTTCR_Default,PKCOC.O_THFC_Default).O_THFC).choose ~
        A(R_SMDTTCRCPKCO_C(A,PKCOC_TCR.O_SMDTTCR_Default,PKCOC.O_THFC_Default).O_THFC).choose :
    ={glob A,glob PKCOC.O_THFC_Default,R_SMDTTCRCPKCO_C.O_THFC.ads,R_SMDTTCRCPKCO_C.O_THFC.xs} ==>
    ={glob A,glob PKCOC.O_THFC_Default,R_SMDTTCRCPKCO_C.O_THFC.ads,R_SMDTTCRCPKCO_C.O_THFC.xs}].
proof.
  proc (={glob PKCOC.O_THFC_Default,R_SMDTTCRCPKCO_C.O_THFC.ads,R_SMDTTCRCPKCO_C.O_THFC.xs}) => //.
  by proc; inline *; auto.
qed.

lemma trh_oracle_observation :
  equiv[A(R_SMDTTCRCTRH_C(Observe(A),TRHC_TCR.O_SMDTTCR_Default,TRHC.O_THFC_Default).O_THFC).choose ~
        A(R_SMDTTCRCTRH_C(A,TRHC_TCR.O_SMDTTCR_Default,TRHC.O_THFC_Default).O_THFC).choose :
    ={glob A,glob TRHC.O_THFC_Default,R_SMDTTCRCTRH_C.O_THFC.ads,R_SMDTTCRCTRH_C.O_THFC.xs} ==>
    ={glob A,glob TRHC.O_THFC_Default,R_SMDTTCRCTRH_C.O_THFC.ads,R_SMDTTCRCTRH_C.O_THFC.xs}].
proof.
  proc (={glob TRHC.O_THFC_Default,R_SMDTTCRCTRH_C.O_THFC.ads,R_SMDTTCRCTRH_C.O_THFC.xs}) => //.
  by proc; inline *; auto.
qed.

lemma observed_pkco_choose :
  hoare[A(R_SMDTTCRCPKCO_C(A,PKCOC_TCR.O_SMDTTCR_Default,PKCOC.O_THFC_Default).O_THFC).choose :
    R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads] =>
  hoare[Observe(A,R_SMDTTCRCPKCO_C(Observe(A),PKCOC_TCR.O_SMDTTCR_Default,PKCOC.O_THFC_Default).O_THFC).choose :
    R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads].
proof.
  move=> hpk; proc; call (_ : R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads).
  + conseq pkco_oracle_observation hpk.
    - move=> &m hp; exists (glob A){m} R_SMDTTCRCPKCO_C.O_THFC.ads{m}
        R_SMDTTCRCPKCO_C.O_THFC.xs{m} PKCOC.O_THFC_Default.pp{m} PKCOC.O_THFC_Default.tws{m}; smt().
    by smt().
  by auto.
qed.

lemma observed_trh_choose :
  hoare[A(R_SMDTTCRCTRH_C(A,TRHC_TCR.O_SMDTTCR_Default,TRHC.O_THFC_Default).O_THFC).choose :
    R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads] =>
  hoare[Observe(A,R_SMDTTCRCTRH_C(Observe(A),TRHC_TCR.O_SMDTTCR_Default,TRHC.O_THFC_Default).O_THFC).choose :
    R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads].
proof.
  move=> htr; proc; call (_ : R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads).
  + conseq trh_oracle_observation htr.
    - move=> &m hp; exists (glob A){m} R_SMDTTCRCTRH_C.O_THFC.ads{m}
        R_SMDTTCRCTRH_C.O_THFC.xs{m} TRHC.O_THFC_Default.pp{m} TRHC.O_THFC_Default.tws{m}; smt().
    by smt().
  by auto.
qed.
end section.

lemma bounded_hypertree_accepted
  (A_ht <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF{ -Observe, -R_int_STCRC, -R_int_WOTSTW,
             -O_MEUFGCMA_WOTSC_Default, -O_MEUFGCMA_WOTSTWESNPRF,
             -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT,
             -R_MEUFGCMAWOTSC_EUFNAGCMA_C, -EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C,
             -O_MEUFGCMA_WOTSC_V,
             -R_SMDTTCRCPKCO_C, -R_SMDTTCRCTRH_C,
             -FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.PKCOC.O_THFC_Default,
             -FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, -FSSLXMTWES.TRHC.O_THFC_Default }) &m :
    islossless A_ht(FC.O_THFC_Default).forge =>
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    dfC0 <> 8 * n =>
    dfC0 <> 8 * n * len =>
    dfC0 <> 8 * n * 2 =>
    hoare[ A_ht(O_THFC_MA).choose :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    hoare[ A_ht(FC.O_THFC_Default).choose :
             FC.O_THFC_Default.tws = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws ] =>
    hoare[ A_ht(R_SMDTTCRCPKCO_C(A_ht, FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                                 FSSLXMTWES.PKCOC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads ] =>
    hoare[ A_ht(R_SMDTTCRCTRH_C(A_ht, FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                                FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
             R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
             all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads ] =>
    Pr[BoundedHypertreeGame(A_ht, FC.O_THFC_Default).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A_ht))),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A_ht))),
                         STCRC_WC.O_STCRC_Default).main() @ &m : res]
     + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(Observe(A_ht)),
            FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
            FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
     + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(Observe(A_ht)),
            FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
            FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
  move=> hll hc hemb henc hd0 hdlen hd2 hwf hch hpk htr.
  have hwfO : hoare[Observe(A_ht,O_THFC_MA).choose :
    O_THFC_MA.tws_ma = [] ==> all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma].
  + by proc; call hwf; auto.
  have hchO : hoare[Observe(A_ht,FC.O_THFC_Default).choose :
    FC.O_THFC_Default.tws = [] ==> all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws].
  + by proc; call hch; auto.
  have hpkO : hoare[Observe(A_ht,R_SMDTTCRCPKCO_C(Observe(A_ht),
    FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,FSSLXMTWES.PKCOC.O_THFC_Default).O_THFC).choose :
    R_SMDTTCRCPKCO_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_C.O_THFC.ads].
  + exact (observed_pkco_choose A_ht hpk).
  have htrO : hoare[Observe(A_ht,R_SMDTTCRCTRH_C(Observe(A_ht),
    FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,FSSLXMTWES.TRHC.O_THFC_Default).O_THFC).choose :
    R_SMDTTCRCTRH_C.O_THFC.ads = [] ==>
    all (fun (ad : adrs) => get_typeidx ad <> trhxtype) R_SMDTTCRCTRH_C.O_THFC.ads].
  + exact (observed_trh_choose A_ht htr).
  have hwleaf := R_leaf_C_A_wf_MA (Observe(A_ht)) hd0 hdlen hd2 hwfO.
  have hb := C10HypertreeCorrect.bounded_win_le_total_good A_ht &m hll.
  have heq := EqPr_EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Orig_V_event
    (Observe(A_ht)) FC.O_THFC_Default observed_good &m.
  rewrite /observed_good /= in heq.
  have hs := seam_branch1_WOTSC_event (Observe(A_ht)) observed_good &m
    hc hemb henc hd0 hdlen hd2 hwfO hchO.
  rewrite /observed_good /= in hs.
  have hg := reduced_game_good_probability A_ht &m.
  have hh1 := interactive_hop1_MA_good (R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A_ht)))
    &m hc henc hwleaf.
  have hh2 := interactive_hop2_charged (R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A_ht)))
    &m hemb henc.
  have hother := seam_branch2 (Observe(A_ht)) &m henc hpkO htrO.
  have hsplit : Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(Observe(A_ht),FC.O_THFC_Default).main() @ &m :
      res /\ good_transcript Observe.public Observe.messages Observe.signatures]
    <= Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(Observe(A_ht),FC.O_THFC_Default).main() @ &m :
      res /\ EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES /\
        good_transcript Observe.public Observe.messages Observe.signatures]
      + Pr[EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_V(Observe(A_ht),FC.O_THFC_Default).main() @ &m :
        res /\ !EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES].
  + rewrite Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWCESNPRF_C.valid_WOTSTWES] RealOrder.ler_add.
    - by rewrite Pr[mu_sub]; smt().
    by rewrite Pr[mu_sub]; smt().
  smt().
qed.
