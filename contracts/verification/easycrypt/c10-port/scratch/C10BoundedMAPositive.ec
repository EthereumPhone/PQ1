require import AllCore List Distr.
require import C10BoundedMA.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive C10BoundedSigning GFailCharged.

lemma checked_bounded_member_aware
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -R_int_WOTSTW, -O_MEUFGCMA_WOTSC_Default,
                          -O_MEUFGCMA_WOTSTWESNPRF, -STCRC_WC.O_STCRC_Default,
                          -FC.O_THFC_Default, -O_THFC_MA, -G0_INT, -O_Bounded}) &m :
    (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
      islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
    (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
      islossless A(O, OC).forge) =>
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, O_THFC_MA).pick :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    Pr[BoundedGame(A).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(A), STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
  exact (bounded_interactive_D1_MA A &m).
qed.
