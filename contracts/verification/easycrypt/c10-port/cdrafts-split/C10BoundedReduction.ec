(* Conditional composition with the existing interactive WOTS reduction.
   No total-grind premise is discharged here. This is not a whole-scheme
   SPHINCS+C or a real-SHA-256 probability theorem. *)
require import AllCore List Distr.
require import C10BoundedGame WOTS_C_Interactive.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedSigning.

lemma bounded_interactive_D1
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -R_int_WOTSTW, -O_MEUFGCMA_WOTSC_Default,
                          -O_MEUFGCMA_WOTSTWESNPRF, -STCRC_WC.O_STCRC_Default,
                          -FC.O_THFC_Default, -G0_INT, -O_Bounded}) &m :
    (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
      islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
    (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
      islossless A(O, OC).forge) =>
    c <= p_tgts =>
    (forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)) =>
    (* 2026-07-25: the CONTRADICTORY unguarded embinj premise is GONE. *)
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (* Retained premise of the existing total-game reduction. The bounded
       comparison itself does not require it, and this corollary does not
       claim that actual finite-prefix exhaustion is impossible. *)
    (forall (ps0 : pseed) (ad0 : adrs) (m0 : dgstblock),
       exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)) =>
    hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, FC.O_THFC_Default).pick :
             FC.O_THFC_Default.tws = [] ==> all valid_wadrs FC.O_THFC_Default.tws ] =>
    Pr[BoundedGame(A).main() @ &m : res]
  <=   Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(A),
                                 O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
     + Pr[S_TCR_C_Int(R_int_STCRC(A),
                      STCRC_WC.O_STCRC_Default, FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> A_choose_ll A_forge_ll le_c_ptgts embdisj encb hN2 A_wf.
  have hb := bounded_win_le_total A &m A_choose_ll A_forge_ll.
  have ht := interactive_D1 A &m le_c_ptgts embdisj encb hN2 A_wf.
  smt().
qed.
