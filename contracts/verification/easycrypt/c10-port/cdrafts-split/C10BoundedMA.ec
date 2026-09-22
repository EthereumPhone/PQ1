(* A bounded, failure-rejecting WOTS game needs reachability only for
   queries it actually accepts. No universal N2 or hash-success premise. *)
require import AllCore List Distr.
require import C10BoundedGame GFailCharged.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive.
import C10Counter C10BoundedGrind C10BoundedSigning.

lemma prefix_hit_no_grind_failure (ps : pseed) (ad : adrs) (m : dgstblock) :
  prefix_hit ps ad m => !STCRC_WC.G.grind_fails ps ad m.
proof.
  rewrite /prefix_hit /hit STCRC_WC.G.grind_fails_iff; smt().
qed.

(* Exhausted queries append no record, including after the absorbing failure.
   Thus the recorded transcript remains good even on a failed experiment. *)
lemma bounded_query_good_transcript :
  hoare[O_Bounded.query :
    O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs ==>
    O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  proc; sp 1; if; last by auto.
  exists* O_Bounded.ps, wad, m; elim* => ps0 wad0 m0.
  seq 1 : (O_Bounded.ps = ps0 /\ wad = wad0 /\ m = m0 /\
    O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs /\
    search_result ps0 (WAddress.val wad0) m0 r).
  + by call (search_contract ps0 (WAddress.val wad0) m0); auto.
  if; first by auto.
  inline O_MEUFGCMA_WOTSC_Default.query.
  wp; call (_ : true ==> true); first by conseq WOTS_C_ES_sign_ll.
  call (_ : true ==> true); first by conseq WOTS_C_ES_keygen_ll.
  auto => />; rewrite /gfail_of /search_result;
    smt(prefix_hit_no_grind_failure hasP mem_rcons).
qed.

lemma bounded_choose_good_transcript
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) :
  hoare[A(O_Bounded, FC.O_THFC_Default).choose :
    O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs ==>
    O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  proc (O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs) => //.
  + exact bounded_query_good_transcript.
  by proc; auto.
qed.

lemma bounded_choose_good
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  equiv[A(O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).choose ~
        A(O_Bounded, FC.O_THFC_Default).choose :
    ={glob A, glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default} /\
    !O_Bounded.bad{2} /\ O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1} /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps{2} O_MEUFGCMA_WOTSC_Default.qs{2} ==>
    !O_Bounded.bad{2} =>
      ={glob A, glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default} /\
      O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1} /\
      !gfail_of O_MEUFGCMA_WOTSC_Default.ps{2} O_MEUFGCMA_WOTSC_Default.qs{2}].
proof.
  move=> A_choose_ll.
  conseq (bounded_choose A A_choose_ll) _ (bounded_choose_good_transcript A); smt().
qed.

lemma total_bounded_main_good
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless A(O, OC).forge) =>
  equiv[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main ~
        M_EUF_GCMA_WOTSC_NPRF(A, O_Bounded, FC.O_THFC_Default).main :
    ={glob A} ==> !O_Bounded.bad{2} => ={res} /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps{1} O_MEUFGCMA_WOTSC_Default.qs{1}].
proof.
  move=> A_choose_ll A_forge_ll.
  proc.
  seq 4 4 : (={ps} /\ (!O_Bounded.bad{2} =>
    ={glob A, glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default} /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps{2} O_MEUFGCMA_WOTSC_Default.qs{2})).
  + call (bounded_choose_good A A_choose_ll).
    inline *; by auto; rewrite /gfail_of.
  case (O_Bounded.bad{2}).
  + inline O_MEUFGCMA_WOTSC_Default.get O_MEUFGCMA_WOTSC_Default.nr_queries
      O_MEUFGCMA_WOTSC_Default.dist_addresses O_MEUFGCMA_WOTSC_Default.get_addresses
      FC.O_THFC_Default.get_tweaks.
    wp; call{1} bounded_verify_ll; call{2} bounded_verify_ll.
    wp; call{1} (A_forge_ll O_MEUFGCMA_WOTSC_Default FC.O_THFC_Default).
    call{2} (A_forge_ll O_Bounded FC.O_THFC_Default).
    by auto.
  inline O_MEUFGCMA_WOTSC_Default.get O_MEUFGCMA_WOTSC_Default.nr_queries
    O_MEUFGCMA_WOTSC_Default.dist_addresses O_MEUFGCMA_WOTSC_Default.get_addresses
    FC.O_THFC_Default.get_tweaks.
  wp; call (_ : ={arg} ==> ={res}); first by sim.
  wp; call (_ : true).
  by auto; smt().
qed.

lemma bounded_win_le_total_good
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) &m :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless A(O, OC).forge) =>
  Pr[BoundedGame(A).main() @ &m : res] <=
  Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  move=> A_choose_ll A_forge_ll.
  byequiv (_ : ={glob A} ==> res{1} => res{2} /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps{2} O_MEUFGCMA_WOTSC_Default.qs{2}) => //; symmetry.
  proc*; inline{2} 1; wp.
  call (total_bounded_main_good A A_choose_ll A_forge_ll).
  by auto; smt().
qed.

lemma interactive_hop1_MA_good
  (A <: Adv_MEUFGCMA_WOTSC{-R_int_STCRC, -O_MEUFGCMA_WOTSC_Default,
                           -STCRC_WC.O_STCRC_Default, -FC.O_THFC_Default, -O_THFC_MA, -G0_INT}) &m :
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    hoare[ R_int_STCRC(A, STCRC_WC.O_STCRC_Default, O_THFC_MA).pick :
             O_THFC_MA.tws_ma = [] ==>
             all (fun (p : int * adrs) => p.`1 <> dfC0) O_THFC_MA.tws_ma ] =>
    Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
      res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs]
  <=   Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
      res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs]
     + Pr[S_TCR_C_Int_MA(R_int_STCRC(A), STCRC_WC.O_STCRC_Default).main() @ &m : res].
proof.
  move=> le_c_ptgts encb A_wf_MA.
  have e0 : Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
      res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs]
          = Pr[G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
      res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
  + byequiv (_ : ={glob A} ==> res{1} = res{2} /\ ={glob O_MEUFGCMA_WOTSC_Default}) => //; proc.
    seq 12 12 : (={ps, i, m, m', sigc, sigc', ad, pkWOTS, is_valid, is_fresh,
                   dist_wgpidxs, nrqs, adlO, adlOC}
                 /\ ={glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default}).
    + sim.
    wp; skip => />.
  rewrite e0 Pr[mu_split (G0_INT.coll)].
  have e1 : Pr[G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
      (res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs) /\ !G0_INT.coll]
          = Pr[GAME1_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
      res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
  + byequiv (_ : ={glob A} ==> ((res{1} /\ ! G0_INT.coll{1}) <=> res{2}) /\ ={glob O_MEUFGCMA_WOTSC_Default}) => //; proc.
    seq 12 12 : (={ps, i, m, m', sigc, sigc', ad, pkWOTS, is_valid, is_fresh,
                   dist_wgpidxs, nrqs, adlO, adlOC}
                 /\ ={glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default}).
    + sim.
    wp; skip => />; smt().
  rewrite e1.
  have e3 : Pr[G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m :
      (res /\ !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs) /\ G0_INT.coll]
    <= Pr[G0_INT(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res /\ G0_INT.coll].
  + by rewrite Pr[mu_sub]; smt().
  have e2 := interactive_hop1_reduce_MA A &m le_c_ptgts encb A_wf_MA.
  smt().
qed.

(* The failure guard removes the grind-failure summand for this bounded
   experiment. The challenge reductions remain the existing total reductions;
   their cost and the two challenge probabilities are not bounded here. *)
lemma bounded_interactive_D1_MA
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
  move=> A_choose_ll A_forge_ll le_c_ptgts embdisj encb A_wf_MA.
  have hb := bounded_win_le_total_good A &m A_choose_ll A_forge_ll.
  have h1 := interactive_hop1_MA_good A &m le_c_ptgts encb A_wf_MA.
  have h2 := interactive_hop2_charged A &m embdisj encb.
  smt().
qed.
