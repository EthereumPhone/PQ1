(* Probability bridge for the operational, failure-rejecting WOTS game. *)
require import AllCore List Distr.
require import C10BoundedSigning.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10Counter C10BoundedGrind.

lemma total_bounded_query :
  equiv[O_MEUFGCMA_WOTSC_Default.query ~ O_Bounded.query :
    ={wad, m, glob O_MEUFGCMA_WOTSC_Default} /\ !O_Bounded.bad{2} /\
    O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1} ==>
    !O_Bounded.bad{2} =>
      ={res, glob O_MEUFGCMA_WOTSC_Default} /\
      O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1}].
proof.
  proc; sp 0 1; if{2}.
  + seq 0 1 : (={wad, m, glob O_MEUFGCMA_WOTSC_Default} /\
      !O_Bounded.bad{2} /\ O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1}).
    - by call{2} search_ll; auto.
    if{2}.
    - by wp; call{1} WOTS_C_ES_sign_ll; call{1} WOTS_C_ES_keygen_ll; auto.
    inline{2} 1.
    wp; call (_ : ={arg} ==> ={res}); first by sim.
    call (_ : ={arg} ==> ={res}); first by sim.
    by auto.
  by wp; call{1} WOTS_C_ES_sign_ll; call{1} WOTS_C_ES_keygen_ll; auto; smt().
qed.

(* A later request cannot clear failure, append a record, or release a
   signature. Initialization is the only reset point. *)
lemma bounded_failed_query_stops (qs0 : (adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) list) :
  phoare[O_Bounded.query : O_Bounded.bad /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 ==>
    O_Bounded.bad /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 /\ res = witness] = 1%r.
proof. proc; rcondf 2; by auto. qed.

(* Adversary termination is explicit. Oracle globals, including bad, are
   private; choose may adaptively call both interfaces any finite number of
   times. The up-to-bad rule imposes no independence or prefix-hit premise. *)
lemma bounded_choose
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  equiv[A(O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).choose ~
        A(O_Bounded, FC.O_THFC_Default).choose :
    ={glob A, glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default} /\
    !O_Bounded.bad{2} /\ O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1} ==>
    !O_Bounded.bad{2} =>
      ={glob A, glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default} /\
      O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1}].
proof.
  move=> A_choose_ll.
  proc (O_Bounded.bad)
       (={glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default} /\
        O_Bounded.ps{2} = O_MEUFGCMA_WOTSC_Default.ps{1})
       true.
  + by smt().
  + by smt().
  + exact A_choose_ll.
  + conseq total_bounded_query; smt().
  + move=> &2 _; exact O_MEUFGCMA_WOTSC_query_ll.
  + move=> &1; proc; rcondf 2; by auto.
  + by proc; auto; smt().
  + move=> &2 _; by islossless.
  + move=> &1; by proc; auto.
qed.

lemma bounded_verify_ll : islossless WOTS_C_ES.verify.
proof. by islossless; while true (len - size pkWOTS_l); auto; smt(size_rcons). qed.

lemma total_bounded_main
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless A(O, OC).forge) =>
  equiv[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main ~
        M_EUF_GCMA_WOTSC_NPRF(A, O_Bounded, FC.O_THFC_Default).main :
    ={glob A} ==> !O_Bounded.bad{2} => ={res}].
proof.
  move=> A_choose_ll A_forge_ll.
  proc.
  seq 4 4 : (={ps} /\ (!O_Bounded.bad{2} =>
    ={glob A, glob O_MEUFGCMA_WOTSC_Default, glob FC.O_THFC_Default})).
  + call (bounded_choose A A_choose_ll).
    inline *; by auto.
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

lemma bounded_win_le_total
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) &m :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless A(O, OC).forge) =>
  Pr[BoundedGame(A).main() @ &m : res] <=
  Pr[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() @ &m : res].
proof.
  move=> A_choose_ll A_forge_ll.
  byequiv (_ : ={glob A} ==> res{1} => res{2}) => //; symmetry.
  proc*; inline{2} 1; wp.
  call (total_bounded_main A A_choose_ll A_forge_ll).
  by auto; smt().
qed.
