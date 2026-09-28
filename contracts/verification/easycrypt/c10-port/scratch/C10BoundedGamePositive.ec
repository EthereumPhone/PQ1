require import AllCore List Distr.
require import C10BoundedGame.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedSigning.

lemma sticky_failure (qs0 : (adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) list) :
  phoare[O_Bounded.query : O_Bounded.bad /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 ==>
    O_Bounded.bad /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 /\ res = witness] = 1%r.
proof. exact (bounded_failed_query_stops qs0). qed.

lemma guarded_comparison
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless A(O, OC).forge) =>
  equiv[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main ~
        M_EUF_GCMA_WOTSC_NPRF(A, O_Bounded, FC.O_THFC_Default).main :
    ={glob A} ==> !O_Bounded.bad{2} => ={res}].
proof.
  move=> hchoose hforge.
  exact (total_bounded_main A hchoose hforge).
qed.
