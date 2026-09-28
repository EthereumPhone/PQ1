require import AllCore List Distr.
require import C10BoundedGame.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedSigning.

lemma erased_guard
  (A <: Adv_MEUFGCMA_WOTSC {-O_Bounded, -O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default}) :
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless O.query => islossless OC.query => islossless A(O, OC).choose) =>
  (forall (O <: Oracle_MEUFGCMA_WOTSC {-A}) (OC <: FC.Oracle_THFC {-A}),
    islossless A(O, OC).forge) =>
  equiv[M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main ~
        M_EUF_GCMA_WOTSC_NPRF(A, O_Bounded, FC.O_THFC_Default).main :
    ={glob A} ==> ={res}].
proof.
  move=> hchoose hforge.
  conseq (total_bounded_main A hchoose hforge).
  + by trivial.
  by trivial.
qed.
