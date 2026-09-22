require import AllCore List Distr.
require import C10BoundedMA.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive C10BoundedSigning GFailCharged.

lemma erased_history :
  hoare[O_Bounded.query :
    O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps ==>
    O_Bounded.ps = O_MEUFGCMA_WOTSC_Default.ps /\
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  conseq bounded_query_good_transcript.
  + by trivial.
  by trivial.
qed.
