require import AllCore List Distr.
require import C10BoundedMA.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive C10BoundedSigning GFailCharged.

(* Faulty variant: append an honest total-oracle record even when search
   has no valid counter. The bounded oracle must refuse this query instead. *)
module Unchecked = {
  proc query(wad : wadrs, m : dgstblock) : pkWOTS * (sigWOTS * cntr) = {
    var answer : pkWOTS * (sigWOTS * cntr);
    answer <@ O_MEUFGCMA_WOTSC_Default.query(wad, m);
    return answer;
  }
}.

lemma appended_failed_query (ps0 : pseed) (wad0 : wadrs) (m0 : dgstblock) :
  hoare[Unchecked.query :
    O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ O_MEUFGCMA_WOTSC_Default.qs = [] /\
    wad = wad0 /\ m = m0 /\ STCRC_WC.G.grind_fails ps0 (WAddress.val wad0) m0 ==>
    !gfail_of O_MEUFGCMA_WOTSC_Default.ps O_MEUFGCMA_WOTSC_Default.qs].
proof.
  proc; inline O_MEUFGCMA_WOTSC_Default.query.
  wp; call (_ : true ==> true); first by conseq WOTS_C_ES_sign_ll.
  call (_ : true ==> true); first by conseq WOTS_C_ES_keygen_ll.
  auto => />; rewrite /gfail_of /=.
  by trivial.
qed.
