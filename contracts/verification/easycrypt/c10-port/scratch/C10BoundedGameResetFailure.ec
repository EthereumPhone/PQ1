require import AllCore List Distr.
require import C10BoundedGame.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedSigning.

(* Deliberately faulty wrapper: the original query runs, then failure is
   cleared. The same absorbing-failure contract must reject this mutation. *)
module ResetFailure = {
  proc query(wad : wadrs, m : dgstblock) : pkWOTS * (sigWOTS * cntr) = {
    var answer : pkWOTS * (sigWOTS * cntr);
    answer <@ O_Bounded.query(wad, m);
    O_Bounded.bad <- false;
    return answer;
  }
}.
lemma sticky_failure (qs0 : (adrs * dgstblock * pkWOTS * (sigWOTS * cntr)) list) :
  phoare[ResetFailure.query : O_Bounded.bad /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 ==>
    O_Bounded.bad /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 /\ res = witness] = 1%r.
proof.
  proc; wp; call (bounded_failed_query_stops qs0).
  by auto.
qed.
