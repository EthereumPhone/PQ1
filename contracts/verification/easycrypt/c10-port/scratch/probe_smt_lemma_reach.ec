(* THE DECISIVE PROBE for PHASE 5's first named hole.
   P1 (probe_smt_reach.ec) showed a bare `smt()` DOES reach an AXIOM of a required theory.
   The hole PHASE 5 actually cares about is different: can a bare `smt()` reach an
   arbitrary LEMMA -- specifically the ADMITTED `nhchwcoll_hchwpre_msg` -- without naming
   it?  If yes, a proof could consume the admit invisibly and the name-level closure would
   miss it.  If no, the hole is far smaller than PHASE 5's header claims.

   P2 restates that lemma's exact conclusion under its exact hypotheses and offers the
   prover NO hint.  Closing it would mean smt found the lemma on its own. *)
require import AllCore.
require import SPHINCS_PLUS.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.

lemma P2_lemma_reach (ps : pseed) (ad : adrs) (m m' : msgWOTS) (sig sig' : sigWOTS) :
     P m
  => P m'
  => m <> m'
  => !has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
  => has_chwpre ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof. smt(). qed.
