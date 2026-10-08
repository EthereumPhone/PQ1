(* Hidden-vector sampling can be delayed until an arbitrary candidate producer has finished. *)
require import AllCore List Distr DList StdOrder.
require import C10RawOracle C10Randomizer RawKeygen NodeVectorMass.
import RealOrder RField.
module type CandidateProducer = { proc run() : raw_input list }.
module IndependentVectorGuess (P : CandidateProducer) = {
  proc run() : bool = {
    var hidden, candidates;
    hidden <$ dlist full_digest 8;
    candidates <@ P.run();
    return node_vector_hit hidden candidates;
  }
}.
module LateVectorGuess (P : CandidateProducer) = {
  proc run() : bool = {
    var hidden, candidates;
    candidates <@ P.run();
    hidden <$ dlist full_digest 8;
    return node_vector_hit hidden candidates;
  }
}.
lemma vector_guess_late (P <: CandidateProducer) :
  equiv [IndependentVectorGuess(P).run ~ LateVectorGuess(P).run : ={glob P} ==> ={res}].
proof. proc; swap{1} 1 1; sim. qed.
lemma independent_vector_guess_bound (P <: CandidateProducer) k &m :
  0<=k =>
  hoare [P.run : (glob P)=(glob P){m} ==> size res<=k] =>
  Pr[IndependentVectorGuess(P).run() @ &m : res] <= 8%r*k%r*(1%r/2%r)^128.
proof.
  move=> hk hb.
  have he : Pr[IndependentVectorGuess(P).run() @ &m : res]=Pr[LateVectorGuess(P).run() @ &m : res]
    by byequiv (vector_guess_late P) => //.
  rewrite he; byphoare (_ : (glob P)=(glob P){m} ==> res) => //.
  proc; rnd; call hb; auto=> /> candidates hc.
  have hm := node_vector_mass candidates.
  have hp : 0%r<=(1%r/2%r)^128 by apply expr_ge0; smt().
  smt(le_fromint).
qed.
