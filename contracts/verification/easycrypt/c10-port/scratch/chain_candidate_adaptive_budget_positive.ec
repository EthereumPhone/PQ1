require import AllCore List Distr DList StdOrder.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount.
require import NodeVectorMass VectorGuessBound.
import RealOrder.
require import ChainCandidateMass.

lemma checked (P <: CandidateProducer) k &m :
  0<=k =>
  hoare [P.run : (glob P)=(glob P){m} ==> size (chain_variable_nodes res)<=k] =>
  Pr[IndependentVectorGuess(P).run() @ &m : res] <= 8%r*(k+2)%r*(1%r/2%r)^128.
proof.
  exact (independent_vector_candidate_bound P k &m).
qed.
