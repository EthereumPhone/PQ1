require import AllCore List Distr DList StdOrder.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount.
require import NodeVectorMass VectorGuessBound.
import RealOrder.
require import ChainCandidateMass.

lemma checked candidates :
  mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=
    7%r*(size (chain_variable_nodes candidates)+2)%r*(1%r/2%r)^128.
proof.
  exact (chain_candidate_vector_mass candidates).
qed.
