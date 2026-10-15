require import AllCore List Distr StdOrder.
require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid RawKeygen NodeDistribution.
require import LeafCommitmentHybrid LeafCommitmentBound LeafCandidateCount.
import RealOrder.
require import LeafCandidateMass.

lemma checked queries outputs :
  mu full_digest (fun d => mem (leaf_commitment_candidates queries outputs) (node d)) <=
    (leaf_variable_count queries+1+size outputs)%r*(1%r/2%r)^128.
proof.
  exact (leaf_reduced_candidate_mass queries outputs).
qed.
