(* A covering list retains both fixed guesses exactly once. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid RawKeygen NodeDistribution.
require import LeafCommitmentHybrid LeafCommitmentBound LeafCandidateCount.
import RealOrder.

op leaf_reduced_candidates queries outputs =
  map leaf_suffix_candidate (filter leaf_variable_query queries) ++
  [nseq 16 0; nseq 16 255] ++ outputs.

lemma leaf_reduced_candidates_cover queries outputs key :
  mem (leaf_commitment_candidates queries outputs) key =>
  mem (leaf_reduced_candidates queries outputs) key.
proof.
  rewrite /leaf_commitment_candidates /leaf_reduced_candidates !mem_cat.
  move=> [hq|ho]; last by smt().
  move: hq => /mapP [x [hx he]].
  case (leaf_variable_query x) => hv.
  + have hm : mem (map leaf_suffix_candidate (filter leaf_variable_query queries)) key.
    - apply mapP; exists x; rewrite mem_filter; smt().
    smt().
  move: hv; rewrite /leaf_variable_query /=; smt().
qed.
lemma leaf_reduced_candidates_size queries outputs :
  size (leaf_reduced_candidates queries outputs) = leaf_variable_count queries+2+size outputs.
proof. by rewrite /leaf_reduced_candidates /leaf_variable_count !size_cat size_map /=. qed.
lemma leaf_reduced_candidate_mass queries outputs :
  mu full_digest (fun d => mem (leaf_commitment_candidates queries outputs) (node d)) <=
    (leaf_variable_count queries+2+size outputs)%r*(1%r/2%r)^128.
proof.
  have hc : mu full_digest (fun d => mem (leaf_commitment_candidates queries outputs) (node d)) <=
    mu full_digest (fun d => mem (leaf_reduced_candidates queries outputs) (node d)).
  + apply mu_le => d hd hm; exact (leaf_reduced_candidates_cover queries outputs (node d) hm).
  have hb := node_history_mass (leaf_reduced_candidates queries outputs).
  rewrite leaf_reduced_candidates_size in hb; exact (ler_trans _ _ _ hc hb).
qed.
