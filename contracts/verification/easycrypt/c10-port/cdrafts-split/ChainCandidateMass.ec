(* A cover of the same candidate list retains both fixed values once. *)
require import AllCore List Distr DList StdOrder.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount.
require import NodeVectorMass VectorGuessBound.
import RealOrder.

op chain_variable_nodes (xs : raw_input list) =
  filter (fun x => x <> nseq 16 0 /\ x <> nseq 16 255) xs.
op chain_candidate_cover xs = chain_variable_nodes xs ++ [nseq 16 0; nseq 16 255].

lemma chain_candidate_cover_mem xs x : mem xs x => mem (chain_candidate_cover xs) x.
proof. rewrite /chain_candidate_cover mem_cat /chain_variable_nodes mem_filter /=; smt(). qed.
lemma chain_candidate_cover_size xs : size (chain_candidate_cover xs) = size (chain_variable_nodes xs)+2.
proof. by rewrite /chain_candidate_cover size_cat /=. qed.
lemma chain_variable_nodes_le_size xs : size (chain_variable_nodes xs) <= size xs.
proof.
  rewrite /chain_variable_nodes; elim: xs => [|x xs ih] //=.
  case (x <> nseq 16 0 /\ x <> nseq 16 255); smt().
qed.
lemma chain_variable_nodes_cat xs ys :
  size (chain_variable_nodes (xs ++ ys)) = size (chain_variable_nodes xs)+size (chain_variable_nodes ys).
proof. by rewrite /chain_variable_nodes filter_cat size_cat. qed.
lemma chain_variable_nodes_queries queries :
  chain_variable_nodes (map leaf_suffix_candidate queries) =
    map leaf_suffix_candidate (filter leaf_variable_query queries).
proof.
  rewrite /chain_variable_nodes; elim: queries => [|x xs ih] //=.
  rewrite /leaf_variable_query /=.
  by case (leaf_suffix_candidate x <> nseq 16 0 /\ leaf_suffix_candidate x <> nseq 16 255); rewrite /= ih.
qed.
lemma chain_variable_nodes_query_outputs queries outputs :
  size (chain_variable_nodes (map leaf_suffix_candidate queries ++ outputs)) <=
    leaf_variable_count queries + size outputs.
proof.
  rewrite chain_variable_nodes_cat chain_variable_nodes_queries size_map /leaf_variable_count.
  smt(chain_variable_nodes_le_size).
qed.
lemma chain_candidate_vector_cover ds candidates :
  node_vector_hit ds candidates => node_vector_hit ds (chain_candidate_cover candidates).
proof.
  rewrite /node_vector_hit !hasP; move=> [d [hd hc]].
  exists d; split; first exact hd.
  exact (chain_candidate_cover_mem candidates (node d) hc).
qed.
lemma chain_candidate_vector_mass candidates :
  mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=
    8%r*(size (chain_variable_nodes candidates)+2)%r*(1%r/2%r)^128.
proof.
  have he : mu (dlist full_digest 8) (fun ds => node_vector_hit ds candidates) <=
    mu (dlist full_digest 8) (fun ds => node_vector_hit ds (chain_candidate_cover candidates)).
  + apply mu_le => ds hs hm; exact (chain_candidate_vector_cover ds candidates hm).
  have hb := node_vector_mass (chain_candidate_cover candidates).
  rewrite chain_candidate_cover_size in hb; exact (ler_trans _ _ _ he hb).
qed.
lemma independent_vector_candidate_bound (P <: CandidateProducer) k &m :
  0<=k =>
  hoare [P.run : (glob P)=(glob P){m} ==> size (chain_variable_nodes res)<=k] =>
  Pr[IndependentVectorGuess(P).run() @ &m : res] <= 8%r*(k+2)%r*(1%r/2%r)^128.
proof.
  move=> hk hb.
  have he : Pr[IndependentVectorGuess(P).run() @ &m : res]=Pr[LateVectorGuess(P).run() @ &m : res]
    by byequiv (vector_guess_late P) => //.
  rewrite he; byphoare (_ : (glob P)=(glob P){m} ==> res) => //.
  proc; rnd; call hb; auto=> /> candidates hc.
  have hm := chain_candidate_vector_mass candidates.
  have hp : 0%r<=(1%r/2%r)^128 by apply expr_ge0; smt().
  smt(le_fromint).
qed.
