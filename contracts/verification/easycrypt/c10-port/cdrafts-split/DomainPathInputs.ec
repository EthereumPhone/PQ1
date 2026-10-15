(* Actual fixed-width FORS and Merkle path inputs are in the node domain. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForsPathReplay RawPathReplay ForsLeafInputs.
require import NodeQueryDomain DomainNodeCollision ClientGuessCandidates.

lemma domain_merkle_pair seed layer tree level parent lhs rhs :
  size seed=32 => size lhs=16 => size rhs=16 =>
  node_query (merkle_pair seed layer tree level parent lhs rhs).
proof.
  move=> hs hl hr; rewrite /merkle_pair; apply node_query_pair => //.
  exact node_query_merkle_kind.
qed.

lemma domain_fors_pair seed ht tree level parent lhs rhs :
  size seed=32 => size lhs=16 => size rhs=16 =>
  node_query (fors_pair seed ht tree level parent lhs rhs).
proof.
  move=> hs hl hr; rewrite /fors_pair; apply node_query_pair => //.
  exact node_query_fors_kind.
qed.

lemma domain_fors_leaf seed ht tree index secret :
  size seed=32 => size secret=16 => node_query (fors_leaf_input seed ht tree index secret).
proof.
  move=> hs hx; rewrite /fors_leaf_input; apply node_query_chain => //.
  exact (raw_address_width _ _ _ _ _ _ _).
qed.

lemma domain_fors_leaf_collision h seed ht tree index :
  size seed=32 => fors_leaf_collision h seed ht tree index => domain_node_collision h.
proof.
  move=> hs; rewrite /fors_leaf_collision /domain_node_collision.
  move=> hc; elim hc => s1 s2 [#] h1 h2 hx hy hn he.
  exists (fors_leaf_input seed ht tree index s1) (fors_leaf_input seed ht tree index s2)
    (oget h.[fors_leaf_input seed ht tree index s1]) (oget h.[fors_leaf_input seed ht tree index s2]).
  smt(domE domain_fors_leaf).
qed.
