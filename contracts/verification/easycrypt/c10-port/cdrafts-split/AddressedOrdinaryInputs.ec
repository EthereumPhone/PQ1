(* Honest ordinary public inputs: non-node calls, short singleton prefixes,
   or the canonical WOTS/Merkle/FORS/forest families. Special FORS calls are
   classified separately and remain explicitly charged. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain PersistentGrind AcceptedContexts ForsInputSeparation.
require import AddressedNodeCollision AddressedInputFields AddressedInputKinds AddressedForsException.
require import AddressedWotsCanonicity AddressedMerkleCanonicity AddressedTreeLog AddressedForsCanonicity AddressedForestCanonicity.

op canonical_long_input h s seed x =
  canonical_tree_input h s seed x \/ canonical_fors_input h s seed x \/ canonical_forest_input h s seed x.
op ordinary_public_input h s seed x = !node_query x \/ size x<64 \/ canonical_long_input h s seed x.
op ordinary_new_inputs (old h s : (raw_input,digest) fmap) seed =
  forall x, x \in h => x \in old \/ ordinary_public_input h s seed x \/ exceptional_fors_query x.

lemma canonical_tree_kind h s seed x :
  size seed=32 => canonical_tree_input h s seed x =>
  public_address_kind x=be 4 0 \/ public_address_kind x=be 4 1 \/ public_address_kind x=be 4 2.
proof. rewrite /canonical_tree_input; smt(canonical_wots_kind canonical_merkle_kind). qed.

lemma canonical_long_input_extends h h' s s' seed x :
  extends h h' => extends s s' => canonical_long_input h s seed x => canonical_long_input h' s' seed x.
proof.
  rewrite /canonical_long_input;
    smt(canonical_tree_input_extends canonical_fors_input_extends canonical_forest_input_extends).
qed.

lemma canonical_long_input_unique h s seed x y :
  size seed=32 => canonical_long_input h s seed x => canonical_long_input h s seed y =>
  same_node_address x y => x=y.
proof.
  move=> hs; rewrite /canonical_long_input => hx hy he.
  have hk := public_address_kind_same x y he.
  smt(canonical_tree_input_unique canonical_fors_input_unique canonical_forest_input_unique
    canonical_tree_kind canonical_fors_kind canonical_forest_kind be4_injective).
qed.

lemma ordinary_public_input_extends h h' s s' seed x :
  extends h h' => extends s s' => ordinary_public_input h s seed x => ordinary_public_input h' s' seed x.
proof. rewrite /ordinary_public_input; smt(canonical_long_input_extends). qed.

lemma ordinary_public_node_unique h s seed x y :
  size seed=32 => node_query x => node_query y =>
  ordinary_public_input h s seed x => ordinary_public_input h s seed y =>
  same_node_address x y => x=y.
proof.
  move=> hs hn hn'; rewrite /ordinary_public_input => hx hy he.
  have hsym : same_node_address y x by move: he; rewrite /same_node_address; smt().
  smt(short_same_address_is_same_input canonical_long_input_unique).
qed.

lemma ordinary_new_inputs_initial h s seed : ordinary_new_inputs h h s seed.
proof. rewrite /ordinary_new_inputs; smt(). qed.

lemma ordinary_new_inputs_compose old h h' s s' seed :
  extends h h' => extends s s' => ordinary_new_inputs old h s seed =>
  ordinary_new_inputs h h' s' seed => ordinary_new_inputs old h' s' seed.
proof.
  move=> hh hs hp hn x hx; have hc := hn x hx.
  case (x \in h) => hm; first smt(ordinary_public_input_extends).
  smt().
qed.

lemma ordinary_new_inputs_insert old h s seed x d :
  x \notin h => ordinary_new_inputs old h s seed =>
  ordinary_public_input h s seed x \/ exceptional_fors_query x =>
  ordinary_new_inputs old h.[x<-d] s seed.
proof.
  move=> hf ho hx y hy; have hh := extends_insert h x d hf.
  have hs := extends_refl s.
  have hy' : y=x \/ y \in h by smt(mem_set).
  smt(ordinary_public_input_extends).
qed.
