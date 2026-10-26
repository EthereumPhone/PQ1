(* Node collisions at the same public-seed/address prefix. These component
   lemmas preserve the special FORS root-as-secret address overlap. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain DomainNodeCollision.
require import PathInputs PathCollision RawPathReplay RawForsPathReplay.
require import DomainPathInputs RawChainTrace LinearChain LinearCollision ClientGuessCandidates.
require import ForestWitness ForsLeafInputs.

op same_node_address (x y : raw_input) = take 64 x = take 64 y.
op addressed_node_collision (h : (raw_input,digest) fmap) =
  exists x y dx dy, node_query x /\ node_query y /\ same_node_address x y /\
    x<>y /\ h.[x]=Some dx /\ h.[y]=Some dy /\ node dx=node dy.

lemma addressed_collision_is_domain h :
  addressed_node_collision h => domain_node_collision h.
proof. rewrite /addressed_node_collision /domain_node_collision; smt(). qed.

lemma addressed_recorded_equal_input h x y :
  !addressed_node_collision h => node_query x => node_query y =>
  same_node_address x y => x \in h => y \in h =>
  node (oget h.[x])=node (oget h.[y]) => x=y.
proof. rewrite /addressed_node_collision; smt(domE). qed.

lemma node_prefix (seed a payload : raw_input) :
  size seed=32 => size a=32 =>
  take 64 (seed ++ a ++ payload)=seed ++ a.
proof.
  move=> hs ha.
  by rewrite -catA take_cat hs /= take_cat ha /= take0 cats0.
qed.

lemma actual_node_same_address (seed a lhs rhs : raw_input) :
  size seed=32 => size a=32 =>
  same_node_address (seed ++ (a ++ lhs)) (seed ++ (a ++ rhs)).
proof. rewrite /same_node_address !catA; smt(node_prefix). qed.

lemma actual_node_pair_same_address (seed a l1 r1 l2 r2 : raw_input) :
  size seed=32 => size a=32 =>
  same_node_address (seed ++ a ++ l1 ++ r1) (seed ++ a ++ l2 ++ r2).
proof.
  move=> hs ha.
  have hp := actual_node_same_address seed a (l1 ++ r1) (l2 ++ r2) hs ha.
  by move: hp; rewrite -!catA.
qed.

lemma addressed_path_input_collision h f :
  (forall level parent left right, size left=16 => size right=16 =>
    node_query (f level parent left right)) =>
  (forall level parent l1 r1 l2 r2,
    same_node_address (f level parent l1 r1) (f level parent l2 r2)) =>
  path_input_collision h f => addressed_node_collision h.
proof.
  move=> hf hp; rewrite /path_input_collision /addressed_node_collision.
  move=> hc; elim hc => level parent l1 r1 l2 r2 [#] h1 h2 h3 h4 hx hy hn he.
  exists (f level parent l1 r1) (f level parent l2 r2)
    (oget h.[f level parent l1 r1]) (oget h.[f level parent l2 r2]).
  smt(domE).
qed.

lemma addressed_merkle_path_collision h seed layer tree :
  size seed=32 => path_input_collision h (merkle_pair seed layer tree) =>
  addressed_node_collision h.
proof.
  move=> hs; apply addressed_path_input_collision.
  + smt(domain_merkle_pair).
  move=> level parent l1 r1 l2 r2.
  rewrite /merkle_pair; apply actual_node_pair_same_address.
  + exact hs.
  exact (raw_address_width layer tree 2 0 0 level parent).
qed.

lemma addressed_fors_path_collision h seed ht tree :
  size seed=32 => path_input_collision h (fors_pair seed ht tree) =>
  addressed_node_collision h.
proof.
  move=> hs; apply addressed_path_input_collision.
  + smt(domain_fors_pair).
  move=> level parent l1 r1 l2 r2.
  rewrite /fors_pair; apply actual_node_pair_same_address.
  + exact hs.
  exact (raw_address_width 0 ht 3 tree 0 level parent).
qed.

lemma special_and_leaf_share_address seed ht secret root :
  size seed=32 =>
  same_node_address (fors_leaf_input seed ht 12 0 secret)
    (forest_special_input seed ht root).
proof.
  move=> hs; rewrite /forest_special_input /fors_leaf_input /same_node_address.
  have hw := raw_address_width 0 ht 3 12 0 0 0.
  by rewrite (node_prefix seed _ (pad secret) hs hw)
    (node_prefix seed _ (pad root) hs hw).
qed.

lemma special_and_leaf_distinct_inputs seed ht secret root :
  secret<>root => fors_leaf_input seed ht 12 0 secret <> forest_special_input seed ht root.
proof. rewrite /forest_special_input; smt(fors_leaf_input_injective). qed.

lemma addressed_linear_start_unique h f indices u v :
  (forall index x y, f index x=f index y => x=y) =>
  (forall index x, size x=16 => node_query (f index x)) =>
  (forall index x y, same_node_address (f index x) (f index y)) =>
  !addressed_node_collision h => size u=16 => size v=16 =>
  linear_recorded h f u indices => linear_recorded h f v indices =>
  linear_value h f u indices=linear_value h f v indices => u=v.
proof.
  move=> hf hd hp hc; elim: indices u v => [u v | index rest ih u v].
  + by rewrite /linear_value /=.
  rewrite /= /linear_value /=.
  move=> hu hv [hl hr] [hl' hr'] he.
  have hs := ih (linear_step h f u index) (linear_step h f v index) _ _ hr hr' he.
  + rewrite /linear_step; exact (node_width _).
  + rewrite /linear_step; exact (node_width _).
  apply (hf index).
  apply (addressed_recorded_equal_input h (f index u) (f index v)) => //; smt().
qed.

lemma addressed_raw_chain_start_unique h seed layer tree kp index indices u v :
  size seed=32 => !addressed_node_collision h => size u=16 => size v=16 =>
  linear_recorded h (chain_input seed layer tree kp index) u indices =>
  linear_recorded h (chain_input seed layer tree kp index) v indices =>
  linear_value h (chain_input seed layer tree kp index) u indices =
    linear_value h (chain_input seed layer tree kp index) v indices => u=v.
proof.
  move=> hs; apply addressed_linear_start_unique.
  + smt(chain_input_value_injective).
  + move=> step x hx; rewrite /chain_input; apply node_query_chain; smt(raw_address_width).
  move=> step x y; rewrite /same_node_address /chain_input.
  have ha := raw_address_width layer tree 0 kp index step 0.
  by rewrite (node_prefix seed _ (pad x) hs ha) (node_prefix seed _ (pad y) hs ha).
qed.

lemma addressed_fors_leaf_same_address seed ht tree index x y :
  size seed=32 =>
  same_node_address (fors_leaf_input seed ht tree index x)
    (fors_leaf_input seed ht tree index y).
proof.
  move=> hs; rewrite /same_node_address /fors_leaf_input.
  have ha := raw_address_width 0 ht 3 tree 0 0 index.
  by rewrite (node_prefix seed _ (pad x) hs ha) (node_prefix seed _ (pad y) hs ha).
qed.

lemma addressed_fors_leaf_collision h seed ht tree index :
  size seed=32 => fors_leaf_collision h seed ht tree index => addressed_node_collision h.
proof.
  move=> hs; rewrite /fors_leaf_collision /addressed_node_collision.
  move=> hc; elim hc => s1 s2 [#] h1 h2 hx hy hn he.
  exists (fors_leaf_input seed ht tree index s1) (fors_leaf_input seed ht tree index s2)
    (oget h.[fors_leaf_input seed ht tree index s1]) (oget h.[fors_leaf_input seed ht tree index s2]).
  smt(domE domain_fors_leaf addressed_fors_leaf_same_address).
qed.
