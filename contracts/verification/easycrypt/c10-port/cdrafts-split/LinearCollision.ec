(* Reverse comparison uses the charged public-table event, not a new assumption. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen LinearChain RawChainTrace MemoNodeCollision.

lemma recorded_node_equal_input h x y :
  !public_node_collision h => x \in h => y \in h =>
  node (oget h.[x]) = node (oget h.[y]) => x=y.
proof.
  rewrite /public_node_collision; smt(domE).
qed.

lemma chain_input_value_injective seed layer tree kp index step u v :
  chain_input seed layer tree kp index step u =
    chain_input seed layer tree kp index step v => u=v.
proof. rewrite /chain_input /pad -!catA; smt(catsI catIs). qed.

lemma linear_start_unique h f indices u v :
  (forall index x y, f index x=f index y => x=y) =>
  !public_node_collision h =>
  linear_recorded h f u indices => linear_recorded h f v indices =>
  linear_value h f u indices=linear_value h f v indices => u=v.
proof.
  move=> hf hc; elim: indices u v => [u v | index rest ih u v].
  + by rewrite /linear_value /=.
  rewrite /= /linear_value /=.
  move=> [hl hr] [hl' hr'] he.
  have hs := ih (linear_step h f u index) (linear_step h f v index) hr hr' he.
  apply (hf index).
  apply (recorded_node_equal_input h (f index u) (f index v)) => //.
qed.

lemma raw_chain_start_unique h seed layer tree kp index indices u v :
  !public_node_collision h =>
  linear_recorded h (chain_input seed layer tree kp index) u indices =>
  linear_recorded h (chain_input seed layer tree kp index) v indices =>
  linear_value h (chain_input seed layer tree kp index) u indices =
    linear_value h (chain_input seed layer tree kp index) v indices => u=v.
proof.
  apply linear_start_unique; smt(chain_input_value_injective).
qed.
