(* Reverse chain comparison needs injectivity only on node-producing inputs. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen LinearChain RawChainTrace LinearCollision.
require import NodeQueryDomain DomainNodeCollision ClientGuessCandidates.

lemma domain_linear_start_unique h f indices u v :
  (forall index x y, f index x=f index y => x=y) =>
  (forall index x, size x=16 => node_query (f index x)) =>
  !domain_node_collision h => size u=16 => size v=16 =>
  linear_recorded h f u indices => linear_recorded h f v indices =>
  linear_value h f u indices=linear_value h f v indices => u=v.
proof.
  move=> hf hd hc; elim: indices u v => [u v | index rest ih u v].
  + by rewrite /linear_value /=.
  rewrite /= /linear_value /=.
  move=> hu hv [hl hr] [hl' hr'] he.
  have hs := ih (linear_step h f u index) (linear_step h f v index) _ _ hr hr' he.
  + rewrite /linear_step; exact (node_width _).
  + rewrite /linear_step; exact (node_width _).
  apply (hf index).
  apply (domain_recorded_equal_input h (f index u) (f index v)) => //; smt().
qed.

lemma domain_raw_chain_start_unique h seed layer tree kp index indices u v :
  size seed=32 => !domain_node_collision h => size u=16 => size v=16 =>
  linear_recorded h (chain_input seed layer tree kp index) u indices =>
  linear_recorded h (chain_input seed layer tree kp index) v indices =>
  linear_value h (chain_input seed layer tree kp index) u indices =
    linear_value h (chain_input seed layer tree kp index) v indices => u=v.
proof.
  move=> hs; apply domain_linear_start_unique.
  + smt(chain_input_value_injective).
  move=> step x hx; rewrite /chain_input; apply node_query_chain; smt(raw_address_width).
qed.
