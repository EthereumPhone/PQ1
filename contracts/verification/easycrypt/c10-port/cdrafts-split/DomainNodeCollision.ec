(* Restrict collisions to the conservative node-input domain. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain MemoNodeCollision.
require import PathInputs PathCollision.

op domain_node_collision (h : (raw_input,digest) fmap) =
  exists x y dx dy, node_query x /\ node_query y /\
    x<>y /\ h.[x]=Some dx /\ h.[y]=Some dy /\ node dx=node dy.

lemma domain_collision_is_public h : domain_node_collision h => public_node_collision h.
proof. rewrite /domain_node_collision /public_node_collision; smt(). qed.

lemma domain_recorded_equal_input h x y :
  !domain_node_collision h => node_query x => node_query y => x \in h => y \in h =>
  node (oget h.[x])=node (oget h.[y]) => x=y.
proof. rewrite /domain_node_collision; smt(domE). qed.

lemma path_input_collision_in_domain h f :
  (forall level parent left right, size left=16 => size right=16 => node_query (f level parent left right)) =>
  path_input_collision h f => domain_node_collision h.
proof.
  move=> hf; rewrite /path_input_collision /domain_node_collision.
  move=> hc; elim hc => level parent l1 r1 l2 r2 [#] h1 h2 h3 h4 hx hy hn he.
  exists (f level parent l1 r1) (f level parent l2 r2)
    (oget h.[f level parent l1 r1]) (oget h.[f level parent l2 r2]).
  smt(domE).
qed.
