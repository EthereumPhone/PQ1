(* Earlier path and FORS leaf events are covered by the charged table event. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen PathInputs PathCollision ForsLeafInputs.
require import MemoNodeCollision.

lemma path_input_collision_is_public h f :
  path_input_collision h f => public_node_collision h.
proof.
  rewrite /path_input_collision /public_node_collision.
  move=> hc; elim hc => level parent l1 r1 l2 r2 [#] h1 h2 h3 h4 hx hy hn he.
  exists (f level parent l1 r1) (f level parent l2 r2)
    (oget h.[f level parent l1 r1]) (oget h.[f level parent l2 r2]).
  smt(domE).
qed.

lemma path_pair_collision_is_public h f :
  pair_input_injective f => path_pair_collision h f => public_node_collision h.
proof. smt(path_pair_to_input_collision path_input_collision_is_public). qed.

lemma fors_leaf_collision_is_public h seed ht tree target :
  fors_leaf_collision h seed ht tree target => public_node_collision h.
proof.
  rewrite /fors_leaf_collision /public_node_collision.
  move=> hc; elim hc => s1 s2 [#] h1 h2 hx hy hn he.
  exists (RawForsPathReplay.fors_leaf_input seed ht tree target s1)
    (RawForsPathReplay.fors_leaf_input seed ht tree target s2)
    (oget h.[RawForsPathReplay.fors_leaf_input seed ht tree target s1])
    (oget h.[RawForsPathReplay.fors_leaf_input seed ht tree target s2]).
  smt(domE).
qed.
