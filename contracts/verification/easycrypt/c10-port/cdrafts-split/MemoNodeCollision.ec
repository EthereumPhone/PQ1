(* Retained public-table collisions are covered by collisions among fresh draws. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen.

op public_node_collision (h : (raw_input,digest) fmap) =
  exists x y dx dy, x<>y /\ h.[x]=Some dx /\ h.[y]=Some dy /\ node dx=node dy.
op nodes_cover (h : (raw_input,digest) fmap) (nodes : raw_input list) =
  forall x d, h.[x]=Some d => mem nodes (node d).
op node_table_recorded h nodes = nodes_cover h nodes /\ (uniq nodes => !public_node_collision h).

lemma node_table_empty : node_table_recorded empty [].
proof. rewrite /node_table_recorded /nodes_cover /public_node_collision; smt(emptyE). qed.

lemma node_table_insert h nodes x d :
  node_table_recorded h nodes => x\notin h =>
  node_table_recorded h.[x<-d] (node d::nodes).
proof.
  rewrite /node_table_recorded /nodes_cover /public_node_collision /=; smt(get_setE domE).
qed.

lemma recorded_collision_implies_repeat h nodes :
  node_table_recorded h nodes => public_node_collision h => !uniq nodes.
proof. rewrite /node_table_recorded; smt(). qed.
