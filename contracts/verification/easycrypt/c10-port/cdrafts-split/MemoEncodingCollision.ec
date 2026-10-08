(* Retained low-129-bit collisions are covered by collisions among fresh draws. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen WotsDigitOrder.

op encoding_public_node_collision (h : (raw_input,digest) fmap) =
  exists x y dx dy, x<>y /\ h.[x]=Some dx /\ h.[y]=Some dy /\ encoding_bits dx=encoding_bits dy.
op encoding_nodes_cover (h : (raw_input,digest) fmap) (nodes : digest list) =
  forall x d, h.[x]=Some d => mem nodes (encoding_bits d).
op encoding_node_table_recorded h nodes = encoding_nodes_cover h nodes /\ (uniq nodes => !encoding_public_node_collision h).

lemma encoding_node_table_empty : encoding_node_table_recorded empty [].
proof. rewrite /encoding_node_table_recorded /encoding_nodes_cover /encoding_public_node_collision; smt(emptyE). qed.

lemma encoding_node_table_insert h nodes x d :
  encoding_node_table_recorded h nodes => x\notin h =>
  encoding_node_table_recorded h.[x<-d] (encoding_bits d::nodes).
proof.
  rewrite /encoding_node_table_recorded /encoding_nodes_cover /encoding_public_node_collision /=; smt(get_setE domE).
qed.

lemma encoding_recorded_collision_implies_repeat h nodes :
  encoding_node_table_recorded h nodes => encoding_public_node_collision h => !uniq nodes.
proof. rewrite /encoding_node_table_recorded; smt(). qed.
