(* Count aliases across both independent tables, including private coordinates. *)
require import AllCore List FMap FSet.
require import C10RawOracle RawKeygen MemoNodeCollision.

op cross_node_alias (h s : (raw_input,digest) fmap) =
  exists x k dx dk, h.[x]=Some dx /\ s.[k]=Some dk /\ node dx=node dk.
op private_node_alias (h s : (raw_input,digest) fmap) = public_node_collision s.
op joint_node_collision h s = public_node_collision h \/ private_node_alias h s.
op joint_draws (h s : (raw_input,digest) fmap) = card (fdom h) + card (fdom s).
op joint_nodes_valid h s nodes =
  nodes_cover h nodes /\ nodes_cover s nodes /\ size nodes=joint_draws h s /\
  (uniq nodes => !joint_node_collision h s).

lemma joint_nodes_empty : joint_nodes_valid empty empty [].
proof.
  rewrite /joint_nodes_valid /nodes_cover /joint_draws /joint_node_collision
    /private_node_alias /public_node_collision /cross_node_alias !fdom0 !fcards0 /=;
    smt(emptyE).
qed.

lemma joint_nodes_public_insert h s nodes x d :
  joint_nodes_valid h s nodes => x\notin h =>
  joint_nodes_valid h.[x<-d] s (node d::nodes).
proof.
  rewrite /joint_nodes_valid /nodes_cover /joint_draws /joint_node_collision
    /private_node_alias /public_node_collision /cross_node_alias /=;
    smt(get_setE domE fdom_set mem_fdom fcardU1).
qed.

lemma joint_nodes_private_insert h s nodes k d :
  joint_nodes_valid h s nodes => k\notin s =>
  joint_nodes_valid h s.[k<-d] (node d::nodes).
proof.
  rewrite /joint_nodes_valid /nodes_cover /joint_draws /joint_node_collision
    /private_node_alias /public_node_collision /cross_node_alias /=;
    smt(get_setE domE fdom_set mem_fdom fcardU1).
qed.

lemma joint_recorded_alias h s nodes :
  joint_nodes_valid h s nodes => private_node_alias h s => !uniq nodes.
proof. rewrite /joint_nodes_valid /joint_node_collision; smt(). qed.

op node_known_elsewhere (h s : (raw_input,digest) fmap) key value =
  (exists x d, h.[x]=Some d /\ value=node d) \/
  (exists other d, other<>key /\ s.[other]=Some d /\ value=node d).

lemma private_value_known_elsewhere h s key d :
  s.[key]=Some d => node_known_elsewhere h s key (node d) => private_node_alias h s.
proof. rewrite /node_known_elsewhere /private_node_alias /cross_node_alias /public_node_collision; smt(). qed.
