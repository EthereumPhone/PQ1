(* Only node-domain entries must be covered by the retained fresh-node pool. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain DomainNodeCollision.

op domain_nodes_cover (h : (raw_input,digest) fmap) (nodes : raw_input list) =
  forall x d, node_query x => h.[x]=Some d => mem nodes (node d).
op domain_table_recorded h nodes =
  domain_nodes_cover h nodes /\ (uniq nodes => !domain_node_collision h).

lemma domain_table_empty : domain_table_recorded empty [].
proof. rewrite /domain_table_recorded /domain_nodes_cover /domain_node_collision; smt(emptyE). qed.

lemma domain_table_insert_node h nodes x d :
  domain_table_recorded h nodes => x\notin h => node_query x =>
  domain_table_recorded h.[x<-d] (node d::nodes).
proof.
  rewrite /domain_table_recorded /domain_nodes_cover /domain_node_collision /=; smt(get_setE domE).
qed.

lemma domain_table_insert_other h nodes x d :
  domain_table_recorded h nodes => !node_query x => domain_table_recorded h.[x<-d] nodes.
proof.
  rewrite /domain_table_recorded /domain_nodes_cover /domain_node_collision; smt(get_setE).
qed.

lemma domain_collision_implies_repeat h nodes :
  domain_table_recorded h nodes => domain_node_collision h => !uniq nodes.
proof. rewrite /domain_table_recorded; smt(). qed.
