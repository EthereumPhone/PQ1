(* Algebraic boundary witnesses; none is an adaptive guessing bound. *)
require import AllCore List FMap FSet.
require import C10RawOracle RawKeygen RawForest ForsPrivateLeaves MemoNodeCollision.
require import JointNodeCollision ForsValueExposure ExposureCoverage.

lemma singleton_private_not_aliased key d :
  !private_node_alias empty (empty.[key<-d]).
proof.
  rewrite /private_node_alias /cross_node_alias /public_node_collision;
    smt(get_setE emptyE).
qed.

lemma one_private_draw key d : joint_draws empty (empty.[key<-d])=1.
proof. rewrite /joint_draws !fdom_set !fdom0 !fcards0 fcardU1; smt(in_fset0). qed.

lemma private_replay_one_draw key d : joint_draws empty (empty.[key<-d].[key<-d])=1.
proof. rewrite set_set_sameE; exact (one_private_draw key d). qed.

lemma equal_raw_keys_cross_alias key d :
  private_node_alias (empty.[key<-d]) (empty.[key<-d]).
proof.
  rewrite /private_node_alias /cross_node_alias; right; exists key key d d;
    smt(get_setE).
qed.

lemma equal_raw_keys_two_draws key d :
  joint_draws (empty.[key<-d]) (empty.[key<-d])=2.
proof. rewrite /joint_draws !fdom_set !fdom0 !fcardU1; smt(in_fset0 fcards0). qed.

lemma distinct_private_alias key other d : key<>other =>
  private_node_alias empty (empty.[key<-d].[other<-d]).
proof.
  rewrite /private_node_alias /public_node_collision; move=> hn; left;
    exists key other d d; smt(get_setE).
qed.

lemma public_node_alias key query d :
  node_known_elsewhere (empty.[query<-d]) (empty.[key<-d]) key (node d).
proof. rewrite /node_known_elsewhere; left; exists query d; smt(get_setE). qed.

lemma singleton_private_value_not_elsewhere key d :
  !node_known_elsewhere empty (empty.[key<-d]) key (node d).
proof. rewrite /node_known_elsewhere; smt(get_setE emptyE). qed.

lemma unaliased_opening_is_possible seed root d sd :
  unaliased_private_opening empty
    (empty.[fors_private_key (hypertree_index d) 0 (forest_index d 0)<-sd])
    seed root [] d (nseq 12 (node sd)).
proof.
  rewrite /unaliased_private_opening; exists 0 sd.
  rewrite /returned_coordinate /logged_digest /=;
    smt(get_setE nth_nseq singleton_private_value_not_elsewhere).
qed.
