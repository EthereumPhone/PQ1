(* Successful complete signing uses the canonical count at both fixed component messages. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts ForestRootWitness ForestRootRecording MerkleRootWitness.
require import SignerCoordinates LayerMinimumCounts.

op top_minimum_count h s seed ht layers =
  exists lower, merkle_root_witness h s seed 0 (ht %/512) lower /\
    minimal_layer_count h seed 1 0 (ht %/512) lower (nth ([],0,[]) layers 1).
op signed_minimum_counts h s seed ht layers =
  exists forest, forest_root_witness h s seed ht forest /\
    minimal_layer_count h seed 0 (ht %/512) (ht %%512) forest (nth ([],0,[]) layers 0) /\
    top_minimum_count h s seed ht layers.

lemma top_minimum_extends h h' s s' seed ht layers :
  extends h h' => extends s s' => top_minimum_count h s seed ht layers =>
  top_minimum_count h' s' seed ht layers.
proof. rewrite /top_minimum_count; smt(merkle_root_witness_extends minimal_layer_count_extends). qed.
lemma signed_minimum_extends h h' s s' seed ht layers :
  extends h h' => extends s s' => signed_minimum_counts h s seed ht layers =>
  signed_minimum_counts h' s' seed ht layers.
proof. rewrite /signed_minimum_counts; smt(forest_root_witness_extends minimal_layer_count_extends top_minimum_extends). qed.
lemma top_minimum_step h h' s s' seed ht layers lower signature :
  extends h h' => extends s s' => size layers=1 =>
  merkle_root_witness h s seed 0 (ht %/512) lower =>
  minimal_layer_count h' seed 1 0 (ht %/512) lower signature =>
  top_minimum_count h' s' seed ht (rcons layers signature).
proof.
  move=> hh hs hl hw hc; exists lower; rewrite nth_rcons hl /=;
    smt(merkle_root_witness_extends).
qed.

lemma finish_minimum_counts seed0 digest0 :
  hoare [RawSigner(Independent).finish : seed=seed0 /\ digest=digest0 ==>
    res<>None => signed_minimum_counts Independent.rawhistory Independent.secrethistory
      seed0 (hypertree_index digest0) (oget res).`4].
proof.
  proc; seq 2 : (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht forest.`3).
  + call (raw_forest_sign_root seed0 (hypertree_index digest0) digest0); auto.
  wp; while (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht forest.`3 /\
    (ok => size layers=layer /\
      (layer=0 => current=forest.`3) /\
      (1<=layer => minimal_layer_count Independent.rawhistory seed0 0 (ht %/512) (ht %%512)
        forest.`3 (nth ([],0,[]) layers 0)) /\
      (layer=1 => merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 0 (ht %/512) current) /\
      (layer=2 => top_minimum_count Independent.rawhistory Independent.secrethistory seed0 ht layers))).
  + exists* layer,current,layers,Independent.rawhistory,Independent.secrethistory;
      elim* => k cur layers0 h0 s0.
    wp; call (layer_sign_root_count seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) cur s0 h0).
    auto; rewrite /signer_tree;
      smt(size_rcons nth_rcons minimal_layer_count_extends forest_root_witness_extends top_minimum_step
        extends_refl hypertree_index_range pdiv_small modz_small divz_ge0 ltz_divLR).
  auto; rewrite /signer_tree /signed_minimum_counts; smt().
qed.
