(* Accepted actual finish results retain a complete forest/layer trace. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts MerkleRootWitness ForestOpening SignerCoordinates.
require import SignerForestStep SignerLayerStep SignerFinishState SignerFinishWitness.

lemma observed_finish_recorded seed0 digest0 root0 :
  hoare [SignerFinishWitness(Independent).finish :
    seed=seed0 /\ digest=digest0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res.`1<>None => signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 digest0 (oget res.`1) root0].
proof.
  proc; seq 2 : (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    forest_opening Independent.rawhistory seed0 ht digest0 forest.`1 forest.`2 forest.`3 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (forest_sign_keeps_top seed0 (hypertree_index digest0) digest0 root0); auto; smt().
  wp; while (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\
    (ok => signer_finish_state Independent.rawhistory Independent.secrethistory
      seed0 digest0 forest values layers layer current root0)).
  + exists* layer,current,forest,values,layers,Independent.rawhistory,Independent.secrethistory;
      elim* => k cur forest0 values0 layers0 h0 s0.
    wp; call (layer_sign_step seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) cur root0 s0 h0).
    auto; smt(extends_refl hypertree_index_range signer_coordinate_step signer_top_tree
      finish_state_extends finish_state_step).
  auto; rewrite /signer_tree; smt(finish_state_initial finish_state_complete).
qed.

lemma raw_finish_recorded seed0 digest0 root0 :
  hoare [RawSigner(Independent).finish :
    seed=seed0 /\ digest=digest0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res<>None => signer_finish_opening Independent.rawhistory Independent.secrethistory seed0 digest0 (oget res) root0].
proof.
  conseq (signer_finish_witness_projection Independent) (observed_finish_recorded seed0 digest0 root0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},randomizer{m},digest{m},shuffle{m}); smt().
  smt().
qed.
