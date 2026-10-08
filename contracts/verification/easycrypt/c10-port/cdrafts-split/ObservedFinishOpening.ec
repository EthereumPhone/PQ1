(* Both hypertree layers account for every newly opened cut in a returned signature. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts ForestCoordinates ForestRootWitness MerkleRootWitness SignerCoordinates.
require import ChainValueView ChainStageSampling CachedChainOracle ChainLayerView ChainSignerView.
require import ObservedValueOpening ObservedPrivateOpening ObservedReferenceTransfer ObservedLayerOpening ObservedCutEvidence.

lemma observed_forest_root_unopened seed0 ht0 digest0 opened0 :
  hoare[RawForest(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ ChainRevelation.opened=opened0 ==>
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 res.`3 /\
    ChainRevelation.opened=opened0].
proof. conseq (observed_forest_root seed0 ht0 digest0) (observed_forest_unopened opened0); smt(). qed.

lemma observed_finish_opening seed0 digest0 opened0 :
  hoare[ChainSigner(ObservedChain(Independent)).finish :
    seed=seed0 /\ digest=digest0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    res<>None => ChainRevelation.opened => opened0 \/
      signed_cut_opened Independent.rawhistory Independent.secrethistory seed0 (hypertree_index digest0)
        (oget res).`4 ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut].
proof.
  proc; seq 2 : (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    ChainStage.seed=seed0 /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht forest.`3).
  + call (observed_forest_root_unopened seed0 (hypertree_index digest0) digest0 opened0); auto.
  wp; while (seed=seed0 /\ digest=digest0 /\ ht=hypertree_index digest0 /\
    0<=layer<=2 /\ idx_tree=signer_tree ht layer /\
    ChainStage.seed=seed0 /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht forest.`3 /\
    (ok => size layers=layer /\ (layer=0 => current=forest.`3) /\
      (layer=1 => merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 0 (ht %/512) current) /\
      (ChainRevelation.opened => opened0 \/
        (1<=layer /\ ChainStage.layer=0 /\ ChainStage.tree=ht %/512 /\ ChainStage.kp=ht %%512 /\
          bottom_cut_opened Independent.rawhistory Independent.secrethistory seed0 ht layers ChainStage.index ChainCut.cut) \/
        (layer=2 /\ ChainStage.layer=1 /\ ChainStage.tree=0 /\ ChainStage.kp=ht %/512 /\
          top_cut_opened Independent.rawhistory Independent.secrethistory seed0 ht layers ChainStage.index ChainCut.cut)))).
  + exists* layer,current,layers,ChainRevelation.opened,Independent.rawhistory,Independent.secrethistory;
      elim* => k cur layers0 opened h0 s0.
    wp; call (observed_layer_history_opening seed0 k (signer_tree (hypertree_index digest0) (k+1))
      (signer_tree (hypertree_index digest0) k %%512) cur opened s0 h0).
    auto; rewrite /signer_tree /valid_chain_address;
      smt(size_rcons extends_refl hypertree_index_range pdiv_small modz_small divz_ge0 ltz_divLR
        forest_root_witness_extends merkle_root_witness_extends bottom_cut_first bottom_cut_append top_cut_second).
  auto; rewrite /signer_tree /signed_cut_opened; smt().
qed.
