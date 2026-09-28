require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import MerkleRootWitness MerkleRootPersistence LayerPriorRoot LayerSignWitness ActualLayerCorrect.
lemma raw_layer_matches_prior_root seed0 layer0 tree0 index0 message0 root0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    res<>None => (oget res).`2=root0].
proof. exact (raw_layer_matches_prior_root seed0 layer0 tree0 index0 message0 root0). qed.
