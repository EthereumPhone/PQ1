require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import MerkleRootWitness MerkleRootPersistence LayerPriorRoot LayerSignWitness ActualLayerCorrect.
lemma total_actual_layer_correct seed0 layer0 tree0 index0 message0 :
  phoare [ActualLayerConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 ==>
    (res.`2=None => res.`3=None) /\ (res.`2<>None => res.`3=Some res.`1)] = 1%r.
proof. exact (total_actual_layer_correct seed0 layer0 tree0 index0 message0). qed.
