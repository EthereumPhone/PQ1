require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import MerkleRootWitness MerkleRootPersistence LayerPriorRoot LayerSignWitness ActualLayerCorrect.

lemma wrong_projection (O <: PreparationOracle) :
  equiv [RawLayer(O).sign ~ LayerSignWitness(O).sign :
    ={seed,layer,tree,leaf,message,shuffle,glob O} ==> res{1}=None /\ ={glob O}].
proof. exact (layer_sign_witness_projection O). qed.
