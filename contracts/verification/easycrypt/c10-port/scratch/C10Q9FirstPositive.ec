require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import MerkleRootWitness MerkleRootPersistence LayerPriorRoot LayerSignWitness ActualLayerCorrect.

module ActualFirst = {
  proc run() : raw_input * (layer_signature * raw_input) option * raw_input option = {
    var result;
    result <@ ActualLayerConstruction(PreparationView(Independent)).run(nseq 32 0,0,0,0,nseq 16 0,nseq 32 0);
    return result;
  }
}.
lemma actual_layer_component :
  phoare [ActualFirst.run : true ==>
    (res.`2=None => res.`3=None) /\ (res.`2<>None => res.`3=Some res.`1)] = 1%r.
proof. proc; call (total_actual_layer_correct (nseq 32 0) 0 0 0 (nseq 16 0)); auto. qed.
