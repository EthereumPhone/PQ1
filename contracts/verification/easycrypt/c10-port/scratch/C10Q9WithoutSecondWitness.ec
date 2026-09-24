require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import MerkleRootWitness MerkleRootPersistence LayerPriorRoot LayerSignWitness ActualLayerCorrect.
lemma merkle_root_witness_unique h s seed layer tree root root' :
  merkle_root_witness h s seed layer tree root => root=root'.
proof. exact (merkle_root_witness_unique h s seed layer tree root root'). qed.
