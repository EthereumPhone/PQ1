require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import PersistentGrind WotsReferenceRoot VerifierWotsOpening VerifierWotsReplay RawRecoveryTrace.
require import RawWotsExtraction LayerWotsExtraction WotsKeyExtraction LayerBuildExtraction MemoNodeCollision PublicNodeZero.
lemma checked_statement seed0 layer0 tree0 kp0 message0 (sig0 : layer_signature) :
  phoare [LayerBuildCompare.run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sig=sig0 /\
    layer_width sig0 ==>
    res.`2=res.`1 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists leaf0, wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 leaf0 (sig0.`1,sig0.`2)] = 1%r.
proof. exact (total_actual_layer_builder_extraction seed0 layer0 tree0 kp0 message0 sig0). qed.
