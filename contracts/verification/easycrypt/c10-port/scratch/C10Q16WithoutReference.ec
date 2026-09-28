require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import PersistentGrind WotsReferenceRoot VerifierWotsOpening VerifierWotsReplay RawRecoveryTrace.
require import RawWotsExtraction LayerWotsExtraction WotsKeyExtraction LayerBuildExtraction MemoNodeCollision PublicNodeZero.
lemma checked_statement seed0 layer0 tree0 kp0 message0 sigma0 count0 root0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    rows_width 43 sigma0 /\ 0<=count0<4294967296 ==>
    res=root0 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 root0 (sigma0,count0)].
proof. exact (raw_wots_extracts_opening seed0 layer0 tree0 kp0 message0 sigma0 count0 root0). qed.
