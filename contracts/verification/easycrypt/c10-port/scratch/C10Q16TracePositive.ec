require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import PersistentGrind WotsReferenceRoot VerifierWotsOpening VerifierWotsReplay RawRecoveryTrace.
require import RawWotsExtraction LayerWotsExtraction WotsKeyExtraction LayerBuildExtraction MemoNodeCollision PublicNodeZero.
lemma checked_statement seed0 layer0 tree0 kp0 message0 sigma0 count0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 ==>
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 res].
proof. exact (raw_recovery_recorded seed0 layer0 tree0 kp0 message0 sigma0 count0). qed.
