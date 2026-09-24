require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import PersistentGrind WotsReferenceRoot VerifierWotsOpening VerifierWotsReplay RawRecoveryTrace.
require import RawWotsExtraction LayerWotsExtraction WotsKeyExtraction LayerBuildExtraction MemoNodeCollision PublicNodeZero.
lemma checked_statement seed0 layer0 tree0 kp0 message0 (signature0 : raw_input list * int) root0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    sigma=signature0.`1 /\ count=signature0.`2 /\
    wots_verifier_opening h0 s0 seed0 layer0 tree0 kp0 message0 root0 signature0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=root0].
proof. exact (raw_wots_recovers_verifier_opening seed0 layer0 tree0 kp0 message0 signature0 root0 h0 s0). qed.
