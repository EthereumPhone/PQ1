require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsLeafReference WotsReferenceRoot WotsSignatureValue.
require import RawCountRecorded RawWotsRecovery RawWotsReference ActualWotsCorrect WotsSignCorrect RawLeafChains.
lemma total_actual_wots_correct seed0 layer0 tree0 kp0 message0 :
  phoare [ActualWotsConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res.`2<>None /\ res.`3=Some res.`1] = 1%r.
proof. exact (total_actual_wots_correct seed0 layer0 tree0 kp0 message0). qed.
