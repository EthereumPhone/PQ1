require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsLeafReference WotsReferenceRoot WotsSignatureValue.
require import RawCountRecorded RawWotsRecovery RawWotsReference ActualWotsCorrect WotsSignCorrect RawLeafChains.
lemma wots_sign_recover_correct seed0 layer0 tree0 kp0 message0 root0 :
  hoare [RawWotsSignRecover(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    (res.`1=None => res.`2=None) /\ (res.`1<>None => res.`2=Some root0)].
proof. exact (wots_sign_recover_correct seed0 layer0 tree0 kp0 message0 root0). qed.
