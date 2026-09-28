require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsLeafReference WotsReferenceRoot WotsSignatureValue.
require import RawCountRecorded RawWotsRecovery RawWotsReference ActualWotsCorrect WotsSignCorrect RawLeafChains.
lemma raw_wots_recovers_reference seed0 layer0 tree0 kp0 message0 sigma0 count0 d0 leaf0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 sigma0 /\ count_accepts d0 /\
    h0.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf0 /\
    extends h0 Independent.rawhistory ==>
    res=node leaf0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. exact (raw_wots_recovers_reference seed0 layer0 tree0 kp0 message0 sigma0 count0 d0 leaf0 h0 s0). qed.
