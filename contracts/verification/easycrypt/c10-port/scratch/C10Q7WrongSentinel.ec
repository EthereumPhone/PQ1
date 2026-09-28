require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsLeafReference WotsReferenceRoot WotsSignatureValue.
require import RawCountRecorded RawWotsRecovery RawWotsReference ActualWotsCorrect WotsSignCorrect RawLeafChains.
lemma raw_wots_invalid_sum_sentinel seed0 layer0 tree0 kp0 message0 count0 d0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ count=count0 /\
    !count_accepts d0 /\ h0.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=nseq 16 1].
proof. exact (raw_wots_invalid_sum_sentinel seed0 layer0 tree0 kp0 message0 count0 d0 h0 s0). qed.
