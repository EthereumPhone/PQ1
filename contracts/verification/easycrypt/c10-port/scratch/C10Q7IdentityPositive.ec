require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsLeafReference WotsReferenceRoot WotsSignatureValue.
require import RawCountRecorded RawWotsRecovery RawWotsReference ActualWotsCorrect WotsSignCorrect RawLeafChains.

module ActualIdentity = {
  proc run() : raw_input * (raw_input list * int) option * raw_input option = {
    var result;
    result <@ ActualWotsConstruction(PreparationView(Independent)).run(nseq 32 0,0,0,0,nseq 16 0,nseq 32 0);
    return result;
  }
}.
lemma actual_wots_component :
  phoare [ActualIdentity.run : true ==>
    (res.`2=None => res.`3=None) /\ (res.`2<>None => res.`3=Some res.`1)] = 1%r.
proof.
  proc; call (total_actual_wots_correct (nseq 32 0) 0 0 0 (nseq 16 0)); auto.
qed.
