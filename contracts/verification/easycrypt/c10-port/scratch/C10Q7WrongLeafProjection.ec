require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsLeafReference WotsReferenceRoot WotsSignatureValue.
require import RawCountRecorded RawWotsRecovery RawWotsReference ActualWotsCorrect WotsSignCorrect RawLeafChains.

lemma wrong_leaf_projection (O <: PreparationOracle) :
  equiv [RawKeygen(O).leaf ~ RawLeafChains(O).leaf :
    ={seed,layer,tree,kp,glob O} ==> res{1}=nseq 16 0 /\ ={glob O}].
proof. exact (raw_leaf_chain_projection O). qed.
