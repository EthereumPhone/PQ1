require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest.
require import PersistentGrind RawForsPathReplay ForsOpening ForestOpenings ForestWitness.
require import ForestRecoveryReplay ForestSignRecorded ActualForestCorrect.

module ActualShuffled = {
  proc run() : (raw_input list * raw_input list list * raw_input) * raw_input = {
    var result;
    result <@ ActualForestConstruction(PreparationView(Independent)).run(nseq 32 0,0,nseq 256 false,nseq 32 1);
    return result;
  }
}.
lemma actual_forest_component :
  phoare [ActualShuffled.run : true ==> res.`1.`3=res.`2] = 1%r.
proof. proc; call (total_actual_forest_correct (nseq 32 0) 0 (nseq 256 false)); auto. qed.
