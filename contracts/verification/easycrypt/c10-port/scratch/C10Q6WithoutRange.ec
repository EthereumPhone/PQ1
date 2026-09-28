require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay ForsPrivateLeaves.
require import ForsBuilderPrivate ForsKnownSecret ForsSignWitness ForsSignCorrect ForsSignRecord.
lemma without_target_range seed0 ht0 tree0 target0 :
  phoare [RawFors(PreparationView(Independent)).sign :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 ==>
    size res.`1 = 16 /\ rows_width 11 res.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 res.`1] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2] = 1%r.
proof. exact (total_fors_sign_recorded seed0 ht0 tree0 target0). qed.
