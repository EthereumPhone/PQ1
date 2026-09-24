require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay ForsPrivateLeaves.
require import ForsBuilderPrivate ForsKnownSecret ForsSignWitness ForsSignCorrect ForsSignRecord.
lemma without_private_entry seed0 ht0 tree0 target0 sd0 :
  hoare [RawFors(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 (node sd0)] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2).`1 = res.`1].
proof. exact (fors_tree_known_secret seed0 ht0 tree0 target0 sd0). qed.
