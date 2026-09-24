require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature PathReplay RawPathReplay RawForsPathReplay.
require import RawBuilderReference TotalBuilderReference BuildRootProjection.
lemma without_range_fors_tree_reference seed0 ht0 tree0 target0 :
  phoare [RawFors(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 ==>
    rows_width 11 res.`2 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2).`1 = res.`1] = 1%r.
proof. exact (total_fors_tree_reference seed0 ht0 tree0 target0). qed.
