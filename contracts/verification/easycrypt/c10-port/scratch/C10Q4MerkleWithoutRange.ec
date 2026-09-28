require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature PathReplay RawPathReplay RawForsPathReplay.
require import RawBuilderReference TotalBuilderReference BuildRootProjection.
lemma without_range_merkle_build_reference seed0 layer0 tree0 target0 :
  phoare [RawMerkle(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1).`1 = res.`2] = 1%r.
proof. exact (total_merkle_build_reference seed0 layer0 tree0 target0). qed.
