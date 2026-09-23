require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature RawWidths PathReplay PathInputs RawPathReplay RawForsPathReplay ForsLeafInputs.
require import ForsBuilderSecret ForsBuilderComparison MerkleBuilderComparison.
lemma without_collision seed0 layer0 tree0 target0 leaf0 auth0 :
  phoare [MerkleBuildCompare.run :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    leaf = leaf0 /\ auth = auth0 /\
    0 <= target0 < 512 /\ size leaf0 = 16 /\ rows_width 9 auth0 ==>
    rows_width 9 res.`3 /\ exists reference_leaf, size reference_leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (reference_leaf,0,target0) res.`3 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (reference_leaf,0,target0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 => leaf0 = reference_leaf)] = 1%r.
proof. exact (total_actual_merkle_builder_comparison seed0 layer0 tree0 target0 leaf0 auth0). qed.
