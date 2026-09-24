require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature RawWidths PathReplay PathInputs RawPathReplay RawForsPathReplay ForsLeafInputs.
require import ForsBuilderSecret ForsBuilderComparison MerkleBuilderComparison.
lemma without_collision seed0 ht0 tree0 target0 secret0 auth0 :
  phoare [ForsBuildCompare.run :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    secret = secret0 /\ auth = auth0 /\
    0 <= target0 < 2048 /\ size secret0 = 16 /\ rows_width 11 auth0 ==>
    rows_width 11 res.`3 /\ exists reference_secret reference_digest,
      size reference_secret = 16 /\
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 reference_secret] = Some reference_digest /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node reference_digest,0,target0) res.`3 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node reference_digest,0,target0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 =>
        secret0 = reference_secret)] = 1%r.
proof. exact (total_actual_fors_builder_comparison seed0 ht0 tree0 target0 secret0 auth0). qed.
