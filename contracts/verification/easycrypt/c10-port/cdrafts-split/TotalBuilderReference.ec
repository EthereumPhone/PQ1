(* The reference-path result holds with probability one for the actual oracle. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature.
require import PathReplay RawPathReplay RawForsPathReplay RawBuilderReference BuilderTotality.

lemma total_merkle_build_reference seed0 layer0 tree0 target0 :
  phoare [RawMerkle(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1).`1 = res.`2] = 1%r.
proof.
  conseq merkle_independent_build_ll (merkle_build_reference seed0 layer0 tree0 target0); smt().
qed.

lemma total_fors_tree_reference seed0 ht0 tree0 target0 :
  phoare [RawFors(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2).`1 = res.`1] = 1%r.
proof.
  conseq fors_independent_tree_ll (fors_tree_reference seed0 ht0 tree0 target0); smt().
qed.
