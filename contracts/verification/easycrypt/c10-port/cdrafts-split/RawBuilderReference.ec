(* Reference paths produced by the actual memoized raw builders. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature.
require import PathReplay RawPathReplay RawForsPathReplay.
require import MerkleBuildWitness ForsBuildWitness MerkleCatalogObserver ForsCatalogObserver.
require import MerkleBuilderPath ForsBuilderPath.

lemma merkle_witness_reference seed0 layer0 tree0 target0 :
  hoare [MerkleBuildWitness(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1).`1 = (head (nseq 16 0,0) res.`2).`1].
proof.
  conseq (merkle_catalog_projection (PreparationView(Independent)))
    (merkle_catalog_wide_path seed0 layer0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma merkle_build_reference seed0 layer0 tree0 target0 :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1).`1 = res.`2].
proof.
  conseq (merkle_build_witness_projection (PreparationView(Independent)))
    (merkle_witness_reference seed0 layer0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fors_witness_reference seed0 ht0 tree0 target0 :
  hoare [ForsBuildWitness(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2).`1 = (head (nseq 16 0,0) res.`1).`1].
proof.
  conseq (fors_catalog_projection (PreparationView(Independent)))
    (fors_catalog_wide_path seed0 ht0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fors_tree_reference seed0 ht0 tree0 target0 :
  hoare [RawFors(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2).`1 = res.`1].
proof.
  conseq (fors_tree_witness_projection (PreparationView(Independent)))
    (fors_witness_reference seed0 ht0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.
