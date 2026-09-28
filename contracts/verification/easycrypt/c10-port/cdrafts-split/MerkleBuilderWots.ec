(* Actual Merkle construction supplies both the path and its actual WOTS leaf. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawSignature.
require import PathReplay RawPathReplay NodeCatalog NodeCatalogDomain CatalogForest.
require import AuthSlots AuthPhase CatalogWidths StackPowers BuilderPath BuilderTotality.
require import MerkleCatalogObserver MerkleBuilderPath MerkleBuildWitness WotsCatalog MerkleWotsLeaves WotsReferenceRoot.

lemma merkle_catalog_wots_facts seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    catalog_exact res.`3 512 /\ map snd res.`2=[9] /\
    catalog_sound Independent.rawhistory (merkle_pair seed0 layer0 tree0) res.`3 /\
    forest_references res.`3 res.`2 512 /\
    slots_saved res.`3 res.`1 target0 9 (captured_full 512 target0) /\ catalog_width res.`3 /\
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 res.`3].
proof.
  conseq (merkle_catalog_wide_facts seed0 layer0 tree0 target0)
    (merkle_catalog_wots_leaves seed0 layer0 tree0); smt().
qed.

lemma merkle_catalog_wots_path seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf=16 /\
      wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 target0 leaf /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1).`1
        = (head (nseq 16 0,0) res.`2).`1].
proof.
  conseq (merkle_catalog_wots_facts seed0 layer0 tree0 target0).
  move=> &m hpre result table private [hc [hm [hs [hf [ha [hw ho]]]]]].
  have ht : 0<=target0<2^9 by smt(stack_pow2_9).
  have hcat : catalog_exact result.`3 (2^9) by smt(stack_pow2_9).
  have ha' : slots_saved result.`3 result.`1 target0 9 (captured_full (2^9) target0) by smt(stack_pow2_9).
  have hwa := catalog_auth_width result.`3 result.`1 9 target0 _ ht hw ha'; first smt().
  have hwl := catalog_leaf_width result.`3 9 target0 _ ht hcat hw; first smt().
  have hp := builder_path table (merkle_pair seed0 layer0 tree0) result.`3 result.`2 result.`1 target0 9
    (nseq 16 0) _ ht hcat hs hm _ ha'; first 2 smt(stack_pow2_9).
  have hmem : (0,target0) \in result.`3.
  + apply hc; rewrite /node_due /node_right_edge expr0; smt().
  have hwo := wots_catalog_target table private seed0 layer0 tree0 result.`3 target0 hmem ho.
  split; first exact hwa.
  exists (catalog_grid result.`3 0 target0); smt().
qed.

lemma merkle_witness_wots_path seed0 layer0 tree0 target0 :
  hoare [MerkleBuildWitness(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf=16 /\
      wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 target0 leaf /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1).`1
        = (head (nseq 16 0,0) res.`2).`1].
proof.
  conseq (merkle_catalog_projection (PreparationView(Independent)))
    (merkle_catalog_wots_path seed0 layer0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma merkle_build_wots_path seed0 layer0 tree0 target0 :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf=16 /\
      wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 target0 leaf /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1).`1=res.`2].
proof.
  conseq (merkle_build_witness_projection (PreparationView(Independent)))
    (merkle_witness_wots_path seed0 layer0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma total_merkle_build_wots_path seed0 layer0 tree0 target0 :
  phoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf=16 /\
      wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 target0 leaf /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0) (leaf,0,target0) res.`1).`1=res.`2] = 1%r.
proof. conseq merkle_independent_build_ll (merkle_build_wots_path seed0 layer0 tree0 target0); smt(). qed.
