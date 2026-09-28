(* The actual stack builder supplies its own recorded reference-path witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle.
require import PathReplay RawPathReplay NodeCatalog NodeCatalogDomain CatalogForest.
require import MerkleCatalogObserver MerkleCatalogSound MerkleCatalogAuth.
require import AuthSlots AuthPhase StackPowers BuilderPath.
require import RawSignature CatalogWidths BuilderTotality.

lemma merkle_catalog_structure seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    catalog_exact res.`3 512 /\ map snd res.`2 = [9] /\
    catalog_sound Independent.rawhistory (merkle_pair seed0 layer0 tree0) res.`3 /\
    forest_references res.`3 res.`2 512].
proof.
  conseq (merkle_catalog_complete (PreparationView(Independent)))
    (merkle_catalog_recorded seed0 layer0 tree0); smt().
qed.

lemma merkle_catalog_facts seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    catalog_exact res.`3 512 /\ map snd res.`2 = [9] /\
    catalog_sound Independent.rawhistory (merkle_pair seed0 layer0 tree0) res.`3 /\
    forest_references res.`3 res.`2 512 /\
    slots_saved res.`3 res.`1 target0 9 (captured_full 512 target0)].
proof.
  conseq (merkle_catalog_structure seed0 layer0 tree0 target0)
    (merkle_catalog_auth (PreparationView(Independent)) target0); smt().
qed.

lemma merkle_catalog_path seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    exists leaf,
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1).`1 = (head (nseq 16 0,0) res.`2).`1].
proof.
  conseq (merkle_catalog_facts seed0 layer0 tree0 target0).
  move=> &m hpre result table [hc [hm [hs [hf ha]]]].
  exists (catalog_grid result.`3 0 target0).
  apply (builder_path table (merkle_pair seed0 layer0 tree0)
    result.`3 result.`2 result.`1 target0 9 (nseq 16 0)); smt(stack_pow2_9).
qed.

lemma merkle_catalog_wide_facts seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    catalog_exact res.`3 512 /\ map snd res.`2 = [9] /\
    catalog_sound Independent.rawhistory (merkle_pair seed0 layer0 tree0) res.`3 /\
    forest_references res.`3 res.`2 512 /\
    slots_saved res.`3 res.`1 target0 9 (captured_full 512 target0) /\ catalog_width res.`3].
proof.
  conseq (merkle_catalog_facts seed0 layer0 tree0 target0)
    (merkle_catalog_width (PreparationView(Independent)) independent_hash_ll preparation_wots_ll); smt().
qed.

lemma merkle_catalog_wide_path seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 512 ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair seed0 layer0 tree0)
        (leaf,0,target0) res.`1).`1 = (head (nseq 16 0,0) res.`2).`1].
proof.
  conseq (merkle_catalog_wide_facts seed0 layer0 tree0 target0).
  move=> &m hpre result table [hc [hm [hs [hf [ha hw]]]]].
  have ht : 0 <= target0 < 2^9 by smt(stack_pow2_9).
  have hcat : catalog_exact result.`3 (2^9) by smt(stack_pow2_9).
  have ha' : slots_saved result.`3 result.`1 target0 9
    (captured_full (2^9) target0) by smt(stack_pow2_9).
  have hwleaf := catalog_leaf_width result.`3 9 target0 _ ht hcat hw; first by smt().
  have hwauth := catalog_auth_width result.`3 result.`1 9 target0 _ ht hw ha'; first by smt().
  split; first exact hwauth.
  exists (catalog_grid result.`3 0 target0); split; first exact hwleaf.
  apply (builder_path table (merkle_pair seed0 layer0 tree0)
    result.`3 result.`2 result.`1 target0 9 (nseq 16 0)); smt(stack_pow2_9).
qed.
