(* The actual stack builder supplies its own recorded reference-path witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PathReplay RawForsPathReplay NodeCatalog NodeCatalogDomain CatalogForest.
require import ForsCatalogObserver ForsCatalogSound ForsCatalogAuth.
require import AuthSlots AuthPhase StackPowers BuilderPath.
require import RawSignature CatalogWidths BuilderTotality.

lemma fors_catalog_structure seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    catalog_exact res.`3 2048 /\ map snd res.`1 = [11] /\
    catalog_sound Independent.rawhistory (fors_pair seed0 ht0 tree0) res.`3 /\
    forest_references res.`3 res.`1 2048].
proof.
  conseq (fors_catalog_complete (PreparationView(Independent)))
    (fors_catalog_recorded seed0 ht0 tree0); smt().
qed.

lemma fors_catalog_facts seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    catalog_exact res.`3 2048 /\ map snd res.`1 = [11] /\
    catalog_sound Independent.rawhistory (fors_pair seed0 ht0 tree0) res.`3 /\
    forest_references res.`3 res.`1 2048 /\
    slots_saved res.`3 res.`2 target0 11 (captured_full 2048 target0)].
proof.
  conseq (fors_catalog_structure seed0 ht0 tree0 target0)
    (fors_catalog_auth (PreparationView(Independent)) target0); smt().
qed.

lemma fors_catalog_path seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    exists leaf,
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2).`1 = (head (nseq 16 0,0) res.`1).`1].
proof.
  conseq (fors_catalog_facts seed0 ht0 tree0 target0).
  move=> &m hpre result table [hc [hm [hs [hf ha]]]].
  exists (catalog_grid result.`3 0 target0).
  apply (builder_path table (fors_pair seed0 ht0 tree0)
    result.`3 result.`1 result.`2 target0 11 (nseq 16 0)); smt(stack_pow2_11).
qed.

lemma fors_catalog_wide_facts seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    catalog_exact res.`3 2048 /\ map snd res.`1 = [11] /\
    catalog_sound Independent.rawhistory (fors_pair seed0 ht0 tree0) res.`3 /\
    forest_references res.`3 res.`1 2048 /\
    slots_saved res.`3 res.`2 target0 11 (captured_full 2048 target0) /\ catalog_width res.`3].
proof.
  conseq (fors_catalog_facts seed0 ht0 tree0 target0)
    (fors_catalog_width (PreparationView(Independent))); smt().
qed.

lemma fors_catalog_wide_path seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (leaf,0,target0) res.`2).`1 = (head (nseq 16 0,0) res.`1).`1].
proof.
  conseq (fors_catalog_wide_facts seed0 ht0 tree0 target0).
  move=> &m hpre result table [hc [hm [hs [hf [ha hw]]]]].
  have ht : 0 <= target0 < 2^11 by smt(stack_pow2_11).
  have hcat : catalog_exact result.`3 (2^11) by smt(stack_pow2_11).
  have ha' : slots_saved result.`3 result.`2 target0 11
    (captured_full (2^11) target0) by smt(stack_pow2_11).
  have hwleaf := catalog_leaf_width result.`3 11 target0 _ ht hcat hw; first by smt().
  have hwauth := catalog_auth_width result.`3 result.`2 11 target0 _ ht hw ha'; first by smt().
  split; first exact hwauth.
  exists (catalog_grid result.`3 0 target0); split; first exact hwleaf.
  apply (builder_path table (fors_pair seed0 ht0 tree0)
    result.`3 result.`1 result.`2 target0 11 (nseq 16 0)); smt(stack_pow2_11).
qed.
