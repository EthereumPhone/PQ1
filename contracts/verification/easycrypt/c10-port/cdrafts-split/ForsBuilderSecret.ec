(* The actual FORS builder supplies both the initial leaf hash and the path. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay NodeCatalog NodeCatalogDomain CatalogForest.
require import AuthSlots AuthPhase CatalogWidths StackPowers BuilderPath BuilderTotality.
require import ForsCatalogObserver ForsBuilderPath ForsBuildWitness.
require import LeafOrigins ForsLeafOrigins.

lemma fors_catalog_secret_facts seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    catalog_exact res.`3 2048 /\ map snd res.`1 = [11] /\
    catalog_sound Independent.rawhistory (fors_pair seed0 ht0 tree0) res.`3 /\
    forest_references res.`3 res.`1 2048 /\
    slots_saved res.`3 res.`2 target0 11 (captured_full 2048 target0) /\
    catalog_width res.`3 /\
    leaf_origins Independent.rawhistory (fors_leaf_input seed0 ht0 tree0) res.`3].
proof.
  conseq (fors_catalog_wide_facts seed0 ht0 tree0 target0)
    (fors_catalog_leaf_origins seed0 ht0 tree0); smt().
qed.

lemma fors_catalog_secret_path seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists secret d, size secret = 16 /\
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2).`1 = (head (nseq 16 0,0) res.`1).`1].
proof.
  conseq (fors_catalog_secret_facts seed0 ht0 tree0 target0).
  move=> &m hpre result table [hc [hm [hs [hf [ha [hw ho]]]]]].
  have ht : 0 <= target0 < 2^11 by smt(stack_pow2_11).
  have hcat : catalog_exact result.`3 (2^11) by smt(stack_pow2_11).
  have ha' : slots_saved result.`3 result.`2 target0 11
    (captured_full (2^11) target0) by smt(stack_pow2_11).
  have hwauth := catalog_auth_width result.`3 result.`2 11 target0 _ ht hw ha'; first by smt().
  have hp := builder_path table (fors_pair seed0 ht0 tree0)
    result.`3 result.`1 result.`2 target0 11 (nseq 16 0) _ ht hcat hs hm _ ha';
    first 2 by smt(stack_pow2_11).
  have [secret d [hwidth [hentry hleaf]]] :=
    catalog_target_origin table (fors_leaf_input seed0 ht0 tree0) result.`3 11 target0 _ ht hcat ho;
    first by smt().
  split; first exact hwauth.
  exists secret d; smt().
qed.

lemma fors_witness_secret_path seed0 ht0 tree0 target0 :
  hoare [ForsBuildWitness(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists secret d, size secret = 16 /\
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2).`1 = (head (nseq 16 0,0) res.`1).`1].
proof.
  conseq (fors_catalog_projection (PreparationView(Independent)))
    (fors_catalog_secret_path seed0 ht0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fors_tree_secret_path seed0 ht0 tree0 target0 :
  hoare [RawFors(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists secret d, size secret = 16 /\
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2).`1 = res.`1].
proof.
  conseq (fors_tree_witness_projection (PreparationView(Independent)))
    (fors_witness_secret_path seed0 ht0 tree0 target0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma total_fors_tree_secret_path seed0 ht0 tree0 target0 :
  phoare [RawFors(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    rows_width 11 res.`2 /\ exists secret d, size secret = 16 /\
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 secret] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2).`1 = res.`1] = 1%r.
proof.
  conseq fors_independent_tree_ll (fors_tree_secret_path seed0 ht0 tree0 target0); smt().
qed.
