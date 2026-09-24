(* Actual FORS builders supply the complete private-leaf root witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import NodeCatalog NodeCatalogDomain CatalogForest StackPowers ForsRootWitness.
require import ForsCatalogObserver ForsBuildWitness ForsBuilderPrivate.

lemma fors_catalog_records_root seed0 ht0 tree0 target0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<2048 ==>
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0
      (head (nseq 16 0,0) res.`1).`1].
proof.
  conseq (fors_catalog_private_facts seed0 ht0 tree0 target0).
  move=> &m hp result table private [hc [hm [hs [hf [ha [hw ho]]]]]].
  have hf' : forest_references result.`3 result.`1 (2^11) by smt(stack_pow2_11).
  have hr := forest_singleton_root result.`3 result.`1 11 (nseq 16 0) _ hm hf'; first smt().
  exists result.`3; smt().
qed.

lemma fors_witness_records_root seed0 ht0 tree0 target0 :
  hoare [ForsBuildWitness(PreparationView(Independent)).tree :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<2048 ==>
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0
      (head (nseq 16 0,0) res.`1).`1].
proof.
  conseq (fors_catalog_projection (PreparationView(Independent)))
    (fors_catalog_records_root seed0 ht0 tree0 target0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fors_tree_records_root seed0 ht0 tree0 target0 :
  hoare [RawFors(PreparationView(Independent)).tree :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<2048 ==>
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`1].
proof.
  conseq (fors_tree_witness_projection (PreparationView(Independent)))
    (fors_witness_records_root seed0 ht0 tree0 target0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fors_root_records_root seed0 ht0 tree0 :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 ==>
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res].
proof. proc; call (fors_tree_records_root seed0 ht0 tree0 0); auto; smt(). qed.
