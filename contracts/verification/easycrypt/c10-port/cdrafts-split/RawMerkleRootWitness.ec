(* Actual builders and key generation supply the complete root witness. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RawMerkle.
require import NodeCatalog NodeCatalogDomain CatalogForest StackPowers WotsCatalog MerkleRootWitness.
require import MerkleCatalogObserver MerkleBuildWitness MerkleBuilderWots BuildRootProjection BuilderTotality.

lemma merkle_catalog_records_root seed0 layer0 tree0 target0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0
      (head (nseq 16 0,0) res.`2).`1].
proof.
  conseq (merkle_catalog_wots_facts seed0 layer0 tree0 target0).
  move=> &m hp result table private [hc [hm [hs [hf [ha [hw ho]]]]]].
  have hf' : forest_references result.`3 result.`2 (2^9) by smt(stack_pow2_9).
  have hr := forest_singleton_root result.`3 result.`2 9 (nseq 16 0) _ hm hf'; first smt().
  rewrite /merkle_root_witness; exists result.`3; smt().
qed.

lemma merkle_witness_records_root seed0 layer0 tree0 target0 :
  hoare [MerkleBuildWitness(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0
      (head (nseq 16 0,0) res.`2).`1].
proof.
  conseq (merkle_catalog_projection (PreparationView(Independent)))
    (merkle_catalog_records_root seed0 layer0 tree0 target0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma merkle_build_records_root seed0 layer0 tree0 target0 :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 res.`2].
proof.
  conseq (merkle_build_witness_projection (PreparationView(Independent)))
    (merkle_witness_records_root seed0 layer0 tree0 target0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma keygen_root_recorded seed0 layer0 tree0 :
  hoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 res].
proof.
  conseq (merkle_build_root_projection (PreparationView(Independent)))
    (merkle_build_records_root seed0 layer0 tree0 0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},0); smt().
  smt().
qed.

lemma total_keygen_root_recorded seed0 layer0 tree0 :
  phoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 res] = 1%r.
proof.
  conseq (root_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll)
    (keygen_root_recorded seed0 layer0 tree0); smt().
qed.
