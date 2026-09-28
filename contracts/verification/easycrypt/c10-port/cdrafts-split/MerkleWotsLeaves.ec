(* Actual Merkle catalog leaves retain their actual WOTS keygen roots. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import NodeCatalog MerkleCatalogObserver WotsCatalog WotsCatalogOracle.

lemma merkle_catalog_wots_leaves seed0 layer0 tree0 :
  hoare [MerkleCatalogObserver(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 ==>
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 res.`3].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 catalog).
  + wp; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=height /\
      wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 catalog).
    - exists* catalog; elim* => cat0.
      wp; call (hash_keeps_wots_catalog seed0 layer0 tree0 cat0).
      auto; smt(wots_catalog_parent).
    exists* catalog,kp; elim* => cat0 index0.
    wp; call (leaf_records_wots_catalog seed0 layer0 tree0 index0 cat0).
    auto; smt(wots_catalog_leaf).
  auto; smt(wots_catalog_empty).
qed.
