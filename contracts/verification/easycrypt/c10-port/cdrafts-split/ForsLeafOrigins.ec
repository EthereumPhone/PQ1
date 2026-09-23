(* Every actual FORS catalog leaf comes from a retained initial leaf-hash call. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import RawForsPathReplay NodeCatalog ForsCatalogObserver LeafOrigins LeafOriginOracle.

lemma fors_catalog_leaf_origins seed0 ht0 tree0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 ==>
    leaf_origins Independent.rawhistory (fors_leaf_input seed0 ht0 tree0) res.`3].
proof.
  proc; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    leaf_origins Independent.rawhistory (fors_leaf_input seed0 ht0 tree0) catalog).
  + wp; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ 0 <= height /\
      leaf_origins Independent.rawhistory (fors_leaf_input seed0 ht0 tree0) catalog).
    - exists* catalog; elim* => cat0.
      wp; call (hash_keeps_leaf_origins (fors_leaf_input seed0 ht0 tree0) cat0).
      auto; smt(leaf_origins_parent).
    seq 2 : (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ size current = 16 /\
      leaf_origins Independent.rawhistory (fors_leaf_input seed0 ht0 tree0) catalog).
    - exists* catalog; elim* => cat0.
      wp; call (fors_keeps_leaf_origins (fors_leaf_input seed0 ht0 tree0) cat0).
      auto; smt(node_width).
    exists* catalog,current,j; elim* => cat0 secret0 j0.
    wp; call (hash_records_leaf_origins (fors_leaf_input seed0 ht0 tree0) cat0
      (fors_leaf_input seed0 ht0 tree0 j0 secret0)).
    auto; rewrite /fors_leaf_input; smt(leaf_origins_leaf).
  auto; smt(leaf_origins_empty).
qed.
