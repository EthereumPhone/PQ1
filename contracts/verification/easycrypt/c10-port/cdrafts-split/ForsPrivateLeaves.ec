(* Actual FORS leaves use the digest retained under their own private key. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import RawForsPathReplay NodeCatalog ForsCatalogObserver SecretLeafOrigins SecretLeafOracle.

op fors_private_key ht tree index = fors_tag ++ fors_tail ht tree index.

lemma fors_catalog_private_leaves seed0 ht0 tree0 :
  hoare [ForsCatalogObserver(PreparationView(Independent)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 ==>
    secret_leaf_origins Independent.rawhistory Independent.secrethistory
      (fors_leaf_input seed0 ht0 tree0) (fors_private_key ht0 tree0) res.`3].
proof.
  proc; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    secret_leaf_origins Independent.rawhistory Independent.secrethistory
      (fors_leaf_input seed0 ht0 tree0) (fors_private_key ht0 tree0) catalog).
  + wp; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ 0 <= height /\
      secret_leaf_origins Independent.rawhistory Independent.secrethistory
        (fors_leaf_input seed0 ht0 tree0) (fors_private_key ht0 tree0) catalog).
    - exists* catalog; elim* => cat0.
      wp; call (hash_keeps_secret_leaves (fors_leaf_input seed0 ht0 tree0)
        (fors_private_key ht0 tree0) cat0).
      auto; smt(secret_leaf_parent).
    seq 2 : (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ current = node d /\
      Independent.secrethistory.[fors_private_key ht0 tree0 j] = Some d /\
      secret_leaf_origins Independent.rawhistory Independent.secrethistory
        (fors_leaf_input seed0 ht0 tree0) (fors_private_key ht0 tree0) catalog).
    - exists* catalog,j; elim* => cat0 j0.
      wp; call (fors_records_secret_leaves (fors_leaf_input seed0 ht0 tree0)
        (fors_private_key ht0 tree0) cat0 (fors_tail ht0 tree0 j0)).
      auto; rewrite /fors_private_key; smt().
    exists* catalog,d,j; elim* => cat0 sd0 j0.
    wp; call (hash_records_secret_leaves (fors_leaf_input seed0 ht0 tree0)
      (fors_private_key ht0 tree0) cat0
      (fors_leaf_input seed0 ht0 tree0 j0 (node sd0))).
    auto; rewrite /fors_leaf_input; smt(secret_leaf_insert).
  auto; smt(secret_leaf_empty).
qed.
