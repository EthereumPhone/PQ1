(* The actual forest signer records all twelve paths, its special last hash,
   and the exact final root-compression input. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawShuffle.
require import ForsOpening ForestOpenings ForestWitness ForestOracle ForestOneStep RawShufflePermutation.

lemma forest_sign_recorded seed0 ht0 digest0 :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 ==>
    exists roots d, forest_witness Independent.rawhistory seed0 ht0 digest0 res.`1 res.`2 roots /\
      Independent.rawhistory.[forest_compress_input seed0 ht0 roots]=Some d /\ res.`3=node d].
proof.
  proc; seq 7 : (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets auths roots (range 0 12)).
  + while (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ 0<=step<=12 /\
      perm_eq order (range 0 12) /\
      forest_openings Independent.rawhistory seed0 ht0 digest0 secrets auths roots (take step order)).
    - exists* order,step,secrets,auths,roots; elim* => ord st se au ro.
      wp; call (forest_one_step seed0 ht0 digest0 (nth 0 ord st) se au ro (take st ord)).
      auto; smt(forest_openings_step take_nth perm_eq_size size_range mem_nth perm_eq_mem mem_range).
    wp; call (raw_shuffle_permutation (PreparationView(Independent)) 12 independent_hash_ll).
    call (_ : true ==> true); first by conseq (shuffle_derive_lossless (PreparationView(Independent)) independent_hash_ll).
    auto; smt(forest_openings_empty forest_visited_complete take0).
  seq 1 : (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\
    forest_openings Independent.rawhistory seed0 ht0 digest0 secrets auths roots (range 0 12)).
  + exists* secrets,auths,roots; elim* => se au ro.
    call (root_keeps_forest seed0 ht0 digest0 se au ro (range 0 12)); auto; smt().
  exists* secrets,auths,roots,last; elim* => se au ro finalsecret.
  seq 3 : (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\
    forest_witness Independent.rawhistory seed0 ht0 digest0 secrets auths roots).
  + wp; call (hash_records_forest seed0 ht0 digest0 se au ro (range 0 12)
      (forest_special_input seed0 ht0 finalsecret)).
    auto; rewrite /forest_special_input /RawForsPathReplay.fors_leaf_input;
      smt(forest_special_recorded).
  exists* secrets,auths,roots; elim* => se1 au1 ro1.
  call (hash_records_forest_witness seed0 ht0 digest0 se1 au1 ro1 (forest_compress_input seed0 ht0 ro1)).
  auto; rewrite /forest_compress_input; smt().
qed.
