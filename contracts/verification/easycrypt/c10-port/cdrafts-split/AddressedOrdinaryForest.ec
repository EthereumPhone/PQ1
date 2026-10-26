(* Actual shuffled forest signing: every new public entry is ordinary or an
   explicitly exceptional FORS input. The two-call exception count is separate. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawShuffle.
require import PersistentGrind AcceptedContexts IndependentWidths ForsComponentHistory.
require import ForsRootWitness ForestRootPrefix ForestRootRecording ForestCoordinates ForestWitness RawForsPathReplay.
require import AddressedOrdinaryInputs AddressedOrdinaryHistory AddressedOrdinaryShuffle AddressedOrdinaryForsExceptions.
require import AddressedForestCanonicity AddressedForsException.

lemma ordinary_forest_compression_member h s seed ht roots :
  0<=ht<2^64 => canonical_forest_roots h s seed ht roots =>
  ordinary_public_input h s seed (forest_compress_input seed ht roots).
proof.
  move=> hv hc; rewrite /ordinary_public_input /canonical_long_input /canonical_forest_input.
  right; right; right; right; exists ht roots; smt().
qed.

lemma ordinary_forest_one_root_prefix seed0 ht0 tree0 target0 roots0 visited old :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\
    0<=ht0<2^64 /\ 0<=tree0<13 /\ 0<=target0<2048 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`3 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  have hp : hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\
    0<=ht0<2^64 /\ 0<=tree0<13 /\ 0<=target0<2048 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 ==>
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`3 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
  + conseq (forest_one_root_prefix seed0 ht0 tree0 target0 roots0 visited)
      (ordinary_fors_one_new_inputs seed0 ht0 tree0 target0 old); smt().
  conseq hp (width_forest_one_valid RawForest); smt().
qed.

lemma ordinary_forest_last_root_prefix seed0 ht0 roots0 visited old :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ ht=ht0 /\ tree=12 /\ 0<=ht0<2^64 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 ==>
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 12 res /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  conseq (forest_last_root_prefix seed0 ht0 roots0 visited)
    (ordinary_fors_root_new_inputs seed0 ht0 12 old); smt().
qed.

lemma raw_forest_sign_ordinary_inputs seed0 ht0 digest0 old :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ size seed0=32 /\ size shuffle=32 /\ 0<=ht0<2^64 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  proc; seq 7 : (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ size seed0=32 /\ 0<=ht0<2^64 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots (range 0 12) /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0).
  + while (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ size seed0=32 /\ 0<=ht0<2^64 /\ 0<=step<=12 /\
      perm_eq order (range 0 12) /\
      forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots (take step order) /\
      ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
      independent_tables_valid Independent.rawhistory Independent.secrethistory).
    - exists* order,step,roots; elim* => ord st ro.
      wp; call (ordinary_forest_one_root_prefix seed0 ht0 (nth 0 ord st)
        (forest_index digest0 (nth 0 ord st)) ro (take st ord) old).
      auto; smt(forest_index_range forest_root_prefix_step take_nth perm_eq_size size_range mem_nth perm_eq_mem mem_range).
    wp; call (shuffle_permutation_ordinary_order old seed0 12).
    call (shuffle_derive_ordinary_inputs old seed0).
    auto; smt(forest_root_prefix_empty forest_root_prefix_complete take0).
  seq 1 : (seed=seed0 /\ ht=ht0 /\ size seed0=32 /\ 0<=ht0<2^64 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots (range 0 12) /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 12 last /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0).
  + exists* roots; elim* => ro; call (ordinary_forest_last_root_prefix seed0 ht0 ro (range 0 12) old); auto.
  exists* roots,last,Independent.rawhistory,Independent.secrethistory; elim* => roots0 lastroot0 h0 s0.
  seq 3 : (seed=seed0 /\ ht=ht0 /\ 0<=ht0<2^64 /\
    canonical_forest_roots Independent.rawhistory Independent.secrethistory seed0 ht0 roots /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0).
  + wp; call (ordinary_hash_new_records old seed0 (forest_special_input seed0 ht0 lastroot0) s0 h0).
    auto; move=> &m hp; split.
    - have hw : size lastroot0=16 by smt(fors_root_witness_width).
      have he := exceptional_fors_leaf_query seed0 ht0 12 0 lastroot0 _ hw _ _; first 3 smt().
      rewrite /forest_special_input /fors_leaf_input; smt(extends_refl).
    move=> _ value table hh.
    have hs : forest_root_prefix table s0 seed0 ht0 roots0 (range 0 12)
      by smt(forest_root_prefix_extends).
    have hl : fors_root_witness table s0 seed0 ht0 12 lastroot0 by smt(fors_root_witness_extends).
    have hf := forest_root_special table s0 seed0 ht0 roots0 lastroot0 value hs hl _; first smt().
    split; first smt().
    split; first smt().
    split; first smt().
    split; last smt().
    rewrite /canonical_forest_roots; split; first smt().
    split; first smt().
    exists lastroot0 value; smt().
  call (ordinary_hash_new_inputs old seed0).
  auto; rewrite /forest_compress_input; smt(ordinary_forest_compression_member).
qed.
