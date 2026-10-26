(* The unchanged full honest forest makes exactly two exceptional-address
   public calls: tree-12 leaf zero, then the transmitted root-as-secret hash. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawShuffle.
require import IndependentWidths AddressedForsException AddressedForsExceptionCount.
require import AddressedShuffleExceptions AddressedOrdinaryForsExceptions.

lemma exceptional_hash_flag_width q flag :
  hoare [Independent.hash :
    exceptional_fors_count Independent.queries=q /\ exceptional_fors_query x=flag /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q+b2i flag /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=256].
proof. conseq (exceptional_hash_count q flag) independent_hash_width; smt(). qed.

lemma shuffled_fors_index_bound order step :
  perm_eq order (range 0 12) => 0<=step<12 => 0<=nth 0 order step<12.
proof. smt(perm_eq_size size_range mem_nth perm_eq_mem mem_range). qed.

lemma raw_forest_sign_exception_count q :
  hoare [RawForest(PreparationView(Independent)).sign :
    size seed=32 /\ size shuffle=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q+2 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res.`3=16].
proof.
  exists* seed; elim* => seed0.
  proc; call (exceptional_hash_count_width (q+2)); wp;
    call (exceptional_hash_flag_width (q+1) true); wp;
    call (raw_fors_root_exception_valid seed0 12 q).
  while (seed=seed0 /\ size seed0=32 /\ 0<=step<=12 /\ perm_eq order (range 0 12) /\
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (raw_forest_one_exception_zero q); auto; smt(shuffled_fors_index_bound).
  wp; call (shuffle_permutation_exception_order q 12); call (shuffle_derive_exception_count q).
  auto; smt(exceptional_fors_leaf_query exceptional_fors_other_kind node_width b2i1).
qed.
