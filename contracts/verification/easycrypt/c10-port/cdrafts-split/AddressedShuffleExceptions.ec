(* Actual software shuffle calls contribute no exceptional FORS-address
   queries. Widths follow from the initialized memo-table invariant. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawShuffle.
require import IndependentWidths RawShufflePermutation.
require import AddressedInputFields AddressedForsException AddressedForsExceptionCount.

lemma exceptional_hash_count_width q :
  hoare [Independent.hash :
    exceptional_fors_count Independent.queries=q /\ !exceptional_fors_query x /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=256].
proof. conseq (exceptional_hash_excluded q) independent_hash_width; smt(). qed.

lemma shuffle_derive_exception_count q :
  hoare [RawShuffle(PreparationView(Independent)).derive :
    size seed=32 /\ size label<=7 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=32].
proof.
  proc; sp 1; if.
  + wp; call (exceptional_hash_count_width q); auto;
      smt(shuffle_derive_input_short exceptional_fors_short_excluded bits_to_bytes_size).
  auto; smt(size_nseq).
qed.

lemma shuffle_permutation_exception_count q :
  hoare [RawShuffle(PreparationView(Independent)).permutation :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; sp 1; if; last by auto.
  while (exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory); first by auto.
  wp; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (exceptional_hash_count_width q); auto;
      smt(shuffle_stream_input_short exceptional_fors_short_excluded).
  auto.
qed.

lemma shuffle_permutation_exception_order q n0 :
  hoare [RawShuffle(PreparationView(Independent)).permutation :
    size seed=32 /\ n=n0 /\ 0<=n0 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ perm_eq res (range 0 n0)].
proof.
  conseq (shuffle_permutation_exception_count q)
    (raw_shuffle_permutation (PreparationView(Independent)) n0 independent_hash_ll); smt().
qed.
