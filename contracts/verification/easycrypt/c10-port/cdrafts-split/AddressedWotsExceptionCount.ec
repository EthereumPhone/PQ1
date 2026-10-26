(* WOTS and key-generation public calls use address kinds zero or one.
   Bounded failure and cached calls preserve the same exception counter. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import IndependentWidths AddressedForsException AddressedForsExceptionCount AddressedShuffleExceptions.

lemma exceptional_derive_count_valid q :
  hoare [Independent.derive :
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=256].
proof. conseq independent_derive_width; smt(). qed.

lemma exceptional_wots_private_valid q :
  hoare [PreparationView(Independent).wots :
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. proc; call (exceptional_derive_count_valid q); auto. qed.

lemma raw_wots_count_exceptions q :
  hoare [RawWots(PreparationView(Independent)).count :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (exceptional_hash_count_width q); auto; move=> &m hp.
    have he := exceptional_fors_other_kind seed{m} layer{m} tree{m} 0 kp{m} 0 0 0
      (pad message{m}++be 32 i{m}) _ _ _; first 3 smt().
    move: he; rewrite -!catA; smt().
  auto.
qed.

lemma raw_wots_chain_exceptions q :
  hoare [RawWots(PreparationView(Independent)).chain :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (exceptional_hash_count_width q); auto; smt(exceptional_fors_other_kind).
  auto.
qed.

lemma raw_wots_recover_exceptions q :
  hoare [RawWots(PreparationView(Independent)).recover :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; seq 1 : (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (exceptional_hash_count_width q); auto; move=> &m hp.
    have he := exceptional_fors_other_kind seed{m} layer{m} tree{m} 0 kp{m} 0 0 0
      (pad message{m}++be 32 count{m}) _ _ _; first 3 smt().
    move: he; rewrite -!catA; smt().
  sp 1; if; last by auto.
  wp; call (exceptional_hash_count_width q); wp;
    while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
      independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (raw_wots_chain_exceptions q); auto.
  auto; smt(exceptional_fors_other_kind).
qed.

lemma raw_wots_sign_exceptions q :
  hoare [RawWots(PreparationView(Independent)).sign :
    size seed=32 /\ size shuffle=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; seq 1 : (size seed=32 /\ size shuffle=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (raw_wots_count_exceptions q); auto.
  sp 1; if; last by auto.
  wp; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (raw_wots_chain_exceptions q); call (exceptional_wots_private_valid q); auto.
  wp; call (shuffle_permutation_exception_count q); auto.
qed.

lemma raw_keygen_leaf_exceptions q :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; call (exceptional_hash_count_width q); wp;
    while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
      independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
      independent_tables_valid Independent.rawhistory Independent.secrethistory).
    - wp; call (exceptional_hash_count_width q); auto; smt(exceptional_fors_other_kind).
    wp; call (exceptional_wots_private_valid q); auto.
  auto; smt(exceptional_fors_other_kind).
qed.
