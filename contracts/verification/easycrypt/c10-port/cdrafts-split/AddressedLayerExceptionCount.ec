(* All key-generation/Merkle hashes use kind two, and the actual two-layer
   signer keeps the exceptional FORS count even on count-search failure. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer.
require import IndependentWidths AddressedInputFields AddressedForsException AddressedForsExceptionCount.
require import AddressedShuffleExceptions AddressedWotsExceptionCount.

lemma exceptional_merkle_pair seed layer tree level parent lval rval :
  size seed=32 =>
  !exceptional_fors_query (seed++address layer tree 2 0 0 level parent++pad lval++pad rval).
proof.
  move=> hs.
  have he := exceptional_fors_other_kind seed layer tree 2 0 0 level parent (pad lval++pad rval) hs _ _;
    first 2 smt().
  by move: he; rewrite -!catA.
qed.

lemma raw_keygen_root_exceptions q :
  hoare [RawKeygen(PreparationView(Independent)).root :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
      independent_tables_valid Independent.rawhistory Independent.secrethistory).
    - wp; call (exceptional_hash_count_width q); auto; smt(exceptional_merkle_pair).
    wp; call (raw_keygen_leaf_exceptions q); auto.
  auto.
qed.

lemma raw_merkle_build_exceptions q :
  hoare [RawMerkle(PreparationView(Independent)).build :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
      independent_tables_valid Independent.rawhistory Independent.secrethistory).
    - wp; call (exceptional_hash_count_width q); auto; smt(exceptional_merkle_pair).
    wp; call (raw_keygen_leaf_exceptions q); auto.
  auto.
qed.

lemma raw_merkle_recover_exceptions q :
  hoare [RawMerkle(PreparationView(Independent)).recover :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (exceptional_hash_count_width q); auto; smt(exceptional_merkle_pair).
  auto.
qed.

lemma raw_layer_recover_exceptions q :
  hoare [RawLayer(PreparationView(Independent)).recover :
    size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. proc; call (raw_merkle_recover_exceptions q); call (raw_wots_recover_exceptions q); auto. qed.

lemma raw_layer_sign_exceptions q :
  hoare [RawLayer(PreparationView(Independent)).sign :
    size seed=32 /\ size shuffle=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; seq 3 : (size seed=32 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (raw_wots_sign_exceptions q); call (shuffle_derive_exception_count q);
      call (raw_merkle_build_exceptions q); auto; smt(layer_shuffle_label_short).
  sp 1; if; last by auto.
  wp; call (raw_layer_recover_exceptions q); auto.
qed.
