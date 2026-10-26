(* Shuffle labels and stream counters are short singleton-prefix inputs. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawShuffle.
require import IndependentWidths RawShufflePermutation AddressedInputFields AddressedOrdinaryInputs AddressedOrdinaryHistory.

lemma shuffle_derive_ordinary_inputs old seed0 :
  hoare [RawShuffle(PreparationView(Independent)).derive :
    size seed=32 /\ size label<=7 /\ ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=32].
proof.
  proc; sp 1; if.
  + wp; call (ordinary_hash_new_valid old seed0); auto;
      smt(shuffle_derive_input_short ordinary_public_short bits_to_bytes_size).
  auto; smt(size_nseq).
qed.

lemma shuffle_permutation_ordinary_inputs old seed0 :
  hoare [RawShuffle(PreparationView(Independent)).permutation :
    size seed=32 /\ ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; sp 1; if; last by auto.
  while (ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory); first by auto.
  wp; while (size seed=32 /\ ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (ordinary_hash_new_valid old seed0); auto;
      smt(shuffle_stream_input_short ordinary_public_short).
  auto.
qed.

lemma shuffle_permutation_ordinary_order old seed0 n0 :
  hoare [RawShuffle(PreparationView(Independent)).permutation :
    size seed=32 /\ n=n0 /\ 0<=n0 /\ ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ perm_eq res (range 0 n0)].
proof.
  conseq (shuffle_permutation_ordinary_inputs old seed0)
    (raw_shuffle_permutation (PreparationView(Independent)) n0 independent_hash_ll); smt().
qed.
