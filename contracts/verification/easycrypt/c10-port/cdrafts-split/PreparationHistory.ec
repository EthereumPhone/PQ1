(* Software shuffling preserves both histories of the independent oracle. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawShuffle.
require import PersistentGrind MonotoneHistory RawShufflePermutation.

lemma raw_shuffle_extends s0 h0 :
  hoare [RawShuffle(PreparationView(Independent)).permutation :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; sp 1; if; last by auto.
  while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory); first by auto.
  wp; while (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + wp; call (independent_hash_extends s0 h0); auto.
  auto.
qed.

lemma raw_shuffle_recorded n0 s0 h0 :
  hoare [RawShuffle(PreparationView(Independent)).permutation :
    n=n0 /\ 0<=n0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    perm_eq res (range 0 n0) /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_shuffle_permutation (PreparationView(Independent)) n0 independent_hash_ll)
    (raw_shuffle_extends s0 h0); smt().
qed.
