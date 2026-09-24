(* Actual WOTS outputs contain bytes regardless of oracle digest lengths. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RawWots RawShuffle.
require import ByteSession RawWidths RawByteValues.

lemma raw_chain_bytes (O <: PreparationOracle) :
  islossless O.hash => hoare [RawWots(O).chain : byte_values current ==> byte_values res].
proof.
  move=> hh; proc; while (byte_values current).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt(node_bytes).
  auto.
qed.
lemma raw_leaf_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare [RawKeygen(O).leaf : true ==> byte_values res].
proof.
  move=> hh hw; proc; call (_ : true ==> true); first by conseq hh.
  wp; while true.
  + wp; while true.
    - wp; call (_ : true ==> true); first by conseq hh.
      auto.
    wp; call (_ : true ==> true); first by conseq hw.
    auto.
  auto; smt(node_bytes).
qed.
lemma raw_wots_signature_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare [RawWots(O).sign : true ==> res<>None => byte_rows (oget res).`1].
proof.
  move=> hh hw; proc; seq 1 : true.
  + call (_ : true ==> true); first by conseq (raw_count_lossless O hh).
    auto.
  sp 1; if; last by auto.
  wp; while (byte_rows sigma).
  + wp; call (raw_chain_bytes O hh).
    call (_ : true ==> true); first by conseq hw.
    auto; smt(node_bytes byte_rows_put).
  wp; call (_ : true ==> true); first by conseq (shuffle_permutation_lossless O hh).
  auto; smt(byte_rows_zeros).
qed.
