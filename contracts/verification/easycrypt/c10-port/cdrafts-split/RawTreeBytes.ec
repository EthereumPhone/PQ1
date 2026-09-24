(* Actual tree nodes and authentication arrays contain only bytes. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawMerkle RawSignature RawWidths ByteSession RawByteValues RawWotsBytes.

lemma raw_fors_tree_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawFors(O).tree : true ==> byte_values res.`1 /\ byte_rows res.`2].
proof.
  move=> hh hf; proc; while (byte_stack stack /\ byte_rows auth).
  + wp; while (byte_stack stack /\ byte_rows auth /\ byte_values current).
    - wp; call (_ : true ==> true); first by conseq hh.
      auto; smt(node_bytes byte_stack_tail byte_stack_first byte_rows_put).
    wp; call (_ : true ==> true); first by conseq hh.
    wp; call (_ : true ==> true); first by conseq hf.
    auto; rewrite /byte_stack /=; smt(node_bytes).
  auto; rewrite /byte_stack /=; smt(byte_rows_zeros byte_stack_head).
qed.

lemma raw_merkle_recover_bytes (O <: PreparationOracle) :
  islossless O.hash => hoare[RawMerkle(O).recover : true ==> byte_values res].
proof.
  move=> hh; proc; while (0 <= h <= 9 /\ (0 < h => byte_values current)).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt(node_bytes).
  auto; smt().
qed.
lemma raw_fors_sign_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawFors(O).sign : true ==> byte_values res.`1 /\ byte_rows res.`2].
proof.
  move=> hh hf; proc; call (raw_fors_tree_bytes O hh hf); wp.
  call (_ : true ==> true); first by conseq hf.
  auto; smt(node_bytes).
qed.
lemma raw_fors_root_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawFors(O).root : true ==> byte_values res].
proof. move=> hh hf; proc; call (raw_fors_tree_bytes O hh hf); auto. qed.
lemma raw_fors_recover_bytes (O <: PreparationOracle) :
  islossless O.hash => hoare[RawFors(O).recover : true ==> byte_values res].
proof.
  move=> hh; proc; while (byte_values current).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt(node_bytes).
  wp; call (_ : true ==> true); first by conseq hh.
  auto; smt(node_bytes).
qed.

lemma raw_merkle_build_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare[RawMerkle(O).build : true ==> byte_rows res.`1 /\ byte_values res.`2].
proof.
  move=> hh hw; proc; while (byte_stack stack /\ byte_rows keep).
  + wp; while (byte_stack stack /\ byte_rows keep /\ byte_values current).
    - wp; call (_ : true ==> true); first by conseq hh.
      auto; smt(node_bytes byte_stack_tail byte_stack_first byte_rows_put).
    wp; call (raw_leaf_bytes O hh hw).
    auto; rewrite /byte_stack /=; smt().
  auto; rewrite /byte_stack /=; smt(byte_rows_zeros byte_stack_head).
qed.
