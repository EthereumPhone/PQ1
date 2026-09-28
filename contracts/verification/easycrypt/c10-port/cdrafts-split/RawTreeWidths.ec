require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawMerkle RawSignature RawWidths.

lemma stack_first_width stack : valid_stack stack => stack <> [] =>
  size (head ([],0) stack).`1 = 16.
proof. case stack => // x xs; rewrite /valid_stack /=; smt(). qed.

lemma raw_fors_tree_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawFors(O).tree : true ==> size res.`1 = 16 /\ rows_width 11 res.`2].
proof.
  move=> hh hf; proc; while (valid_stack stack /\ rows_width 11 auth).
  + wp; while (valid_stack stack /\ rows_width 11 auth /\ size current = 16).
    - wp; call (_ : true ==> true); first by conseq hh.
      auto; smt(node_width valid_stack_tail stack_first_width rows_put).
    wp; call (_ : true ==> true); first by conseq hh.
    wp; call (_ : true ==> true); first by conseq hf.
    auto; rewrite /valid_stack /=; smt(node_width).
  auto; rewrite /valid_stack /=; smt(rows_zeros valid_stack_head).
qed.

lemma raw_merkle_recover_width (O <: PreparationOracle) :
  islossless O.hash => hoare[RawMerkle(O).recover : true ==> size res = 16].
proof.
  move=> hh; proc; while (0 <= h <= 9 /\ (0 < h => size current = 16)).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt(node_width).
  auto; smt().
qed.
lemma raw_fors_sign_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawFors(O).sign : true ==> size res.`1 = 16 /\ rows_width 11 res.`2].
proof.
  move=> hh hf; proc; call (raw_fors_tree_width O hh hf); wp.
  call (_ : true ==> true); first by conseq hf.
  auto; smt(node_width).
qed.
lemma raw_fors_root_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawFors(O).root : true ==> size res = 16].
proof. move=> hh hf; proc; call (raw_fors_tree_width O hh hf); auto. qed.
lemma raw_fors_recover_width (O <: PreparationOracle) :
  islossless O.hash => hoare[RawFors(O).recover : true ==> size res = 16].
proof.
  move=> hh; proc; while (size current = 16).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt(node_width).
  wp; call (_ : true ==> true); first by conseq hh.
  auto; smt(node_width).
qed.

lemma raw_merkle_build_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare[RawMerkle(O).build : true ==> rows_width 9 res.`1 /\ size res.`2 = 16].
proof.
  move=> hh hw; proc; while (valid_stack stack /\ rows_width 9 keep).
  + wp; while (valid_stack stack /\ rows_width 9 keep /\ size current = 16).
    - wp; call (_ : true ==> true); first by conseq hh.
      auto; smt(node_width valid_stack_tail stack_first_width rows_put).
    wp; call (raw_leaf_width O hh hw).
    auto; rewrite /valid_stack /=; smt().
  auto; rewrite /valid_stack /=; smt(rows_zeros valid_stack_head).
qed.
