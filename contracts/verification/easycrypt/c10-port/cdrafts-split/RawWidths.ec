(* Width preservation independent of oracle output values. Truncation is
   totalized by node; its agreement on 256-bit outputs is proved separately. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors RawWots RawSignature.

lemma all_put_preserved ['a] (p : 'a -> bool) xs i x :
  all p xs => p x => all p (put xs i x).
proof.
  move=> ha hx; rewrite /put; case (0 <= i < size xs) => //.
  move=> hi; rewrite all_cat /= hx /=; split; apply/allP => y hy;
    move: ha=> /allP; apply; smt(mem_take mem_drop).
qed.
lemma rows_put n xs i x : rows_width n xs => size x = 16 => rows_width n (put xs i x).
proof. rewrite /rows_width; smt(size_put all_put_preserved). qed.
lemma rows_zeros n : 0 <= n => rows_width n (nseq n (nseq 16 0)).
proof. rewrite /rows_width size_nseq all_nseq; smt(size_nseq). qed.

lemma raw_chain_width (O <: PreparationOracle) :
  islossless O.hash => hoare[RawWots(O).chain : size current = 16 ==> size res = 16].
proof.
  move=> hh; proc; while (size current = 16).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt(node_width).
  auto.
qed.
lemma raw_leaf_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare[RawKeygen(O).leaf : true ==> size res = 16].
proof.
  move=> hh hw; proc; call (_ : true ==> true); first by conseq hh.
  wp; while true.
  + wp; while true.
    - wp; call (_ : true ==> true); first by conseq hh.
      auto.
    wp; call (_ : true ==> true); first by conseq hw.
    auto.
  auto; smt(node_width).
qed.
lemma raw_count_range (O <: PreparationOracle) :
  islossless O.hash =>
  hoare[RawWots(O).count : true ==>
    res <> None => 0 <= (oget res).`1 < signing_budget].
proof.
  move=> hh; proc; while (0 <= i <= signing_budget /\
    (result <> None => 0 <= (oget result).`1 < signing_budget)).
  + wp; call (_ : true ==> true); first by conseq hh.
    auto; smt().
  auto; smt().
qed.
lemma raw_wots_signature_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare[RawWots(O).sign : true ==> res <> None =>
    rows_width 43 (oget res).`1 /\ 0 <= (oget res).`2 < signing_budget].
proof.
  move=> hh hw; proc; seq 1 : (accepted <> None => 0 <= (oget accepted).`1 < signing_budget).
  + call (raw_count_range O hh); auto.
  sp 1; if; last by auto.
  wp; while (rows_width 43 sigma /\ 0 <= (oget accepted).`1 < signing_budget).
  + wp; call (raw_chain_width O hh).
    call (_ : true ==> true); first by conseq hw.
    auto; smt(node_width rows_put).
  wp; call (_ : true ==> true); first by conseq (RawShuffle.shuffle_permutation_lossless O hh).
  auto; smt(rows_zeros).
qed.
