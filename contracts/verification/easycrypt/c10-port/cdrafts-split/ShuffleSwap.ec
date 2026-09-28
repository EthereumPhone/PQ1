(* The concrete double-put swap preserves all element multiplicities. *)
require import AllCore List.

lemma count_put_change ['a] (p : 'a -> bool) (s : 'a list) (x0 x : 'a) i :
  0 <= i < size s =>
  count p (put s i x) = count p s - b2i (p (nth x0 s i)) + b2i (p x).
proof.
  move=> hi.
  have hp := perm_eq_nth_take_drop x0 i s hi.
  have hc : count p (nth x0 s i :: take i s ++ drop (i+1) s) = count p s
    by move: hp; rewrite perm_eqP; smt().
  move: hc; rewrite put_in 1:// !count_cat /=; smt().
qed.

lemma swap_put_permutation ['a] (x0 : 'a) (s : 'a list) i j :
  0 <= i < size s => 0 <= j < size s =>
  perm_eq (put (put s i (nth x0 s j)) j (nth x0 s i)) s.
proof.
  move=> hi hj; apply/perm_eqP => p.
  have hj' : 0 <= j < size (put s i (nth x0 s j)) by rewrite size_put.
  have hc1 := count_put_change p (put s i (nth x0 s j)) x0 (nth x0 s i) j hj'.
  have hc2 := count_put_change p s x0 (nth x0 s j) i hi.
  have hn := nth_put x0 s i j (nth x0 s j) hi.
  case (i=j) => hij; smt().
qed.
