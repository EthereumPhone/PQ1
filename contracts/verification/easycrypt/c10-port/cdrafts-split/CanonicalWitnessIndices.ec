(* Reversing last-occurrence deduplication bounds each assigned witness index
   by the number of remaining coordinates. Pure finite-list fact. *)
require import AllCore List.

lemma reverse_undup_index ['a] (x0 : 'a) xs i :
  0<=i<size xs =>
  index (nth x0 xs i) (rev (undup xs)) <= size xs-1-i.
proof.
  elim: xs i => [|x xs ih] i hi; first smt(size_ge0).
  case (i=0)=> hz.
  + subst i; rewrite /=.
    case (mem xs x)=> hm /=.
    - have h := index_size x (rev (undup xs)).
      have hs := size_undup xs.
      rewrite size_rev in h; smt().
    rewrite rev_cons -cats1 index_cat mem_rev mem_undup hm /= size_rev.
    have hs := size_undup xs; smt().
  have hib : 0<=i-1<size xs by smt().
  have hm : mem xs (nth x0 xs (i-1)) by exact (mem_nth x0 xs (i-1) hib).
  have hh := ih (i-1) hib.
  rewrite /= hz /=.
  case (mem xs x)=> hx /=; first smt().
  rewrite rev_cons -cats1 index_cat mem_rev mem_undup hm /=; smt().
qed.
