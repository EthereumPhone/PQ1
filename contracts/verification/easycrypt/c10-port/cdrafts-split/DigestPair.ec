(* External Q research: joint law of adjacent fresh digest windows. *)
require import AllCore List Distr DList DBool.
require import C10RawOracle C10Randomizer DigestPrefix.

lemma digest_pair_uniform m n : 0 <= m => 0 <= n => m+n <= 256 =>
  dmap full_digest (fun d => (take m d, take n (drop m d))) =
    (dlist dbool m) `*` (dlist dbool n).
proof.
  move=> hm hn hsize.
  have he := digest_prefix_uniform (m+n) _; first smt().
  have hp :
    dmap full_digest (fun d => (take m d, take n (drop m d))) =
    dmap (dmap full_digest (take (m+n)))
      (fun d => (take m d, take n (drop m d))).
  + rewrite dmap_comp; apply eq_dmap => d.
    rewrite /(\o) take_take drop_take 1,2:/# take_take; smt().
  rewrite hp he dlist_add 1:hm 1:hn dmap_comp.
  rewrite (eq_dmap_in _ _ idfun).
  + move=> [a b] /= /supp_dprod [ha hb].
    have hsa := supp_dlist_size dbool m a hm ha.
    have hsb := supp_dlist_size dbool n b hn hb.
    rewrite /(\o) /idfun /= take_cat drop_cat hsa /=.
    rewrite ?take0 ?cats0 ?drop0.
    by rewrite -hsb take_size.
  by rewrite dmap_id.
qed.

lemma digest_pair_mass m n (p q : bool list -> bool) :
  0 <= m => 0 <= n => m+n <= 256 =>
  mu full_digest (fun d => p (take m d) /\ q (take n (drop m d))) =
    mu (dlist dbool m) p * mu (dlist dbool n) q.
proof.
  move=> hm hn hsize.
  have he := digest_pair_uniform m n hm hn hsize.
  have hp :
    mu full_digest (fun d => p (take m d) /\ q (take n (drop m d))) =
    mu (dmap full_digest (fun d => (take m d, take n (drop m d))))
      (fun (xy : bool list * bool list) => p xy.`1 /\ q xy.`2).
  + by rewrite dmapE /pred_o /(\o).
  by rewrite hp he dprodE.
qed.
