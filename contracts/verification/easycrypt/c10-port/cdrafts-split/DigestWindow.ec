(* External Q research: any fixed contiguous window of a fresh digest is
   uniform. This also distinguishes node suffixes from message prefixes. *)
require import AllCore List Distr DList DProd DBool.
require import C10RawOracle C10Randomizer.

lemma digest_window_uniform offset width :
  0 <= offset => 0 <= width => offset+width <= 256 =>
  dmap full_digest (fun d => take width (drop offset d)) = dlist dbool width.
proof.
  move=> ho hw hn.
  rewrite /full_digest (_ : 256 = offset+(256-offset)) 1:/#
    dlist_add 1,2:/# dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => take width xy.`2)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /=
      drop_cat (supp_dlist_size dbool offset lo ho hlo) /= drop0.
    by [].
  rewrite (dprod_marginalR _ _ (take width)) (dlist_ll _ _ dbool_ll) dscalar1.
  rewrite (_ : 256-offset = width+(256-offset-width)) 1:/# dlist_add 1,2:/# dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => xy.`1)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /=
      take_cat (supp_dlist_size dbool width lo hw hlo) /= take0 cats0.
    by [].
  by rewrite (dprod_marginalL _ _ idfun) (dlist_ll _ _ dbool_ll) /idfun dmap_id dscalar1.
qed.

lemma digest_window_mass offset width (target : bool list) :
  0 <= offset => 0 <= width => offset+width <= 256 => size target = width =>
  mu full_digest (fun d => take width (drop offset d) = target) = (1%r/2%r)^width.
proof.
  move=> ho hw hn hs.
  have he : mu full_digest (fun d => take width (drop offset d) = target) =
    mu1 (dmap full_digest (fun d => take width (drop offset d))) target by rewrite dmap1E.
  rewrite he (digest_window_uniform offset width ho hw hn).
  by rewrite -{1}hs bool_word_mass hs.
qed.
