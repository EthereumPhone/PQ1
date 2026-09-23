(* Exact zero-chunk acceptance mass for one fresh raw hash query. Cached queries are not independent draws. *)
require import AllCore List Distr DList DProd DBool FMap C10Randomizer C10RawGrind C10RawOracle.

op zero_chunk (digest : bool list) = take 11 (drop 132 digest).

lemma zero_chunk_uniform : dmap full_digest zero_chunk = dlist dbool 11.
proof.
  rewrite /full_digest (_ : 256 = 132+124) 1:// dlist_add 1,2:// dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => take 11 xy.`2)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /zero_chunk /=
      drop_cat (supp_dlist_size dbool 132 lo _ hlo) 1:// /= drop0.
    by [].
  rewrite (dprod_marginalR _ _ (take 11)) (dlist_ll _ _ dbool_ll) dscalar1.
  rewrite (_ : 124 = 11+113) 1:// dlist_add 1,2:// dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => xy.`1)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /=
      take_cat (supp_dlist_size dbool 11 lo _ hlo) 1:// /= take0 cats0.
    by [].
  by rewrite (dprod_marginalL _ _ idfun) (dlist_ll _ _ dbool_ll) /idfun dmap_id dscalar1.
qed.

lemma fors_acceptance_mass :
  mu full_digest accept_digest = (1%r / 2%r)^11.
proof.
  have he : mu full_digest accept_digest = mu1 (dmap full_digest zero_chunk) (nseq 11 false).
  + by rewrite dmap1E /accept_digest /zero_chunk.
  rewrite he zero_chunk_uniform.
  have hs : size (nseq 11 false) = 11 by rewrite size_nseq.
  by rewrite -{1}hs bool_word_mass hs.
qed.

(* A single fresh H_msg raw input has the exact acceptance mass, conditional
   on any well-formed or adversarially selected entry table. Repeated inputs
   deliberately do not satisfy this precondition. *)
lemma fresh_hash_acceptance (h : (raw_input,digest) fmap) (x0 : raw_input) :
  x0 \notin h =>
  phoare[Shared.hash : Shared.history = h /\ x = x0 ==>
    accept_digest res] = ((1%r / 2%r)^11).
proof.
  move=> hn; proc; rcondt 2; first by auto.
  wp; rnd; wp; skip => />.
  smt(fors_acceptance_mass get_set_sameE).
qed.
