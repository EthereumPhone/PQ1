(* External Q research: a fresh digest against opening sets fixed before
   that draw. This does not cover sets enlarged by future signing queries. *)
require import AllCore List Distr DList DBool FMap StdBigop StdOrder.
require import C10RawOracle C10Randomizer C10RawGrind PrefixGuess DigestPrefix.
import Bigreal Bigreal.BRM RealOrder.

op digest_chunks w k (d : bool list) =
  mkseq (fun i => take w (drop (w*i) d)) k.

lemma chunks_flatten w k (xs : bool list list) :
  0 <= w => 0 <= k => size xs = k =>
  (forall x, x \in xs => size x = w) =>
  digest_chunks w k (flatten xs) = xs.
proof.
  move=> hw hk hs hall; apply (eq_from_nth []).
  + rewrite /digest_chunks size_mkseq; smt().
  move=> i hi.
  have hir : 0 <= i < k by move: hi; rewrite /digest_chunks size_mkseq; smt().
  rewrite /digest_chunks nth_mkseq 1:hir /=.
  rewrite (drop_flatten_ctt w i xs hall) (drop_nth [] i xs) 1:/# flatten_cons.
  have hmem : nth [] xs i \in xs by apply mem_nth; smt().
  rewrite take_cat (hall _ hmem) /= take0 cats0.
  by [].
qed.

op c10_opened (opened : bool list list list) =
  mkseq (fun i => if i < 12 then nth [] opened i else [nseq 11 false]) 13.

lemma c10_coverage_event opened d :
  (forall i, 0 <= i < 13 =>
    nth [] (digest_chunks 11 13 d) i \in nth [] (c10_opened opened) i) <=>
  accept_digest d /\
    (forall i, 0 <= i < 12 => take 11 (drop (11*i) d) \in nth [] opened i).
proof.
  split.
  + move=> h; split.
    - have h12 := h 12 _; first smt().
      move: h12; rewrite /digest_chunks /c10_opened !nth_mkseq 1,2:/# /= /accept_digest; smt().
    move=> i hi; have hc := h i _; first smt().
    move: hc; rewrite /digest_chunks /c10_opened !nth_mkseq 1,2:/# /=; smt().
  move=> [ha hc] i hi.
  rewrite /digest_chunks /c10_opened !nth_mkseq 1,2:/# /=.
  case (i < 12) => hlt; first smt().
  have -> : i = 12 by smt().
  rewrite /=; move: ha; rewrite /accept_digest; smt().
qed.

lemma chunks_prefix w k d : 0 <= w => 0 <= k =>
  digest_chunks w k (take (w*k) d) = digest_chunks w k d.
proof.
  move=> hw hk; apply (eq_from_nth []).
  + by rewrite /digest_chunks !size_mkseq.
  move=> i hi.
  have hir : 0 <= i < k by move: hi; rewrite /digest_chunks size_mkseq; smt().
  rewrite /digest_chunks !nth_mkseq 1,2:hir /=.
  rewrite drop_take 1:/# 1:/# take_take; smt().
qed.

lemma digest_chunks_uniform w k : 0 <= w => 0 <= k => w*k <= 256 =>
  dmap full_digest (digest_chunks w k) = dlist (dlist dbool w) k.
proof.
  move=> hw hk hsize.
  have hn : 0 <= w*k <= 256 by smt().
  have he := digest_prefix_uniform (w*k) hn.
  have hd := dlist_dlist dbool w k hw hk.
  have hc : dmap (dmap full_digest (take (w*k))) (digest_chunks w k) =
    dmap full_digest (digest_chunks w k).
  + rewrite dmap_comp; apply eq_dmap; move=> d; rewrite /(\o) chunks_prefix //.
  rewrite -hc he -hd dmap_comp.
  rewrite (eq_dmap_in _ _ idfun).
  + move=> xs hx; rewrite /(\o) /idfun; apply chunks_flatten => //.
    - exact (supp_dlist_size _ _ _ hk hx).
    move: hx; rewrite (supp_dlist (dlist dbool w) k xs hk) => -[_ ha] x hmem.
    move: ha => /allP ha.
    have hx := ha x hmem.
    exact (supp_dlist_size dbool w x hw hx).
  by rewrite dmap_id.
qed.

lemma fresh_chunk_coverage w k (opened : bool list list list) :
  0 <= w => 0 <= k => w*k <= 256 =>
  mu full_digest (fun d => forall i, 0 <= i < k =>
    nth [] (digest_chunks w k d) i \in nth [] opened i) =
  bigi predT (fun i => mu (dlist dbool w) (fun chunk => chunk \in nth [] opened i)) 0 k.
proof.
  move=> hw hk hn.
  have he := digest_chunks_uniform w k hw hk hn.
  have hm : mu full_digest (fun d => forall i, 0 <= i < k =>
      nth [] (digest_chunks w k d) i \in nth [] opened i) =
    mu (dmap full_digest (digest_chunks w k))
      (fun xs => forall i, 0 <= i < k => nth [] xs i \in nth [] opened i).
  + by rewrite dmapE /pred_o /(\o).
  rewrite hm he.
  rewrite (dlistE [] (dlist dbool w)
    (fun i chunk => chunk \in nth [] opened i) k).
  by [].
qed.

lemma fresh_c10_coverage opened :
  mu full_digest (fun d => accept_digest d /\
    (forall i, 0 <= i < 12 => take 11 (drop (11*i) d) \in nth [] opened i)) =
  (bigi predT (fun i => mu (dlist dbool 11)
    (fun chunk => chunk \in nth [] opened i)) 0 12) * (1%r/2%r)^11.
proof.
  rewrite (mu_eq _ _ (fun d => forall i, 0 <= i < 13 =>
    nth [] (digest_chunks 11 13 d) i \in nth [] (c10_opened opened) i)).
  + by move=> d; rewrite c10_coverage_event.
  rewrite fresh_chunk_coverage 1,2,3:/# (big_int_recr 12 0) 1:/#.
  have hp : bigi predT (fun i => mu (dlist dbool 11)
      (fun chunk => chunk \in nth [] (c10_opened opened) i)) 0 12 =
    bigi predT (fun i => mu (dlist dbool 11)
      (fun chunk => chunk \in nth [] opened i)) 0 12.
  + apply eq_big_seq; move=> i /mem_range hi /=.
    by rewrite /c10_opened nth_mkseq 1:/# /= (_ : i < 12) 1:/#.
  rewrite hp /= /c10_opened nth_mkseq 1:/# /=.
  have hm : mu (dlist dbool 11) (fun chunk => chunk \in [nseq 11 false]) = (1%r/2%r)^11.
  + rewrite (mu_eq _ _ (pred1 (nseq 11 false))) 1:/#.
    have hs : size (nseq 11 false) = 11 by rewrite size_nseq.
    by rewrite -{1}hs bool_word_mass hs.
  by rewrite hm.
qed.

lemma fresh_public_coverage h x0 opened : x0 \notin h =>
  phoare[Independent.hash : Independent.rawhistory = h /\ x = x0 ==>
    accept_digest res /\
    (forall i, 0 <= i < 12 => take 11 (drop (11*i) res) \in nth [] opened i)] =
  ((bigi predT (fun i => mu (dlist dbool 11)
    (fun chunk => chunk \in nth [] opened i)) 0 12) * (1%r/2%r)^11).
proof.
  move=> hn; proc; sp 1; rcondt 1; first by auto.
  wp; rnd; skip => />.
  move=> &hr hh hx.
  rewrite -(fresh_c10_coverage opened).
  apply mu_eq => d; by rewrite get_set_sameE /=.
qed.

lemma fresh_c10_coverage_cardinality opened :
  mu full_digest (fun d => accept_digest d /\
    (forall i, 0 <= i < 12 => take 11 (drop (11*i) d) \in nth [] opened i)) <=
  (bigi predT (fun i => (size (nth [] opened i))%r * (1%r/2%r)^11) 0 12) * (1%r/2%r)^11.
proof.
  rewrite fresh_c10_coverage; apply ler_wpmul2r.
  + apply expr_ge0; smt().
  apply ler_prod => i _; split.
  + have h := mu_bounded (dlist dbool 11) (fun chunk => chunk \in nth [] opened i); smt().
  move=> _ /=; apply mu_mem_le_mu1; move=> t; apply prefix_atom_bound; smt().
qed.
