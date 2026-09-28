(* Exact acceptance arithmetic for an independently uniform bit string.
   This file makes no assumption about SHA-256 outputs or counter searches. *)
require import AllCore List Distr DList DBool BitEncoding IntDiv StdOrder.
require import CountDS RadixEncoding.
import BS2Int IntOrder RealOrder.

lemma uniform_same_support ['a] (d e : 'a distr) :
  is_uniform d => is_uniform e => is_lossless d => is_lossless e =>
  (forall x, (x \in d) = (x \in e)) => d = e.
proof.
  move=> du eu dl el hs.
  have he : support d = support e by apply fun_ext => x; apply hs.
  by apply eq_distr => x; rewrite !mu1_uni // dl el he.
qed.

lemma pow2_3 : 2 ^ 3 = 8.
proof. by rewrite (_ : 3 = 2 + 1) 1:// exprS 1://
  (_ : 2 = 1 + 1) 1:// exprS 1:// expr1. qed.

lemma uniform_three_bits : dmap (dlist dbool 3) bs2int = drange 0 8.
proof.
  apply uniform_same_support.
  + apply dmap_uni_in_inj.
    - move=> x y hx hy hxy; apply inj_bs2int_eqsize; last exact hxy.
      by rewrite (supp_dlist_size dbool 3 x _ hx) 1://
                 (supp_dlist_size dbool 3 y _ hy) 1://.
    exact (dlist_uni _ _ dbool_uni).
  + exact drange_uni.
  + apply dmap_ll; exact (dlist_ll _ _ dbool_ll).
  + by apply drange_ll.
  move=> x; rewrite supp_dmap supp_drange eq_iff; split.
  + move=> [bs [hbs ->]]; have hs := supp_dlist_size dbool 3 bs _ hbs; first done.
    have := bs2int_le2Xs bs; rewrite hs pow2_3; smt(bs2int_ge0).
  move=> hx; exists (int2bs 3 x); split.
  + rewrite supp_dlist 1:// size_int2bs ler_maxr 1:// /=.
    apply allP => b hb.
    exact supp_dbool.
  by rewrite int2bsK 1:// 1:pow2_3.
qed.

lemma size_words (n b : int) : 0 <= n => 0 <= b =>
  size (words n b) = b ^ n.
proof.
  move=> hn hb; elim: n hn => [|n hn ih].
  + by rewrite words0 /= expr0.
  by rewrite wordsS // size_allpairs size_range ler_maxr 1:/#
    ih exprS //; ring.
qed.

lemma uniform_words (n b : int) : 0 <= n => 0 < b =>
  dlist (drange 0 b) n = duniform (words n b).
proof.
  move=> hn hb; apply uniform_same_support.
  + exact (dlist_uni _ _ (drange_uni 0 b)).
  + exact duniform_uni.
  + apply dlist_ll; exact (drange_ll 0 b hb).
  + apply duniform_ll; have := size_words n b hn _; first smt().
    have hp : 0 < b ^ n by apply IntOrder.expr_gt0.
    smt(size_eq0).
  move=> l; rewrite supp_dlist // supp_duniform mem_words //.
  have hp : support (drange 0 b) = is_digit b.
  + by apply fun_ext => d; rewrite supp_drange /is_digit.
  by rewrite hp.
qed.

lemma uniform_digits (n extra : int) : 0 <= n => 0 <= extra =>
  dmap (dlist dbool (3*n+extra)) (digits 3 n) = dlist (drange 0 8) n.
proof.
  move=> hn he; elim: n hn => [|n hn ih].
  + rewrite (dlist0 (drange 0 8) 0) 1:// (_ : digits 3 0 = fun _ => []).
    - by apply fun_ext => bs; rewrite /digits mkseq0.
    by rewrite dmap_cst //; apply dlist_ll; exact dbool_ll.
  rewrite (_ : 3*(n+1)+extra = 3+(3*n+extra)) 1:/# dlist_add 1:// 1:/# dmap_comp.
  rewrite (eq_dmap_in _ _ (fun xy : bool list * bool list => bs2int xy.`1 :: digits 3 n xy.`2)).
  + move=> [lo hi] /= /supp_dprod [hlo hhi]; rewrite /(\o) /= digits_cat //.
    exact (supp_dlist_size dbool 3 lo _ hlo).
  by rewrite (dmap_dprod_comp _ _ bs2int (digits 3 n) (fun x xs => x :: xs))
    uniform_three_bits ih dlistS.
qed.

lemma uniform_digit_sum (n extra target : int) : 0 <= n => 0 <= extra =>
  mu (dlist dbool (3*n+extra)) (fun bs => sumz (digits 3 n bs) = target)
   = (count_ds n 8 target)%r / (8 ^ n)%r.
proof.
  move=> hn he.
  rewrite -(dmapE (dlist dbool (3*n+extra)) (digits 3 n) (fun ds => sumz ds = target)).
  by rewrite uniform_digits // uniform_words // duniformE undup_id 1:uniq_words //
    -count_ds_correct // size_words.
qed.
