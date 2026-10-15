(* Canonical witness labels, read from the last coordinate to the first.
   An existing label is below the suffix width; a new label is that width. *)
require import AllCore List IntDiv StdOrder.
import IntOrder.

op growth_state (xs : int list) : bool * int =
  foldr (fun x (a : bool * int) =>
    (a.`1 /\ 0<=x<=a.`2, max (x+1) a.`2)) (true,0) xs.
op growth_word xs = (growth_state xs).`1.
op growth_width xs = (growth_state xs).`2.
op growth_extend xs = map (fun x => x::xs) (range 0 (growth_width xs+1)).
op growth_next words = flatten (map growth_extend words).
op growth_words k : int list list =
  foldr (fun (_ : int) words => growth_next words) [[]] (nseq k 0).
op growth_count k j = size (filter (fun xs => growth_width xs=j) (growth_words k)).

op stirling_step (row : int list) =
  mkseq (fun j => j*nth 0 row j + nth 0 row (j-1)) (size row+1).
op stirling_row k = foldr (fun (_ : int) row => stirling_step row) [1] (nseq k 0).
op stirling k j = nth 0 (stirling_row k) j.

lemma growth_word_nil : growth_word [].
proof. by rewrite /growth_word /growth_state. qed.

lemma growth_width_nil : growth_width []=0.
proof. by rewrite /growth_width /growth_state. qed.

lemma growth_word_cons x xs :
  growth_word (x::xs) = (growth_word xs /\ 0<=x<=growth_width xs).
proof. by rewrite /growth_word /growth_width /growth_state /=. qed.

lemma growth_width_cons x xs :
  growth_width (x::xs)=max (x+1) (growth_width xs).
proof. by rewrite /growth_width /growth_state /=. qed.

lemma growth_width_nonnegative xs : 0<=growth_width xs.
proof.
  elim: xs => [|x xs ih]; first by rewrite growth_width_nil.
  rewrite growth_width_cons; smt().
qed.

lemma growth_width_bound xs : growth_word xs => growth_width xs<=size xs.
proof.
  elim: xs => [|x xs ih]; first by rewrite growth_width_nil /=.
  rewrite growth_word_cons growth_width_cons /=.
  move=> [hw hx]; have h:=ih hw; smt().
qed.

lemma growth_labels_bound xs :
  growth_word xs => all (fun x => 0<=x<growth_width xs) xs.
proof.
  elim: xs => [|x xs ih]; first by [].
  rewrite growth_word_cons growth_width_cons /=.
  move=> [hw hx]; split; first smt().
  apply/allP=> y hy; have h:=ih hw; move: h=> /allP h.
  have hb:=h y hy; smt().
qed.

lemma growth_words_zero : growth_words 0=[[]].
proof. by rewrite /growth_words nseq0. qed.

lemma growth_words_step k : 0<=k =>
  growth_words (k+1)=growth_next (growth_words k).
proof. move=> hk; by rewrite /growth_words nseqS 1:hk /=. qed.

lemma stirling_row_zero : stirling_row 0=[1].
proof. by rewrite /stirling_row nseq0. qed.

lemma stirling_row_step k : 0<=k =>
  stirling_row (k+1)=stirling_step (stirling_row k).
proof. move=> hk; by rewrite /stirling_row nseqS 1:hk /=. qed.

lemma growth_extend_member xs ys :
  mem (growth_extend xs) ys =
    (exists x, 0<=x<=growth_width xs /\ ys=x::xs).
proof.
  rewrite /growth_extend mapP eq_iff; split.
  + move=> [x [hx he]]; exists x; move: hx; rewrite mem_range; smt().
  move=> [x [hx he]]; exists x; rewrite mem_range; smt().
qed.

lemma growth_words_membership k xs : 0<=k =>
  mem (growth_words k) xs = (size xs=k /\ growth_word xs).
proof.
  move=> hk; elim: k hk xs => [|k hk ih] xs.
  + rewrite growth_words_zero /=; smt(size_eq0 growth_word_nil).
  rewrite growth_words_step 1:hk /growth_next -flatten_mapP eq_iff; split.
  + move=> [ys [hy he]]; have hh:=ih ys.
    have hs : size ys=k by smt().
    have hw : growth_word ys by smt().
    move: he; rewrite growth_extend_member; move=> [x [hx ->]].
    rewrite /= growth_word_cons; smt().
  case xs => [|x ys]; first by rewrite /=; smt().
  move=> [hs hw]; have hh:=growth_word_cons x ys.
  have hy : growth_word ys by smt().
  have hx : 0<=x<=growth_width ys by smt().
  exists ys; split; first by rewrite (ih ys); smt().
  rewrite growth_extend_member; exists x; smt().
qed.

lemma stirling_row_size k : 0<=k => size (stirling_row k)=k+1.
proof.
  move=> hk; elim: k hk => [|k hk ih]; first by rewrite stirling_row_zero.
  rewrite stirling_row_step 1:hk /stirling_step size_mkseq; smt(size_ge0).
qed.

lemma stirling_zero j : stirling 0 j=(if j=0 then 1 else 0).
proof. by rewrite /stirling stirling_row_zero /=. qed.

lemma stirling_outside k j : 0<=k => j<0 \/ k<j => stirling k j=0.
proof.
  move=> hk hj; rewrite /stirling nth_out; first smt(stirling_row_size).
  by [].
qed.

lemma stirling_recurrence k j : 0<=k =>
  stirling (k+1) j=j*stirling k j+stirling k (j-1).
proof.
  move=> hk; case (0<=j<=k+1)=> hj.
  + rewrite /stirling stirling_row_step 1:hk /stirling_step nth_mkseq.
    - smt(stirling_row_size).
    by [].
  have h0 : stirling (k+1) j=0 by apply stirling_outside; smt().
  have h1 : stirling k j=0 by apply stirling_outside; smt().
  have h2 : stirling k (j-1)=0 by apply stirling_outside; smt().
  by rewrite h0 h1 h2 /=.
qed.

lemma growth_labels_complete xs j :
  growth_word xs => 0<=j<growth_width xs => mem xs j.
proof.
  elim: xs j => [|x xs ih] j.
  + by rewrite growth_width_nil; smt().
  rewrite growth_word_cons growth_width_cons /=; move=> [hw hx] hj.
  case (j=x)=> he; first by rewrite he.
  have hb : 0<=j<growth_width xs by smt().
  have hm:=ih j hw hb; smt().
qed.

lemma growth_distinct_labels xs :
  growth_word xs => size (undup xs)=growth_width xs.
proof.
  move=> hw.
  have hp : perm_eq (undup xs) (range 0 (growth_width xs)).
  + apply uniq_perm_eq; first exact (undup_uniq xs).
    - exact (range_uniq 0 (growth_width xs)).
    move=> j; rewrite mem_undup mem_range; split.
    - move=> hj; have h:=growth_labels_bound xs hw; move: h=> /allP h; exact (h j hj).
    move=> hj; exact (growth_labels_complete xs j hw hj).
  have hs:=perm_eq_size _ _ hp.
  rewrite size_range in hs; have hn:=growth_width_nonnegative xs; smt().
qed.

lemma growth_extend_uniq xs : uniq (growth_extend xs).
proof.
  rewrite /growth_extend map_inj_in_uniq; first smt().
  exact (range_uniq _ _).
qed.

lemma growth_next_uniq words : uniq words => uniq (growth_next words).
proof.
  move=> hw; rewrite /growth_next; apply uniq_flatten_map.
  + exact growth_extend_uniq.
  + move=> xs ys hx hy; rewrite hasP.
    move=> [zs [hzx hzy]].
    move: hzx hzy; rewrite !growth_extend_member.
    move=> [x [hb he]] [y [hb' he']]; smt().
  exact hw.
qed.

lemma growth_words_uniq k : 0<=k => uniq (growth_words k).
proof.
  move=> hk; elim: k hk => [|k hk ih].
  + by rewrite growth_words_zero.
  rewrite growth_words_step 1:hk; exact (growth_next_uniq _ ih).
qed.

lemma growth_extend_count xs j :
  count (fun ys => growth_width ys=j) (growth_extend xs)=
    j*b2i(growth_width xs=j)+b2i(growth_width xs=j-1).
proof.
  have hn:=growth_width_nonnegative xs.
  rewrite /growth_extend count_map /= rangeSr 1:hn -cats1 count_cat /=.
  have hc : count (fun x => growth_width (x::xs)=j)
      (range 0 (growth_width xs))=
      (if growth_width xs=j then growth_width xs else 0).
  + case (growth_width xs=j)=> he.
    - rewrite he; rewrite count_predT_eq_in.
      * move=> x hx; move: hx; rewrite mem_range /= growth_width_cons; smt().
      rewrite size_range; smt().
    rewrite count_pred0_eq_in; last by [].
    move=> x hx; move: hx; rewrite mem_range /= growth_width_cons; smt().
  have hw:=growth_width_cons (growth_width xs) xs.
  rewrite hc /b2i; smt().
qed.

lemma growth_next_count words j :
  count (fun ys => growth_width ys=j) (growth_next words)=
    j*count (fun ys => growth_width ys=j) words+
      count (fun ys => growth_width ys=j-1) words.
proof.
  elim: words => [|xs words ih]; first by rewrite /growth_next /= flatten_nil.
  rewrite /growth_next /= flatten_cons count_cat growth_extend_count.
  have hh:=ih; rewrite /growth_next in hh; smt().
qed.

lemma growth_count_zero j : growth_count 0 j=(if j=0 then 1 else 0).
proof.
  rewrite /growth_count growth_words_zero /= growth_width_nil; smt().
qed.

lemma growth_count_recurrence k j : 0<=k =>
  growth_count (k+1) j=j*growth_count k j+growth_count k (j-1).
proof.
  move=> hk; rewrite /growth_count !size_filter growth_words_step 1:hk.
  exact (growth_next_count _ _).
qed.

lemma growth_count_stirling k j : 0<=k => growth_count k j=stirling k j.
proof.
  move=> hk; elim: k hk j => [|k hk ih] j.
  + by rewrite growth_count_zero stirling_zero.
  by rewrite growth_count_recurrence 1:hk stirling_recurrence 1:hk !ih.
qed.
