(* The existing reverse-last-occurrence witness normalization is a
   restricted-growth word, with every distinct witness used. *)
require import AllCore List StdOrder.
require import RestrictedGrowthWords BoundedAssignmentWords.
import IntOrder.

op reverse_labels (xs : int list) =
  map (fun x => index x (rev (undup xs))) xs.
op exact_growth_words k j =
  filter (fun xs => growth_width xs=j) (growth_words k).

lemma reverse_labels_size xs : size (reverse_labels xs)=size xs.
proof. by rewrite /reverse_labels size_map. qed.

lemma reverse_labels_old x xs : mem xs x =>
  reverse_labels (x::xs)=index x (rev (undup xs))::reverse_labels xs.
proof. move=> hx; by rewrite /reverse_labels /= hx. qed.

lemma reverse_labels_new x xs : !mem xs x =>
  reverse_labels (x::xs)=size (undup xs)::reverse_labels xs.
proof.
  move=> hx.
  have hm : map (fun y => index y (rev (undup xs)++[x])) xs=
      map (fun y => index y (rev (undup xs))) xs.
  + apply/eq_in_map=> y hy.
    by rewrite /= index_cat mem_rev mem_undup hy.
  rewrite /reverse_labels /= hx /= rev_cons -cats1.
  by rewrite index_cat mem_rev mem_undup hx /= size_rev hm.
qed.

lemma reverse_labels_growth xs :
  growth_word (reverse_labels xs) /\
  growth_width (reverse_labels xs)=size (undup xs).
proof.
  elim: xs => [|x xs [ihw ihs]].
  + by rewrite /reverse_labels /= growth_word_nil growth_width_nil.
  case (mem xs x)=> hx.
  + rewrite reverse_labels_old 1:hx growth_word_cons growth_width_cons /= hx /=.
    have hg:=index_ge0 x (rev (undup xs)).
    have hm : index x (rev (undup xs))<size (undup xs).
    - by rewrite -size_rev index_mem mem_rev mem_undup hx.
    smt().
  have he:=reverse_labels_new x xs hx.
  have hw:=growth_word_cons (size (undup xs)) (reverse_labels xs).
  have hs:=growth_width_cons (size (undup xs)) (reverse_labels xs).
  have hu : size (undup (x::xs))=size (undup xs)+1 by rewrite /= hx /=; smt().
  have hn:=size_ge0 (undup xs); smt().
qed.

lemma reverse_labels_reconstruct xs :
  map (fun j => nth 0 (rev (undup xs)) j) (reverse_labels xs)=xs.
proof.
  have he : map (fun x => nth 0 (rev (undup xs))
      (index x (rev (undup xs)))) xs=map idfun xs.
  + apply/eq_in_map=> x hx /=; rewrite nth_index; first by rewrite mem_rev mem_undup.
    by [].
  rewrite /reverse_labels -map_comp /(\o) /=.
  by rewrite he map_id.
qed.

lemma exact_growth_words_member k j xs : 0<=k =>
  mem (exact_growth_words k j) xs=
    (size xs=k /\ growth_word xs /\ growth_width xs=j).
proof.
  move=> hk; rewrite /exact_growth_words mem_filter growth_words_membership 1:hk /=; smt().
qed.

lemma exact_growth_words_size k j : 0<=k =>
  size (exact_growth_words k j)=stirling k j.
proof. move=> hk; exact (growth_count_stirling k j hk). qed.

lemma exact_growth_words_uniq k j : 0<=k => uniq (exact_growth_words k j).
proof.
  move=> hk; rewrite /exact_growth_words filter_uniq; exact (growth_words_uniq k hk).
qed.

lemma reverse_labels_enumerated xs :
  mem (exact_growth_words (size xs) (size (undup xs))) (reverse_labels xs).
proof.
  rewrite exact_growth_words_member 1:size_ge0 reverse_labels_size.
  exact (reverse_labels_growth xs).
qed.

lemma growth_position_bound xs i :
  growth_word xs => 0<=i<size xs => nth 0 xs i<size xs-i.
proof.
  elim: xs i => [|x xs ih] i; first by rewrite /=; smt().
  rewrite growth_word_cons /=; move=> [hw hx] hi.
  case (i=0)=> hz; first by subst i; have hb:=growth_width_bound xs hw; smt().
  have hib : 0<=i-1<size xs by smt().
  have hb:=ih (i-1) hw hib; smt().
qed.

lemma growth_is_canonical xs j :
  size xs=12 => growth_word xs => growth_width xs=j =>
  canonical_assignment j xs.
proof.
  move=> hs hw hj; rewrite canonical_assignment_shape; split=> // i hi.
  have hm : mem xs (nth 0 xs i) by apply mem_nth; smt().
  have hl:=growth_labels_bound xs hw; move: hl=> /allP hl.
  have hb:=hl _ hm; have hp:=growth_position_bound xs i hw _; smt().
qed.

lemma stirling_canonical_upper j :
  0<=stirling 12 j<=canonical_assignment_count j.
proof.
  have hu : uniq (exact_growth_words 12 j) by apply exact_growth_words_uniq; smt().
  have hi : forall xs, mem (exact_growth_words 12 j) xs => mem (canonical_words j) xs.
  + move=> xs; rewrite exact_growth_words_member 1:/# canonical_words_member.
    move=> [hs [hw hj]]; exact (growth_is_canonical xs j hs hw hj).
  have hb:=uniq_leq_size (exact_growth_words 12 j) (canonical_words j) hu hi.
  have hs:=exact_growth_words_size 12 j _; first smt().
  have hc:=canonical_words_size j.
  have hn:=size_ge0 (exact_growth_words 12 j); smt().
qed.
