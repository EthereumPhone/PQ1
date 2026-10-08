(* Cartesian words with a separate alphabet size at each position. *)
require import AllCore List IntDiv StdOrder Ring.
import IntOrder.

op bounded_words (bounds : int list) : int list list =
  foldr (fun b acc => allpairs (fun x xs => x::xs) (range 0 b) acc) [[]] bounds.
op bounded_word bounds (xs : int list) =
  size xs=size bounds /\ forall i, 0<=i<size xs => 0<=nth 0 xs i<nth 0 bounds i.
op bounded_word_count (bounds : int list) = foldr (fun b n => max 0 b*n) 1 bounds.
op canonical_bounds j = mkseq (fun i => min j (12-i)) 12.
op canonical_words j = bounded_words (canonical_bounds j).
op canonical_assignment j f = bounded_word (canonical_bounds j) f.
op canonical_assignment_count j = bounded_word_count (canonical_bounds j).

lemma bounded_word_cons b bounds x xs :
  bounded_word (b::bounds) (x::xs) = (0<=x<b /\ bounded_word bounds xs).
proof.
  rewrite /bounded_word /= eq_iff; split.
  + move=> [hs hall]; have hx:=hall 0 _; first smt(size_ge0).
    split; first smt().
    split; first smt().
    move=> i hi; have h:=hall (i+1) _; first smt().
    move: h; rewrite /= (: i+1<>0) 1:/# /=; smt().
  move=> [hx [hs hall]]; split; first smt().
  move=> i hi; case (i=0)=> hz; first by subst i.
  have h:=hall (i-1) _; first smt().
  smt().
qed.
lemma bounded_words_membership bounds xs :
  mem (bounded_words bounds) xs = bounded_word bounds xs.
proof.
  elim: bounds xs => [|b bounds ih] xs.
  + rewrite /bounded_words /bounded_word /=; smt(size_eq0).
  rewrite /bounded_words /= -/(bounded_words bounds) allpairsP.
  case xs => [|x xs]; first rewrite /bounded_word /=; first smt(size_ge0).
  rewrite bounded_word_cons eq_iff; split.
  + move=> [[y ys] /= [hy [hys he]]]; move: hy; rewrite mem_range=> hy; smt().
  move=> [hx hxs]; exists (x,xs); rewrite /= mem_range ih; smt().
qed.
lemma bounded_words_size bounds : size (bounded_words bounds)=bounded_word_count bounds.
proof.
  elim: bounds=> [|b bounds ih]; first by rewrite /bounded_words /bounded_word_count.
  by rewrite /bounded_words /= -/(bounded_words bounds) size_allpairs size_range ih
    /bounded_word_count /=.
qed.
lemma canonical_assignment_shape j f :
  canonical_assignment j f =
    (size f=12 /\ forall i, 0<=i<12 => 0<=nth 0 f i<j /\ nth 0 f i<12-i).
proof.
  rewrite /canonical_assignment /bounded_word /canonical_bounds size_mkseq /= eq_iff; split.
  + move=> [hs hall]; split=> // i hi; have h:=hall i _; first smt().
    move: h; rewrite nth_mkseq //; smt().
  move=> [hs hall]; split=> // i hi; rewrite nth_mkseq 1:/# /=.
  have h:=hall i _; first smt().
  smt().
qed.
lemma canonical_words_member j f : mem (canonical_words j) f=canonical_assignment j f.
proof. by rewrite /canonical_words /canonical_assignment bounded_words_membership. qed.
lemma canonical_words_size j : size (canonical_words j)=canonical_assignment_count j.
proof. by rewrite /canonical_words /canonical_assignment_count bounded_words_size. qed.

lemma bounded_word_count_nonnegative bounds : 0<=bounded_word_count bounds.
proof. rewrite -(bounded_words_size bounds); exact (size_ge0 _). qed.
lemma bounded_word_count_upper bounds j :
  0<=j => all (fun b=>0<=b<=j) bounds => bounded_word_count bounds<=j^(size bounds).
proof.
  elim: bounds=> [|b bounds ih] hj hb; first by rewrite /bounded_word_count /= IntID.expr0.
  move: hb=> /= [hb hbs]; have h:=ih hj hbs.
  have hpos:=bounded_word_count_nonnegative bounds.
  rewrite /bounded_word_count /= -/(bounded_word_count bounds) (: 1+size bounds=size bounds+1) 1:/# IntID.exprS 1:size_ge0.
  have hjpow : 0<=j^(size bounds) by apply expr_ge0.
  smt().
qed.
lemma canonical_count_upper j : 0<=j => 0<=canonical_assignment_count j<=j^12.
proof.
  move=> hj; rewrite /canonical_assignment_count; split; first exact (bounded_word_count_nonnegative _).
  have hall : all (fun b=>0<=b<=j) (canonical_bounds j).
  + apply/allP=> b; rewrite /canonical_bounds mkseqP; move=> [i [hi ->]]; smt().
  have h:=bounded_word_count_upper (canonical_bounds j) j hj hall.
  by move: h; rewrite /canonical_bounds size_mkseq /=.
qed.
