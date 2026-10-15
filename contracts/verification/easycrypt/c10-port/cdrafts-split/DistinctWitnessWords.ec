(* Ordered selections without replacement. A selected position is removed
   before the next one, so the finite count is a falling factorial. *)
require import AllCore List StdOrder Ring.
import IntOrder.

op distinct_step (f : int list -> int list list) alphabet =
  flatten (map (fun x => map (fun xs => x::xs) (f (rem x alphabet))) alphabet).
op distinct_words k alphabet =
  (foldr (fun (_ : int) f => distinct_step f)
    (fun (_ : int list) => [[]]) (nseq k 0)) alphabet.
op falling n k =
  (foldr (fun (_ : int) f => fun m => max 0 m*f (m-1))
    (fun (_ : int) => 1) (nseq k 0)) n.
op witness_alphabet n target = rem target (range 0 n).
op distinct_witness_words n target j = distinct_words j (witness_alphabet n target).

lemma distinct_words_zero alphabet : distinct_words 0 alphabet=[[]].
proof. by rewrite /distinct_words nseq0. qed.

lemma distinct_words_step k alphabet : 0<=k =>
  distinct_words (k+1) alphabet=distinct_step (distinct_words k) alphabet.
proof. move=> hk; by rewrite /distinct_words nseqS 1:hk /=. qed.

lemma falling_zero n : falling n 0=1.
proof. by rewrite /falling nseq0. qed.

lemma falling_step n k : 0<=k => falling n (k+1)=max 0 n*falling (n-1) k.
proof. move=> hk; by rewrite /falling nseqS 1:hk /=. qed.

lemma falling_nonnegative n k : 0<=k => 0<=falling n k.
proof.
  move=> hk; elim: k hk n => [|k hk ih] n.
  + by rewrite falling_zero.
  rewrite falling_step 1:hk; have h:=ih (n-1); smt().
qed.

lemma distinct_step_member f alphabet xs :
  mem (distinct_step f alphabet) xs=
    (exists x ys, mem alphabet x /\ mem (f (rem x alphabet)) ys /\ xs=x::ys).
proof.
  rewrite /distinct_step -flatten_mapP eq_iff; split.
  + move=> [x [hx hy]]; move: hy; rewrite mapP.
    move=> [ys [hys he]]; exists x ys; smt().
  move=> [x ys [hx [hy he]]]; exists x; split=> //.
  rewrite mapP; exists ys; smt().
qed.

lemma distinct_rem_member (alphabet : int list) x y : uniq alphabet =>
  mem (rem x alphabet) y=(mem alphabet y /\ y<>x).
proof. move=> hu; rewrite rem_filter 1:hu mem_filter /predC1 /=; smt(). qed.

lemma distinct_words_member k alphabet xs : 0<=k => uniq alphabet =>
  mem (distinct_words k alphabet) xs=
    (size xs=k /\ uniq xs /\ all (mem alphabet) xs).
proof.
  move=> hk; elim: k hk alphabet xs => [|k hk ih] alphabet xs hu.
  + rewrite distinct_words_zero /=; smt(size_eq0).
  rewrite distinct_words_step 1:hk distinct_step_member eq_iff; split.
  + move=> [x ys [hx [hy ->]]].
    have hr:=rem_uniq x alphabet hu.
    have hh:=ih (rem x alphabet) ys hr.
    have hs : size ys=k by smt().
    have hyu : uniq ys by smt().
    have hya : all (mem (rem x alphabet)) ys by smt().
    have hne : !mem ys x.
    - move: hya=> /allP ha; have hm:=distinct_rem_member alphabet x x hu; smt().
    have hall : all (mem alphabet) ys.
    - apply/allP=> y hym; move: hya=> /allP ha.
      have hm:=ha y hym; exact (mem_rem x alphabet y hm).
    rewrite /= hs hyu hne hx hall; smt().
  case xs=> [|x ys]; first by rewrite /=; smt().
  move=> [hs [hyu hya]].
  have hx : mem alphabet x by smt().
  have hn : !mem ys x by smt().
  have hy : uniq ys by smt().
  have hall : all (mem (rem x alphabet)) ys.
  + apply/allP=> y hym; rewrite distinct_rem_member 1:hu.
    move: hya=> /= [_ /allP ha]; have hm:=ha y hym; smt().
  exists x ys; split=> //; split; last by [].
  rewrite (ih (rem x alphabet) ys (rem_uniq x alphabet hu)); smt().
qed.

lemma distinct_words_size k alphabet : 0<=k => uniq alphabet =>
  size (distinct_words k alphabet)=falling (size alphabet) k.
proof.
  move=> hk; elim: k hk alphabet => [|k hk ih] alphabet hu.
  + by rewrite distinct_words_zero falling_zero.
  rewrite distinct_words_step 1:hk /distinct_step.
  have hc : forall xs,
      mem (map (fun x => map (fun ys => x::ys)
        (distinct_words k (rem x alphabet))) alphabet) xs =>
      size xs=falling (size alphabet-1) k.
  + move=> xs; rewrite mapP; move=> [x [hx ->]].
    rewrite size_map ih 1:(rem_uniq x alphabet hu) size_rem 1:hx; by [].
  rewrite (size_flatten_ctt (falling (size alphabet-1) k) _ hc) size_map.
  rewrite falling_step 1:hk; have hn:=size_ge0 alphabet; smt().
qed.

lemma witness_alphabet_uniq n target : uniq (witness_alphabet n target).
proof. rewrite /witness_alphabet; apply rem_uniq; exact (range_uniq 0 n). qed.

lemma witness_alphabet_member n target x :
  mem (witness_alphabet n target) x=(0<=x<n /\ x<>target).
proof.
  rewrite /witness_alphabet distinct_rem_member 1:(range_uniq 0 n) mem_range.
  by [].
qed.

lemma witness_alphabet_size n target : 0<=target<n =>
  size (witness_alphabet n target)=n-1.
proof.
  move=> ht; rewrite /witness_alphabet size_rem; first by rewrite mem_range.
  rewrite size_range; smt().
qed.

lemma distinct_witness_words_size n target j :
  0<=j => 0<=target<n => size (distinct_witness_words n target j)=falling (n-1) j.
proof.
  move=> hj ht; rewrite /distinct_witness_words distinct_words_size 1:hj
    1:witness_alphabet_uniq witness_alphabet_size 1:ht; by [].
qed.

lemma distinct_witness_words_member n target j xs : 0<=j =>
  mem (distinct_witness_words n target j) xs=
    (size xs=j /\ uniq xs /\ all (fun x => 0<=x<n /\ x<>target) xs).
proof.
  move=> hj; rewrite /distinct_witness_words distinct_words_member 1:hj
    1:witness_alphabet_uniq.
  have he : all (mem (witness_alphabet n target)) xs=
      all (fun x => 0<=x<n /\ x<>target) xs.
  + rewrite eq_iff; apply eq_all=> x; by rewrite /= witness_alphabet_member.
  by rewrite he.
qed.

lemma distinct_words_uniq k alphabet : 0<=k => uniq alphabet =>
  uniq (distinct_words k alphabet).
proof.
  move=> hk; elim: k hk alphabet => [|k hk ih] alphabet hu.
  + by rewrite distinct_words_zero.
  rewrite distinct_words_step 1:hk /distinct_step.
  apply uniq_flatten_map.
  + move=> x; rewrite map_inj_in_uniq; first smt().
    exact (ih (rem x alphabet) (rem_uniq x alphabet hu)).
  + move=> x y hx hy; rewrite hasP.
    move=> [xs [hx' hy']]; move: hx' hy'; rewrite !mapP.
    move=> [ys [hys he]] [zs [hzs he']]; smt().
  exact hu.
qed.

lemma falling_upper n m k : 0<=k => 0<=m => n<=m => falling n k<=m^k.
proof.
  move=> hk; elim: k hk n => [|k hk ih] n hm hnm.
  + by rewrite falling_zero IntID.expr0.
  rewrite falling_step 1:hk IntID.exprS 1:hk.
  have hi:=ih (n-1) hm _; first smt().
  have hn:=falling_nonnegative (n-1) k hk.
  have hp : 0<=m^k by apply expr_ge0.
  smt().
qed.

lemma falling_insufficient n k : 0<=k => 0<=n<k => falling n k=0.
proof.
  move=> hk; elim: k hk n => [|k hk ih] n hn.
  + smt().
  rewrite falling_step 1:hk.
  case (n=0)=> hz; first by rewrite hz /=.
  have hi:=ih (n-1) _; first smt().
  by rewrite hi /=.
qed.

lemma falling_nonpositive n k : n<=0 => 1<=k => falling n k=0.
proof.
  move=> hn hk; have hs:=falling_step n (k-1) _; first smt().
  smt().
qed.

lemma distinct_witness_words_insufficient n target j :
  0<=target<n => n<=j => distinct_witness_words n target j=[].
proof.
  move=> ht hj; have hj0 : 0<=j by smt().
  have hs:=distinct_witness_words_size n target j hj0 ht.
  have hz:=falling_insufficient (n-1) j hj0 _; first smt().
  smt(size_eq0).
qed.
