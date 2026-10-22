(* Finite first-hit selectors: zero is exhaustion; otherwise index + 1.
   A mathematical digest schedule does not perform additional oracle queries. *)
require import AllCore List C10Representation.

op first_slot ['a] (accept : 'a -> bool) (xs : 'a list) : int =
  foldr (fun x slot => if accept x then 1 else if slot = 0 then 0 else slot + 1) 0 xs.

lemma first_slot_nil ['a] (p : 'a -> bool) : first_slot p [] = 0.
proof. by rewrite /first_slot. qed.

lemma first_slot_cons ['a] (p : 'a -> bool) x xs :
  first_slot p (x :: xs) =
    if p x then 1 else if first_slot p xs = 0 then 0 else first_slot p xs + 1.
proof. by rewrite /first_slot. qed.

lemma first_slot_bounds ['a] (p : 'a -> bool) xs :
  0 <= first_slot p xs <= size xs.
proof. elim xs => [|x xs ih]; rewrite ?first_slot_nil ?first_slot_cons /=; smt(). qed.

lemma first_slot_zero ['a] (p : 'a -> bool) xs :
  first_slot p xs = 0 <=> all (fun x => !p x) xs.
proof.
  elim xs => [|x xs ih]; rewrite ?first_slot_nil ?first_slot_cons /=.
  + trivial.
  have hb := first_slot_bounds p xs; smt().
qed.

lemma first_slot_hit ['a] (p : 'a -> bool) pre a post :
  p a => all (fun x => !p x) pre =>
  first_slot p (pre ++ a :: post) = size pre + 1.
proof.
  move=> ha; elim pre => [|x xs ih]; rewrite /= first_slot_cons; smt(size_ge0).
qed.

lemma first_slot_rcons ['a] (p : 'a -> bool) xs x :
  first_slot p (rcons xs x) =
    if first_slot p xs = 0 then (if p x then size xs + 1 else 0)
    else first_slot p xs.
proof.
  elim xs => [|y ys ih]; rewrite ?first_slot_nil ?first_slot_cons /=.
  + by rewrite first_slot_cons first_slot_nil.
  have hb := first_slot_bounds p ys; rewrite first_slot_cons ih; smt().
qed.

lemma first_slot_mkseq_zero ['a] (p : 'a -> bool) (f : int -> 'a) n :
  (forall i, 0 <= i < n => !p (f i)) => first_slot p (mkseq f n) = 0.
proof. move=> h; rewrite first_slot_zero allP; smt(mkseqP). qed.

lemma first_slot_cat ['a] (p : 'a -> bool) xs ys :
  first_slot p (xs ++ ys) =
    if first_slot p xs = 0 then
      (if first_slot p ys = 0 then 0 else size xs + first_slot p ys)
    else first_slot p xs.
proof.
  elim xs => [|x xs ih]; rewrite ?first_slot_nil ?first_slot_cons /=; first smt().
  have hx := first_slot_bounds p xs.
  have hy := first_slot_bounds p ys.
  rewrite first_slot_cons ih; smt().
qed.

lemma first_slot_mkseq_hit ['a] (p : 'a -> bool) (f : int -> 'a) n i :
  0 <= i < n => p (f i) => (forall j, 0 <= j < i => !p (f j)) =>
  first_slot p (mkseq f n) = i + 1.
proof.
  move=> hi ha hp.
  have he : n = i + (n-i) by ring.
  rewrite he mkseq_add 1:/# 1:/#.
  rewrite first_slot_cat (first_slot_mkseq_zero p f i hp) /=.
  rewrite mkseqSr_minus 1:/# first_slot_cons /= ha /= size_mkseq; smt().
qed.

lemma signed_difference_zero (a b : int) : (a-b = 0) = (a=b).
proof. smt(). qed.

lemma wots_first_slot_common digests :
  wots_first_slot digests = first_slot (fun d => wots_sum d = wots_target) digests.
proof.
  rewrite /wots_first_slot /first_slot.
  congr; apply fun_ext => d; apply fun_ext => n; by rewrite signed_difference_zero.
qed.

lemma fors_first_slot_common digests :
  fors_first_slot digests = first_slot (fun d => fors_zero_field d = 0) digests.
proof. by rewrite /fors_first_slot /first_slot. qed.
