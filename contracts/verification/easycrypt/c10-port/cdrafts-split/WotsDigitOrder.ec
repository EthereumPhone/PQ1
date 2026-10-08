(* Accepted constant-sum words either agree or require a lower chain cut. *)
require import AllCore List IntDiv RadixEncoding.
require import C10RawOracle RawWots.

op encoding_bits (d : digest) = mkseq (fun j => nth false d j) 129.

lemma equal_digit_bits d e i j :
  0<=j<3 => digit 3 d i=digit 3 e i =>
  nth false d (3*i+j)=nth false e (3*i+j).
proof. rewrite !digit3 /b2i; smt(). qed.

lemma equal_raw_digits_encoding d e :
  raw_digits d=raw_digits e => encoding_bits d=encoding_bits e.
proof.
  move=> he; apply (eq_from_nth false); first by rewrite /encoding_bits !size_mkseq.
  move=> j; rewrite /encoding_bits size_mkseq /= => hj.
  rewrite !nth_mkseq 1,2:/# /=.
  have hi : 0<=j %/3<43 by smt(divz_ge0 ltz_divLR).
  have hrem : 0<=j %%3<3 by smt(modz_ge0 ltz_pmod).
  have hd : digit 3 d (j %/3)=digit 3 e (j %/3).
  + have hn : nth 0 (raw_digits d) (j %/3)=nth 0 (raw_digits e) (j %/3) by rewrite he.
    by move: hn; rewrite /raw_digits /digits !nth_mkseq 1,2:/#.
  have hb := equal_digit_bits d e (j %/3) (j %%3) hrem hd.
  smt(divz_eq).
qed.

lemma ordered_equal_sum (xs ys : int list) :
  size xs=size ys =>
  (forall i, 0<=i<size xs => nth 0 xs i<=nth 0 ys i) =>
  sumz xs<=sumz ys /\ (sumz xs=sumz ys => xs=ys).
proof.
  elim: xs ys => [ys hs ho|x xs ih ys hs ho].
  + have -> : ys=[] by smt(size_eq0).
    by rewrite /sumz /=.
  case: ys hs ho => [|y ys] /= hs ho; first smt(size_ge0).
  have hh : x<=y by have := ho 0 _; smt(size_ge0).
  have ht : forall i, 0<=i<size xs => nth 0 xs i<=nth 0 ys i.
  + move=> i hi; have := ho (i+1) _; smt().
  have h := ih ys _ ht; first smt().
  move: h; rewrite /sumz /=; smt().
qed.

lemma accepted_digits_reverse_or_equal d e :
  count_accepts d => count_accepts e =>
  raw_digits d=raw_digits e \/
    exists i, 0<=i<43 /\ digit 3 d i<digit 3 e i.
proof.
  rewrite /count_accepts => hd he.
  case (exists i, 0<=i<43 /\ digit 3 d i<digit 3 e i); first smt().
  move=> hn; left.
  have hs : size (raw_digits e)=size (raw_digits d) by rewrite /raw_digits /digits !size_mkseq.
  have ho : forall i, 0<=i<size (raw_digits e) => nth 0 (raw_digits e) i<=nth 0 (raw_digits d) i.
  + move=> i; rewrite /raw_digits /digits size_mkseq /= => hi.
    rewrite !nth_mkseq 1,2:/#; smt().
  have h := ordered_equal_sum (raw_digits e) (raw_digits d) hs ho; smt().
qed.
