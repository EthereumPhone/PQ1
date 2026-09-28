(* Radix digits read in increasing significance order from a bit list.
   BitEncoding uses least-significant-bit-first lists. Missing bits are zero;
   consumer correspondence below uses only in-bounds 256-bit windows. *)
require import AllCore List IntDiv BitEncoding StdOrder.
import BS2Int IntOrder.

op digit (k : int) (bs : bool list) (i : int) : int =
  bs2int (mkseq (fun j => nth false bs (k * i + j)) k).

op digits (k n : int) (bs : bool list) : int list =
  mkseq (digit k bs) n.

lemma digit_range (k : int) (bs : bool list) (i : int) :
  0 <= k => 0 <= digit k bs i < 2 ^ k.
proof.
  move=> hk; rewrite /digit; split; first exact bs2int_ge0.
  have := bs2int_le2Xs (mkseq (fun j => nth false bs (k * i + j)) k).
  by rewrite size_mkseq ler_maxr.
qed.

lemma digit3 (bs : bool list) (i : int) :
  digit 3 bs i = b2i (nth false bs (3*i))
    + 2 * b2i (nth false bs (3*i+1))
    + 4 * b2i (nth false bs (3*i+2)).
proof.
  rewrite /digit (mkseqSr _ 2) 1:// (mkseqSr _ 1) 1:// (mkseqSr _ 0) 1:// mkseq0 /= /(\o) /= !bs2int_cons bs2int_nil /=.
  ring.
qed.


lemma digit_slice (k : int) (bs : bool list) (i : int) :
  0 <= k => 0 <= i => k * (i + 1) <= size bs =>
  digit k bs i = bs2int (take k (drop (k*i) bs)).
proof.
  move=> hk hi hsz; rewrite /digit; congr.
  apply (eq_from_nth false).
  + rewrite size_mkseq size_take 1:// size_drop 1:/#; smt().
  move=> j; rewrite size_mkseq => hj.
  by rewrite nth_mkseq 1:/# nth_take 1,2:/# nth_drop 1,2:/#.
qed.

lemma digit_integer (k : int) (bs : bool list) (i : int) :
  0 <= k => 0 <= i => k * (i + 1) <= size bs =>
  digit k bs i = (bs2int bs %/ 2 ^ (k*i)) %% 2 ^ k.
proof.
  move=> hk hi hs; rewrite digit_slice // bs2int_div 1:/# bs2int_mod //.
qed.

lemma digits_cat (k n : int) (lo hi : bool list) :
  0 <= k => 0 <= n => size lo = k =>
  digits k (n+1) (lo ++ hi) = bs2int lo :: digits k n hi.
proof.
  move=> hk hn hs; rewrite /digits mkseqSr //=.
  have headE : digit k (lo ++ hi) 0 = bs2int lo.
  + rewrite digit_slice 1,2:// 1:size_cat; first smt(size_ge0).
    by rewrite /= drop0 take_cat hs /= take0 cats0.
  rewrite headE /=.
  apply (eq_from_nth 0); first by rewrite !size_mkseq.
  move=> j; rewrite size_mkseq => hj; rewrite !nth_mkseq 1,2:/# /= /(\o) /digit.
  congr; apply (eq_from_nth false); first by rewrite !size_mkseq.
  move=> t; rewrite size_mkseq => ht; rewrite !nth_mkseq 1,2:/# /=.
  rewrite nth_cat hs (: !(k * (1+j)+t < k)) 1:/# /=.
  by congr; ring.
qed.
