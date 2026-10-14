(* Exact acceptance tests over one correlated digest. The byte-domain premises
   match Rust's fixed byte arrays; no oracle/backend or probability relation. *)
require import AllCore List IntDiv StdBigop BitEncoding.
require import C10Bytes C10RawGrind RawWots C10RepresentationBridge.
require import C10Representation.
import Bigint BS2Int.

lemma wots_sum_common bs :
  size bs = 32 => all (fun b => 0 <= b < 256) bs =>
  sumz (raw_digits (bytes_to_bits bs)) = wots_sum bs.
proof.
  move=> hs hb; rewrite /raw_digits /RadixEncoding.digits /wots_sum.
  have he : mkseq (fun j => RadixEncoding.digit 3 (bytes_to_bits bs) j) 43 =
    mkseq (fun j => wots_field bs j) 43.
  + apply eq_in_mkseq => j hj; exact (wots_common bs j hs hj hb).
  by rewrite he /sumz.
qed.

lemma wots_accept_common bs :
  size bs = 32 => all (fun b => 0 <= b < 256) bs =>
  count_accepts (bytes_to_bits bs) = (wots_sum bs = wots_target).
proof. by move=> hs hb; rewrite /count_accepts (wots_sum_common bs hs hb) /wots_target. qed.

lemma fors_accept_common bs :
  size bs = 32 => all (fun b => 0 <= b < 256) bs =>
  accept_digest (bytes_to_bits bs) = (fors_zero_field bs = 0).
proof.
  move=> hs hb; rewrite /accept_digest /fors_zero_field /word_window.
  rewrite -(byte_window bs 132 11) 1,2:// 1:hb.
  have hw : size (take 11 (drop 132 (bytes_to_bits bs))) = 11
    by rewrite size_take 1:// size_drop 1:// bytes_to_bits_size hs /=.
  rewrite eq_iff; split.
  + move=> ->; by rewrite bs2int_nseq_false.
  move=> hz.
  have hinj := inj_bs2int_eqsize (take 11 (drop 132 (bytes_to_bits bs))) (nseq 11 false).
  apply hinj; first by rewrite hw size_nseq.
  by rewrite hz bs2int_nseq_false.
qed.
