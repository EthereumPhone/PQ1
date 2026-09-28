(* Bounds for every byte used by the concrete multiply-high shuffle. *)
require import AllCore List IntDiv BitEncoding Ring.
require import C10Bytes.
import BS2Int BitChunking.

lemma shuffle_bytes_valid d :
  all (fun b => 0 <= b < 256) (bits_to_bytes d).
proof.
  rewrite /bits_to_bytes all_rev; apply/allP => x /mapP [bits [hb ->]].
  have hw := in_chunk_size 8 d bits _ hb; first by [].
  have hlo := bs2int_ge0 bits; have hhi := bs2int_le2Xs bits.
  have hpow : 2^8=256 by rewrite (_ : 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  smt().
qed.

lemma shuffle_nth_byte stream i :
  all (fun b => 0 <= b < 256) stream => 0 <= nth 0 stream i < 256.
proof.
  move=> hs; case (0 <= i < size stream) => hi.
  + have hm := mem_nth 0 stream i hi; move: hs => /allP; smt().
  rewrite nth_out 1:/#; smt().
qed.

lemma shuffle_mulhi_range lo hi i :
  0 <= lo < 256 => 0 <= hi < 256 => 0 <= i =>
  0 <= ((hi*256+lo)*(i+1)) %/ 65536 <= i.
proof. smt(divz_ge0 ltz_divLR). qed.
