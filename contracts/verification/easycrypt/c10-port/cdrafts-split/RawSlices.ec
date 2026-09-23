(* Exact block assembly; no byte or cryptographic assumptions. *)
require import AllCore List IntDiv BitEncoding.
require import C10RawOracle RawSignature RawCodec.
import BitChunking.

lemma blocks_chunk w n (bs : raw_input) offset :
  0 < w => 0 <= n => 0 <= offset => offset+w*n <= size bs =>
  mkseq (fun i => take w (drop (offset+w*i) bs)) n =
  chunk w (take (w*n) (drop offset bs)).
proof.
  move=> hw hn ho hs.
  have hz : size (take (w*n) (drop offset bs)) = w*n
    by rewrite size_take 1:/# size_drop 1://; smt().
  rewrite /chunk hz IntDiv.mulKz 1:/#.
  apply eq_in_mkseq => i hi /=.
  rewrite drop_take 1,2:/# drop_drop 1,2:/# take_take; smt().
qed.
lemma blocks_flatten w n (bs : raw_input) offset :
  0 < w => 0 <= n => 0 <= offset => offset+w*n <= size bs =>
  flatten (mkseq (fun i => take w (drop (offset+w*i) bs)) n) =
  take (w*n) (drop offset bs).
proof.
  move=> hw hn ho hs; rewrite blocks_chunk // chunkK 1://.
  + rewrite size_take 1:/# size_drop 1://; smt(IntDiv.dvdz_mulr).
  by [].
qed.
lemma slice_cat a b offset (bs : raw_input) :
  0 <= a => 0 <= b => 0 <= offset =>
  take a (drop offset bs) ++ take b (drop (offset+a) bs) =
  take (a+b) (drop offset bs).
proof.
  move=> ha hb ho; rewrite takeD // drop_drop 1,2:/#.
  congr; smt().
qed.
