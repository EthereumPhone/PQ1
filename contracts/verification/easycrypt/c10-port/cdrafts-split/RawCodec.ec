(* Layout slicing/assembly lemmas for the exact byte-signature adapter. *)
require import AllCore List IntDiv BitEncoding.
require import C10RawOracle C10Bytes RawKeygen RawLayer RawSigner RawSignature.
import BS2Int BitChunking.

lemma read_nodes_chunk n bs offset :
  0 <= n => 0 <= offset => offset+16*n <= size bs =>
  read_nodes n bs offset = chunk 16 (take (16*n) (drop offset bs)).
proof.
  move=> hn ho hs.
  have hw : size (take (16*n) (drop offset bs)) = 16*n
    by rewrite size_take 1:/# size_drop 1://; smt().
  rewrite /read_nodes /chunk hw IntDiv.mulKz 1://.
  apply eq_in_mkseq => i hi /=.
  rewrite drop_take 1,2:/# drop_drop 1,2:/# take_take.
  smt().
qed.
lemma read_nodes_flatten n bs offset :
  0 <= n => 0 <= offset => offset+16*n <= size bs =>
  flatten (read_nodes n bs offset) = take (16*n) (drop offset bs).
proof.
  move=> hn ho hs; rewrite read_nodes_chunk // chunkK 1://.
  + rewrite size_take 1:/# size_drop 1://; smt(IntDiv.dvdz_mulr).
  by [].
qed.
lemma read_nodes_width n bs offset :
  0 <= n => 0 <= offset => offset+16*n <= size bs =>
  rows_width n (read_nodes n bs offset).
proof.
  move=> hn ho hs; rewrite /rows_width /read_nodes size_mkseq; split; first smt().
  apply/allP=> row /mapP [i [hi ->]]; move: hi; rewrite mem_iota => hi /=.
  rewrite size_take 1:// size_drop 1:/#; smt().
qed.

lemma count_bytes_roundtrip bs :
  size bs = 4 => all (fun b => 0 <= b < 256) bs =>
  be 4 (bs2int (bytes_to_bits bs)) = bs.
proof.
  move=> hs hb; rewrite /be (_: 8*4 = size (bytes_to_bits bs))
    1:bytes_to_bits_size 1:hs 1:// bs2intK.
  exact (bytes_bits_roundtrip bs hb).
qed.
