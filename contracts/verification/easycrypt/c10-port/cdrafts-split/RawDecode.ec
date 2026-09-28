(* The concrete signature parser preserves every byte and enforces all widths. *)
require import AllCore List IntDiv BitEncoding Ring.
require import C10RawOracle C10Bytes RawKeygen RawLayer RawSigner RawSignature RawCodec RawSlices.
import BS2Int.

lemma count_read_range bs :
  size bs = 4 => 0 <= bs2int (bytes_to_bits bs) < 4294967296.
proof.
  move=> hs; have hp : 2^32 = 4294967296
    by rewrite (_ : 32 = 2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have hb := bs2int_le2Xs (bytes_to_bits bs).
  rewrite bytes_to_bits_size hs /= hp in hb; smt(bs2int_ge0).
qed.
lemma read_layer_width bs offset :
  0 <= offset => offset+836 <= size bs => layer_width (read_layer bs offset).
proof.
  move=> ho hs; rewrite /layer_width /read_layer /=; split.
  + apply read_nodes_width; smt().
  split; last by apply read_nodes_width; smt().
  apply count_read_range; rewrite size_take 1:// size_drop 1:/#; smt().
qed.
lemma read_layer_roundtrip bs offset :
  0 <= offset => offset+836 <= size bs =>
  all (fun b => 0 <= b < 256) bs =>
  encode_layer (read_layer bs offset) = take 836 (drop offset bs).
proof.
  move=> ho hs hb; rewrite /encode_layer /read_layer /=.
  rewrite read_nodes_flatten 1:// 1:ho 1:/# /=.
  rewrite count_bytes_roundtrip.
  + rewrite size_take 1:// size_drop 1:/#; smt().
  + apply/allP=> b hin; move: hb=>/allP; apply; smt(mem_take mem_drop).
  rewrite read_nodes_flatten 1:// 1:/# 1:/# /=.
  rewrite (slice_cat 688 4 offset bs) 1..3:/# /=.
  by rewrite (slice_cat 692 144 offset bs) 1..3:/#.
qed.
lemma decoded_signature_width bs :
  size bs = 4008 => signature_width (decode_signature bs).
proof.
  move=> hs; rewrite /signature_width /decode_signature /= !size_mkseq /max /=.
  split; first by rewrite size_take 1:// hs.
  split; first by apply read_nodes_width; smt().
  split.
  + apply/allP=> row /mapP [i [hi ->]]; move: hi; rewrite mem_iota => hi /=.
    apply read_nodes_width; smt().
  apply/allP=> sig /mapP [i [hi ->]]; move: hi; rewrite mem_iota => hi /=.
  apply read_layer_width; smt().
qed.
lemma signature_bytes_roundtrip bs :
  size bs = 4008 => all (fun b => 0 <= b < 256) bs =>
  encode_signature (decode_signature bs) = bs.
proof.
  move=> hs hb; rewrite /encode_signature /decode_signature /=.
  rewrite read_nodes_flatten 1:// 1:// 1:/# /=.
  have ha : map flatten (mkseq (fun t => read_nodes 11 bs (224+176*t)) 12) =
    mkseq (fun t => take 176 (drop (224+176*t) bs)) 12.
  + rewrite -map_comp; apply eq_in_mkseq=> t ht; rewrite /(\o) /=.
    by rewrite read_nodes_flatten 1:// 1:/# 1:/#.
  have hl : map encode_layer (mkseq (fun l => read_layer bs (2336+836*l)) 2) =
    mkseq (fun l => take 836 (drop (2336+836*l) bs)) 2.
  + rewrite -map_comp; apply eq_in_mkseq=> l hl; rewrite /(\o) /=.
    by apply read_layer_roundtrip; smt().
  rewrite ha hl !blocks_flatten 1..8:/# /=.
  rewrite -{1}(drop0 bs) (slice_cat 16 208 0 bs) 1..3:// /=.
  rewrite (slice_cat 224 2112 0 bs) 1..3:// /=.
  rewrite (slice_cat 2336 1672 0 bs) 1..3:// /= drop0.
  by rewrite -hs take_size.
qed.
