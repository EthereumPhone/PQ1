(* The exact 836-byte layer encoding parses back to the same signature. *)
require import AllCore List IntDiv BitEncoding Ring.
require import C10RawOracle C10Bytes RawKeygen RawLayer RawSigner RawSignature EncodedSlices.
import BS2Int.

lemma encoded_count_value c :
  0<=c<4294967296 => bs2int (bytes_to_bits (be 4 c))=c.
proof.
  move=> hc; have hpow : 2^32=4294967296 by rewrite (_:32=2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  rewrite /be bits_bytes_roundtrip 1:size_int2bs 1:// int2bsK 1://; smt().
qed.

lemma read_layer_slice bs offset :
  0<=offset => read_layer (take 836 (drop offset bs)) 0=read_layer bs offset.
proof.
  move=> ho; rewrite /read_layer /= (read_nodes_slice 43 836 offset 0 bs) 1..4:/# /=.
  rewrite (read_nodes_slice 9 836 offset 692 bs) 1..4:/#.
  by rewrite (slice_inside 4 836 offset 688 bs) 1..4:/#.
qed.

lemma layer_encoding_roundtrip (sig : layer_signature) :
  layer_width sig => read_layer (encode_layer sig) 0=sig.
proof.
  move=> [hw [hc ha]].
  have hsw : size (flatten sig.`1)=688 by exact (rows_flatten_width 43 sig.`1 hw).
  have hsa : size (flatten sig.`3)=144 by exact (rows_flatten_width 9 sig.`3 ha).
  have hbe : size (be 4 sig.`2)=4 by apply be_width; smt().
  have hf : read_nodes 43 (encode_layer sig) 0=sig.`1.
  + have h := read_nodes_body 43 sig.`1 [] (be 4 sig.`2 ++ flatten sig.`3) hw.
    move: h; rewrite /= catA /encode_layer; smt().
  have hb : take 4 (drop 688 (encode_layer sig))=be 4 sig.`2.
  + have h := slice_body (flatten sig.`1) (be 4 sig.`2) (flatten sig.`3).
    move: h; rewrite hsw hbe /encode_layer; smt().
  have hauth : read_nodes 9 (encode_layer sig) 692=sig.`3.
  + have h := read_nodes_body 9 sig.`3 (flatten sig.`1 ++ be 4 sig.`2) [] ha.
    move: h; rewrite cats0 size_cat hsw hbe /= /encode_layer; smt().
  rewrite /read_layer /= hf hb hauth encoded_count_value 1:hc; smt().
qed.
