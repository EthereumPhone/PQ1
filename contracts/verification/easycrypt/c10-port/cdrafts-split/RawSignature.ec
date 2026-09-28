(* Fixed 4008-byte layout; width accounting for the structured signature. *)
require import AllCore List IntDiv BitEncoding.
require import C10RawOracle C10Bytes RawKeygen RawLayer RawSigner.
import BS2Int.

op rows_width n (rows : raw_input list) =
  size rows = n /\ all (fun (x : raw_input) => size x = 16) rows.
op layer_width (sig : layer_signature) =
  rows_width 43 sig.`1 /\ 0 <= sig.`2 < 4294967296 /\ rows_width 9 sig.`3.
op signature_width (sig : raw_signature) =
  size sig.`1 = 16 /\ rows_width 13 sig.`2 /\
  size sig.`3 = 12 /\ all (rows_width 11) sig.`3 /\
  size sig.`4 = 2 /\ all layer_width sig.`4.
op encode_layer (sig : layer_signature) =
  flatten sig.`1 ++ be 4 sig.`2 ++ flatten sig.`3.
op encode_signature (sig : raw_signature) =
  sig.`1 ++ flatten sig.`2 ++ flatten (map flatten sig.`3) ++ flatten (map encode_layer sig.`4).

op read_nodes n (bytes : raw_input) offset =
  mkseq (fun i => take 16 (drop (offset+16*i) bytes)) n.
op read_layer (bytes : raw_input) offset : layer_signature =
  (read_nodes 43 bytes offset,
   bs2int (bytes_to_bits (take 4 (drop (offset+688) bytes))),
   read_nodes 9 bytes (offset+692)).
op decode_signature (bytes : raw_input) : raw_signature =
  (take 16 bytes, read_nodes 13 bytes 16,
   mkseq (fun t => read_nodes 11 bytes (224+176*t)) 12,
   mkseq (fun l => read_layer bytes (2336+836*l)) 2).

lemma be_width n x : 0 <= n => size (be n x) = n.
proof. move=> hn; rewrite /be bits_to_bytes_size size_int2bs; smt(IntDiv.mulzK). qed.
lemma rows_flatten_width n rows : rows_width n rows => size (flatten rows) = 16*n.
proof.
  rewrite /rows_width => [#] hs ha; rewrite (size_flatten_ctt 16).
  + by move: ha=> /allP; apply.
  by rewrite hs; ring.
qed.
lemma encoded_layer_width sig : layer_width sig => size (encode_layer sig) = 836.
proof.
  rewrite /layer_width => [#] hw hc0 hc1 ha.
  rewrite /encode_layer !size_cat be_width 1:// (rows_flatten_width 43 _ hw) (rows_flatten_width 9 _ ha); smt().
qed.
lemma encoded_signature_width sig : signature_width sig => size (encode_signature sig) = 4008.
proof.
  rewrite /signature_width => [#] hr hs hna ha hnl hl.
  have hpa : size (flatten (map flatten sig.`3)) = 2112.
  + rewrite (size_flatten_ctt 176).
    - move=> x /mapP [row [hin ->]].
      have hw : rows_width 11 row by move: ha=> /allP; apply.
      by rewrite (rows_flatten_width 11 _ hw).
    by rewrite size_map hna.
  have hpl : size (flatten (map encode_layer sig.`4)) = 1672.
  + rewrite (size_flatten_ctt 836).
    - move=> x /mapP [s [hin ->]]; apply encoded_layer_width.
      by move: hl=> /allP; apply.
    by rewrite size_map hnl.
  rewrite /encode_signature !size_cat hr (rows_flatten_width 13 _ hs) hpa hpl; smt().
qed.
