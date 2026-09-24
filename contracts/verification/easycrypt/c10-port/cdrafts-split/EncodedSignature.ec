(* Encoding a well-shaped structured signature and parsing it is identity. *)
require import AllCore List IntDiv.
require import C10RawOracle RawLayer RawSigner RawSignature.
require import EncodedSlices EncodedLayer EncodedSignatureSlices.

lemma read_nodes_window n bs offset : 0<=n => 0<=offset =>
  read_nodes n (take (16*n) (drop offset bs)) 0=read_nodes n bs offset.
proof.
  move=> hn ho; have h := read_nodes_slice n (16*n) offset 0 bs hn _ _ ho.
  + smt().
  + smt().
  move: h; rewrite /=; smt().
qed.
lemma read_nodes_flatten_identity n rows : rows_width n rows => read_nodes n (flatten rows) 0=rows.
proof.
  move=> hw; have h := read_nodes_body n rows [] [] hw.
  move: h; rewrite /= cats0; smt().
qed.

lemma signature_encoding_roundtrip (sig : raw_signature) :
  signature_width sig => decode_signature (encode_signature sig)=sig.
proof.
  move=> hw; have [hr [hs [ha hl]]] := encoded_signature_windows sig hw.
  have hsw : rows_width 13 sig.`2 by move: hw; rewrite /signature_width; smt().
  have [han haa] : size sig.`3=12 /\ all (rows_width 11) sig.`3 by move: hw; rewrite /signature_width; smt().
  have [hln hla] : size sig.`4=2 /\ all layer_width sig.`4 by move: hw; rewrite /signature_width; smt().
  have hsecrets : read_nodes 13 (encode_signature sig) 16=sig.`2.
  + rewrite -(read_nodes_window 13 (encode_signature sig) 16) 1,2:// /= hs.
    exact (read_nodes_flatten_identity 13 sig.`2 hsw).
  have hauth : mkseq (fun t => read_nodes 11 (encode_signature sig) (224+176*t)) 12=sig.`3.
  + rewrite -{1}(mkseq_nth [] sig.`3) han.
    apply eq_in_mkseq => t ht /=.
    rewrite -(read_nodes_window 11 (encode_signature sig) (224+176*t)) 1,2:/# /=.
    rewrite (encoded_auth_window sig t hw ht); apply read_nodes_flatten_identity.
    smt(allP mem_nth).
  have hlayers : mkseq (fun i => read_layer (encode_signature sig) (2336+836*i)) 2=sig.`4.
  + rewrite -{1}(mkseq_nth ([],0,[]) sig.`4) hln.
    apply eq_in_mkseq => i hi /=.
    rewrite -(read_layer_slice (encode_signature sig) (2336+836*i)) 1:/#.
    rewrite (encoded_layer_window sig i hw hi); apply layer_encoding_roundtrip.
    smt(allP mem_nth).
  rewrite /decode_signature hr hsecrets hauth hlayers; smt().
qed.
