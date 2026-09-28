(* Exact component windows in the deployed 4008-byte signature layout. *)
require import AllCore List IntDiv.
require import C10RawOracle RawLayer RawSigner RawSignature EncodedSlices.

lemma encoded_signature_windows (sig : raw_signature) : signature_width sig =>
  take 16 (encode_signature sig)=sig.`1 /\
  take 208 (drop 16 (encode_signature sig))=flatten sig.`2 /\
  take 2112 (drop 224 (encode_signature sig))=flatten (map flatten sig.`3) /\
  take 1672 (drop 2336 (encode_signature sig))=flatten (map encode_layer sig.`4).
proof.
  rewrite /signature_width; move=> [hr [hs [hna [ha [hnl hl]]]]].
  have hfs : size (flatten sig.`2)=208 by exact (rows_flatten_width 13 sig.`2 hs).
  have hpa : size (flatten (map flatten sig.`3))=2112.
  + rewrite (size_flatten_ctt 176).
    - move=> x /mapP [row [hin ->]]; apply (rows_flatten_width 11); smt(allP).
    rewrite size_map hna; smt().
  have hpl : size (flatten (map encode_layer sig.`4))=1672.
  + rewrite (size_flatten_ctt 836).
    - move=> x /mapP [row [hin ->]]; apply encoded_layer_width; smt(allP).
    rewrite size_map hnl; smt().
  have h1 := slice_body [] sig.`1 (flatten sig.`2 ++ flatten (map flatten sig.`3) ++ flatten (map encode_layer sig.`4)).
  have h2 := slice_body sig.`1 (flatten sig.`2) (flatten (map flatten sig.`3) ++ flatten (map encode_layer sig.`4)).
  have h3 := slice_body (sig.`1 ++ flatten sig.`2) (flatten (map flatten sig.`3)) (flatten (map encode_layer sig.`4)).
  have h4 := slice_body (sig.`1 ++ flatten sig.`2 ++ flatten (map flatten sig.`3)) (flatten (map encode_layer sig.`4)) [].
  move: h1 h2 h3 h4; rewrite /= drop0 !cats0 !size_cat hr hfs hpa hpl /= !catA /encode_signature; smt().
qed.

lemma encoded_auth_window (sig : raw_signature) t :
  signature_width sig => 0<=t<12 =>
  take 176 (drop (224+176*t) (encode_signature sig))=flatten (nth [] sig.`3 t).
proof.
  move=> hw ht; have [_ [_ [ha _]]] := encoded_signature_windows sig hw.
  have hn : size sig.`3=12 by move: hw; rewrite /signature_width; smt().
  have hb : all (fun (x : raw_input) => size x=176) (map flatten sig.`3).
  + apply/allP=> x /mapP [row [hin ->]]; apply (rows_flatten_width 11).
    move: hw; rewrite /signature_width; smt(allP).
  have h := flat_block 176 (map flatten sig.`3) t _ hb _.
  + smt().
  + rewrite size_map hn; smt().
  have he : take 176 (drop (176*t) (take 2112 (drop 224 (encode_signature sig))))=
    take 176 (drop (224+176*t) (encode_signature sig)) by apply slice_inside; smt().
  move: h he; rewrite ha (nth_map [] []) 1:/# /=; smt().
qed.

lemma encoded_layer_window (sig : raw_signature) i :
  signature_width sig => 0<=i<2 =>
  take 836 (drop (2336+836*i) (encode_signature sig))=encode_layer (nth ([],0,[]) sig.`4 i).
proof.
  move=> hw hi; have [_ [_ [_ hl]]] := encoded_signature_windows sig hw.
  have hn : size sig.`4=2 by move: hw; rewrite /signature_width; smt().
  have hb : all (fun (x : raw_input) => size x=836) (map encode_layer sig.`4).
  + apply/allP=> x /mapP [row [hin ->]]; apply encoded_layer_width.
    move: hw; rewrite /signature_width; smt(allP).
  have h := flat_block 836 (map encode_layer sig.`4) i _ hb _.
  + smt().
  + rewrite size_map hn; smt().
  have he : take 836 (drop (836*i) (take 1672 (drop 2336 (encode_signature sig))))=
    take 836 (drop (2336+836*i) (encode_signature sig)) by apply slice_inside; smt().
  move: h he; rewrite hl (nth_map ([],0,[]) []) 1:/# /=; smt().
qed.
