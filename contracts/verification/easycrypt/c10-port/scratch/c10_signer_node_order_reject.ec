require import AllCore List IntDiv.
require import C10RawOracle RawLayer RawSigner RawSignature.
require import C10Representation C10AddressInputBridge C10CallerInputBridge.

op nodes_bytes (values : ((int list) list)) : (int list) =
  (foldr (fun value tail => (tail ++ value)) [] values).

op layer_bytes (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  ((nodes_bytes values) ++ (u32_bytes nonce) ++ (nodes_bytes auth)).

op signature_bytes (random : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) (values0 : ((int list) list)) (nonce0 : int) (auth0 : ((int list) list)) (values1 : ((int list) list)) (nonce1 : int) (auth1 : ((int list) list)) : (int list) =
  (random ++ (nodes_bytes forest_secrets) ++ (foldr (fun path_row tail => ((nodes_bytes path_row) ++ tail)) [] forest_paths) ++ (layer_bytes values0 nonce0 auth0) ++ (layer_bytes values1 nonce1 auth1)).


(* The common byte expression is the actual native signature encoder, including
   every byte of both u32 counters. Width is discharged by the caller separately. *)




op paired_signature_bytes (sig : raw_signature) =
  let first = nth ([],0,[]) sig.`4 0 in
  let second = nth ([],0,[]) sig.`4 1 in
  signature_bytes sig.`1 sig.`2 sig.`3
    first.`1 first.`2 first.`3 second.`1 second.`2 second.`3.

lemma nodes_bytes_flatten rows : nodes_bytes rows = flatten rows.
proof. by rewrite /nodes_bytes /flatten. qed.

lemma paths_bytes_flatten rows :
  foldr (fun row tail => nodes_bytes row ++ tail) [] rows = flatten (map flatten rows).
proof. by elim rows => [|row rows ih] //=; rewrite nodes_bytes_flatten ih. qed.

lemma layer_bytes_encoder sig : layer_width sig =>
  layer_bytes sig.`1 sig.`2 sig.`3 = encode_layer sig.
proof.
  rewrite /layer_width => [#] hw hc0 hc1 ha.
  have hc : 0 <= sig.`2 < 2^32 by rewrite caller_u32_size; smt().
  by rewrite /layer_bytes /encode_layer !nodes_bytes_flatten (be4_common sig.`2 hc).
qed.

lemma signature_bytes_encoder sig : signature_width sig =>
  paired_signature_bytes sig = encode_signature sig.
proof.
  rewrite /signature_width => [#] hr hs hpa ha hl hls.
  have he : sig.`4 = [nth ([],0,[]) sig.`4 0;nth ([],0,[]) sig.`4 1].
  + apply (eq_from_nth ([],0,[])); first by rewrite /= hl.
    move=> i hi; have hc : i = 0 \/ i = 1 by smt().
    by case: hc => -> /=.
  have hw0 : layer_width (nth ([],0,[]) sig.`4 0) by smt(allP mem_nth).
  have hw1 : layer_width (nth ([],0,[]) sig.`4 1) by smt(allP mem_nth).
  by rewrite /paired_signature_bytes /signature_bytes /encode_signature /=
    !nodes_bytes_flatten paths_bytes_flatten
    (layer_bytes_encoder _ hw0) (layer_bytes_encoder _ hw1) he /=
    !flatten_cons flatten_nil /= /encode_layer !catA cats0.
qed.

lemma paired_signature_bytes_width sig : signature_width sig =>
  size (paired_signature_bytes sig) = 4008.
proof. move=> hw; rewrite (signature_bytes_encoder sig hw); exact (encoded_signature_width sig hw). qed.
