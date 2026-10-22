(* Pure WOTS values under the disclosed deterministic backend interpretation.
   These laws do not identify that function with the sampled Shared oracle. *)
require import AllCore List BitEncoding.
require import C10Bytes C10RawOracle C10RawGrind C10Randomizer RawKeygen.
require import C10Representation C10AddressInputBridge C10CallerInputBridge.
require import C10FixedCallerBridge.
require import C10RepresentationBridge ShuffleBytes RadixEncoding.
import BitChunking.

op interpreted_backend (f : raw_input -> digest) (x : raw_input) = bits_to_bytes (f x).

lemma functional_digest_width f x : backend_width f => size (f x) = 256.
proof. by rewrite /backend_width; smt(). qed.

lemma interpreted_backend_width f x : backend_width f => size (interpreted_backend f x) = 32.
proof. by move=> hf; rewrite /interpreted_backend bits_to_bytes_size; move: hf; rewrite /backend_width; smt(). qed.

lemma node_bytes_common d : size d = 256 => node d = take 16 (bits_to_bytes d).
proof.
  move=> hd.
  have hlo : size (take 128 d) = 128 by rewrite size_take 1:// hd.
  have hhi : size (bits_to_bytes (drop 128 d)) = 16
    by rewrite bits_to_bytes_size size_drop 1:// hd.
  have hcat : bits_to_bytes d = bits_to_bytes (drop 128 d) ++ bits_to_bytes (take 128 d).
  + rewrite -{1}(cat_take_drop 128 d) /bits_to_bytes chunk_cat 1:hlo 1://.
    by rewrite map_cat rev_cat.
  by rewrite (node_exact d hd) /compact_r /truncate_r hcat take_cat hhi /= take0 cats0.
qed.

lemma functional_digit_bits d i : size d = 256 => 0 <= i < 43 =>
  digit 3 d i = wots_field (bits_to_bytes d) i.
proof.
  move=> hd hi.
  have hb := shuffle_bytes_valid d.
  have hs : size (bits_to_bytes d) = 32 by rewrite bits_to_bytes_size hd.
  have he := wots_common (bits_to_bytes d) i hs hi hb.
  by move: he; rewrite bits_bytes_roundtrip 1:hd.
qed.

lemma interpreted_node f x : backend_width f =>
  node (f x) = hash_bytes_node (interpreted_backend f) x.
proof. move=> hf; rewrite /hash_bytes_node /interpreted_backend; apply node_bytes_common; move: hf; rewrite /backend_width; smt(). qed.

lemma functional_chain_fold f seed adr value start steps :
  wots_chain_value f seed adr value start steps =
    foldl (fun current i => hash_bytes_node f
      (th_preimage seed (chain_position_words adr (start+i)) (pad_node current)))
      value (mkseq (fun i => i) steps).
proof. by rewrite /wots_chain_value -foldl_rev revK. qed.

lemma functional_chain_zero f seed adr value start :
  wots_chain_value f seed adr value start 0 = value.
proof. by rewrite functional_chain_fold mkseq0. qed.

lemma functional_chain_next f seed adr value start n : 0 <= n =>
  wots_chain_value f seed adr value start (n+1) =
    hash_bytes_node f (th_preimage seed (chain_position_words adr (start+n))
      (pad_node (wots_chain_value f seed adr value start n))).
proof. by move=> hn; rewrite !functional_chain_fold mkseqS 1:hn foldl_rcons. qed.

lemma functional_chain_address layer tree kp index pos :
  caller_fields layer tree kp => 0 <= index < 2^32 => 0 <= pos < 2^32 =>
  chain_position_words (address_words layer tree 0 kp index 0 0) pos =
    address_words layer tree 0 kp index pos 0.
proof.
  move=> [hl [ht hk]] hi hp.
  have hz : 0 <= 0 < 2^32 by rewrite caller_u32_size.
  by rewrite -(address_common layer tree 0 kp index 0 0 hl ht hz hk hi hz hz)
    (chain_position_common layer tree 0 kp index 0 0 pos hp)
    (address_common layer tree 0 kp index pos 0 hl ht hz hk hi hp hz).
qed.
