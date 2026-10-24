(* Values and digest-bound discharge for complete verifier composition.
   The fixed backend and paired-printer interpretation are explicit. *)
require import AllCore List IntDiv.
require import C10Representation C10RawOracle C10RawGrind RawSigner RawLayer RawForest SignerCoordinates.
require import C10FixedBackend C10FixedCallerBridge C10DigestCallers.
require import C10Bytes ShuffleBytes C10CallerInputBridge C10OuterCallerBridge.
require import C10FunctionalWotsValue C10FunctionalForestRecover C10FunctionalLayerRecover.

op functional_verifier_query seed root message (sig : raw_signature) =
  hmsg_preimage seed root (pad_node sig.`1) message.
op functional_verifier_layer (sig : raw_signature) i = nth ([],0,[]) sig.`4 i.
op functional_verifier_forest f seed d (sig : raw_signature) =
  digest_forest_value (interpreted_backend f) seed (bits_to_bytes d) sig.`2 sig.`3.
op functional_verifier_root f seed d (sig : raw_signature) i =
  let first = functional_verifier_layer sig 0 in
  let second = functional_verifier_layer sig 1 in
  if i = 0 then functional_verifier_forest f seed d sig else
  if i = 1 then hypertree_first_value (interpreted_backend f) seed (ht_field (bits_to_bytes d))
    (functional_verifier_forest f seed d sig) first.`1 first.`2 first.`3 else
  verifier_recover_value (interpreted_backend f) seed (bits_to_bytes d) sig.`2 sig.`3
    first.`1 first.`2 first.`3 second.`1 second.`2 second.`3.
op functional_verifier_index ht i =
  if i = 0 then ht else if i = 1 then ht %/ 512 else ht %/ 512 %/ 512.

lemma functional_verifier_digest f seed root message (sig : raw_signature) :
  bits_to_bytes (f (functional_verifier_query seed root message sig)) =
    verifier_digest (interpreted_backend f) seed root sig.`1 message.
proof. by rewrite /functional_verifier_query /verifier_digest /interpreted_backend. qed.

lemma functional_digest_indices d : size d = 256 =>
  functional_forest_indices d = digest_fors_indices (bits_to_bytes d).
proof.
  move=> hd; rewrite /functional_forest_indices /digest_fors_indices.
  apply eq_in_mkseq => i hi; apply digest_fors_field => //; smt().
qed.

lemma functional_verifier_forest_value f seed d (sig : raw_signature) : size d = 256 =>
  forest_recover_value (interpreted_backend f) seed (hypertree_index d)
    (functional_forest_indices d) sig.`2 sig.`3 = functional_verifier_forest f seed d sig.
proof.
  move=> hd; rewrite (functional_digest_indices d hd) (digest_ht_field d hd)
    /functional_verifier_forest /digest_forest_value; trivial.
qed.

lemma functional_verifier_index_step ht i : 0 <= i < 2 =>
  functional_verifier_index ht (i+1) = functional_verifier_index ht i %/ 512.
proof.
  move=> hi; have hc : i = 0 \/ i = 1 by smt().
  case: hc => ->; by rewrite /functional_verifier_index /=.
qed.

lemma functional_verifier_layer_step f seed d (sig : raw_signature) i :
  size d = 256 => 0 <= i < 2 =>
  let idx = functional_verifier_index (hypertree_index d) i in
  let layer = functional_verifier_layer sig i in
  layer_recover_value (interpreted_backend f) seed i (idx %/ 512) (idx %% 512)
    (functional_verifier_root f seed d sig i) layer.`1 layer.`2 layer.`3 =
    functional_verifier_root f seed d sig (i+1).
proof.
  move=> hd hi; have hc : i = 0 \/ i = 1 by smt().
  case: hc => ->; rewrite /functional_verifier_index /functional_verifier_root /=
    /verifier_recover_value /hypertree_recover_value /hypertree_first_value
    /functional_verifier_forest (digest_ht_field d hd); trivial.
qed.

lemma functional_verifier_coordinates d i : size d = 256 => 0 <= i < 2 =>
  let idx = functional_verifier_index (hypertree_index d) i in
  caller_fields i (idx %/ 512) (idx %% 512).
proof.
  move=> hd hi; have hh := hypertree_index_range d.
  have hc : i = 0 \/ i = 1 by smt().
  case: hc => ->; rewrite /functional_verifier_index /=.
  + have he := outer_coordinates 0 (hypertree_index d) _ hh; first smt().
    smt().
  have he := outer_coordinates 0 (hypertree_index d) _ hh; first smt().
  have he' := outer_coordinates 1 (hypertree_index d %/ 512) _ _; smt().
qed.
