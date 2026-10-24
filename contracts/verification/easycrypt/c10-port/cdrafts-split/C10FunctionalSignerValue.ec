(* Complete signer values, with zero selectors retained as exhaustion.
   Pure calls here specify values, not a count of executed hash queries. *)
require import AllCore List IntDiv.
require import C10Bytes C10RawOracle C10RawGrind C10Representation RawSigner RawLayer RawForest.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue.
require import C10FunctionalLayerSign C10FunctionalForestRecover C10FunctionalVerifierValue.
require import C10CallerInputBridge C10OuterCallerBridge C10DigestCallers.

op paired_layer_result fn key seed layer tree leaf message =
  let slot = layer_sign_slot fn seed layer tree leaf message in
  let sig = layer_sign_values fn seed key layer tree leaf message (slot-1) in
  if slot = 0 then None else Some
    (sig,layer_recover_value fn seed layer tree leaf message sig.`1 sig.`2 sig.`3).
op paired_finish_result fn key seed (randomizer : raw_input) d =
  let ht = ht_field d in
  let forest = forest_sign_value fn seed key ht (digest_fors_indices d) in
  let first = paired_layer_result fn key seed 0 (ht %/ 512) (ht %% 512) forest.`3 in
  if first = None then None else
  let second = paired_layer_result fn key seed 1 (ht %/ 512 %/ 512) (ht %/ 512 %% 512) (oget first).`2 in
  if second = None then None else Some (randomizer,forest.`1,forest.`2,[(oget first).`1;(oget second).`1]).

op functional_signer_forest f key seed d =
  forest_sign_value (interpreted_backend f) seed key (hypertree_index d) (functional_forest_indices d).
op functional_signer_layer0 f key seed d =
  functional_layer_result f key seed 0 (hypertree_index d %/ 512) (hypertree_index d %% 512)
    (functional_signer_forest f key seed d).`3.
op functional_signer_layer1 f key seed d =
  functional_layer_result f key seed 1 (hypertree_index d %/ 512 %/ 512) (hypertree_index d %/ 512 %% 512)
    (oget (functional_signer_layer0 f key seed d)).`2.
op functional_signer_current f key seed d i =
  if i = 0 then (functional_signer_forest f key seed d).`3 else
  if functional_signer_layer0 f key seed d = None then (functional_signer_forest f key seed d).`3 else
  if i = 1 \/ functional_signer_layer1 f key seed d = None then (oget (functional_signer_layer0 f key seed d)).`2
  else (oget (functional_signer_layer1 f key seed d)).`2.
op functional_signer_layers f key seed d i =
  if i = 0 \/ functional_signer_layer0 f key seed d = None then [] else
  if i = 1 \/ functional_signer_layer1 f key seed d = None then [(oget (functional_signer_layer0 f key seed d)).`1]
  else [(oget (functional_signer_layer0 f key seed d)).`1;(oget (functional_signer_layer1 f key seed d)).`1].
op functional_signer_ok f key seed d i =
  i = 0 \/ (functional_signer_layer0 f key seed d <> None /\
    (i = 1 \/ functional_signer_layer1 f key seed d <> None)).
op functional_signer_iterations f key seed d =
  if functional_signer_layer0 f key seed d = None then 1 else 2.
op functional_signer_layer f key seed d i =
  functional_layer_result f key seed i
    (functional_verifier_index (hypertree_index d) i %/ 512)
    (functional_verifier_index (hypertree_index d) i %% 512)
    (functional_signer_current f key seed d i).

lemma functional_layer_result_shared f key seed layer tree leaf message :
  functional_layer_result f key seed layer tree leaf message =
    paired_layer_result (interpreted_backend f) key seed layer tree leaf message.
proof.
  by rewrite /functional_layer_result /functional_layer_signature /paired_layer_result
    functional_layer_slot_shared.
qed.

lemma functional_signer_forest_shared f key seed d : size d = 256 =>
  functional_signer_forest f key seed d =
    forest_sign_value (interpreted_backend f) seed key (ht_field (bits_to_bytes d))
      (digest_fors_indices (bits_to_bytes d)).
proof.
  move=> hd; rewrite /functional_signer_forest (functional_digest_indices d hd) (digest_ht_field d hd); trivial.
qed.

lemma functional_signer_layer_step f key seed d i :
  0 <= i < 2 => functional_signer_ok f key seed d i =>
  let signed = functional_signer_layer f key seed d i in
  functional_signer_ok f key seed d (i+1) = (signed <> None) /\
  functional_signer_current f key seed d (i+1) =
    (if signed = None then functional_signer_current f key seed d i else (oget signed).`2) /\
  functional_signer_layers f key seed d (i+1) =
    (if signed = None then functional_signer_layers f key seed d i else
      rcons (functional_signer_layers f key seed d i) (oget signed).`1).
proof.
  move=> hi hok; have hc : i = 0 \/ i = 1 by smt().
  case: hc => he; subst i;
    move: hok; rewrite /functional_signer_layer /functional_verifier_index
      /functional_signer_current /functional_signer_layers /functional_signer_ok
      /functional_signer_layer0 /functional_signer_layer1 /=; smt().
qed.

lemma functional_signer_finish_value f key seed randomizer d i :
  size d = 256 => 0 <= i <= 2 =>
  (i = 2 \/ !functional_signer_ok f key seed d i) =>
  (i = 2 => functional_signer_layer0 f key seed d <> None) =>
  i = functional_signer_iterations f key seed d /\
  (if functional_signer_ok f key seed d i then Some
    (randomizer,(functional_signer_forest f key seed d).`1,(functional_signer_forest f key seed d).`2,
      functional_signer_layers f key seed d i) else None) =
    paired_finish_result (interpreted_backend f) key seed randomizer (bits_to_bytes d).
proof.
  move=> hd hi he hp.
  rewrite /paired_finish_result /= -(functional_signer_forest_shared f key seed d hd)
    -(digest_ht_field d hd) -!functional_layer_result_shared.
  move: he hp; rewrite /functional_signer_iterations /functional_signer_layers /functional_signer_ok
    /functional_signer_layer0 /functional_signer_layer1; smt().
qed.

lemma functional_signer_next_reachable f key seed d i :
  functional_signer_ok f key seed d i => i+1 = 2 =>
    functional_signer_layer0 f key seed d <> None.
proof. rewrite /functional_signer_ok; smt(). qed.
