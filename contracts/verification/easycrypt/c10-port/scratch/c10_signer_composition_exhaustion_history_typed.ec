require import AllCore List IntDiv C10Bytes C10RawOracle C10RawGrind C10Representation RawSigner RawLayer RawForest C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue C10FunctionalLayerSign C10FunctionalForestRecover C10FunctionalVerifierValue C10CallerInputBridge C10OuterCallerBridge C10DigestCallers FMap C10FunctionalForestSign C10FunctionalBuildHistory C10FunctionalMerkleBuildHistory KeygenPrefixes SignerCoordinates RoleGrind RawSignature C10Counter C10SearchAcceptance C10FunctionalFors C10FunctionalSearch C10FunctionalSignerHeader.

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

op functional_signer_step_cost f key seed d shuffle i =
  functional_layer_sign_cost f key seed i
    (functional_verifier_index (hypertree_index d) i %/ 512)
    (functional_verifier_index (hypertree_index d) i %% 512)
    (functional_signer_current f key seed d i) shuffle.

op functional_signer_layers_cost f key seed d shuffle n =
  if n = 0 then 0 else functional_signer_step_cost f key seed d shuffle 0 +
    (if n = 1 then 0 else functional_signer_step_cost f key seed d shuffle 1).

op functional_signer_step_state f initial final key seed d shuffle i =
  let idx = functional_verifier_index (hypertree_index d) i in
  exists built, functional_history_exact f initial built
    (functional_tree_queried (functional_merkle_build_queries f key seed i (idx %/ 512)) 9) /\
    final = functional_layer_sign_history f built key seed i (idx %/ 512) (idx %% 512)
      (functional_signer_current f key seed d i) shuffle.

op functional_signer_layers_state f initial final key seed d shuffle n =
  exists (histories : int -> (raw_input,digest) fmap),
    histories 0 = initial /\ histories n = final /\
    forall i, 0 <= i < n =>
      functional_signer_step_state f (histories i) (histories (i+1)) key seed d shuffle i.

op functional_finish_cost f key seed d shuffle =
  functional_forest_initial_cost f shuffle + 80017 +
    functional_signer_layers_cost f key seed d shuffle (functional_signer_iterations f key seed d).

op functional_finish_state f initial final key seed d shuffle =
  exists forest, functional_forest_sign_state f initial forest key seed (hypertree_index d) d shuffle /\
    functional_signer_layers_state f forest final key seed d shuffle (functional_signer_iterations f key seed d).

op paired_signer_result fn key seed root random message =
  let slot = signer_nonce_slot fn seed root key random message in
  if slot = 0 then None else
    paired_finish_result fn key seed (signer_randomizer fn key random message (slot-1))
      (signer_digest fn seed root key random message (slot-1)).

op functional_signer_digest f key seed root random message =
  f (functional_fors_query f key random message seed root
    (functional_header_slot f key seed root random message-1)).

op functional_signer_cost f key seed root random message shuffle =
  2 * functional_header_steps f key seed root random message +
    (if functional_header_slot f key seed root random message = 0 then 0 else
      functional_finish_cost f key seed (functional_signer_digest f key seed root random message) shuffle).

op functional_signer_state f h final key seed root random message shuffle =
  let searched = functional_fors_history f h key random message seed root
    (functional_header_steps f key seed root random message) in
  if functional_header_slot f key seed root random message = 0 then final = h else
    functional_finish_state f searched final key seed (functional_signer_digest f key seed root random message) shuffle.
