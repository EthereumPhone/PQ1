(* Layer signing retains construction and shuffle effects even on exhaustion.
   The intermediate construction map is specified pointwise, not assumed. *)
require import AllCore List FMap.
require import C10Bytes C10RawOracle C10RawGrind RawLayer KeygenPrefixes C10Representation.
require import C10CallerInputBridge C10PrivateCallerBridge C10TreeCallerBridge C10OuterCallerBridge.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalWots C10FunctionalWotsValue.
require import C10FunctionalWotsSign C10FunctionalLayerRecover C10FunctionalBuildHistory.
require import C10FunctionalMerkleBuildHistory C10FunctionalCallerState C10FunctionalCallerShuffle.
require import C10FunctionalBuildContracts.

op functional_layer_signature f key seed layer tree leaf message =
  layer_sign_values (interpreted_backend f) seed key layer tree leaf message
    (functional_sign_slot f seed layer tree leaf message - 1).
op functional_layer_result f key seed layer tree leaf message =
  let sig = functional_layer_signature f key seed layer tree leaf message in
  if functional_sign_slot f seed layer tree leaf message = 0 then None else Some
    (sig,layer_recover_value (interpreted_backend f) seed layer tree leaf message sig.`1 sig.`2 sig.`3).
op functional_layer_after_search f built key seed layer tree leaf message shuffle =
  functional_sign_history f (functional_derive_history f built shuffle (shuffle_layer_label layer))
    key seed layer tree leaf message (functional_derived_seed f shuffle (shuffle_layer_label layer)).
op functional_layer_sign_history f built key seed layer tree leaf message shuffle =
  let h = functional_layer_after_search f built key seed layer tree leaf message shuffle in
  if functional_sign_slot f seed layer tree leaf message = 0 then h else
    functional_layer_recovery_history f h seed layer tree leaf message
      (functional_layer_signature f key seed layer tree leaf message).
op functional_layer_sign_cost f key seed layer tree leaf message shuffle =
  177151 + functional_derive_cost shuffle +
    functional_sign_cost f seed layer tree leaf message (functional_derived_seed f shuffle (shuffle_layer_label layer)) +
    (if functional_sign_slot f seed layer tree leaf message = 0 then 0 else
      functional_layer_recovery_cost f seed layer tree leaf message
        (functional_layer_signature f key seed layer tree leaf message)).

lemma functional_layer_slot_shared f seed layer tree leaf message :
  functional_sign_slot f seed layer tree leaf message =
    layer_sign_slot (interpreted_backend f) seed layer tree leaf message.
proof.
  by rewrite /functional_sign_slot /functional_wots_digests /functional_wots_query /signing_budget
    /layer_sign_slot /wots_search_digests /interpreted_backend.
qed.

lemma functional_layer_exhausted_cost f key seed layer tree leaf message shuffle :
  functional_sign_slot f seed layer tree leaf message = 0 =>
  functional_layer_sign_cost f key seed layer tree leaf message shuffle =
    10177151 + functional_derive_cost shuffle.
proof.
  move=> hs; rewrite /functional_layer_sign_cost /functional_sign_cost /functional_sign_search_steps
    /signing_budget; smt().
qed.

lemma fixed_functional_layer_sign_lossless : islossless CommonInputLayer(FixedPrefix).sign.
proof.
  proc; seq 3 : true 1%r 1%r 0%r 0%r => //.
  + call fixed_functional_sign_lossless; call fixed_functional_derive_lossless.
    call common_functional_merkle_build_lossless; auto.
  sp 1; if; auto; wp; call fixed_functional_layer_recover_lossless; auto.
qed.

lemma raw_functional_layer_sign_lossless : islossless RawLayer(PreparationView(FixedPrefix)).sign.
proof.
  apply (layer_sign_lossless (PreparationView(FixedPrefix)) fixed_hash_ll).
  proc; call fixed_derive_ll; auto.
qed.

lemma functional_layer_payload f key seed layer tree leaf message :
  functional_sign_slot f seed layer tree leaf message <> 0 =>
  let signed = oget (functional_sign_result f key seed layer tree leaf message) in
  (signed.`1,signed.`2,merkle_auth_values (interpreted_backend f) seed key layer tree leaf) =
    functional_layer_signature f key seed layer tree leaf message.
proof.
  move=> hs; rewrite /functional_sign_result.
  case (functional_sign_slot f seed layer tree leaf message = 0) => hslot /=; first smt().
  rewrite /functional_layer_signature /layer_sign_values
    /functional_sign_digest /functional_wots_query /interpreted_backend; smt().
qed.

lemma functional_layer_sign_failure f key seed layer tree leaf message :
  functional_sign_result f key seed layer tree leaf message = None <=>
    functional_sign_slot f seed layer tree leaf message = 0.
proof. rewrite /functional_sign_result; smt(). qed.

lemma fixed_functional_layer_sign f h c key0 seed0 layer0 tree0 leaf0 message0 shuffle0 :
  hoare[CommonInputLayer(FixedPrefix).sign :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\
    message = message0 /\ shuffle = shuffle0 /\ caller_fields layer0 tree0 leaf0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_layer_result f key0 seed0 layer0 tree0 leaf0 message0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c + functional_layer_sign_cost f key0 seed0 layer0 tree0 leaf0 message0 shuffle0 /\
    exists built, functional_history_exact f h built
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
      FixedBackend.history = functional_layer_sign_history f built key0 seed0 layer0 tree0 leaf0 message0 shuffle0].
proof.
  proc; seq 1 : (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\
    message = message0 /\ shuffle = shuffle0 /\ caller_fields layer0 tree0 leaf0 /\ backend_width f /\
    built = merkle_build_value (interpreted_backend f) seed0 key0 layer0 tree0 leaf0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151 /\ functional_history_exact f h FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9)).
  + call (common_functional_merkle_build f h c key0 seed0 layer0 tree0 leaf0).
    auto; rewrite /caller_fields /tree_fields; smt().
  exists* FixedBackend.history; elim* => built0.
  seq 2 : (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\
    message = message0 /\ shuffle = shuffle0 /\ caller_fields layer0 tree0 leaf0 /\ backend_width f /\
    built = merkle_build_value (interpreted_backend f) seed0 key0 layer0 tree0 leaf0 /\
    signed = functional_sign_result f key0 seed0 layer0 tree0 leaf0 message0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151+functional_derive_cost shuffle0+
      functional_sign_cost f seed0 layer0 tree0 leaf0 message0 (functional_derived_seed f shuffle0 (shuffle_layer_label layer0)) /\
    FixedBackend.history = functional_layer_after_search f built0 key0 seed0 layer0 tree0 leaf0 message0 shuffle0 /\
    functional_history_exact f h built0
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9)).
  + call (fixed_functional_sign f (functional_derive_history f built0 shuffle0 (shuffle_layer_label layer0))
      (c+177151+functional_derive_cost shuffle0) key0 seed0 layer0 tree0 leaf0 message0
      (functional_derived_seed f shuffle0 (shuffle_layer_label layer0))).
    call (fixed_functional_derive f built0 (c+177151) key0 shuffle0 (shuffle_layer_label layer0)).
    auto; rewrite /functional_layer_after_search; smt().
  sp 1; if.
  + wp; call (fixed_functional_layer_recover f
      (functional_layer_after_search f built0 key0 seed0 layer0 tree0 leaf0 message0 shuffle0)
      (c+177151+functional_derive_cost shuffle0+
        functional_sign_cost f seed0 layer0 tree0 leaf0 message0 (functional_derived_seed f shuffle0 (shuffle_layer_label layer0)))
      key0 seed0 layer0 tree0 leaf0 message0 (functional_layer_signature f key0 seed0 layer0 tree0 leaf0 message0)).
    wp; auto => />; rewrite /merkle_build_value /functional_layer_result /functional_layer_sign_cost
      /functional_layer_sign_history; smt(functional_layer_payload functional_layer_sign_failure).
  auto => />; rewrite /functional_layer_result /functional_layer_sign_cost /functional_layer_sign_history
    /functional_sign_result; smt().
qed.

lemma raw_functional_layer_sign f h c key0 seed0 layer0 tree0 leaf0 message0 shuffle0 :
  equiv[RawLayer(PreparationView(FixedPrefix)).sign ~ CommonInputLayer(FixedPrefix).sign :
    ={seed,layer,tree,leaf,message,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ leaf{1} = leaf0 /\
    message{1} = message0 /\ shuffle{1} = shuffle0 /\ caller_fields layer0 tree0 leaf0 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\ res{1} = functional_layer_result f key0 seed0 layer0 tree0 leaf0 message0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c + functional_layer_sign_cost f key0 seed0 layer0 tree0 leaf0 message0 shuffle0 /\
    exists built, functional_history_exact f h built
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
      FixedBackend.history{1} = functional_layer_sign_history f built key0 seed0 layer0 tree0 leaf0 message0 shuffle0].
proof.
  conseq (caller_layer_sign FixedPrefix) (_ : true ==> true)
    (fixed_functional_layer_sign f h c key0 seed0 layer0 tree0 leaf0 message0 shuffle0) => //; smt().
qed.
