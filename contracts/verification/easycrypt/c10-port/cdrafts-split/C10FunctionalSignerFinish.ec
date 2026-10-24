(* Actual complete forest/two-layer caller, retaining state on exhaustion. *)
require import AllCore List IntDiv FMap.
require import C10Bytes C10RawOracle C10RawGrind RawSigner RawLayer RawForest.
require import KeygenPrefixes C10FixedBackend C10FixedCallerBridge.
require import SignerCoordinates.
require import C10Representation C10CallerInputBridge C10OuterCallerBridge.
require import C10FunctionalWotsValue C10FunctionalLayerSign C10FunctionalForestSign.
require import C10FunctionalSignerValue C10FunctionalSignerState C10FunctionalVerifierValue.

lemma fixed_functional_signer_layer f h c key0 seed0 d0 shuffle0 i0 :
  hoare[CommonInputLayer(FixedPrefix).sign :
    0 <= i0 < 2 /\ size d0 = 256 /\ seed = seed0 /\ layer = i0 /\
    tree = functional_verifier_index (hypertree_index d0) i0 %/ 512 /\
    leaf = functional_verifier_index (hypertree_index d0) i0 %% 512 /\
    message = functional_signer_current f key0 seed0 d0 i0 /\ shuffle = shuffle0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_signer_layer f key0 seed0 d0 i0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c + functional_signer_step_cost f key0 seed0 d0 shuffle0 i0 /\
    functional_signer_step_state f h FixedBackend.history key0 seed0 d0 shuffle0 i0].
proof.
  conseq (fixed_functional_layer_sign f h c key0 seed0 i0
    (functional_verifier_index (hypertree_index d0) i0 %/ 512)
    (functional_verifier_index (hypertree_index d0) i0 %% 512)
    (functional_signer_current f key0 seed0 d0 i0) shuffle0) => //.
  + smt(functional_verifier_coordinates).
  rewrite /functional_signer_layer /functional_signer_step_cost /functional_signer_step_state; smt().
qed.

lemma fixed_functional_signer_finish f h c key0 seed0 randomizer0 d0 shuffle0 : size d0 = 256 =>
  hoare[CommonInputSigner(FixedPrefix).finish :
    seed = seed0 /\ randomizer = randomizer0 /\ digest = d0 /\ shuffle = shuffle0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = paired_finish_result (interpreted_backend f) key0 seed0 randomizer0 (bits_to_bytes d0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c + functional_finish_cost f key0 seed0 d0 shuffle0 /\
    functional_finish_state f h FixedBackend.history key0 seed0 d0 shuffle0].
proof.
  move=> hd; proc.
  seq 2 : (seed = seed0 /\ randomizer = randomizer0 /\ digest = d0 /\ shuffle = shuffle0 /\
    ht = hypertree_index d0 /\ forest = functional_signer_forest f key0 seed0 d0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
    backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80017 /\
    functional_forest_sign_state f h FixedBackend.history key0 seed0 (hypertree_index d0) d0 shuffle0).
  + call (fixed_functional_forest_sign f h c key0 seed0 (hypertree_index d0) d0 shuffle0).
    auto; rewrite /functional_signer_forest; smt(hypertree_index_range caller_u32_size).
  exists* FixedBackend.history; elim* => forest0.
  wp; while (seed = seed0 /\ randomizer = randomizer0 /\ digest = d0 /\ shuffle = shuffle0 /\
    ht = hypertree_index d0 /\ forest = functional_signer_forest f key0 seed0 d0 /\
    0 <= layer <= 2 /\ idx_tree = functional_verifier_index (hypertree_index d0) layer /\
    current = functional_signer_current f key0 seed0 d0 layer /\
    layers = functional_signer_layers f key0 seed0 d0 layer /\
    ok = functional_signer_ok f key0 seed0 d0 layer /\
    (layer = 2 => functional_signer_layer0 f key0 seed0 d0 <> None) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
    backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80017+
      functional_signer_layers_cost f key0 seed0 d0 shuffle0 layer /\
    functional_forest_sign_state f h forest0 key0 seed0 (hypertree_index d0) d0 shuffle0 /\
    functional_signer_layers_state f forest0 FixedBackend.history key0 seed0 d0 shuffle0 layer).
  + exists* layer, FixedBackend.history; elim* => i0 history0; wp.
    call (fixed_functional_signer_layer f history0
      (c+functional_forest_initial_cost f shuffle0+80017+functional_signer_layers_cost f key0 seed0 d0 shuffle0 i0)
      key0 seed0 d0 shuffle0 i0).
    auto; smt(functional_signer_layer_step functional_verifier_index_step
      functional_signer_layers_cost_step functional_signer_layers_state_step functional_signer_next_reachable).
  auto; move=> &m hpre; split.
  + have hi := functional_signer_initial f forest0 key0 seed0 d0 shuffle0; smt().
  move=> calls history current0 idx0 layer0 layers0 ok0 hexit hpost.
  have hb : 0 <= layer0 <= 2 by smt().
  have he : layer0 = 2 \/ !functional_signer_ok f key0 seed0 d0 layer0 by smt().
  have hp : layer0 = 2 => functional_signer_layer0 f key0 seed0 d0 <> None by smt().
  have hf : functional_forest_sign_state f h forest0 key0 seed0 (hypertree_index d0) d0 shuffle0 by smt().
  have hs : functional_signer_layers_state f forest0 history key0 seed0 d0 shuffle0 layer0 by smt().
  have hc := functional_signer_complete f h forest0 history key0 seed0 randomizer0 d0 shuffle0 layer0
    hd hb he hp hf hs.
  smt().
qed.

lemma raw_functional_signer_finish f h c key0 seed0 randomizer0 d0 shuffle0 :
  equiv[RawSigner(FixedPrefix).finish ~ CommonInputSigner(FixedPrefix).finish :
    size d0 = 256 /\ ={seed,randomizer,digest,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ randomizer{1} = randomizer0 /\ digest{1} = d0 /\ shuffle{1} = shuffle0 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = paired_finish_result (interpreted_backend f) key0 seed0 randomizer0 (bits_to_bytes d0) /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c + functional_finish_cost f key0 seed0 d0 shuffle0 /\
    functional_finish_state f h FixedBackend.history{1} key0 seed0 d0 shuffle0].
proof.
  case (size d0 = 256) => hd; last by exfalso; smt().
  conseq (caller_signer_finish FixedPrefix) (_ : true ==> true)
    (fixed_functional_signer_finish f h c key0 seed0 randomizer0 d0 shuffle0 hd) => //; smt().
qed.

lemma fixed_functional_signer_finish_lossless : islossless CommonInputSigner(FixedPrefix).finish.
proof.
  proc; wp; while true (2-layer).
  + move=> z; wp; call fixed_functional_layer_sign_lossless; auto; smt().
  wp; call fixed_functional_forest_sign_lossless; auto; smt().
qed.

lemma raw_functional_signer_finish_lossless : islossless RawSigner(FixedPrefix).finish.
proof.
  exact (signer_finish_lossless FixedPrefix fixed_hash_ll fixed_derive_ll).
qed.
