(* Complete actual verifier under a fixed backend, with exact state and cost.
   No valid-signature, successful-search or empty-history premise is used. *)
require import AllCore List IntDiv FMap.
require import C10Bytes C10RawOracle C10RawGrind C10Representation RawSigner RawLayer RawForest.
require import KeygenPrefixes C10FixedBackend C10FixedCallerBridge.
require import C10HashInputBridge C10CallerInputBridge C10OuterCallerBridge C10SearchAcceptance.
require import C10FunctionalWotsValue C10FunctionalForestRecover C10FunctionalLayerRecover.
require import C10FunctionalVerifierValue C10FunctionalVerifierState.
require import RawSignature RawDecode C10RepresentationBridge.

op paired_verifier_result fn seed root message (sig : raw_signature) =
  let d = verifier_digest fn seed root sig.`1 message in
  let first = nth ([],0,[]) sig.`4 0 in
  let second = nth ([],0,[]) sig.`4 1 in
  fors_zero_field d = 0 /\
    pad_node (verifier_recover_value fn seed d sig.`2 sig.`3
      first.`1 first.`2 first.`3 second.`1 second.`2 second.`3) = root.

lemma functional_verifier_decision f seed root message (sig : raw_signature) : backend_width f =>
  let d = f (functional_verifier_query seed root message sig) in
  paired_verifier_result (interpreted_backend f) seed root message sig =
    (accept_digest d /\ pad_node (functional_verifier_root f seed d sig 2) = root).
proof.
  move=> hf; rewrite /paired_verifier_result -functional_verifier_digest /=
    /functional_verifier_root /functional_verifier_layer /=.
  rewrite (fors_accept_bits (f (functional_verifier_query seed root message sig)))
    1:(functional_digest_width f _ hf); trivial.
qed.

lemma fixed_functional_verifier f h c key0 seed0 root0 message0 sig0 :
  hoare[CommonInputSigner(FixedPrefix).verify :
    seed = seed0 /\ root = root0 /\ message = message0 /\ sig = sig0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = paired_verifier_result (interpreted_backend f) seed0 root0 message0 sig0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_verifier_history f h seed0 root0 message0 sig0 /\
    FixedBackend.calls = c + functional_verifier_cost f seed0 root0 message0 sig0].
proof.
  proc.
  seq 1 : (seed = seed0 /\ root = root0 /\ message = message0 /\ sig = sig0 /\
    digest = f (functional_verifier_query seed0 root0 message0 sig0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
    backend_consistent FixedBackend.history f /\
    FixedBackend.history = remember h (functional_verifier_query seed0 root0 message0 sig0)
      (f (functional_verifier_query seed0 root0 message0 sig0)) /\ FixedBackend.calls = c+1).
  + call (fixed_hash f h (functional_verifier_query seed0 root0 message0 sig0) c).
    auto; rewrite /functional_verifier_query; smt().
  sp 1; if.
  + wp; while (seed = seed0 /\ root = root0 /\ message = message0 /\ sig = sig0 /\
      digest = f (functional_verifier_query seed0 root0 message0 sig0) /\ accept_digest digest /\
      ht = hypertree_index digest /\ 0 <= layer <= 2 /\
      idx_tree = functional_verifier_index (hypertree_index digest) layer /\
      current = functional_verifier_root f seed0 digest sig0 layer /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
      backend_consistent FixedBackend.history f /\
      FixedBackend.history = functional_verifier_layer_history f
        (functional_verifier_forest_history f h seed0 root0 message0 sig0) seed0 digest sig0 layer /\
      FixedBackend.calls = c+147+functional_verifier_layer_cost f seed0 digest sig0 layer).
    - exists* layer; elim* => i0; wp.
      call (fixed_functional_layer_recover f
        (functional_verifier_layer_history f
          (functional_verifier_forest_history f h seed0 root0 message0 sig0)
          seed0 (f (functional_verifier_query seed0 root0 message0 sig0)) sig0 i0)
        (c+147+functional_verifier_layer_cost f seed0
          (f (functional_verifier_query seed0 root0 message0 sig0)) sig0 i0)
        key0 seed0 i0
        (functional_verifier_index (hypertree_index (f (functional_verifier_query seed0 root0 message0 sig0))) i0 %/ 512)
        (functional_verifier_index (hypertree_index (f (functional_verifier_query seed0 root0 message0 sig0))) i0 %% 512)
        (functional_verifier_root f seed0 (f (functional_verifier_query seed0 root0 message0 sig0)) sig0 i0)
        (functional_verifier_layer sig0 i0)).
      auto => />; rewrite /functional_verifier_layer;
        smt(functional_digest_width functional_verifier_coordinates functional_verifier_index_step
          functional_verifier_layer_step functional_verifier_history_step functional_verifier_cost_step).
    wp; call (fixed_functional_forest_recover f
      (remember h (functional_verifier_query seed0 root0 message0 sig0)
        (f (functional_verifier_query seed0 root0 message0 sig0))) (c+1) key0 seed0
      (hypertree_index (f (functional_verifier_query seed0 root0 message0 sig0)))
      (f (functional_verifier_query seed0 root0 message0 sig0)) sig0.`2 sig0.`3).
    auto => />; rewrite /functional_verifier_forest_history /functional_verifier_index
      /functional_verifier_root /functional_verifier_layer_history /functional_verifier_layer_cost
      /functional_verifier_history /functional_verifier_cost;
      smt(functional_digest_width functional_verifier_forest_value functional_verifier_decision pad_common).
  auto => />; rewrite /functional_verifier_history /functional_verifier_cost;
    smt(functional_verifier_decision).
qed.

lemma raw_functional_verifier f h c key0 seed0 root0 message0 sig0 :
  equiv[RawSigner(FixedPrefix).verify ~ CommonInputSigner(FixedPrefix).verify :
    ={seed,root,message,sig,glob FixedPrefix} /\
    seed{1} = seed0 /\ root{1} = root0 /\ message{1} = message0 /\ sig{1} = sig0 /\
    outer_counters sig0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = paired_verifier_result (interpreted_backend f) seed0 root0 message0 sig0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = functional_verifier_history f h seed0 root0 message0 sig0 /\
    FixedBackend.calls{1} = c + functional_verifier_cost f seed0 root0 message0 sig0].
proof.
  conseq (caller_signer_verify FixedPrefix) (_ : true ==> true)
    (fixed_functional_verifier f h c key0 seed0 root0 message0 sig0) => //; smt().
qed.

lemma raw_functional_verifier_decoded f h c key0 seed0 root0 message0 bytes :
  size bytes = 4008 => all (fun b => 0 <= b < 256) bytes =>
  equiv[RawSigner(FixedPrefix).verify ~ CommonInputSigner(FixedPrefix).verify :
    ={seed,root,message,sig,glob FixedPrefix} /\
    seed{1} = seed0 /\ root{1} = root0 /\ message{1} = message0 /\ sig{1} = decode_signature bytes /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = paired_verifier_result (interpreted_backend f) seed0 root0 message0 (word_decode bytes) /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = functional_verifier_history f h seed0 root0 message0 (word_decode bytes) /\
    FixedBackend.calls{1} = c + functional_verifier_cost f seed0 root0 message0 (word_decode bytes)].
proof.
  move=> hs hb; conseq (raw_functional_verifier f h c key0 seed0 root0 message0 (decode_signature bytes));
    smt(outer_decoded_counters decode_word).
qed.

lemma fixed_functional_verifier_lossless : islossless CommonInputSigner(FixedPrefix).verify.
proof.
  proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call fixed_hash_ll; auto.
  sp 1; if; auto; wp; while true (2-layer).
  + move=> z; wp; call fixed_functional_layer_recover_lossless; auto; smt().
  wp; call fixed_functional_forest_recover_lossless; auto; smt().
qed.

lemma raw_functional_verifier_lossless : islossless RawSigner(FixedPrefix).verify.
proof. exact (signer_verify_lossless FixedPrefix fixed_hash_ll). qed.
