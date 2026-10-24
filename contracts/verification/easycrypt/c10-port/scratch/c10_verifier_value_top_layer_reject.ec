require import AllCore List IntDiv C10Representation C10RawOracle C10RawGrind RawSigner RawLayer RawForest SignerCoordinates C10FixedBackend C10FixedCallerBridge C10DigestCallers C10Bytes ShuffleBytes C10CallerInputBridge C10OuterCallerBridge C10FunctionalWotsValue C10FunctionalForestRecover C10FunctionalLayerRecover FMap KeygenPrefixes C10HashInputBridge C10SearchAcceptance RawSignature RawDecode C10RepresentationBridge.

op digest_fors_indices (bs : (int list)) : (int list) =
  (mkseq (fun i => (fors_field bs i)) 13).

op verifier_digest (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (random : (int list)) (message : (int list)) : (int list) =
  (hash_fn (hmsg_preimage seed root (pad_node random) message)).

op digest_forest_value (hash_fn : (int list -> int list)) (seed : (int list)) (bs : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) : (int list) =
  (forest_recover_value hash_fn seed (ht_field bs) (digest_fors_indices bs) forest_secrets forest_paths).

op hypertree_first_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (message : (int list)) (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  (layer_recover_value hash_fn seed 0 (ht %/ 512) (ht %% 512) message values nonce auth).

op hypertree_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (message : (int list)) (values0 : ((int list) list)) (nonce0 : int) (auth0 : ((int list) list)) (values1 : ((int list) list)) (nonce1 : int) (auth1 : ((int list) list)) : (int list) =
  (layer_recover_value hash_fn seed 0 ((ht %/ 512) %/ 512) ((ht %/ 512) %% 512) (hypertree_first_value hash_fn seed ht message values0 nonce0 auth0) values1 nonce1 auth1).

op verifier_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (bs : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) (values0 : ((int list) list)) (nonce0 : int) (auth0 : ((int list) list)) (values1 : ((int list) list)) (nonce1 : int) (auth1 : ((int list) list)) : (int list) =
  (hypertree_recover_value hash_fn seed (ht_field bs) (digest_forest_value hash_fn seed bs forest_secrets forest_paths) values0 nonce0 auth0 values1 nonce1 auth1).

(* Values and digest-bound discharge for complete verifier composition.
   The fixed backend and paired-printer interpretation are explicit. *)






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

(* Exact histories and query costs for both verifier layers. Each history
   starts with arbitrary backend-consistent state; repeated queries remain. *)





op functional_verifier_first_history f h seed d (sig : raw_signature) =
  functional_layer_recovery_history f h seed 0 (hypertree_index d %/ 512) (hypertree_index d %% 512)
    (functional_verifier_root f seed d sig 0) (functional_verifier_layer sig 0).
op functional_verifier_layer_history f h seed d (sig : raw_signature) i =
  if i = 0 then h else if i = 1 then functional_verifier_first_history f h seed d sig else
  functional_layer_recovery_history f (functional_verifier_first_history f h seed d sig)
    seed 1 (hypertree_index d %/ 512 %/ 512) (hypertree_index d %/ 512 %% 512)
    (functional_verifier_root f seed d sig 1) (functional_verifier_layer sig 1).
op functional_verifier_first_cost f seed d (sig : raw_signature) =
  functional_layer_recovery_cost f seed 0 (hypertree_index d %/ 512) (hypertree_index d %% 512)
    (functional_verifier_root f seed d sig 0) (functional_verifier_layer sig 0).
op functional_verifier_layer_cost f seed d (sig : raw_signature) i =
  if i = 0 then 0 else if i = 1 then functional_verifier_first_cost f seed d sig else
  functional_verifier_first_cost f seed d sig +
    functional_layer_recovery_cost f seed 1 (hypertree_index d %/ 512 %/ 512) (hypertree_index d %/ 512 %% 512)
      (functional_verifier_root f seed d sig 1) (functional_verifier_layer sig 1).

lemma functional_verifier_history_step f h seed d sig i : 0 <= i < 2 =>
  let idx = functional_verifier_index (hypertree_index d) i in
  functional_layer_recovery_history f (functional_verifier_layer_history f h seed d sig i)
    seed i (idx %/ 512) (idx %% 512) (functional_verifier_root f seed d sig i)
    (functional_verifier_layer sig i) = functional_verifier_layer_history f h seed d sig (i+1).
proof.
  move=> hi; have hc : i = 0 \/ i = 1 by smt().
  case: hc => ->; by rewrite /functional_verifier_index /functional_verifier_layer_history
    /functional_verifier_first_history /=.
qed.

lemma functional_verifier_cost_step f seed d sig i : 0 <= i < 2 =>
  let idx = functional_verifier_index (hypertree_index d) i in
  functional_verifier_layer_cost f seed d sig i +
    functional_layer_recovery_cost f seed i (idx %/ 512) (idx %% 512)
      (functional_verifier_root f seed d sig i) (functional_verifier_layer sig i) =
    functional_verifier_layer_cost f seed d sig (i+1).
proof.
  move=> hi; have hc : i = 0 \/ i = 1 by smt().
  case: hc => ->; by rewrite /functional_verifier_index /functional_verifier_layer_cost
    /functional_verifier_first_cost /=.
qed.

op functional_verifier_forest_history f h seed root message (sig : raw_signature) =
  let q = functional_verifier_query seed root message sig in
  functional_forest_recovery_history f (remember h q (f q)) seed (hypertree_index (f q)) (f q) sig.`2 sig.`3.
op functional_verifier_history f h seed root message (sig : raw_signature) =
  let q = functional_verifier_query seed root message sig in
  if accept_digest (f q) then
    functional_verifier_layer_history f (functional_verifier_forest_history f h seed root message sig)
      seed (f q) sig 2
  else remember h q (f q).
op functional_verifier_cost f seed root message (sig : raw_signature) =
  let q = functional_verifier_query seed root message sig in
  if accept_digest (f q) then 147 + functional_verifier_layer_cost f seed (f q) sig 2 else 1.


(* Complete actual verifier under a fixed backend, with exact state and cost.
   No valid-signature, successful-search or empty-history premise is used. *)








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
