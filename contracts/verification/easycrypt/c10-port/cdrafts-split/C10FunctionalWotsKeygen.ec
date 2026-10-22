(* Complete WOTS public-key computation under the fixed backend. *)
require import AllCore List FMap.
require import C10Representation C10RawOracle RawKeygen KeygenPrefixes.
require import C10CallerInputBridge C10PrivateCallerBridge C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWotsValue C10FunctionalWotsChain.

op functional_private_query key layer tree kp i = wots_private_preimage key layer tree kp i.
op functional_private_value f key layer tree kp i =
  wots_secret_value (interpreted_backend f) key layer tree kp i.
op functional_keygen_node f key seed layer tree kp i =
  wots_chain_value (interpreted_backend f) seed (address_words layer tree 0 kp i 0 0)
    (functional_private_value f key layer tree kp i) 0 7.
op functional_keygen_queries f key seed layer tree kp i =
  functional_private_query key layer tree kp i ::
    mkseq (functional_chain_query f seed layer tree kp i
      (functional_private_value f key layer tree kp i) 0) 7.
op functional_keygen_history f h key seed layer tree kp n =
  foldl (fun table i => backend_history f table (functional_keygen_queries f key seed layer tree kp i))
    h (mkseq (fun i => i) n).
op functional_keygen_compression f key seed layer tree kp =
  multi_preimage seed (address_words layer tree 1 kp 0 0 0)
    (wots_keygen_nodes (interpreted_backend f) seed key layer tree kp).

lemma functional_private_prefix key layer tree kp i :
  key ++ wots_private_preimage [] layer tree kp i = functional_private_query key layer tree kp i.
proof. by rewrite /functional_private_query /wots_private_preimage -!catA. qed.

lemma functional_private_node f key layer tree kp i : backend_width f =>
  node (f (functional_private_query key layer tree kp i)) = functional_private_value f key layer tree kp i.
proof. by move=> hf; rewrite interpreted_node 1:hf /functional_private_value /wots_secret_value /functional_private_query. qed.

lemma functional_keygen_nodes f key seed layer tree kp :
  wots_keygen_nodes (interpreted_backend f) seed key layer tree kp =
    mkseq (functional_keygen_node f key seed layer tree kp) 43.
proof. by rewrite /wots_keygen_nodes /functional_keygen_node /functional_private_value. qed.

lemma functional_keygen_value f key seed layer tree kp :
  wots_keygen_value (interpreted_backend f) seed key layer tree kp =
    hash_bytes_node (interpreted_backend f) (functional_keygen_compression f key seed layer tree kp).
proof. by rewrite /wots_keygen_value /functional_keygen_compression. qed.

lemma functional_keygen_history_zero f h key seed layer tree kp :
  functional_keygen_history f h key seed layer tree kp 0 = h.
proof. by rewrite /functional_keygen_history mkseq0. qed.

lemma functional_keygen_history_next f h key seed layer tree kp i : 0 <= i =>
  functional_keygen_history f h key seed layer tree kp (i+1) =
    backend_history f
      (remember (functional_keygen_history f h key seed layer tree kp i)
        (functional_private_query key layer tree kp i) (f (functional_private_query key layer tree kp i)))
      (mkseq (functional_chain_query f seed layer tree kp i
        (functional_private_value f key layer tree kp i) 0) 7).
proof.
  move=> hi; rewrite /functional_keygen_history mkseqS 1:hi foldl_rcons.
  by rewrite /functional_keygen_queries /backend_history /=.
qed.

lemma fixed_functional_keygen f h c key0 seed0 layer0 tree0 kp0 :
  hoare[CommonPrivateWots(FixedPrefix).leaf :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ caller_fields layer0 tree0 kp0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = remember (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 43)
      (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)
      (f (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+345].
proof.
  proc; call (fixed_hash f (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 43)
    (functional_keygen_compression f key0 seed0 layer0 tree0 kp0) (c+344)).
  while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ caller_fields layer0 tree0 kp0 /\
    0 <= i <= 43 /\ backend_width f /\
    elements = mkseq (functional_keygen_node f key0 seed0 layer0 tree0 kp0) i /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = functional_keygen_history f h key0 seed0 layer0 tree0 kp0 i /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+8*i).
  + exists* i; elim* => i0; wp.
    call (fixed_functional_chain f
      (remember (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 i0)
        (functional_private_query key0 layer0 tree0 kp0 i0) (f (functional_private_query key0 layer0 tree0 kp0 i0)))
      (c+8*i0+1) key0 seed0 layer0 tree0 kp0 i0 (functional_private_value f key0 layer0 tree0 kp0 i0) 0 7).
    call (fixed_derive f (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 i0)
      (wots_private_preimage [] layer0 tree0 kp0 i0) (c+8*i0) key0).
    auto => />; rewrite functional_private_prefix;
      smt(functional_private_node functional_keygen_history_next mkseqS caller_u32_size).
  auto => />; rewrite functional_keygen_history_zero mkseq0 /functional_keygen_compression
    functional_keygen_nodes /wots_keygen_value;
    smt(interpreted_node functional_keygen_nodes).
qed.

lemma fixed_functional_keygen_lossless : islossless CommonPrivateWots(FixedPrefix).leaf.
proof.
  proc; call fixed_hash_ll; while true (43-i).
  + move=> z; wp; call fixed_functional_chain_lossless; call fixed_derive_ll; auto; smt().
  auto; smt().
qed.

lemma raw_functional_keygen f h c key0 seed0 layer0 tree0 kp0 :
  equiv[RawKeygen(PreparationView(FixedPrefix)).leaf ~ CommonPrivateWots(FixedPrefix).leaf :
    ={seed,layer,tree,kp,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\ caller_fields layer0 tree0 kp0 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\
    FixedBackend.history{1} = remember (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 43)
      (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)
      (f (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)) /\
    backend_consistent FixedBackend.history{1} f /\ FixedBackend.calls{1} = c+345].
proof.
  conseq (caller_keygen_leaf FixedPrefix) (_ : true ==> true)
    (fixed_functional_keygen f h c key0 seed0 layer0 tree0 kp0) => //; smt().
qed.

lemma raw_functional_keygen_lossless : islossless RawKeygen(PreparationView(FixedPrefix)).leaf.
proof.
  have hw : islossless PreparationView(FixedPrefix).wots by proc; call fixed_derive_ll; auto.
  proc; call fixed_hash_ll; while true (43-i).
  + move=> z; wp; while true (7-j).
    - move=> k; wp; call fixed_hash_ll; auto; smt().
    wp; call hw; auto; smt().
  auto; smt().
qed.
