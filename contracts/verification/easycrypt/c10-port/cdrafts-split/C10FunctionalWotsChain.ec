(* Ordered WOTS chains with arbitrary consistent backend prehistory.
   Query history and calls describe the actual imperative loop, not evaluation
   cost of the generated mathematical expression. *)
require import AllCore List FMap.
require import C10Representation C10RawOracle C10RawGrind RawKeygen RawWots KeygenPrefixes.
require import C10CallerInputBridge C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue.

op functional_chain_query f seed layer tree kp index value start i =
  th_preimage seed (address_words layer tree 0 kp index (start+i) 0)
    (pad_node (wots_chain_value (interpreted_backend f) seed
      (address_words layer tree 0 kp index 0 0) value start i)).

lemma functional_chain_step f seed layer tree kp index value start i :
  backend_width f => caller_fields layer tree kp => 0 <= index < 2^32 =>
  0 <= i => 0 <= start+i < 2^32 =>
  node (f (functional_chain_query f seed layer tree kp index value start i)) =
    wots_chain_value (interpreted_backend f) seed
      (address_words layer tree 0 kp index 0 0) value start (i+1).
proof.
  move=> hf ha hi hn hp.
  by rewrite functional_chain_next 1:hn
    (functional_chain_address layer tree kp index (start+i) ha hi hp)
    /functional_chain_query interpreted_node 1:hf.
qed.

lemma fixed_functional_chain f h c key0 seed0 layer0 tree0 kp0 index0 value0 start0 stop0 :
  hoare[CommonInputWots(PreparationView(FixedPrefix)).chain :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ index = index0 /\
    current = value0 /\ start = start0 /\ stop = stop0 /\
    caller_fields layer0 tree0 kp0 /\ 0 <= index0 < 2^32 /\ 0 <= start0 <= stop0 /\ stop0 <= 2^32 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = wots_chain_value (interpreted_backend f) seed0
      (address_words layer0 tree0 0 kp0 index0 0 0) value0 start0 (stop0-start0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h
      (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (stop0-start0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+(stop0-start0)].
proof.
  proc; while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ index = index0 /\
    start = start0 /\ stop = stop0 /\ caller_fields layer0 tree0 kp0 /\
    0 <= index0 < 2^32 /\ 0 <= start0 <= j <= stop0 /\ stop0 <= 2^32 /\ backend_width f /\
    current = wots_chain_value (interpreted_backend f) seed0
      (address_words layer0 tree0 0 kp0 index0 0 0) value0 start0 (j-start0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h
      (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (j-start0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+(j-start0)).
  + exists* j; elim* => j0; wp.
    call (fixed_hash f
      (backend_history f h (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (j0-start0)))
      (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0 (j0-start0)) (c+(j0-start0))).
    auto => />; rewrite /functional_chain_query;
      smt(functional_chain_step backend_history_mkseqS).
  auto => />; rewrite functional_chain_zero mkseq0 backend_history_nil; smt().
qed.

lemma fixed_functional_chain_lossless :
  islossless CommonInputWots(PreparationView(FixedPrefix)).chain.
proof.
  proc; while true (max 0 (stop-j)).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  auto; smt().
qed.

lemma raw_functional_chain_lossless :
  islossless RawWots(PreparationView(FixedPrefix)).chain.
proof. exact (raw_chain_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.

lemma raw_functional_chain f h c key0 seed0 layer0 tree0 kp0 index0 value0 start0 stop0 :
  equiv[RawWots(PreparationView(FixedPrefix)).chain ~
    CommonInputWots(PreparationView(FixedPrefix)).chain :
    ={seed,layer,tree,kp,index,current,start,stop,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\ index{1} = index0 /\
    current{1} = value0 /\ start{1} = start0 /\ stop{1} = stop0 /\
    caller_fields layer0 tree0 kp0 /\ 0 <= index0 < 2^32 /\ 0 <= start0 <= stop0 /\ stop0 <= 2^32 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = wots_chain_value (interpreted_backend f) seed0
      (address_words layer0 tree0 0 kp0 index0 0 0) value0 start0 (stop0-start0) /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\
    FixedBackend.history{1} = backend_history f h
      (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (stop0-start0)) /\
    backend_consistent FixedBackend.history{1} f /\ FixedBackend.calls{1} = c+(stop0-start0)].
proof.
  conseq (caller_wots_chain (PreparationView(FixedPrefix))) (_ : true ==> true)
    (fixed_functional_chain f h c key0 seed0 layer0 tree0 kp0 index0 value0 start0 stop0) => //; smt().
qed.
