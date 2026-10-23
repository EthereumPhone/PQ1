(* Whole layer recovery, including rejected WOTS digests, exact prior history,
   all nine subsequent XMSS queries, and full-width verification counters. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind RawWots RawLayer KeygenPrefixes C10Representation.
require import C10CallerInputBridge C10TreeCallerBridge.
require import C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue C10FunctionalWotsRecover.
require import C10FunctionalTreeValue C10FunctionalMerkle.

op functional_layer_wots_history f h seed layer tree leaf message sigma count =
  let q = functional_wots_query seed layer tree leaf message count in
  let d = f q in let h1 = remember h q d in
  let comp = functional_recover_compression f seed layer tree leaf d sigma in
  if count_accepts d then
    remember (functional_recover_history f h1 seed layer tree leaf d sigma 43) comp (f comp)
  else h1.

op functional_layer_wots_cost f seed layer tree leaf message count =
  let d = f (functional_wots_query seed layer tree leaf message count) in
  if count_accepts d then 2 + functional_recover_cost d 43 else 1.

op functional_layer_recovery_history f h seed layer tree leaf message (sig : layer_signature) =
  let pk = wots_recover_value (interpreted_backend f) seed layer tree leaf message sig.`1 sig.`2 in
  backend_history f (functional_layer_wots_history f h seed layer tree leaf message sig.`1 sig.`2)
    (mkseq (functional_tree_query f seed layer tree 2 0 pk leaf sig.`3) 9).

op functional_layer_recovery_cost f seed layer tree leaf message (sig : layer_signature) =
  functional_layer_wots_cost f seed layer tree leaf message sig.`2 + 9.

lemma fixed_functional_layer_recover f h c key0 seed0 layer0 tree0 leaf0 message0 sig0 :
  hoare[CommonInputLayer(FixedPrefix).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\
    message = message0 /\ sig = sig0 /\ caller_fields layer0 tree0 leaf0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = layer_recover_value (interpreted_backend f) seed0 layer0 tree0 leaf0 message0 sig0.`1 sig0.`2 sig0.`3 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_layer_recovery_history f h seed0 layer0 tree0 leaf0 message0 sig0 /\
    FixedBackend.calls = c + functional_layer_recovery_cost f seed0 layer0 tree0 leaf0 message0 sig0].
proof.
  proc.
  call (fixed_functional_merkle f
    (functional_layer_wots_history f h seed0 layer0 tree0 leaf0 message0 sig0.`1 sig0.`2)
    (c + functional_layer_wots_cost f seed0 layer0 tree0 leaf0 message0 sig0.`2)
    key0 seed0 layer0 tree0
    (wots_recover_value (interpreted_backend f) seed0 layer0 tree0 leaf0 message0 sig0.`1 sig0.`2)
    leaf0 sig0.`3).
  call (fixed_functional_recover f h c key0 seed0 layer0 tree0 leaf0 message0 sig0.`1 sig0.`2).
  auto => />; rewrite /layer_recover_value /functional_layer_wots_history /functional_layer_wots_cost
    /functional_layer_recovery_history /functional_layer_recovery_cost; smt().
qed.

lemma common_functional_merkle_recover_lossless : islossless CommonInputMerkle(FixedPrefix).recover.
proof.
  proc; while true (9-h).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  auto; smt().
qed.

lemma fixed_functional_layer_recover_lossless : islossless CommonInputLayer(FixedPrefix).recover.
proof.
  proc; call common_functional_merkle_recover_lossless.
  call fixed_functional_recover_lossless; auto.
qed.

lemma raw_functional_layer_recover f h c key0 seed0 layer0 tree0 leaf0 message0 sig0 :
  equiv[RawLayer(PreparationView(FixedPrefix)).recover ~ CommonInputLayer(FixedPrefix).recover :
    ={seed,layer,tree,leaf,message,sig,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ leaf{1} = leaf0 /\
    message{1} = message0 /\ sig{1} = sig0 /\ caller_fields layer0 tree0 leaf0 /\
    0 <= sig0.`2 < 4294967296 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = layer_recover_value (interpreted_backend f) seed0 layer0 tree0 leaf0 message0 sig0.`1 sig0.`2 sig0.`3 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = functional_layer_recovery_history f h seed0 layer0 tree0 leaf0 message0 sig0 /\
    FixedBackend.calls{1} = c + functional_layer_recovery_cost f seed0 layer0 tree0 leaf0 message0 sig0].
proof.
  conseq (caller_layer_recover FixedPrefix) (_ : true ==> true)
    (fixed_functional_layer_recover f h c key0 seed0 layer0 tree0 leaf0 message0 sig0) => //; smt().
qed.

lemma raw_functional_layer_recover_lossless :
  islossless RawLayer(PreparationView(FixedPrefix)).recover.
proof. exact (layer_recover_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.
