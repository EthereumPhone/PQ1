require import AllCore List FMap C10RawOracle RawKeygen RawFors RawMerkle KeygenPrefixes C10Representation C10TreeCallerBridge C10FixedBackend C10FixedCallerBridge C10FunctionalWots C10FunctionalWotsValue C10FunctionalForsRecovery C10FunctionalBuildContracts C10FunctionalBuildHistory C10FunctionalForsBuildHistory C10FunctionalMerkleBuildHistory C10Bytes RawShuffle C10ShuffleBridge C10FunctionalWotsShuffle C10PrivateCallerBridge RawForest C10OuterCallerBridge C10RawGrind RawWots RawLayer C10CallerInputBridge C10FunctionalWotsRecover C10FunctionalTreeValue C10FunctionalMerkle C10FunctionalWotsSign ForestCoordinates.

op forest_sign_secrets (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (forest_indices : (int list)) : ((int list) list) =
  ((mkseq (fun i => (fors_secret_value hash_fn secret ht (i) (nth 0 forest_indices i))) 12) ++ [(fors_root_value hash_fn seed secret ht 12)]).

op forest_sign_paths (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (forest_indices : (int list)) : (((int list) list) list) =
  (mkseq (fun i => (fors_auth_values hash_fn seed secret ht (i) (nth 0 forest_indices i))) 12).

op forest_recover_roots (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (forest_indices : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) : ((int list) list) =
  ((mkseq (fun i => (fors_recover_value hash_fn seed ht (i) (nth 0 forest_indices i) (nth (nseq 16 0) forest_secrets i) (nth [] forest_paths i))) 12) ++ [(fors_leaf_value hash_fn seed ht 12 0 (nth (nseq 16 0) forest_secrets 12))]).

op forest_compress_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (values : ((int list) list)) : (int list) =
  (hash_bytes_node hash_fn (multi_preimage seed (address_words 0 ht 4 0 0 0 0) values)).

op forest_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (forest_indices : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) : (int list) =
  (forest_compress_value hash_fn seed ht (forest_recover_roots hash_fn seed ht forest_indices forest_secrets forest_paths)).

op forest_sign_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (forest_indices : (int list)) : (((int list) list) * (((int list) list) list) * (int list)) =
  ((forest_sign_secrets hash_fn seed secret ht forest_indices), (forest_sign_paths hash_fn seed secret ht forest_indices), (forest_recover_value hash_fn seed (ht+1) forest_indices (forest_sign_secrets hash_fn seed secret ht forest_indices) (forest_sign_paths hash_fn seed secret ht forest_indices))).

op wots_search_digests (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) : ((int list) list) =
  (mkseq (fun i => (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) (i)))) 10000000).

op layer_sign_slot (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) : int =
  (wots_first_slot (wots_search_digests hash_fn seed layer tree kp message)).

op layer_sign_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (nonce : int) : (((int list) list) * int * ((int list) list)) =
  ((wots_sign_values hash_fn seed secret layer tree kp (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) nonce))), nonce, (merkle_auth_values hash_fn seed secret layer tree kp)).

op layer_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  (merkle_recover_value hash_fn seed layer tree (wots_recover_value hash_fn seed layer tree kp message values nonce) kp auth).


(* Transfer existing actual construction contracts to their checked paired callers. *)







lemma functional_common_merkle_build_projection :
  equiv[CommonInputMerkle(FixedPrefix).build ~ RawMerkle(PreparationView(FixedPrefix)).build :
    ={seed,layer,tree,target,glob FixedPrefix} /\ tree_fields layer{1} tree{1} ==> ={res,glob FixedPrefix}].
proof. symmetry; conseq (caller_merkle_build FixedPrefix); smt(). qed.

lemma common_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0 :
  hoare[CommonInputMerkle(FixedPrefix).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    target = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = merkle_build_value (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151].
proof.
  conseq functional_common_merkle_build_projection (fixed_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma functional_common_fors_sign_projection :
  equiv[CommonInputFors(FixedPrefix).sign ~ RawFors(PreparationView(FixedPrefix)).sign :
    ={seed,ht,tree,target,glob FixedPrefix} /\ fors_fields ht{1} tree{1} /\ 0 <= target{1} < 2^32 ==> ={res,glob FixedPrefix}].
proof. symmetry; conseq (caller_fors_sign FixedPrefix); smt(). qed.

lemma common_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0 :
  hoare[CommonInputFors(FixedPrefix).sign :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = fors_sign_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f (remember initial (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0))) FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6144].
proof.
  conseq functional_common_fors_sign_projection (fixed_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma functional_common_fors_root_projection :
  equiv[CommonInputFors(FixedPrefix).root ~ RawFors(PreparationView(FixedPrefix)).root :
    ={seed,ht,tree,glob FixedPrefix} /\ fors_fields ht{1} tree{1} ==> ={res,glob FixedPrefix}].
proof. symmetry; conseq (caller_fors_root FixedPrefix); smt(). qed.

lemma common_functional_fors_root f initial c key0 seed0 ht0 tree0 :
  hoare[CommonInputFors(FixedPrefix).root :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6143].
proof.
  conseq functional_common_fors_root_projection (fixed_functional_fors_root f initial c key0 seed0 ht0 tree0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m}); smt().
  smt().
qed.

(* Fixed-backend derivation and the forest's twelve-position permutation. *)





op functional_derived_seed f seed label =
  if seed = nseq 32 0 then nseq 32 0 else bits_to_bytes (f (shuffle_seed_preimage seed label)).
op functional_derive_history f h seed label =
  if seed = nseq 32 0 then h else
    remember h (shuffle_seed_preimage seed label) (f (shuffle_seed_preimage seed label)).
op functional_derive_cost seed = if seed = nseq 32 0 then 0 else 1.

lemma fixed_functional_derive f h c key0 seed0 label0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).derive :
    seed = seed0 /\ label = label0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_derived_seed f seed0 label0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_derive_history f h seed0 label0 /\
    FixedBackend.calls = c+functional_derive_cost seed0].
proof.
  proc; sp 1; if.
  + wp; call (fixed_hash f h (shuffle_seed_preimage seed0 label0) c).
    auto; rewrite /functional_derived_seed /functional_derive_history /functional_derive_cost; smt().
  auto; rewrite /functional_derived_seed /functional_derive_history /functional_derive_cost; smt().
qed.

lemma fixed_functional_derive_lossless :
  islossless PairedShuffle(PreparationView(FixedPrefix)).derive.
proof. proc; sp 1; if; last by auto. wp; call fixed_hash_ll; auto. qed.

op functional_forest_order f seed = if seed = nseq 32 0 then range 0 12
  else shuffle_order 12 (functional_shuffle_stream f seed 4).

lemma fixed_functional_forest_shuffle_value f h c key0 seed0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation :
    seed = seed0 /\ n = 12 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_forest_order f seed0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) (functional_shuffle_steps seed0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+functional_shuffle_steps seed0].
proof.
  proc; sp 1; if.
  + wp; while (seed = seed0 /\ n = 12 /\ seed0 <> nseq 32 0 /\ 0 <= blk <= 4 /\
      stream = functional_shuffle_stream f seed0 blk /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
      FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) blk) /\
      backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+blk).
    - exists* blk; elim* => b; wp.
      call (fixed_hash f (backend_history f h (mkseq (shuffle_block_preimage seed0) b))
        (shuffle_block_preimage seed0 b) (c+b)).
      auto; smt(functional_shuffle_stream_next backend_history_mkseqS).
    auto => />; rewrite functional_shuffle_stream_zero mkseq0 backend_history_nil
      /functional_shuffle_steps /functional_forest_order; smt().
  auto => />; rewrite /functional_shuffle_steps /functional_forest_order mkseq0 backend_history_nil; smt().
qed.

lemma functional_shuffle_reverse :
  equiv[PairedShuffle(PreparationView(FixedPrefix)).permutation ~ RawShuffle(PreparationView(FixedPrefix)).permutation :
    ={arg,glob FixedPrefix} /\ 0 <= n{1} <= 64 ==> ={res,glob FixedPrefix}].
proof. symmetry; conseq (shuffle_permutation_common (PreparationView(FixedPrefix))); smt(). qed.

lemma paired_forest_shuffle_permutation :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation : n = 12 ==>
    perm_eq res (range 0 12)].
proof.
  conseq functional_shuffle_reverse
    (caller_shuffle_permutation (PreparationView(FixedPrefix)) 12).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},n{m}); smt().
  smt().
qed.

lemma fixed_functional_forest_shuffle f h c key0 seed0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation :
    seed = seed0 /\ n = 12 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_forest_order f seed0 /\ perm_eq res (range 0 12) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) (functional_shuffle_steps seed0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+functional_shuffle_steps seed0].
proof.
  conseq (fixed_functional_forest_shuffle_value f h c key0 seed0) paired_forest_shuffle_permutation; smt().
qed.

(* Actual complete forest recovery: twelve normal paths, the root-as-secret
   thirteenth slot, then compression; arbitrary consistent initial history. *)






op functional_forest_indices d = mkseq (forest_index d) 13.
op functional_forest_normal_roots f seed ht d secrets auths n =
  mkseq (fun t => fors_recover_value (interpreted_backend f) seed ht t (forest_index d t)
    (nth (nseq 16 0) secrets t) (nth [] auths t)) n.
op functional_forest_normal_history f h seed ht d secrets auths n =
  foldl (fun table t => functional_fors_recovery_history f table seed ht t (forest_index d t)
    (nth (nseq 16 0) secrets t) (nth [] auths t) 11) h (mkseq (fun t => t) n).
op functional_forest_last_query seed ht secrets =
  functional_fors_leaf_query seed ht 12 0 (nth (nseq 16 0) secrets 12).
op functional_forest_compression f seed ht d secrets auths =
  multi_preimage seed (address_words 0 ht 4 0 0 0 0)
    (rcons (functional_forest_normal_roots f seed ht d secrets auths 12)
      (node (f (functional_forest_last_query seed ht secrets)))).
op functional_forest_recovery_history f h seed ht d secrets auths =
  let last = functional_forest_last_query seed ht secrets in
  let comp = functional_forest_compression f seed ht d secrets auths in
  remember (remember (functional_forest_normal_history f h seed ht d secrets auths 12)
    last (f last)) comp (f comp).

lemma functional_forest_history_zero f h seed ht d secrets auths :
  functional_forest_normal_history f h seed ht d secrets auths 0 = h.
proof. by rewrite /functional_forest_normal_history mkseq0. qed.

lemma functional_forest_history_next f h seed ht d secrets auths t : 0 <= t =>
  functional_forest_normal_history f h seed ht d secrets auths (t+1) =
    functional_fors_recovery_history f
      (functional_forest_normal_history f h seed ht d secrets auths t)
      seed ht t (forest_index d t) (nth (nseq 16 0) secrets t) (nth [] auths t) 11.
proof. by move=> hn; rewrite /functional_forest_normal_history mkseqS 1:hn foldl_rcons. qed.

lemma functional_forest_roots_value f seed ht d secrets auths : backend_width f =>
  forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d) secrets auths =
    rcons (functional_forest_normal_roots f seed ht d secrets auths 12)
      (node (f (functional_forest_last_query seed ht secrets))).
proof.
  move=> hf; rewrite /forest_recover_roots /functional_forest_indices /functional_forest_normal_roots -cats1.
  congr.
  + apply eq_in_mkseq => t hb; smt(nth_mkseq).
  by rewrite /functional_forest_last_query functional_fors_leaf 1:hf.
qed.

lemma fixed_functional_forest_recover f h c key0 seed0 ht0 d0 secrets0 auths0 :
  hoare[CommonInputForest(FixedPrefix).recover :
    seed = seed0 /\ ht = ht0 /\ digest = d0 /\ secrets = secrets0 /\ auths = auths0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = forest_recover_value (interpreted_backend f) seed0 ht0 (functional_forest_indices d0) secrets0 auths0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_forest_recovery_history f h seed0 ht0 d0 secrets0 auths0 /\
    FixedBackend.calls = c+146].
proof.
  proc.
  call (fixed_hash f
    (remember (functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 12)
      (functional_forest_last_query seed0 ht0 secrets0) (f (functional_forest_last_query seed0 ht0 secrets0)))
    (functional_forest_compression f seed0 ht0 d0 secrets0 auths0) (c+145)).
  wp; call (fixed_hash f (functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 12)
    (functional_forest_last_query seed0 ht0 secrets0) (c+144)).
  while (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ secrets = secrets0 /\ auths = auths0 /\
    0 <= t <= 12 /\ roots = functional_forest_normal_roots f seed0 ht0 d0 secrets0 auths0 t /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
    backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 t /\
    FixedBackend.calls = c+12*t).
  + exists* t; elim* => t0; wp.
    call (fixed_functional_fors f (functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 t0)
      (c+12*t0) key0 seed0 ht0 t0 (forest_index d0 t0)
      (nth (nseq 16 0) secrets0 t0) (nth [] auths0 t0)).
    auto => />; rewrite /functional_forest_normal_roots;
      smt(mkseqS functional_forest_history_next).
  auto => />; rewrite /functional_forest_normal_roots mkseq0 functional_forest_history_zero
    /functional_forest_last_query /functional_fors_leaf_query /functional_forest_compression
    /functional_forest_recovery_history /forest_recover_value /forest_compress_value;
    smt(functional_forest_roots_value interpreted_node).
qed.

lemma raw_functional_forest_recover f h c key0 seed0 ht0 d0 secrets0 auths0 :
  equiv[RawForest(PreparationView(FixedPrefix)).recover ~ CommonInputForest(FixedPrefix).recover :
    ={seed,ht,digest,secrets,auths,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ digest{1} = d0 /\ secrets{1} = secrets0 /\ auths{1} = auths0 /\
    0 <= ht0 < 2^32 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = forest_recover_value (interpreted_backend f) seed0 ht0 (functional_forest_indices d0) secrets0 auths0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = functional_forest_recovery_history f h seed0 ht0 d0 secrets0 auths0 /\
    FixedBackend.calls{1} = c+146].
proof.
  conseq (caller_forest_recover FixedPrefix) (_ : true ==> true)
    (fixed_functional_forest_recover f h c key0 seed0 ht0 d0 secrets0 auths0) => //; smt().
qed.

lemma raw_functional_forest_recover_lossless :
  islossless RawForest(PreparationView(FixedPrefix)).recover.
proof. exact (forest_recover_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.

lemma common_functional_fors_recover_lossless :
  islossless CommonInputFors(FixedPrefix).recover.
proof.
  proc; while true (11-h).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  wp; call fixed_hash_ll; auto; smt().
qed.

lemma fixed_functional_forest_recover_lossless :
  islossless CommonInputForest(FixedPrefix).recover.
proof.
  proc; call fixed_hash_ll; wp; call fixed_hash_ll.
  while true (12-t).
  + move=> z; wp; call common_functional_fors_recover_lossless; auto; smt().
  auto; smt().
qed.

(* Whole layer recovery, including rejected WOTS digests, exact prior history,
   all nine subsequent XMSS queries, and full-width verification counters. *)







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

(* Layer signing retains construction and shuffle effects even on exhaustion.
   The intermediate construction map is specified pointwise, not assumed. *)








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

(* One actual forest row: selected secret, complete tree construction and
   recovery, with exact final-map membership and 6156 calls. *)







lemma functional_history_compose f initial middle final prior later :
  functional_history_exact f initial middle prior =>
  functional_history_exact f middle final later =>
  functional_history_exact f initial final (fun x => prior x \/ later x).
proof. rewrite /functional_history_exact; smt(). qed.

op functional_forest_one_secret f key ht tree target =
  fors_secret_value (interpreted_backend f) key ht tree target.
op functional_forest_one_path f key seed ht tree target =
  fors_auth_values (interpreted_backend f) seed key ht tree target.
op functional_forest_one_root f key seed ht tree target =
  fors_recover_value (interpreted_backend f) seed ht tree target
    (functional_forest_one_secret f key ht tree target)
    (functional_forest_one_path f key seed ht tree target).
op functional_forest_one_recovery_queries f key seed ht tree target =
  functional_fors_leaf_query seed ht tree target (functional_forest_one_secret f key ht tree target) ::
  mkseq (functional_tree_query f seed 0 ht 3 tree
    (fors_leaf_value (interpreted_backend f) seed ht tree target
      (functional_forest_one_secret f key ht tree target)) target
    (functional_forest_one_path f key seed ht tree target)) 11.
op functional_forest_one_queried f key seed ht tree target x =
  x = fors_private_preimage key ht tree target \/
  functional_tree_queried (functional_fors_build_queries f key seed ht tree) 11 x \/
  x \in functional_forest_one_recovery_queries f key seed ht tree target.

lemma functional_forest_one_history f initial built key seed ht tree target :
  backend_consistent initial f =>
  functional_history_exact f
    (remember initial (fors_private_preimage key ht tree target) (f (fors_private_preimage key ht tree target)))
    built (functional_tree_queried (functional_fors_build_queries f key seed ht tree) 11) =>
  functional_history_exact f initial
    (functional_fors_recovery_history f built seed ht tree target
      (functional_forest_one_secret f key ht tree target)
      (functional_forest_one_path f key seed ht tree target) 11)
    (functional_forest_one_queried f key seed ht tree target).
proof.
  move=> hc hb.
  have hr := functional_history_remember f initial initial (fun _ => false)
    (fors_private_preimage key ht tree target) hc (functional_history_empty f initial).
  have hm := functional_history_compose f initial _ built _ _ hr hb.
  have hq := functional_history_queries f initial built _
    (functional_forest_one_recovery_queries f key seed ht tree target) hc hm.
  move: hq; rewrite functional_fors_recovery_history_order
    /functional_forest_one_recovery_queries /functional_forest_one_queried /functional_history_exact; smt().
qed.

lemma fixed_functional_forest_one f h c key0 seed0 ht0 tree0 target0 :
  hoare[CommonInputForest(FixedPrefix).one :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ leaf = target0 /\
    fors_fields ht0 tree0 /\ 0 <= target0 < 2^32 /\ backend_width f /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = (functional_forest_one_secret f key0 ht0 tree0 target0,
      functional_forest_one_path f key0 seed0 ht0 tree0 target0,
      functional_forest_one_root f key0 seed0 ht0 tree0 target0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    functional_history_exact f h FixedBackend.history
      (functional_forest_one_queried f key0 seed0 ht0 tree0 target0) /\
    FixedBackend.calls = c+6156].
proof.
  proc; seq 1 : (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ leaf = target0 /\
    sig = fors_sign_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\ backend_width f /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    backend_consistent h f /\ FixedBackend.calls = c+6144 /\
    functional_history_exact f
      (remember h (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0)))
      FixedBackend.history (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11)).
  + call (common_functional_fors_sign f h c key0 seed0 ht0 tree0 target0); auto.
  exists* FixedBackend.history; elim* => built0.
  call (fixed_functional_fors f built0 (c+6144) key0 seed0 ht0 tree0 target0
    (functional_forest_one_secret f key0 ht0 tree0 target0)
    (functional_forest_one_path f key0 seed0 ht0 tree0 target0)).
  auto => />; rewrite /fors_sign_values /functional_forest_one_secret /functional_forest_one_path
    /functional_forest_one_root; smt(functional_forest_one_history).
qed.

(* Positional forest rows and exact queried sets under the actual permutation. *)




op forest_covered ['a] (default : 'a) n (values : 'a list) (value : int -> 'a) order visited =
  size values = n /\ forall j, j \in take visited order => nth default values j = value j.

lemma forest_covered_zero ['a] (default : 'a) n value order : 0 <= n =>
  forest_covered default n (nseq n default) value order 0.
proof. move=> hn; rewrite /forest_covered size_nseq take0; smt(). qed.

lemma forest_covered_next ['a] (default : 'a) n values value order visited :
  12 <= n => perm_eq order (range 0 12) => 0 <= visited < 12 =>
  forest_covered default n values value order visited =>
  forest_covered default n (put values (nth 0 order visited) (value (nth 0 order visited))) value order (visited+1).
proof.
  move=> hn hp hv [hs he].
  have hlen : size order = 12 by smt(perm_eq_size size_range).
  have hi := outer_shuffle_index order visited 12 hp hv.
  rewrite /forest_covered size_put hs /= (take_nth 0 visited order) 1:/#.
  move=> j hj; rewrite nth_put 1:/#; move: hj; rewrite mem_rcons; smt().
qed.

lemma forest_covered_complete ['a] (default : 'a) values value order :
  perm_eq order (range 0 12) => forest_covered default 12 values value order 12 =>
  values = mkseq value 12.
proof.
  move=> hp [hs he].
  have hlen : size order = 12 by smt(perm_eq_size size_range).
  have ht : take 12 order = order by rewrite -hlen take_size.
  apply (eq_from_nth default); first by rewrite hs size_mkseq.
  move=> j hj; rewrite nth_mkseq 1:/#; apply he; rewrite ht; smt(perm_eq_mem mem_range).
qed.

lemma forest_covered_last ['a] (default : 'a) values value order final_value :
  perm_eq order (range 0 12) => forest_covered default 13 values value order 12 =>
  put values 12 final_value = mkseq value 12 ++ [final_value].
proof.
  move=> hp [hs he].
  have hlen : size order = 12 by smt(perm_eq_size size_range).
  have ht : take 12 order = order by rewrite -hlen take_size.
  apply (eq_from_nth default); first by rewrite size_put hs size_cat size_mkseq /=.
  move=> j hj; have hj13 : 0 <= j < 13 by move: hj; rewrite size_put hs.
  rewrite nth_put 1:/# nth_cat size_mkseq /=.
  case (j = 12) => hj12; first by rewrite hj12 /=.
  have hjb : 0 <= j < 12 by smt().
  have hjm : j \in take 12 order by rewrite ht; smt(perm_eq_mem mem_range).
  have hv := he j hjm.
  by rewrite (_ : j < 12) 1:/# nth_mkseq 1:hjb; smt().
qed.

op functional_forest_visited f key seed ht (d : digest) (order : int list) visited x =
  exists t, t \in take visited order /\ functional_forest_one_queried f key seed ht t (forest_index d t) x.
op functional_forest_normal_queried f key seed ht (d : digest) x =
  exists t, 0 <= t < 12 /\ functional_forest_one_queried f key seed ht t (forest_index d t) x.

lemma functional_forest_visited_zero f key seed ht d order x :
  !functional_forest_visited f key seed ht d order 0 x.
proof. rewrite /functional_forest_visited take0; smt(). qed.

lemma functional_forest_visited_next f key seed ht d order visited x : 0 <= visited < size order =>
  functional_forest_visited f key seed ht d order (visited+1) x <=>
    functional_forest_visited f key seed ht d order visited x \/
      functional_forest_one_queried f key seed ht (nth 0 order visited)
        (forest_index d (nth 0 order visited)) x.
proof. move=> hv; rewrite /functional_forest_visited (take_nth 0 visited order hv); smt(mem_rcons). qed.

lemma functional_forest_visited_complete f key seed ht d order x : perm_eq order (range 0 12) =>
  functional_forest_visited f key seed ht d order 12 x <=> functional_forest_normal_queried f key seed ht d x.
proof.
  move=> hp; have hlen : size order = 12 by smt(perm_eq_size size_range).
  rewrite /functional_forest_visited -hlen take_size /functional_forest_normal_queried;
    smt(perm_eq_mem mem_range).
qed.

lemma functional_forest_history_initial f history key seed ht d order :
  functional_history_exact f history history (functional_forest_visited f key seed ht d order 0).
proof. rewrite /functional_history_exact; smt(functional_forest_visited_zero). qed.

lemma functional_forest_history_complete f initial history key seed ht d order :
  perm_eq order (range 0 12) =>
  functional_history_exact f initial history (functional_forest_visited f key seed ht d order 12) =>
  functional_history_exact f initial history (functional_forest_normal_queried f key seed ht d).
proof. rewrite /functional_history_exact; smt(functional_forest_visited_complete). qed.

lemma functional_forest_history_step f initial middle final key seed ht d order visited :
  0 <= visited < size order =>
  functional_history_exact f initial middle (functional_forest_visited f key seed ht d order visited) =>
  functional_history_exact f middle final (functional_forest_one_queried f key seed ht
    (nth 0 order visited) (forest_index d (nth 0 order visited))) =>
  functional_history_exact f initial final (functional_forest_visited f key seed ht d order (visited+1)).
proof.
  move=> hv hm hf.
  have hc := functional_history_compose f initial middle final _ _ hm hf.
  move: hc; rewrite /functional_history_exact; smt(functional_forest_visited_next).
qed.

(* Shared forest values in the positional form used by the actual loop. *)






op functional_forest_final_root f key seed ht =
  fors_root_value (interpreted_backend f) seed key ht 12.

lemma functional_forest_secrets_value f key seed ht d :
  forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d) =
    mkseq (fun t => functional_forest_one_secret f key ht t (forest_index d t)) 12 ++
      [functional_forest_final_root f key seed ht].
proof.
  rewrite /forest_sign_secrets /functional_forest_indices /functional_forest_final_root
    /functional_forest_one_secret.
  congr; apply eq_in_mkseq => t hb; smt(nth_mkseq).
qed.

lemma functional_forest_secrets_finish f key seed ht d secrets order :
  perm_eq order (range 0 12) =>
  forest_covered (nseq 16 0) 13 secrets
    (fun t => functional_forest_one_secret f key ht t (forest_index d t)) order 12 =>
  put secrets 12 (functional_forest_final_root f key seed ht) =
    forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d).
proof.
  move=> hp hc; rewrite functional_forest_secrets_value.
  exact (forest_covered_last (nseq 16 0) secrets _ order _ hp hc).
qed.

lemma functional_forest_paths_value f key seed ht d :
  forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d) =
    mkseq (fun t => functional_forest_one_path f key seed ht t (forest_index d t)) 12.
proof.
  rewrite /forest_sign_paths /functional_forest_indices /functional_forest_one_path.
  apply eq_in_mkseq => t hb; smt(nth_mkseq).
qed.

lemma functional_forest_secret_nth f key seed ht d t : 0 <= t < 12 =>
  nth (nseq 16 0) (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d)) t =
    functional_forest_one_secret f key ht t (forest_index d t).
proof. move=> hb; rewrite functional_forest_secrets_value nth_cat size_mkseq /=; smt(nth_mkseq). qed.

lemma functional_forest_final_nth f key seed ht d :
  nth (nseq 16 0) (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d)) 12 =
    functional_forest_final_root f key seed ht.
proof. by rewrite functional_forest_secrets_value nth_cat size_mkseq /=. qed.

lemma functional_forest_path_nth f key seed ht d t : 0 <= t < 12 =>
  nth [] (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d)) t =
    functional_forest_one_path f key seed ht t (forest_index d t).
proof. move=> hb; by rewrite functional_forest_paths_value nth_mkseq 1:hb. qed.

lemma functional_forest_signed_roots f key seed ht d : backend_width f =>
  forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d)
    (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d))
    (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d)) =
    mkseq (fun t => functional_forest_one_root f key seed ht t (forest_index d t)) 12 ++
      [node (f (functional_fors_leaf_query seed ht 12 0 (functional_forest_final_root f key seed ht)))].
proof.
  move=> hf; rewrite functional_forest_roots_value 1:hf /functional_forest_normal_roots
    /functional_forest_last_query functional_forest_final_nth -cats1.
  congr; apply eq_in_mkseq => t hb.
  rewrite /functional_forest_one_root; smt(functional_forest_secret_nth functional_forest_path_nth).
qed.

lemma functional_forest_roots_finish f key seed ht d roots order : backend_width f =>
  perm_eq order (range 0 12) =>
  forest_covered (nseq 16 0) 13 roots
    (fun t => functional_forest_one_root f key seed ht t (forest_index d t)) order 12 =>
  put roots 12 (node (f (functional_fors_leaf_query seed ht 12 0 (functional_forest_final_root f key seed ht)))) =
    forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d)
      (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d))
      (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d)).
proof.
  move=> hf hp hc; rewrite functional_forest_signed_roots 1:hf.
  exact (forest_covered_last (nseq 16 0) roots _ order _ hp hc).
qed.

lemma functional_forest_result_value f key seed ht d : backend_width f =>
  let secrets = forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d) in
  let paths = forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d) in
  let roots = forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d) secrets paths in
  (secrets,paths,node (f (multi_preimage seed (address_words 0 ht 4 0 0 0 0) roots))) =
    forest_sign_value (interpreted_backend f) seed key ht (functional_forest_indices d).
proof.
  move=> hf; rewrite /forest_sign_value /forest_recover_value /forest_compress_value /=.
  by rewrite interpreted_node 1:hf.
qed.

(* Complete actual shuffled forest signing. Intermediate maps are specified
   pointwise, and the final two remembered queries are explicit. *)









op functional_forest_initial_history f h shuffle =
  let sub = functional_derived_seed f shuffle shuffle_forest_label in
  backend_history f (functional_derive_history f h shuffle shuffle_forest_label)
    (mkseq (shuffle_block_preimage sub) (functional_shuffle_steps sub)).
op functional_forest_initial_cost f shuffle =
  functional_derive_cost shuffle +
    functional_shuffle_steps (functional_derived_seed f shuffle shuffle_forest_label).
op functional_forest_sign_compression f key seed ht d =
  multi_preimage seed (address_words 0 ht 4 0 0 0 0)
    (forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d)
      (forest_sign_secrets (interpreted_backend f) seed key ht (functional_forest_indices d))
      (forest_sign_paths (interpreted_backend f) seed key ht (functional_forest_indices d))).
op functional_forest_sign_state f h final key seed ht d shuffle =
  exists normal built,
    functional_history_exact f (functional_forest_initial_history f h shuffle) normal
      (functional_forest_normal_queried f key seed ht d) /\
    functional_history_exact f normal built
      (functional_tree_queried (functional_fors_build_queries f key seed ht 12) 11) /\
    let q = functional_fors_leaf_query seed ht 12 0 (functional_forest_final_root f key seed ht) in
    let comp = functional_forest_sign_compression f key seed ht d in
    final = remember (remember built q (f q)) comp (f comp).

lemma fixed_functional_forest_sign f h c key0 seed0 ht0 d0 shuffle0 :
  hoare[CommonInputForest(FixedPrefix).sign :
    seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\ 0 <= ht0 < 2^32 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = forest_sign_value (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80017 /\
    functional_forest_sign_state f h FixedBackend.history key0 seed0 ht0 d0 shuffle0].
proof.
  proc; seq 5 : (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\
    0 <= ht0 < 2^32 /\ backend_width f /\
    secrets = nseq 13 (nseq 16 0) /\ auths = nseq 12 (nseq 11 (nseq 16 0)) /\ roots = nseq 13 (nseq 16 0) /\
    order = functional_forest_order f (functional_derived_seed f shuffle0 shuffle_forest_label) /\
    perm_eq order (range 0 12) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_forest_initial_history f h shuffle0 /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0).
  + call (fixed_functional_forest_shuffle f (functional_derive_history f h shuffle0 shuffle_forest_label)
      (c+functional_derive_cost shuffle0) key0 (functional_derived_seed f shuffle0 shuffle_forest_label)).
    call (fixed_functional_derive f h c key0 shuffle0 shuffle_forest_label).
    auto; rewrite /functional_forest_initial_history /functional_forest_initial_cost; smt().
  seq 2 : (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\
    0 <= ht0 < 2^32 /\ backend_width f /\ perm_eq order (range 0 12) /\
    forest_covered (nseq 16 0) 13 secrets (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order 12 /\
    auths = forest_sign_paths (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    forest_covered (nseq 16 0) 13 roots (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order 12 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+73872 /\
    functional_history_exact f (functional_forest_initial_history f h shuffle0) FixedBackend.history
      (functional_forest_normal_queried f key0 seed0 ht0 d0)).
  + while (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ shuffle = shuffle0 /\
      0 <= ht0 < 2^32 /\ backend_width f /\ perm_eq order (range 0 12) /\ 0 <= step <= 12 /\
      forest_covered (nseq 16 0) 13 secrets (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order step /\
      forest_covered (nseq 11 (nseq 16 0)) 12 auths (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order step /\
      forest_covered (nseq 16 0) 13 roots (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order step /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
      FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+6156*step /\
      functional_history_exact f (functional_forest_initial_history f h shuffle0) FixedBackend.history
        (functional_forest_visited f key0 seed0 ht0 d0 order step)).
    - exists* step, order, FixedBackend.history; elim* => step0 order0 history0; wp.
      call (fixed_functional_forest_one f history0 (c+functional_forest_initial_cost f shuffle0+6156*step0)
        key0 seed0 ht0 (nth 0 order0 step0) (forest_index d0 (nth 0 order0 step0))).
      auto => />; rewrite /fors_fields.
      move=> &hr hh0 hh hw hp hs0 hs hss hsv has hav hrs hrv hc he hlt.
      have hn : 0 <= step0 < 12 by smt().
      have hi := outer_shuffle_index order0 step0 12 hp hn.
      have hd := forest_index_range d0 (nth 0 order0 step0).
      have hlen : size order0 = 12 by smt(perm_eq_size size_range).
      have hcs := forest_covered_next (nseq 16 0) 13 secrets{hr}
        (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order0 step0 _ hp hn _.
      + smt().
      + rewrite /forest_covered; smt().
      have hca := forest_covered_next (nseq 11 (nseq 16 0)) 12 auths{hr}
        (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order0 step0 _ hp hn _.
      + smt().
      + rewrite /forest_covered; smt().
      have hcr := forest_covered_next (nseq 16 0) 13 roots{hr}
        (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order0 step0 _ hp hn _.
      + smt().
      + rewrite /forest_covered; smt().
      move: hcs hca hcr; rewrite /forest_covered => hcs hca hcr.
      split; first smt(caller_u32_size).
      move=> _ _ _ _ _ _ history hc' he'.
      have hhist := functional_forest_history_step f (functional_forest_initial_history f h shuffle0)
        history0 history key0 seed0 ht0 d0 order0 step0 _ he he'; first smt().
      smt().
    auto; move=> &hr hpre; split.
    - smt(forest_covered_zero functional_forest_history_initial).
    move=> calls history auths0 roots0 secrets0 step0 hstop hinv.
    have hstep : step0 = 12 by smt().
    subst step0.
    have hp : perm_eq order{hr} (range 0 12) by smt().
    have hpaths : forest_covered (nseq 11 (nseq 16 0)) 12 auths0
      (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order{hr} 12 by smt().
    have hpath_value := forest_covered_complete (nseq 11 (nseq 16 0)) auths0
      (fun t => functional_forest_one_path f key0 seed0 ht0 t (forest_index d0 t)) order{hr} hp hpaths.
    have hhist := functional_forest_history_complete f (functional_forest_initial_history f h shuffle0)
      history key0 seed0 ht0 d0 order{hr} hp _; first smt().
    rewrite (functional_forest_paths_value f key0 seed0 ht0 d0); smt().
  exists* FixedBackend.history; elim* => normal0.
  seq 1 : (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ 0 <= ht0 < 2^32 /\ backend_width f /\
    perm_eq order (range 0 12) /\
    forest_covered (nseq 16 0) 13 secrets (fun t => functional_forest_one_secret f key0 ht0 t (forest_index d0 t)) order 12 /\
    auths = forest_sign_paths (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    forest_covered (nseq 16 0) 13 roots (fun t => functional_forest_one_root f key0 seed0 ht0 t (forest_index d0 t)) order 12 /\
    last = functional_forest_final_root f key0 seed0 ht0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80015 /\
    functional_history_exact f (functional_forest_initial_history f h shuffle0) normal0
      (functional_forest_normal_queried f key0 seed0 ht0 d0) /\
    functional_history_exact f normal0 FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 12) 11)).
  + call (common_functional_fors_root f normal0 (c+functional_forest_initial_cost f shuffle0+73872) key0 seed0 ht0 12).
    auto; rewrite /fors_fields /functional_forest_final_root; smt(caller_u32_size).
  exists* FixedBackend.history; elim* => built0.
  call (fixed_hash f
    (remember built0 (functional_fors_leaf_query seed0 ht0 12 0 (functional_forest_final_root f key0 seed0 ht0))
      (f (functional_fors_leaf_query seed0 ht0 12 0 (functional_forest_final_root f key0 seed0 ht0))))
    (functional_forest_sign_compression f key0 seed0 ht0 d0) (c+functional_forest_initial_cost f shuffle0+80016)).
  wp; call (fixed_hash f built0
    (functional_fors_leaf_query seed0 ht0 12 0 (functional_forest_final_root f key0 seed0 ht0))
    (c+functional_forest_initial_cost f shuffle0+80015)).
  wp; auto => />.
  move=> &hr hh0 hh hf hp hss hsv hrs hrv hc hn hb hq hc1.
  have hs := functional_forest_secrets_finish f key0 seed0 ht0 d0 secrets{hr} order{hr} hp _.
  + rewrite /forest_covered; smt().
  have hr := functional_forest_roots_finish f key0 seed0 ht0 d0 roots{hr} order{hr} hf hp _.
  + rewrite /forest_covered; smt().
  split.
  + rewrite hr /functional_forest_sign_compression; trivial.
  move=> _ hc2; split.
  + rewrite hs /functional_forest_sign_compression.
    exact (functional_forest_result_value f key0 seed0 ht0 d0 hf).
  rewrite /functional_forest_sign_state; exists normal0 built0; smt().
qed.

lemma raw_functional_forest_sign f h c key0 seed0 ht0 d0 shuffle0 :
  equiv[RawForest(PreparationView(FixedPrefix)).sign ~ CommonInputForest(FixedPrefix).sign :
    ={seed,ht,digest,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ digest{1} = d0 /\ shuffle{1} = shuffle0 /\
    0 <= ht0 < 2^32 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = forest_sign_value (interpreted_backend f) seed0 key0 ht0 (functional_forest_indices d0) /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+functional_forest_initial_cost f shuffle0+80017 /\
    functional_forest_sign_state f h FixedBackend.history{1} key0 seed0 ht0 d0 shuffle0].
proof.
  conseq (caller_forest_sign FixedPrefix) (_ : true ==> true)
    (fixed_functional_forest_sign f h c key0 seed0 ht0 d0 shuffle0) => //; smt().
qed.

lemma fixed_functional_forest_one_lossless : islossless CommonInputForest(FixedPrefix).one.
proof.
  proc; call common_functional_fors_recover_lossless;
    call common_functional_fors_sign_lossless; auto.
qed.

lemma fixed_functional_forest_sign_lossless : islossless CommonInputForest(FixedPrefix).sign.
proof.
  proc; call fixed_hash_ll; wp; call fixed_hash_ll; wp;
    call common_functional_fors_root_lossless; wp.
  while true (12-step).
  + move=> z; wp; call fixed_functional_forest_one_lossless; auto; smt().
  wp; call fixed_functional_shuffle_lossless; call fixed_functional_derive_lossless; auto; smt().
qed.

lemma raw_functional_forest_sign_lossless : islossless RawForest(PreparationView(FixedPrefix)).sign.
proof.
  apply (forest_sign_lossless (PreparationView(FixedPrefix)) fixed_hash_ll).
  proc; call fixed_derive_ll; auto.
qed.
