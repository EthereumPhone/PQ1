(* Combined contracts on actual callers: values, exact history maps, frames and calls. *)
require import AllCore List FMap.
require import C10RawOracle KeygenPrefixes RawKeygen RawFors RawMerkle.
require import C10Representation C10FixedBackend C10FixedCallerBridge C10TreeCallerBridge.
require import C10FunctionalWotsKeygen C10PrivateCallerBridge.
require import C10FunctionalWotsValue C10FunctionalForsRecovery C10FunctionalBuildHistory C10FunctionalBuildCost.
require import C10FunctionalForsBuild C10FunctionalForsBuildHistory.
require import C10FunctionalMerkleBuild C10FunctionalMerkleBuildHistory.

lemma fixed_fors_build_effects f initial c key0 seed0 ht0 tree0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6143].
proof.
  conseq (fixed_fors_raw_tree_history f initial key0 seed0 ht0 tree0)
    (fixed_builder_fors_tree_count c); smt().
qed.

lemma fixed_functional_fors_build f initial c key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res.`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6143].
proof.
  conseq (fixed_fors_raw_tree f key0 seed0 ht0 tree0 target0)
    (fixed_fors_build_effects f initial c key0 seed0 ht0 tree0); smt().
qed.

lemma fixed_functional_fors_root f initial c key0 seed0 ht0 tree0 :
  hoare[RawFors(PreparationView(FixedPrefix)).root :
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
  proc; call (fixed_functional_fors_build f initial c key0 seed0 ht0 tree0 0); auto; smt().
qed.

lemma fixed_merkle_build_effects f initial c key0 seed0 layer0 tree0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151].
proof.
  conseq (fixed_merkle_raw_build_history f initial key0 seed0 layer0 tree0)
    (fixed_builder_merkle_build_count c); smt().
qed.

lemma fixed_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
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
  conseq (fixed_merkle_raw_build f key0 seed0 layer0 tree0 target0)
    (fixed_merkle_build_effects f initial c key0 seed0 layer0 tree0); rewrite /merkle_build_value; smt().
qed.

lemma fixed_functional_merkle_root f initial c key0 seed0 layer0 tree0 :
  hoare[RawKeygen(PreparationView(FixedPrefix)).root :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151].
proof.
  conseq (functional_merkle_root_build_projection (PreparationView(FixedPrefix)))
    (fixed_functional_merkle_build f initial c key0 seed0 layer0 tree0 0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},0); smt().
  rewrite /merkle_build_value; smt().
qed.

lemma fixed_builder_fors_secret_full f initial c key0 ht0 tree0 target0 :
  hoare[PreparationView(FixedPrefix).fors :
    tail = fors_tail ht0 tree0 target0 /\ fors_fields ht0 tree0 /\ 0 <= target0 < 2^32 /\
    backend_width f /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    node res = fors_secret_value (interpreted_backend f) key0 ht0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember initial (fors_private_preimage key0 ht0 tree0 target0)
      (f (fors_private_preimage key0 ht0 tree0 target0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+1].
proof.
  conseq (fixed_builder_fors_secret_history f initial key0 ht0 tree0 target0)
    (fixed_builder_fors_count c); smt().
qed.

lemma fixed_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).sign :
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
  proc; call (fixed_functional_fors_build f (remember initial (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0))) (c+1) key0 seed0 ht0 tree0 target0); wp.
  call (fixed_builder_fors_secret_full f initial c key0 ht0 tree0 target0).
  auto; rewrite /fors_sign_values; smt().
qed.

lemma raw_functional_fors_build f initial c key0 seed0 ht0 tree0 target0 :
  equiv[RawFors(PreparationView(FixedPrefix)).tree ~ CommonInputFors(FixedPrefix).tree :
    ={seed,ht,tree,target,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ tree{1} = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target{1} = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1}.`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res{1}.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+6143].
proof.
  conseq (caller_fors_tree FixedPrefix)
    (fixed_functional_fors_build f initial c key0 seed0 ht0 tree0 target0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_fors_root f initial c key0 seed0 ht0 tree0 :
  equiv[RawFors(PreparationView(FixedPrefix)).root ~ CommonInputFors(FixedPrefix).root :
    ={seed,ht,tree,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ tree{1} = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+6143].
proof.
  conseq (caller_fors_root FixedPrefix)
    (fixed_functional_fors_root f initial c key0 seed0 ht0 tree0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0 :
  equiv[RawFors(PreparationView(FixedPrefix)).sign ~ CommonInputFors(FixedPrefix).sign :
    ={seed,ht,tree,target,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ tree{1} = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target{1} = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = fors_sign_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f (remember initial (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0))) FixedBackend.history{1}
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+6144].
proof.
  conseq (caller_fors_sign FixedPrefix)
    (fixed_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0 :
  equiv[RawMerkle(PreparationView(FixedPrefix)).build ~ CommonInputMerkle(FixedPrefix).build :
    ={seed,layer,tree,target,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    target{1} = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = merkle_build_value (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+177151].
proof.
  conseq (caller_merkle_build FixedPrefix)
    (fixed_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_merkle_root f initial c key0 seed0 layer0 tree0 :
  equiv[RawKeygen(PreparationView(FixedPrefix)).root ~ CommonInputMerkle(FixedPrefix).root :
    ={seed,layer,tree,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+177151].
proof.
  conseq (caller_keygen_root FixedPrefix)
    (fixed_functional_merkle_root f initial c key0 seed0 layer0 tree0) (_ : true ==> true) => //; smt().
qed.

lemma common_functional_fors_tree_lossless : islossless CommonInputFors(FixedPrefix).tree.
proof.
  proc; while true (2048-j).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call fixed_hash_ll; auto; smt(size_behead size_ge0 size_eq0).
    wp; call fixed_hash_ll; wp; call fixed_derive_ll; auto; smt(size_ge0).
  auto; smt().
qed.

lemma common_functional_fors_root_lossless : islossless CommonInputFors(FixedPrefix).root.
proof. proc; call common_functional_fors_tree_lossless; auto. qed.

lemma common_functional_fors_sign_lossless : islossless CommonInputFors(FixedPrefix).sign.
proof. proc; call common_functional_fors_tree_lossless; wp; call fixed_derive_ll; auto. qed.

lemma common_functional_merkle_build_lossless : islossless CommonInputMerkle(FixedPrefix).build.
proof.
  proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call fixed_hash_ll; auto; smt(size_behead size_ge0 size_eq0).
    wp; call fixed_functional_keygen_lossless; auto; smt(size_ge0).
  auto; smt().
qed.

lemma common_functional_merkle_root_lossless : islossless CommonInputMerkle(FixedPrefix).root.
proof.
  proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call fixed_hash_ll; auto; smt(size_behead size_ge0 size_eq0).
    wp; call fixed_functional_keygen_lossless; auto; smt(size_ge0).
  auto; smt().
qed.
