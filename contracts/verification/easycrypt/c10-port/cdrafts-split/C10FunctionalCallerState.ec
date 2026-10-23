(* Transfer existing actual construction contracts to their checked paired callers. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawFors RawMerkle KeygenPrefixes C10Representation.
require import C10TreeCallerBridge C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue C10FunctionalForsRecovery.
require import C10FunctionalBuildContracts C10FunctionalBuildHistory.
require import C10FunctionalForsBuildHistory C10FunctionalMerkleBuildHistory.

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
