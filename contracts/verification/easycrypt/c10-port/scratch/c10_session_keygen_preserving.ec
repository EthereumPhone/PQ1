require import AllCore List FMap C10RawOracle RawKeygen KeygenPrefixes KeygenExhaustion C10Representation PreparedGrind C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue C10FunctionalBuildContracts C10FunctionalBuildHistory C10FunctionalMerkleBuildHistory C10PairedKeygen.

(* Actual key preparation under one fixed backend. The native public-seed
   totalization and auxiliary inputs remain unchanged; no sampled-key claim. *)







op functional_public_seed (public : digest) = pad_node ((fun d => node d) public).
op functional_public_root (f : raw_input -> digest) (key : raw_input) (public : digest) =
  pad_node (merkle_root_value (interpreted_backend f) (functional_public_seed public) key 1 0).

lemma fixed_functional_key_preparation f initial c key0 public0 random0 message0 :
  hoare[KeygenPreparation(PreparationView(FixedPrefix)).run :
    KeygenInputs.public_seed = public0 /\ KeygenInputs.random = random0 /\ KeygenInputs.message = message0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ backend_width f /\ FixedBackend.calls = c ==>
    res = (random0,message0,functional_public_seed public0,functional_public_root f key0 public0) /\
    KeygenInputs.public_seed = public0 /\ KeygenInputs.random = random0 /\ KeygenInputs.message = message0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 (functional_public_seed public0) 1 0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151].
proof.
  proc; call (fixed_functional_merkle_root f initial c key0 (functional_public_seed public0) 1 0).
  auto => />; rewrite /functional_public_seed /functional_public_root /pad_node /pad;
    smt(paired_keygen_domain).
qed.

lemma raw_functional_key_preparation f initial c key0 public0 random0 message0 :
  equiv[KeygenPreparation(PreparationView(FixedPrefix)).run ~ PairedKeygenPreparation(FixedPrefix).run :
    ={glob KeygenInputs,glob FixedPrefix} /\
    KeygenInputs.public_seed{1} = public0 /\ KeygenInputs.random{1} = random0 /\ KeygenInputs.message{1} = message0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
    ={res,glob KeygenInputs,glob FixedPrefix} /\
    res{1} = (random0,message0,functional_public_seed public0,functional_public_root f key0 public0) /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_merkle_build_queries f key0 (functional_public_seed public0) 1 0) 9) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+177151].
proof.
  conseq (paired_keygen_preparation FixedPrefix)
    (fixed_functional_key_preparation f initial c key0 public0 random0 message0) (_ : true ==> true) => //; smt().
qed.

lemma fixed_key_preparation_lossless : islossless PairedKeygenPreparation(FixedPrefix).run.
proof. proc; call common_functional_merkle_root_lossless; auto. qed.

lemma raw_key_preparation_lossless : islossless KeygenPreparation(PreparationView(FixedPrefix)).run.
proof.
  have [#] hh hw hf := preparation_view_lossless FixedPrefix fixed_hash_ll fixed_derive_ll.
  exact (keygen_preparation_lossless (PreparationView(FixedPrefix)) hh hw hf).
qed.

lemma fixed_functional_key_preparation_total f initial c key0 public0 random0 message0 :
  phoare[KeygenPreparation(PreparationView(FixedPrefix)).run :
    KeygenInputs.public_seed = public0 /\ KeygenInputs.random = random0 /\ KeygenInputs.message = message0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ backend_width f /\ FixedBackend.calls = c ==>
    res = (random0,message0,functional_public_seed public0,functional_public_root f key0 public0) /\
    KeygenInputs.public_seed = public0 /\ KeygenInputs.random = random0 /\ KeygenInputs.message = message0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 (functional_public_seed public0) 1 0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151] = 1%r.
proof. conseq raw_key_preparation_lossless (fixed_functional_key_preparation f initial c key0 public0 random0 message0) => //. qed.
