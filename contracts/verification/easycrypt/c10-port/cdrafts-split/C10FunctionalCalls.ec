(* Unary projections for composing fixed-backend callers without executing
   a second copy of their algorithms. The history and cost are not erased. *)
require import AllCore List FMap.
require import C10RawOracle RawSigner RawSignature C10Counter.
require import C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge.
require import C10FunctionalWotsValue C10FunctionalSigner C10FunctionalSignerBytes.
require import C10FunctionalVerifier C10FunctionalVerifierState.
require import C10CallerInputBridge C10FunctionalSignerFinish.

lemma common_fixed_nonce_lossless : islossless CommonInputGrind(FixedPrefix).run.
proof.
  proc; while true (signing_budget-i).
  + move=> z; wp; call fixed_hash_ll; wp; call fixed_derive_ll; auto; smt().
  auto; smt().
qed.

lemma common_fixed_signer_lossless : islossless CommonInputSigner(FixedPrefix).sign.
proof.
  proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call common_fixed_nonce_lossless; auto.
  sp 1; if; auto; call fixed_functional_signer_finish_lossless; auto.
qed.

lemma fixed_signer_call f h c key0 seed0 root0 random0 message0 shuffle0 :
  hoare[RawSigner(FixedPrefix).sign :
    seed = seed0 /\ root = root0 /\ random = random0 /\ message = message0 /\ shuffle = shuffle0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls = c ==>
    res = paired_signer_result (interpreted_backend f) key0 seed0 root0 random0 message0 /\
    omap encode_signature res = paired_signer_bytes (interpreted_backend f) key0 seed0 root0 random0 message0 /\
    (res <> None => signature_width (oget res) /\ size (encode_signature (oget res)) = 4008) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_signer_cost f key0 seed0 root0 random0 message0 shuffle0 /\
    functional_signer_state f h FixedBackend.history key0 seed0 root0 random0 message0 shuffle0].
proof.
  conseq (raw_functional_signer_bytes f h c key0 seed0 root0 random0 message0 shuffle0)
    (_ : true ==> true).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},root{m},random{m},message{m},shuffle{m}); smt().
  smt().
  by conseq common_fixed_signer_lossless.
qed.

lemma fixed_verifier_call f h c key0 seed0 root0 message0 sig0 :
  hoare[RawSigner(FixedPrefix).verify :
    seed = seed0 /\ root = root0 /\ message = message0 /\ sig = sig0 /\ outer_counters sig0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls = c ==>
    res = paired_verifier_result (interpreted_backend f) seed0 root0 message0 sig0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_verifier_history f h seed0 root0 message0 sig0 /\
    FixedBackend.calls = c+functional_verifier_cost f seed0 root0 message0 sig0].
proof.
  conseq (raw_functional_verifier f h c key0 seed0 root0 message0 sig0) (_ : true ==> true).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},root{m},message{m},sig{m}); smt().
  smt().
  by conseq fixed_functional_verifier_lossless.
qed.

lemma fixed_signer_call_total f h c key0 seed0 root0 random0 message0 shuffle0 :
  phoare[RawSigner(FixedPrefix).sign :
    seed = seed0 /\ root = root0 /\ random = random0 /\ message = message0 /\ shuffle = shuffle0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls = c ==>
    res = paired_signer_result (interpreted_backend f) key0 seed0 root0 random0 message0 /\
    omap encode_signature res = paired_signer_bytes (interpreted_backend f) key0 seed0 root0 random0 message0 /\
    (res <> None => signature_width (oget res) /\ size (encode_signature (oget res)) = 4008) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_signer_cost f key0 seed0 root0 random0 message0 shuffle0 /\
    functional_signer_state f h FixedBackend.history key0 seed0 root0 random0 message0 shuffle0] = 1%r.
proof. conseq raw_functional_signer_lossless (fixed_signer_call f h c key0 seed0 root0 random0 message0 shuffle0) => //. qed.

lemma fixed_verifier_call_total f h c key0 seed0 root0 message0 sig0 :
  phoare[RawSigner(FixedPrefix).verify :
    seed = seed0 /\ root = root0 /\ message = message0 /\ sig = sig0 /\ outer_counters sig0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls = c ==>
    res = paired_verifier_result (interpreted_backend f) seed0 root0 message0 sig0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_verifier_history f h seed0 root0 message0 sig0 /\
    FixedBackend.calls = c+functional_verifier_cost f seed0 root0 message0 sig0] = 1%r.
proof. conseq raw_functional_verifier_lossless (fixed_verifier_call f h c key0 seed0 root0 message0 sig0) => //. qed.

lemma fixed_hash_total f h x0 c :
  phoare[FixedBackend.hash :
    FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ x = x0 /\ FixedBackend.calls = c ==>
    res = f x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember h x0 (f x0) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c + 1] = 1%r.
proof. conseq fixed_hash_ll (fixed_hash f h x0 c) => //. qed.
