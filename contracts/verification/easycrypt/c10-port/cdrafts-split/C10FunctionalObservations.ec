(* Observable values of the actual native calls under a fixed backend.
   The left execution retains its history; the right is a pure value model.
   Unary contracts separately retain exact executed-prefix cost and history. *)
require import AllCore List FMap.
require import C10RawOracle RawSigner RawSignature KeygenPrefixes.
require import C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge.
require import C10FunctionalWotsValue C10FunctionalSigner C10FunctionalSignerBytes.
require import C10FunctionalVerifier C10FunctionalCalls.

module FunctionalValues = {
  proc hash(x : raw_input) : digest = { return FixedBackend.fn x; }
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    return paired_signer_result (interpreted_backend FixedBackend.fn)
      FixedPrefix.key seed root random message;
  }
  proc verify(seed root message : raw_input, sig : raw_signature) : bool = {
    return paired_verifier_result (interpreted_backend FixedBackend.fn) seed root message sig;
  }
}.

lemma functional_hash_observation f :
  equiv[FixedBackend.hash ~ FunctionalValues.hash :
    ={x,FixedBackend.fn} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f ==>
    ={res,FixedBackend.fn} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc*; inline{2} FunctionalValues.hash; wp.
  exists* FixedBackend.history{1}, FixedBackend.calls{1}, x{1}; elim* => h c x0.
  call{1} (fixed_hash_total f h x0 c); auto.
qed.

lemma functional_signer_observation f :
  equiv[RawSigner(FixedPrefix).sign ~ FunctionalValues.sign :
    ={arg,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\
    (res{1} <> None => signature_width (oget res{1}))].
proof.
  proc*; inline{2} FunctionalValues.sign; wp.
  exists* FixedBackend.history{1}, FixedBackend.calls{1}, FixedPrefix.key{1},
    seed{1},root{1},random{1},message{1},shuffle{1}; elim* => h c key0 seed0 root0 random0 message0 shuffle0.
  call{1} (fixed_signer_call_total f h c key0 seed0 root0 random0 message0 shuffle0); auto; smt().
qed.

lemma functional_verifier_observation f :
  equiv[RawSigner(FixedPrefix).verify ~ FunctionalValues.verify :
    ={arg,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    outer_counters sig{1} /\ backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc*; inline{2} FunctionalValues.verify; wp.
  exists* FixedBackend.history{1}, FixedBackend.calls{1}, FixedPrefix.key{1},
    seed{1},root{1},message{1},sig{1}; elim* => h c key0 seed0 root0 message0 sig0.
  call{1} (fixed_verifier_call_total f h c key0 seed0 root0 message0 sig0); auto.
qed.

lemma functional_value_sign_lossless : islossless FunctionalValues.sign.
proof. proc; auto. qed.
lemma functional_value_verify_lossless : islossless FunctionalValues.verify.
proof. proc; auto. qed.
