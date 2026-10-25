require import AllCore List FMap C10RawOracle RawSigner RawSignature RawWrapper WrapperSession KeygenPrefixes KeygenExhaustion C10FunctionalWotsValue C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge C10FunctionalWrapper C10FunctionalObservations C10FunctionalInitialization.

(* The adaptive wrapper context has charged refusals and permits retries.
   This is a fixed-function value equality, not a random-oracle or Rust
   session refinement. Native query effects remain in the unary contract. *)






module FunctionalWrapperValues = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input, ready final_guard : bool) : raw_signature option = {
    return paired_wrapper_result (interpreted_backend FixedBackend.fn)
      FixedPrefix.key seed root random message ready final_guard;
  }
}.

module FunctionalWrapperSession = {
  proc init = WrapperSession(FixedPrefix).init
  proc hash(x : raw_input) : digest = {
    var result; result <- nseq 256 false;
    if (WrapperSession.raw_calls < WrapperSession.raw_limit) {
      result <@ FunctionalValues.hash(x);
      WrapperSession.raw_calls <- WrapperSession.raw_calls+1;
    }
    return result;
  }
  proc sign(random message shuffle_a shuffle_b : raw_input, ready final_guard : bool) : raw_signature option = {
    var result; result <- None;
    if (size message = 32 /\ (size random = 0 \/ size random = 16) /\
        size shuffle_a = 32 /\ size shuffle_b = 32 /\ WrapperSession.sign_calls < WrapperSession.sign_limit) {
      result <@ FunctionalWrapperValues.sign(WrapperSession.seed,WrapperSession.root,
        random,message,shuffle_a,shuffle_b,ready,final_guard);
      if (ready) { WrapperSession.sign_calls <- WrapperSession.sign_calls+1; }
      if (result <> None) { WrapperSession.signed_messages <- rcons WrapperSession.signed_messages message; }
    }
    return result;
  }
}.

module FunctionalWrapperDriver (A : WrapperClient) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FunctionalWrapperSession.init(seed,root,qr,qs);
    forged <@ A(FunctionalWrapperSession).run(seed,root);
    result <- false;
    if (size forged.`1 = 32 /\ signature_width forged.`2 /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ FunctionalValues.verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.

module FunctionalWrapperContext (A : WrapperClient) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ FunctionalKeyPreparation.run();
    result <@ FunctionalWrapperDriver(A).run(inputs.`3,inputs.`4,WrapperLimits.raw_cap,WrapperLimits.sign_cap);
    return result;
  }
}.

module FixedWrapperExperiment (A : WrapperClient) = {
  proc run(fn : raw_input -> digest, key : raw_input) : bool = {
    var result;
    FixedBackend.init(fn); FixedPrefix.key <- key;
    result <@ WrapperContext(A,FixedPrefix).run();
    return result;
  }
}.

module FunctionalWrapperExperiment (A : WrapperClient) = {
  proc run(fn : raw_input -> digest, key : raw_input) : bool = {
    var result;
    FixedBackend.init(fn); FixedPrefix.key <- key;
    result <@ FunctionalWrapperContext(A).run();
    return result;
  }
}.

lemma fixed_functional_wrapper_total f h c key0 seed0 root0 random0 message0 sha0 shb0 ready0 guard0 :
  phoare[RawWrapper(FixedPrefix).sign :
    seed = seed0 /\ root = root0 /\ random = random0 /\ message = message0 /\
      shuffle_a = sha0 /\ shuffle_b = shb0 /\ ready = ready0 /\ final_guard = guard0 /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_width f /\
      backend_consistent FixedBackend.history f /\ FixedBackend.history = h /\ FixedBackend.calls = c ==>
    res = paired_wrapper_result (interpreted_backend f) key0 seed0 root0 random0 message0 ready0 guard0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c + functional_wrapper_cost f key0 seed0 root0 random0 message0 sha0 shb0 ready0 /\
    functional_wrapper_state f h FixedBackend.history key0 seed0 root0 random0 message0 sha0 shb0 ready0] = 1%r.
proof. conseq fixed_functional_wrapper_lossless (fixed_functional_wrapper f h c key0 seed0 root0 random0 message0 sha0 shb0 ready0 guard0) => //. qed.

lemma functional_wrapper_observation f :
  equiv[RawWrapper(FixedPrefix).sign ~ FunctionalWrapperValues.sign :
    ={arg,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc*; inline{2} FunctionalWrapperValues.sign; wp.
  exists* FixedBackend.history{1}, FixedBackend.calls{1}, FixedPrefix.key{1},
    seed{1},root{1},random{1},message{1},shuffle_a{1},shuffle_b{1},ready{1},final_guard{1};
    elim* => h c key0 seed0 root0 random0 message0 sha0 shb0 ready0 guard0.
  call{1} (fixed_functional_wrapper_total f h c key0 seed0 root0 random0 message0 sha0 shb0 ready0 guard0); auto.
qed.

lemma functional_wrapper_session_hash f :
  equiv[WrapperSession(FixedPrefix).hash ~ FunctionalWrapperSession.hash :
    ={arg,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f ==>
    ={res,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; sp 1 1; if; first by auto.
  + wp; call (functional_hash_observation f); auto.
  by auto.
qed.

lemma functional_wrapper_session_sign f :
  equiv[WrapperSession(FixedPrefix).sign ~ FunctionalWrapperSession.sign :
    ={arg,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; sp 1 1; if; first by auto.
  + wp; call (functional_wrapper_observation f); auto.
  by auto.
qed.

lemma functional_wrapper_client f (A <: WrapperClient {-WrapperSession,-FixedPrefix,-FixedBackend}) :
  equiv[A(WrapperSession(FixedPrefix)).run ~ A(FunctionalWrapperSession).run :
    ={arg,glob A,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob A,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc (={glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f) => //.
  + by conseq (functional_wrapper_session_hash f).
  by conseq (functional_wrapper_session_sign f); smt().
qed.

lemma functional_wrapper_driver f (A <: WrapperClient {-WrapperSession,-FixedPrefix,-FixedBackend}) :
  equiv[WrapperDriver(A,FixedPrefix).run ~ FunctionalWrapperDriver(A).run :
    ={arg,glob A,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob A,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; seq 2 2 : (={seed,root,qr,qs,forged,glob A,glob WrapperSession,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_width f /\ backend_consistent FixedBackend.history{1} f).
  + call (functional_wrapper_client f A); inline WrapperSession(FixedPrefix).init; auto.
  sp 1 1; if; first by auto.
  + call (functional_verifier_observation f); auto; smt(functional_signature_counters).
  by auto.
qed.

lemma functional_wrapper_context f
  (A <: WrapperClient {-WrapperSession,-FixedPrefix,-FixedBackend,-WrapperLimits,-KeygenInputs}) :
  equiv[WrapperContext(A,FixedPrefix).run ~ FunctionalWrapperContext(A).run :
    ={glob A,glob WrapperLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob A,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f].
proof.
  proc; call (functional_wrapper_driver f A); call (functional_key_preparation_observation f); auto.
qed.

lemma functional_initialized_wrapper_session f
  (A <: WrapperClient {-WrapperSession,-FixedPrefix,-FixedBackend,-WrapperLimits,-KeygenInputs}) :
  equiv[FixedWrapperExperiment(A).run ~ FunctionalWrapperExperiment(A).run :
    ={arg,glob A,glob WrapperLimits,glob KeygenInputs} /\ fn{1} = f /\ backend_width f ==>
    ={res,glob A,glob WrapperSession,glob WrapperLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f].
proof.
  proc; call (functional_wrapper_context f A); inline FixedBackend.init; auto.
  smt(backend_empty_consistent).
qed.

lemma functional_initialized_wrapper_success_probability f key0
  (A <: WrapperClient {-WrapperSession,-FixedPrefix,-FixedBackend,-WrapperLimits,-KeygenInputs}) &m :
  backend_width f =>
  Pr[FixedWrapperExperiment(A).run(f,key0) @ &m : res] =
  Pr[FunctionalWrapperExperiment(A).run(f,key0) @ &m : res].
proof.
  move=> hf; byequiv (functional_initialized_wrapper_session f A) => //.
qed.

lemma functional_wrapper_session_sign_lossless : islossless FunctionalWrapperSession.sign.
proof. proc; inline FunctionalWrapperValues.sign; auto. qed.

lemma functional_wrapper_session_hash_lossless : islossless FunctionalWrapperSession.hash.
proof. proc; inline FunctionalValues.hash; auto. qed.

lemma functional_wrapper_driver_lossless (A <: WrapperClient {-WrapperSession,-FixedPrefix,-FixedBackend}) :
  (forall (V <: WrapperClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless FunctionalWrapperDriver(A).run.
proof.
  move=> ha; proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (ha FunctionalWrapperSession functional_wrapper_session_hash_lossless functional_wrapper_session_sign_lossless).
    inline WrapperSession(FixedPrefix).init; auto.
  sp 1; if; auto; call functional_value_verify_lossless; auto.
qed.

lemma functional_initialized_wrapper_lossless
  (A <: WrapperClient {-WrapperSession,-FixedPrefix,-FixedBackend,-WrapperLimits,-KeygenInputs}) :
  (forall (V <: WrapperClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless FunctionalWrapperExperiment(A).run.
proof.
  move=> ha; proc; inline FunctionalWrapperContext(A).run.
  wp; call (functional_wrapper_driver_lossless A ha).
  inline FunctionalKeyPreparation.run FixedBackend.init; auto.
qed.
