(* Initialized adaptive byte-session equality under the same fixed backend.
   The backend and secret are explicit inputs, not a sampled random oracle.
   No valid-history or successful-signing premise is required after init. *)
require import AllCore List FMap.
require import C10RawOracle KeygenPrefixes KeygenExhaustion FullSession ByteSession.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalKeygen C10FunctionalSession.

module FunctionalKeyPreparation = {
  proc run() : raw_input * raw_input * raw_input * raw_input = {
    return (KeygenInputs.random,KeygenInputs.message,
      functional_public_seed KeygenInputs.public_seed,
      functional_public_root FixedBackend.fn FixedPrefix.key KeygenInputs.public_seed);
  }
}.

module FunctionalByteContext (A : ByteClient) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ FunctionalKeyPreparation.run();
    result <@ FunctionalByteDriver(A).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

module FixedByteExperiment (A : ByteClient) = {
  proc run(fn : raw_input -> digest, key : raw_input) : bool = {
    var result;
    FixedBackend.init(fn); FixedPrefix.key <- key;
    result <@ ByteContext(A,FixedPrefix).run();
    return result;
  }
}.

module FunctionalByteExperiment (A : ByteClient) = {
  proc run(fn : raw_input -> digest, key : raw_input) : bool = {
    var result;
    FixedBackend.init(fn); FixedPrefix.key <- key;
    result <@ FunctionalByteContext(A).run();
    return result;
  }
}.

lemma functional_key_preparation_observation f :
  equiv[KeygenPreparation(PreparationView(FixedPrefix)).run ~ FunctionalKeyPreparation.run :
    ={glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc*; inline{2} FunctionalKeyPreparation.run; wp.
  exists* FixedBackend.history{1}, FixedBackend.calls{1}, FixedPrefix.key{1},
    KeygenInputs.public_seed{1},KeygenInputs.random{1},KeygenInputs.message{1};
    elim* => h c key0 public0 random0 message0.
  call{1} (fixed_functional_key_preparation_total f h c key0 public0 random0 message0); auto.
qed.

lemma functional_byte_context f
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) :
  equiv[ByteContext(A,FixedPrefix).run ~ FunctionalByteContext(A).run :
    ={glob A,glob FullLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_width f /\ backend_consistent FixedBackend.history{1} f ==>
    ={res,glob A,glob FullSession,glob FullLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f].
proof.
  proc; call (functional_byte_driver f A); call (functional_key_preparation_observation f); auto.
qed.

lemma functional_initialized_byte_session f
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) :
  equiv[FixedByteExperiment(A).run ~ FunctionalByteExperiment(A).run :
    ={arg,glob A,glob FullLimits,glob KeygenInputs} /\ fn{1} = f /\ backend_width f ==>
    ={res,glob A,glob FullSession,glob FullLimits,glob KeygenInputs,FixedBackend.fn,FixedPrefix.key} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f].
proof.
  proc; call (functional_byte_context f A); inline FixedBackend.init; auto => />.
  by move=> _; apply backend_empty_consistent.
qed.

lemma functional_initialized_success_probability f key0
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) &m :
  backend_width f =>
  Pr[FixedByteExperiment(A).run(f,key0) @ &m : res] =
  Pr[FunctionalByteExperiment(A).run(f,key0) @ &m : res].
proof.
  move=> hf; byequiv (functional_initialized_byte_session f A) => //.
qed.

lemma functional_initialized_lossless
  (A <: ByteClient {-FullSession,-FixedPrefix,-FixedBackend,-FullLimits,-KeygenInputs}) :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless FunctionalByteExperiment(A).run.
proof.
  move=> ha; proc; inline FunctionalByteContext(A).run.
  wp; call (functional_byte_driver_lossless A ha).
  inline FunctionalKeyPreparation.run FixedBackend.init; auto.
qed.
