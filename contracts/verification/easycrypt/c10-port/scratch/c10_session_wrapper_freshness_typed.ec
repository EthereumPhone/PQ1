require import AllCore List FMap C10RawOracle RawSigner RawSignature RawWrapper WrapperSession KeygenPrefixes KeygenExhaustion C10FunctionalWotsValue C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge C10FunctionalWrapper C10FunctionalObservations C10FunctionalInitialization.

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
      WrapperSession.sign_calls <- WrapperSession.sign_calls+1;
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
        List.mem WrapperSession.signed_messages forged.`1) {
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
