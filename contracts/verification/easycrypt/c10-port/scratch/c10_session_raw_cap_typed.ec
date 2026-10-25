require import AllCore List FMap C10RawOracle RawSigner RawSignature RawDecode FullSession ByteSession C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge C10FunctionalObservations C10FunctionalSignatureBytes C10Representation C10RepresentationBridge KeygenPrefixes KeygenExhaustion C10FunctionalKeygen.

module FunctionalSession = {
  proc init = FullSession(FixedPrefix).init
  proc hash(x : raw_input) : digest = {
    var result; result <- nseq 256 false;
    if (FullSession.raw_calls <= FullSession.raw_limit) {
      result <@ FunctionalValues.hash(x);
      FullSession.raw_calls <- FullSession.raw_calls+1;
    }
    return result;
  }
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\
        (size random = 0 \/ size random = 16) /\ size shuffle = 32 /\
        FullSession.sign_calls < FullSession.sign_limit) {
      result <@ FunctionalValues.sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) {
        FullSession.signed_messages <- rcons FullSession.signed_messages message;
      } else { FullSession.failed <- true; }
    }
    return result;
  }
}.

module FunctionalByteView = {
  proc hash = FunctionalSession.hash
  proc sign(random message shuffle : raw_input) : raw_input option = {
    var s, result; result <- None;
    if (byte_values random /\ byte_values message /\ byte_values shuffle) {
      s <@ FunctionalSession.sign(random,message,shuffle);
      if (s <> None) { result <- Some (paired_signature_bytes (oget s)); }
    }
    return result;
  }
}.

module FunctionalByteDriver (A : ByteClient) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FunctionalSession.init(seed,root,qr,qs);
    forged <@ A(FunctionalByteView).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ byte_values forged.`1 /\
        byte_signature forged.`2 /\ !List.mem FullSession.signed_messages forged.`1) {
      result <@ FunctionalValues.verify(seed,root,forged.`1,word_decode forged.`2);
    }
    return result;
  }
}.

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
