(* Paired computations through the actual adaptive byte session. The comparison
   shares the original session state and preserves admission, failure and the
   returned-message ledger. This is an EasyCrypt relation, not a Rust theorem. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawSigner RawSignature RawDecode FullSession ByteSession.
require import C10OuterCallerBridge C10SearchAcceptance C10DigestCallers.

module PairedSession (O : PrefixOracle) = {
  proc init = FullSession(O).init
  proc hash = FullSession(O).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\
        (size random = 0 \/ size random = 16) /\ size shuffle = 32 /\
        FullSession.sign_calls <= FullSession.sign_limit) {
      result <@ PairedDigestSigner(O).sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) {
        FullSession.signed_messages <- rcons FullSession.signed_messages message;
      } else { FullSession.failed <- true; }
    }
    return result;
  }
}.

module PairedByteDriver (A : ByteClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    PairedSession(O).init(seed,root,qr,qs);
    forged <@ A(ByteView(PairedSession(O))).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ byte_values forged.`1 /\
        byte_signature forged.`2 /\ !List.mem FullSession.signed_messages forged.`1) {
      result <@ PairedDigestSigner(O).verify(seed,root,forged.`1,decode_signature forged.`2);
    }
    return result;
  }
}.

module PairedByteContext (A : ByteClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ PairedByteDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.
