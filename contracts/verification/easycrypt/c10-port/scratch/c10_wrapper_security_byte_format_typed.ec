require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion PreparedGrind.
require import RawSigner RawSignature RawDecode ByteSession.
require import WrapperSession WrapperLossless.
require import WrapperByteSession.

module WrapperByteGuardControl (A : WrapperByteClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    WrapperSession(O).init(seed,root,qr,qs);
    forged <@ A(WrapperByteView(WrapperSession(O))).run(seed,root);
    result <- false;
    if (size forged.`1 = 32 /\ byte_values forged.`1 /\ true /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,decode_signature forged.`2);
    }
    return result;
  }
}.

