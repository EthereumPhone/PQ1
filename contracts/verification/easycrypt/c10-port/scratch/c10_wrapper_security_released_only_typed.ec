(* Private observers for the existing wrapper. Internal signing results are
   not exposure entries: an entry is appended only when the wrapper releases
   its result to the adaptive client. Hash logs record admitted client calls. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner RawSignature.
require import WrapperSession WrapperLossless ExposureLog ClientQueryLog.

module WrapperExposureSession (O : PrefixOracle) = {
  proc hash = WrapperSession(O).hash
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var result;
    result <@ WrapperSession(O).sign(random,message,shuffle_a,shuffle_b,ready,final_guard);
    if (true) { ExposureLog.entries <- rcons ExposureLog.entries (message,oget result); }
    return result;
  }
}.
module WrapperQueryExposureSession (O : PrefixOracle) = {
  proc hash(x : raw_input) : digest = {
    var result;
    if (WrapperSession.raw_calls < WrapperSession.raw_limit) {
      ClientQueryLog.inputs <- rcons ClientQueryLog.inputs x;
    }
    result <@ WrapperSession(O).hash(x);
    return result;
  }
  proc sign = WrapperExposureSession(O).sign
}.

