(* Cost bounds for the explicit wrapper context. The internal verifier is
   charged per admitted attempt and the final candidate verifier once more.
   Refused attempts are counted without requiring successful release.
   These lemmas do not instantiate a cryptographic reduction for this context. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrindCost KeygenExhaustion.
require import RawSigner RawSignerCost RawWrapper RawWrapperCost.
(* Adaptive cost context for the abstract wrapper schedule. Every admitted
   attempt is charged, including refusals; later attempts may still run.
   Caller-selected guard booleans only overapproximate environment outcomes.
   All queries share one persistent oracle. No EUF or Rust/session refinement
   theorem follows from this accounting context. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind.
require import RawWrapper.
require import KeygenExhaustion RawSigner RawSignature.

module WrapperLimits = { var raw_cap, sign_cap : int }.
module type WrapperClientOracle = {
  proc hash(x : raw_input) : digest
  proc sign(random message shuffle_a shuffle_b : raw_input, ready final_guard : bool) : raw_signature option
}.
module type WrapperClient (O : WrapperClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_signature { O.hash, O.sign }
}.
module WrapperSession (O : PrefixOracle) = {
  var seed, root : raw_input
  var raw_limit, sign_limit, raw_calls, sign_calls : int
  var signed_messages : raw_input list
  proc init(ps pr : raw_input, qr qs : int) : unit = {
    seed <- ps; root <- pr; raw_limit <- qr; sign_limit <- qs;
    raw_calls <- 0; sign_calls <- 0; signed_messages <- [];
  }
  proc hash(x : raw_input) : digest = {
    var result; result <- nseq 256 false;
    if (raw_calls < raw_limit) {
      result <@ O.hash(x); raw_calls <- raw_calls+1;
    }
    return result;
  }
  proc sign(random message shuffle_a shuffle_b : raw_input, ready final_guard : bool) : raw_signature option = {
    var result; result <- None;
    if (size message = 32 /\ (size random = 0 \/ size random = 16) /\
        size shuffle_a = 32 /\ size shuffle_b = 32 /\ true) {
      result <@ RawWrapper(O).sign(seed,root,random,message,shuffle_a,shuffle_b,ready,final_guard);
      sign_calls <- sign_calls+1;
      if (result <> None) { signed_messages <- rcons signed_messages message; }
    }
    return result;
  }
}.
module WrapperDriver (A : WrapperClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    WrapperSession(O).init(seed,root,qr,qs);
    forged <@ A(WrapperSession(O)).run(seed,root);
    result <- false;
    if (size forged.`1 = 32 /\ signature_width forged.`2 /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module WrapperContext (A : WrapperClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ WrapperDriver(A,O).run(inputs.`3,inputs.`4,WrapperLimits.raw_cap,WrapperLimits.sign_cap);
    return result;
  }
}.

(* Full caps and a refused readiness check are explicit normal-return cases. *)

(* Admission charges an attempt even when the wrapper refuses. These exact
   counter facts are separate from the larger hash-query arithmetic. *)



