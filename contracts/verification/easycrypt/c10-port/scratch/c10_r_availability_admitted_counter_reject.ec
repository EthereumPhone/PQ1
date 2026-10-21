require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner FullSession RObservedSigner.
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner FullSession RObservedSigner.
require import FullRSession FullRSession.

module ControlledRAvailability (O : PrefixOracle) = {
  proc init(ps pr : raw_input, qr qs : int) : unit = {
    FullSession(O).init(ps,pr,qr,qs);
    RFailure.bad <- false;
  }
  proc hash = FullSession(O).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\
        (size random = 0 \/ size random = 16) /\ size shuffle = 32 /\
        FullSession.sign_calls < FullSession.sign_limit) {
      result <@ RObservedSigner(O).sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+0;
      if (result <> None) {
        FullSession.signed_messages <- rcons FullSession.signed_messages message;
      } else { FullSession.failed <- true; }
    }
    return result;
  }
}.

lemma checked (O <: PrefixOracle {-FullSession,-RFailure}) :
  equiv[FullSession(O).sign ~ ControlledRAvailability(O).sign :
    ={arg,glob FullSession,glob O} ==> ={res,glob FullSession,glob O}].
proof.
  proc; sp 1 1; if; first by auto.
  + by wp; call (r_observed_sign_erases O); auto => />.
  by auto.
qed.
