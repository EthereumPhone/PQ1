require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawSigner FullSession RObservedSigner.
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen RawSigner PersistentGrind AcceptedContexts KeygenPrefixes KeygenExhaustion.
require import FullSession RObservedSigner FullRSession FullRGame.
require import WotsRejectDomain WotsPhysicalFailure WotsSignerFailure.
require import FullRSession FullAvailabilityTrace.

module ControlledTotalAvailability (O : PrefixOracle) = {
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
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) {
        FullSession.signed_messages <- rcons FullSession.signed_messages message;
      } else { FullSession.failed <- true; RFailure.bad <- false; }
    }
    return result;
  }
}.

