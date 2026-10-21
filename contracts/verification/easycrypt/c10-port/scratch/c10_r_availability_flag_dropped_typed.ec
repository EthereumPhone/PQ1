require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RoleGrindCost RawSigner.
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RawSigner.
require import RawTrial ClassifiedHistory GrindExhaustion RClassifiedExhaustion RObservedSigner.
import RealOrder.
require import RObservedSigner RObservedExhaustion.

module ControlledRAvailability (O : PrefixOracle) = {
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    RFailure.bad <- false;
    result <- None;
    if (accepted <> None) {
      result <@ RawSigner(O).finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.

