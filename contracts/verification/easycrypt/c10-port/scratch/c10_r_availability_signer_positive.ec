require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RoleGrindCost RawSigner.
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RoleGrindCost RawSigner.
require import RObservedSigner RObservedSigner.

module ControlledRAvailability (O : PrefixOracle) = {
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    RFailure.bad <- RFailure.bad \/ accepted = None;
    result <- None;
    if (accepted <> None) {
      result <@ RawSigner(O).finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.

lemma checked (O <: PrefixOracle {-RFailure}) :
  equiv[RawSigner(O).sign ~ ControlledRAvailability(O).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof. by proc; sim. qed.
