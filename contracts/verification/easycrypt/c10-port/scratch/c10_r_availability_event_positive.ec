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
    RFailure.bad <- RFailure.bad \/ accepted = None;
    result <- None;
    if (accepted <> None) {
      result <@ RawSigner(O).finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.

lemma checked (O <: PrefixOracle {-RFailure}) :
  islossless O.hash => islossless O.derive =>
  equiv[ROnlyFailure(O).run ~ ControlledRAvailability(O).sign :
    ={arg,glob O} /\ !RFailure.bad{2} ==> res{1} = RFailure.bad{2}].
proof.
  move=> hh hd; proc; seq 1 1 : (={accepted} /\ !RFailure.bad{2}).
  + call (_ : ={glob O}); first by sim.
    auto.
  sp 0 2; if{2}.
  + by call{2} (signer_finish_lossless O hh hd); auto => />.
  by auto => />.
qed.
