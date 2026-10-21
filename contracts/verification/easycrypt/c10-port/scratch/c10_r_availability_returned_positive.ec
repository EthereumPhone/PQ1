require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import PreparedGrind.
require import RawSigner RawSignature FullSession RObservedSigner FullRSession FullRBound.
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import PreparedGrind.
require import RawSigner RawSignature FullSession RObservedSigner FullRSession FullRBound.
require import FullRGame FullRGame.

module ControlledRAvailability (A : FullClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var result;
    result <@ FullRContext(A,O).run();
    return RFailure.bad;
  }
}.

lemma checked (A <: FullClient) (O <: PrefixOracle) :
  hoare[ControlledRAvailability(A,O).run : true ==> res = RFailure.bad].
proof. proc; call (_ : true); auto. qed.
