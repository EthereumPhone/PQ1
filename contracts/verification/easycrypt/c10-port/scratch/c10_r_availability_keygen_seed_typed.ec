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
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ FullRDriver(A,O).run(inputs.`4,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

