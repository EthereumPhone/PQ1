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
    result <@ FullRDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap+0,FullLimits.sign_cap+0);
    return result;
  }
}.

lemma checked (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure,-FullLimits,-KeygenInputs}) :
  equiv[FullContext(A,O).run ~ ControlledRAvailability(A,O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession}].
proof.
  proc; call (full_r_driver_erases A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.
