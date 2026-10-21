require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import PreparedGrind.
require import RawSigner RawSignature FullSession RObservedSigner FullRSession FullRBound.
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen RawSigner PersistentGrind AcceptedContexts KeygenPrefixes KeygenExhaustion.
require import FullSession RObservedSigner FullRSession FullRGame.
require import WotsRejectDomain WotsPhysicalFailure WotsSignerFailure.
require import FullRGame FullAvailabilityTrace.

module ControlledTotalAvailability (A : FullClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ FullRDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

lemma checked
    (A <: FullClient {-FullSession,-RFailure,-Physical,-Shared,-FullLimits,-KeygenInputs}) seed0 :
  hoare[ControlledTotalAvailability(A,Physical).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad].
proof.
  proc; call (full_availability_driver A seed0).
  inline KeygenPreparation(PreparationView(Physical)).run; wp.
  call (_ : true ==> true); first by trivial.
  auto.
qed.
