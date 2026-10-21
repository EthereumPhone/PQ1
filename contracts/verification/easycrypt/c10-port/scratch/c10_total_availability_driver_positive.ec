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
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullRSession(O).init(seed,root,qr,qs);
    forged <@ A(FullRSession(O)).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.

lemma checked
    (A <: FullClient {-FullSession,-RFailure,-Physical,-Shared}) seed0 :
  hoare[ControlledTotalAvailability(A,Physical).run : seed=seed0 ==>
    FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad].
proof.
  proc; seq 2 : (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad).
  + call (full_availability_client A seed0).
    inline FullRSession(Physical).init FullSession(Physical).init; auto.
  sp 1; if; last by auto.
  call (_ : true ==> true); first by trivial.
  auto.
qed.
