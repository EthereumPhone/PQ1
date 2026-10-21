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
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullRSession(O).init(seed,root,qr,qs);
    forged <@ A(FullRSession(O)).run(seed,root);
    result <- false;
    if (true /\ size forged.`1 = 32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.

lemma checked (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure}) :
  equiv[FullDriver(A,O).run ~ ControlledRAvailability(A,O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob FullSession,glob O}].
proof.
  proc; seq 2 2 : (={seed,root,qr,qs,forged,glob A,glob FullSession,glob O}).
  + call (full_r_client_erases A O); call (full_r_init_erases O); auto.
  sp 1 1; if; first by auto.
  + call (_ : ={glob O}); first by sim.
    auto.
  by auto.
qed.
