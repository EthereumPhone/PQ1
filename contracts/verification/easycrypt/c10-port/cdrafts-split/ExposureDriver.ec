(* Exact projection of the passive log onto the existing full and byte games. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawSigner RawSignature FullSession ByteSession ExposureLog.

module ExposureDriver (A : FullClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullSession(O).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    forged <@ A(ExposureSession(O)).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module ExposureContext (A : FullClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ ExposureDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

lemma exposure_driver_projection
  (A <: FullClient {-FullSession,-ExposureLog}) (O <: PrefixOracle {-A,-FullSession,-ExposureLog}) :
  equiv [FullDriver(A,O).run ~ ExposureDriver(A,O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob FullSession}].
proof.
  proc; seq 2 3 : (={seed,root,forged,glob A,glob O,glob FullSession}).
  + call (exposure_client_projection A O); wp; inline FullSession(O).init; auto.
  sp 1 1; if; auto; call (_ : ={glob O}); first by sim.
  auto.
qed.
lemma exposure_context_projection
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog}) :
  equiv [FullContext(A,O).run ~ ExposureContext(A,O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==> ={res,glob A,glob O,glob FullSession}].
proof.
  proc; call (exposure_driver_projection A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.
lemma byte_exposure_context_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog}) :
  equiv [ByteContext(A,O).run ~ ExposureContext(ByteLift(A),O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==> ={res,glob A,glob O,glob FullSession}].
proof.
  transitivity FullContext(ByteLift(A),O).run
    (={glob A,glob O,glob FullLimits,glob KeygenInputs} ==> ={res,glob A,glob O,glob FullSession})
    (={glob A,glob O,glob FullLimits,glob KeygenInputs} ==> ={res,glob A,glob O,glob FullSession}).
  + smt().
  + smt().
  + exact (byte_context_equiv A O).
  exact (exposure_context_projection (ByteLift(A)) O).
qed.
lemma byte_exposure_game_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) :
  equiv [IndependentGame(ByteContext(A)).run ~ IndependentGame(ExposureContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==> ={res,glob A,glob Independent,glob FullSession}].
proof.
  proc; call (byte_exposure_context_projection A Independent); inline Independent.init; auto.
qed.
lemma byte_exposure_probability
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) &m :
  Pr[IndependentGame(ByteContext(A)).run() @ &m : res] =
  Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m : res].
proof. byequiv (byte_exposure_game_projection A) => //. qed.
