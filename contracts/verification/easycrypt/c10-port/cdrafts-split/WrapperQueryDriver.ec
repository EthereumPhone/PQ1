(* Passive released-output/query observers for the actual initialized wrapper
   game. Projection preserves every original result and all wrapper/oracle
   state, including refusal charges and later retries. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawSigner RawSignature WrapperSession WrapperLossless WrapperByteSession.
require import ExposureLog ClientQueryLog WrapperExposureLog.

module WrapperQueryDriver (A : WrapperClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    WrapperSession(O).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    ClientQueryLog.inputs <- [];
    ClientQueryLog.output <- ([],([],[],[],[]));
    forged <@ A(WrapperQueryExposureSession(O)).run(seed,root);
    ClientQueryLog.output <- forged;
    result <- false;
    if (size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module WrapperQueryContext (A : WrapperClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ WrapperQueryDriver(A,O).run(inputs.`3,inputs.`4,
      WrapperLimits.raw_cap,WrapperLimits.sign_cap);
    return result;
  }
}.

lemma wrapper_query_driver_projection
    (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
    (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  equiv[WrapperDriver(A,O).run ~ WrapperQueryDriver(A,O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob WrapperSession}].
proof.
  proc; seq 2 5 : (={seed,root,forged,glob A,glob O,glob WrapperSession}).
  + call (wrapper_logged_client_projection A O); wp; inline WrapperSession(O).init; auto.
  sp 1 2; if; auto; call (_ : ={glob O}); first by sim.
  auto.
qed.

lemma wrapper_query_context_projection
    (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
    (O <: PrefixOracle {-A,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  equiv[WrapperContext(A,O).run ~ WrapperQueryContext(A,O).run :
    ={glob A,glob O,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob WrapperSession}].
proof.
  proc; call (wrapper_query_driver_projection A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.

lemma wrapper_query_game_projection
    (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,
      -ExposureLog,-ClientQueryLog,-Independent}) :
  equiv[IndependentGame(WrapperContext(A)).run ~
      IndependentGame(WrapperQueryContext(A)).run :
    ={glob A,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob Independent,glob WrapperSession}].
proof.
  proc; call (wrapper_query_context_projection A Independent); inline Independent.init; auto.
qed.

lemma wrapper_byte_query_probability
    (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,
      -ExposureLog,-ClientQueryLog,-Independent}) &m :
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] =
    Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res].
proof.
  have h1 : Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] =
      Pr[IndependentGame(WrapperContext(WrapperByteLift(A))).run() @ &m : res].
  + byequiv (_ : ={glob A,glob WrapperLimits,glob KeygenInputs} ==> ={res}) => //.
    proc; call (wrapper_byte_context_equiv A Independent); inline Independent.init; auto.
  have h2 : Pr[IndependentGame(WrapperContext(WrapperByteLift(A))).run() @ &m : res] =
      Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m : res]
    by byequiv (wrapper_query_game_projection (WrapperByteLift(A))) => //.
  smt().
qed.
