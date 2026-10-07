(* Exact original-game projection with client-only inputs and the final output. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawSigner RawSignature FullSession ByteSession ExposureLog ExposureDriver ClientQueryLog.

module ClientQueryDriver (A : FullClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullSession(O).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    ClientQueryLog.inputs <- [];
    ClientQueryLog.output <- ([],([],[],[],[]));
    forged <@ A(QueryExposureSession(O)).run(seed,root);
    ClientQueryLog.output <- forged;
    result <- false;
    if (!FullSession.failed /\ size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module ClientQueryContext (A : FullClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ ClientQueryDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

lemma client_query_driver_projection
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [ExposureDriver(A,O).run ~ ClientQueryDriver(A,O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob FullSession,glob ExposureLog}].
proof.
  proc; seq 3 6 : (={seed,root,forged,glob A,glob O,glob FullSession,glob ExposureLog}).
  + wp; call (client_query_client_projection A O); wp; inline FullSession(O).init; auto.
  sp 1 1; if; auto; call (_ : ={glob O}); first by sim.
  auto.
qed.

lemma client_query_context_projection
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  equiv [ExposureContext(A,O).run ~ ClientQueryContext(A,O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog}].
proof.
  proc; call (client_query_driver_projection A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.

lemma byte_query_exposure_game_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [IndependentGame(ExposureContext(ByteLift(A))).run ~
    IndependentGame(ClientQueryContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog}].
proof.
  proc; call (client_query_context_projection (ByteLift(A)) Independent); inline Independent.init; auto.
qed.

lemma client_query_driver_bound
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) qr0 :
  hoare [ClientQueryDriver(A,O).run : qr=qr0 /\ 0<=qr0 ==>
    size ClientQueryLog.inputs<=qr0].
proof.
  proc; seq 5 : (client_query_accounting ClientQueryLog.inputs FullSession.raw_calls
    FullSession.raw_limit /\ FullSession.raw_limit=qr0).
  + call (client_query_client_accounting A O); wp; inline FullSession(O).init; auto;
      rewrite /client_query_accounting /=; smt().
  sp 2; if.
  + call (_ : true ==> true); first by trivial.
    auto; rewrite /client_query_accounting; smt().
  auto; rewrite /client_query_accounting; smt().
qed.

lemma client_query_context_bound
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) qr0 :
  hoare [ClientQueryContext(A,O).run : FullLimits.raw_cap=qr0 /\ 0<=qr0 ==>
    size ClientQueryLog.inputs<=qr0].
proof.
  proc; call (client_query_driver_bound A O qr0).
  call (_ : true ==> true); first by trivial.
  auto.
qed.
