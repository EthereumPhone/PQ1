(* Original session state and byte client, with only the FORS leaf backend factored. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawSigner RawSignature FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import ForsLeafView LeafForestView LeafSignerView.

module LeafSession (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc hash = QueryExposureSession(O).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\ (size random = 0 \/ size random = 16) /\
        size shuffle = 32 /\ FullSession.sign_calls < FullSession.sign_limit) {
      result <@ LeafSigner(O,F).sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) { FullSession.signed_messages <- rcons FullSession.signed_messages message; }
      else { FullSession.failed <- true; }
    }
    return result;
  }
}.
module LeafExposureSession (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc hash = LeafSession(O,F).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result;
    result <@ LeafSession(O,F).sign(random,message,shuffle);
    if (result <> None) { ExposureLog.entries <- rcons ExposureLog.entries (message,oget result); }
    return result;
  }
}.
module LeafQueryDriver (A : FullClient) (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullSession(O).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    ClientQueryLog.inputs <- [];
    ClientQueryLog.output <- ([],([],[],[],[]));
    forged <@ A(LeafExposureSession(O,F)).run(seed,root);
    ClientQueryLog.output <- forged;
    result <- false;
    if (!FullSession.failed /\ size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module LeafQueryContext (A : FullClient) (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ LeafQueryDriver(A,O,F).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

module ConcreteLeafQueryContext (A : FullClient) (O : PrefixOracle) = LeafQueryContext(A,O,ConcreteForsLeaf(PreparationView(O))).

lemma leaf_session_sign_projection
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [FullSession(O).sign ~ LeafSession(O,ConcreteForsLeaf(PreparationView(O))).sign :
    ={arg,glob O,glob FullSession} ==> ={res,glob O,glob FullSession}].
proof.
  proc; sp 1 1; if; auto.
  wp; call (leaf_signer_sign_projection O); auto; smt().
qed.
lemma leaf_exposure_sign_projection
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [QueryExposureSession(O).sign ~ LeafExposureSession(O,ConcreteForsLeaf(PreparationView(O))).sign :
    ={arg,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof. proc; wp; call (leaf_session_sign_projection O); auto; smt(). qed.
lemma leaf_query_client_projection
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [A(QueryExposureSession(O)).run ~ A(LeafExposureSession(O,ConcreteForsLeaf(PreparationView(O)))).run :
    ={arg,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc (={glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}) => //.
  + by sim.
  conseq (leaf_exposure_sign_projection O); smt().
qed.
lemma leaf_query_driver_projection
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [ClientQueryDriver(A,O).run ~ LeafQueryDriver(A,O,ConcreteForsLeaf(PreparationView(O))).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc; seq 5 5 : (={seed,root,forged,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}).
  + call (leaf_query_client_projection A O); wp; inline FullSession(O).init; auto.
  sp 2 2; if; auto; call (_ : ={glob O}); first by sim.
  auto.
qed.
lemma leaf_query_context_projection
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  equiv [ClientQueryContext(A,O).run ~ ConcreteLeafQueryContext(A,O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc; call (leaf_query_driver_projection A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.
lemma byte_leaf_query_game_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [IndependentGame(ClientQueryContext(ByteLift(A))).run ~
    IndependentGame(ConcreteLeafQueryContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc; call (leaf_query_context_projection (ByteLift(A)) Independent); inline Independent.init; auto.
qed.
