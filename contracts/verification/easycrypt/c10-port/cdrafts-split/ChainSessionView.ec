(* The original adaptive byte session with only trusted WOTS values factored. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion RawKeygen.
require import RawSigner RawSignature FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import ChainValueView ChainKeygenView ChainSignerView.

module ChainPreparation (O : ChainOracle) = {
  proc run() : raw_input * raw_input * raw_input * raw_input = {
    var seed, root;
    seed <- pad (node KeygenInputs.public_seed);
    root <@ ChainKeygen(O).root(seed,1,0);
    return (KeygenInputs.random,KeygenInputs.message,seed,pad root);
  }
}.
lemma chain_preparation_projection (O <: PrefixOracle {-KeygenInputs}) :
  equiv [KeygenPreparation(PreparationView(O)).run ~ ChainPreparation(ConcreteChain(O)).run :
    ={glob O,glob KeygenInputs} ==> ={res,glob O,glob KeygenInputs}].
proof. proc; call (chain_keygen_root_projection O); auto. qed.

module ChainSession (O : ChainOracle) = {
  proc hash = QueryExposureSession(ChainPrefix(O)).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!FullSession.failed /\ size message = 32 /\ (size random = 0 \/ size random = 16) /\
        size shuffle = 32 /\ FullSession.sign_calls < FullSession.sign_limit) {
      result <@ ChainSigner(O).sign(FullSession.seed,FullSession.root,random,message,shuffle);
      FullSession.sign_calls <- FullSession.sign_calls+1;
      if (result <> None) { FullSession.signed_messages <- rcons FullSession.signed_messages message; }
      else { FullSession.failed <- true; }
    }
    return result;
  }
}.
module ChainExposureSession (O : ChainOracle) = {
  proc hash = ChainSession(O).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result;
    result <@ ChainSession(O).sign(random,message,shuffle);
    if (result <> None) { ExposureLog.entries <- rcons ExposureLog.entries (message,oget result); }
    return result;
  }
}.
module ChainQueryDriver (A : FullClient) (O : ChainOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullSession(ChainPrefix(O)).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    ClientQueryLog.inputs <- [];
    ClientQueryLog.output <- ([],([],[],[],[]));
    forged <@ A(ChainExposureSession(O)).run(seed,root);
    ClientQueryLog.output <- forged;
    result <- false;
    if (!FullSession.failed /\ size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(ChainPrefix(O)).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module ChainQueryContext (A : FullClient) (O : ChainOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ ChainPreparation(O).run();
    result <@ ChainQueryDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

module ConcreteChainQueryContext (A : FullClient) (O : PrefixOracle) = ChainQueryContext(A,ConcreteChain(O)).

lemma chain_session_sign_projection
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [FullSession(O).sign ~ ChainSession(ConcreteChain(O)).sign :
    ={arg,glob O,glob FullSession} ==> ={res,glob O,glob FullSession}].
proof.
  proc; sp 1 1; if; auto.
  wp; call (chain_signer_sign_projection O); auto; smt().
qed.
lemma chain_exposure_sign_projection
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [QueryExposureSession(O).sign ~ ChainExposureSession(ConcreteChain(O)).sign :
    ={arg,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof. proc; wp; call (chain_session_sign_projection O); auto; smt(). qed.
lemma chain_query_client_projection
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [A(QueryExposureSession(O)).run ~ A(ChainExposureSession(ConcreteChain(O))).run :
    ={arg,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc (={glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}) => //.
  + by sim.
  conseq (chain_exposure_sign_projection O); smt().
qed.
lemma chain_query_driver_projection
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [ClientQueryDriver(A,O).run ~ ChainQueryDriver(A,ConcreteChain(O)).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc; seq 5 5 : (={seed,root,forged,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}).
  + call (chain_query_client_projection A O); wp; inline FullSession(O).init FullSession(ChainPrefix(ConcreteChain(O))).init; auto.
  sp 2 2; if; auto; call (_ : ={glob O}); first by sim.
  auto.
qed.
lemma chain_query_context_projection
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  equiv [ClientQueryContext(A,O).run ~ ConcreteChainQueryContext(A,O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc; call (chain_query_driver_projection A O).
  call (chain_preparation_projection O).
  auto.
qed.
lemma byte_chain_query_game_projection
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [IndependentGame(ClientQueryContext(ByteLift(A))).run ~
    IndependentGame(ConcreteChainQueryContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob Independent,glob FullSession,glob ExposureLog,glob ClientQueryLog}].
proof.
  proc; call (chain_query_context_projection (ByteLift(A)) Independent); inline Independent.init; auto.
qed.
