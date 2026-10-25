(* Actual adaptive wrapper admission, caps and retries, with WOTS values
   materialized only when a signature is externally released. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature WrapperSession WrapperByteSession ChainValueView ChainSessionView WrapperReleaseSession.
require import ExposureLog ClientQueryLog WrapperExposureLog WrapperQueryDriver WrapperHistory.
require import MerkleRootWitness RootSessionHistory VerifierHistory WrapperMemoProjection WrapperChainReleasedWots.

module WrapperWotsReleaseSession (O : PrefixOracle) (C : ChainOracle) = {
  proc hash = WrapperQueryExposureSession(O).hash
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var result; result <- None;
    if (size message=32 /\ (size random=0 \/ size random=16) /\
        size shuffle_a=32 /\ size shuffle_b=32 /\ WrapperSession.sign_calls<WrapperSession.sign_limit) {
      result <@ WrapperChainReleasedWots(C).sign(WrapperSession.seed,WrapperSession.root,
        random,message,shuffle_a,shuffle_b,ready,final_guard);
      WrapperSession.sign_calls <- WrapperSession.sign_calls+1;
      if (result<>None) { WrapperSession.signed_messages <- rcons WrapperSession.signed_messages message; }
    }
    return result;
  }
}.
module WrapperWotsReleaseExposure (O : PrefixOracle) (C : ChainOracle) = {
  proc hash = WrapperWotsReleaseSession(O,C).hash
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var result;
    result <@ WrapperWotsReleaseSession(O,C).sign(random,message,shuffle_a,shuffle_b,ready,final_guard);
    if (result<>None) { ExposureLog.entries <- rcons ExposureLog.entries (message,oget result); }
    return result;
  }
}.
module WrapperWotsReleaseDriver (A : WrapperClient) (O : PrefixOracle) (C : ChainOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    WrapperSession(O).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    ClientQueryLog.inputs <- [];
    ClientQueryLog.output <- ([],([],[],[],[]));
    forged <@ A(WrapperWotsReleaseExposure(O,C)).run(seed,root);
    ClientQueryLog.output <- forged;
    result <- false;
    if (size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module WrapperWotsReleaseContext (A : WrapperClient) (O : PrefixOracle) (C : ChainOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ ChainPreparation(C).run();
    result <@ WrapperWotsReleaseDriver(A,O,C).run(inputs.`3,inputs.`4,
      WrapperLimits.raw_cap,WrapperLimits.sign_cap);
    return result;
  }
}.
module ConcreteWrapperWotsReleaseContext (A : WrapperClient) (O : PrefixOracle) =
  WrapperWotsReleaseContext(A,O,ConcreteChain(O)).

lemma wrapper_wots_release_session_projection seed0 root0 :
  equiv [WrapperSession(Independent).sign ~
    WrapperWotsReleaseSession(Independent,ConcreteChain(Independent)).sign :
    ={arg,glob WrapperSession,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob WrapperSession,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; sp 1 1; if => //.
  exists* message{1}; elim* => message0.
  wp; call (wrapper_chain_released_original seed0 root0 message0); auto; smt().
qed.

lemma wrapper_wots_release_exposure_projection seed0 root0 :
  equiv [WrapperQueryExposureSession(Independent).sign ~
    WrapperWotsReleaseExposure(Independent,ConcreteChain(Independent)).sign :
    ={arg,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0].
proof.
  proc; wp.
  call (_ : ={arg,glob WrapperSession,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob WrapperSession,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0).
  + conseq (wrapper_wots_release_session_projection seed0 root0)
      (wrapper_sign_root_preserved seed0 1 0 root0); smt().
  auto; smt().
qed.

lemma wrapper_wots_release_client_projection
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  equiv [A(WrapperQueryExposureSession(Independent)).run ~
    A(WrapperWotsReleaseExposure(Independent,ConcreteChain(Independent))).run :
    ={arg,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0) => //.
  + conseq (wrapper_release_hash_projection seed0 root0); smt().
  conseq (wrapper_wots_release_exposure_projection seed0 root0); smt().
qed.

lemma wrapper_wots_release_driver_projection
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  equiv [WrapperQueryDriver(A,Independent).run ~
    WrapperWotsReleaseDriver(A,Independent,ConcreteChain(Independent)).run :
    ={arg,glob A,Independent.rawhistory,Independent.secrethistory} /\ seed{1}=seed0 /\ root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; seq 5 5 : (={seed,root,forged,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}).
  + call (wrapper_wots_release_client_projection A seed0 root0); wp; inline WrapperSession(Independent).init; auto.
  sp 2 2; if; auto.
  call (wrapper_verifier_table_projection RawSigner); auto.
qed.
