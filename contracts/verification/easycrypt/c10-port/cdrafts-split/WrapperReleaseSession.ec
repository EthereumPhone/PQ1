(* The release-only FORS view retains the actual adaptive wrapper session:
   admitted refusals consume a slot and later attempts remain available. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature WrapperSession WrapperByteSession ForsLeafView.
require import ExposureLog ClientQueryLog WrapperExposureLog WrapperQueryDriver WrapperHistory.
require import MerkleRootWitness RootSessionHistory VerifierHistory WrapperMemoProjection WrapperReleasedFors.

module WrapperReleaseSession (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc hash = WrapperQueryExposureSession(O).hash
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var result; result <- None;
    if (size message=32 /\ (size random=0 \/ size random=16) /\
        size shuffle_a=32 /\ size shuffle_b=32 /\ WrapperSession.sign_calls<WrapperSession.sign_limit) {
      result <@ WrapperReleasedFors(O,F).sign(WrapperSession.seed,WrapperSession.root,
        random,message,shuffle_a,shuffle_b,ready,final_guard);
      WrapperSession.sign_calls <- WrapperSession.sign_calls+1;
      if (result<>None) { WrapperSession.signed_messages <- rcons WrapperSession.signed_messages message; }
    }
    return result;
  }
}.
module WrapperReleaseExposure (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc hash = WrapperReleaseSession(O,F).hash
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var result;
    result <@ WrapperReleaseSession(O,F).sign(random,message,shuffle_a,shuffle_b,ready,final_guard);
    if (result<>None) { ExposureLog.entries <- rcons ExposureLog.entries (message,oget result); }
    return result;
  }
}.
module WrapperReleaseDriver (A : WrapperClient) (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    WrapperSession(O).init(seed,root,qr,qs);
    ExposureLog.entries <- [];
    ClientQueryLog.inputs <- [];
    ClientQueryLog.output <- ([],([],[],[],[]));
    forged <@ A(WrapperReleaseExposure(O,F)).run(seed,root);
    ClientQueryLog.output <- forged;
    result <- false;
    if (size forged.`1=32 /\ signature_width forged.`2 /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module WrapperReleaseContext (A : WrapperClient) (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ WrapperReleaseDriver(A,O,F).run(inputs.`3,inputs.`4,
      WrapperLimits.raw_cap,WrapperLimits.sign_cap);
    return result;
  }
}.
module ConcreteWrapperReleaseContext (A : WrapperClient) (O : PrefixOracle) =
  WrapperReleaseContext(A,O,ConcreteForsLeaf(PreparationView(O))).

lemma wrapper_release_session_projection seed0 root0 :
  equiv [WrapperSession(Independent).sign ~
    WrapperReleaseSession(Independent,ConcreteForsLeaf(PreparationView(Independent))).sign :
    ={arg,glob WrapperSession,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob WrapperSession,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; sp 1 1; if => //.
  exists* message{1}; elim* => message0.
  wp; call (wrapper_released_fors_projection seed0 root0 message0); auto; smt().
qed.

lemma wrapper_release_exposure_projection seed0 root0 :
  equiv [WrapperQueryExposureSession(Independent).sign ~
    WrapperReleaseExposure(Independent,ConcreteForsLeaf(PreparationView(Independent))).sign :
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
  + conseq (wrapper_release_session_projection seed0 root0)
      (wrapper_sign_root_preserved seed0 1 0 root0); smt().
  auto; smt().
qed.

lemma wrapper_release_hash_projection seed0 root0 :
  equiv [WrapperQueryExposureSession(Independent).hash ~ WrapperQueryExposureSession(Independent).hash :
    ={arg,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0].
proof.
  have he : equiv [WrapperSession(Independent).hash ~ WrapperSession(Independent).hash :
    ={arg,glob WrapperSession,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob WrapperSession,Independent.rawhistory,Independent.secrethistory}].
  + proc; sp 1 1; if; auto; wp; call wrapper_memo_hash_projection; auto.
  proc; call (_ : ={arg,glob WrapperSession,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob WrapperSession,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0).
  + conseq he (wrapper_hash_root_preserved seed0 1 0 root0); smt().
  auto; smt().
qed.

lemma wrapper_release_client_projection
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  equiv [A(WrapperQueryExposureSession(Independent)).run ~
    A(WrapperReleaseExposure(Independent,ConcreteForsLeaf(PreparationView(Independent)))).run :
    ={arg,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory} /\
    WrapperSession.seed{1}=seed0 /\ WrapperSession.root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0) => //.
  + conseq (wrapper_release_hash_projection seed0 root0); smt().
  conseq (wrapper_release_exposure_projection seed0 root0); smt().
qed.

lemma wrapper_verifier_table_projection (V <: PublicVerifier {-Independent}) :
  equiv [V(Independent).verify ~ V(Independent).verify :
    ={arg,glob V,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob V,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  exact wrapper_memo_hash_projection.
qed.

lemma wrapper_release_driver_projection
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  equiv [WrapperQueryDriver(A,Independent).run ~
    WrapperReleaseDriver(A,Independent,ConcreteForsLeaf(PreparationView(Independent))).run :
    ={arg,glob A,Independent.rawhistory,Independent.secrethistory} /\ seed{1}=seed0 /\ root{1}=pad root0 /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 1 0 root0 ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; seq 5 5 : (={seed,root,forged,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}).
  + call (wrapper_release_client_projection A seed0 root0); wp; inline WrapperSession(Independent).init; auto.
  sp 2 2; if; auto.
  call (wrapper_verifier_table_projection RawSigner); auto.
qed.
